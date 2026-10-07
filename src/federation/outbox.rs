// SPDX-License-Identifier: AGPL-3.0-only
//! Outgoing server-to-server notifications (FEDERATION.md §5.3).
//!
//! [`enqueue`] stores the exact envelope JSON in `federation_outbox`; [`deliver_due`] sends due entries
//! with a fresh node token per attempt. The clock is a parameter, so tests drive the retry schedule
//! without sleeping; [`spawn`] runs it every few seconds (and right after an enqueue) with the real
//! clock. Retry schedule after a failed attempt: 1 min, 5 min, 30 min, 2 h, 12 h, then every 12 h, each
//! ±10 % jitter, a larger `Retry-After` is honored; network errors, timeouts, 408, 429 and 5xx retry,
//! `401` retries once after 5 minutes, every other 4xx is final. Entries are given up at `expires_at`
//! (3 days; `notify` 1 hour, `node.announce` 1 day). A failed target delays all its queued entries.

use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use futures::StreamExt;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Notify;

use super::{client::FetchError, inbox::INBOX_PATH, tokens};
use crate::{
    app::AppState,
    error::ApiError,
    store::{self, federation::OutboxRow},
    util,
};

/// Delays after the 1st, 2nd, … failed attempt; the last one repeats.
pub const SCHEDULE_SECS: [i64; 5] = [60, 300, 1800, 7200, 43_200];
pub const JITTER: f64 = 0.1;
/// A `401` is retried once after this delay (the peer may refresh our keys), then it is final.
pub const UNAUTHORIZED_RETRY_SECS: i64 = 300;
pub const GIVE_UP_SECS: i64 = 3 * 24 * 3600;
/// Entries per worker round.
pub const BATCH: i64 = 256;
/// Targets delivered to concurrently (the client limits requests further: 4 per peer, 64 overall).
pub const CONCURRENT_TARGETS: usize = 16;
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Lifetime of an entry of `kind` before it is given up.
pub fn lifetime_secs(kind: &str) -> i64 {
    match kind {
        "notify" => 3600,
        "node.announce" => 24 * 3600,
        _ => GIVE_UP_SECS,
    }
}

/// Delay before the next attempt after `failures` failed attempts (≥ 1), with `jitter` in −0.1…0.1, at
/// least `retry_after` (capped at the 3-day lifetime: a longer wait means giving up anyway).
pub fn next_delay_secs(failures: i64, retry_after: Option<u64>, jitter: f64) -> i64 {
    let index = usize::try_from(failures.max(1) - 1).unwrap_or(0).min(SCHEDULE_SECS.len() - 1);
    let base = SCHEDULE_SECS[index] as f64;
    let delay = (base * (1.0 + jitter.clamp(-JITTER, JITTER))).round() as i64;
    delay.max(retry_after.map_or(0, |r| i64::try_from(r).unwrap_or(i64::MAX).min(GIVE_UP_SECS)))
}

/// The inbox envelope (§5.1).
#[derive(Debug, Serialize)]
pub struct Envelope<'a> {
    pub id: &'a str,
    #[serde(rename = "type")]
    pub kind: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub at: &'a str,
    pub payload: Value,
}

/// Queues a notification for `target`. Returns the message id.
pub async fn enqueue(
    state: &AppState,
    target: &str,
    kind: &str,
    from: &str,
    to: &str,
    payload: Value,
) -> Result<String, ApiError> {
    let id = util::ulid();
    // `at` is the ULID time, so the receiver's staleness check and `at` agree.
    let created: DateTime<Utc> =
        ulid::Ulid::from_string(&id).map(|u| DateTime::<Utc>::from(u.datetime())).unwrap_or_else(|_| Utc::now());
    let at = util::format_time(created);
    let body = serde_json::to_string(&Envelope { id: &id, kind, from, to, at: &at, payload })
        .map_err(|e| ApiError::Internal(e.into()))?;
    let expires_at = util::format_time(created + chrono::Duration::seconds(lifetime_secs(kind)));
    store::federation::enqueue(
        &state.db,
        store::federation::NewOutbox { id: &id, target, kind, body: &body, created_at: &at, expires_at: &expires_at },
    )
    .await?;
    tracing::debug!(target, kind, id, "federation notification queued");
    crate::cache::wake(state, crate::cache::Job::Outbox);
    Ok(id)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub delivered: u64,
    pub retried: u64,
    pub given_up: u64,
}

impl DeliveryReport {
    fn add(&mut self, other: &Self) {
        self.delivered += other.delivered;
        self.retried += other.retried;
        self.given_up += other.given_up;
    }
}

/// Delivers every entry due at `now`. Paused while federation is disabled.
pub async fn deliver_due(state: &AppState, now: DateTime<Utc>) -> Result<DeliveryReport, ApiError> {
    if !state.config.federation_enabled {
        return Ok(DeliveryReport::default());
    }
    let rows = store::federation::due(&state.db, &util::format_time(now), BATCH).await?;
    let mut by_target: Vec<(String, Vec<OutboxRow>)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for row in rows {
        match index.get(&row.target) {
            Some(i) => by_target[*i].1.push(row),
            None => {
                index.insert(row.target.clone(), by_target.len());
                by_target.push((row.target.clone(), vec![row]));
            }
        }
    }
    let results: Vec<Result<DeliveryReport, ApiError>> = futures::stream::iter(by_target)
        .map(|(target, rows)| deliver_target(state, target, rows, now))
        .buffer_unordered(CONCURRENT_TARGETS)
        .collect()
        .await;
    let mut report = DeliveryReport::default();
    for r in results {
        report.add(&r?);
    }
    Ok(report)
}

/// Delivers the due entries of one target in order; stops at the first retryable failure and delays
/// the rest of the target's queue to the same next attempt.
async fn deliver_target(
    state: &AppState,
    target: String,
    rows: Vec<OutboxRow>,
    now: DateTime<Utc>,
) -> Result<DeliveryReport, ApiError> {
    let mut report = DeliveryReport::default();
    let now_s = util::format_time(now);
    for row in rows {
        if row.expires_at <= now_s {
            give_up(state, &row, "expired").await?;
            report.given_up += 1;
            continue;
        }
        match attempt(state, &row).await {
            Ok(status) => {
                state.metrics.federation_delivery(true);
                store::federation::delete_outbox(&state.db, &row.id).await?;
                tracing::info!(
                    target,
                    kind = row.kind,
                    id = row.id,
                    status,
                    attempt = row.attempts + 1,
                    "federation notification delivered"
                );
                report.delivered += 1;
            }
            Err(e) => {
                state.metrics.federation_delivery(false);
                let status = e.status();
                let retry_in = if status == Some(401) {
                    (row.last_status != Some(401)).then_some(UNAUTHORIZED_RETRY_SECS)
                } else if e.retryable() {
                    let jitter = rand::thread_rng().gen_range(-JITTER..=JITTER);
                    Some(next_delay_secs(row.attempts + 1, e.retry_after(), jitter))
                } else {
                    None
                };
                let Some(delay) = retry_in else {
                    give_up(state, &row, &e.label()).await?;
                    report.given_up += 1;
                    continue;
                };
                let next_at = util::format_time(now + chrono::Duration::seconds(delay));
                store::federation::reschedule(
                    &state.db,
                    &row.id,
                    row.attempts + 1,
                    &next_at,
                    status.map(i64::from),
                    &e.label(),
                )
                .await?;
                store::federation::delay_target(&state.db, &target, &next_at).await?;
                tracing::info!(
                    target,
                    kind = row.kind,
                    id = row.id,
                    result = e.label(),
                    next_at,
                    "federation notification failed, retry scheduled"
                );
                report.retried += 1;
                break;
            }
        }
    }
    Ok(report)
}

async fn attempt(state: &AppState, row: &OutboxRow) -> Result<u16, FetchError> {
    let body = row.body.as_bytes().to_vec();
    let token = tokens::issue_node_token(state, &row.target, "POST", INBOX_PATH, &body)
        .map_err(|_| FetchError::Unreachable(row.target.clone()))?;
    state.federation.post_inbox(&row.target, &token, body).await
}

/// Types whose failure the originating user is told about (§5.3).
const USER_VISIBLE: &[&str] = &["friend.request", "room.invite", "conversation.invite"];

async fn give_up(state: &AppState, row: &OutboxRow, reason: &str) -> Result<(), ApiError> {
    store::federation::delete_outbox(&state.db, &row.id).await?;
    store::federation::count_undeliverable(&state.db).await?;
    if USER_VISIBLE.contains(&row.kind.as_str())
        && let Ok(body) = serde_json::from_str::<Value>(&row.body)
        && let (Some(from), Some(to)) = (body["from"].as_str(), body["to"].as_str())
        && let Some((name, domain)) = util::parse_address(from)
        && domain == state.config.domain
        && let Some(user) = store::users::by_username(&state.db, name, domain).await?
    {
        state.hub.users(vec![user.id], "federation.undeliverable", serde_json::json!({ "type": row.kind, "to": to }));
    }
    tracing::warn!(
        target = row.target,
        kind = row.kind,
        id = row.id,
        attempts = row.attempts,
        reason,
        "federation.undeliverable: notification given up"
    );
    Ok(())
}

/// Runs the outbox worker with the real clock: every 10 seconds and whenever an entry is queued.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    let wakeup: Arc<Notify> = state.outbox_wakeup.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                _ = wakeup.notified() => {}
            }
            // Several instances: the leader delivers (`cache::leader`); the others only queue.
            if !state.cluster.is_leader() {
                continue;
            }
            if let Err(e) = deliver_due(&state, Utc::now()).await {
                tracing::warn!(error = %e, "federation outbox round failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_schedule_follows_the_spec() {
        let plain: Vec<i64> = (1..=7).map(|n| next_delay_secs(n, None, 0.0)).collect();
        assert_eq!(plain, vec![60, 300, 1800, 7200, 43_200, 43_200, 43_200]);
        assert_eq!(next_delay_secs(0, None, 0.0), 60, "a first failure even with a zero count");
    }

    #[test]
    fn jitter_is_bounded_to_ten_percent() {
        assert_eq!(next_delay_secs(1, None, 0.1), 66);
        assert_eq!(next_delay_secs(1, None, -0.1), 54);
        assert_eq!(next_delay_secs(1, None, 5.0), 66, "clamped");
        assert_eq!(next_delay_secs(2, None, -1.0), 270);
    }

    #[test]
    fn a_larger_retry_after_wins() {
        assert_eq!(next_delay_secs(1, Some(600), 0.0), 600);
        assert_eq!(next_delay_secs(3, Some(600), 0.0), 1800, "a smaller one does not shorten the schedule");
        assert_eq!(next_delay_secs(1, Some(u64::MAX), 0.0), GIVE_UP_SECS, "capped");
    }

    #[test]
    fn lifetimes_per_type() {
        assert_eq!(lifetime_secs("session.revoke"), 3 * 24 * 3600);
        assert_eq!(lifetime_secs("friend.request"), 3 * 24 * 3600);
        assert_eq!(lifetime_secs("notify"), 3600);
        assert_eq!(lifetime_secs("node.announce"), 24 * 3600);
    }
}
