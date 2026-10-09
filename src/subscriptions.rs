// SPDX-License-Identifier: AGPL-3.0-only
//! Outgoing event subscriptions of applications (protocol/APPLICATIONS.md §6.2).
//!
//! [`record`] runs right after a change of a room on this node (in the same request, before it answers) and
//! queues the event for every subscription that may see it: the application's bot is a member of the room, the
//! subscription lists the type, the application's scopes cover it (the WebSocket filter of §2.6) and, for
//! `message.*`, the bot can read the channel. Content of encrypted conversations is never queued: `message.*`
//! events of encrypted channels and of DMs are skipped before anything else, and `mls.*`, `ephemeral`, `typing`
//! and presence are not subscribable at all.
//!
//! [`deliver_due`] sends due entries as signed hook requests (`hooks.rs`) with an injectable clock: at most
//! [`PER_APPLICATION_CONCURRENCY`] requests per application, the retry schedule of FEDERATION.md §5.3 (1 min,
//! 5 min, 30 min, 2 h, 12 h, then every 12 h, `Retry-After` honored, given up after 3 days), at most
//! [`MAX_QUEUE`] queued events per application (the oldest are dropped and counted). A subscription turns
//! `failing` when an event is given up and `disabled` after 3 days without any success; the owner then gets the
//! WebSocket event `application.subscription_disabled`. [`spawn`] runs the worker with the real clock.

use std::{collections::HashMap, time::Duration};

use chrono::{DateTime, Utc};
use futures::StreamExt;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    error::ApiError,
    federation::outbox::{GIVE_UP_SECS, JITTER, next_delay_secs},
    hooks::{self, HookError},
    permissions as p,
    store::{
        self,
        subscriptions::{NewHook, OutboxRow, SubscriptionRow},
    },
    util,
};

/// Event types an application can subscribe to (§6.2).
pub const EVENT_TYPES: &[&str] = &[
    "application.install",
    "application.uninstall",
    "member.join",
    "member.leave",
    "member.update",
    "message.create",
    "message.update",
    "message.delete",
    "commands.update",
];
/// Queued events per application; beyond, the oldest are dropped.
pub const MAX_QUEUE: i64 = 10_000;
/// Concurrent requests per application.
pub const PER_APPLICATION_CONCURRENCY: usize = 4;
/// Applications delivered to at the same time.
pub const CONCURRENT_APPLICATIONS: usize = 16;
/// Entries per worker round.
pub const BATCH: i64 = 512;
/// A failing subscription without a success for this long is disabled.
pub const DISABLE_AFTER_SECS: i64 = GIVE_UP_SECS;
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The subscription of an application as its owner sees it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Subscription {
    pub url: String,
    pub events: Vec<String>,
    /// active | failing | disabled
    pub state: String,
    pub last_success_at: Option<String>,
    /// The last delivery error (`status 500`, `timeout`, `unreachable`, …), never the receiver's content.
    pub last_error: Option<String>,
    /// Events waiting for delivery.
    pub queued: i64,
    /// Events dropped because more than 10 000 were queued.
    pub dropped: i64,
    pub created_at: String,
}

pub async fn view(state: &AppState, row: &SubscriptionRow) -> Result<Subscription, ApiError> {
    Ok(Subscription {
        url: row.url.clone(),
        events: row.events(),
        state: row.state.clone(),
        last_success_at: row.last_success_at.clone(),
        last_error: row.last_error.clone(),
        queued: store::subscriptions::queued(&state.db, &row.application_id).await?,
        dropped: row.dropped,
        created_at: row.created_at.clone(),
    })
}

/// Validates an event list (`400 subscription.event_invalid`) and returns it in canonical order.
pub fn parse_events(events: &[String]) -> Result<Vec<String>, ApiError> {
    if let Some(bad) = events.iter().find(|e| !EVENT_TYPES.contains(&e.as_str())) {
        return Err(ApiError::BadRequest {
            code: "subscription.event_invalid",
            detail: format!("Unknown event type: {bad:.64}"),
        });
    }
    if events.is_empty() {
        return Err(ApiError::BadRequest {
            code: "subscription.event_invalid",
            detail: "Subscribe to at least one event type".into(),
        });
    }
    Ok(EVENT_TYPES.iter().filter(|t| events.iter().any(|e| e == *t)).map(|t| t.to_string()).collect())
}

/// Publishes a room event to the room's WebSockets and queues it for the room's subscriptions. Returns the event id.
pub async fn room_event(state: &AppState, room_id: &str, kind: &str, data: impl Serialize) -> String {
    let id = state.hub.room(room_id, kind, &data);
    record(state, room_id, kind, &id, &data).await;
    id
}

/// Queues the event `kind` (published with `event_id`) of `room_id` for every subscription that may receive it.
/// Never fails the caller: errors are logged.
pub async fn record(state: &AppState, room_id: &str, kind: &str, event_id: &str, data: &impl Serialize) {
    if !EVENT_TYPES.contains(&kind) {
        return;
    }
    if let Err(e) = record_inner(state, room_id, kind, event_id, data).await {
        tracing::warn!(error = %e, kind, "subscription event not queued");
    }
}

async fn record_inner(
    state: &AppState,
    room_id: &str,
    kind: &str,
    event_id: &str,
    data: &impl Serialize,
) -> Result<(), ApiError> {
    let subscribers = store::subscriptions::subscribers_of_room(&state.db, room_id).await?;
    if subscribers.is_empty() {
        return Ok(());
    }
    let data = serde_json::to_value(data).map_err(|e| ApiError::Internal(e.into()))?;
    // Never content of encrypted conversations: the conversation must be a plaintext channel of this room.
    let channel = if kind.starts_with("message.") {
        if kind != "message.delete" && data.get("encrypted").and_then(Value::as_bool) != Some(false) {
            return Ok(());
        }
        let Some(conversation_id) = data.get("conversation_id").and_then(Value::as_str) else { return Ok(()) };
        match store::rooms::channel_by_id(&state.db, conversation_id).await? {
            Some(c) if c.room_id == room_id && c.encrypted == 0 => Some(c),
            _ => return Ok(()),
        }
    } else {
        None
    };
    let at = util::now();
    let mut queued = false;
    for sub in subscribers {
        let events: Vec<String> = serde_json::from_str(&sub.events).unwrap_or_default();
        if !events.iter().any(|e| e == kind) {
            continue;
        }
        let Some(app) = store::applications::by_id(&state.db, &sub.application_id).await? else { continue };
        let Some(mut bot) = store::users::by_id(&state.db, &sub.bot_user_id).await? else { continue };
        if crate::applications::disabled_reason(state, &app, &bot).await?.is_some() {
            continue;
        }
        let scopes = app.scopes();
        if !crate::applications::event_allowed(kind, &data, &scopes) {
            continue;
        }
        if let Some(channel) = &channel {
            bot.app_scopes = Some(scopes.clone());
            let Ok(access) = crate::access::room_access(state, room_id, &bot).await else { continue };
            let perms = crate::access::channel_perms(state, &access, channel, &bot.id).await?;
            if !p::has(perms, p::VIEW_CHANNEL | p::READ_HISTORY) {
                continue;
            }
        }
        let body = json!({
            "id": event_id, "type": kind, "at": at, "application_id": app.id, "room_id": room_id, "data": data,
        })
        .to_string();
        let expires_at = util::in_seconds(GIVE_UP_SECS);
        let hook = NewHook {
            application_id: &app.id,
            event_id,
            event_type: kind,
            body: &body,
            next_at: &at,
            expires_at: &expires_at,
        };
        let dropped = store::subscriptions::enqueue(&state.db, hook, MAX_QUEUE).await?;
        if dropped > 0 {
            tracing::warn!(application = app.id, dropped, "subscription queue full, oldest events dropped");
        }
        queued = true;
    }
    if queued {
        crate::cache::wake(state, crate::cache::Job::Subscriptions);
    }
    Ok(())
}

/// Queues an application-level event (`application.install` / `application.uninstall`) for one local
/// application's subscription, independent of room membership (the bot may already have left the room).
/// Never fails the caller: errors are logged.
pub async fn application_event(
    state: &AppState,
    application_id: &str,
    room_id: &str,
    kind: &str,
    data: &impl Serialize,
) {
    if let Err(e) = application_event_inner(state, application_id, room_id, kind, data).await {
        tracing::warn!(error = %e, kind, "subscription event not queued");
    }
}

async fn application_event_inner(
    state: &AppState,
    application_id: &str,
    room_id: &str,
    kind: &str,
    data: &impl Serialize,
) -> Result<(), ApiError> {
    let Some(sub) = store::subscriptions::get(&state.db, application_id).await? else { return Ok(()) };
    if sub.state == "disabled" {
        return Ok(());
    }
    let events: Vec<String> = serde_json::from_str(&sub.events).unwrap_or_default();
    if !events.iter().any(|e| e == kind) {
        return Ok(());
    }
    let Some(app) = store::applications::by_id(&state.db, application_id).await? else { return Ok(()) };
    let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { return Ok(()) };
    if crate::applications::disabled_reason(state, &app, &bot).await?.is_some() {
        return Ok(());
    }
    let data = serde_json::to_value(data).map_err(|e| ApiError::Internal(e.into()))?;
    let at = util::now();
    let event_id = util::ulid();
    let body = json!({
        "id": event_id, "type": kind, "at": at, "application_id": app.id, "room_id": room_id, "data": data,
    })
    .to_string();
    let expires_at = util::in_seconds(GIVE_UP_SECS);
    let hook = NewHook {
        application_id: &app.id,
        event_id: &event_id,
        event_type: kind,
        body: &body,
        next_at: &at,
        expires_at: &expires_at,
    };
    let dropped = store::subscriptions::enqueue(&state.db, hook, MAX_QUEUE).await?;
    if dropped > 0 {
        tracing::warn!(application = app.id, dropped, "subscription queue full, oldest events dropped");
    }
    crate::cache::wake(state, crate::cache::Job::Subscriptions);
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub delivered: u64,
    pub retried: u64,
    pub given_up: u64,
    pub disabled: u64,
}

impl DeliveryReport {
    fn add(&mut self, other: &Self) {
        self.delivered += other.delivered;
        self.retried += other.retried;
        self.given_up += other.given_up;
    }
}

/// Delivers every entry due at `now`, then disables subscriptions that have been failing for 3 days.
pub async fn deliver_due(state: &AppState, now: DateTime<Utc>) -> Result<DeliveryReport, ApiError> {
    let rows = store::subscriptions::due(&state.db, &util::format_time(now), BATCH).await?;
    let mut by_app: Vec<Vec<OutboxRow>> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for row in rows {
        match index.get(&row.application_id) {
            Some(i) => by_app[*i].push(row),
            None => {
                index.insert(row.application_id.clone(), by_app.len());
                by_app.push(vec![row]);
            }
        }
    }
    let results: Vec<Result<DeliveryReport, ApiError>> = futures::stream::iter(by_app)
        .map(|rows| deliver_application(state, rows, now))
        .buffer_unordered(CONCURRENT_APPLICATIONS)
        .collect()
        .await;
    let mut report = DeliveryReport::default();
    for r in results {
        report.add(&r?);
    }
    let before = util::format_time(now - chrono::Duration::seconds(DISABLE_AFTER_SECS));
    for (application_id, owner_id, url, last_error) in store::subscriptions::disable_stale(&state.db, &before).await? {
        tracing::warn!(application = application_id, url, "event subscription disabled after 3 days without success");
        state.hub.users(
            vec![owner_id],
            "application.subscription_disabled",
            json!({ "application_id": application_id, "url": url, "last_error": last_error }),
        );
        report.disabled += 1;
    }
    Ok(report)
}

/// The due entries of one application, at most [`PER_APPLICATION_CONCURRENCY`] at a time.
async fn deliver_application(
    state: &AppState,
    rows: Vec<OutboxRow>,
    now: DateTime<Utc>,
) -> Result<DeliveryReport, ApiError> {
    let results: Vec<Result<Outcome, ApiError>> = futures::stream::iter(rows)
        .map(|row| deliver_one(state, row, now))
        .buffer_unordered(PER_APPLICATION_CONCURRENCY)
        .collect()
        .await;
    let mut report = DeliveryReport::default();
    for r in results {
        match r? {
            Outcome::Delivered => report.delivered += 1,
            Outcome::Retried => report.retried += 1,
            Outcome::GivenUp => report.given_up += 1,
        }
    }
    Ok(report)
}

enum Outcome {
    Delivered,
    Retried,
    GivenUp,
}

async fn deliver_one(state: &AppState, row: OutboxRow, now: DateTime<Utc>) -> Result<Outcome, ApiError> {
    let now_s = util::format_time(now);
    if row.expires_at <= now_s {
        give_up(state, &row, row.last_error.as_deref().unwrap_or("expired")).await?;
        return Ok(Outcome::GivenUp);
    }
    let url = match hooks::check_url(&row.url, state.config.dev) {
        Ok(u) => u,
        Err(_) => {
            give_up(state, &row, &HookError::Invalid.label()).await?;
            return Ok(Outcome::GivenUp);
        }
    };
    let started = std::time::Instant::now();
    let result = hooks::send(
        state,
        &row.application_id,
        &url,
        &row.event_type,
        &row.event_id,
        row.body.as_bytes().to_vec(),
        hooks::EVENT_TIMEOUT,
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(answer) => {
            store::subscriptions::delete_outbox(&state.db, &row.id).await?;
            store::subscriptions::succeeded(&state.db, &row.application_id, &now_s).await?;
            tracing::info!(
                application = row.application_id,
                event_type = row.event_type,
                id = row.event_id,
                status = answer.status,
                attempt = row.attempts + 1,
                latency_ms,
                "hook delivered"
            );
            Ok(Outcome::Delivered)
        }
        Err(e) if e.retryable() => {
            let jitter = rand::rng().random_range(-JITTER..=JITTER);
            let delay = next_delay_secs(row.attempts + 1, e.retry_after(), jitter);
            let next_at = util::format_time(now + chrono::Duration::seconds(delay));
            store::subscriptions::reschedule(&state.db, &row.id, row.attempts + 1, &next_at, &e.label()).await?;
            store::subscriptions::failed(&state.db, &row.application_id, &e.label(), false).await?;
            tracing::info!(
                application = row.application_id,
                event_type = row.event_type,
                id = row.event_id,
                result = e.label(),
                attempt = row.attempts + 1,
                latency_ms,
                next_at,
                "hook failed, retry scheduled"
            );
            Ok(Outcome::Retried)
        }
        Err(e) => {
            give_up(state, &row, &e.label()).await?;
            Ok(Outcome::GivenUp)
        }
    }
}

async fn give_up(state: &AppState, row: &OutboxRow, reason: &str) -> Result<(), ApiError> {
    store::subscriptions::delete_outbox(&state.db, &row.id).await?;
    store::subscriptions::failed(&state.db, &row.application_id, reason, true).await?;
    tracing::warn!(
        application = row.application_id,
        event_type = row.event_type,
        id = row.event_id,
        attempts = row.attempts,
        reason,
        "hook given up"
    );
    Ok(())
}

/// Runs the delivery worker with the real clock: every few seconds and whenever an event is queued.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    let wakeup = state.subscription_wakeup.clone();
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
                tracing::warn!(error = %e, "subscription delivery round failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn event_lists_are_validated() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_events(&s(&["message.delete", "member.join", "message.delete"])).unwrap(),
            s(&["member.join", "message.delete"])
        );
        for bad in [&["mls.commit"][..], &["typing"], &["presence.update"], &["ephemeral"], &[]] {
            assert_eq!(parse_events(&s(bad)).unwrap_err().code(), "subscription.event_invalid", "{bad:?}");
        }
    }
}
