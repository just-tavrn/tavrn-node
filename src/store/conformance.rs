// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance checks and reputation (migration 0014, FEDERATION.md §9): the probe account, the
//! reputation record on `federation_peers`, live-traffic violations and the throwaway conformance rooms
//! this node hosts for the probes of other nodes.

use std::collections::HashMap;

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    models::UserRow,
    util::{now, ulid},
};

use super::users::USER_COLS;

// ---------------------------------------------------------------- probe account

/// The local probe user (`tavrn-conformance@<this node>`), if it exists.
pub async fn probe_user(db: &Pool, username: &str, domain: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM users WHERE username = $1 AND domain = $2"))
        .bind(username)
        .bind(domain)
        .fetch_optional(db)
        .await?)
}

/// Creates the probe user without password, e-mail or admin rights; an existing row is kept.
pub async fn create_probe_user(db: &Pool, username: &str, domain: &str, display_name: &str) -> Result<(), ApiError> {
    let r = sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, password_hash, email, is_node_admin, created_at)
         VALUES ($1, $2, $3, $4, 'user', NULL, NULL, 0, $5)",
    )
    .bind(ulid())
    .bind(username)
    .bind(domain)
    .bind(display_name)
    .bind(now())
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(()),
        Err(e) if super::is_unique_violation(&e) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Device ids of a user, oldest first.
pub async fn device_ids(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT id FROM devices WHERE user_id = $1 ORDER BY created_at, id")
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

/// Sets the probe's identity key (derived from the node secret, so normally unchanged).
pub async fn set_identity(db: &Pool, user_id: &str, key: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET identity_pubkey = $1 WHERE id = $2 AND (identity_pubkey IS NULL OR identity_pubkey <> $1)",
    )
    .bind(key)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Stores the attested key of a probe device (overwrites: the probe's keys are derived, not uploaded).
pub async fn set_device_key(
    db: &Pool,
    device_id: &str,
    public_key: &str,
    signature: &str,
    identity_key: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE devices SET public_key = $1, identity_signature = $2, attested_identity_key = $3,
           attested_at = COALESCE(attested_at, $4)
         WHERE id = $5 AND (public_key IS NULL OR public_key <> $1 OR identity_signature <> $2
           OR attested_identity_key IS NULL OR attested_identity_key <> $3)",
    )
    .bind(public_key)
    .bind(signature)
    .bind(identity_key)
    .bind(now())
    .bind(device_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Deletes every KeyPackage of the probe's devices (their private parts only live during one run).
pub async fn clear_key_packages(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM key_packages WHERE user_id = $1").bind(user_id).execute(db).await?;
    Ok(())
}

// ---------------------------------------------------------------- reputation record

/// Peer status values of `federation_peers.status`.
pub const STATUS_OK: &str = "ok";
pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_BLOCKED_AUTO: &str = "blocked_auto";

#[derive(Debug, Clone, FromRow)]
pub struct PeerStateRow {
    pub domain: String,
    /// `ok`, `blocked`, `blocked_auto` or `key_conflict`.
    pub status: String,
    pub fetched_at: String,
    /// JSON record of the latest run.
    pub conformance: Option<String>,
    pub conformance_checked_at: Option<String>,
    /// `pass`, `warn` or `fail`; `None` = never checked.
    pub conformance_result: Option<String>,
    pub hard_failures: i64,
    pub soft_failures: i64,
    pub violations: i64,
    pub blocked_at: Option<String>,
    pub blocked_reason: Option<String>,
}

const STATE_COLS: &str = "domain, status, fetched_at, conformance, conformance_checked_at, conformance_result, hard_failures, soft_failures, violations, blocked_at, blocked_reason";

pub async fn peer_state(db: &Pool, domain: &str) -> Result<Option<PeerStateRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {STATE_COLS} FROM federation_peers WHERE domain = $1"))
        .bind(domain)
        .fetch_optional(db)
        .await?)
}

/// Peers ordered by domain, after `after`.
pub async fn peer_states(db: &Pool, after: &str, limit: i64) -> Result<Vec<PeerStateRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {STATE_COLS} FROM federation_peers WHERE domain > $1 ORDER BY domain LIMIT $2"))
        .bind(after)
        .bind(limit)
        .fetch_all(db)
        .await?)
}

/// Creates the peer row (empty, expired document) if this node never fetched the peer's document.
pub async fn ensure_peer(db: &Pool, domain: &str) -> Result<(), ApiError> {
    let ts = now();
    sqlx::query(
        "INSERT INTO federation_peers (domain, document, fetched_at, expires_at) VALUES ($1, '{}', $2, $2)
         ON CONFLICT (domain) DO NOTHING",
    )
    .bind(domain)
    .bind(&ts)
    .execute(db)
    .await?;
    Ok(())
}

pub struct RunRecord<'a> {
    pub domain: &'a str,
    pub record: &'a str,
    pub result: &'a str,
    pub checked_at: &'a str,
    pub hard: i64,
    pub soft: i64,
}

/// Stores the result of a check run and adds its failures to the peer's counters.
pub async fn record_run(db: &Pool, r: RunRecord<'_>) -> Result<(), ApiError> {
    ensure_peer(db, r.domain).await?;
    sqlx::query(
        "UPDATE federation_peers SET conformance = $1, conformance_checked_at = $2, conformance_result = $3,
           hard_failures = hard_failures + $4, soft_failures = soft_failures + $5
         WHERE domain = $6",
    )
    .bind(r.record)
    .bind(r.checked_at)
    .bind(r.result)
    .bind(r.hard)
    .bind(r.soft)
    .bind(r.domain)
    .execute(db)
    .await?;
    Ok(())
}

/// Moves a peer from status `from` to `to` (with the block reason and time, or none for `ok`). `false`
/// if the peer was not in `from`.
pub async fn transition(
    db: &Pool,
    domain: &str,
    from: &[&str],
    to: &str,
    reason: Option<&str>,
) -> Result<bool, ApiError> {
    ensure_peer(db, domain).await?;
    let blocked_at = (to != STATUS_OK).then(now);
    let placeholders: Vec<String> = (0..from.len()).map(|i| format!("${}", i + 5)).collect();
    let sql = format!(
        "UPDATE federation_peers SET status = $1, blocked_at = $2, blocked_reason = $3
         WHERE domain = $4 AND status IN ({})",
        placeholders.join(", ")
    );
    let mut q = sqlx::query(&sql).bind(to).bind(blocked_at).bind(reason).bind(domain);
    for f in from {
        q = q.bind(*f);
    }
    Ok(q.execute(db).await?.rows_affected() > 0)
}

/// Forgets every key ever seen for a peer and expires its cached document (after an operator lifted a
/// key conflict, the keys the peer publishes now are accepted on the next fetch).
pub async fn forget_keys(db: &Pool, domain: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM federation_peer_keys WHERE domain = $1").bind(domain).execute(db).await?;
    sqlx::query("UPDATE federation_peers SET expires_at = fetched_at WHERE domain = $1")
        .bind(domain)
        .execute(db)
        .await?;
    Ok(())
}

/// Peers to check now: never checked or last checked before `cutoff`, not blocked by an operator or a key
/// conflict, and federating with this node (remote users of that domain exist here, or local users
/// requested federation tokens for it).
pub async fn due_peers(db: &Pool, cutoff: &str, limit: i64) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT p.domain FROM federation_peers p
         WHERE p.status IN ('ok', 'blocked_auto')
           AND (p.conformance_checked_at IS NULL OR p.conformance_checked_at < $1)
           AND (EXISTS (SELECT 1 FROM users u WHERE u.domain = p.domain)
                OR EXISTS (SELECT 1 FROM federation_targets t WHERE t.target = p.domain))
         ORDER BY p.conformance_checked_at, p.domain LIMIT $2",
    )
    .bind(cutoff)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Latest conformance result per domain for the given domains (missing = never checked).
pub async fn results(db: &Pool, domains: &[String]) -> Result<HashMap<String, String>, ApiError> {
    if domains.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders: Vec<String> = (1..=domains.len()).map(|i| format!("${i}")).collect();
    let sql = format!(
        "SELECT domain, conformance_result FROM federation_peers
         WHERE conformance_result IS NOT NULL AND domain IN ({})",
        placeholders.join(", ")
    );
    let mut q = sqlx::query(&sql);
    for d in domains {
        q = q.bind(d);
    }
    let rows = q.fetch_all(db).await?;
    rows.iter().map(|r| Ok((r.try_get("domain")?, r.try_get("conformance_result")?))).collect()
}

// ---------------------------------------------------------------- live-traffic violations

pub async fn add_violation(db: &Pool, domain: &str, kind: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO federation_violations (id, domain, kind, at) VALUES ($1, $2, $3, $4)")
        .bind(ulid())
        .bind(domain)
        .bind(kind)
        .bind(now())
        .execute(db)
        .await?;
    sqlx::query("UPDATE federation_peers SET violations = violations + 1 WHERE domain = $1")
        .bind(domain)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn count_violations(db: &Pool, domain: &str, kind: &str, since: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT COUNT(*) AS n FROM federation_violations WHERE domain = $1 AND kind = $2 AND at >= $3")
            .bind(domain)
            .bind(kind)
            .bind(since)
            .fetch_one(db)
            .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// `(kind, count, last time)` of the violations of a peer since `since`.
pub async fn violation_summary(db: &Pool, domain: &str, since: &str) -> Result<Vec<(String, i64, String)>, ApiError> {
    let rows = sqlx::query(
        "SELECT kind, COUNT(*) AS n, MAX(at) AS last_at FROM federation_violations
         WHERE domain = $1 AND at >= $2 GROUP BY kind ORDER BY kind",
    )
    .bind(domain)
    .bind(since)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("kind")?, r.try_get("n")?, r.try_get("last_at")?))).collect()
}

// ---------------------------------------------------------------- conformance rooms (as the checked node)

/// Number of conformance rooms created for probes of `domain` since `since`.
pub async fn rooms_created_since(db: &Pool, domain: &str, since: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM conformance_rooms WHERE domain = $1 AND created_at >= $2")
        .bind(domain)
        .bind(since)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// Rooms of `domain`'s probe that still exist.
pub async fn live_rooms(db: &Pool, domain: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT room_id FROM conformance_rooms WHERE domain = $1 AND deleted_at IS NULL")
        .bind(domain)
        .fetch_all(db)
        .await?)
}

/// The checking domain of a live conformance room.
pub async fn room_domain(db: &Pool, room_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT domain FROM conformance_rooms WHERE room_id = $1 AND deleted_at IS NULL")
        .bind(room_id)
        .fetch_optional(db)
        .await?)
}

/// Live rooms whose lifetime ended before `now`.
pub async fn expired_rooms(db: &Pool, now: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT room_id FROM conformance_rooms WHERE deleted_at IS NULL AND expires_at <= $1")
        .bind(now)
        .fetch_all(db)
        .await?)
}

/// The (encrypted) text channel a new room was created with.
pub async fn text_channel(db: &Pool, room_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT id FROM channels WHERE room_id = $1 AND kind = 'text' ORDER BY position LIMIT 1")
        .bind(room_id)
        .fetch_optional(db)
        .await?)
}

pub async fn category_of(db: &Pool, channel_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<String>>("SELECT category_id FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(db)
        .await?
        .flatten())
}

pub struct NewConformanceRoom {
    pub room_id: String,
    pub plaintext_channel_id: String,
}

/// Records a new conformance room and adds its unencrypted text channel (the room itself is created
/// with `store::rooms::create_room`, whose text channel is encrypted).
pub async fn add_room(
    db: &Pool,
    room_id: &str,
    category_id: Option<&str>,
    domain: &str,
    created_at: &str,
    expires_at: &str,
) -> Result<NewConformanceRoom, ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO conformance_rooms (room_id, domain, created_at, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(room_id)
        .bind(domain)
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
    let channel_id = ulid();
    // Unencrypted on purpose: the `msg.ciphertext` check posts ciphertext there.
    sqlx::query(
        "INSERT INTO conversations (id, kind, room_id, encrypted, created_at) VALUES ($1, 'channel', $2, 0, $3)",
    )
    .bind(&channel_id)
    .bind(room_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO channels (id, room_id, category_id, kind, name, position, system_name) VALUES ($1, $2, $3, 'text', 'plaintext', 2, NULL)",
    )
    .bind(&channel_id)
    .bind(room_id)
    .bind(category_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(NewConformanceRoom { room_id: room_id.to_string(), plaintext_channel_id: channel_id })
}

pub async fn mark_room_deleted(db: &Pool, room_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE conformance_rooms SET deleted_at = $1 WHERE room_id = $2")
        .bind(now())
        .bind(room_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Forgets room records older than `cutoff` and violations older than `violations_cutoff`.
pub async fn prune(db: &Pool, cutoff: &str, violations_cutoff: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM conformance_rooms WHERE deleted_at IS NOT NULL AND created_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM federation_violations WHERE at < $1").bind(violations_cutoff).execute(db).await?;
    Ok(())
}
