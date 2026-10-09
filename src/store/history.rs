// SPDX-License-Identifier: AGPL-3.0-only
//! History key shares and pending marks of new members (ENCRYPTION.md §7b).

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util};

#[derive(Debug, Clone, FromRow)]
pub struct ShareRow {
    pub id: String,
    pub conversation_id: String,
    pub to_user: String,
    pub from_user: String,
    pub from_device: String,
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub ciphertext: String,
    pub created_at: String,
    pub acked_at: Option<String>,
}

const SHARE_COLS: &str =
    "id, conversation_id, to_user, from_user, from_device, epoch_from, epoch_to, ciphertext, created_at, acked_at";

pub struct NewShare<'a> {
    pub conversation_id: &'a str,
    pub to_user: &'a str,
    pub from_user: &'a str,
    pub from_device: &'a str,
    pub epoch_from: i64,
    pub epoch_to: i64,
    pub ciphertext: &'a str,
}

pub async fn insert_share(db: &Pool, s: NewShare<'_>) -> Result<String, ApiError> {
    let id = util::ulid();
    sqlx::query(
        "INSERT INTO history_key_shares (id, conversation_id, to_user, from_user, from_device, epoch_from, epoch_to, ciphertext, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(s.conversation_id)
    .bind(s.to_user)
    .bind(s.from_user)
    .bind(s.from_device)
    .bind(s.epoch_from)
    .bind(s.epoch_to)
    .bind(s.ciphertext)
    .bind(util::now())
    .execute(db)
    .await?;
    Ok(id)
}

/// Shares for `to_user` in the conversation created since `since` (acknowledged ones included): the rate limit.
pub async fn count_since(db: &Pool, conversation_id: &str, to_user: &str, since: &str) -> Result<i64, ApiError> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM history_key_shares WHERE conversation_id = $1 AND to_user = $2 AND created_at >= $3",
    )
    .bind(conversation_id)
    .bind(to_user)
    .bind(since)
    .fetch_one(db)
    .await?;
    Ok(row.try_get("n")?)
}

/// Unacknowledged shares addressed to `to_user`, oldest first.
pub async fn shares_for(
    db: &Pool,
    conversation_id: &str,
    to_user: &str,
    limit: i64,
) -> Result<Vec<ShareRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {SHARE_COLS} FROM history_key_shares WHERE conversation_id = $1 AND to_user = $2 AND acked_at IS NULL
         ORDER BY created_at, id LIMIT $3"
    ))
    .bind(conversation_id)
    .bind(to_user)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Marks a share of `to_user` as acknowledged; `false` if there is no such unacknowledged share.
pub async fn ack(db: &Pool, conversation_id: &str, to_user: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE history_key_shares SET acked_at = $1, ciphertext = ''
         WHERE id = $2 AND conversation_id = $3 AND to_user = $4 AND acked_at IS NULL",
    )
    .bind(util::now())
    .bind(id)
    .bind(conversation_id)
    .bind(to_user)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// `member_since` of the user's pending mark in the conversation (pending or already handled).
pub async fn pending_since(db: &Pool, conversation_id: &str, user_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT member_since FROM history_pending WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get("member_since")).transpose()?)
}

/// Records the membership `member_since` as handled; `pending` = still waiting for a share.
pub async fn set_pending(
    db: &Pool,
    conversation_id: &str,
    user_id: &str,
    member_since: &str,
    pending: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO history_pending (conversation_id, user_id, member_since, pending, created_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (conversation_id, user_id) DO UPDATE SET member_since = $3, pending = $4, created_at = $5",
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(member_since)
    .bind(pending as i64)
    .bind(util::now())
    .execute(db)
    .await?;
    Ok(())
}

/// The member acknowledged a share: no longer pending.
pub async fn clear_pending(db: &Pool, conversation_id: &str, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE history_pending SET pending = 0 WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// A member still waiting for a share.
#[derive(Debug, Clone, FromRow)]
pub struct PendingRow {
    pub user_id: String,
    pub username: String,
    pub domain: String,
    pub member_since: String,
    /// The membership's `key_reset_at` (ENCRYPTION.md §7b "History after a key reset").
    pub key_reset_at: Option<String>,
}

/// Members of the channel's room still waiting for a share, for the current membership only (a mark of a
/// membership that ended is ignored; after a key reset the mark belongs to the reset), at most 100.
pub async fn pending_members(
    db: &Pool,
    conversation_id: &str,
    room_id: &str,
    newer_than: &str,
) -> Result<Vec<PendingRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT p.user_id AS user_id, u.username AS username, u.domain AS domain, p.member_since AS member_since,
                m.key_reset_at AS key_reset_at
         FROM history_pending p
         JOIN users u ON u.id = p.user_id
         JOIN room_members m ON m.room_id = $2 AND m.user_id = p.user_id
              AND (m.joined_at = p.member_since OR m.key_reset_at = p.member_since)
         WHERE p.conversation_id = $1 AND p.pending = 1 AND p.created_at >= $3
         ORDER BY p.created_at LIMIT 100",
    )
    .bind(conversation_id)
    .bind(room_id)
    .bind(newer_than)
    .fetch_all(db)
    .await?)
}

/// Is there an encrypted message older than `before` (a ULID floor) and, with `from`, not older than `from`?
pub async fn has_encrypted_before(
    db: &Pool,
    conversation_id: &str,
    before: &str,
    from: Option<&str>,
) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT id FROM messages WHERE conversation_id = $1 AND encrypted = 1 AND id < $2 AND id >= $3 LIMIT 1",
    )
    .bind(conversation_id)
    .bind(before)
    .bind(from.unwrap_or(""))
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// `joined_at` of a group DM member.
pub async fn direct_joined_at(db: &Pool, conversation_id: &str, user_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT joined_at FROM conversation_members WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get("joined_at")).transpose()?)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct HistoryPrune {
    pub shares: u64,
    pub pending: u64,
}

/// Housekeeping: shares acknowledged before `acked_before` or created before `older_than`, and pending
/// marks created before `older_than`.
pub async fn prune(db: &Pool, acked_before: &str, older_than: &str) -> Result<HistoryPrune, ApiError> {
    let shares =
        sqlx::query("DELETE FROM history_key_shares WHERE (acked_at IS NOT NULL AND acked_at < $1) OR created_at < $2")
            .bind(acked_before)
            .bind(older_than)
            .execute(db)
            .await?
            .rows_affected();
    let pending = sqlx::query("DELETE FROM history_pending WHERE created_at < $1")
        .bind(older_than)
        .execute(db)
        .await?
        .rows_affected();
    Ok(HistoryPrune { shares, pending })
}

/// Sets a channel's `history_for_new_members` (validated by the caller).
pub async fn set_policy(db: &Pool, channel_id: &str, policy: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE channels SET history_for_new_members = $1 WHERE id = $2")
        .bind(policy)
        .bind(channel_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- history after a key reset

/// The user's identity key was reset at `at`: every room membership of the user gets `key_reset_at` (an earlier
/// restore is dropped) and every encrypted group of those rooms records its current epoch as the user's reset
/// epoch. Returns the number of memberships.
pub async fn mark_key_reset(db: &Pool, user_id: &str, at: &str) -> Result<u64, ApiError> {
    let n = sqlx::query("UPDATE room_members SET key_reset_at = $1, history_restored_at = NULL WHERE user_id = $2")
        .bind(at)
        .bind(user_id)
        .execute(db)
        .await?
        .rows_affected();
    // `WHERE` before `ON CONFLICT`: SQLite needs it to parse an upsert from a SELECT.
    sqlx::query(
        "INSERT INTO history_reset_epochs (conversation_id, user_id, epoch)
         SELECT g.conversation_id, $1, g.epoch FROM mls_groups g
         JOIN channels c ON c.id = g.conversation_id
         JOIN room_members m ON m.room_id = c.room_id AND m.user_id = $1
         WHERE g.epoch >= 0
         ON CONFLICT (conversation_id, user_id) DO UPDATE SET epoch = excluded.epoch",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(n)
}

/// The group epoch of the conversation at the user's last key reset (None: no group then, nothing before it).
pub async fn reset_epoch(db: &Pool, conversation_id: &str, user_id: &str) -> Result<Option<i64>, ApiError> {
    let row = sqlx::query("SELECT epoch FROM history_reset_epochs WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get("epoch")).transpose()?)
}

/// A restore of the membership was approved at `at`.
pub async fn set_restored(db: &Pool, room_id: &str, user_id: &str, at: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET history_restored_at = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(at)
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// The room setting `history_restore` (validated by the caller).
pub async fn set_room_setting(db: &Pool, room_id: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE rooms SET history_restore = $1 WHERE id = $2").bind(value).bind(room_id).execute(db).await?;
    Ok(())
}

/// A membership ended: its open requests are cancelled and its reset epochs in the room's channels dropped.
pub async fn membership_ended(db: &Pool, room_id: &str, user_id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE history_requests SET status = 'cancelled', decided_at = $1 WHERE room_id = $2 AND user_id = $3 AND status = 'open'",
    )
    .bind(util::now())
    .bind(room_id)
    .bind(user_id)
    .execute(db)
    .await?;
    sqlx::query(
        "DELETE FROM history_reset_epochs WHERE user_id = $1 AND conversation_id IN (SELECT id FROM channels WHERE room_id = $2)",
    )
    .bind(user_id)
    .bind(room_id)
    .execute(db)
    .await?;
    Ok(())
}

/// The room's owner and the members whose roles hold `restore_history` or `administrator`.
pub async fn restorer_ids(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let mask = (crate::permissions::RESTORE_HISTORY | crate::permissions::ADMINISTRATOR) as i64;
    let rows = sqlx::query(
        "SELECT owner_id AS user_id FROM rooms WHERE id = $1
         UNION
         SELECT mr.user_id FROM member_roles mr JOIN roles r ON r.id = mr.role_id WHERE mr.room_id = $1 AND (r.permissions & $2) <> 0",
    )
    .bind(room_id)
    .bind(mask)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}

#[derive(Debug, Clone, FromRow)]
pub struct RequestRow {
    pub id: String,
    pub room_id: String,
    pub user_id: String,
    pub member_since: String,
    pub message: String,
    pub status: String,
    pub created_at: String,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
    pub reason: Option<String>,
    pub partial: i64,
}

const REQUEST_COLS: &str =
    "id, room_id, user_id, member_since, message, status, created_at, decided_at, decided_by, reason, partial";

/// A new open request; `None` when the member already has an open one in the room (the unique index).
pub async fn insert_request(
    db: &Pool,
    room_id: &str,
    user_id: &str,
    member_since: &str,
    message: &str,
) -> Result<Option<RequestRow>, ApiError> {
    let id = util::ulid();
    let now = util::now();
    let inserted = sqlx::query(
        "INSERT INTO history_requests (id, room_id, user_id, member_since, message, status, created_at, partial)
         VALUES ($1, $2, $3, $4, $5, 'open', $6, 0) ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(room_id)
    .bind(user_id)
    .bind(member_since)
    .bind(message)
    .bind(&now)
    .execute(db)
    .await?
    .rows_affected();
    if inserted == 0 {
        return Ok(None);
    }
    request(db, room_id, &id).await
}

pub async fn request(db: &Pool, room_id: &str, id: &str) -> Result<Option<RequestRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {REQUEST_COLS} FROM history_requests WHERE id = $1 AND room_id = $2"))
        .bind(id)
        .bind(room_id)
        .fetch_optional(db)
        .await?)
}

/// The member's latest request of the membership that started at `member_since`.
pub async fn latest_request(
    db: &Pool,
    room_id: &str,
    user_id: &str,
    member_since: &str,
) -> Result<Option<RequestRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {REQUEST_COLS} FROM history_requests WHERE room_id = $1 AND user_id = $2 AND member_since = $3
         ORDER BY created_at DESC, id DESC LIMIT 1"
    ))
    .bind(room_id)
    .bind(user_id)
    .bind(member_since)
    .fetch_optional(db)
    .await?)
}

pub async fn has_open_request(db: &Pool, room_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT id FROM history_requests WHERE room_id = $1 AND user_id = $2 AND status = 'open'")
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

/// Requests of the member in the room created since `since` (every status): the rate limit.
pub async fn count_requests_since(db: &Pool, room_id: &str, user_id: &str, since: &str) -> Result<i64, ApiError> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM history_requests WHERE room_id = $1 AND user_id = $2 AND created_at >= $3",
    )
    .bind(room_id)
    .bind(user_id)
    .bind(since)
    .fetch_one(db)
    .await?;
    Ok(row.try_get("n")?)
}

/// Open requests of current members (oldest first, at most 100).
pub async fn open_requests(db: &Pool, room_id: &str) -> Result<Vec<RequestRow>, ApiError> {
    let cols = REQUEST_COLS.split(", ").map(|c| format!("h.{c}")).collect::<Vec<_>>().join(", ");
    Ok(sqlx::query_as(&format!(
        "SELECT {cols} FROM history_requests h
         JOIN room_members m ON m.room_id = h.room_id AND m.user_id = h.user_id AND m.joined_at = h.member_since
         WHERE h.room_id = $1 AND h.status = 'open' ORDER BY h.created_at, h.id LIMIT 100"
    ))
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

/// Decides an open request (`approved` or `denied`); `false` if it is not open (any more).
pub async fn decide(
    db: &Pool,
    id: &str,
    status: &str,
    by: &str,
    reason: Option<&str>,
    partial: bool,
) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE history_requests SET status = $1, decided_at = $2, decided_by = $3, reason = $4, partial = $5
         WHERE id = $6 AND status = 'open'",
    )
    .bind(status)
    .bind(util::now())
    .bind(by)
    .bind(reason)
    .bind(partial as i64)
    .bind(id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// The requester cancels its open request; `false` if there is no such open request.
pub async fn cancel(db: &Pool, room_id: &str, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE history_requests SET status = 'cancelled', decided_at = $1
         WHERE id = $2 AND room_id = $3 AND user_id = $4 AND status = 'open'",
    )
    .bind(util::now())
    .bind(id)
    .bind(room_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Housekeeping: decided and cancelled requests decided before `decided_before`.
pub async fn prune_requests(db: &Pool, decided_before: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM history_requests WHERE status <> 'open' AND decided_at < $1")
        .bind(decided_before)
        .execute(db)
        .await?
        .rows_affected())
}
