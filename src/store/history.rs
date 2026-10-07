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

/// Members of the channel's room still waiting for a share, for the current membership only (a mark of a
/// membership that ended is ignored): `(user_id, username, domain, member_since)`, at most 100.
pub async fn pending_members(
    db: &Pool,
    conversation_id: &str,
    room_id: &str,
    newer_than: &str,
) -> Result<Vec<(String, String, String, String)>, ApiError> {
    let rows = sqlx::query(
        "SELECT p.user_id AS user_id, u.username AS username, u.domain AS domain, p.member_since AS member_since
         FROM history_pending p
         JOIN users u ON u.id = p.user_id
         JOIN room_members m ON m.room_id = $2 AND m.user_id = p.user_id AND m.joined_at = p.member_since
         WHERE p.conversation_id = $1 AND p.pending = 1 AND p.created_at >= $3
         ORDER BY p.created_at LIMIT 100",
    )
    .bind(conversation_id)
    .bind(room_id)
    .bind(newer_than)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("user_id")?, r.try_get("username")?, r.try_get("domain")?, r.try_get("member_since")?)))
        .collect()
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
