// SPDX-License-Identifier: AGPL-3.0-only
//! MLS leaves waiting for their removal (ENCRYPTION.md §4.7): written when the node emits `mls.remove_needed`
//! or housekeeping finds the leaf of a device that no longer exists, deleted when a commit removes the leaf.

use sqlx::Row;

use crate::{db::Pool, error::ApiError, util::now};

/// Why a leaf has to go.
pub const DELETED: &str = "deleted";
pub const UNATTESTED: &str = "unattested";
pub const NOT_MEMBER: &str = "not_member";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRemoval {
    pub conversation_id: String,
    pub identity: String,
    pub reason: String,
    pub created_at: String,
}

fn row(r: &sqlx::any::AnyRow) -> Result<PendingRemoval, ApiError> {
    Ok(PendingRemoval {
        conversation_id: r.try_get("conversation_id")?,
        identity: r.try_get("identity")?,
        reason: r.try_get("reason")?,
        created_at: r.try_get("created_at")?,
    })
}

/// Records leaves to remove; an existing row keeps its time and takes the new reason.
pub async fn insert(db: &Pool, conversation_id: &str, identities: &[String], reason: &str) -> Result<(), ApiError> {
    let ts = now();
    for identity in identities {
        sqlx::query(
            "INSERT INTO mls_pending_removals (conversation_id, identity, reason, created_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (conversation_id, identity) DO UPDATE SET reason = excluded.reason",
        )
        .bind(conversation_id)
        .bind(identity)
        .bind(reason)
        .bind(&ts)
        .execute(db)
        .await?;
    }
    Ok(())
}

/// Pending removals of one conversation, oldest first (at most 500).
pub async fn of_conversation(db: &Pool, conversation_id: &str) -> Result<Vec<PendingRemoval>, ApiError> {
    let rows = sqlx::query(
        "SELECT conversation_id, identity, reason, created_at FROM mls_pending_removals WHERE conversation_id = $1
         ORDER BY created_at, identity LIMIT 500",
    )
    .bind(conversation_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(row).collect()
}

/// Pending removals of the leaves of one user (`<address>/…`), oldest first (at most 500).
pub async fn of_address(db: &Pool, address: &str) -> Result<Vec<PendingRemoval>, ApiError> {
    let rows = sqlx::query(
        "SELECT conversation_id, identity, reason, created_at FROM mls_pending_removals
         WHERE identity >= $1 AND identity < $2 ORDER BY created_at, conversation_id LIMIT 500",
    )
    .bind(format!("{address}/"))
    .bind(format!("{address}0"))
    .fetch_all(db)
    .await?;
    rows.iter().map(row).collect()
}

/// The leaves are gone from the group (a commit removed them, or the roster no longer has them).
pub async fn clear(db: &Pool, conversation_id: &str, identities: &[String]) -> Result<u64, ApiError> {
    let mut n = 0;
    for identity in identities {
        n += sqlx::query("DELETE FROM mls_pending_removals WHERE conversation_id = $1 AND identity = $2")
            .bind(conversation_id)
            .bind(identity)
            .execute(db)
            .await?
            .rows_affected();
    }
    Ok(n)
}

/// Rows older than `cutoff` (housekeeping, 90 days).
pub async fn prune(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM mls_pending_removals WHERE created_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected())
}

/// MLS groups ordered by conversation id after `after` (`""` = from the start): the ghost scan's window.
pub async fn groups_after(db: &Pool, after: &str, limit: i64) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT conversation_id, ds_state FROM mls_groups WHERE conversation_id > $1 ORDER BY conversation_id LIMIT $2",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("conversation_id")?, r.try_get("ds_state")?))).collect()
}
