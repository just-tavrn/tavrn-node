// SPDX-License-Identifier: AGPL-3.0-only
//! Home-node data the client keeps on its account's node: the conversation index (FEDERATION.md §4)
//! and the session check of the connect flow (§8).

use sqlx::Row;

use crate::{db::Pool, error::ApiError, util::now};

/// The stored index: version and the JSON array of entries (as written by the client).
pub async fn conversation_index(db: &Pool, user_id: &str) -> Result<Option<(i64, String)>, ApiError> {
    let row = sqlx::query("SELECT version, items FROM conversation_index WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(match row {
        Some(r) => Some((r.try_get("version")?, r.try_get("items")?)),
        None => None,
    })
}

/// Replaces the index. With `expected` the write only succeeds if the stored version still is
/// `expected` (0 = no index yet); without it the write always succeeds (last writer wins). Returns the
/// new version, or `None` on a version conflict.
pub async fn put_conversation_index(
    db: &Pool,
    user_id: &str,
    items: &str,
    expected: Option<i64>,
) -> Result<Option<i64>, ApiError> {
    let ts = now();
    match expected {
        Some(0) => {
            let done = sqlx::query(
                "INSERT INTO conversation_index (user_id, version, items, updated_at) VALUES ($1, 1, $2, $3) \
                 ON CONFLICT (user_id) DO NOTHING",
            )
            .bind(user_id)
            .bind(items)
            .bind(&ts)
            .execute(db)
            .await?;
            Ok((done.rows_affected() == 1).then_some(1))
        }
        Some(version) => {
            let done = sqlx::query(
                "UPDATE conversation_index SET version = version + 1, items = $1, updated_at = $2 \
                 WHERE user_id = $3 AND version = $4",
            )
            .bind(items)
            .bind(&ts)
            .bind(user_id)
            .bind(version)
            .execute(db)
            .await?;
            Ok((done.rows_affected() == 1).then_some(version + 1))
        }
        None => {
            sqlx::query(
                "INSERT INTO conversation_index (user_id, version, items, updated_at) VALUES ($1, 1, $2, $3) \
                 ON CONFLICT (user_id) DO UPDATE SET version = conversation_index.version + 1, \
                 items = excluded.items, updated_at = excluded.updated_at",
            )
            .bind(user_id)
            .bind(items)
            .bind(&ts)
            .execute(db)
            .await?;
            let version: i64 = sqlx::query_scalar("SELECT version FROM conversation_index WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(db)
                .await?;
            Ok(Some(version))
        }
    }
}

/// `true` if the device has a session that is neither revoked nor expired.
pub async fn device_has_live_session(db: &Pool, device_id: &str) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(device_id)
    .bind(now())
    .fetch_one(db)
    .await?;
    Ok(n > 0)
}
