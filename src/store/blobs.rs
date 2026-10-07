// SPDX-License-Identifier: AGPL-3.0-only
use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    models::BlobRow,
    util::{now, ulid},
};

const COLS: &str =
    "id, uploader_id, conversation_id, room_id, message_id, name, mime, size, sha256, created_at, expired_at, spoiler";

pub struct NewBlob<'a> {
    pub uploader_id: &'a str,
    pub conversation_id: &'a str,
    pub room_id: Option<&'a str>,
    pub name: &'a str,
    pub mime: &'a str,
    pub size: i64,
    pub sha256: &'a str,
}

pub async fn insert(db: &Pool, b: NewBlob<'_>) -> Result<BlobRow, ApiError> {
    let id = ulid();
    sqlx::query("INSERT INTO blobs (id, uploader_id, conversation_id, room_id, name, mime, size, sha256, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
        .bind(&id)
        .bind(b.uploader_id)
        .bind(b.conversation_id)
        .bind(b.room_id)
        .bind(b.name)
        .bind(b.mime)
        .bind(b.size)
        .bind(b.sha256)
        .bind(now())
        .execute(db)
        .await?;
    by_id(db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("blob not found after INSERT")))
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<BlobRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM blobs WHERE id = $1")).bind(id).fetch_optional(db).await?)
}

pub async fn by_message(db: &Pool, message_id: &str) -> Result<Vec<BlobRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM blobs WHERE message_id = $1 ORDER BY id"))
        .bind(message_id)
        .fetch_all(db)
        .await?)
}

/// Ids per `IN (…)` list: far below the bind limits of PostgreSQL (65535) and SQLite (32766).
const IN_CHUNK: usize = 500;

/// `$start, $start+1, …` for `n` bound values (the values themselves are always bound, never inlined).
fn placeholders(start: usize, n: usize) -> String {
    (start..start + n).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ")
}

/// Attachments of several messages in one query per chunk (message id → blobs ordered by id).
pub async fn by_messages(
    db: &Pool,
    message_ids: &[String],
) -> Result<std::collections::HashMap<String, Vec<BlobRow>>, ApiError> {
    let mut out: std::collections::HashMap<String, Vec<BlobRow>> = std::collections::HashMap::new();
    for chunk in message_ids.chunks(IN_CHUNK) {
        let sql =
            format!("SELECT {COLS} FROM blobs WHERE message_id IN ({}) ORDER BY id", placeholders(1, chunk.len()));
        let mut q = sqlx::query_as::<_, BlobRow>(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        for blob in q.fetch_all(db).await? {
            if let Some(message_id) = blob.message_id.clone() {
                out.entry(message_id).or_default().push(blob);
            }
        }
    }
    Ok(out)
}

/// Binds the author's still unbound blobs in this conversation to a message. Returns the bound IDs.
pub async fn bind_to_message(
    db: &Pool,
    blob_ids: &[String],
    message_id: &str,
    author_id: &str,
    conversation_id: &str,
) -> Result<Vec<String>, ApiError> {
    let mut bound = Vec::new();
    for id in blob_ids {
        let r = sqlx::query("UPDATE blobs SET message_id = $1 WHERE id = $2 AND message_id IS NULL AND uploader_id = $3 AND conversation_id = $4")
            .bind(message_id)
            .bind(id)
            .bind(author_id)
            .bind(conversation_id)
            .execute(db)
            .await?;
        if r.rows_affected() > 0 {
            bound.push(id.clone());
        }
    }
    Ok(bound)
}

/// Marks bound attachments of a plaintext message as spoilers.
pub async fn mark_spoilers(db: &Pool, message_id: &str, blob_ids: &[String]) -> Result<(), ApiError> {
    for id in blob_ids {
        sqlx::query("UPDATE blobs SET spoiler = 1 WHERE id = $1 AND message_id = $2")
            .bind(id)
            .bind(message_id)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// Of `ids`, those that name an existing message (replies whose original was deleted are not among them).
pub async fn existing_messages(db: &Pool, ids: &[String]) -> Result<std::collections::HashSet<String>, ApiError> {
    let mut out = std::collections::HashSet::new();
    for chunk in ids.chunks(500) {
        let sql = format!("SELECT id FROM messages WHERE id IN ({})", placeholders(1, chunk.len()));
        let mut q = sqlx::query_as::<_, (String,)>(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        out.extend(q.fetch_all(db).await?.into_iter().map(|(id,)| id));
    }
    Ok(out)
}

pub async fn room_usage(db: &Pool, room_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS n FROM blobs WHERE room_id = $1 AND expired_at IS NULL",
    )
    .bind(room_id)
    .fetch_one(db)
    .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// Storage used by one conversation (quota of DMs and group DMs, which have no room).
pub async fn conversation_usage(db: &Pool, conversation_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS n FROM blobs WHERE conversation_id = $1 AND expired_at IS NULL")
        .bind(conversation_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// IDs of the blobs belonging to the given messages (query before deleting the messages).
pub async fn ids_for_messages(db: &Pool, filter_sql: &str, binds: &[String]) -> Result<Vec<String>, ApiError> {
    let sql = format!("SELECT id FROM blobs WHERE message_id IN (SELECT id FROM messages WHERE {filter_sql})");
    let mut q = sqlx::query(&sql);
    for b in binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

/// Ids of every upload of a conversation (before deleting the conversation; the rows cascade).
pub async fn ids_of_conversation(db: &Pool, conversation_id: &str) -> Result<Vec<String>, ApiError> {
    let rows =
        sqlx::query("SELECT id FROM blobs WHERE conversation_id = $1").bind(conversation_id).fetch_all(db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

/// Ids of every upload in a room's conversations (before deleting the room).
pub async fn ids_of_room(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT id FROM blobs WHERE room_id = $1 OR conversation_id IN (SELECT id FROM conversations WHERE room_id = $1)",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

pub async fn delete_rows(db: &Pool, ids: &[String]) -> Result<(), ApiError> {
    for id in ids {
        sqlx::query("DELETE FROM blobs WHERE id = $1").bind(id).execute(db).await?;
    }
    Ok(())
}

/// Attachments due for deletion by retention: bound to a message, not expired yet, uploaded
/// before `cutoff`, not attached to a pinned message; all conversations, or only the room `room_id`.
pub async fn retention_candidates(
    db: &Pool,
    cutoff: &str,
    room_id: Option<&str>,
    limit: i64,
) -> Result<Vec<String>, ApiError> {
    let room_filter = if room_id.is_some() { "AND b.room_id = $3" } else { "AND $3 = ''" };
    let sql = format!(
        "SELECT b.id FROM blobs b WHERE b.message_id IS NOT NULL AND b.expired_at IS NULL AND b.created_at < $1 {room_filter}
           AND NOT EXISTS (SELECT 1 FROM pins p WHERE p.message_id = b.message_id)
         ORDER BY b.created_at LIMIT $2"
    );
    let rows = sqlx::query(&sql).bind(cutoff).bind(limit).bind(room_id.unwrap_or("")).fetch_all(db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

/// Marks attachments as expired (their files are already deleted).
pub async fn mark_expired(db: &Pool, ids: &[String]) -> Result<(), ApiError> {
    let ts = now();
    for chunk in ids.chunks(IN_CHUNK) {
        let sql = format!("UPDATE blobs SET expired_at = $1 WHERE id IN ({})", placeholders(2, chunk.len()));
        let mut q = sqlx::query(&sql).bind(&ts);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(db).await?;
    }
    Ok(())
}

/// Unbound blobs older than `before` (cleanup of orphaned uploads).
pub async fn orphans_before(db: &Pool, before: &str, limit: i64) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT id FROM blobs WHERE message_id IS NULL AND created_at < $1 LIMIT $2")
        .bind(before)
        .bind(limit)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

// ---------------------------------------------------------------- Encryption at rest

/// The wrapped key of an encrypted stored file (`blob_keys`, see `storage.rs`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlobKeyRow {
    pub storage_id: String,
    pub wrapped_key: String,
    pub wrap_nonce: String,
    pub key_id: String,
    pub enc_version: i64,
}

/// Values of a `blob_keys` row to write.
#[derive(Debug, Clone)]
pub struct NewBlobKey {
    pub wrapped_key: String,
    pub wrap_nonce: String,
    pub key_id: String,
    pub enc_version: i64,
}

const KEY_COLS: &str = "storage_id, wrapped_key, wrap_nonce, key_id, enc_version";

pub async fn blob_key(db: &Pool, storage_id: &str) -> Result<Option<BlobKeyRow>, sqlx::Error> {
    sqlx::query_as(&format!("SELECT {KEY_COLS} FROM blob_keys WHERE storage_id = $1"))
        .bind(storage_id)
        .fetch_optional(db)
        .await
}

/// Inserts or replaces the key row of a stored file.
pub async fn put_blob_key(db: &Pool, storage_id: &str, k: &NewBlobKey) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO blob_keys (storage_id, wrapped_key, wrap_nonce, key_id, enc_version, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (storage_id) DO UPDATE SET wrapped_key = excluded.wrapped_key, wrap_nonce = excluded.wrap_nonce,
           key_id = excluded.key_id, enc_version = excluded.enc_version",
    )
    .bind(storage_id)
    .bind(&k.wrapped_key)
    .bind(&k.wrap_nonce)
    .bind(&k.key_id)
    .bind(k.enc_version)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_blob_key(db: &Pool, storage_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM blob_keys WHERE storage_id = $1").bind(storage_id).execute(db).await?;
    Ok(())
}

/// Storage key fingerprints in use and how many files each wraps.
pub async fn blob_key_ids(db: &Pool) -> Result<Vec<(String, i64)>, sqlx::Error> {
    sqlx::query_as("SELECT key_id, COUNT(*) AS n FROM blob_keys GROUP BY key_id ORDER BY key_id").fetch_all(db).await
}

/// Up to `limit` rows wrapped with the storage key `key_id` (rotation).
pub async fn blob_keys_wrapped_by(db: &Pool, key_id: &str, limit: i64) -> Result<Vec<BlobKeyRow>, sqlx::Error> {
    sqlx::query_as(&format!("SELECT {KEY_COLS} FROM blob_keys WHERE key_id = $1 ORDER BY storage_id LIMIT $2"))
        .bind(key_id)
        .bind(limit)
        .fetch_all(db)
        .await
}

/// Replaces a wrapped key if it is still wrapped with `old_key_id`.
pub async fn rewrap_blob_key(
    db: &Pool,
    storage_id: &str,
    old_key_id: &str,
    k: &NewBlobKey,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE blob_keys SET wrapped_key = $1, wrap_nonce = $2, key_id = $3 WHERE storage_id = $4 AND key_id = $5",
    )
    .bind(&k.wrapped_key)
    .bind(&k.wrap_nonce)
    .bind(&k.key_id)
    .bind(storage_id)
    .bind(old_key_id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------- Reactions

pub async fn add_reaction(db: &Pool, message_id: &str, user_id: &str, emoji: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("INSERT INTO reactions (message_id, user_id, emoji, created_at) VALUES ($1, $2, $3, $4)")
        .bind(message_id)
        .bind(user_id)
        .bind(emoji)
        .bind(now())
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_reaction(db: &Pool, message_id: &str, user_id: &str, emoji: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji = $3")
        .bind(message_id)
        .bind(user_id)
        .bind(emoji)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// (emoji, count, whether the user reacted) per message, in the order of the first reaction.
/// One query per chunk of messages instead of one per message.
pub async fn reactions_for(
    db: &Pool,
    message_ids: &[String],
    user_id: &str,
) -> Result<std::collections::HashMap<String, Vec<(String, i64, bool)>>, ApiError> {
    let mut out: std::collections::HashMap<String, Vec<(String, i64, bool)>> = std::collections::HashMap::new();
    for chunk in message_ids.chunks(IN_CHUNK) {
        let sql = format!(
            "SELECT message_id, emoji, COUNT(*) AS n, CAST(SUM(CASE WHEN user_id = $1 THEN 1 ELSE 0 END) AS BIGINT) AS me \
             FROM reactions WHERE message_id IN ({}) GROUP BY message_id, emoji ORDER BY message_id, MIN(created_at), emoji",
            placeholders(2, chunk.len())
        );
        let mut q = sqlx::query(&sql).bind(user_id);
        for id in chunk {
            q = q.bind(id);
        }
        for r in q.fetch_all(db).await? {
            out.entry(r.try_get::<String, _>("message_id")?).or_default().push((
                r.try_get::<String, _>("emoji")?,
                r.try_get::<i64, _>("n")?,
                r.try_get::<i64, _>("me")? > 0,
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- Pins

pub async fn pin(db: &Pool, conversation_id: &str, message_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("INSERT INTO pins (conversation_id, message_id, pinned_by, pinned_at) VALUES ($1, $2, $3, $4)")
        .bind(conversation_id)
        .bind(message_id)
        .bind(user_id)
        .bind(now())
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn unpin(db: &Pool, conversation_id: &str, message_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM pins WHERE conversation_id = $1 AND message_id = $2")
        .bind(conversation_id)
        .bind(message_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Which of `message_ids` are pinned in the conversation (one query per chunk, uses the primary key).
pub async fn pinned_among(
    db: &Pool,
    conversation_id: &str,
    message_ids: &[String],
) -> Result<std::collections::HashSet<String>, ApiError> {
    let mut out = std::collections::HashSet::new();
    for chunk in message_ids.chunks(IN_CHUNK) {
        let sql = format!(
            "SELECT message_id FROM pins WHERE conversation_id = $1 AND message_id IN ({})",
            placeholders(2, chunk.len())
        );
        let mut q = sqlx::query(&sql).bind(conversation_id);
        for id in chunk {
            q = q.bind(id);
        }
        for r in q.fetch_all(db).await? {
            out.insert(r.try_get::<String, _>("message_id")?);
        }
    }
    Ok(out)
}

pub async fn pinned_ids(db: &Pool, conversation_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT message_id FROM pins WHERE conversation_id = $1 ORDER BY pinned_at DESC")
        .bind(conversation_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get::<String, _>("message_id").map_err(Into::into)).collect()
}

pub async fn pin_count(db: &Pool, conversation_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM pins WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}
