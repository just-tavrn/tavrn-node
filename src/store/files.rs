// SPDX-License-Identifier: AGPL-3.0-only
//! Entries and storage backends of files channels (protocol/FILES.md).

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    files::FileEntry,
    util::{now, ulid},
};

#[derive(Debug, Clone, FromRow)]
pub struct EntryRow {
    pub id: String,
    pub room_id: String,
    pub channel_id: String,
    pub parent_id: Option<String>,
    pub kind: String,
    pub name: String,
    pub name_key: String,
    pub storage_id: Option<String>,
    pub backend: String,
    pub encrypted: i64,
    pub mime: String,
    pub size: i64,
    pub sha256: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Entry record of an end-to-end encrypted channel (FILES.md §8.4), its epoch, writer and time.
    pub record: Option<String>,
    pub record_epoch: Option<i64>,
    pub record_author: Option<String>,
    pub record_device_id: Option<String>,
    pub record_at: Option<String>,
    /// Stored thumbnail (encrypted channels) and its size.
    pub thumbnail_id: Option<String>,
    pub thumbnail_size: i64,
}

const COLS: &str = "id, room_id, channel_id, parent_id, kind, name, name_key, storage_id, backend, encrypted, mime, \
                    size, sha256, created_by, created_at, updated_at, record, record_epoch, record_author, \
                    record_device_id, record_at, thumbnail_id, thumbnail_size";

impl EntryRow {
    pub fn is_folder(&self) -> bool {
        self.kind == "folder"
    }

    pub fn to_api(&self) -> FileEntry {
        self.to_api_cut(None)
    }

    /// Bytes the entry occupies (file and thumbnail).
    pub fn stored_bytes(&self) -> i64 {
        self.size.saturating_add(self.thumbnail_size)
    }

    /// Is the record visible for a history window that starts at `cut` (RFC 3339; FILES.md §8.7)?
    pub fn record_visible(&self, cut: Option<&str>) -> bool {
        match (cut, self.record_at.as_deref()) {
            (Some(cut), Some(at)) => at >= cut,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// The API form; the record is left out when it was written before `cut`.
    pub fn to_api_cut(&self, cut: Option<&str>) -> FileEntry {
        let visible = self.record.is_some() && self.record_visible(cut);
        let r = |v: &Option<String>| if visible { v.clone() } else { None };
        FileEntry {
            record: r(&self.record),
            record_epoch: if visible { self.record_epoch } else { None },
            record_author: r(&self.record_author),
            record_device_id: r(&self.record_device_id),
            record_at: r(&self.record_at),
            thumbnail_size: self.thumbnail_size,
            id: self.id.clone(),
            channel_id: self.channel_id.clone(),
            parent_id: self.parent_id.clone(),
            kind: self.kind.clone(),
            name: self.name.clone(),
            mime: self.mime.clone(),
            size: self.size,
            sha256: self.sha256.clone(),
            created_by: self.created_by.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

pub async fn entry(db: &Pool, channel_id: &str, id: &str) -> Result<Option<EntryRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM file_entries WHERE id = $1 AND channel_id = $2"))
        .bind(id)
        .bind(channel_id)
        .fetch_optional(db)
        .await?)
}

/// A new entry (folder: no storage, size 0).
pub struct NewEntry<'a> {
    pub id: &'a str,
    pub room_id: &'a str,
    pub channel_id: &'a str,
    pub parent_id: Option<&'a str>,
    pub kind: &'a str,
    pub name: &'a str,
    pub storage_id: Option<&'a str>,
    pub backend: &'a str,
    pub encrypted: bool,
    pub mime: &'a str,
    pub size: i64,
    pub sha256: &'a str,
    pub created_by: &'a str,
    /// Encrypted channels: the entry record (`name` and `mime` are then empty).
    pub record: Option<Record<'a>>,
}

/// An entry record as it is stored (FILES.md §8.4).
#[derive(Clone, Copy)]
pub struct Record<'a> {
    pub record: &'a str,
    pub epoch: i64,
    pub author: &'a str,
    pub device_id: &'a str,
}

/// Inserts an entry; `Ok(None)` when the name (encrypted channels: the id) is taken.
pub async fn insert(db: &Pool, e: NewEntry<'_>) -> Result<Option<EntryRow>, ApiError> {
    let ts = now();
    // Encrypted entries have no name: the id is their unique key.
    let key = if e.record.is_some() { e.id.to_string() } else { crate::files::name_key(e.name) };
    let r = sqlx::query(
        "INSERT INTO file_entries (id, room_id, channel_id, parent_id, kind, name, name_key, storage_id, backend, encrypted, mime, size, sha256, created_by, created_at, updated_at, record, record_epoch, record_author, record_device_id, record_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15, $16, $17, $18, $19, $20)",
    )
    .bind(e.id)
    .bind(e.room_id)
    .bind(e.channel_id)
    .bind(e.parent_id)
    .bind(e.kind)
    .bind(e.name)
    .bind(key)
    .bind(e.storage_id)
    .bind(e.backend)
    .bind(i64::from(e.encrypted))
    .bind(e.mime)
    .bind(e.size)
    .bind(e.sha256)
    .bind(e.created_by)
    .bind(&ts)
    .bind(e.record.map(|r| r.record))
    .bind(e.record.map(|r| r.epoch))
    .bind(e.record.map(|r| r.author))
    .bind(e.record.map(|r| r.device_id))
    .bind(e.record.map(|_| ts.clone()))
    .execute(db)
    .await;
    match r {
        Ok(_) => entry(db, e.channel_id, e.id).await,
        Err(err) if super::is_unique_violation(&err) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Is `name` taken in the folder (case-insensitive)?
pub async fn name_taken(db: &Pool, channel_id: &str, parent_id: Option<&str>, name: &str) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM file_entries WHERE channel_id = $1 AND COALESCE(parent_id, '') = $2 AND name_key = $3",
    )
    .bind(channel_id)
    .bind(parent_id.unwrap_or(""))
    .bind(crate::files::name_key(name))
    .fetch_one(db)
    .await?;
    Ok(n > 0)
}

/// Renames and/or moves an entry; `Ok(false)` when the name is taken in the target folder.
pub async fn update(db: &Pool, id: &str, name: &str, parent_id: Option<&str>) -> Result<bool, ApiError> {
    let r =
        sqlx::query("UPDATE file_entries SET name = $1, name_key = $2, parent_id = $3, updated_at = $4 WHERE id = $5")
            .bind(name)
            .bind(crate::files::name_key(name))
            .bind(parent_id)
            .bind(now())
            .bind(id)
            .execute(db)
            .await;
    match r {
        Ok(_) => Ok(true),
        Err(err) if super::is_unique_violation(&err) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Encrypted entries: a new record (rename) and/or a new folder (move).
pub async fn update_encrypted(
    db: &Pool,
    id: &str,
    record: Option<Record<'_>>,
    parent_id: Option<&str>,
) -> Result<(), ApiError> {
    let ts = now();
    match record {
        Some(r) => {
            sqlx::query(
                "UPDATE file_entries SET record = $1, record_epoch = $2, record_author = $3, record_device_id = $4,
                 record_at = $5, parent_id = $6, updated_at = $5 WHERE id = $7",
            )
            .bind(r.record)
            .bind(r.epoch)
            .bind(r.author)
            .bind(r.device_id)
            .bind(&ts)
            .bind(parent_id)
            .bind(id)
            .execute(db)
            .await?;
        }
        None => {
            sqlx::query("UPDATE file_entries SET parent_id = $1, updated_at = $2 WHERE id = $3")
                .bind(parent_id)
                .bind(&ts)
                .bind(id)
                .execute(db)
                .await?;
        }
    }
    Ok(())
}

/// Sets the thumbnail of an entry; returns the storage id of the one it replaces.
pub async fn set_thumbnail(db: &Pool, id: &str, storage_id: &str, size: i64) -> Result<Option<String>, ApiError> {
    let old: Option<Option<String>> =
        sqlx::query_scalar("SELECT thumbnail_id FROM file_entries WHERE id = $1").bind(id).fetch_optional(db).await?;
    sqlx::query("UPDATE file_entries SET thumbnail_id = $1, thumbnail_size = $2 WHERE id = $3")
        .bind(storage_id)
        .bind(size)
        .bind(id)
        .execute(db)
        .await?;
    Ok(old.flatten())
}

/// The requester's own entries, oldest first (by id), after the cursor id.
pub async fn mine(
    db: &Pool,
    channel_id: &str,
    user_id: &str,
    after: &str,
    limit: i64,
) -> Result<Vec<EntryRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM file_entries WHERE channel_id = $1 AND created_by = $2 AND id > $3 ORDER BY id LIMIT $4"
    ))
    .bind(channel_id)
    .bind(user_id)
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Files, folders and bytes (files and thumbnails) of one member's entries in a channel.
pub async fn mine_totals(db: &Pool, channel_id: &str, user_id: &str) -> Result<(i64, i64, i64), ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COALESCE(SUM(CASE WHEN kind = 'file' THEN 1 ELSE 0 END), 0) AS BIGINT) AS files,
                CAST(COALESCE(SUM(CASE WHEN kind = 'folder' THEN 1 ELSE 0 END), 0) AS BIGINT) AS folders,
                CAST(COALESCE(SUM(size + thumbnail_size), 0) AS BIGINT) AS bytes
         FROM file_entries WHERE channel_id = $1 AND created_by = $2",
    )
    .bind(channel_id)
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("files")?, row.try_get("folders")?, row.try_get("bytes")?))
}

/// Filter of [`records`].
pub struct RecordQuery<'a> {
    pub epoch: Option<i64>,
    /// Records written at or after this time (the later of the requested `since` and the history window).
    pub since: Option<&'a str>,
    /// Cursor: records after this one in (record_at, id) order.
    pub after: Option<(&'a str, &'a str)>,
    pub limit: i64,
}

/// Entries with a record, ordered by the time the record was written (FILES.md §3 `GET records`).
pub async fn records(db: &Pool, channel_id: &str, q: RecordQuery<'_>) -> Result<Vec<EntryRow>, ApiError> {
    let (at, aid) = q.after.unwrap_or(("", ""));
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM file_entries WHERE channel_id = $1 AND record IS NOT NULL
           AND ($2 < 0 OR record_epoch = $2) AND record_at >= $3
           AND (record_at > $4 OR (record_at = $4 AND id > $5))
         ORDER BY record_at, id LIMIT $6"
    ))
    .bind(channel_id)
    .bind(q.epoch.unwrap_or(-1))
    .bind(q.since.unwrap_or(""))
    .bind(at)
    .bind(aid)
    .bind(q.limit)
    .fetch_all(db)
    .await?)
}

/// Are there entry records written in `[from, before)` (history marks, ENCRYPTION.md §7b)?
pub async fn has_records_between(
    db: &Pool,
    channel_id: &str,
    from: Option<&str>,
    before: &str,
) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT id FROM file_entries WHERE channel_id = $1 AND record IS NOT NULL AND record_at >= $2 AND record_at < $3 LIMIT 1",
    )
    .bind(channel_id)
    .bind(from.unwrap_or(""))
    .bind(before)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// The cursor condition of a listing (`$3`–`$5`): entries after `after` in the order kind DESC ('folder'
/// before 'file'), name_key, id.
const AFTER: &str = "AND (kind < $3 OR (kind = $3 AND (name_key > $4 OR (name_key = $4 AND id > $5))))";

/// One page of a folder (folders first, then by name): entries after the cursor entry `after`.
pub async fn list(
    db: &Pool,
    channel_id: &str,
    parent_id: Option<&str>,
    after: Option<&EntryRow>,
    limit: i64,
) -> Result<Vec<EntryRow>, ApiError> {
    page(db, "COALESCE(parent_id, '') = $2", channel_id, parent_id.unwrap_or(""), after, limit).await
}

/// Search by name across the channel (same order and cursor as [`list`]).
pub async fn search(
    db: &Pool,
    channel_id: &str,
    pattern: &str,
    after: Option<&EntryRow>,
    limit: i64,
) -> Result<Vec<EntryRow>, ApiError> {
    page(db, "name_key LIKE $2 ESCAPE '\\'", channel_id, pattern, after, limit).await
}

async fn page(
    db: &Pool,
    filter: &str,
    channel_id: &str,
    arg: &str,
    after: Option<&EntryRow>,
    limit: i64,
) -> Result<Vec<EntryRow>, ApiError> {
    let order = "ORDER BY kind DESC, name_key, id";
    Ok(match after {
        Some(a) => {
            sqlx::query_as(&format!(
                "SELECT {COLS} FROM file_entries WHERE channel_id = $1 AND {filter} {AFTER} {order} LIMIT $6"
            ))
            .bind(channel_id)
            .bind(arg)
            .bind(&a.kind)
            .bind(&a.name_key)
            .bind(&a.id)
            .bind(limit)
            .fetch_all(db)
            .await?
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {COLS} FROM file_entries WHERE channel_id = $1 AND {filter} {order} LIMIT $3"
            ))
            .bind(channel_id)
            .bind(arg)
            .bind(limit)
            .fetch_all(db)
            .await?
        }
    })
}

/// Direct children of several folders (recursive walks, at most 500 parents per call).
pub async fn children_of(db: &Pool, channel_id: &str, parents: &[String]) -> Result<Vec<EntryRow>, ApiError> {
    let mut out = Vec::new();
    for chunk in parents.chunks(500) {
        let list = (0..chunk.len()).map(|i| format!("${}", i + 2)).collect::<Vec<_>>().join(", ");
        let sql = format!("SELECT {COLS} FROM file_entries WHERE channel_id = $1 AND parent_id IN ({list})");
        let mut q = sqlx::query_as::<_, EntryRow>(&sql).bind(channel_id);
        for p in chunk {
            q = q.bind(p);
        }
        out.extend(q.fetch_all(db).await?);
    }
    Ok(out)
}

/// Deletes entries (children before parents is not required: every id is deleted explicitly).
pub async fn delete_ids(db: &Pool, ids: &[String]) -> Result<(), ApiError> {
    for chunk in ids.chunks(500) {
        let list = (0..chunk.len()).map(|i| format!("${}", i + 1)).collect::<Vec<_>>().join(", ");
        let sql = format!("DELETE FROM file_entries WHERE id IN ({list})");
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(db).await?;
    }
    Ok(())
}

/// Bytes, files and folders of a channel.
pub async fn usage(db: &Pool, channel_id: &str) -> Result<(i64, i64, i64), ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COALESCE(SUM(size + thumbnail_size), 0) AS BIGINT) AS bytes,
                CAST(COALESCE(SUM(CASE WHEN kind = 'file' THEN 1 ELSE 0 END), 0) AS BIGINT) AS files,
                CAST(COALESCE(SUM(CASE WHEN kind = 'folder' THEN 1 ELSE 0 END), 0) AS BIGINT) AS folders
         FROM file_entries WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("bytes")?, row.try_get("files")?, row.try_get("folders")?))
}

/// Every entry of a channel or a room that holds bytes (before deleting it: internal files and external
/// objects are removed by the caller).
pub async fn stored_of(db: &Pool, column: &str, id: &str) -> Result<Vec<EntryRow>, ApiError> {
    let column = if column == "room_id" { "room_id" } else { "channel_id" };
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM file_entries WHERE {column} = $1 AND (kind = 'file' OR thumbnail_id IS NOT NULL)"
    ))
    .bind(id)
    .fetch_all(db)
    .await?)
}

/// Internal files older than `cutoff` (page by id): the orphan sweep checks that their stored file exists.
pub async fn internal_files_page(db: &Pool, cutoff: &str, after: &str, limit: i64) -> Result<Vec<EntryRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM file_entries WHERE kind = 'file' AND storage_id IS NOT NULL AND created_at < $1 AND id > $2
         ORDER BY id LIMIT $3"
    ))
    .bind(cutoff)
    .bind(after)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

// ---------------------------------------------------------------- Backends

#[derive(Debug, Clone, FromRow)]
pub struct BackendRow {
    pub channel_id: String,
    pub kind: String,
    pub config: String,
    pub encrypt_files: i64,
    pub created_by: Option<String>,
    pub updated_at: String,
}

pub async fn backend(db: &Pool, channel_id: &str) -> Result<Option<BackendRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT channel_id, kind, config, encrypt_files, created_by, updated_at FROM file_channel_backends WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_optional(db)
    .await?)
}

pub async fn set_backend(
    db: &Pool,
    channel_id: &str,
    kind: &str,
    config: &str,
    encrypt_files: bool,
    by: &str,
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM file_channel_backends WHERE channel_id = $1").bind(channel_id).execute(&mut *tx).await?;
    if kind != "internal" {
        sqlx::query(
            "INSERT INTO file_channel_backends (channel_id, kind, config, encrypt_files, created_by, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(channel_id)
        .bind(kind)
        .bind(config)
        .bind(i64::from(encrypt_files))
        .bind(by)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------- Pending external deletes

#[derive(Debug, Clone, FromRow)]
pub struct PendingDelete {
    pub id: String,
    pub channel_id: String,
    pub kind: String,
    pub config: String,
    pub object_key: String,
    pub attempts: i64,
    pub next_at: String,
    pub created_at: String,
}

const PENDING_COLS: &str = "id, channel_id, kind, config, object_key, attempts, next_at, created_at";

/// Queues objects of one store for deletion (FILES.md §6); returns the queue ids.
pub async fn enqueue_deletes(
    db: &Pool,
    channel_id: &str,
    kind: &str,
    config: &str,
    keys: &[String],
) -> Result<Vec<String>, ApiError> {
    let ts = now();
    let mut ids = Vec::with_capacity(keys.len());
    let mut tx = db.begin().await?;
    for key in keys {
        let id = ulid();
        sqlx::query(&format!(
            "INSERT INTO file_pending_deletes ({PENDING_COLS}) VALUES ($1, $2, $3, $4, $5, 0, $6, $6)"
        ))
        .bind(&id)
        .bind(channel_id)
        .bind(kind)
        .bind(config)
        .bind(key)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        ids.push(id);
    }
    tx.commit().await?;
    Ok(ids)
}

/// Queued deletes due at `now` (or the given ids), at most `limit`.
pub async fn pending_deletes(
    db: &Pool,
    now: &str,
    ids: Option<&[String]>,
    limit: i64,
) -> Result<Vec<PendingDelete>, ApiError> {
    match ids {
        Some(ids) => {
            let mut out = Vec::new();
            for chunk in ids.chunks(500) {
                let list = (0..chunk.len()).map(|i| format!("${}", i + 1)).collect::<Vec<_>>().join(", ");
                let sql = format!("SELECT {PENDING_COLS} FROM file_pending_deletes WHERE id IN ({list})");
                let mut q = sqlx::query_as::<_, PendingDelete>(&sql);
                for id in chunk {
                    q = q.bind(id);
                }
                out.extend(q.fetch_all(db).await?);
            }
            Ok(out)
        }
        None => Ok(sqlx::query_as(&format!(
            "SELECT {PENDING_COLS} FROM file_pending_deletes WHERE next_at <= $1 ORDER BY next_at, id LIMIT $2"
        ))
        .bind(now)
        .bind(limit)
        .fetch_all(db)
        .await?),
    }
}

/// Removes a queued delete (done or given up).
pub async fn delete_pending(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM file_pending_deletes WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

/// A failed attempt: retried at `next_at`.
pub async fn pending_failed(db: &Pool, id: &str, attempts: i64, next_at: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE file_pending_deletes SET attempts = $1, next_at = $2 WHERE id = $3")
        .bind(attempts)
        .bind(next_at)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// A fresh id for an entry.
pub fn new_id() -> String {
    ulid()
}

/// Is the conversation (a files channel) end-to-end encrypted?
pub async fn channel_encrypted(db: &Pool, channel_id: &str) -> Result<bool, ApiError> {
    let v: Option<i64> = sqlx::query_scalar("SELECT encrypted FROM conversations WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(db)
        .await?;
    Ok(v.unwrap_or(0) != 0)
}

/// Does any files channel have an entry with this id?
pub async fn id_exists(db: &Pool, id: &str) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_entries WHERE id = $1").bind(id).fetch_one(db).await?;
    Ok(n > 0)
}
