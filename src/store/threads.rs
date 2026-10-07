// SPDX-License-Identifier: AGPL-3.0-only
//! Threads of room channels (PROTOCOL.md §7e): the thread rows, their followers with per-thread read markers, and
//! the counters. Thread messages are rows of `messages` with `thread_id` set.

use std::collections::HashMap;

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util::now};

#[derive(Debug, Clone, FromRow)]
pub struct ThreadRow {
    pub id: String,
    pub channel_id: String,
    pub room_id: String,
    pub root_message_id: Option<String>,
    /// Plaintext, or content-format ciphertext when `title_epoch` is set.
    pub title: String,
    pub title_epoch: Option<i64>,
    pub title_author_id: String,
    pub title_author_username: String,
    pub title_author_domain: String,
    pub title_device_id: Option<String>,
    /// JSON list of tag ids.
    pub tags: String,
    pub created_by: String,
    pub created_by_username: String,
    pub created_by_domain: String,
    pub created_at: String,
    pub last_message_id: Option<String>,
    pub last_message_at: String,
    pub message_count: i64,
    pub archived_at: Option<String>,
    pub locked: i64,
}

impl ThreadRow {
    pub fn tag_ids(&self) -> Vec<String> {
        serde_json::from_str(&self.tags).unwrap_or_default()
    }
    pub fn is_locked(&self) -> bool {
        self.locked != 0
    }
}

const COLS: &str = "t.id, t.channel_id, c.room_id, t.root_message_id, t.title, t.title_epoch, t.title_author_id, ta.username AS title_author_username, ta.domain AS title_author_domain, t.title_device_id, t.tags, t.created_by, cu.username AS created_by_username, cu.domain AS created_by_domain, t.created_at, t.last_message_id, t.last_message_at, t.message_count, t.archived_at, t.locked";
const FROM: &str = "FROM threads t JOIN channels c ON c.id = t.channel_id JOIN users ta ON ta.id = t.title_author_id JOIN users cu ON cu.id = t.created_by";

fn placeholders(start: usize, n: usize) -> String {
    (start..start + n).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ")
}

/// The title of a thread with who set it (`epoch` and `device_id` for ciphertext).
pub struct Title<'a> {
    pub text: &'a str,
    pub epoch: Option<i64>,
    pub author_id: &'a str,
    pub device_id: Option<&'a str>,
}

pub struct NewThread<'a> {
    pub id: &'a str,
    pub channel_id: &'a str,
    pub root_message_id: Option<&'a str>,
    pub title: Title<'a>,
    pub tags: &'a [String],
    pub created_by: &'a str,
}

/// Inserts a thread. `Ok(false)` when its root already has a thread (unique root).
pub async fn insert(db: &Pool, t: NewThread<'_>) -> Result<bool, ApiError> {
    let at = now();
    let r = sqlx::query(
        "INSERT INTO threads (id, channel_id, root_message_id, title, title_epoch, title_author_id, title_device_id, tags, created_by, created_at, last_message_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)",
    )
    .bind(t.id)
    .bind(t.channel_id)
    .bind(t.root_message_id)
    .bind(t.title.text)
    .bind(t.title.epoch)
    .bind(t.title.author_id)
    .bind(t.title.device_id)
    .bind(serde_json::to_string(t.tags).unwrap_or_else(|_| "[]".into()))
    .bind(t.created_by)
    .bind(&at)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<ThreadRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} {FROM} WHERE t.id = $1")).bind(id).fetch_optional(db).await?)
}

/// The thread started from `root_message_id`, if any.
pub async fn id_by_root(db: &Pool, root_message_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT id FROM threads WHERE root_message_id = $1")
        .bind(root_message_id)
        .fetch_optional(db)
        .await?)
}

/// The threads started from these root messages.
pub async fn by_roots(db: &Pool, root_ids: &[String]) -> Result<Vec<ThreadRow>, ApiError> {
    let mut out = Vec::new();
    for chunk in root_ids.chunks(200) {
        let sql = format!("SELECT {COLS} {FROM} WHERE t.root_message_id IN ({})", placeholders(1, chunk.len()));
        let mut q = sqlx::query_as::<_, ThreadRow>(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        out.extend(q.fetch_all(db).await?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archived {
    Active,
    Archived,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Activity,
    Created,
}

pub struct ListFilter<'a> {
    pub channel_id: &'a str,
    pub archived: Archived,
    /// A tag id (validated ULID).
    pub tag: Option<&'a str>,
    pub sort: Sort,
    /// The last thread of the previous page.
    pub before: Option<&'a ThreadRow>,
    pub limit: i64,
}

/// A page of a channel's threads.
pub async fn list(db: &Pool, f: ListFilter<'_>) -> Result<Vec<ThreadRow>, ApiError> {
    let mut clauses = vec!["t.channel_id = $1".to_string()];
    let mut binds: Vec<String> = vec![f.channel_id.to_string()];
    match f.archived {
        Archived::Active => clauses.push("t.archived_at IS NULL".into()),
        Archived::Archived => clauses.push("t.archived_at IS NOT NULL".into()),
        Archived::All => {}
    }
    if let Some(tag) = f.tag {
        binds.push(format!("%\"{tag}\"%"));
        clauses.push(format!("t.tags LIKE ${}", binds.len()));
    }
    let order = match (f.sort, f.before) {
        (Sort::Activity, Some(b)) => {
            binds.push(b.last_message_at.clone());
            binds.push(b.id.clone());
            let (a, i) = (binds.len() - 1, binds.len());
            clauses.push(format!("(t.last_message_at < ${a} OR (t.last_message_at = ${a} AND t.id < ${i}))"));
            "t.last_message_at DESC, t.id DESC"
        }
        (Sort::Activity, None) => "t.last_message_at DESC, t.id DESC",
        (Sort::Created, Some(b)) => {
            binds.push(b.id.clone());
            clauses.push(format!("t.id < ${}", binds.len()));
            "t.id DESC"
        }
        (Sort::Created, None) => "t.id DESC",
    };
    let sql = format!("SELECT {COLS} {FROM} WHERE {} ORDER BY {order} LIMIT {}", clauses.join(" AND "), f.limit.max(1));
    let mut q = sqlx::query_as::<_, ThreadRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.fetch_all(db).await?)
}

/// Changes of `PATCH /threads/{id}`; `None` = unchanged.
#[derive(Default)]
pub struct Update<'a> {
    pub title: Option<Title<'a>>,
    pub tags: Option<&'a [String]>,
    /// `Some(Some(t))` archives at `t`, `Some(None)` reopens.
    pub archived_at: Option<Option<&'a str>>,
    pub locked: Option<bool>,
}

pub async fn update(db: &Pool, id: &str, u: Update<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    if let Some(t) = &u.title {
        sqlx::query("UPDATE threads SET title = $1, title_epoch = $2, title_author_id = $3, title_device_id = $4 WHERE id = $5")
            .bind(t.text)
            .bind(t.epoch)
            .bind(t.author_id)
            .bind(t.device_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(tags) = u.tags {
        sqlx::query("UPDATE threads SET tags = $1 WHERE id = $2")
            .bind(serde_json::to_string(tags).unwrap_or_else(|_| "[]".into()))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(archived_at) = u.archived_at {
        sqlx::query("UPDATE threads SET archived_at = $1 WHERE id = $2").bind(archived_at).bind(id).execute(&mut *tx).await?;
    }
    if let Some(locked) = u.locked {
        sqlx::query("UPDATE threads SET locked = $1 WHERE id = $2").bind(locked as i64).bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// A new message in the thread: counters, last activity, and an archived thread reopens unless it is locked.
pub async fn record_message(db: &Pool, id: &str, message_id: &str, created_at: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE threads SET message_count = message_count + 1, last_message_id = $2, last_message_at = $3,
           archived_at = CASE WHEN locked = 0 THEN NULL ELSE archived_at END
         WHERE id = $1",
    )
    .bind(id)
    .bind(message_id)
    .bind(created_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Counts the messages of these threads again (after deletions); the last activity time stays.
pub async fn recount(db: &Pool, ids: &[String]) -> Result<(), ApiError> {
    for chunk in ids.chunks(200) {
        let sql = format!(
            "UPDATE threads SET message_count = (SELECT COUNT(*) FROM messages m WHERE m.thread_id = threads.id),
               last_message_id = (SELECT MAX(m.id) FROM messages m WHERE m.thread_id = threads.id)
             WHERE id IN ({})",
            placeholders(1, chunk.len())
        );
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(db).await?;
    }
    Ok(())
}

/// The threads holding messages that match a purge filter (`filter_sql` over `messages`).
pub async fn ids_for_messages(db: &Pool, filter_sql: &str, binds: &[String]) -> Result<Vec<String>, ApiError> {
    let sql = format!("SELECT DISTINCT thread_id FROM messages WHERE thread_id IS NOT NULL AND {filter_sql}");
    let mut q = sqlx::query_scalar::<_, String>(&sql);
    for b in binds {
        q = q.bind(b);
    }
    Ok(q.fetch_all(db).await?)
}

/// Number of messages in the thread written by somebody else than `user_id`.
pub async fn foreign_messages(db: &Pool, id: &str, user_id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE thread_id = $1 AND author_id <> $2")
        .bind(id)
        .bind(user_id)
        .fetch_one(db)
        .await?)
}

/// Deletes the thread with its messages (rows of reactions, pins, uploads and the search index cascade).
/// Returns the number of deleted messages; the caller deletes the upload files.
pub async fn delete(db: &Pool, id: &str) -> Result<i64, ApiError> {
    let mut tx = db.begin().await?;
    let deleted = sqlx::query("DELETE FROM messages WHERE thread_id = $1").bind(id).execute(&mut *tx).await?.rows_affected();
    sqlx::query("DELETE FROM threads WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(deleted as i64)
}

/// Up to three users per thread who wrote in it most recently, newest first.
pub async fn participants(db: &Pool, ids: &[String]) -> Result<HashMap<String, Vec<String>>, ApiError> {
    let mut latest: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for chunk in ids.chunks(200) {
        let sql = format!(
            "SELECT thread_id, author_id, MAX(id) AS last FROM messages WHERE thread_id IN ({}) GROUP BY thread_id, author_id",
            placeholders(1, chunk.len())
        );
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        for row in q.fetch_all(db).await? {
            latest
                .entry(row.try_get("thread_id")?)
                .or_default()
                .push((row.try_get::<String, _>("last")?, row.try_get("author_id")?));
        }
    }
    Ok(latest
        .into_iter()
        .map(|(thread, mut authors)| {
            authors.sort_by(|a, b| b.0.cmp(&a.0));
            (thread, authors.into_iter().take(3).map(|(_, a)| a).collect())
        })
        .collect())
}

/// The oldest message id of each thread (the first message of forum posts).
pub async fn first_messages(db: &Pool, ids: &[String]) -> Result<HashMap<String, String>, ApiError> {
    let mut out = HashMap::new();
    for chunk in ids.chunks(200) {
        let sql = format!(
            "SELECT thread_id, MIN(id) AS first FROM messages WHERE thread_id IN ({}) GROUP BY thread_id",
            placeholders(1, chunk.len())
        );
        let mut q = sqlx::query(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        for row in q.fetch_all(db).await? {
            out.insert(row.try_get("thread_id")?, row.try_get("first")?);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- followers and read markers

/// A user's state in one thread.
#[derive(Debug, Clone, Default)]
pub struct MemberState {
    pub following: bool,
    pub last_read_message_id: Option<String>,
}

pub async fn members(db: &Pool, user_id: &str, ids: &[String]) -> Result<HashMap<String, MemberState>, ApiError> {
    let mut out = HashMap::new();
    for chunk in ids.chunks(200) {
        let sql = format!(
            "SELECT thread_id, following, last_read_message_id FROM thread_members WHERE user_id = $1 AND thread_id IN ({})",
            placeholders(2, chunk.len())
        );
        let mut q = sqlx::query(&sql).bind(user_id);
        for id in chunk {
            q = q.bind(id);
        }
        for row in q.fetch_all(db).await? {
            out.insert(
                row.try_get("thread_id")?,
                MemberState {
                    following: row.try_get::<i64, _>("following")? != 0,
                    last_read_message_id: row.try_get("last_read_message_id")?,
                },
            );
        }
    }
    Ok(out)
}

/// Follows the thread. `read_up_to` moves the read marker forward at the same time (the user's own message, or
/// the newest message when following by hand). Returns `true` when the user did not follow before.
pub async fn follow(db: &Pool, id: &str, user_id: &str, read_up_to: Option<&str>) -> Result<bool, ApiError> {
    let before: Option<i64> =
        sqlx::query_scalar("SELECT following FROM thread_members WHERE thread_id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    sqlx::query(
        "INSERT INTO thread_members (thread_id, user_id, following, followed_at, last_read_message_id) VALUES ($1, $2, 1, $3, $4)
         ON CONFLICT (thread_id, user_id) DO UPDATE SET
           following = 1,
           followed_at = CASE WHEN thread_members.following = 0 THEN excluded.followed_at ELSE thread_members.followed_at END,
           last_read_message_id = CASE WHEN excluded.last_read_message_id IS NOT NULL
               AND (thread_members.last_read_message_id IS NULL OR thread_members.last_read_message_id < excluded.last_read_message_id)
             THEN excluded.last_read_message_id ELSE thread_members.last_read_message_id END",
    )
    .bind(id)
    .bind(user_id)
    .bind(now())
    .bind(read_up_to)
    .execute(db)
    .await?;
    Ok(before != Some(1))
}

/// Stops following. Returns `true` when the user followed before.
pub async fn unfollow(db: &Pool, id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE thread_members SET following = 0 WHERE thread_id = $1 AND user_id = $2 AND following = 1")
        .bind(id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Moves the per-thread read marker forward (never backwards). Returns the marker and whether it moved.
pub async fn advance_marker(db: &Pool, id: &str, user_id: &str, message_id: &str) -> Result<(String, bool), ApiError> {
    let r = sqlx::query(
        "INSERT INTO thread_members (thread_id, user_id, following, followed_at, last_read_message_id) VALUES ($1, $2, 0, $3, $4)
         ON CONFLICT (thread_id, user_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id
         WHERE thread_members.last_read_message_id IS NULL OR thread_members.last_read_message_id < excluded.last_read_message_id",
    )
    .bind(id)
    .bind(user_id)
    .bind(now())
    .bind(message_id)
    .execute(db)
    .await?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT last_read_message_id FROM thread_members WHERE thread_id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(db)
            .await?
            .flatten();
    Ok((current.unwrap_or_else(|| message_id.to_string()), r.rows_affected() > 0))
}

/// The followed threads of a user in a room, most recent activity first.
pub async fn followed_in_room(db: &Pool, user_id: &str, room_id: &str, limit: i64) -> Result<Vec<ThreadRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} {FROM} JOIN thread_members tm ON tm.thread_id = t.id AND tm.user_id = $1 AND tm.following = 1
         WHERE c.room_id = $2 ORDER BY t.last_message_at DESC, t.id DESC LIMIT $3"
    ))
    .bind(user_id)
    .bind(room_id)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Followers of a thread (user ids).
pub async fn follower_ids(db: &Pool, id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT user_id FROM thread_members WHERE thread_id = $1 AND following = 1")
        .bind(id)
        .fetch_all(db)
        .await?)
}

/// Unread messages of others in one followed thread, with the mentions among them (before notification
/// settings): `direct` mentions of the user or one of their roles, `everyone` the rest that mention `@everyone`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub thread_id: String,
    pub channel_id: String,
    pub unread: i64,
    pub direct: i64,
    pub everyone: i64,
}

/// Which followed threads to count.
pub enum CountScope<'a> {
    Threads(&'a [String]),
    Channels(&'a [String]),
}

/// Counts of the user's followed threads after their per-thread markers (or after following when there is no
/// marker). Threads the user does not follow are not counted.
pub async fn followed_counts(
    db: &Pool,
    user_id: &str,
    address: &str,
    role_ids: &[String],
    scope: CountScope<'_>,
) -> Result<Vec<Counts>, ApiError> {
    let (column, ids) = match scope {
        CountScope::Threads(ids) => ("t.id", ids),
        CountScope::Channels(ids) => ("t.channel_id", ids),
    };
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let roles: Vec<String> =
        role_ids.iter().take(100).map(|r| super::messages::mention_pattern(&super::messages::role_mention(r))).collect();
    let direct = std::iter::once("m.mentions LIKE $2 ESCAPE '\\'".to_string())
        .chain((0..roles.len()).map(|i| format!("m.mentions LIKE ${} ESCAPE '\\'", i + 3)))
        .collect::<Vec<_>>()
        .join(" OR ");
    let mut out = Vec::new();
    for chunk in ids.chunks(200) {
        let sql = format!(
            "SELECT m.thread_id AS thread_id, t.channel_id AS channel_id,
                    CAST(COUNT(*) AS BIGINT) AS unread,
                    CAST(SUM(CASE WHEN {direct} THEN 1 ELSE 0 END) AS BIGINT) AS direct,
                    CAST(SUM(CASE WHEN m.mentions_everyone <> 0 AND NOT ({direct}) THEN 1 ELSE 0 END) AS BIGINT) AS everyone
             FROM messages m
             JOIN threads t ON t.id = m.thread_id
             JOIN thread_members tm ON tm.thread_id = t.id AND tm.user_id = $1 AND tm.following = 1
             WHERE {column} IN ({}) AND m.author_id <> $1
               AND (m.id > tm.last_read_message_id OR (tm.last_read_message_id IS NULL AND m.created_at > tm.followed_at))
             GROUP BY m.thread_id, t.channel_id",
            placeholders(3 + roles.len(), chunk.len())
        );
        let mut q = sqlx::query(&sql).bind(user_id).bind(super::messages::mention_pattern(address));
        for r in &roles {
            q = q.bind(r);
        }
        for id in chunk {
            q = q.bind(id);
        }
        for row in q.fetch_all(db).await? {
            out.push(Counts {
                thread_id: row.try_get("thread_id")?,
                channel_id: row.try_get("channel_id")?,
                unread: row.try_get("unread")?,
                direct: row.try_get::<Option<i64>, _>("direct")?.unwrap_or(0),
                everyone: row.try_get::<Option<i64>, _>("everyone")?.unwrap_or(0),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- channel settings and housekeeping

pub async fn set_auto_archive(db: &Pool, channel_id: &str, minutes: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE channels SET auto_archive_minutes = $1 WHERE id = $2").bind(minutes).bind(channel_id).execute(db).await?;
    Ok(())
}

pub async fn set_forum_tags(db: &Pool, channel_id: &str, tags_json: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE channels SET forum_tags = $1 WHERE id = $2").bind(tags_json).bind(channel_id).execute(db).await?;
    Ok(())
}

/// The auto-archive settings in use by channels that have active threads.
pub async fn archive_settings_in_use(db: &Pool) -> Result<Vec<i64>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT c.auto_archive_minutes FROM channels c JOIN threads t ON t.channel_id = c.id WHERE t.archived_at IS NULL",
    )
    .fetch_all(db)
    .await?)
}

/// Active threads of channels with this auto-archive setting whose last activity is older than `cutoff`.
pub async fn idle(db: &Pool, minutes: i64, cutoff: &str, limit: i64) -> Result<Vec<ThreadRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} {FROM} WHERE t.archived_at IS NULL AND c.auto_archive_minutes = $1 AND t.last_message_at < $2 ORDER BY t.id LIMIT $3"
    ))
    .bind(minutes)
    .bind(cutoff)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    async fn db() -> Pool {
        let pool = crate::db::connect("sqlite::memory:").await.unwrap();
        let t = now();
        for (id, name) in [("u1", "alice"), ("u2", "bob")] {
            sqlx::query("INSERT INTO users (id, username, domain, display_name, created_at) VALUES ($1, $2, 'd', $2, $3)")
                .bind(id)
                .bind(name)
                .bind(&t)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO rooms (id, name, owner_id, created_at) VALUES ('r', 'r', 'u1', $1)")
            .bind(&t)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO conversations (id, kind, room_id, encrypted, created_at) VALUES ('c', 'channel', 'r', 0, $1)")
            .bind(&t)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO channels (id, room_id, kind, name) VALUES ('c', 'r', 'text', 'general')")
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    fn new<'a>(id: &'a str, root: Option<&'a str>, tags: &'a [String]) -> NewThread<'a> {
        NewThread {
            id,
            channel_id: "c",
            root_message_id: root,
            title: Title { text: id, epoch: None, author_id: "u1", device_id: None },
            tags,
            created_by: "u1",
        }
    }

    async fn message(db: &Pool, id: &str, thread: &str, author: &str, mentions: &str) {
        // Activity times have millisecond resolution.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        sqlx::query(
            "INSERT INTO messages (id, conversation_id, author_id, encrypted, content, content_size, thread_id, mentions, created_at)
             VALUES ($1, 'c', $2, 0, '{}', 2, $3, $4, $5)",
        )
        .bind(id)
        .bind(author)
        .bind(thread)
        .bind(mentions)
        .bind(now())
        .execute(db)
        .await
        .unwrap();
        record_message(db, thread, id, &now()).await.unwrap();
    }

    #[tokio::test]
    async fn one_thread_per_root_and_paging() {
        let db = db().await;
        assert!(insert(&db, new("T1", Some("M1"), &[])).await.unwrap());
        assert!(!insert(&db, new("T2", Some("M1"), &[])).await.unwrap(), "unique root");
        assert!(insert(&db, new("T2", None, &["TAG".into()])).await.unwrap());
        assert!(insert(&db, new("T3", None, &[])).await.unwrap(), "several standalone threads");
        assert_eq!(id_by_root(&db, "M1").await.unwrap().as_deref(), Some("T1"));
        message(&db, "MA", "T1", "u2", "[]").await;
        fn page<'a>(before: Option<&'a ThreadRow>, sort: Sort, archived: Archived, tag: Option<&'a str>) -> ListFilter<'a> {
            ListFilter { channel_id: "c", archived, tag, sort, before, limit: 2 }
        }
        let ids = |rows: Vec<ThreadRow>| rows.into_iter().map(|t| t.id).collect::<Vec<_>>();
        let first = list(&db, page(None, Sort::Activity, Archived::Active, None)).await.unwrap();
        assert_eq!(first[0].id, "T1", "the newest activity first");
        let rest = list(&db, page(first.last(), Sort::Activity, Archived::Active, None)).await.unwrap();
        assert_eq!(first.len() + rest.len(), 3);
        assert_eq!(ids(list(&db, page(None, Sort::Created, Archived::All, None)).await.unwrap()), vec!["T3", "T2"]);
        assert_eq!(ids(list(&db, page(None, Sort::Created, Archived::All, Some("TAG"))).await.unwrap()), vec!["T2"]);
        update(&db, "T3", Update { archived_at: Some(Some("2026")), ..Default::default() }).await.unwrap();
        assert_eq!(ids(list(&db, page(None, Sort::Created, Archived::Archived, None)).await.unwrap()), vec!["T3"]);
        // A message reopens an archived thread, unless it is locked.
        message(&db, "MB", "T3", "u1", "[]").await;
        assert!(by_id(&db, "T3").await.unwrap().unwrap().archived_at.is_none());
        update(&db, "T3", Update { archived_at: Some(Some("2026")), locked: Some(true), ..Default::default() })
            .await
            .unwrap();
        message(&db, "MC", "T3", "u1", "[]").await;
        let t3 = by_id(&db, "T3").await.unwrap().unwrap();
        assert!(t3.archived_at.is_some() && t3.is_locked());
        assert_eq!(t3.message_count, 2);
        assert_eq!(foreign_messages(&db, "T3", "u1").await.unwrap(), 0);
        assert_eq!(delete(&db, "T3").await.unwrap(), 2);
        assert!(by_id(&db, "T3").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn follow_markers_and_counts() {
        let db = db().await;
        insert(&db, new("T1", None, &[])).await.unwrap();
        message(&db, "M1", "T1", "u2", "[]").await;
        assert!(follow(&db, "T1", "u1", Some("M1")).await.unwrap());
        assert!(!follow(&db, "T1", "u1", None).await.unwrap(), "already following");
        message(&db, "M2", "T1", "u2", "[\"alice@d\"]").await;
        message(&db, "M3", "T1", "u2", "[]").await;
        sqlx::query("UPDATE messages SET mentions_everyone = 1 WHERE id = 'M3'").execute(&db).await.unwrap();
        message(&db, "M4", "T1", "u1", "[]").await;
        let counts = followed_counts(&db, "u1", "alice@d", &[], CountScope::Channels(&["c".into()])).await.unwrap();
        assert_eq!(
            counts,
            vec![Counts { thread_id: "T1".into(), channel_id: "c".into(), unread: 2, direct: 1, everyone: 1 }]
        );
        assert_eq!(advance_marker(&db, "T1", "u1", "M2").await.unwrap(), ("M2".into(), true));
        assert_eq!(advance_marker(&db, "T1", "u1", "M1").await.unwrap(), ("M2".into(), false), "never backwards");
        let counts = followed_counts(&db, "u1", "alice@d", &[], CountScope::Threads(&["T1".into()])).await.unwrap();
        assert_eq!(counts[0].unread, 1);
        assert!(unfollow(&db, "T1", "u1").await.unwrap());
        assert!(followed_counts(&db, "u1", "alice@d", &[], CountScope::Threads(&["T1".into()])).await.unwrap().is_empty());
        assert!(follower_ids(&db, "T1").await.unwrap().is_empty());
        let m = members(&db, "u1", &["T1".into()]).await.unwrap();
        assert_eq!(m["T1"].last_read_message_id.as_deref(), Some("M2"));
        assert!(!m["T1"].following);
        let p = participants(&db, &["T1".into()]).await.unwrap();
        assert_eq!(p["T1"], vec!["u1".to_string(), "u2".to_string()]);
        assert_eq!(first_messages(&db, &["T1".into()]).await.unwrap()["T1"], "M1");
        // Recounting after deletions.
        sqlx::query("DELETE FROM messages WHERE id IN ('M3', 'M4')").execute(&db).await.unwrap();
        recount(&db, &["T1".into()]).await.unwrap();
        let t = by_id(&db, "T1").await.unwrap().unwrap();
        assert_eq!((t.message_count, t.last_message_id.as_deref()), (2, Some("M2")));
    }
}
