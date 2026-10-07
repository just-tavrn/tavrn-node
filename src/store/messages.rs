// SPDX-License-Identifier: AGPL-3.0-only
use sqlx::Row;

use crate::{db::Pool, error::ApiError, models::MessageRow, util::now};

const COLS: &str = "m.id, m.conversation_id, m.author_id, u.username AS author_username, u.domain AS author_domain, u.kind AS author_kind, m.device_id, m.encrypted, m.format, m.epoch, m.content, m.content_size, m.reply_to_id, m.thread_id, m.mentions, m.mentions_everyone, m.created_at, m.edited_at, m.signature, m.webhook_id, m.webhook_name, m.interaction, u.deleted_at AS author_deleted_at";

pub struct NewMessage<'a> {
    pub id: &'a str,
    pub conversation_id: &'a str,
    pub author_id: &'a str,
    pub device_id: Option<&'a str>,
    pub encrypted: bool,
    pub format: i64,
    pub epoch: Option<i64>,
    pub content: &'a str,
    pub reply_to_id: Option<&'a str>,
    pub thread_id: Option<&'a str>,
    pub mentions: &'a [String],
    pub mentions_everyone: bool,
    /// Device signature of a plaintext message (FEDERATION.md §10.3), stored unchanged.
    pub signature: Option<&'a str>,
}

/// The envelope field `webhook` of a message posted by an incoming webhook (APPLICATIONS.md §6.1).
pub struct WebhookAuthor<'a> {
    pub id: &'a str,
    pub name: &'a str,
}

/// Inserts a webhook message (no device, no signature) with its envelope field `webhook`: plaintext, or a sealed
/// box in an encrypted channel (`encrypted`, `epoch`; APPLICATIONS.md §6.1a).
pub async fn insert_webhook(db: &Pool, m: NewMessage<'_>, webhook: WebhookAuthor<'_>) -> Result<MessageRow, ApiError> {
    sqlx::query(
        "INSERT INTO messages (id, conversation_id, author_id, device_id, encrypted, format, epoch, content, content_size, reply_to_id, thread_id, mentions, mentions_everyone, created_at, signature, webhook_id, webhook_name)
         VALUES ($1, $2, $3, NULL, $12, 1, $13, $4, $5, $6, NULL, $7, $8, $9, NULL, $10, $11)",
    )
    .bind(m.id)
    .bind(m.conversation_id)
    .bind(m.author_id)
    .bind(m.content)
    .bind(m.content.len() as i64)
    .bind(m.reply_to_id)
    .bind(serde_json::to_string(m.mentions).unwrap_or_else(|_| "[]".into()))
    .bind(m.mentions_everyone as i64)
    .bind(now())
    .bind(webhook.id)
    .bind(webhook.name)
    .bind(m.encrypted as i64)
    .bind(m.epoch)
    .execute(db)
    .await?;
    by_id(db, m.id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("message not found after INSERT")))
}

pub async fn insert(db: &Pool, m: NewMessage<'_>) -> Result<MessageRow, ApiError> {
    sqlx::query(
        "INSERT INTO messages (id, conversation_id, author_id, device_id, encrypted, format, epoch, content, content_size, reply_to_id, thread_id, mentions, mentions_everyone, created_at, signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(m.id)
    .bind(m.conversation_id)
    .bind(m.author_id)
    .bind(m.device_id)
    .bind(m.encrypted as i64)
    .bind(m.format)
    .bind(m.epoch)
    .bind(m.content)
    .bind(m.content.len() as i64)
    .bind(m.reply_to_id)
    .bind(m.thread_id)
    .bind(serde_json::to_string(m.mentions).unwrap_or_else(|_| "[]".into()))
    .bind(m.mentions_everyone as i64)
    .bind(now())
    .bind(m.signature)
    .execute(db)
    .await?;
    by_id(db, m.id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("message not found after INSERT")))
}

/// Sets the envelope field `interaction` of a message an application posted as the answer to a command
/// (APPLICATIONS.md §5.7), as JSON.
pub async fn set_interaction(db: &Pool, id: &str, interaction: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE messages SET interaction = $1 WHERE id = $2").bind(interaction).bind(id).execute(db).await?;
    Ok(())
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<MessageRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// Messages by id (search results), in no particular order; unknown ids are skipped.
pub async fn by_ids(db: &Pool, ids: &[String]) -> Result<Vec<MessageRow>, ApiError> {
    let mut out = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(100) {
        let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.id IN ({})",
            placeholders.join(", ")
        );
        let mut q = sqlx::query_as::<_, MessageRow>(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        out.extend(q.fetch_all(db).await?);
    }
    Ok(out)
}

/// The page around `target` (PROTOCOL.md §7, `around`): up to `limit / 2` newer messages, the target and older
/// ones up to `limit` in total, newest first. Same `cut` as [`list`]; the caller has checked that the target is
/// visible.
pub async fn list_around(
    db: &Pool,
    conversation_id: &str,
    target: &str,
    limit: i64,
    cut: Option<&str>,
) -> Result<Vec<MessageRow>, ApiError> {
    const FILTER: &str = "(m.encrypted = 0 OR m.id >= $4)";
    let newer_limit = limit / 2;
    let mut newer: Vec<MessageRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.conversation_id = $1 AND m.id > $2 AND {FILTER} ORDER BY m.id ASC LIMIT $3"
    ))
    .bind(conversation_id)
    .bind(target)
    .bind(newer_limit)
    .bind(cut.unwrap_or(""))
    .fetch_all(db)
    .await?;
    let older: Vec<MessageRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.conversation_id = $1 AND m.id <= $2 AND {FILTER} ORDER BY m.id DESC LIMIT $3"
    ))
    .bind(conversation_id)
    .bind(target)
    .bind(limit - newer.len() as i64)
    .bind(cut.unwrap_or(""))
    .fetch_all(db)
    .await?;
    newer.reverse();
    newer.extend(older);
    Ok(newer)
}

/// Newest first, `before`/`after` as ID bounds (exclusive).
/// A page of a conversation's messages. `cut` (a ULID floor, ENCRYPTION.md §7b) hides encrypted messages
/// older than it; `epoch` limits the page to encrypted messages of one epoch (key checks of history shares).
pub async fn list(
    db: &Pool,
    conversation_id: &str,
    limit: i64,
    before: Option<&str>,
    after: Option<&str>,
    cut: Option<&str>,
    epoch: Option<i64>,
) -> Result<Vec<MessageRow>, ApiError> {
    const FILTER: &str = "(m.encrypted = 0 OR m.id >= $4) AND ($5 < 0 OR (m.encrypted = 1 AND m.epoch = $5))";
    let rows: Vec<MessageRow> = match after {
        Some(after) => {
            sqlx::query_as(&format!(
                "SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.conversation_id = $1 AND m.id > $2 AND {FILTER} ORDER BY m.id ASC LIMIT $3"
            ))
            .bind(conversation_id)
            .bind(after)
            .bind(limit)
            .bind(cut.unwrap_or(""))
            .bind(epoch.unwrap_or(-1))
            .fetch_all(db)
            .await?
        }
        None => {
            sqlx::query_as(&format!(
                "SELECT {COLS} FROM messages m JOIN users u ON u.id = m.author_id WHERE m.conversation_id = $1 AND m.id < $2 AND {FILTER} ORDER BY m.id DESC LIMIT $3"
            ))
            .bind(conversation_id)
            .bind(before.unwrap_or("~"))
            .bind(limit)
            .bind(cut.unwrap_or(""))
            .bind(epoch.unwrap_or(-1))
            .fetch_all(db)
            .await?
        }
    };
    Ok(rows)
}

pub struct ContentUpdate<'a> {
    pub id: &'a str,
    pub content: &'a str,
    pub mentions: &'a [String],
    pub mentions_everyone: bool,
    /// Device that produced the new content (encrypted content is bound to it).
    pub device_id: &'a str,
    pub epoch: Option<i64>,
    /// New device signature (plaintext only); an edit without one clears the old signature.
    pub signature: Option<&'a str>,
}

pub async fn update_content(db: &Pool, u: ContentUpdate<'_>) -> Result<(), ApiError> {
    sqlx::query("UPDATE messages SET content = $1, content_size = $2, mentions = $3, mentions_everyone = $4, edited_at = $5, device_id = $6, epoch = $7, signature = $8 WHERE id = $9")
        .bind(u.content)
        .bind(u.content.len() as i64)
        .bind(serde_json::to_string(u.mentions).unwrap_or_else(|_| "[]".into()))
        .bind(u.mentions_everyone as i64)
        .bind(now())
        .bind(u.device_id)
        .bind(u.epoch)
        .bind(u.signature)
        .bind(u.id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &Pool, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM messages WHERE id = $1").bind(id).execute(db).await?;
    Ok(r.rows_affected() > 0)
}

/// Counts the messages of an author in a conversation within the last `window_secs` seconds
/// (basis of the auto-moderation).
pub async fn count_recent_by_author(
    db: &Pool,
    conversation_id: &str,
    author_id: &str,
    since: &str,
) -> Result<i64, ApiError> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM messages WHERE conversation_id = $1 AND author_id = $2 AND created_at > $3",
    )
    .bind(conversation_id)
    .bind(author_id)
    .bind(since)
    .fetch_one(db)
    .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub async fn last_created_by_author(
    db: &Pool,
    conversation_id: &str,
    author_id: &str,
) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT MAX(created_at) AS t FROM messages WHERE conversation_id = $1 AND author_id = $2")
        .bind(conversation_id)
        .bind(author_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<Option<String>, _>("t")?)
}

/// Moves the read marker of a user forward to `message_id` (never backwards). Returns the marker
/// after the call and whether it moved.
pub async fn advance_read_marker(
    db: &Pool,
    conversation_id: &str,
    user_id: &str,
    message_id: &str,
) -> Result<(String, bool), ApiError> {
    let r = sqlx::query(
        "INSERT INTO read_markers (conversation_id, user_id, last_read_message_id) VALUES ($1, $2, $3)
         ON CONFLICT (conversation_id, user_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id
         WHERE read_markers.last_read_message_id < excluded.last_read_message_id",
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(message_id)
    .execute(db)
    .await?;
    let current = read_marker(db, conversation_id, user_id).await?.unwrap_or_else(|| message_id.to_string());
    Ok((current, r.rows_affected() > 0))
}

pub async fn read_marker(db: &Pool, conversation_id: &str, user_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT last_read_message_id FROM read_markers WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get::<String, _>("last_read_message_id")).transpose()?)
}

/// Unread and mention counts are capped here (clients show "999+").
pub const UNREAD_CAP: i64 = 999;

/// Read state of one conversation for one user.
#[derive(Debug, Clone, Default, serde::Serialize, utoipa::ToSchema)]
pub struct ReadState {
    pub conversation_id: String,
    /// Newest message of the conversation (null if empty).
    pub last_message_id: Option<String>,
    /// The user's read marker (null if never set).
    pub last_read_message_id: Option<String>,
    /// Messages of others after the marker, at most 999. System channels (the welcome channel): 1 when
    /// something changed since the last read, else 0. Muted conversations: 0.
    pub unread_count: i64,
    /// Of those, messages mentioning the user, one of their roles or @everyone, at most 999, after the
    /// user's notification settings (mode `nothing`, muted: 0; `suppress_everyone`: without @everyone).
    /// System channels never count mentions.
    pub mention_count: i64,
    /// Muted by the user's notification settings (the conversation or its room).
    #[serde(default)]
    pub muted: bool,
}

/// What [`read_states`] applies on top of the plain counts.
#[derive(Default)]
pub struct ReadContext<'a> {
    /// The user's role ids in the room (role mentions `role:<id>` count as mentions).
    pub role_ids: &'a [String],
    /// The user's notification settings (local users).
    pub settings: Option<&'a crate::notifications::NotificationSettings>,
    /// The room the conversations belong to (room channels).
    pub room_id: Option<&'a str>,
    /// System channels among the conversations (the welcome channel).
    pub system_channels: &'a [String],
}

/// The mention entry of a role (`role:<id>`, id in canonical uppercase).
pub fn role_mention(role_id: &str) -> String {
    format!("role:{}", role_id.to_ascii_uppercase())
}

/// `LIKE` pattern matching `"<address>"` inside the JSON mention list, with `\` as escape character
/// (`_` is valid in usernames and would otherwise match any character).
pub fn mention_pattern(address: &str) -> String {
    let mut out = String::from("%\"");
    for c in address.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push_str("\"%");
    out
}

/// Read states of `conversation_ids` for `user_id` with three queries in total: newest message ids,
/// markers, and one grouped count. Without a marker, messages count from the user's join: the
/// conversation membership (DMs, group DMs) or `joined_since` (room channels).
pub async fn read_states(
    db: &Pool,
    user_id: &str,
    address: &str,
    conversation_ids: &[String],
    joined_since: &str,
    ctx: &ReadContext<'_>,
) -> Result<Vec<ReadState>, ApiError> {
    if conversation_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut states: Vec<ReadState> =
        conversation_ids.iter().map(|id| ReadState { conversation_id: id.clone(), ..Default::default() }).collect();
    let index: std::collections::HashMap<String, usize> =
        conversation_ids.iter().enumerate().map(|(i, id)| (id.clone(), i)).collect();
    // `IN (…)` placeholders after `leading` other parameters.
    let ids = |leading: usize| {
        (0..conversation_ids.len()).map(|i| format!("${}", i + leading + 1)).collect::<Vec<_>>().join(", ")
    };
    let query = |sql: String, leading: Vec<String>| {
        (sql, leading.into_iter().chain(conversation_ids.iter().cloned()).collect::<Vec<String>>())
    };
    let pattern = mention_pattern(address);
    let role_patterns: Vec<String> = ctx.role_ids.iter().take(100).map(|r| mention_pattern(&role_mention(r))).collect();
    let direct = std::iter::once("m.mentions LIKE $2 ESCAPE '\\'".to_string())
        .chain((0..role_patterns.len()).map(|i| format!("m.mentions LIKE ${} ESCAPE '\\'", i + 4)))
        .collect::<Vec<_>>()
        .join(" OR ");
    let (last_sql, last_binds) = query(
        format!(
            "SELECT conversation_id, MAX(id) AS last_id FROM messages WHERE conversation_id IN ({}) GROUP BY conversation_id",
            ids(0)
        ),
        vec![],
    );
    let (marker_sql, marker_binds) = query(
        format!(
            "SELECT conversation_id, last_read_message_id FROM read_markers WHERE user_id = $1 AND conversation_id IN ({})",
            ids(1)
        ),
        vec![user_id.to_string()],
    );
    let (count_sql, count_binds) = query(
        format!(
            "SELECT m.conversation_id AS conversation_id,
                    CAST(COUNT(*) AS BIGINT) AS unread,
                    CAST(SUM(CASE WHEN {direct} THEN 1 ELSE 0 END) AS BIGINT) AS direct,
                    CAST(SUM(CASE WHEN m.mentions_everyone <> 0 AND NOT ({direct}) THEN 1 ELSE 0 END) AS BIGINT) AS everyone
             FROM messages m
             LEFT JOIN read_markers r ON r.conversation_id = m.conversation_id AND r.user_id = $1
             WHERE m.conversation_id IN ({}) AND m.author_id <> $1
               AND (m.id > r.last_read_message_id
                    OR (r.last_read_message_id IS NULL AND m.created_at > COALESCE(
                          (SELECT cm.joined_at FROM conversation_members cm WHERE cm.conversation_id = m.conversation_id AND cm.user_id = $1),
                          $3)))
             GROUP BY m.conversation_id",
            ids(3 + role_patterns.len())
        ),
        [user_id.to_string(), pattern, joined_since.to_string()].into_iter().chain(role_patterns.iter().cloned()).collect(),
    );
    let fetch = |sql: String, binds: Vec<String>| async move {
        let mut q = sqlx::query(&sql);
        for b in binds {
            q = q.bind(b);
        }
        q.fetch_all(db).await
    };
    for row in fetch(last_sql, last_binds).await? {
        if let Some(&i) = index.get(&row.try_get::<String, _>("conversation_id")?) {
            states[i].last_message_id = row.try_get::<Option<String>, _>("last_id")?;
        }
    }
    for row in fetch(marker_sql, marker_binds).await? {
        if let Some(&i) = index.get(&row.try_get::<String, _>("conversation_id")?) {
            states[i].last_read_message_id = Some(row.try_get::<String, _>("last_read_message_id")?);
        }
    }
    let now = crate::util::now();
    for row in fetch(count_sql, count_binds).await? {
        if let Some(&i) = index.get(&row.try_get::<String, _>("conversation_id")?) {
            let unread = row.try_get::<i64, _>("unread")?;
            let direct = row.try_get::<Option<i64>, _>("direct")?.unwrap_or(0);
            let everyone = row.try_get::<Option<i64>, _>("everyone")?.unwrap_or(0);
            let id = &states[i].conversation_id;
            let effective = ctx.settings.map(|s| s.effective(ctx.room_id, id, &now)).unwrap_or_default();
            let (unread, mentions) = if ctx.system_channels.contains(id) {
                (unread.min(1), 0)
            } else {
                (unread, effective.mentions(direct, everyone))
            };
            states[i].unread_count = if effective.muted { 0 } else { unread.min(UNREAD_CAP) };
            states[i].mention_count = mentions.min(UNREAD_CAP);
        }
    }
    if let Some(settings) = ctx.settings {
        for s in &mut states {
            s.muted = settings.effective(ctx.room_id, &s.conversation_id, &now).muted;
        }
    }
    Ok(states)
}

/// Filter for bulk deletions (moderation). All fields optional; at least one must be set.
#[derive(Debug, Clone, Default)]
pub struct PurgeFilter {
    pub conversation_ids: Vec<String>,
    pub author_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

pub fn purge_where(f: &PurgeFilter) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut binds = Vec::new();
    if !f.conversation_ids.is_empty() {
        let placeholders: Vec<String> = f
            .conversation_ids
            .iter()
            .map(|id| {
                binds.push(id.clone());
                format!("${}", binds.len())
            })
            .collect();
        clauses.push(format!("conversation_id IN ({})", placeholders.join(", ")));
    }
    if let Some(a) = &f.author_id {
        binds.push(a.clone());
        clauses.push(format!("author_id = ${}", binds.len()));
    }
    if let Some(t) = &f.from {
        binds.push(t.clone());
        clauses.push(format!("created_at >= ${}", binds.len()));
    }
    if let Some(t) = &f.to {
        binds.push(t.clone());
        clauses.push(format!("created_at <= ${}", binds.len()));
    }
    // The welcome channel's entries are never purged (MODERATION.md §3).
    if !clauses.is_empty() {
        clauses.push("conversation_id NOT IN (SELECT id FROM channels WHERE kind = 'system')".into());
    }
    (clauses.join(" AND "), binds)
}

pub async fn purge_count(db: &Pool, f: &PurgeFilter) -> Result<i64, ApiError> {
    let (where_sql, binds) = purge_where(f);
    if where_sql.is_empty() {
        return Ok(0);
    }
    let sql = format!("SELECT COUNT(*) AS n FROM messages WHERE {where_sql}");
    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.fetch_one(db).await?.try_get::<i64, _>("n")?)
}

pub async fn purge(db: &Pool, f: &PurgeFilter) -> Result<i64, ApiError> {
    let (where_sql, binds) = purge_where(f);
    if where_sql.is_empty() {
        return Ok(0);
    }
    let sql = format!("DELETE FROM messages WHERE {where_sql}");
    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.execute(db).await?.rows_affected() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_where_builds_parameterized_sql() {
        let f = PurgeFilter {
            conversation_ids: vec!["c1".into(), "c2".into()],
            author_id: Some("u1".into()),
            from: Some("2026".into()),
            to: None,
        };
        let (sql, binds) = purge_where(&f);
        assert_eq!(
            sql,
            "conversation_id IN ($1, $2) AND author_id = $3 AND created_at >= $4 \
             AND conversation_id NOT IN (SELECT id FROM channels WHERE kind = 'system')"
        );
        assert_eq!(binds, vec!["c1", "c2", "u1", "2026"]);
        assert_eq!(purge_where(&PurgeFilter::default()).0, "");
    }

    #[test]
    fn mention_pattern_escapes_like_wildcards() {
        assert_eq!(mention_pattern("bob@t.local"), "%\"bob@t.local\"%");
        assert_eq!(mention_pattern("b_b@t.local"), "%\"b\\_b@t.local\"%");
        assert_eq!(mention_pattern("x%\\y"), "%\"x\\%\\\\y\"%");
    }
}
