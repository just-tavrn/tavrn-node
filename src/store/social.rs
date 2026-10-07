// SPDX-License-Identifier: AGPL-3.0-only
//! Friends, blocks, direct messages and group DMs (local node).

use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

// ---------------------------------------------------------------- Friends

pub async fn are_friends(db: &Pool, a: &str, b: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM friends WHERE user_id = $1 AND friend_id = $2")
        .bind(a)
        .bind(b)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Friends of a user: (friend id, since).
pub async fn friends_of(db: &Pool, user_id: &str) -> Result<Vec<(String, String)>, ApiError> {
    let rows = sqlx::query("SELECT friend_id, created_at FROM friends WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| Ok((r.try_get("friend_id")?, r.try_get("created_at")?))).collect()
}

/// Creates the friendship in both directions and removes requests between the two.
pub async fn add_friendship(db: &Pool, a: &str, b: &str) -> Result<String, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    for (x, y) in [(a, b), (b, a)] {
        sqlx::query("DELETE FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2")
            .bind(x)
            .bind(y)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM friends WHERE user_id = $1 AND friend_id = $2")
            .bind(x)
            .bind(y)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO friends (user_id, friend_id, created_at) VALUES ($1, $2, $3)")
            .bind(x)
            .bind(y)
            .bind(&ts)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ts)
}

/// Removes friendship and pending requests between two users. `true` if a friendship existed.
pub async fn remove_friendship(db: &Pool, a: &str, b: &str) -> Result<bool, ApiError> {
    let mut removed = false;
    for (x, y) in [(a, b), (b, a)] {
        let r = sqlx::query("DELETE FROM friends WHERE user_id = $1 AND friend_id = $2")
            .bind(x)
            .bind(y)
            .execute(db)
            .await?;
        removed |= r.rows_affected() > 0;
        sqlx::query("DELETE FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2")
            .bind(x)
            .bind(y)
            .execute(db)
            .await?;
    }
    Ok(removed)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FriendRequestRow {
    pub id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub created_at: String,
    /// Requests with a user of another node: the id the other home node uses (FEDERATION.md §6.2).
    pub remote_request_id: Option<String>,
    /// Optional message of the requester (≤ 256 characters).
    pub message: Option<String>,
}

const REQUEST_COLS: &str = "id, from_user_id, to_user_id, created_at, remote_request_id, message";

pub async fn request_between(db: &Pool, from: &str, to: &str) -> Result<Option<FriendRequestRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {REQUEST_COLS} FROM friend_requests WHERE from_user_id = $1 AND to_user_id = $2"
    ))
    .bind(from)
    .bind(to)
    .fetch_optional(db)
    .await?)
}

pub async fn request_by_id(db: &Pool, id: &str) -> Result<Option<FriendRequestRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {REQUEST_COLS} FROM friend_requests WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// Requests involving a user (both directions).
pub async fn requests_of(db: &Pool, user_id: &str) -> Result<Vec<FriendRequestRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {REQUEST_COLS} FROM friend_requests WHERE from_user_id = $1 OR to_user_id = $1 ORDER BY id"
    ))
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

pub async fn outgoing_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM friend_requests WHERE from_user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// `None` if a request already exists.
pub async fn create_request(
    db: &Pool,
    from: &str,
    to: &str,
    message: Option<&str>,
) -> Result<Option<FriendRequestRow>, ApiError> {
    create_request_with(db, from, to, None, message).await
}

/// Creates a request; `remote_request_id` is the id of the other home node for an incoming remote request.
pub async fn create_request_with(
    db: &Pool,
    from: &str,
    to: &str,
    remote_request_id: Option<&str>,
    message: Option<&str>,
) -> Result<Option<FriendRequestRow>, ApiError> {
    let row = FriendRequestRow {
        id: ulid(),
        from_user_id: from.into(),
        to_user_id: to.into(),
        created_at: now(),
        remote_request_id: remote_request_id.map(String::from),
        message: message.map(String::from),
    };
    let r = sqlx::query(
        "INSERT INTO friend_requests (id, from_user_id, to_user_id, created_at, remote_request_id, message) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&row.id)
    .bind(from)
    .bind(to)
    .bind(&row.created_at)
    .bind(remote_request_id)
    .bind(message)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(Some(row)),
        Err(e) if super::is_unique_violation(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub async fn set_remote_request_id(db: &Pool, id: &str, remote_request_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE friend_requests SET remote_request_id = $1 WHERE id = $2")
        .bind(remote_request_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes the requests between `a` and `b` (either direction) known by `request_id` on either node.
/// Returns the deleted rows.
pub async fn delete_requests_by_ref(
    db: &Pool,
    a: &str,
    b: &str,
    request_id: &str,
) -> Result<Vec<FriendRequestRow>, ApiError> {
    let rows: Vec<FriendRequestRow> = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLS} FROM friend_requests
         WHERE ((from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1))
           AND (id = $3 OR remote_request_id = $3)"
    ))
    .bind(a)
    .bind(b)
    .bind(request_id)
    .fetch_all(db)
    .await?;
    for r in &rows {
        delete_request(db, &r.id).await?;
    }
    Ok(rows)
}

/// Ordering of friend messages of another node (FEDERATION.md §5.4): `true` (and remembered) if `at` is
/// newer than the last applied message for the pair, `false` for an older or equal one.
pub async fn friend_sync_apply(db: &Pool, user_id: &str, other_id: &str, at: &str) -> Result<bool, ApiError> {
    let last: Option<String> = sqlx::query("SELECT last_at FROM friend_sync WHERE user_id = $1 AND other_id = $2")
        .bind(user_id)
        .bind(other_id)
        .fetch_optional(db)
        .await?
        .map(|r| r.try_get("last_at"))
        .transpose()?;
    if last.as_deref().is_some_and(|l| l >= at) {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO friend_sync (user_id, other_id, last_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, other_id) DO UPDATE SET last_at = $3",
    )
    .bind(user_id)
    .bind(other_id)
    .bind(at)
    .execute(db)
    .await?;
    Ok(true)
}

pub async fn delete_request(db: &Pool, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM friend_requests WHERE id = $1").bind(id).execute(db).await?.rows_affected() > 0)
}

// ---------------------------------------------------------------- Blocks

/// Has `a` blocked `b` or `b` blocked `a`?
pub async fn blocked_either(db: &Pool, a: &str, b: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM user_blocks WHERE (user_id = $1 AND blocked_id = $2) OR (user_id = $2 AND blocked_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_optional(db)
    .await?
    .is_some())
}

/// Has `user_id` blocked `other_id` (one direction only)?
pub async fn has_blocked(db: &Pool, user_id: &str, other_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM user_blocks WHERE user_id = $1 AND blocked_id = $2")
        .bind(user_id)
        .bind(other_id)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Blocks a user with a private note; blocking again updates the note.
pub async fn block(db: &Pool, user_id: &str, blocked_id: &str, reason: &str) -> Result<(), ApiError> {
    let r = sqlx::query("INSERT INTO user_blocks (user_id, blocked_id, created_at, reason) VALUES ($1, $2, $3, $4)")
        .bind(user_id)
        .bind(blocked_id)
        .bind(now())
        .bind(reason)
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(()),
        Err(e) if super::is_unique_violation(&e) => {
            if !reason.is_empty() {
                sqlx::query("UPDATE user_blocks SET reason = $1 WHERE user_id = $2 AND blocked_id = $3")
                    .bind(reason)
                    .bind(user_id)
                    .bind(blocked_id)
                    .execute(db)
                    .await?;
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// The blocks of a user: `(blocked id, reason, created_at)`, oldest first.
pub async fn blocks_of(db: &Pool, user_id: &str) -> Result<Vec<(String, String, String)>, ApiError> {
    let rows =
        sqlx::query("SELECT blocked_id, reason, created_at FROM user_blocks WHERE user_id = $1 ORDER BY created_at")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    rows.iter().map(|r| Ok((r.try_get("blocked_id")?, r.try_get("reason")?, r.try_get("created_at")?))).collect()
}

pub async fn unblock(db: &Pool, user_id: &str, blocked_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM user_blocks WHERE user_id = $1 AND blocked_id = $2")
        .bind(user_id)
        .bind(blocked_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn blocked_by(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT blocked_id FROM user_blocks WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get::<String, _>("blocked_id").map_err(Into::into)).collect()
}

// ---------------------------------------------------------------- Conversations (DMs, group DMs)

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConversationRow {
    pub id: String,
    /// channel | dm | group
    pub kind: String,
    pub room_id: Option<String>,
    pub encrypted: i64,
    pub name: Option<String>,
    pub creator_id: Option<String>,
    pub created_at: String,
}

const CONV_COLS: &str = "id, kind, room_id, encrypted, name, creator_id, created_at";

pub async fn conversation(db: &Pool, id: &str) -> Result<Option<ConversationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {CONV_COLS} FROM conversations WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub fn dm_key(a: &str, b: &str) -> String {
    if a < b { format!("{a}:{b}") } else { format!("{b}:{a}") }
}

pub async fn dm_by_key(db: &Pool, key: &str) -> Result<Option<ConversationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {CONV_COLS} FROM conversations WHERE dm_key = $1"))
        .bind(key)
        .fetch_optional(db)
        .await?)
}

/// Creates a DM (`dm_key` set) or group DM with its members; the `requested` ones get the conversation as
/// a message request. A DM that already exists (unique `dm_key`) yields `None`.
pub async fn create_conversation(
    db: &Pool,
    kind: &str,
    name: Option<&str>,
    creator_id: &str,
    dm_key: Option<&str>,
    member_ids: &[String],
    requested: &[String],
) -> Result<Option<String>, ApiError> {
    let id = ulid();
    let ts = now();
    let mut tx = db.begin().await?;
    let r = sqlx::query(
        "INSERT INTO conversations (id, kind, room_id, encrypted, created_at, name, creator_id, dm_key) VALUES ($1, $2, NULL, 1, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(kind)
    .bind(&ts)
    .bind(name)
    .bind(creator_id)
    .bind(dm_key)
    .execute(&mut *tx)
    .await;
    match r {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    for m in member_ids {
        let state = if requested.contains(m) { STATE_REQUESTED } else { STATE_ACTIVE };
        sqlx::query(
            "INSERT INTO conversation_members (conversation_id, user_id, joined_at, state) VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(m)
        .bind(&ts)
        .bind(state)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Some(id))
}

pub async fn member_ids(db: &Pool, conversation_id: &str) -> Result<Vec<String>, ApiError> {
    let rows =
        sqlx::query("SELECT user_id FROM conversation_members WHERE conversation_id = $1 ORDER BY joined_at, user_id")
            .bind(conversation_id)
            .fetch_all(db)
            .await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}

pub async fn is_member(db: &Pool, conversation_id: &str, user_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM conversation_members WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Membership states: `active` members use the conversation, `requested` ones see it as a message request.
pub const STATE_ACTIVE: &str = "active";
pub const STATE_REQUESTED: &str = "requested";

pub async fn add_member(db: &Pool, conversation_id: &str, user_id: &str, requested: bool) -> Result<bool, ApiError> {
    let state = if requested { STATE_REQUESTED } else { STATE_ACTIVE };
    let r = sqlx::query(
        "INSERT INTO conversation_members (conversation_id, user_id, joined_at, state) VALUES ($1, $2, $3, $4)",
    )
    .bind(conversation_id)
    .bind(user_id)
    .bind(now())
    .bind(state)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_member(db: &Pool, conversation_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM conversation_members WHERE conversation_id = $1 AND user_id = $2")
        .bind(conversation_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn set_name(db: &Pool, conversation_id: &str, name: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE conversations SET name = $1 WHERE id = $2")
        .bind(name)
        .bind(conversation_id)
        .execute(db)
        .await?;
    Ok(())
}

/// DMs and group DMs of a user in membership state `state` (active ones, or message requests).
pub async fn conversations_of(db: &Pool, user_id: &str, state: &str) -> Result<Vec<ConversationRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CONV_COLS} FROM conversations WHERE id IN (SELECT conversation_id FROM conversation_members WHERE user_id = $1 AND state = $2) ORDER BY id"
    ))
    .bind(user_id)
    .bind(state)
    .fetch_all(db)
    .await?)
}

/// Members of a conversation who have not accepted it yet.
pub async fn requested_ids(db: &Pool, conversation_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT user_id FROM conversation_members WHERE conversation_id = $1 AND state = 'requested' ORDER BY joined_at, user_id",
    )
    .bind(conversation_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}

/// Accepts a message request (`requested` → `active`). `true` if it was a request.
pub async fn accept_request(db: &Pool, conversation_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE conversation_members SET state = 'active' WHERE conversation_id = $1 AND user_id = $2 AND state = 'requested'",
    )
    .bind(conversation_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// The id of the first message of a conversation (the preview of a message request).
pub async fn first_message_id(db: &Pool, conversation_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT MIN(id) AS m FROM messages WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<Option<String>, _>("m")?)
}

pub async fn last_message_id(db: &Pool, conversation_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT MAX(id) AS m FROM messages WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<Option<String>, _>("m")?)
}

/// Users who share a DM or group DM with `user_id` (for `identity.changed`).
pub async fn contact_ids(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT DISTINCT user_id FROM conversation_members WHERE conversation_id IN (SELECT conversation_id FROM conversation_members WHERE user_id = $1) AND user_id <> $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}
