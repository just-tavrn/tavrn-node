// SPDX-License-Identifier: AGPL-3.0-only
//! The invite list of local users (FEDERATION.md §4) and `notify` push hints (§5.2), migration 0011.

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

/// Entries kept per user; the oldest are dropped beyond this.
pub const MAX_INVITES: i64 = 200;
/// Push hints kept per user.
pub const MAX_HINTS: i64 = 500;

#[derive(Debug, Clone, FromRow)]
pub struct UserInviteRow {
    pub id: String,
    pub user_id: String,
    /// room | conversation
    pub kind: String,
    pub node: String,
    pub target_id: String,
    /// JSON of the room or conversation summary.
    pub summary: String,
    pub inviter: String,
    pub invite_code: Option<String>,
    pub received_at: String,
    pub expires_at: String,
}

const COLS: &str = "id, user_id, kind, node, target_id, summary, inviter, invite_code, received_at, expires_at";

pub struct NewUserInvite<'a> {
    pub user_id: &'a str,
    pub kind: &'a str,
    pub node: &'a str,
    pub target_id: &'a str,
    pub summary: &'a str,
    pub inviter: &'a str,
    pub invite_code: Option<&'a str>,
    pub expires_at: &'a str,
}

/// Stores an invitation (replacing an older one for the same room or conversation), drops expired
/// entries and keeps at most [`MAX_INVITES`] per user.
pub async fn put(db: &Pool, i: NewUserInvite<'_>) -> Result<UserInviteRow, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM user_invites WHERE user_id = $1 AND kind = $2 AND node = $3 AND target_id = $4")
        .bind(i.user_id)
        .bind(i.kind)
        .bind(i.node)
        .bind(i.target_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_invites WHERE user_id = $1 AND expires_at <= $2")
        .bind(i.user_id)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
    let row = UserInviteRow {
        id: ulid(),
        user_id: i.user_id.into(),
        kind: i.kind.into(),
        node: i.node.into(),
        target_id: i.target_id.into(),
        summary: i.summary.into(),
        inviter: i.inviter.into(),
        invite_code: i.invite_code.map(String::from),
        received_at: ts,
        expires_at: i.expires_at.into(),
    };
    sqlx::query(&format!("INSERT INTO user_invites ({COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"))
        .bind(&row.id)
        .bind(&row.user_id)
        .bind(&row.kind)
        .bind(&row.node)
        .bind(&row.target_id)
        .bind(&row.summary)
        .bind(&row.inviter)
        .bind(&row.invite_code)
        .bind(&row.received_at)
        .bind(&row.expires_at)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM user_invites WHERE user_id = $1 AND id NOT IN
         (SELECT id FROM user_invites WHERE user_id = $1 ORDER BY id DESC LIMIT $2)",
    )
    .bind(i.user_id)
    .bind(MAX_INVITES)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

/// Pending (not expired) invitations of a user, newest first.
pub async fn list(db: &Pool, user_id: &str) -> Result<Vec<UserInviteRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM user_invites WHERE user_id = $1 AND expires_at > $2 ORDER BY id DESC LIMIT $3"
    ))
    .bind(user_id)
    .bind(now())
    .bind(MAX_INVITES)
    .fetch_all(db)
    .await?)
}

pub async fn delete(db: &Pool, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM user_invites WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Stores a push hint and keeps the newest [`MAX_HINTS`] of the user.
pub async fn add_hint(
    db: &Pool,
    user_id: &str,
    node: &str,
    conversation_id: &str,
    room_id: Option<&str>,
    mention: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO push_hints (id, user_id, node, conversation_id, room_id, mention, received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(ulid())
    .bind(user_id)
    .bind(node)
    .bind(conversation_id)
    .bind(room_id)
    .bind(i64::from(mention))
    .bind(now())
    .execute(db)
    .await?;
    sqlx::query(
        "DELETE FROM push_hints WHERE user_id = $1 AND id NOT IN
         (SELECT id FROM push_hints WHERE user_id = $1 ORDER BY id DESC LIMIT $2)",
    )
    .bind(user_id)
    .bind(MAX_HINTS)
    .execute(db)
    .await?;
    Ok(())
}

/// Drops push hints received before `cutoff`.
pub async fn prune_hints(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM push_hints WHERE received_at < $1").bind(cutoff).execute(db).await?.rows_affected())
}

/// Number of push hints of a user (tests and admin views).
pub async fn hint_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM push_hints WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}
