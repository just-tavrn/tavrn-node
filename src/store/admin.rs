// SPDX-License-Identifier: AGPL-3.0-only
//! Node admin: account invites, user management, statistics.

use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    models::{AccountInvite, UserRow},
    util::{now, random_token},
};

use super::users::USER_COLS;

pub async fn list_users(
    db: &Pool,
    domain: &str,
    query: &str,
    limit: i64,
    after: &str,
) -> Result<Vec<UserRow>, ApiError> {
    let pattern = format!("%{}%", query.to_lowercase().replace('%', "\\%").replace('_', "\\_"));
    Ok(sqlx::query_as(&format!(
        "SELECT {USER_COLS} FROM users WHERE domain = $1 AND id > $2 AND (LOWER(username) LIKE $3 OR LOWER(display_name) LIKE $3)
         AND username <> $5 AND kind <> 'webhook' AND NOT (deleted_at IS NOT NULL AND username LIKE 'deleted-%')
         ORDER BY id LIMIT $4"
    ))
    .bind(domain)
    .bind(after)
    .bind(pattern)
    .bind(limit)
    // The conformance probe is hidden (FEDERATION.md §9.1).
    .bind(crate::federation::conformance::PROBE_USERNAME)
    .fetch_all(db)
    .await?)
}

pub async fn set_disabled(db: &Pool, user_id: &str, disabled: bool) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET disabled_at = $1 WHERE id = $2")
        .bind(disabled.then(now))
        .bind(user_id)
        .execute(db)
        .await?;
    if disabled {
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL")
            .bind(now())
            .bind(user_id)
            .execute(db)
            .await?;
    }
    Ok(())
}

pub async fn set_node_admin(db: &Pool, user_id: &str, admin: bool) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET is_node_admin = $1 WHERE id = $2")
        .bind(admin as i64)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub struct Stats {
    pub users: i64,
    pub rooms: i64,
    pub messages: i64,
    pub blob_bytes: i64,
}

pub async fn stats(db: &Pool, domain: &str) -> Result<Stats, ApiError> {
    let count =
        |sql: &'static str| async move { sqlx::query(sql).fetch_one(db).await.and_then(|r| r.try_get::<i64, _>("n")) };
    let users =
        sqlx::query("SELECT COUNT(*) AS n FROM users WHERE domain = $1 AND username <> $2 AND kind <> 'webhook'")
            .bind(domain)
            .bind(crate::federation::conformance::PROBE_USERNAME)
            .fetch_one(db)
            .await?
            .try_get::<i64, _>("n")?;
    Ok(Stats {
        users,
        rooms: count("SELECT COUNT(*) AS n FROM rooms").await?,
        messages: count("SELECT COUNT(*) AS n FROM messages").await?,
        blob_bytes: count("SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS n FROM blobs").await?,
    })
}

// ---------------------------------------------------------------- Account invites

const INVITE_COLS: &str = "code, created_by, note, max_uses, uses, expires_at, created_at";

pub async fn create_invite(
    db: &Pool,
    created_by: &str,
    note: &str,
    max_uses: i64,
    expires_at: Option<&str>,
) -> Result<AccountInvite, ApiError> {
    let code = random_token(12);
    let ts = now();
    sqlx::query("INSERT INTO account_invites (code, created_by, note, max_uses, uses, expires_at, created_at) VALUES ($1, $2, $3, $4, 0, $5, $6)")
        .bind(&code)
        .bind(created_by)
        .bind(note)
        .bind(max_uses)
        .bind(expires_at)
        .bind(&ts)
        .execute(db)
        .await?;
    Ok(AccountInvite {
        code,
        created_by: created_by.into(),
        note: note.into(),
        max_uses,
        uses: 0,
        expires_at: expires_at.map(String::from),
        created_at: ts,
    })
}

pub async fn list_invites(db: &Pool) -> Result<Vec<AccountInvite>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {INVITE_COLS} FROM account_invites ORDER BY created_at DESC"))
        .fetch_all(db)
        .await?)
}

pub async fn invite_by_code(db: &Pool, code: &str) -> Result<Option<AccountInvite>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {INVITE_COLS} FROM account_invites WHERE code = $1"))
        .bind(code)
        .fetch_optional(db)
        .await?)
}

/// Checks and consumes an invite atomically; `false` if invalid, expired or used up.
/// Redeems one use of an account invite (atomic: the use count never exceeds `max_uses`); `false` if the code is
/// unknown, expired or used up. Registration calls it inside the transaction that creates the account
/// ([`super::users::create_local_with_invite`]), so a failed registration never uses an invite.
pub async fn consume_invite<'e, E>(executor: E, code: &str) -> Result<bool, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let r = sqlx::query("UPDATE account_invites SET uses = uses + 1 WHERE code = $1 AND (max_uses = 0 OR uses < max_uses) AND (expires_at IS NULL OR expires_at > $2)")
        .bind(code)
        .bind(now())
        .execute(executor)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// `403 auth.invite_invalid`.
pub fn invite_invalid() -> ApiError {
    ApiError::Forbidden { code: "auth.invite_invalid", detail: "Invite invalid, expired or used up".into() }
}

pub async fn delete_invite(db: &Pool, code: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM account_invites WHERE code = $1").bind(code).execute(db).await?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------- Password reset

pub async fn set_password_reset(db: &Pool, user_id: &str, token_hash: &str, ttl_secs: i64) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM password_resets WHERE user_id = $1").bind(user_id).execute(db).await?;
    sqlx::query("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(token_hash)
        .bind(crate::util::in_seconds(ttl_secs))
        .execute(db)
        .await?;
    Ok(())
}

/// `true` if `user_id` has a reset token that has not expired yet (a new request then keeps it: repeated requests
/// cannot invalidate the link the owner already received).
pub async fn has_pending_password_reset(db: &Pool, user_id: &str) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM password_resets WHERE user_id = $1 AND expires_at > $2")
        .bind(user_id)
        .bind(now())
        .fetch_one(db)
        .await?;
    Ok(n > 0)
}

/// Redeems a reset token (single use) and returns the user ID.
pub async fn consume_password_reset(db: &Pool, token_hash: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT user_id, expires_at FROM password_resets WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let user_id: String = row.try_get("user_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    sqlx::query("DELETE FROM password_resets WHERE user_id = $1").bind(&user_id).execute(db).await?;
    if expires_at <= now() {
        return Ok(None);
    }
    Ok(Some(user_id))
}

pub async fn user_by_email(db: &Pool, domain: &str, email: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {USER_COLS} FROM users WHERE domain = $1 AND email = $2 AND email_verified_at IS NOT NULL"
    ))
    .bind(domain)
    .bind(email)
    .fetch_optional(db)
    .await?)
}
