// SPDX-License-Identifier: AGPL-3.0-only
//! Single sign-on (APPLICATIONS.md §8): external identities, SSO grants, SSO sessions and the group map
//! edited in the admin API.

use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    models::UserRow,
    util::{in_seconds, now, ulid},
};

/// A linked identity of the configured issuer.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExternalIdentity {
    pub user_id: String,
    pub issuer: String,
    pub subject: String,
    pub linked_at: String,
    pub last_login_at: Option<String>,
}

const IDENTITY_COLS: &str = "user_id, issuer, subject, linked_at, last_login_at";

pub async fn identity_by_subject(db: &Pool, issuer: &str, subject: &str) -> Result<Option<ExternalIdentity>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {IDENTITY_COLS} FROM external_identities WHERE issuer = $1 AND subject = $2"))
        .bind(issuer)
        .bind(subject)
        .fetch_optional(db)
        .await?)
}

pub async fn identity_of_user(db: &Pool, user_id: &str, issuer: &str) -> Result<Option<ExternalIdentity>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {IDENTITY_COLS} FROM external_identities WHERE user_id = $1 AND issuer = $2"))
        .bind(user_id)
        .bind(issuer)
        .fetch_optional(db)
        .await?)
}

/// Links `(issuer, subject)` to the user. `Ok(false)` if the identity or the account is linked already
/// (unique constraints, so concurrent attempts cannot both succeed).
pub async fn link(db: &Pool, user_id: &str, issuer: &str, subject: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "INSERT INTO external_identities (user_id, issuer, subject, linked_at, last_login_at) VALUES ($1, $2, $3, $4, $4)",
    )
    .bind(user_id)
    .bind(issuer)
    .bind(subject)
    .bind(now())
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn unlink(db: &Pool, user_id: &str, issuer: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM external_identities WHERE user_id = $1 AND issuer = $2")
        .bind(user_id)
        .bind(issuer)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn touch_login(db: &Pool, issuer: &str, subject: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE external_identities SET last_login_at = $1 WHERE issuer = $2 AND subject = $3")
        .bind(now())
        .bind(issuer)
        .bind(subject)
        .execute(db)
        .await?;
    Ok(())
}

/// A new SSO account: no password, email (verified or not), linked to `(issuer, subject)` in one
/// transaction. `Ok(None)` if the username is taken (the caller tries the next suffix).
pub struct NewSsoUser<'a> {
    pub username: &'a str,
    pub domain: &'a str,
    pub display_name: &'a str,
    pub email: Option<&'a str>,
    pub email_verified: bool,
    pub is_node_admin: bool,
    pub issuer: &'a str,
    pub subject: &'a str,
}

pub async fn create_sso_user(db: &Pool, u: NewSsoUser<'_>) -> Result<Option<UserRow>, ApiError> {
    let id = ulid();
    let ts = now();
    let mut tx = db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, password_hash, email, email_verified_at, is_node_admin, created_at)
         VALUES ($1, $2, $3, $4, 'user', NULL, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(u.username)
    .bind(u.domain)
    .bind(u.display_name)
    .bind(u.email)
    .bind(u.email_verified.then_some(&ts))
    .bind(u.is_node_admin as i64)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    sqlx::query(
        "INSERT INTO external_identities (user_id, issuer, subject, linked_at, last_login_at) VALUES ($1, $2, $3, $4, $4)",
    )
    .bind(&id)
    .bind(u.issuer)
    .bind(u.subject)
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::users::by_id(db, &id).await
}

// ---------------------------------------------------------------- Sessions

/// A session started by an SSO login: refresh token like any session, hard end after `max_secs`.
pub async fn create_sso_session(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    refresh_hash: &str,
    ttl_secs: i64,
    max_secs: i64,
) -> Result<(), ApiError> {
    let max = in_seconds(max_secs);
    // Computed from the same instant, so a capped session has `expires_at == max_expires_at` exactly.
    let expires = if ttl_secs >= max_secs { max.clone() } else { in_seconds(ttl_secs) };
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, created_at, expires_at, max_expires_at, sso)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1)",
    )
    .bind(ulid())
    .bind(user_id)
    .bind(device_id)
    .bind(refresh_hash)
    .bind(now())
    .bind(expires)
    .bind(max)
    .execute(db)
    .await?;
    Ok(())
}

/// `true` if the device's live session was started by an SSO login.
pub async fn device_has_sso_session(db: &Pool, device_id: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM sessions WHERE device_id = $1 AND sso = 1 AND revoked_at IS NULL")
        .bind(device_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")? > 0)
}

// ---------------------------------------------------------------- Grants

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SsoGrant {
    pub kind: String,
    pub room_id: String,
    pub role_id: String,
    pub grp: String,
}

pub async fn grants_of(db: &Pool, user_id: &str) -> Result<Vec<SsoGrant>, ApiError> {
    Ok(sqlx::query_as("SELECT kind, room_id, role_id, grp FROM sso_grants WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

pub async fn record_grant(
    db: &Pool,
    user_id: &str,
    kind: &str,
    room_id: &str,
    role_id: &str,
    grp: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO sso_grants (user_id, kind, room_id, role_id, grp, granted_at) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, kind, room_id, role_id) DO UPDATE SET grp = $5",
    )
    .bind(user_id)
    .bind(kind)
    .bind(room_id)
    .bind(role_id)
    .bind(grp)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_grant(db: &Pool, user_id: &str, kind: &str, room_id: &str, role_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM sso_grants WHERE user_id = $1 AND kind = $2 AND room_id = $3 AND role_id = $4")
        .bind(user_id)
        .bind(kind)
        .bind(room_id)
        .bind(role_id)
        .execute(db)
        .await?;
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

pub async fn delete_room_creation_grant(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM room_creation_grants WHERE user_id = $1").bind(user_id).execute(db).await?;
    Ok(())
}

// ---------------------------------------------------------------- Group map (admin API)

pub async fn stored_group_map(db: &Pool) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT value FROM node_settings WHERE key = $1")
        .bind(crate::oidc::groups::SETTINGS_KEY)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get::<String, _>("value")).transpose()?)
}

pub async fn set_stored_group_map(db: &Pool, json: &str, at: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3",
    )
    .bind(crate::oidc::groups::SETTINGS_KEY)
    .bind(json)
    .bind(at)
    .execute(db)
    .await?;
    Ok(())
}
