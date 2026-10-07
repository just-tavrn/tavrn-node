// SPDX-License-Identifier: AGPL-3.0-only
//! Applications (bots), app tokens, transfers and the application blocklist (protocol/APPLICATIONS.md §1–§2).

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    models::UserRow,
    util::{in_seconds, now, ulid},
};

#[derive(Debug, Clone, FromRow)]
pub struct ApplicationRow {
    pub id: String,
    pub bot_user_id: String,
    pub owner_id: String,
    pub name: String,
    pub description: String,
    pub public: i64,
    pub requested_permissions: i64,
    /// JSON array.
    pub scopes: String,
    pub interactions_url: Option<String>,
    /// JSON array.
    pub rpc_origins: String,
    pub commands_version: i64,
    pub disabled_at: Option<String>,
    pub disabled_reason: Option<String>,
    pub created_at: String,
}

impl ApplicationRow {
    pub fn scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }
    pub fn rpc_origins(&self) -> Vec<String> {
        serde_json::from_str(&self.rpc_origins).unwrap_or_default()
    }
}

const APP_COLS: &str = "id, bot_user_id, owner_id, name, description, public, requested_permissions, scopes, interactions_url, rpc_origins, commands_version, disabled_at, disabled_reason, created_at";

#[derive(Debug, Clone, FromRow)]
pub struct TokenRow {
    pub id: String,
    pub application_id: String,
    pub device_id: String,
    pub name: String,
    /// JSON array.
    pub scopes: String,
    pub jti: String,
    pub token_hash: String,
    pub prev_jti: Option<String>,
    pub prev_token_hash: Option<String>,
    pub prev_valid_until: Option<String>,
    pub rotated_at: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

impl TokenRow {
    pub fn scopes(&self) -> Vec<String> {
        serde_json::from_str(&self.scopes).unwrap_or_default()
    }
}

const TOKEN_COLS: &str = "id, application_id, device_id, name, scopes, jti, token_hash, prev_jti, prev_token_hash, prev_valid_until, rotated_at, created_at, expires_at, last_used_at, revoked_at";

pub struct NewApplication<'a> {
    pub username: &'a str,
    pub domain: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub public: bool,
    pub requested_permissions: u64,
    pub scopes: &'a [String],
    pub owner: &'a UserRow,
}

/// Creates the bot user and the application in one transaction. `Ok(None)` if the username is taken.
pub async fn create(db: &Pool, a: NewApplication<'_>) -> Result<Option<ApplicationRow>, ApiError> {
    let (app_id, bot_id, ts) = (ulid(), ulid(), now());
    let mut tx = db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, owner_id, owner_address, application_id,
                            is_node_admin, dm_policy, created_at)
         VALUES ($1, $2, $3, $4, 'bot', $5, $6, $7, 0, 'everyone_shared', $8)",
    )
    .bind(&bot_id)
    .bind(a.username)
    .bind(a.domain)
    .bind(a.name)
    .bind(&a.owner.id)
    .bind(a.owner.address())
    .bind(&app_id)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    sqlx::query(
        "INSERT INTO applications (id, bot_user_id, owner_id, name, description, public, requested_permissions, scopes,
                                   rpc_origins, commands_version, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '[]', 0, $9)",
    )
    .bind(&app_id)
    .bind(&bot_id)
    .bind(&a.owner.id)
    .bind(a.name)
    .bind(a.description)
    .bind(i64::from(a.public))
    .bind(a.requested_permissions as i64)
    .bind(serde_json::to_string(a.scopes).unwrap_or_else(|_| "[]".into()))
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    by_id(db, &app_id).await
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<ApplicationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {APP_COLS} FROM applications WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn by_bot(db: &Pool, bot_user_id: &str) -> Result<Option<ApplicationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {APP_COLS} FROM applications WHERE bot_user_id = $1"))
        .bind(bot_user_id)
        .fetch_optional(db)
        .await?)
}

pub async fn of_owner(db: &Pool, owner_id: &str) -> Result<Vec<ApplicationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {APP_COLS} FROM applications WHERE owner_id = $1 ORDER BY created_at, id"))
        .bind(owner_id)
        .fetch_all(db)
        .await?)
}

pub async fn count_of_owner(db: &Pool, owner_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM applications WHERE owner_id = $1")
        .bind(owner_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}

/// `true` if a user (also a tombstone or a remote user) has this username on `domain`.
pub async fn username_taken(db: &Pool, username: &str, domain: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM users WHERE username = $1 AND domain = $2")
        .bind(username)
        .bind(domain)
        .fetch_optional(db)
        .await?
        .is_some())
}

#[derive(Default)]
pub struct ApplicationUpdate<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub public: Option<bool>,
    pub requested_permissions: Option<u64>,
    pub scopes: Option<&'a [String]>,
    pub rpc_origins: Option<&'a [String]>,
}

/// Updates the application; a new name also becomes the bot's display name (bumps its profile version).
pub async fn update(db: &Pool, app: &ApplicationRow, u: ApplicationUpdate<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE applications SET name = COALESCE($1, name), description = COALESCE($2, description),
                public = COALESCE($3, public), requested_permissions = COALESCE($4, requested_permissions),
                scopes = COALESCE($5, scopes), rpc_origins = COALESCE($6, rpc_origins) WHERE id = $7",
    )
    .bind(u.name)
    .bind(u.description)
    .bind(u.public.map(i64::from))
    .bind(u.requested_permissions.map(|p| p as i64))
    .bind(u.scopes.map(|s| serde_json::to_string(s).unwrap_or_else(|_| "[]".into())))
    .bind(u.rpc_origins.map(|s| serde_json::to_string(s).unwrap_or_else(|_| "[]".into())))
    .bind(&app.id)
    .execute(&mut *tx)
    .await?;
    if let Some(name) = u.name {
        sqlx::query(
            "UPDATE users SET display_name = $1, profile_version = profile_version + 1 WHERE id = $2 AND display_name <> $1",
        )
        .bind(name)
        .bind(&app.bot_user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Deletes the application (tokens, transfer cascade) and leaves the bot row as a disabled tombstone
/// (APPLICATIONS.md §1.4): its username is never reused and its messages keep an author.
pub async fn delete(db: &Pool, app: &ApplicationRow) -> Result<(), ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    super::users::retire_devices(&mut *tx, "d.user_id = $2", &[&app.bot_user_id]).await?;
    super::users::tombstone_devices(&mut *tx, "d.user_id = $2", &[&app.bot_user_id]).await?;
    sqlx::query("DELETE FROM devices WHERE user_id = $1").bind(&app.bot_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM key_backups WHERE user_id = $1").bind(&app.bot_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM applications WHERE id = $1").bind(&app.id).execute(&mut *tx).await?;
    // The tombstone keeps its owner columns for attribution of old messages; it can never sign in.
    sqlx::query("UPDATE users SET disabled_at = $1, owner_id = NULL WHERE id = $2")
        .bind(&ts)
        .bind(&app.bot_user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------- tokens

pub struct NewToken<'a> {
    pub id: &'a str,
    pub application_id: &'a str,
    pub bot_user_id: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub jti: &'a str,
    pub token_hash: &'a str,
    pub expires_at: &'a str,
}

/// Creates the token row and its bot device (`device_id` is chosen by the caller and baked into the token).
pub async fn create_token(db: &Pool, t: NewToken<'_>, device_id: &str) -> Result<(), ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO devices (id, user_id, name, client, created_at, last_seen_at) VALUES ($1, $2, $3, 'app-token', $4, $4)",
    )
    .bind(device_id)
    .bind(t.bot_user_id)
    .bind(t.name)
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO application_tokens (id, application_id, device_id, name, scopes, jti, token_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(t.id)
    .bind(t.application_id)
    .bind(device_id)
    .bind(t.name)
    .bind(serde_json::to_string(t.scopes).unwrap_or_else(|_| "[]".into()))
    .bind(t.jti)
    .bind(t.token_hash)
    .bind(&ts)
    .bind(t.expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn tokens(db: &Pool, application_id: &str) -> Result<Vec<TokenRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {TOKEN_COLS} FROM application_tokens WHERE application_id = $1 AND revoked_at IS NULL ORDER BY created_at, id"
    ))
    .bind(application_id)
    .fetch_all(db)
    .await?)
}

pub async fn token(db: &Pool, application_id: &str, token_id: &str) -> Result<Option<TokenRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {TOKEN_COLS} FROM application_tokens WHERE id = $1 AND application_id = $2 AND revoked_at IS NULL"
    ))
    .bind(token_id)
    .bind(application_id)
    .fetch_optional(db)
    .await?)
}

/// The token row whose current secret has this `jti`, or whose previous secret has it and is still
/// within the rotation overlap.
pub async fn token_by_jti(db: &Pool, jti: &str) -> Result<Option<TokenRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {TOKEN_COLS} FROM application_tokens
         WHERE (jti = $1 OR (prev_jti = $1 AND prev_valid_until > $2)) AND revoked_at IS NULL"
    ))
    .bind(jti)
    .bind(now())
    .fetch_optional(db)
    .await?)
}

pub async fn count_tokens(db: &Pool, application_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS n FROM application_tokens WHERE application_id = $1 AND revoked_at IS NULL",
    )
    .bind(application_id)
    .fetch_one(db)
    .await?;
    Ok(row.try_get("n")?)
}

/// Reset by the owner: new secret, the old one (and a previous rotation secret) invalid at once.
pub async fn reset_token(
    db: &Pool,
    token_id: &str,
    jti: &str,
    token_hash: &str,
    expires_at: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_tokens SET jti = $1, token_hash = $2, expires_at = $3, prev_jti = NULL,
                prev_token_hash = NULL, prev_valid_until = NULL, expiry_notified_days = NULL WHERE id = $4",
    )
    .bind(jti)
    .bind(token_hash)
    .bind(expires_at)
    .bind(token_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Rotation by the bot: new secret, the current one stays valid for `overlap_secs`.
pub async fn rotate_token(
    db: &Pool,
    row: &TokenRow,
    jti: &str,
    token_hash: &str,
    expires_at: &str,
    overlap_secs: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_tokens SET prev_jti = jti, prev_token_hash = token_hash, prev_valid_until = $1,
                jti = $2, token_hash = $3, expires_at = $4, rotated_at = $5, expiry_notified_days = NULL
          WHERE id = $6 AND jti = $7",
    )
    .bind(in_seconds(overlap_secs))
    .bind(jti)
    .bind(token_hash)
    .bind(expires_at)
    .bind(now())
    .bind(&row.id)
    .bind(&row.jti)
    .execute(db)
    .await?;
    Ok(())
}

/// Deletes the token and its device (revocation). Returns the device id if a token was deleted.
pub async fn revoke_token(db: &Pool, application_id: &str, token_id: &str) -> Result<Option<String>, ApiError> {
    let Some(row) = token(db, application_id, token_id).await? else { return Ok(None) };
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_tokens WHERE id = $1").bind(&row.id).execute(&mut *tx).await?;
    // The bot's messages stay verifiable (ENCRYPTION.md §5.2).
    super::users::retire_devices(&mut *tx, "d.id = $2", &[&row.device_id]).await?;
    super::users::tombstone_devices(&mut *tx, "d.id = $2", &[&row.device_id]).await?;
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(&row.device_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Some(row.device_id))
}

/// Deletes every token and device of the application (transfer, deletion). Returns the device ids.
pub async fn revoke_all_tokens(db: &Pool, app: &ApplicationRow) -> Result<Vec<String>, ApiError> {
    let devices: Vec<String> = sqlx::query("SELECT id FROM devices WHERE user_id = $1")
        .bind(&app.bot_user_id)
        .fetch_all(db)
        .await?
        .iter()
        .map(|r| r.try_get("id"))
        .collect::<Result<_, _>>()?;
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_tokens WHERE application_id = $1").bind(&app.id).execute(&mut *tx).await?;
    super::users::retire_devices(&mut *tx, "d.user_id = $2", &[&app.bot_user_id]).await?;
    super::users::tombstone_devices(&mut *tx, "d.user_id = $2", &[&app.bot_user_id]).await?;
    sqlx::query("DELETE FROM devices WHERE user_id = $1").bind(&app.bot_user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(devices)
}

/// Writes `last_used_at` at most once per minute.
pub async fn touch_token(db: &Pool, token_id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_tokens SET last_used_at = $1 WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < $3)",
    )
    .bind(now())
    .bind(token_id)
    .bind(in_seconds(-60))
    .execute(db)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------- transfers

#[derive(Debug, Clone, FromRow)]
pub struct TransferRow {
    pub application_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub created_at: String,
    pub expires_at: String,
}

/// The pending (not expired) transfer of an application.
pub async fn transfer(db: &Pool, application_id: &str) -> Result<Option<TransferRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT application_id, from_user_id, to_user_id, created_at, expires_at FROM application_transfers
         WHERE application_id = $1 AND expires_at > $2",
    )
    .bind(application_id)
    .bind(now())
    .fetch_optional(db)
    .await?)
}

/// Pending transfers to a user.
pub async fn transfers_to(db: &Pool, user_id: &str) -> Result<Vec<TransferRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT application_id, from_user_id, to_user_id, created_at, expires_at FROM application_transfers
         WHERE to_user_id = $1 AND expires_at > $2 ORDER BY created_at",
    )
    .bind(user_id)
    .bind(now())
    .fetch_all(db)
    .await?)
}

/// Creates a pending transfer (an expired one is replaced).
pub async fn create_transfer(db: &Pool, app: &ApplicationRow, to_user_id: &str, ttl_secs: i64) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_transfers WHERE application_id = $1").bind(&app.id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO application_transfers (application_id, from_user_id, to_user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&app.id)
    .bind(&app.owner_id)
    .bind(to_user_id)
    .bind(now())
    .bind(in_seconds(ttl_secs))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_transfer(db: &Pool, application_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM application_transfers WHERE application_id = $1")
        .bind(application_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Completes a transfer: new owner on the application and the bot row, the transfer row removed.
pub async fn complete_transfer(db: &Pool, app: &ApplicationRow, new_owner: &UserRow) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE applications SET owner_id = $1 WHERE id = $2")
        .bind(&new_owner.id)
        .bind(&app.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE users SET owner_id = $1, owner_address = $2, profile_version = profile_version + 1 WHERE id = $3",
    )
    .bind(&new_owner.id)
    .bind(new_owner.address())
    .bind(&app.bot_user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM application_transfers WHERE application_id = $1").bind(&app.id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------- creation grants and blocks

pub async fn creation_grant(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT app_creation_grant AS n FROM users WHERE id = $1").bind(user_id).fetch_one(db).await?;
    Ok(row.try_get("n")?)
}

pub async fn set_creation_grant(db: &Pool, user_id: &str, n: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET app_creation_grant = $1 WHERE id = $2").bind(n).bind(user_id).execute(db).await?;
    Ok(())
}

/// Consumes one application grant (`TAVRN_APP_CREATION=invite`); `false` if none was left.
pub async fn consume_creation_grant(db: &Pool, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE users SET app_creation_grant = app_creation_grant - 1 WHERE id = $1 AND app_creation_grant > 0",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// `true` if the bot address is on this node's application blocklist (§4.4).
pub async fn is_blocked(db: &Pool, bot_address: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM application_blocks WHERE subject = $1")
        .bind(bot_address)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Bots (local and remote) whose owner is `owner_address` or whose owner's domain is `domain`.
pub async fn bots_of_owner_subject(db: &Pool, subject: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT id FROM users WHERE kind <> 'user' AND owner_address IS NOT NULL
           AND (owner_address = $1 OR owner_address LIKE $2)",
    )
    .bind(subject)
    .bind(format!("%@{subject}"))
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get("id").map_err(ApiError::from)).collect()
}

/// The application reference and scopes stored with the live federated session of a remote device.
pub async fn remote_session_app(
    db: &Pool,
    user_id: &str,
    device_id: &str,
) -> Result<Option<(Option<String>, Option<String>)>, ApiError> {
    let row = sqlx::query(
        "SELECT application_ref, scopes FROM sessions
         WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > $3 LIMIT 1",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(now())
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| (r.try_get("application_ref").ok().flatten(), r.try_get("scopes").ok().flatten())))
}

/// Stores the application reference and scopes of a remote bot with its federated session (and on the
/// user row, so its `User` object names the application).
pub async fn set_remote_session_app(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    application_ref: Option<&str>,
    scopes: Option<&[String]>,
) -> Result<(), ApiError> {
    let scopes = scopes.map(|s| serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
    sqlx::query("UPDATE sessions SET application_ref = $1, scopes = $2 WHERE device_id = $3 AND user_id = $4 AND revoked_at IS NULL")
        .bind(application_ref)
        .bind(scopes)
        .bind(device_id)
        .bind(user_id)
        .execute(db)
        .await?;
    if let Some(app) = application_ref {
        sqlx::query("UPDATE users SET application_id = $1 WHERE id = $2").bind(app).bind(user_id).execute(db).await?;
    }
    Ok(())
}

/// Sets the owner's address on a remote bot row (from the federation token).
pub async fn set_owner_address(db: &Pool, user_id: &str, owner_address: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET owner_address = $1 WHERE id = $2 AND (owner_address IS NULL OR owner_address <> $1)")
        .bind(owner_address)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Clears the bot's identity (owner-driven reset, APPLICATIONS.md §3.4): no identity key, every
/// attestation, KeyPackage and backup gone. Returns the reset time.
pub async fn clear_identity(db: &Pool, bot_user_id: &str) -> Result<String, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET identity_pubkey = NULL, identity_reset_at = $1 WHERE id = $2")
        .bind(&ts)
        .bind(bot_user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE devices SET identity_signature = NULL, attested_identity_key = NULL, attested_at = NULL WHERE user_id = $1",
    )
    .bind(bot_user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM key_packages WHERE user_id = $1").bind(bot_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM key_backups WHERE user_id = $1").bind(bot_user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(ts)
}

/// Sets the "no bots" flag of a room, category or channel (§3.5). `target` is `room`, `category` or
/// `channel`; the id must belong to `room_id`.
pub async fn set_no_bots(db: &Pool, target: &str, room_id: &str, id: &str, value: bool) -> Result<(), ApiError> {
    let sql = match target {
        "room" => "UPDATE rooms SET no_bots = $1 WHERE id = $2 AND id = $3",
        "category" => "UPDATE categories SET no_bots = $1 WHERE room_id = $2 AND id = $3",
        _ => "UPDATE channels SET no_bots = $1 WHERE room_id = $2 AND id = $3",
    };
    sqlx::query(sql).bind(i64::from(value)).bind(room_id).bind(id).execute(db).await?;
    Ok(())
}

/// Sets the room setting `bots_in_encrypted_channels` (§3.5; the value is validated by the caller).
pub async fn set_bots_in_encrypted(db: &Pool, room_id: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE rooms SET bots_in_encrypted_channels = $1 WHERE id = $2")
        .bind(value)
        .bind(room_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Sets the channel setting `bots_allowed` (§3.5).
pub async fn set_bots_allowed(db: &Pool, room_id: &str, channel_id: &str, value: bool) -> Result<(), ApiError> {
    sqlx::query("UPDATE channels SET bots_allowed = $1 WHERE room_id = $2 AND id = $3")
        .bind(i64::from(value))
        .bind(room_id)
        .bind(channel_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Ids of the bot members (every kind except `user`) of a room.
pub async fn bot_member_ids(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT u.id AS id FROM room_members m JOIN users u ON u.id = m.user_id WHERE m.room_id = $1 AND u.kind <> 'user'",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get("id").map_err(ApiError::from)).collect()
}
