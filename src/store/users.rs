// SPDX-License-Identifier: AGPL-3.0-only
use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    models::{DeviceRow, SessionRow, UserRow},
    util::{in_seconds, now, ulid},
};

pub(crate) const USER_COLS: &str = "id, username, domain, display_name, kind, owner_id, password_hash, email, email_verified_at, identity_pubkey, identity_reset_at, is_node_admin, avatar_blob_id, avatar_animated, header_blob_id, header_animated, dm_policy, presence_status, custom_status, hide_activity, created_at, disabled_at, owner_address, application_id, deleted_at";

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM users WHERE id = $1")).bind(id).fetch_optional(db).await?)
}

pub async fn by_username(db: &Pool, username: &str, domain: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM users WHERE username = $1 AND domain = $2"))
        .bind(username)
        .bind(domain)
        .fetch_optional(db)
        .await?)
}

pub async fn by_ids(db: &Pool, ids: &[String]) -> Result<Vec<UserRow>, ApiError> {
    let mut out = Vec::with_capacity(ids.len());
    // Small sets (member lists are paginated); single queries stay portable.
    for id in ids {
        if let Some(u) = by_id(db, id).await? {
            out.push(u);
        }
    }
    Ok(out)
}

pub async fn count_local(db: &Pool, domain: &str) -> Result<i64, ApiError> {
    // The conformance probe (FEDERATION.md §9.1) is a system account, not a user.
    let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE domain = $1 AND kind = 'user' AND username <> $2")
        .bind(domain)
        .bind(crate::federation::conformance::PROBE_USERNAME)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub struct NewLocalUser<'a> {
    pub username: &'a str,
    pub domain: &'a str,
    pub display_name: &'a str,
    pub password_hash: &'a str,
    pub email: Option<&'a str>,
    pub is_node_admin: bool,
}

/// Creates a local account. `Err(Conflict)` if the name is already taken.
pub async fn create_local(db: &Pool, u: NewLocalUser<'_>) -> Result<UserRow, ApiError> {
    let id = ulid();
    let result = sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, password_hash, email, is_node_admin, created_at)
         VALUES ($1, $2, $3, $4, 'user', $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(u.username)
    .bind(u.domain)
    .bind(u.display_name)
    .bind(u.password_hash)
    .bind(u.email)
    .bind(u.is_node_admin as i64)
    .bind(now())
    .execute(db)
    .await;
    match result {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => {
            return Err(ApiError::conflict("auth.username_taken", "This username is already taken"));
        }
        Err(e) => return Err(e.into()),
    }
    by_id(db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("user not found after INSERT")))
}

pub async fn set_email_verified(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id = $2").bind(now()).bind(user_id).execute(db).await?;
    Ok(())
}

pub async fn set_password_hash(db: &Pool, user_id: &str, hash: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2").bind(hash).bind(user_id).execute(db).await?;
    Ok(())
}

/// Deletes a device; its attested key moves to `retired_devices` first (ENCRYPTION.md §5.2: its history stays
/// verifiable).
pub async fn delete_device(db: &Pool, user_id: &str, device_id: &str) -> Result<bool, ApiError> {
    retire_devices(db, "d.id = $2 AND d.user_id = $3", &[device_id, user_id]).await?;
    tombstone_devices(db, "d.id = $2 AND d.user_id = $3", &[device_id, user_id]).await?;
    let r = sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Changes the display name; a real change increments `profile_version` (FEDERATION.md §2.7).
pub async fn update_profile(db: &Pool, user_id: &str, display_name: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET display_name = $1, profile_version = profile_version + 1 WHERE id = $2 AND display_name <> $1",
    )
        .bind(display_name)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Bio, linked accounts (JSON) and the profile version of a user (for remote users the mirrored version).
pub async fn profile_extra(db: &Pool, user_id: &str) -> Result<(String, String, i64), ApiError> {
    let row = sqlx::query(
        "SELECT u.bio AS bio, u.links AS links, COALESCE(r.profile_version, u.profile_version) AS pv
         FROM users u LEFT JOIN remote_users r ON r.user_id = u.id WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("bio")?, row.try_get("links")?, row.try_get("pv")?))
}

/// Profile settings of PATCH /users/me; every given field changes, public fields bump `profile_version`.
#[derive(Default)]
pub struct ProfileUpdate<'a> {
    pub bio: Option<&'a str>,
    pub links: Option<&'a str>,
    pub dm_policy: Option<&'a str>,
    pub hide_activity: Option<bool>,
}

pub async fn update_profile_fields(db: &Pool, user_id: &str, u: ProfileUpdate<'_>) -> Result<(), ApiError> {
    let public = u.bio.is_some() || u.links.is_some() || u.dm_policy.is_some();
    sqlx::query(
        "UPDATE users SET bio = COALESCE($1, bio), links = COALESCE($2, links), dm_policy = COALESCE($3, dm_policy),
                hide_activity = COALESCE($4, hide_activity), profile_version = profile_version + $5 WHERE id = $6",
    )
    .bind(u.bio)
    .bind(u.links)
    .bind(u.dm_policy)
    .bind(u.hide_activity.map(|h| h as i64))
    .bind(public as i64)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// The language of a user's mails (`mail_templates.rs`), `None` = English.
pub async fn locale(db: &Pool, user_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<String>>("SELECT locale FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .flatten())
}

pub async fn set_locale(db: &Pool, user_id: &str, locale: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET locale = $1 WHERE id = $2").bind(locale).bind(user_id).execute(db).await?;
    Ok(())
}

/// The `auto_preview` privacy setting of a user.
pub async fn auto_preview(db: &Pool, user_id: &str) -> Result<String, ApiError> {
    let v: Option<String> =
        sqlx::query_scalar("SELECT auto_preview FROM users WHERE id = $1").bind(user_id).fetch_optional(db).await?;
    Ok(v.unwrap_or_else(|| "friends_and_shared".into()))
}

pub async fn set_auto_preview(db: &Pool, user_id: &str, value: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET auto_preview = $1 WHERE id = $2").bind(value).bind(user_id).execute(db).await?;
    Ok(())
}

// ---------------------------------------------------------------- Devices and sessions

pub async fn create_device(db: &Pool, user_id: &str, name: &str, client: &str) -> Result<DeviceRow, ApiError> {
    let id = ulid();
    let ts = now();
    sqlx::query(
        "INSERT INTO devices (id, user_id, name, client, created_at, last_seen_at) VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(client)
    .bind(&ts)
    .execute(db)
    .await?;
    Ok(DeviceRow {
        id,
        user_id: user_id.into(),
        name: name.into(),
        client: client.into(),
        created_at: ts.clone(),
        last_seen_at: ts,
    })
}

pub async fn devices_of(db: &Pool, user_id: &str) -> Result<Vec<DeviceRow>, ApiError> {
    Ok(sqlx::query_as("SELECT id, user_id, name, client, created_at, last_seen_at FROM devices WHERE user_id = $1 ORDER BY created_at")
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

const SESSION_COLS: &str = "id, user_id, device_id, refresh_token_hash, prev_refresh_token_hash, created_at, expires_at, revoked_at, max_expires_at, rotated_at";

pub async fn create_session(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    refresh_hash: &str,
    ttl_secs: i64,
) -> Result<String, ApiError> {
    let id = ulid();
    sqlx::query("INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(&id)
        .bind(user_id)
        .bind(device_id)
        .bind(refresh_hash)
        .bind(now())
        .bind(in_seconds(ttl_secs))
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn session_by_hash(db: &Pool, hash: &str) -> Result<Option<SessionRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {SESSION_COLS} FROM sessions WHERE refresh_token_hash = $1"))
        .bind(hash)
        .fetch_optional(db)
        .await?)
}

pub async fn session_by_prev_hash(db: &Pool, hash: &str) -> Result<Option<SessionRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {SESSION_COLS} FROM sessions WHERE prev_refresh_token_hash = $1"))
        .bind(hash)
        .fetch_optional(db)
        .await?)
}

/// Rotates the refresh token atomically: only while `old_hash` is still the current token of a live session.
/// `false` when a parallel refresh rotated it first (or the session was revoked meanwhile). The session then
/// expires at `expires_at`.
pub async fn rotate_session(
    db: &Pool,
    id: &str,
    old_hash: &str,
    new_hash: &str,
    expires_at: &str,
) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE sessions SET refresh_token_hash = $1, prev_refresh_token_hash = $2, expires_at = $3, rotated_at = $4
         WHERE id = $5 AND refresh_token_hash = $2 AND revoked_at IS NULL",
    )
    .bind(new_hash)
    .bind(old_hash)
    .bind(expires_at)
    .bind(now())
    .bind(id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn session_by_id(db: &Pool, id: &str) -> Result<Option<SessionRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {SESSION_COLS} FROM sessions WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// The newest live session of a device.
pub async fn live_session_of_device(db: &Pool, device_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM sessions WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(now())
    .fetch_optional(db)
    .await?)
}

/// Marks a device as seen now (refresh, login).
pub async fn touch_device(db: &Pool, device_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2").bind(now()).bind(device_id).execute(db).await?;
    Ok(())
}

/// A local device of `user_id` (no device of a remote user, no bot device).
pub async fn own_device(db: &Pool, user_id: &str, device_id: &str) -> Result<Option<DeviceRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, name, client, created_at, last_seen_at FROM devices
         WHERE id = $1 AND user_id = $2 AND home_domain IS NULL AND client <> 'app-token'",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

/// A new session continues an existing device (device proof at login, PROTOCOL.md §5b): the device's other
/// sessions end (the client replaced their tokens), `client` and `last_seen_at` are updated.
pub async fn reuse_device(db: &Pool, device_id: &str, client: &str) -> Result<(), ApiError> {
    revoke_device_sessions(db, device_id).await?;
    sqlx::query("UPDATE devices SET client = $1, last_seen_at = $2 WHERE id = $3")
        .bind(client)
        .bind(now())
        .bind(device_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Stale devices (`TAVRN_DEVICE_STALE_DAYS`): devices of local users not seen since `cutoff`, without a
/// live session, and never the only device of their user. Oldest first, at most `limit`.
pub async fn stale_devices(db: &Pool, domain: &str, cutoff: &str, limit: i64) -> Result<Vec<DeviceRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT d.id, d.user_id, d.name, d.client, d.created_at, d.last_seen_at FROM devices d
         JOIN users u ON u.id = d.user_id
         WHERE u.domain = $1 AND u.kind = 'user' AND d.home_domain IS NULL AND d.last_seen_at < $2
           AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = d.id AND s.revoked_at IS NULL AND s.expires_at > $3)
           AND (SELECT COUNT(*) FROM devices o WHERE o.user_id = d.user_id) > 1
         ORDER BY d.last_seen_at LIMIT $4",
    )
    .bind(domain)
    .bind(cutoff)
    .bind(now())
    .bind(limit)
    .fetch_all(db)
    .await?)
}

pub async fn revoke_session(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn revoke_device_sessions(db: &Pool, device_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL")
        .bind(now())
        .bind(device_id)
        .execute(db)
        .await?;
    // A signed-out device gets no more pushes (PROTOCOL.md §6d).
    crate::store::push::delete_for_device(db, device_id).await?;
    Ok(())
}

// ---------------------------------------------------------------- Email verification

pub async fn set_email_verification(db: &Pool, user_id: &str, token_hash: &str, ttl_secs: i64) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1").bind(user_id).execute(db).await?;
    sqlx::query("INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(token_hash)
        .bind(in_seconds(ttl_secs))
        .execute(db)
        .await?;
    Ok(())
}

/// Redeems a verification token and returns the user ID if valid.
pub async fn consume_email_verification(db: &Pool, token_hash: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT user_id, expires_at FROM email_verifications WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let user_id: String = row.try_get("user_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    sqlx::query("DELETE FROM email_verifications WHERE user_id = $1").bind(&user_id).execute(db).await?;
    if expires_at <= now() {
        return Ok(None);
    }
    set_email_verified(db, &user_id).await?;
    Ok(Some(user_id))
}

// ---------------------------------------------------------------- Room creation permissions

pub async fn room_creation_grant(db: &Pool, user_id: &str) -> Result<Option<i64>, ApiError> {
    let row = sqlx::query("SELECT remaining FROM room_creation_grants WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get::<i64, _>("remaining")).transpose()?)
}

pub async fn upsert_room_creation_grant(
    db: &Pool,
    user_id: &str,
    granted_by: &str,
    remaining: i64,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM room_creation_grants WHERE user_id = $1").bind(user_id).execute(db).await?;
    sqlx::query(
        "INSERT INTO room_creation_grants (user_id, granted_by, remaining, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(granted_by)
    .bind(remaining)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn consume_room_creation_grant(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_creation_grants SET remaining = remaining - 1 WHERE user_id = $1 AND remaining > 0")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- Retired devices (ENCRYPTION.md §2.3, §5.2)

/// Copies the attested keys of the devices matching `condition` (on `devices d`, placeholders from `$2`, `$1` is the
/// time) to `retired_devices`. Devices without an attested key have written nothing verifiable and are skipped.
pub async fn retire_devices<'e, E>(executor: E, condition: &str, binds: &[&str]) -> Result<u64, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let sql = format!(
        "INSERT INTO retired_devices (device_id, user_id, public_key, identity_signature, attested_identity_key, source, deleted_at)
         SELECT d.id, d.user_id, d.public_key, d.identity_signature, d.attested_identity_key, 'deleted', $1 FROM devices d
         WHERE {condition} AND d.home_domain IS NULL AND d.public_key IS NOT NULL AND d.identity_signature IS NOT NULL
         ON CONFLICT (device_id) DO NOTHING"
    );
    let mut q = sqlx::query(&sql).bind(now());
    for b in binds {
        q = q.bind(*b);
    }
    Ok(q.execute(executor).await?.rows_affected())
}

/// Records the ids of the local devices matching `condition` (same form as [`retire_devices`]) as deleted
/// (`device_tombstones`, ENCRYPTION.md §2.3): only such ids may be re-attested as retired later.
pub async fn tombstone_devices<'e, E>(executor: E, condition: &str, binds: &[&str]) -> Result<u64, ApiError>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let sql = format!(
        "INSERT INTO device_tombstones (device_id, user_id, deleted_at)
         SELECT d.id, d.user_id, $1 FROM devices d WHERE {condition} AND d.home_domain IS NULL
         ON CONFLICT (device_id) DO NOTHING"
    );
    let mut q = sqlx::query(&sql).bind(now());
    for b in binds {
        q = q.bind(*b);
    }
    Ok(q.execute(executor).await?.rows_affected())
}

/// `true` if the home node deleted the device `device_id` of `user_id` (a tombstone exists).
pub async fn has_tombstone(db: &Pool, user_id: &str, device_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM device_tombstones WHERE device_id = $1 AND user_id = $2")
        .bind(device_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Drops tombstones of devices deleted before `cutoff` (housekeeping, `TAVRN_DEVICE_STALE_DAYS`).
pub async fn prune_tombstones(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM device_tombstones WHERE deleted_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RetiredDevice {
    pub device_id: String,
    pub user_id: String,
    pub public_key: String,
    pub identity_signature: String,
    pub attested_identity_key: Option<String>,
    pub source: String,
    pub deleted_at: String,
}

/// Retired devices of a user, oldest removal first (at most 1000).
pub async fn retired_devices(db: &Pool, user_id: &str) -> Result<Vec<RetiredDevice>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT device_id, user_id, public_key, identity_signature, attested_identity_key, source, deleted_at
         FROM retired_devices WHERE user_id = $1 ORDER BY deleted_at, device_id LIMIT 1000",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

pub async fn retired_device(db: &Pool, device_id: &str) -> Result<Option<RetiredDevice>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT device_id, user_id, public_key, identity_signature, attested_identity_key, source, deleted_at
         FROM retired_devices WHERE device_id = $1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?)
}

/// Deletes a retired device key (development test hook only).
pub async fn forget_retired_device(db: &Pool, device_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM retired_devices WHERE device_id = $1").bind(device_id).execute(db).await?;
    Ok(())
}

/// Records a device the user attested again after it was deleted (`source = reattested`).
pub async fn insert_reattested(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    public_key: &str,
    identity_signature: &str,
    identity_key: &str,
) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "INSERT INTO retired_devices (device_id, user_id, public_key, identity_signature, attested_identity_key, source, deleted_at)
         VALUES ($1, $2, $3, $4, $5, 'reattested', $6) ON CONFLICT (device_id) DO NOTHING",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(public_key)
    .bind(identity_signature)
    .bind(identity_key)
    .bind(now())
    .execute(db)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// `true` if any device row (of any user, also remote devices) has this id.
pub async fn device_id_in_use(db: &Pool, device_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM devices WHERE id = $1 OR home_device_id = $1")
        .bind(device_id)
        .fetch_optional(db)
        .await?
        .is_some())
}
