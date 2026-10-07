// SPDX-License-Identifier: AGPL-3.0-only
//! Installations of applications in rooms (room node), the install index (bot's home node), the node's
//! application blocklist and the token expiry notices (protocol/APPLICATIONS.md §2.2, §4).

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

#[derive(Debug, Clone, FromRow)]
pub struct InstallationRow {
    pub id: String,
    pub room_id: String,
    pub application_ref: String,
    pub bot_user_id: String,
    pub role_id: Option<String>,
    pub permissions: i64,
    pub installed_by: String,
    pub installed_at: String,
}

const COLS: &str = "id, room_id, application_ref, bot_user_id, role_id, permissions, installed_by, installed_at";

/// What one installation creates (§4.2), written in one transaction.
pub struct NewInstallation<'a> {
    pub room_id: &'a str,
    pub application_ref: &'a str,
    pub bot_user_id: &'a str,
    pub permissions: u64,
    pub installed_by: &'a str,
    /// The managed role: name and position (every non-`@everyone` role at or above it moves up by one).
    pub role: Option<(&'a str, i64)>,
}

/// The result of [`install`]: the installation and the ids of the roles whose position changed.
pub struct Installed {
    pub installation: InstallationRow,
    pub shifted_roles: Vec<String>,
}

/// Membership, managed role (with the member role) and installation row in one transaction.
/// `Ok(None)` if the bot is a member already or the application is installed (unique violation).
pub async fn install(db: &Pool, n: NewInstallation<'_>) -> Result<Option<Installed>, ApiError> {
    let ts = now();
    let id = ulid();
    let mut tx = db.begin().await?;
    let member = sqlx::query(
        "INSERT INTO room_members (room_id, user_id, joined_at, rules_accepted_at) VALUES ($1, $2, $3, $3)",
    )
    .bind(n.room_id)
    .bind(n.bot_user_id)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match member {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut role_id = None;
    let mut shifted_roles = Vec::new();
    if let Some((name, position)) = n.role {
        let rows = sqlx::query("SELECT id FROM roles WHERE room_id = $1 AND is_everyone = 0 AND position >= $2")
            .bind(n.room_id)
            .bind(position)
            .fetch_all(&mut *tx)
            .await?;
        for r in &rows {
            shifted_roles.push(r.try_get::<String, _>("id")?);
        }
        sqlx::query(
            "UPDATE roles SET position = position + 1 WHERE room_id = $1 AND is_everyone = 0 AND position >= $2",
        )
        .bind(n.room_id)
        .bind(position)
        .execute(&mut *tx)
        .await?;
        let rid = ulid();
        sqlx::query(
            "INSERT INTO roles (id, room_id, name, color, position, permissions, hoist, mentionable, is_everyone, application_id)
             VALUES ($1, $2, $3, NULL, $4, $5, 0, 0, 0, $6)",
        )
        .bind(&rid)
        .bind(n.room_id)
        .bind(name)
        .bind(position)
        .bind(n.permissions as i64)
        .bind(n.application_ref)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO member_roles (room_id, user_id, role_id) VALUES ($1, $2, $3)")
            .bind(n.room_id)
            .bind(n.bot_user_id)
            .bind(&rid)
            .execute(&mut *tx)
            .await?;
        role_id = Some(rid);
    }
    let inserted = sqlx::query(
        "INSERT INTO application_installations (id, room_id, application_ref, bot_user_id, role_id, permissions, installed_by, installed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(n.room_id)
    .bind(n.application_ref)
    .bind(n.bot_user_id)
    .bind(role_id.as_deref())
    .bind(n.permissions as i64)
    .bind(n.installed_by)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    tx.commit().await?;
    Ok(Some(Installed {
        installation: InstallationRow {
            id,
            room_id: n.room_id.into(),
            application_ref: n.application_ref.into(),
            bot_user_id: n.bot_user_id.into(),
            role_id,
            permissions: n.permissions as i64,
            installed_by: n.installed_by.into(),
            installed_at: ts,
        },
        shifted_roles,
    }))
}

pub async fn of_room(db: &Pool, room_id: &str) -> Result<Vec<InstallationRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM application_installations WHERE room_id = $1 ORDER BY installed_at, id"
    ))
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

pub async fn count_of_room(db: &Pool, room_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM application_installations WHERE room_id = $1")
        .bind(room_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}

pub async fn by_ref(db: &Pool, room_id: &str, application_ref: &str) -> Result<Option<InstallationRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM application_installations WHERE room_id = $1 AND application_ref = $2"
    ))
    .bind(room_id)
    .bind(application_ref)
    .fetch_optional(db)
    .await?)
}

pub async fn by_bot(db: &Pool, room_id: &str, bot_user_id: &str) -> Result<Option<InstallationRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM application_installations WHERE room_id = $1 AND bot_user_id = $2"))
        .bind(room_id)
        .bind(bot_user_id)
        .fetch_optional(db)
        .await?)
}

/// Rooms of this node a bot is installed in.
pub async fn rooms_of_bot(db: &Pool, bot_user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT room_id FROM application_installations WHERE bot_user_id = $1")
        .bind(bot_user_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get("room_id").map_err(ApiError::from)).collect()
}

pub async fn delete(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM application_installations WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

// ---------------------------------------------------------------- install index (bot's home node)

#[derive(Debug, Clone, FromRow)]
pub struct IndexRow {
    pub application_id: String,
    pub node: String,
    pub room_id: String,
    pub room_name: String,
    pub installed_at: String,
}

/// Adds (or refreshes the name of) an index entry.
pub async fn index_add(
    db: &Pool,
    application_id: &str,
    node: &str,
    room_id: &str,
    room_name: &str,
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_install_index WHERE application_id = $1 AND node = $2 AND room_id = $3")
        .bind(application_id)
        .bind(node)
        .bind(room_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO application_install_index (application_id, node, room_id, room_name, installed_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(application_id)
    .bind(node)
    .bind(room_id)
    .bind(room_name)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn index_remove(db: &Pool, application_id: &str, node: &str, room_id: &str) -> Result<bool, ApiError> {
    let r =
        sqlx::query("DELETE FROM application_install_index WHERE application_id = $1 AND node = $2 AND room_id = $3")
            .bind(application_id)
            .bind(node)
            .bind(room_id)
            .execute(db)
            .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn index_of(db: &Pool, application_id: &str) -> Result<Vec<IndexRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT application_id, node, room_id, room_name, installed_at FROM application_install_index
         WHERE application_id = $1 ORDER BY installed_at, node, room_id",
    )
    .bind(application_id)
    .fetch_all(db)
    .await?)
}

/// Other nodes in the application's install index.
pub async fn index_nodes(db: &Pool, application_id: &str, own_domain: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT DISTINCT node FROM application_install_index WHERE application_id = $1 AND node <> $2 ORDER BY node",
    )
    .bind(application_id)
    .bind(own_domain)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get("node").map_err(ApiError::from)).collect()
}

pub async fn index_count(db: &Pool, application_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM application_install_index WHERE application_id = $1")
            .bind(application_id)
            .fetch_one(db)
            .await?;
    Ok(row.try_get("n")?)
}

// ---------------------------------------------------------------- blocklist (§4.4)

#[derive(Debug, Clone, FromRow)]
pub struct BlockRow {
    pub subject: String,
    pub reason: String,
    pub created_by: Option<String>,
    pub created_at: String,
}

pub async fn blocks(db: &Pool) -> Result<Vec<BlockRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT subject, reason, created_by, created_at FROM application_blocks ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?)
}

/// Adds a block (an existing one keeps its first reason). `false` if it existed.
pub async fn add_block(db: &Pool, subject: &str, reason: &str, created_by: &str) -> Result<bool, ApiError> {
    let r =
        sqlx::query("INSERT INTO application_blocks (subject, reason, created_by, created_at) VALUES ($1, $2, $3, $4)")
            .bind(subject)
            .bind(reason)
            .bind(created_by)
            .bind(now())
            .execute(db)
            .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn remove_block(db: &Pool, subject: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM application_blocks WHERE subject = $1").bind(subject).execute(db).await?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------- admin and token notices

/// Sets or clears the admin's disable flag of an application.
pub async fn set_disabled(db: &Pool, application_id: &str, disabled: bool) -> Result<(), ApiError> {
    let (at, reason) = if disabled { (Some(now()), Some("admin")) } else { (None, None) };
    sqlx::query("UPDATE applications SET disabled_at = $1, disabled_reason = $2 WHERE id = $3")
        .bind(at)
        .bind(reason)
        .bind(application_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn all_applications(db: &Pool) -> Result<Vec<super::applications::ApplicationRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, bot_user_id, owner_id, name, description, public, requested_permissions, scopes, interactions_url,
                rpc_origins, commands_version, disabled_at, disabled_reason, created_at
         FROM applications ORDER BY created_at, id",
    )
    .fetch_all(db)
    .await?)
}

/// A token whose secret expires within `days` and whose last notice was for a longer threshold (or none).
#[derive(Debug, Clone, FromRow)]
pub struct ExpiringToken {
    pub id: String,
    pub application_id: String,
    pub expires_at: String,
    pub expiry_notified_days: Option<i64>,
}

pub async fn expiring_tokens(db: &Pool, before: &str, days: i64) -> Result<Vec<ExpiringToken>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, application_id, expires_at, expiry_notified_days FROM application_tokens
         WHERE revoked_at IS NULL AND expires_at <= $1 AND expires_at > $2
           AND (expiry_notified_days IS NULL OR expiry_notified_days > $3)",
    )
    .bind(before)
    .bind(now())
    .bind(days)
    .fetch_all(db)
    .await?)
}

pub async fn mark_notified(db: &Pool, token_id: &str, days: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE application_tokens SET expiry_notified_days = $1 WHERE id = $2")
        .bind(days)
        .bind(token_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Sets the application reference on a (remote) bot row.
pub async fn set_bot_application(db: &Pool, user_id: &str, application_ref: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE users SET application_id = $1 WHERE id = $2 AND (application_id IS NULL OR application_id <> $1)",
    )
    .bind(application_ref)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Disables a remote bot row (its home node deleted the application, §4.5): its federated logins fail.
pub async fn disable_remote_bot(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET disabled_at = $1 WHERE id = $2 AND disabled_at IS NULL")
        .bind(now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}
