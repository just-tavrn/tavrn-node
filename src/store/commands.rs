// SPDX-License-Identifier: AGPL-3.0-only
//! Command definitions of applications (local sets and copies of remote ones), their node approval and the
//! per-room command settings (protocol/APPLICATIONS.md §5.1–§5.3).

use std::collections::HashMap;

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util::now};

#[derive(Debug, Clone, FromRow)]
pub struct CommandRow {
    pub id: String,
    pub application_ref: String,
    pub name: String,
    /// JSON of the definition without `id`.
    pub definition: String,
    pub definition_hash: String,
    pub position: i64,
}

const COLS: &str = "id, application_ref, name, definition, definition_hash, position";

/// A definition to store (ids are assigned by the caller, stable per name).
pub struct NewCommand {
    pub id: String,
    pub name: String,
    pub definition: String,
    pub definition_hash: String,
}

/// The command set of an application in its order.
pub async fn of_app(db: &Pool, application_ref: &str) -> Result<Vec<CommandRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM application_commands WHERE application_ref = $1 ORDER BY position, id"
    ))
    .bind(application_ref)
    .fetch_all(db)
    .await?)
}

/// Every stored definition (admin listing of the approval state).
pub async fn all(db: &Pool) -> Result<Vec<CommandRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM application_commands ORDER BY application_ref, position, id"))
        .fetch_all(db)
        .await?)
}

/// Replaces the whole set of an application in one transaction.
pub async fn replace_set(db: &Pool, application_ref: &str, commands: &[NewCommand]) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_commands WHERE application_ref = $1")
        .bind(application_ref)
        .execute(&mut *tx)
        .await?;
    for (position, c) in commands.iter().enumerate() {
        sqlx::query(
            "INSERT INTO application_commands (id, application_ref, name, definition, definition_hash, position)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&c.id)
        .bind(application_ref)
        .bind(&c.name)
        .bind(&c.definition)
        .bind(&c.definition_hash)
        .bind(position as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Increments `commands_version` of a local application and returns the new value.
pub async fn bump_version(db: &Pool, application_id: &str) -> Result<i64, ApiError> {
    sqlx::query("UPDATE applications SET commands_version = commands_version + 1 WHERE id = $1")
        .bind(application_id)
        .execute(db)
        .await?;
    let row = sqlx::query("SELECT commands_version FROM applications WHERE id = $1")
        .bind(application_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("commands_version")?)
}

/// Sets or clears the interactions URL of a local application (§5.6).
pub async fn set_interactions_url(db: &Pool, application_id: &str, url: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE applications SET interactions_url = $1 WHERE id = $2")
        .bind(url)
        .bind(application_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- approval (§5.2)

/// `definition_hash → state` (`approved` | `rejected`) of an application; absent = pending.
pub async fn approvals(db: &Pool, application_ref: &str) -> Result<HashMap<String, String>, ApiError> {
    let rows =
        sqlx::query("SELECT definition_hash, state FROM application_command_approvals WHERE application_ref = $1")
            .bind(application_ref)
            .fetch_all(db)
            .await?;
    let mut out = HashMap::new();
    for r in rows {
        out.insert(r.try_get::<String, _>("definition_hash")?, r.try_get::<String, _>("state")?);
    }
    Ok(out)
}

/// Every decision: `(application_ref, definition_hash) → state`.
pub async fn all_approvals(db: &Pool) -> Result<HashMap<(String, String), String>, ApiError> {
    let rows = sqlx::query("SELECT application_ref, definition_hash, state FROM application_command_approvals")
        .fetch_all(db)
        .await?;
    let mut out = HashMap::new();
    for r in rows {
        out.insert(
            (r.try_get::<String, _>("application_ref")?, r.try_get::<String, _>("definition_hash")?),
            r.try_get::<String, _>("state")?,
        );
    }
    Ok(out)
}

/// Records an admin decision for one definition hash.
pub async fn set_approval(
    db: &Pool,
    application_ref: &str,
    hash: &str,
    state: &str,
    decided_by: &str,
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM application_command_approvals WHERE application_ref = $1 AND definition_hash = $2")
        .bind(application_ref)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO application_command_approvals (application_ref, definition_hash, state, decided_by, decided_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(application_ref)
    .bind(hash)
    .bind(state)
    .bind(decided_by)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------- per-room settings (§5.3)

#[derive(Debug, Clone, FromRow)]
pub struct SettingRow {
    pub room_id: String,
    pub command_id: String,
    pub application_ref: String,
    pub enabled: i64,
    pub permissions: Option<i64>,
    /// JSON array of role ids.
    pub allowed_roles: String,
    /// JSON array of channel ids.
    pub disabled_channels: String,
    pub updated_at: String,
}

impl SettingRow {
    pub fn allowed_roles(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_roles).unwrap_or_default()
    }
    pub fn disabled_channels(&self) -> Vec<String> {
        serde_json::from_str(&self.disabled_channels).unwrap_or_default()
    }
}

const SETTING_COLS: &str =
    "room_id, command_id, application_ref, enabled, permissions, allowed_roles, disabled_channels, updated_at";

/// The settings of every command in a room, by command id.
pub async fn settings_of_room(db: &Pool, room_id: &str) -> Result<HashMap<String, SettingRow>, ApiError> {
    let rows: Vec<SettingRow> =
        sqlx::query_as(&format!("SELECT {SETTING_COLS} FROM room_command_settings WHERE room_id = $1"))
            .bind(room_id)
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().map(|r| (r.command_id.clone(), r)).collect())
}

pub struct NewSetting<'a> {
    pub room_id: &'a str,
    pub command_id: &'a str,
    pub application_ref: &'a str,
    pub enabled: bool,
    pub permissions: Option<u64>,
    pub allowed_roles: &'a [String],
    pub disabled_channels: &'a [String],
}

/// Replaces the settings of one command in a room.
pub async fn put_setting(db: &Pool, s: NewSetting<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM room_command_settings WHERE room_id = $1 AND command_id = $2")
        .bind(s.room_id)
        .bind(s.command_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO room_command_settings (room_id, command_id, application_ref, enabled, permissions, allowed_roles,
                                           disabled_channels, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(s.room_id)
    .bind(s.command_id)
    .bind(s.application_ref)
    .bind(i64::from(s.enabled))
    .bind(s.permissions.map(|p| p as i64))
    .bind(serde_json::to_string(s.allowed_roles).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(s.disabled_channels).unwrap_or_else(|_| "[]".into()))
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Resets one command of a room to the defaults. `false` if it had no settings.
pub async fn delete_setting(db: &Pool, room_id: &str, command_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM room_command_settings WHERE room_id = $1 AND command_id = $2")
        .bind(room_id)
        .bind(command_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// A removed command loses its room settings everywhere on this node (§5.1).
pub async fn delete_settings_of_commands(db: &Pool, command_ids: &[String]) -> Result<(), ApiError> {
    for id in command_ids {
        sqlx::query("DELETE FROM room_command_settings WHERE command_id = $1").bind(id).execute(db).await?;
    }
    Ok(())
}

/// An uninstalled application loses its command settings in that room (§4.3).
pub async fn delete_settings_of_app(db: &Pool, room_id: &str, application_ref: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM room_command_settings WHERE room_id = $1 AND application_ref = $2")
        .bind(room_id)
        .bind(application_ref)
        .execute(db)
        .await?;
    Ok(())
}

/// Rooms of this node an application (by reference) is installed in.
pub async fn rooms_of_app(db: &Pool, application_ref: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT room_id FROM application_installations WHERE application_ref = $1")
        .bind(application_ref)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get("room_id").map_err(ApiError::from)).collect()
}

/// Forgets the cached set of a remote application that is installed nowhere on this node any more.
pub async fn forget_unused(db: &Pool, application_ref: &str) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM application_commands WHERE application_ref = $1
           AND NOT EXISTS (SELECT 1 FROM application_installations i WHERE i.application_ref = $1)",
    )
    .bind(application_ref)
    .execute(db)
    .await?;
    Ok(())
}
