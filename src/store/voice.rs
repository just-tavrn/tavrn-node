// SPDX-License-Identifier: AGPL-3.0-only
//! Voice: moderator server mute and soundboard clips.

use serde::Serialize;
use sqlx::{FromRow, Row};
use utoipa::ToSchema;

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

/// `true` if a moderator muted the member in this room.
pub async fn server_muted(db: &Pool, room_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT voice_muted FROM room_members WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(match row {
        Some(r) => r.try_get::<i64, _>("voice_muted")? != 0,
        None => false,
    })
}

pub async fn set_server_muted(db: &Pool, room_id: &str, user_id: &str, muted: bool) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET voice_muted = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(i64::from(muted))
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// A soundboard clip (the audio itself: `GET …/soundboard/{sound_id}/audio`).
#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct Sound {
    pub id: String,
    pub room_id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub duration_ms: i64,
    pub uploader_id: String,
    pub created_at: String,
    /// Unicode emoji or custom emoji token shown on the player's tile while the clip plays.
    pub emoji: Option<String>,
}

const COLS: &str = "id, room_id, name, mime, size, duration_ms, uploader_id, created_at, emoji";

pub async fn sounds(db: &Pool, room_id: &str) -> Result<Vec<Sound>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM soundboard_sounds WHERE room_id = $1 ORDER BY name"))
        .bind(room_id)
        .fetch_all(db)
        .await?)
}

pub async fn sound(db: &Pool, room_id: &str, id: &str) -> Result<Option<Sound>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM soundboard_sounds WHERE room_id = $1 AND id = $2"))
        .bind(room_id)
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn sound_count(db: &Pool, room_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM soundboard_sounds WHERE room_id = $1")
        .bind(room_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub struct NewSound<'a> {
    pub room_id: &'a str,
    pub name: &'a str,
    pub mime: &'a str,
    pub size: i64,
    pub duration_ms: i64,
    pub uploader_id: &'a str,
    pub emoji: Option<&'a str>,
}

pub async fn insert_sound(db: &Pool, s: NewSound<'_>) -> Result<Sound, ApiError> {
    let id = ulid();
    let result = sqlx::query(
        "INSERT INTO soundboard_sounds (id, room_id, name, mime, size, duration_ms, uploader_id, created_at, emoji) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(s.room_id)
    .bind(s.name)
    .bind(s.mime)
    .bind(s.size)
    .bind(s.duration_ms)
    .bind(s.uploader_id)
    .bind(now())
    .bind(s.emoji)
    .execute(db)
    .await;
    match result {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => {
            return Err(ApiError::conflict(
                "soundboard.name_taken",
                format!("A sound named “{}” already exists in this room", s.name),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    sound(db, s.room_id, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("sound not found after INSERT")))
}

pub async fn delete_sound(db: &Pool, room_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM soundboard_sounds WHERE room_id = $1 AND id = $2")
        .bind(room_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

fn sound_name_taken(name: &str) -> ApiError {
    ApiError::conflict("soundboard.name_taken", format!("A sound named “{name}” already exists"))
}

/// Renames a room clip and/or sets its emoji (`Some(None)` clears it).
pub async fn update_sound(
    db: &Pool,
    room_id: &str,
    id: &str,
    name: Option<&str>,
    emoji: Option<Option<&str>>,
) -> Result<bool, ApiError> {
    update_clip(db, "soundboard_sounds", "room_id", room_id, id, name, emoji).await
}

async fn update_clip(
    db: &Pool,
    table: &str,
    owner_col: &str,
    owner: &str,
    id: &str,
    name: Option<&str>,
    emoji: Option<Option<&str>>,
) -> Result<bool, ApiError> {
    let mut found = sqlx::query(&format!("SELECT id FROM {table} WHERE {owner_col} = $1 AND id = $2"))
        .bind(owner)
        .bind(id)
        .fetch_optional(db)
        .await?
        .is_some();
    if let Some(name) = name {
        let r = sqlx::query(&format!("UPDATE {table} SET name = $1 WHERE {owner_col} = $2 AND id = $3"))
            .bind(name)
            .bind(owner)
            .bind(id)
            .execute(db)
            .await;
        match r {
            Ok(r) => found = r.rows_affected() > 0,
            Err(e) if super::is_unique_violation(&e) => return Err(sound_name_taken(name)),
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(emoji) = emoji {
        sqlx::query(&format!("UPDATE {table} SET emoji = $1 WHERE {owner_col} = $2 AND id = $3"))
            .bind(emoji)
            .bind(owner)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(found)
}

// ---------------------------------------------------------------- personal clips

/// A personal soundboard clip of a local user (home node). Audio: `GET /api/v1/sounds/{id}/audio` (public).
#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct UserSound {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub duration_ms: i64,
    pub emoji: Option<String>,
    pub created_at: String,
}

const USER_COLS: &str = "id, name, mime, size, duration_ms, emoji, created_at";

pub async fn user_sounds(db: &Pool, user_id: &str) -> Result<Vec<UserSound>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM user_sounds WHERE user_id = $1 ORDER BY name"))
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

pub async fn user_sound(db: &Pool, user_id: &str, id: &str) -> Result<Option<UserSound>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM user_sounds WHERE user_id = $1 AND id = $2"))
        .bind(user_id)
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn user_sound_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT COUNT(*) AS n FROM user_sounds WHERE user_id = $1").bind(user_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub async fn insert_user_sound(db: &Pool, user_id: &str, s: &NewSound<'_>) -> Result<UserSound, ApiError> {
    let id = ulid();
    let result = sqlx::query(
        "INSERT INTO user_sounds (id, user_id, name, mime, size, duration_ms, emoji, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(s.name)
    .bind(s.mime)
    .bind(s.size)
    .bind(s.duration_ms)
    .bind(s.emoji)
    .bind(now())
    .execute(db)
    .await;
    match result {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Err(sound_name_taken(s.name)),
        Err(e) => return Err(e.into()),
    }
    user_sound(db, user_id, &id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("sound not found after INSERT")))
}

pub async fn update_user_sound(
    db: &Pool,
    user_id: &str,
    id: &str,
    name: Option<&str>,
    emoji: Option<Option<&str>>,
) -> Result<bool, ApiError> {
    update_clip(db, "user_sounds", "user_id", user_id, id, name, emoji).await
}

pub async fn delete_user_sound(db: &Pool, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM user_sounds WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Mime type of any clip (room or personal) by id, for the public audio route.
pub async fn clip_mime(db: &Pool, id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_as::<_, (String,)>(
        "SELECT mime FROM soundboard_sounds WHERE id = $1 UNION ALL SELECT mime FROM user_sounds WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    .map(|(m,)| m))
}

/// The emoji of a clip of this node by id, `None` if it has none or does not exist (any room or personal).
pub async fn user_sound_emoji(db: &Pool, id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_as::<_, (Option<String>,)>(
        "SELECT emoji FROM soundboard_sounds WHERE id = $1 UNION ALL SELECT emoji FROM user_sounds WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    .and_then(|(e,)| e))
}
