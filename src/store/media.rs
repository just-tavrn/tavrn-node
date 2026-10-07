// SPDX-License-Identifier: AGPL-3.0-only
//! Rows of the `media` table (profile images and room icons, src/media.rs) and the references of
//! users and rooms to them.

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util::now};

#[derive(Debug, Clone, FromRow)]
pub struct MediaRow {
    /// Storage id of the still image.
    pub id: String,
    /// Storage id of the animated variant.
    pub animated_id: Option<String>,
    pub kind: String,
    pub owner_id: String,
    pub mime: String,
    pub still_size: i64,
    pub animated_size: i64,
    pub still_sha256: String,
    pub animated_sha256: Option<String>,
    pub created_at: String,
}

const COLS: &str =
    "id, animated_id, kind, owner_id, mime, still_size, animated_size, still_sha256, animated_sha256, created_at";

pub struct NewMedia<'a> {
    pub id: &'a str,
    pub animated_id: Option<&'a str>,
    pub kind: &'a str,
    pub owner_id: &'a str,
    pub mime: &'a str,
    pub still_size: i64,
    pub animated_size: i64,
    pub still_sha256: &'a str,
    pub animated_sha256: Option<&'a str>,
}

pub async fn insert(db: &Pool, m: NewMedia<'_>) -> Result<(), ApiError> {
    sqlx::query(&format!("INSERT INTO media ({COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"))
        .bind(m.id)
        .bind(m.animated_id)
        .bind(m.kind)
        .bind(m.owner_id)
        .bind(m.mime)
        .bind(m.still_size)
        .bind(m.animated_size)
        .bind(m.still_sha256)
        .bind(m.animated_sha256)
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<MediaRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM media WHERE id = $1")).bind(id).fetch_optional(db).await?)
}

/// Deletes a row and returns it (its files are the caller's to delete).
pub async fn delete(db: &Pool, id: &str) -> Result<Option<MediaRow>, ApiError> {
    let row = by_id(db, id).await?;
    if row.is_some() {
        sqlx::query("DELETE FROM media WHERE id = $1").bind(id).execute(db).await?;
    }
    Ok(row)
}

/// The columns of `users` holding an image of `kind`: (id column, animated flag column).
fn user_columns(kind: &str) -> Option<(&'static str, Option<&'static str>)> {
    match kind {
        "avatar" => Some(("avatar_blob_id", Some("avatar_animated"))),
        "header" => Some(("header_blob_id", Some("header_animated"))),
        "background" => Some(("background_blob_id", None)),
        _ => None,
    }
}

/// Points the user's `kind` image at `media_id` (or none) and bumps `profile_version` for public images
/// (FEDERATION.md §2.7). Returns the previous media id.
pub async fn set_user_media(
    db: &Pool,
    user_id: &str,
    kind: &str,
    media_id: Option<&str>,
    animated: bool,
) -> Result<Option<String>, ApiError> {
    let (col, flag) = user_columns(kind).ok_or_else(|| ApiError::Internal(anyhow::anyhow!("unknown kind {kind}")))?;
    let previous: Option<String> = sqlx::query(&format!("SELECT {col} AS m FROM users WHERE id = $1"))
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .map(|r| r.try_get("m"))
        .transpose()?
        .flatten();
    match flag {
        // Avatar and header are part of the public profile: other nodes refresh their mirror by the version.
        Some(flag) => {
            sqlx::query(&format!(
                "UPDATE users SET {col} = $1, {flag} = $2, profile_version = profile_version + 1 WHERE id = $3"
            ))
            .bind(media_id)
            .bind(animated as i64)
            .bind(user_id)
            .execute(db)
            .await?;
        }
        None => {
            sqlx::query(&format!("UPDATE users SET {col} = $1 WHERE id = $2"))
                .bind(media_id)
                .bind(user_id)
                .execute(db)
                .await?;
        }
    }
    Ok(previous)
}

/// The user's voice background media id.
pub async fn user_background(db: &Pool, user_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query("SELECT background_blob_id AS m FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .map(|r| r.try_get::<Option<String>, _>("m"))
        .transpose()?
        .flatten())
}

/// Points the room icon at `media_id` (or none). Returns the previous media id.
pub async fn set_room_icon(
    db: &Pool,
    room_id: &str,
    media_id: Option<&str>,
    animated: bool,
) -> Result<Option<String>, ApiError> {
    let previous: Option<String> = sqlx::query("SELECT icon_blob_id AS m FROM rooms WHERE id = $1")
        .bind(room_id)
        .fetch_optional(db)
        .await?
        .map(|r| r.try_get("m"))
        .transpose()?
        .flatten();
    sqlx::query("UPDATE rooms SET icon_blob_id = $1, icon_animated = $2 WHERE id = $3")
        .bind(media_id)
        .bind(animated as i64)
        .bind(room_id)
        .execute(db)
        .await?;
    Ok(previous)
}
