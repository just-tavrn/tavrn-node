// SPDX-License-Identifier: AGPL-3.0-only
use serde::Serialize;
use sqlx::{FromRow, Row};
use utoipa::ToSchema;

use crate::{
    db::Pool,
    error::ApiError,
    models::EmojiRow,
    util::{now, ulid},
};

const COLS: &str = "id, room_id, name, mime, size, uploader_id, created_at, animated, still_id";

pub async fn list(db: &Pool, room_id: &str) -> Result<Vec<EmojiRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM emojis WHERE room_id = $1 ORDER BY name"))
        .bind(room_id)
        .fetch_all(db)
        .await?)
}

pub async fn by_id(db: &Pool, room_id: &str, id: &str) -> Result<Option<EmojiRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM emojis WHERE room_id = $1 AND id = $2"))
        .bind(room_id)
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn count(db: &Pool, room_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM emojis WHERE room_id = $1").bind(room_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// The converted files of an emoji: `id` is shown in chat, `still_id` is the first frame of an
/// animated one.
pub struct NewEmojiFiles<'a> {
    pub id: &'a str,
    pub still_id: Option<&'a str>,
    pub mime: &'a str,
    pub size: i64,
    pub animated: bool,
}

fn name_taken(name: &str, scope: &str) -> ApiError {
    ApiError::conflict("emoji.name_taken", format!("An emoji :{name}: already exists {scope}"))
}

pub async fn insert(
    db: &Pool,
    room_id: &str,
    name: &str,
    files: &NewEmojiFiles<'_>,
    uploader_id: &str,
) -> Result<EmojiRow, ApiError> {
    let result = sqlx::query(
        "INSERT INTO emojis (id, room_id, name, mime, size, uploader_id, created_at, animated, still_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(files.id)
    .bind(room_id)
    .bind(name)
    .bind(files.mime)
    .bind(files.size)
    .bind(uploader_id)
    .bind(now())
    .bind(i64::from(files.animated))
    .bind(files.still_id)
    .execute(db)
    .await;
    match result {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Err(name_taken(name, "in this room")),
        Err(e) => return Err(e.into()),
    }
    by_id(db, room_id, files.id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("emoji not found after INSERT")))
}

pub async fn delete(db: &Pool, room_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM emojis WHERE room_id = $1 AND id = $2").bind(room_id).bind(id).execute(db).await?;
    Ok(r.rows_affected() > 0)
}

/// Of `ids`, those that are emojis of `room_id`.
pub async fn existing_in_room(
    db: &Pool,
    room_id: &str,
    ids: &[&str],
) -> Result<std::collections::HashSet<String>, ApiError> {
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let list = (2..ids.len() + 2).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
    let sql = format!("SELECT id FROM emojis WHERE room_id = $1 AND id IN ({list})");
    let mut q = sqlx::query_as::<_, (String,)>(&sql).bind(room_id);
    for id in ids {
        q = q.bind(*id);
    }
    Ok(q.fetch_all(db).await?.into_iter().map(|(id,)| id).collect())
}

// ---------------------------------------------------------------- personal emojis

/// A personal emoji of a local user (home node). Image: `GET /api/v1/emojis/{id}/image` (public).
#[derive(Debug, Clone, FromRow, Serialize, ToSchema)]
pub struct UserEmoji {
    pub id: String,
    /// Short name without colons.
    pub name: String,
    pub mime: String,
    pub size: i64,
    #[schema(value_type = bool)]
    #[serde(serialize_with = "as_bool")]
    pub animated: i64,
    #[serde(skip)]
    pub still_id: Option<String>,
    pub created_at: String,
}

fn as_bool<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bool(*v != 0)
}

const USER_COLS: &str = "id, name, mime, size, animated, still_id, created_at";

pub async fn user_list(db: &Pool, user_id: &str) -> Result<Vec<UserEmoji>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM user_emojis WHERE user_id = $1 ORDER BY name"))
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

pub async fn user_emoji(db: &Pool, user_id: &str, id: &str) -> Result<Option<UserEmoji>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM user_emojis WHERE user_id = $1 AND id = $2"))
        .bind(user_id)
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn user_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT COUNT(*) AS n FROM user_emojis WHERE user_id = $1").bind(user_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub async fn user_insert(
    db: &Pool,
    user_id: &str,
    name: &str,
    files: &NewEmojiFiles<'_>,
) -> Result<UserEmoji, ApiError> {
    let result = sqlx::query(
        "INSERT INTO user_emojis (id, user_id, name, mime, size, animated, still_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(files.id)
    .bind(user_id)
    .bind(name)
    .bind(files.mime)
    .bind(files.size)
    .bind(i64::from(files.animated))
    .bind(files.still_id)
    .bind(now())
    .execute(db)
    .await;
    match result {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Err(name_taken(name, "among your emojis")),
        Err(e) => return Err(e.into()),
    }
    user_emoji(db, user_id, files.id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("emoji not found after INSERT")))
}

pub async fn user_rename(db: &Pool, user_id: &str, id: &str, name: &str) -> Result<bool, ApiError> {
    match sqlx::query("UPDATE user_emojis SET name = $1 WHERE user_id = $2 AND id = $3")
        .bind(name)
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await
    {
        Ok(r) => Ok(r.rows_affected() > 0),
        Err(e) if super::is_unique_violation(&e) => Err(name_taken(name, "among your emojis")),
        Err(e) => Err(e.into()),
    }
}

pub async fn user_delete(db: &Pool, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM user_emojis WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// The stored files of any emoji (room or personal) by id, for the public image route: `(mime, id, still_id)`.
pub async fn files_by_id(db: &Pool, id: &str) -> Result<Option<(String, String, Option<String>)>, ApiError> {
    let row = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT mime, id, still_id FROM emojis WHERE id = $1
         UNION ALL SELECT mime, id, still_id FROM user_emojis WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// Generates the storage ids of a new emoji: `(id, still_id)`.
pub fn new_ids(animated: bool) -> (String, Option<String>) {
    (ulid(), animated.then(ulid))
}
