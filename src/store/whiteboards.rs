// SPDX-License-Identifier: AGPL-3.0-only
//! The whiteboard scene library (`whiteboard_scenes`): encrypted scene and thumbnail blobs
//! per user. Listing never loads the blobs.

use sqlx::Row;

use crate::{db::Pool, error::ApiError, util::now};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceneRow {
    pub id: String,
    pub name: String,
    pub size: i64,
    pub thumbnail_size: i64,
    pub created_at: String,
    pub updated_at: String,
}

const LIST_COLS: &str = "id, name, CAST(LENGTH(scene) AS BIGINT) AS size, \
    CAST(COALESCE(LENGTH(thumbnail), 0) AS BIGINT) AS thumbnail_size, created_at, updated_at";

fn row(r: &sqlx::any::AnyRow) -> Result<SceneRow, ApiError> {
    Ok(SceneRow {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        size: r.try_get("size")?,
        thumbnail_size: r.try_get("thumbnail_size")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// The user's scenes, most recently changed first.
pub async fn list(db: &Pool, user_id: &str) -> Result<Vec<SceneRow>, ApiError> {
    let rows = sqlx::query(&format!(
        "SELECT {LIST_COLS} FROM whiteboard_scenes WHERE user_id = $1 ORDER BY updated_at DESC, id DESC"
    ))
    .bind(user_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(row).collect()
}

pub async fn info(db: &Pool, user_id: &str, id: &str) -> Result<Option<SceneRow>, ApiError> {
    let r = sqlx::query(&format!("SELECT {LIST_COLS} FROM whiteboard_scenes WHERE user_id = $1 AND id = $2"))
        .bind(user_id)
        .bind(id)
        .fetch_optional(db)
        .await?;
    r.as_ref().map(row).transpose()
}

pub async fn count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let r = sqlx::query("SELECT COUNT(*) AS n FROM whiteboard_scenes WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
    Ok(r.try_get::<i64, _>("n")?)
}

/// The encrypted scene blob.
pub async fn scene(db: &Pool, user_id: &str, id: &str) -> Result<Option<Vec<u8>>, ApiError> {
    let r = sqlx::query("SELECT scene FROM whiteboard_scenes WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .fetch_optional(db)
        .await?;
    r.map(|r| Ok(r.try_get("scene")?)).transpose()
}

/// The encrypted thumbnail: `None` without a scene, `Some(None)` for a scene without a thumbnail.
pub async fn thumbnail(db: &Pool, user_id: &str, id: &str) -> Result<Option<Option<Vec<u8>>>, ApiError> {
    let r = sqlx::query("SELECT thumbnail FROM whiteboard_scenes WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .fetch_optional(db)
        .await?;
    r.map(|r| Ok(r.try_get::<Option<Vec<u8>>, _>("thumbnail")?)).transpose()
}

/// Creates a scene. `false` if the id exists already (the caller replaces it instead).
pub async fn create(db: &Pool, user_id: &str, id: &str, name: &str, scene: &[u8]) -> Result<bool, ApiError> {
    let ts = now();
    let r = sqlx::query(
        "INSERT INTO whiteboard_scenes (user_id, id, name, scene, thumbnail, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, NULL, $5, $6)",
    )
    .bind(user_id)
    .bind(id)
    .bind(name)
    .bind(scene.to_vec())
    .bind(&ts)
    .bind(&ts)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Replaces the scene blob (and the name if given). `false` if the scene does not exist.
pub async fn replace(db: &Pool, user_id: &str, id: &str, name: Option<&str>, scene: &[u8]) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE whiteboard_scenes SET scene = $1, name = COALESCE($2, name), updated_at = $3 \
         WHERE user_id = $4 AND id = $5",
    )
    .bind(scene.to_vec())
    .bind(name)
    .bind(now())
    .bind(user_id)
    .bind(id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn set_thumbnail(db: &Pool, user_id: &str, id: &str, thumbnail: &[u8]) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE whiteboard_scenes SET thumbnail = $1 WHERE user_id = $2 AND id = $3")
        .bind(thumbnail.to_vec())
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn rename(db: &Pool, user_id: &str, id: &str, name: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE whiteboard_scenes SET name = $1, updated_at = $2 WHERE user_id = $3 AND id = $4")
        .bind(name)
        .bind(now())
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn delete(db: &Pool, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM whiteboard_scenes WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}
