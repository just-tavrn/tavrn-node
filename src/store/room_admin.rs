// SPDX-License-Identifier: AGPL-3.0-only
//! Room ownership transfer and the node admin's room list (protocol MODERATION.md §4; the single sign-on group map
//! picker).

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError};

/// Makes `owner_id` the owner of the room.
pub async fn set_owner(db: &Pool, room_id: &str, owner_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("UPDATE rooms SET owner_id = $1 WHERE id = $2")
        .bind(owner_id)
        .bind(room_id)
        .execute(db)
        .await?
        .rows_affected()
        > 0)
}

/// A room of the node admin's list.
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct AdminRoomRow {
    pub id: String,
    pub name: String,
    pub owner_username: Option<String>,
    pub owner_domain: Option<String>,
    pub members: i64,
}

/// Rooms of this node by id, optionally with a name containing `q`; `after` pages.
pub async fn list(db: &Pool, q: &str, after: Option<&str>, limit: i64) -> Result<Vec<AdminRoomRow>, ApiError> {
    let pattern = crate::store::directory::like_pattern(q);
    Ok(sqlx::query_as(&format!(
        "SELECT r.id AS id, r.name AS name, u.username AS owner_username, u.domain AS owner_domain,
                (SELECT CAST(COUNT(*) AS BIGINT) FROM room_members m WHERE m.room_id = r.id) AS members
         FROM rooms r LEFT JOIN users u ON u.id = r.owner_id
         WHERE ($1 = '' OR LOWER(r.name) LIKE $1 ESCAPE '\\') AND r.id > $2
         ORDER BY r.id LIMIT {}",
        limit.clamp(1, 100)
    ))
    .bind(pattern)
    .bind(after.unwrap_or(""))
    .fetch_all(db)
    .await?)
}

/// Number of rooms owned by `user_id`.
pub async fn owned_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM rooms WHERE owner_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?
        .try_get::<i64, _>("n")?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn owners_move_and_rooms_list_with_search_and_paging() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        for u in ["a", "b"] {
            sqlx::query(
                "INSERT INTO users (id, username, domain, display_name, created_at) VALUES ($1, $1, 'd', $1, 'x')",
            )
            .bind(u)
            .execute(&db)
            .await
            .unwrap();
        }
        for (id, name) in [("r1", "Guild 100%"), ("r2", "Other"), ("r3", "guild two")] {
            sqlx::query("INSERT INTO rooms (id, name, owner_id, created_at) VALUES ($1, $2, 'a', 'x')")
                .bind(id)
                .bind(name)
                .execute(&db)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO room_members (room_id, user_id, joined_at) VALUES ('r1', 'a', 'x'), ('r1', 'b', 'x')")
            .execute(&db)
            .await
            .unwrap();
        let ids = |rows: Vec<AdminRoomRow>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids(list(&db, "", None, 50).await.unwrap()), vec!["r1", "r2", "r3"]);
        assert_eq!(ids(list(&db, "GUILD", None, 50).await.unwrap()), vec!["r1", "r3"]);
        assert_eq!(ids(list(&db, "100%", None, 50).await.unwrap()), vec!["r1"]);
        assert_eq!(ids(list(&db, "", Some("r1"), 1).await.unwrap()), vec!["r2"]);
        let first = list(&db, "", None, 1).await.unwrap().remove(0);
        assert_eq!((first.owner_username.as_deref(), first.members), (Some("a"), 2));
        assert_eq!(owned_count(&db, "a").await.unwrap(), 3);
        assert!(set_owner(&db, "r1", "b").await.unwrap());
        assert!(!set_owner(&db, "nope", "b").await.unwrap());
        assert_eq!((owned_count(&db, "a").await.unwrap(), owned_count(&db, "b").await.unwrap()), (2, 1));
    }
}
