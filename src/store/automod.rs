// SPDX-License-Identifier: AGPL-3.0-only
//! The content rules of a room (protocol MODERATION.md §2.2): one JSON document per room (migration 0270).

use sqlx::Row;

use crate::{db::Pool, error::ApiError};

/// The rules document of a room (`[]` without one).
pub async fn rules(db: &Pool, room_id: &str) -> Result<String, ApiError> {
    let row =
        sqlx::query("SELECT rules FROM automod_rules WHERE room_id = $1").bind(room_id).fetch_optional(db).await?;
    Ok(match row {
        Some(r) => r.try_get::<String, _>("rules")?,
        None => "[]".into(),
    })
}

/// Replaces the rules document of a room.
pub async fn set_rules(db: &Pool, room_id: &str, rules: &str, now: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO automod_rules (room_id, rules, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (room_id) DO UPDATE SET rules = excluded.rules, updated_at = excluded.updated_at",
    )
    .bind(room_id)
    .bind(rules)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn rules_round_trip_per_room() {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, username, domain, display_name, created_at) VALUES ('u', 'u', 'd', 'u', 'x')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO rooms (id, name, owner_id, created_at) VALUES ('r', 'R', 'u', 'x')")
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(rules(&db, "r").await.unwrap(), "[]");
        set_rules(&db, "r", r#"[{"name":"a"}]"#, "t1").await.unwrap();
        set_rules(&db, "r", r#"[{"name":"b"}]"#, "t2").await.unwrap();
        assert_eq!(rules(&db, "r").await.unwrap(), r#"[{"name":"b"}]"#);
        assert_eq!(rules(&db, "other").await.unwrap(), "[]");
    }
}
