// SPDX-License-Identifier: AGPL-3.0-only
//! Poll vote records (protocol PROTOCOL.md §7g): one row per user and poll message, deleted with the message
//! (foreign key cascade), and the plaintext close time on the message.

use sqlx::FromRow;

use crate::{db::Pool, error::ApiError, util::now};

/// A stored vote with the voter's address (joined from `users`).
#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct VoteRow {
    pub message_id: String,
    pub conversation_id: String,
    pub user_id: String,
    pub username: String,
    pub domain: String,
    pub device_id: Option<String>,
    pub epoch: Option<i64>,
    pub content: String,
    pub signature: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

const COLS: &str = "v.message_id, v.conversation_id, v.user_id, u.username, u.domain, v.device_id, v.epoch, v.content, \
                    v.signature, v.created_at, v.updated_at";

pub struct NewVote<'a> {
    pub message_id: &'a str,
    pub conversation_id: &'a str,
    pub user_id: &'a str,
    pub device_id: Option<&'a str>,
    pub epoch: Option<i64>,
    /// Ciphertext, or the plaintext vote object as JSON.
    pub content: &'a str,
    pub signature: Option<&'a str>,
}

/// Creates or replaces the user's vote on the message (the last device wins); `created_at` stays from the first vote.
pub async fn upsert(db: &Pool, v: NewVote<'_>) -> Result<VoteRow, ApiError> {
    let t = now();
    sqlx::query(
        "INSERT INTO poll_votes (message_id, user_id, conversation_id, device_id, epoch, content, signature, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
         ON CONFLICT (message_id, user_id) DO UPDATE SET device_id = excluded.device_id, epoch = excluded.epoch,
             content = excluded.content, signature = excluded.signature, updated_at = excluded.updated_at",
    )
    .bind(v.message_id)
    .bind(v.user_id)
    .bind(v.conversation_id)
    .bind(v.device_id)
    .bind(v.epoch)
    .bind(v.content)
    .bind(v.signature)
    .bind(&t)
    .execute(db)
    .await?;
    get(db, v.message_id, v.user_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("vote not found after the upsert")))
}

pub async fn get(db: &Pool, message_id: &str, user_id: &str) -> Result<Option<VoteRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM poll_votes v JOIN users u ON u.id = v.user_id WHERE v.message_id = $1 AND v.user_id = $2"
    ))
    .bind(message_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

/// Every vote of a poll message, oldest first (at most one per member).
pub async fn list(db: &Pool, message_id: &str) -> Result<Vec<VoteRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM poll_votes v JOIN users u ON u.id = v.user_id WHERE v.message_id = $1 \
         ORDER BY v.created_at, v.user_id"
    ))
    .bind(message_id)
    .fetch_all(db)
    .await?)
}

/// Retracts the user's vote; `false` when there was none.
pub async fn delete(db: &Pool, message_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM poll_votes WHERE message_id = $1 AND user_id = $2")
        .bind(message_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Sets the plaintext close time of a message (create and close early; the caller checks the rules).
pub async fn set_closes_at(db: &Pool, message_id: &str, closes_at: &str) -> Result<(), ApiError> {
    set_closes_at_on(&mut *db.acquire().await?, message_id, closes_at).await
}

/// [`set_closes_at`] on one connection (a transaction).
pub async fn set_closes_at_on(db: &mut sqlx::AnyConnection, message_id: &str, closes_at: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE messages SET poll_closes_at = $1 WHERE id = $2")
        .bind(closes_at)
        .bind(message_id)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    async fn db() -> Pool {
        let pool = crate::db::connect("sqlite::memory:").await.unwrap();
        let t = now();
        for (id, name) in [("u1", "alice"), ("u2", "bob")] {
            sqlx::query(
                "INSERT INTO users (id, username, domain, display_name, created_at) VALUES ($1, $2, 'd', $2, $3)",
            )
            .bind(id)
            .bind(name)
            .bind(&t)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO conversations (id, kind, encrypted, created_at) VALUES ('c', 'dm', 0, $1)")
            .bind(&t)
            .execute(&pool)
            .await
            .unwrap();
        for id in ["m1", "m2"] {
            sqlx::query(
                "INSERT INTO messages (id, conversation_id, author_id, encrypted, format, content, content_size, mentions, mentions_everyone, created_at)
                 VALUES ($1, 'c', 'u1', 0, 1, '{}', 2, '[]', 0, $2)",
            )
            .bind(id)
            .bind(&t)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool
    }

    fn vote<'a>(message_id: &'a str, user_id: &'a str, content: &'a str, device: &'a str) -> NewVote<'a> {
        NewVote {
            message_id,
            conversation_id: "c",
            user_id,
            device_id: Some(device),
            epoch: None,
            content,
            signature: None,
        }
    }

    #[tokio::test]
    async fn one_vote_per_user_and_poll_the_last_device_wins() {
        let db = db().await;
        let first = upsert(&db, vote("m1", "u1", "{\"a\":1}", "d1")).await.unwrap();
        assert_eq!((first.username.as_str(), first.domain.as_str()), ("alice", "d"));
        let second = upsert(&db, vote("m1", "u1", "{\"a\":2}", "d2")).await.unwrap();
        assert_eq!(second.created_at, first.created_at, "created_at stays");
        assert_eq!((second.content.as_str(), second.device_id.as_deref()), ("{\"a\":2}", Some("d2")));
        upsert(&db, vote("m1", "u2", "{}", "d3")).await.unwrap();
        upsert(&db, vote("m2", "u1", "{}", "d1")).await.unwrap();
        let users: Vec<String> = list(&db, "m1").await.unwrap().into_iter().map(|v| v.user_id).collect();
        assert_eq!(users, vec!["u1", "u2"]);
        assert!(delete(&db, "m1", "u2").await.unwrap());
        assert!(!delete(&db, "m1", "u2").await.unwrap());
        assert_eq!(list(&db, "m1").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn votes_go_with_their_message_and_the_close_time_is_stored() {
        let db = db().await;
        upsert(&db, vote("m1", "u1", "{}", "d1")).await.unwrap();
        upsert(&db, vote("m2", "u2", "{}", "d1")).await.unwrap();
        set_closes_at(&db, "m2", "2030-01-01T00:00:00Z").await.unwrap();
        let closes: Option<String> =
            sqlx::query_scalar("SELECT poll_closes_at FROM messages WHERE id = 'm2'").fetch_one(&db).await.unwrap();
        assert_eq!(closes.as_deref(), Some("2030-01-01T00:00:00Z"));
        sqlx::query("DELETE FROM messages WHERE id = 'm1'").execute(&db).await.unwrap();
        assert!(list(&db, "m1").await.unwrap().is_empty(), "cascade");
        assert_eq!(list(&db, "m2").await.unwrap().len(), 1);
    }
}
