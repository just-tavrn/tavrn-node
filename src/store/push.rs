// SPDX-License-Identifier: AGPL-3.0-only
//! Push subscriptions of local users' devices (PROTOCOL.md §6d, migration 0280).

use sqlx::FromRow;

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

/// Subscriptions per user (every browser and installed app of the user counts once).
pub const MAX_PER_USER: i64 = 20;
/// A subscription that failed this many times in a row is deleted.
pub const MAX_FAILURES: i64 = 30;

#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct SubscriptionRow {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub failures: i64,
    pub retry_at: Option<String>,
}

const COLS: &str =
    "id, user_id, device_id, endpoint, p256dh, auth, expires_at, created_at, last_used_at, failures, retry_at";
/// [`COLS`] of the table aliased `p` (in joins).
const P_COLS: &str = "p.id, p.user_id, p.device_id, p.endpoint, p.p256dh, p.auth, p.expires_at, p.created_at, \
    p.last_used_at, p.failures, p.retry_at";

pub struct NewSubscription<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub endpoint: &'a str,
    pub p256dh: &'a str,
    pub auth: &'a str,
    pub expires_at: Option<&'a str>,
}

/// Outcome of [`upsert`].
#[derive(Debug)]
pub enum Upsert {
    /// The row and whether it is new.
    Saved(Box<SubscriptionRow>, bool),
    /// The user already has [`MAX_PER_USER`] other subscriptions.
    TooMany,
    /// The endpoint belongs to a live subscription of another user.
    Taken,
}

/// Registers a subscription, or updates the one with the same endpoint (keys and device are replaced, the failure
/// count is reset). The same user moves an endpoint between its devices; another user's endpoint is refused while
/// that subscription is live (not expired, its device has a live session) and taken over once it is stale, so a
/// known endpoint URL cannot be used to cut another account off its pushes (tavrn-node #9).
pub async fn upsert(db: &Pool, s: NewSubscription<'_>) -> Result<Upsert, ApiError> {
    let mut tx = db.begin().await?;
    let ts = now();
    let existing: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT id, user_id, CASE WHEN (expires_at IS NULL OR expires_at > $2)
                AND EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = p.device_id AND s.revoked_at IS NULL
                            AND s.expires_at > $2) THEN 1 ELSE 0 END
         FROM push_subscriptions p WHERE endpoint = $1",
    )
    .bind(s.endpoint)
    .bind(&ts)
    .fetch_optional(&mut *tx)
    .await?;
    let own_existing = existing.as_ref().is_some_and(|(_, u, _)| u == s.user_id);
    if !own_existing {
        if existing.as_ref().is_some_and(|(_, _, live)| *live == 1) {
            return Ok(Upsert::Taken);
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions WHERE user_id = $1")
            .bind(s.user_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_PER_USER {
            return Ok(Upsert::TooMany);
        }
    }
    let (id, created) = match existing {
        Some((id, _, _)) => {
            sqlx::query(
                "UPDATE push_subscriptions SET device_id = $2, p256dh = $3, auth = $4, expires_at = $5,
                 failures = CASE WHEN user_id = $1 THEN failures ELSE 0 END,
                 retry_at = CASE WHEN user_id = $1 THEN retry_at ELSE NULL END, user_id = $1
                 WHERE id = $6",
            )
            .bind(s.user_id)
            .bind(s.device_id)
            .bind(s.p256dh)
            .bind(s.auth)
            .bind(s.expires_at)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
            (id, false)
        }
        None => {
            let id = ulid();
            sqlx::query(
                "INSERT INTO push_subscriptions (id, user_id, device_id, endpoint, p256dh, auth, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&id)
            .bind(s.user_id)
            .bind(s.device_id)
            .bind(s.endpoint)
            .bind(s.p256dh)
            .bind(s.auth)
            .bind(s.expires_at)
            .bind(now())
            .execute(&mut *tx)
            .await?;
            (id, true)
        }
    };
    let row = sqlx::query_as::<_, SubscriptionRow>(&format!("SELECT {COLS} FROM push_subscriptions WHERE id = $1"))
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Upsert::Saved(Box::new(row), created))
}

/// The user's subscriptions, oldest first.
pub async fn list(db: &Pool, user_id: &str) -> Result<Vec<SubscriptionRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM push_subscriptions WHERE user_id = $1 ORDER BY created_at, id"))
        .bind(user_id)
        .fetch_all(db)
        .await?)
}

/// Subscriptions a push may go to now: of a device with a live session, not expired, not held back after a
/// failure.
pub async fn deliverable(db: &Pool, user_id: &str) -> Result<Vec<SubscriptionRow>, ApiError> {
    let ts = now();
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM push_subscriptions p WHERE user_id = $1
           AND (expires_at IS NULL OR expires_at > $2) AND (retry_at IS NULL OR retry_at <= $2)
           AND EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = p.device_id AND s.revoked_at IS NULL
                       AND s.expires_at > $2)
         ORDER BY created_at, id"
    ))
    .bind(user_id)
    .bind(ts)
    .fetch_all(db)
    .await?)
}

/// A local user a message may push to, with what the decision needs: [`recipients`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub user_id: String,
    pub username: String,
    /// The stored notification settings (JSON), `None` for the defaults.
    pub settings: Option<String>,
    /// The user and the author blocked each other (either direction).
    pub blocked: bool,
    /// The deliverable subscriptions ([`deliverable`]), oldest first.
    pub subscriptions: Vec<SubscriptionRow>,
}

#[derive(FromRow)]
struct RecipientRow {
    #[sqlx(flatten)]
    subscription: SubscriptionRow,
    username: String,
    settings: Option<String>,
    blocked: i64,
}

/// Of `user_ids`, the enabled users of `domain` with a deliverable subscription ([`deliverable`]), with their
/// notification settings and whether they and `author_id` blocked each other: one statement per 500 users instead
/// of four per user (the push fan-out of a message). Ordered by user id.
pub async fn recipients(
    db: &Pool,
    user_ids: &[String],
    author_id: &str,
    domain: &str,
) -> Result<Vec<Recipient>, ApiError> {
    let ts = now();
    let mut out: Vec<Recipient> = Vec::new();
    for chunk in user_ids.chunks(500) {
        let placeholders: Vec<String> = (4..4 + chunk.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "SELECT {P_COLS}, u.username, n.settings,
                    CASE WHEN EXISTS (SELECT 1 FROM user_blocks b
                                      WHERE (b.user_id = p.user_id AND b.blocked_id = $1)
                                         OR (b.user_id = $1 AND b.blocked_id = p.user_id)) THEN 1 ELSE 0 END AS blocked
             FROM push_subscriptions p
             JOIN users u ON u.id = p.user_id
             LEFT JOIN notification_settings n ON n.user_id = p.user_id
             WHERE p.user_id IN ({}) AND u.domain = $3 AND u.disabled_at IS NULL
               AND (p.expires_at IS NULL OR p.expires_at > $2) AND (p.retry_at IS NULL OR p.retry_at <= $2)
               AND EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = p.device_id AND s.revoked_at IS NULL
                           AND s.expires_at > $2)
             ORDER BY p.user_id, p.created_at, p.id",
            placeholders.join(", ")
        );
        let mut q = sqlx::query_as::<_, RecipientRow>(&sql).bind(author_id).bind(&ts).bind(domain);
        for id in chunk {
            q = q.bind(id);
        }
        for row in q.fetch_all(db).await? {
            match out.last_mut() {
                Some(last) if last.user_id == row.subscription.user_id => last.subscriptions.push(row.subscription),
                _ => out.push(Recipient {
                    user_id: row.subscription.user_id.clone(),
                    username: row.username,
                    settings: row.settings,
                    blocked: row.blocked != 0,
                    subscriptions: vec![row.subscription],
                }),
            }
        }
    }
    Ok(out)
}

/// Of `user_ids`, those with at least one subscription (cheap pre-filter before notification rules are evaluated).
pub async fn users_with_subscriptions(db: &Pool, user_ids: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    // Bounded IN lists; the candidates are a room's members, which may be many.
    for chunk in user_ids.chunks(500) {
        let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "SELECT DISTINCT user_id FROM push_subscriptions WHERE user_id IN ({}) ORDER BY user_id",
            placeholders.join(", ")
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql);
        for id in chunk {
            q = q.bind(id);
        }
        out.extend(q.fetch_all(db).await?);
    }
    Ok(out)
}

/// Members of a room with at least one subscription.
pub async fn room_members_with_subscriptions(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT p.user_id FROM push_subscriptions p JOIN room_members m ON m.user_id = p.user_id
         WHERE m.room_id = $1 ORDER BY p.user_id",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

/// Deletes one subscription of the user. `false` when there is none with this id.
pub async fn delete(db: &Pool, user_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM push_subscriptions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Deletes a subscription the push service no longer knows (404/410) or that failed too often.
pub async fn remove(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM push_subscriptions WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

/// Deletes the subscriptions of a device (its sessions were revoked).
pub async fn delete_for_device(db: &Pool, device_id: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM push_subscriptions WHERE device_id = $1")
        .bind(device_id)
        .execute(db)
        .await?
        .rows_affected())
}

/// A successful delivery: resets the failure count.
pub async fn mark_used(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE push_subscriptions SET last_used_at = $1, failures = 0, retry_at = NULL WHERE id = $2")
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Successful deliveries of one push job: [`mark_used`] for many subscriptions in one statement per 500.
pub async fn mark_used_many(db: &Pool, ids: &[String]) -> Result<(), ApiError> {
    let ts = now();
    for chunk in ids.chunks(500) {
        let placeholders: Vec<String> = (2..2 + chunk.len()).map(|i| format!("${i}")).collect();
        let sql = format!(
            "UPDATE push_subscriptions SET last_used_at = $1, failures = 0, retry_at = NULL WHERE id IN ({})",
            placeholders.join(", ")
        );
        let mut q = sqlx::query(&sql).bind(&ts);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(db).await?;
    }
    Ok(())
}

/// A failed delivery (429, 5xx, network): holds the subscription back until `retry_at`; after [`MAX_FAILURES`]
/// in a row it is deleted. Returns `true` when it was deleted.
pub async fn mark_failed(db: &Pool, id: &str, retry_at: &str) -> Result<bool, ApiError> {
    sqlx::query("UPDATE push_subscriptions SET failures = failures + 1, retry_at = $1 WHERE id = $2")
        .bind(retry_at)
        .bind(id)
        .execute(db)
        .await?;
    let r = sqlx::query("DELETE FROM push_subscriptions WHERE id = $1 AND failures >= $2")
        .bind(id)
        .bind(MAX_FAILURES)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Housekeeping: deletes expired subscriptions and those of devices without a live session. Returns the count.
pub async fn prune(db: &Pool) -> Result<u64, ApiError> {
    let ts = now();
    Ok(sqlx::query(
        "DELETE FROM push_subscriptions WHERE (expires_at IS NOT NULL AND expires_at <= $1)
            OR NOT EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = push_subscriptions.device_id
                           AND s.revoked_at IS NULL AND s.expires_at > $1)",
    )
    .bind(ts)
    .execute(db)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    impl Upsert {
        fn unwrap(self) -> (SubscriptionRow, bool) {
            match self {
                Upsert::Saved(row, created) => (*row, created),
                other => panic!("not saved: {other:?}"),
            }
        }
    }

    async fn db_with_user(users: &[&str]) -> Pool {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        for u in users {
            sqlx::query(
                "INSERT INTO users (id, username, domain, display_name, password_hash, created_at)
                 VALUES ($1, $1, 'n.test', $1, '', $2)",
            )
            .bind(*u)
            .bind(now())
            .execute(&db)
            .await
            .unwrap();
            for d in ["1", "2"] {
                let device = format!("{u}-d{d}");
                sqlx::query(
                    "INSERT INTO devices (id, user_id, name, created_at, last_seen_at) VALUES ($1, $2, 'x', $3, $3)",
                )
                .bind(&device)
                .bind(*u)
                .bind(now())
                .execute(&db)
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, created_at, expires_at)
                     VALUES ($1, $2, $3, $1, $4, $5)",
                )
                .bind(format!("s-{device}"))
                .bind(*u)
                .bind(&device)
                .bind(now())
                .bind(crate::util::in_seconds(3600))
                .execute(&db)
                .await
                .unwrap();
            }
        }
        db
    }

    fn sub<'a>(user: &'a str, device: &'a str, endpoint: &'a str) -> NewSubscription<'a> {
        NewSubscription { user_id: user, device_id: device, endpoint, p256dh: "k", auth: "a", expires_at: None }
    }

    #[tokio::test]
    async fn upsert_list_delete_and_takeover() {
        let db = db_with_user(&["u1", "u2"]).await;
        let (a, created) = upsert(&db, sub("u1", "u1-d1", "https://push.example/a")).await.unwrap().unwrap();
        assert!(created);
        let (again, created) = upsert(&db, sub("u1", "u1-d1", "https://push.example/a")).await.unwrap().unwrap();
        assert!(!created);
        assert_eq!(again.id, a.id, "same endpoint, same row");
        upsert(&db, sub("u1", "u1-d2", "https://push.example/b")).await.unwrap().unwrap();
        assert_eq!(list(&db, "u1").await.unwrap().len(), 2);
        // The same user moves it to another device.
        let (moved, created) = upsert(&db, sub("u1", "u1-d2", "https://push.example/a")).await.unwrap().unwrap();
        assert_eq!((moved.id.as_str(), moved.device_id.as_str(), created), (a.id.as_str(), "u1-d2", false));
        // Another user is refused while the subscription is live (tavrn-node #9).
        assert!(matches!(upsert(&db, sub("u2", "u2-d1", "https://push.example/a")).await.unwrap(), Upsert::Taken));
        assert_eq!(list(&db, "u1").await.unwrap().len(), 2);
        // An expired subscription is stale: another user takes it over.
        sqlx::query("UPDATE push_subscriptions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = $1")
            .bind(&a.id)
            .execute(&db)
            .await
            .unwrap();
        let (moved, _) = upsert(&db, sub("u2", "u2-d1", "https://push.example/a")).await.unwrap().unwrap();
        assert_eq!((moved.id.as_str(), moved.user_id.as_str()), (a.id.as_str(), "u2"));
        assert_eq!(list(&db, "u1").await.unwrap().len(), 1);
        assert!(!delete(&db, "u1", &a.id).await.unwrap(), "only the owner deletes");
        assert!(delete(&db, "u2", &a.id).await.unwrap());
        assert!(list(&db, "u2").await.unwrap().is_empty());
        assert_eq!(users_with_subscriptions(&db, &["u1".into(), "u2".into(), "u3".into()]).await.unwrap(), vec!["u1"]);
    }

    #[tokio::test]
    async fn recipients_carry_settings_blocks_and_deliverable_subscriptions() {
        let db = db_with_user(&["u1", "u2", "u3", "author"]).await;
        let (a, _) = upsert(&db, sub("u1", "u1-d1", "https://push.example/a")).await.unwrap().unwrap();
        let (b, _) = upsert(&db, sub("u1", "u1-d2", "https://push.example/b")).await.unwrap().unwrap();
        let (c, _) = upsert(&db, sub("u2", "u2-d1", "https://push.example/c")).await.unwrap().unwrap();
        upsert(&db, sub("u3", "u3-d1", "https://push.example/d")).await.unwrap().unwrap();
        sqlx::query("INSERT INTO notification_settings (user_id, settings, updated_at) VALUES ('u1', '{}', $1)")
            .bind(now())
            .execute(&db)
            .await
            .unwrap();
        crate::store::social::block(&db, "author", "u2", "").await.unwrap();
        // u3 is disabled; u1's second device is held back.
        sqlx::query("UPDATE users SET disabled_at = $1 WHERE id = 'u3'").bind(now()).execute(&db).await.unwrap();
        mark_failed(&db, &b.id, &crate::util::in_seconds(60)).await.unwrap();
        let ids = ["u1", "u2", "u3", "nobody"].map(String::from);
        let got = recipients(&db, &ids, "author", "n.test").await.unwrap();
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!((got[0].user_id.as_str(), got[0].settings.as_deref(), got[0].blocked), ("u1", Some("{}"), false));
        assert_eq!(got[0].subscriptions.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), [a.id.as_str()]);
        assert_eq!((got[1].user_id.as_str(), got[1].settings.as_deref(), got[1].blocked), ("u2", None, true));
        assert_eq!(got[1].subscriptions[0], c);
        assert!(recipients(&db, &ids, "author", "other.test").await.unwrap().is_empty(), "local users only");
        mark_used_many(&db, &[b.id.clone(), c.id.clone()]).await.unwrap();
        let rows = list(&db, "u1").await.unwrap();
        let row = rows.iter().find(|r| r.id == b.id).unwrap();
        assert_eq!((row.failures, row.retry_at.is_none(), row.last_used_at.is_some()), (0, true, true));
    }

    #[tokio::test]
    async fn limit_per_user() {
        let db = db_with_user(&["u1"]).await;
        for i in 0..MAX_PER_USER {
            upsert(&db, sub("u1", "u1-d1", &format!("https://push.example/{i}"))).await.unwrap().unwrap();
        }
        assert!(matches!(upsert(&db, sub("u1", "u1-d1", "https://push.example/new")).await.unwrap(), Upsert::TooMany));
        assert!(
            matches!(upsert(&db, sub("u1", "u1-d1", "https://push.example/0")).await.unwrap(), Upsert::Saved(..)),
            "updates pass"
        );
    }

    #[tokio::test]
    async fn deliverable_failures_and_pruning() {
        let db = db_with_user(&["u1"]).await;
        let (a, _) = upsert(&db, sub("u1", "u1-d1", "https://push.example/a")).await.unwrap().unwrap();
        let (b, _) = upsert(&db, sub("u1", "u1-d2", "https://push.example/b")).await.unwrap().unwrap();
        let expired = NewSubscription {
            expires_at: Some("2000-01-01T00:00:00.000Z"),
            ..sub("u1", "u1-d1", "https://push.example/c")
        };
        upsert(&db, expired).await.unwrap().unwrap();
        let ids = |rows: Vec<SubscriptionRow>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids(deliverable(&db, "u1").await.unwrap()), vec![a.id.clone(), b.id.clone()]);
        // A failure holds the subscription back until retry_at; success resets it.
        assert!(!mark_failed(&db, &a.id, &crate::util::in_seconds(60)).await.unwrap());
        assert_eq!(ids(deliverable(&db, "u1").await.unwrap()), vec![b.id.clone()]);
        mark_used(&db, &a.id).await.unwrap();
        let row = list(&db, "u1").await.unwrap().into_iter().find(|r| r.id == a.id).unwrap();
        assert_eq!((row.failures, row.retry_at.is_none(), row.last_used_at.is_some()), (0, true, true));
        // Too many failures in a row delete it.
        sqlx::query("UPDATE push_subscriptions SET failures = $1 WHERE id = $2")
            .bind(MAX_FAILURES - 1)
            .bind(&a.id)
            .execute(&db)
            .await
            .unwrap();
        assert!(mark_failed(&db, &a.id, &now()).await.unwrap());
        // Revoked sessions: not deliverable, pruned by housekeeping (with the expired one).
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE device_id = 'u1-d2'")
            .bind(now())
            .execute(&db)
            .await
            .unwrap();
        assert!(deliverable(&db, "u1").await.unwrap().is_empty());
        assert_eq!(prune(&db).await.unwrap(), 2);
        assert!(list(&db, "u1").await.unwrap().is_empty());
        upsert(&db, sub("u1", "u1-d1", "https://push.example/d")).await.unwrap().unwrap();
        assert_eq!(delete_for_device(&db, "u1-d1").await.unwrap(), 1);
        upsert(&db, sub("u1", "u1-d1", "https://push.example/e")).await.unwrap().unwrap();
        remove(&db, &list(&db, "u1").await.unwrap()[0].id).await.unwrap();
        assert!(list(&db, "u1").await.unwrap().is_empty());
    }
}
