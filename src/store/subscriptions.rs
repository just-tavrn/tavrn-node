// SPDX-License-Identifier: AGPL-3.0-only
//! Event subscriptions of applications and their outbox (protocol/APPLICATIONS.md §6.2).

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util::now};

#[derive(Debug, Clone, FromRow)]
pub struct SubscriptionRow {
    pub application_id: String,
    pub url: String,
    /// JSON array of event types.
    pub events: String,
    /// active | failing | disabled
    pub state: String,
    pub last_success_at: Option<String>,
    pub last_error: Option<String>,
    pub dropped: i64,
    pub enabled_at: String,
    pub created_at: String,
}

impl SubscriptionRow {
    pub fn events(&self) -> Vec<String> {
        serde_json::from_str(&self.events).unwrap_or_default()
    }
}

const COLS: &str = "s.application_id, s.url, s.events, s.state, s.last_success_at, s.last_error, s.dropped, s.enabled_at, s.created_at";

pub async fn get(db: &Pool, application_id: &str) -> Result<Option<SubscriptionRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM application_subscriptions s WHERE s.application_id = $1"))
        .bind(application_id)
        .fetch_optional(db)
        .await?)
}

/// Creates or replaces the subscription after a successful verification: state `active`, no error.
pub async fn upsert(db: &Pool, application_id: &str, url: &str, events: &[String]) -> Result<(), ApiError> {
    let ts = now();
    let events = serde_json::to_string(events).unwrap_or_else(|_| "[]".into());
    sqlx::query(
        "INSERT INTO application_subscriptions (application_id, url, events, state, dropped, enabled_at, created_at)
         VALUES ($1, $2, $3, 'active', 0, $4, $4)
         ON CONFLICT (application_id) DO UPDATE SET url = excluded.url, events = excluded.events, state = 'active',
                last_error = NULL, enabled_at = excluded.enabled_at",
    )
    .bind(application_id)
    .bind(url)
    .bind(events)
    .bind(ts)
    .execute(db)
    .await?;
    Ok(())
}

/// Re-enables a subscription after a successful verification.
pub async fn enable(db: &Pool, application_id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_subscriptions SET state = 'active', last_error = NULL, enabled_at = $1 WHERE application_id = $2",
    )
    .bind(now())
    .bind(application_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Deletes the subscription and every queued event.
pub async fn delete(db: &Pool, application_id: &str) -> Result<bool, ApiError> {
    clear_outbox(db, application_id).await?;
    let r = sqlx::query("DELETE FROM application_subscriptions WHERE application_id = $1")
        .bind(application_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn clear_outbox(db: &Pool, application_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM application_outbox WHERE application_id = $1").bind(application_id).execute(db).await?;
    Ok(())
}

/// A delivery succeeded at `at`: a failing subscription is active again.
pub async fn succeeded(db: &Pool, application_id: &str, at: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_subscriptions SET last_success_at = $1, last_error = NULL,
                state = CASE WHEN state = 'failing' THEN 'active' ELSE state END
          WHERE application_id = $2",
    )
    .bind(at)
    .bind(application_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Records the error of an attempt; `given_up` (an event was dropped for good) turns an active subscription
/// into `failing`.
pub async fn failed(db: &Pool, application_id: &str, error: &str, given_up: bool) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE application_subscriptions SET last_error = $1,
                state = CASE WHEN $2 = 1 AND state = 'active' THEN 'failing' ELSE state END
          WHERE application_id = $3",
    )
    .bind(error)
    .bind(given_up as i64)
    .bind(application_id)
    .execute(db)
    .await?;
    Ok(())
}

/// Failing subscriptions without a success (or (re-)enabling) since `before`: they are disabled. Returns
/// `(application id, owner id, url, last error)`.
pub async fn disable_stale(db: &Pool, before: &str) -> Result<Vec<(String, String, String, Option<String>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT s.application_id, a.owner_id, s.url, s.last_error FROM application_subscriptions s
           JOIN applications a ON a.id = s.application_id
          WHERE s.state = 'failing' AND COALESCE(s.last_success_at, s.enabled_at) < $1
            AND s.enabled_at < $1",
    )
    .bind(before)
    .fetch_all(db)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        let app: String = r.try_get("application_id")?;
        sqlx::query("UPDATE application_subscriptions SET state = 'disabled' WHERE application_id = $1")
            .bind(&app)
            .execute(db)
            .await?;
        clear_outbox(db, &app).await?;
        out.push((app, r.try_get("owner_id")?, r.try_get("url")?, r.try_get("last_error")?));
    }
    Ok(out)
}

/// A subscription that may receive events of a room: its application's bot is a member there.
#[derive(Debug, Clone, FromRow)]
pub struct RoomSubscriber {
    pub application_id: String,
    pub events: String,
    pub bot_user_id: String,
}

/// The enabled subscriptions whose bot is a member of `room_id`.
pub async fn subscribers_of_room(db: &Pool, room_id: &str) -> Result<Vec<RoomSubscriber>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT s.application_id, s.events, a.bot_user_id FROM application_subscriptions s
           JOIN applications a ON a.id = s.application_id
           JOIN room_members m ON m.user_id = a.bot_user_id AND m.room_id = $1
          WHERE s.state <> 'disabled'",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

pub struct NewHook<'a> {
    pub application_id: &'a str,
    pub event_id: &'a str,
    pub event_type: &'a str,
    pub body: &'a str,
    pub next_at: &'a str,
    pub expires_at: &'a str,
}

/// Queues a delivery. Beyond `cap` queued events of the application the oldest are dropped (and counted in
/// `dropped`). Returns the number dropped. The new event is inserted first and the queue then trimmed to the
/// newest `cap` in the same transaction, so concurrent enqueues cannot leave more than `cap` behind, and no count
/// of the whole queue runs per event.
pub async fn enqueue(db: &Pool, h: NewHook<'_>, cap: i64) -> Result<i64, ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO application_outbox (id, application_id, event_id, event_type, body, attempts, next_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, 0, $6, $7)",
    )
    .bind(crate::util::ulid())
    .bind(h.application_id)
    .bind(h.event_id)
    .bind(h.event_type)
    .bind(h.body)
    .bind(h.next_at)
    .bind(h.expires_at)
    .execute(&mut *tx)
    .await?;
    let dropped = sqlx::query(
        "DELETE FROM application_outbox WHERE application_id = $1 AND id <=
           (SELECT id FROM application_outbox WHERE application_id = $1 ORDER BY id DESC LIMIT 1 OFFSET $2)",
    )
    .bind(h.application_id)
    .bind(cap)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let dropped = i64::try_from(dropped).unwrap_or(i64::MAX);
    if dropped > 0 {
        sqlx::query("UPDATE application_subscriptions SET dropped = dropped + $1 WHERE application_id = $2")
            .bind(dropped)
            .bind(h.application_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(dropped)
}

pub async fn queued(db: &Pool, application_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM application_outbox WHERE application_id = $1")
        .bind(application_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}

/// A queued delivery with the subscription's URL.
#[derive(Debug, Clone, FromRow)]
pub struct OutboxRow {
    pub id: String,
    pub application_id: String,
    pub event_id: String,
    pub event_type: String,
    pub body: String,
    pub attempts: i64,
    pub next_at: String,
    pub expires_at: String,
    pub last_error: Option<String>,
    pub url: String,
}

/// Deliveries due at `at` of subscriptions that are not disabled, oldest first.
pub async fn due(db: &Pool, at: &str, limit: i64) -> Result<Vec<OutboxRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT o.id, o.application_id, o.event_id, o.event_type, o.body, o.attempts, o.next_at, o.expires_at,
                o.last_error, s.url
           FROM application_outbox o JOIN application_subscriptions s ON s.application_id = o.application_id
          WHERE o.next_at <= $1 AND s.state <> 'disabled' ORDER BY o.next_at, o.id LIMIT $2",
    )
    .bind(at)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Every queued delivery of an application (tests, diagnostics).
pub async fn outbox_of(db: &Pool, application_id: &str) -> Result<Vec<OutboxRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT o.id, o.application_id, o.event_id, o.event_type, o.body, o.attempts, o.next_at, o.expires_at,
                o.last_error, s.url
           FROM application_outbox o JOIN application_subscriptions s ON s.application_id = o.application_id
          WHERE o.application_id = $1 ORDER BY o.id",
    )
    .bind(application_id)
    .fetch_all(db)
    .await?)
}

pub async fn delete_outbox(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM application_outbox WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

pub async fn reschedule(db: &Pool, id: &str, attempts: i64, next_at: &str, error: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE application_outbox SET attempts = $1, next_at = $2, last_error = $3 WHERE id = $4")
        .bind(attempts)
        .bind(next_at)
        .bind(error)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}
