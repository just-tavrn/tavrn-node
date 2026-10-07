// SPDX-License-Identifier: AGPL-3.0-only
//! Incoming webhooks (protocol/APPLICATIONS.md §6.1) and their pseudo users.

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError, util::now};

/// A webhook joined with its pseudo user's avatar and the creator's address.
#[derive(Debug, Clone, FromRow)]
pub struct WebhookRow {
    pub id: String,
    pub room_id: String,
    pub channel_id: String,
    pub user_id: String,
    pub name: String,
    pub token_hash: String,
    pub allow_mentions_everyone: i64,
    pub suspended: i64,
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// The creator's address (`users.owner_address` of the pseudo user).
    pub creator: Option<String>,
    /// `sender` | `node` in encrypted channels, NULL in unencrypted ones (APPLICATIONS.md §6.1a).
    #[sqlx(default)]
    pub sealing: Option<String>,
    /// Sealed, but the channel has no published inbox key yet (computed).
    #[sqlx(default)]
    pub pending_key: i64,
}

const COLS: &str = "w.id, w.room_id, w.channel_id, w.user_id, w.name, w.token_hash, w.allow_mentions_everyone, w.suspended, w.created_by, w.created_at, w.last_used_at, u.owner_address AS creator, w.sealing, CAST(CASE WHEN w.sealing IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inbox_keys k WHERE k.conversation_id = w.channel_id) THEN 1 ELSE 0 END AS BIGINT) AS pending_key";
const FROM: &str = "FROM webhooks w JOIN users u ON u.id = w.user_id";

pub struct NewWebhook<'a> {
    pub id: &'a str,
    pub room_id: &'a str,
    pub channel_id: &'a str,
    pub name: &'a str,
    pub token_hash: &'a str,
    pub allow_mentions_everyone: bool,
    pub domain: &'a str,
    pub creator_id: &'a str,
    pub creator_address: &'a str,
    pub sealing: Option<&'a str>,
}

/// The username of a webhook's pseudo user.
pub fn pseudo_username(webhook_id: &str) -> String {
    format!("wh.{}", webhook_id.to_lowercase())
}

/// Creates the webhook and its pseudo user (`kind = 'webhook'`, no password, no memberships, DMs refused) in
/// one transaction. The pseudo user names its creator by address only (`owner_address`): webhooks belong to
/// their room, so nothing cascades from the creator's account.
pub async fn create(db: &Pool, w: NewWebhook<'_>) -> Result<WebhookRow, ApiError> {
    let ts = now();
    let user_id = crate::util::ulid();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, owner_address, is_node_admin, dm_policy, created_at)
         VALUES ($1, $2, $3, $4, 'webhook', $5, 0, 'friends', $6)",
    )
    .bind(&user_id)
    .bind(pseudo_username(w.id))
    .bind(w.domain)
    .bind(w.name)
    .bind(w.creator_address)
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO webhooks (id, room_id, channel_id, user_id, name, token_hash, allow_mentions_everyone, suspended, created_by, created_at, sealing)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10)",
    )
    .bind(w.id)
    .bind(w.room_id)
    .bind(w.channel_id)
    .bind(&user_id)
    .bind(w.name)
    .bind(w.token_hash)
    .bind(w.allow_mentions_everyone as i64)
    .bind(w.creator_id)
    .bind(&ts)
    .bind(w.sealing)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    by_id(db, w.id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("webhook missing after insert")))
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<WebhookRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} {FROM} WHERE w.id = $1")).bind(id).fetch_optional(db).await?)
}

pub async fn of_channel(db: &Pool, channel_id: &str) -> Result<Vec<WebhookRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} {FROM} WHERE w.channel_id = $1 ORDER BY w.id"))
        .bind(channel_id)
        .fetch_all(db)
        .await?)
}

pub async fn of_room(db: &Pool, room_id: &str) -> Result<Vec<WebhookRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} {FROM} WHERE w.room_id = $1 ORDER BY w.id"))
        .bind(room_id)
        .fetch_all(db)
        .await?)
}

/// Webhooks of a channel and of its room.
pub async fn counts(db: &Pool, room_id: &str, channel_id: &str) -> Result<(i64, i64), ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS room_n,
                CAST(COALESCE(SUM(CASE WHEN channel_id = $2 THEN 1 ELSE 0 END), 0) AS BIGINT) AS channel_n
           FROM webhooks WHERE room_id = $1",
    )
    .bind(room_id)
    .bind(channel_id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("channel_n")?, row.try_get("room_n")?))
}

pub struct WebhookUpdate<'a> {
    pub name: Option<&'a str>,
    pub channel_id: Option<&'a str>,
    pub allow_mentions_everyone: Option<bool>,
    /// `Some(value)` sets the sealing mode (`Some(None)`: unencrypted target channel).
    pub sealing: Option<Option<&'a str>>,
}

/// Updates the webhook; a new name also becomes the pseudo user's display name.
pub async fn update(db: &Pool, w: &WebhookRow, u: WebhookUpdate<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE webhooks SET name = COALESCE($1, name), channel_id = COALESCE($2, channel_id),
                allow_mentions_everyone = COALESCE($3, allow_mentions_everyone),
                sealing = CASE WHEN $4 = 1 THEN $5 ELSE sealing END
          WHERE id = $6",
    )
    .bind(u.name)
    .bind(u.channel_id)
    .bind(u.allow_mentions_everyone.map(i64::from))
    .bind(i64::from(u.sealing.is_some()))
    .bind(u.sealing.flatten())
    .bind(&w.id)
    .execute(&mut *tx)
    .await?;
    if let Some(name) = u.name {
        sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
            .bind(name)
            .bind(&w.user_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn set_token_hash(db: &Pool, id: &str, hash: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE webhooks SET token_hash = $1 WHERE id = $2").bind(hash).bind(id).execute(db).await?;
    Ok(())
}

/// Records an execution (at most once a minute).
pub async fn touch(db: &Pool, id: &str) -> Result<(), ApiError> {
    let ts = now();
    let minute_ago = crate::util::format_time(chrono::Utc::now() - chrono::Duration::seconds(60));
    sqlx::query("UPDATE webhooks SET last_used_at = $1 WHERE id = $2 AND (last_used_at IS NULL OR last_used_at < $3)")
        .bind(ts)
        .bind(id)
        .bind(minute_ago)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes the webhook; its pseudo user stays as a disabled tombstone (its messages keep an author).
pub async fn delete(db: &Pool, w: &WebhookRow) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM webhooks WHERE id = $1").bind(&w.id).execute(&mut *tx).await?;
    sqlx::query("UPDATE users SET disabled_at = $1 WHERE id = $2 AND kind = 'webhook'")
        .bind(now())
        .bind(&w.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Sets the sealing mode of every webhook of a channel (its encryption was switched): `sender` for those that had
/// none, NULL when the channel became unencrypted. Returns the webhooks whose mode changed.
pub async fn set_sealing_in_channel(db: &Pool, channel_id: &str, encrypted: bool) -> Result<Vec<WebhookRow>, ApiError> {
    let changed: Vec<WebhookRow> =
        of_channel(db, channel_id).await?.into_iter().filter(|w| w.sealing.is_some() != encrypted).collect();
    let sql = if encrypted {
        "UPDATE webhooks SET sealing = 'sender', suspended = 0 WHERE channel_id = $1 AND sealing IS NULL"
    } else {
        "UPDATE webhooks SET sealing = NULL, suspended = 0 WHERE channel_id = $1"
    };
    sqlx::query(sql).bind(channel_id).execute(db).await?;
    Ok(changed)
}

/// The newest published inbox key of a conversation (ENCRYPTION.md §5b).
#[derive(Debug, Clone, FromRow)]
pub struct InboxKeyRow {
    pub epoch: i64,
    pub public_key: String,
}

pub async fn inbox_key(db: &Pool, conversation_id: &str) -> Result<Option<InboxKeyRow>, ApiError> {
    Ok(sqlx::query_as("SELECT epoch, public_key FROM inbox_keys WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_optional(db)
        .await?)
}

pub struct NewInboxKey<'a> {
    pub conversation_id: &'a str,
    pub epoch: i64,
    pub public_key: &'a str,
    pub signature: &'a str,
    pub user_id: &'a str,
    pub device_id: &'a str,
}

/// Stores the key if the conversation has none or only one of an older epoch (atomic: concurrent publishers of
/// the same or older epochs never replace a newer key). Returns whether it was stored.
pub async fn put_inbox_key(db: &Pool, k: NewInboxKey<'_>) -> Result<bool, ApiError> {
    let done = sqlx::query(
        "INSERT INTO inbox_keys (conversation_id, epoch, public_key, signature, user_id, device_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (conversation_id) DO UPDATE SET epoch = excluded.epoch, public_key = excluded.public_key,
                signature = excluded.signature, user_id = excluded.user_id, device_id = excluded.device_id,
                created_at = excluded.created_at
          WHERE inbox_keys.epoch < excluded.epoch",
    )
    .bind(k.conversation_id)
    .bind(k.epoch)
    .bind(k.public_key)
    .bind(k.signature)
    .bind(k.user_id)
    .bind(k.device_id)
    .bind(now())
    .execute(db)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Forgets the inbox key of a conversation (its encryption was switched; the next member publishes anew).
pub async fn delete_inbox_key(db: &Pool, conversation_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM inbox_keys WHERE conversation_id = $1").bind(conversation_id).execute(db).await?;
    Ok(())
}
