// SPDX-License-Identifier: AGPL-3.0-only
//! Cached copies of other nodes' emojis and soundboard clips.
//!
//! Readers never load bytes from foreign nodes (their address would leak to every node an emoji comes from).
//! The node a client talks to for a conversation serves `GET /emojis/{id}/image?host=<origin>` and
//! `GET /sounds/{id}/audio?host=<origin>`: on the first request it fetches the bytes from the origin over the
//! federation client (public addresses only, redirects to the same origin, 5 s, the emoji or clip size cap,
//! checked content type and format), stores them as a blob and keeps the copy while it is used. Deletion at the
//! origin does not reach the copies (messages stay readable); housekeeping evicts copies unused for
//! `TAVRN_MEDIA_CACHE_UNUSED_DAYS` and node admins purge single copies.
//!
//! The routes need no session, so the cache is bounded: fetches (cache misses) are limited per client address
//! (IPv6 by prefix), the copies of one origin host by `TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST` and all copies by
//! `TAVRN_MEDIA_CACHE_MAX_BYTES`; beyond a cap the least recently used copies go.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::{
    app::AppState,
    error::ApiError,
    federation::{self, client::Kind},
    media, util,
};

/// Budget of one fetch from the origin.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// `used_at` is refreshed at most this often per copy.
const TOUCH_INTERVAL_HOURS: i64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    Emoji,
    EmojiStill,
    Sound,
}

impl CacheKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Emoji => "emoji",
            Self::EmojiStill => "emoji_still",
            Self::Sound => "sound",
        }
    }

    fn path(self, id: &str) -> String {
        match self {
            Self::Emoji => format!("/api/v1/emojis/{id}/image"),
            Self::EmojiStill => format!("/api/v1/emojis/{id}/image?still=1"),
            Self::Sound => format!("/api/v1/sounds/{id}/audio"),
        }
    }

    fn fetch_kind(self) -> Kind {
        if self == Self::Sound { Kind::Sound } else { Kind::Emoji }
    }
}

/// A cached copy: storage id, type and bytes.
pub struct Cached {
    pub id: String,
    pub mime: String,
    pub data: Vec<u8>,
}

fn unavailable(host: &str) -> ApiError {
    ApiError::BadGateway { code: "media.remote_unavailable", detail: format!("{host} does not deliver this file") }
}

fn not_found() -> ApiError {
    ApiError::NotFound { code: "media.remote_not_found", what: "File".into() }
}

/// Cache misses (fetches from other nodes) per client address and minute; development nodes allow more.
pub fn miss_limit(dev: bool) -> u32 {
    if dev { 10_000 } else { 60 }
}

/// The total cap is enforced at most this often per instance (and by housekeeping); the per-host cap at every fetch.
const TOTAL_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// The copy of `origin_id` from `host`, fetched on the first request; a fetch counts against `ip`'s miss budget.
pub async fn get(state: &AppState, kind: CacheKind, host: &str, origin_id: &str, ip: &str) -> Result<Cached, ApiError> {
    if !crate::emoji::valid_host(host) || !federation::valid_node_domain(host.split(':').next().unwrap_or(host)) {
        return Err(crate::validate::bad("media.host_invalid", "host must be a node domain"));
    }
    let row = sqlx::query(
        "SELECT id, mime, used_at FROM remote_emoji_cache WHERE kind = $1 AND origin_host = $2 AND origin_id = $3",
    )
    .bind(kind.as_str())
    .bind(host)
    .bind(origin_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = row {
        let (id, mime, used_at): (String, String, String) =
            (row.try_get("id")?, row.try_get("mime")?, row.try_get("used_at")?);
        if let Some(data) = state.storage.read(&id).await.map_err(ApiError::Internal)? {
            touch(state, &id, &used_at).await?;
            return Ok(Cached { id, mime, data });
        }
        // The file went missing: fetch again.
        sqlx::query("DELETE FROM remote_emoji_cache WHERE id = $1").bind(&id).execute(&state.db).await?;
    }
    federation::check_policy(state, host).await?;
    state.media_miss_limiter.check_all(&[format!("miss:{ip}")])?;
    let fetched =
        tokio::time::timeout(FETCH_TIMEOUT, state.federation.get(host, &kind.path(origin_id), kind.fetch_kind()))
            .await
            .map_err(|_| unavailable(host))?
            .map_err(|e| match e.status() {
                Some(404) | Some(410) => not_found(),
                _ => {
                    tracing::debug!(host, result = e.label(), "remote emoji or clip fetch failed");
                    unavailable(host)
                }
            })?;
    let mime = match kind {
        CacheKind::Sound => fetched.content_type.clone(),
        // Images are checked by content too (never SVG or HTML under an image type).
        _ => match media::sniff(&fetched.body) {
            Some(media::Format::WebP | media::Format::WebPAnimated) => "image/webp".into(),
            Some(media::Format::Png | media::Format::Apng) => "image/png".into(),
            Some(media::Format::Gif | media::Format::GifStill) => "image/gif".into(),
            Some(media::Format::Jpeg) => "image/jpeg".into(),
            _ => return Err(unavailable(host)),
        },
    };
    if fetched.body.is_empty() {
        return Err(unavailable(host));
    }
    let id = util::ulid();
    state.storage.write(&id, &fetched.body).await?;
    let now = util::now();
    let inserted = sqlx::query(
        "INSERT INTO remote_emoji_cache (id, kind, origin_host, origin_id, mime, size, fetched_at, used_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
    )
    .bind(&id)
    .bind(kind.as_str())
    .bind(host)
    .bind(origin_id)
    .bind(&mime)
    .bind(fetched.body.len() as i64)
    .bind(&now)
    .execute(&state.db)
    .await;
    if let Err(e) = inserted {
        // Another request stored it first: keep that copy.
        state.storage.delete(&id).await;
        if crate::store::is_unique_violation(&e) {
            return Box::pin(get(state, kind, host, origin_id, ip)).await;
        }
        return Err(e.into());
    }
    enforce_host_cap(state, host, &id).await?;
    if state
        .media_cache_checked
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none_or(|t| t.elapsed() >= TOTAL_CHECK_INTERVAL)
    {
        *state.media_cache_checked.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        enforce_total_cap(state).await?;
    }
    Ok(Cached { id, mime, data: fetched.body })
}

/// Deletes the least recently used copies of `host` (never `keep`, the copy just stored) until the host is within
/// `TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST`; returns how many.
pub async fn enforce_host_cap(state: &AppState, host: &str, keep: &str) -> Result<u64, ApiError> {
    let cap = i64::try_from(state.config.media_cache_max_bytes_per_host).unwrap_or(i64::MAX);
    let used: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM remote_emoji_cache WHERE origin_host = $1")
        .bind(host)
        .fetch_one(&state.db)
        .await?;
    evict_oldest(
        state,
        used - cap,
        "SELECT id, size FROM remote_emoji_cache WHERE origin_host = $1 AND id <> $2 ORDER BY used_at, id LIMIT 100",
        &[host, keep],
    )
    .await
}

/// Deletes the least recently used copies of all hosts until the cache is within `TAVRN_MEDIA_CACHE_MAX_BYTES`;
/// returns how many.
pub async fn enforce_total_cap(state: &AppState) -> Result<u64, ApiError> {
    let cap = i64::try_from(state.config.media_cache_max_bytes).unwrap_or(i64::MAX);
    let used: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM remote_emoji_cache").fetch_one(&state.db).await?;
    evict_oldest(state, used - cap, "SELECT id, size FROM remote_emoji_cache ORDER BY used_at, id LIMIT 100", &[]).await
}

/// Deletes copies in the order of `query` (oldest use first, pages of at most 100) until `excess` bytes are freed.
async fn evict_oldest(state: &AppState, mut excess: i64, query: &str, binds: &[&str]) -> Result<u64, ApiError> {
    let mut deleted = 0;
    while excess > 0 {
        let mut q = sqlx::query_as::<_, (String, i64)>(query);
        for b in binds {
            q = q.bind(*b);
        }
        let page = q.fetch_all(&state.db).await?;
        if page.is_empty() {
            break;
        }
        for (id, size) in page {
            if excess <= 0 {
                break;
            }
            sqlx::query("DELETE FROM remote_emoji_cache WHERE id = $1").bind(&id).execute(&state.db).await?;
            state.storage.delete(&id).await;
            excess -= size.max(1);
            deleted += 1;
        }
    }
    Ok(deleted)
}

async fn touch(state: &AppState, id: &str, used_at: &str) -> Result<(), ApiError> {
    let stale =
        util::parse_time(used_at).is_none_or(|t| Utc::now() - t > chrono::Duration::hours(TOUCH_INTERVAL_HOURS));
    if stale {
        sqlx::query("UPDATE remote_emoji_cache SET used_at = $1 WHERE id = $2")
            .bind(util::now())
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

/// Deletes copies unused for `TAVRN_MEDIA_CACHE_UNUSED_DAYS` (0 = never); returns how many.
pub async fn evict_unused(state: &AppState, now: DateTime<Utc>) -> Result<u64, ApiError> {
    let days = i64::from(state.config.media_cache_unused_days);
    if days == 0 {
        return Ok(0);
    }
    let cutoff = util::format_time(now - chrono::Duration::days(days));
    let ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM remote_emoji_cache WHERE used_at < $1 LIMIT 500")
        .bind(&cutoff)
        .fetch_all(&state.db)
        .await?;
    for (id,) in &ids {
        sqlx::query("DELETE FROM remote_emoji_cache WHERE id = $1").bind(id).execute(&state.db).await?;
        state.storage.delete(id).await;
    }
    Ok(ids.len() as u64)
}

/// Deletes every cached copy of `origin_id` from `host` (admin purge); returns how many.
pub async fn purge(state: &AppState, host: &str, origin_id: &str) -> Result<u64, ApiError> {
    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM remote_emoji_cache WHERE origin_host = $1 AND origin_id = $2")
            .bind(host)
            .bind(origin_id)
            .fetch_all(&state.db)
            .await?;
    for (id,) in &ids {
        sqlx::query("DELETE FROM remote_emoji_cache WHERE id = $1").bind(id).execute(&state.db).await?;
        state.storage.delete(id).await;
    }
    Ok(ids.len() as u64)
}
