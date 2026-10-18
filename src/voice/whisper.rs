// SPDX-License-Identifier: AGPL-3.0-only
//! Server-authenticated whisper authorizations. Only opaque media reaches the SFU; the shared,
//! sealed cache holds bounded routing authorizations and device connection generations, never keys.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::state::ChannelKey;
use crate::{access, app::AppState, cache, error::ApiError, permissions as p, store, util};

pub const SESSION_SECS: u64 = 30;
pub const REPLY_SECS: u64 = 120;

#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct WhisperSession {
    pub id: String,
    pub sender: String,
    /// Only the sender sees the complete recipient list.
    pub recipients: Vec<String>,
    pub expires_at: String,
}

// Separate persisted form: public serialization must never disclose connection generations.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    public: WhisperSession,
    key: ChannelKey,
    generations: Vec<String>,
    reply: bool,
    reply_deadline_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Receipt {
    id: String,
    sender: String,
    sender_generation: String,
    recipient_generation: String,
    published_ms: u64,
    deadline_ms: u64,
}

#[derive(Serialize, ToSchema)]
pub struct WhisperReceipt {
    pub id: String,
    pub sender: String,
    /// Active playback authorization expiry (30 seconds from start), never the reply deadline.
    pub expires_at: String,
    pub reply_expires_at: String,
}

#[derive(Serialize, Deserialize)]
struct Connection {
    sid: String,
    joined_ms: i64,
    generation: String,
    live: bool,
}
#[derive(Serialize, Deserialize)]
struct Published {
    sid: String,
    at_ms: u64,
}

pub fn forbidden() -> ApiError {
    ApiError::Forbidden { code: "voice.whisper_forbidden", detail: "This whisper authorization is not valid".into() }
}

fn connection_key(key: &ChannelKey, identity: &str) -> String {
    format!("whisper:connection:{}:{}:{identity}", key.0, key.1)
}
fn latest_key(key: &ChannelKey, identity: &str) -> String {
    format!("whisper:latest:{}:{}:{identity}", key.0, key.1)
}
fn receipt_key(key: &ChannelKey, identity: &str) -> String {
    format!("whisper:receipt:{}:{}:{identity}", key.0, key.1)
}
async fn get<T: serde::de::DeserializeOwned>(state: &AppState, key: &str) -> Result<T, ApiError> {
    state.cluster.get_sealed(key).await.map_err(cache::unavailable)?.ok_or_else(forbidden)
}
async fn put<T: Serialize>(state: &AppState, key: &str, value: &T, secs: u64) -> Result<(), ApiError> {
    state.cluster.put_sealed(key, value, Duration::from_secs(secs)).await.map_err(cache::unavailable)
}
async fn delete(state: &AppState, key: &str) -> Result<(), ApiError> {
    state.cluster.cache().delete(&state.cluster.key(key)).await.map_err(cache::unavailable)
}

/// Called from verified LiveKit webhooks. Every departure/rejoin invalidates old capabilities,
/// including reconnects within the ordinary voice grace period.
pub async fn webhook(state: &AppState, key: &ChannelKey, event: &livekit_protocol::WebhookEvent) {
    let Some(participant) = &event.participant else { return };
    let identity = &participant.identity;
    let result = match event.event.as_str() {
        "participant_joined" => {
            if participant.sid.is_empty() {
                return;
            }
            let previous = get::<Connection>(state, &connection_key(key, identity)).await.ok();
            if previous.as_ref().is_some_and(|p| p.sid == participant.sid || p.joined_ms > participant.joined_at_ms) {
                return;
            }
            if previous.as_ref().is_some_and(|p| p.joined_ms == participant.joined_at_ms) {
                invalidate(state, key, identity).await;
                return;
            }
            let connection = Connection {
                sid: participant.sid.clone(),
                joined_ms: participant.joined_at_ms,
                generation: util::ulid(),
                live: true,
            };
            put(state, &connection_key(key, identity), &connection, 86400).await
        }
        "participant_left" | "participant_connection_aborted" => {
            let previous = get::<Connection>(state, &connection_key(key, identity)).await.ok();
            // A delayed departure from an older SFU connection must not revoke a newer join.
            if !participant.sid.is_empty() && previous.as_ref().is_some_and(|p| p.sid != participant.sid) {
                return;
            }
            invalidate(state, key, identity).await;
            Ok(())
        }
        "track_published" | "track_unpublished" => {
            let Some(track) = &event.track else { return };
            let Some(id) = track.name.strip_prefix("whisper:").filter(|id| util::is_ulid(id)) else { return };
            let marker = format!("whisper:published:{id}");
            if event.event == "track_published" {
                match authorized(state, key, identity, id).await {
                    Ok(_) => {
                        let first_key = format!("whisper:first-published:{id}");
                        let published = match get::<Published>(state, &first_key).await {
                            Ok(first) => Published { sid: track.sid.clone(), at_ms: first.at_ms },
                            Err(_) => {
                                let first = Published { sid: track.sid.clone(), at_ms: cache::now_ms() };
                                if put(state, &first_key, &first, REPLY_SECS).await.is_err() {
                                    return;
                                }
                                first
                            }
                        };
                        put(state, &marker, &published, SESSION_SECS).await
                    }
                    Err(_) => {
                        super::remove_from_livekit(state, key, identity).await;
                        return;
                    }
                }
            } else {
                delete(state, &marker).await
            }
        }
        _ => return,
    };
    if let Err(error) = result {
        tracing::warn!(%error, "Whisper connection state update failed");
    }
}

pub async fn invalidate_checked(state: &AppState, key: &ChannelKey, identity: &str) -> Result<(), ApiError> {
    let name = connection_key(key, identity);
    if let Some(mut connection) = state.cluster.get_sealed::<Connection>(&name).await.map_err(cache::unavailable)? {
        connection.live = false;
        put(state, &name, &connection, 86400).await?;
    }
    Ok(())
}

pub async fn invalidate(state: &AppState, key: &ChannelKey, identity: &str) {
    if let Err(error) = invalidate_checked(state, key, identity).await {
        tracing::warn!(%error, "Whisper connection invalidation failed");
    }
}

async fn generation(state: &AppState, key: &ChannelKey, identity: &str) -> Result<String, ApiError> {
    let connection: Connection = get(state, &connection_key(key, identity)).await?;
    if !connection.live {
        return Err(forbidden());
    }
    Ok(connection.generation)
}

/// Recheck DB permissions on every authorization, including active SFU publications and receipts.
pub async fn can_send(state: &AppState, key: &ChannelKey, identity: &str, initiation: bool) -> Result<(), ApiError> {
    access_check(state, key, identity, true, initiation).await
}

async fn access_check(
    state: &AppState,
    key: &ChannelKey,
    identity: &str,
    sending: bool,
    initiation: bool,
) -> Result<(), ApiError> {
    let (address, _) =
        super::parse_identity(identity).filter(|_| !identity.ends_with("#screen")).ok_or_else(forbidden)?;
    let (username, domain) = util::parse_address(address).ok_or_else(forbidden)?;
    let user = store::users::by_username(&state.db, username, domain)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .ok_or_else(forbidden)?;
    let room = access::room_access(state, &key.0, &user).await?;
    if room.member.is_none() {
        return Err(forbidden());
    }
    let channel = access::channel_in_room(state, &key.0, &key.1).await?;
    let permissions = access::channel_perms(state, &room, &channel, &user.id).await?;
    access::require_age(&room, &channel)?;
    let needed =
        p::VIEW_CHANNEL | p::CONNECT | if sending { p::SPEAK } else { 0 } | if initiation { p::WHISPER } else { 0 };
    if channel.kind != "voice"
        || !p::has(permissions, needed)
        || (sending && store::voice::server_muted(&state.db, &key.0, &user.id).await?)
        || store::rooms::is_banned(&state.db, Some(&key.0), address, domain).await?
    {
        return Err(forbidden());
    }
    Ok(())
}

pub async fn start(
    state: &AppState,
    key: ChannelKey,
    sender: String,
    recipients: Vec<String>,
    reply_to: Option<String>,
) -> Result<WhisperSession, ApiError> {
    let _serial = state.voice.whisper_serial.lock().await;
    let sender_generation = generation(state, &key, &sender).await?;
    let reply = reply_to.is_some();
    can_send(state, &key, &sender, !reply).await?;
    let recipients = if let Some(id) = reply_to {
        if !recipients.is_empty() {
            return Err(forbidden());
        }
        let receipt: Receipt = get(state, &receipt_key(&key, &sender)).await?;
        if receipt.id != id
            || receipt.deadline_ms <= cache::now_ms()
            || receipt.recipient_generation != sender_generation
            || generation(state, &key, &receipt.sender).await? != receipt.sender_generation
        {
            return Err(forbidden());
        }
        vec![receipt.sender]
    } else {
        recipients
    };
    if recipients.is_empty() || recipients.len() > 32 {
        return Err(forbidden());
    }
    let mut generations = vec![sender_generation];
    let mut unique = std::collections::HashSet::new();
    for recipient in &recipients {
        if recipient == &sender || recipient.ends_with("#screen") || !unique.insert(recipient) {
            return Err(forbidden());
        }
        access_check(state, &key, recipient, false, false).await?;
        generations.push(generation(state, &key, recipient).await?);
    }
    let public = WhisperSession {
        id: util::ulid(),
        sender: sender.clone(),
        recipients,
        expires_at: util::in_seconds(SESSION_SECS as i64),
    };
    let stored = Stored {
        public: public.clone(),
        key: key.clone(),
        generations,
        reply,
        reply_deadline_ms: cache::now_ms() + REPLY_SECS * 1000,
    };
    put(state, &format!("whisper:session:{}", public.id), &stored, SESSION_SECS).await?;
    put(state, &latest_key(&key, &sender), &public.id, SESSION_SECS).await?;
    Ok(public)
}

pub async fn authorized(
    state: &AppState,
    key: &ChannelKey,
    sender: &str,
    id: &str,
) -> Result<WhisperSession, ApiError> {
    if !util::is_ulid(id) {
        return Err(forbidden());
    }
    let stored: Stored = get(state, &format!("whisper:session:{id}")).await?;
    let latest: String = get(state, &latest_key(key, sender)).await?;
    if stored.key != *key || stored.public.sender != sender || latest != id {
        return Err(forbidden());
    }
    can_send(state, key, sender, !stored.reply).await?;
    for (identity, expected) in
        std::iter::once(sender).chain(stored.public.recipients.iter().map(String::as_str)).zip(&stored.generations)
    {
        if generation(state, key, identity).await? != *expected {
            return Err(forbidden());
        }
    }
    for recipient in &stored.public.recipients {
        access_check(state, key, recipient, false, false).await?;
    }
    Ok(stored.public)
}

pub async fn receive(
    state: &AppState,
    key: &ChannelKey,
    recipient: &str,
    id: &str,
) -> Result<WhisperReceipt, ApiError> {
    let _serial = state.voice.whisper_serial.lock().await;
    let stored: Stored = get(state, &format!("whisper:session:{id}")).await?;
    let session = authorized(state, key, &stored.public.sender, id).await?;
    if !session.recipients.iter().any(|i| i == recipient) {
        return Err(forbidden());
    }
    let publication: Published = get(state, &format!("whisper:published:{id}")).await?;
    let remaining = stored.reply_deadline_ms.saturating_sub(cache::now_ms());
    if remaining == 0 {
        return Err(forbidden());
    }
    let receipt = Receipt {
        id: id.to_string(),
        sender: session.sender.clone(),
        sender_generation: generation(state, key, &session.sender).await?,
        recipient_generation: generation(state, key, recipient).await?,
        published_ms: publication.at_ms,
        deadline_ms: stored.reply_deadline_ms,
    };
    // A replay of an older active whisper cannot replace the last actual sender: publication order
    // is authoritative (timestamps are recorded from verified SFU publication webhooks).
    if let Ok(previous) = get::<Receipt>(state, &receipt_key(key, recipient)).await
        && previous.published_ms > receipt.published_ms
    {
        return Err(forbidden());
    }
    put(state, &receipt_key(key, recipient), &receipt, remaining.div_ceil(1000)).await?;
    Ok(WhisperReceipt {
        id: id.into(),
        sender: session.sender,
        expires_at: session.expires_at,
        reply_expires_at: util::in_seconds((remaining / 1000) as i64),
    })
}

pub async fn end(state: &AppState, key: &ChannelKey, sender: &str, id: &str) -> Result<(), ApiError> {
    let stored: Stored = get(state, &format!("whisper:session:{id}")).await?;
    if stored.key != *key || stored.public.sender != sender {
        return Err(forbidden());
    }
    delete(state, &format!("whisper:session:{id}")).await
}

/// Ignore delayed webhook lifecycle events from old SFU connections before changing voice state.
pub async fn stale_connection_event(
    state: &AppState,
    key: &ChannelKey,
    event: &livekit_protocol::WebhookEvent,
) -> bool {
    let Some(participant) = &event.participant else { return false };
    let Ok(previous) = get::<Connection>(state, &connection_key(key, &participant.identity)).await else {
        return false;
    };
    match event.event.as_str() {
        "participant_left" | "participant_connection_aborted" => {
            !participant.sid.is_empty() && previous.sid != participant.sid
        }
        "participant_joined" => {
            if previous.sid == participant.sid {
                return !previous.live;
            }
            if previous.joined_ms == participant.joined_at_ms {
                invalidate(state, key, &participant.identity).await;
                return true;
            }
            previous.joined_ms > participant.joined_at_ms
        }
        _ => false,
    }
}
