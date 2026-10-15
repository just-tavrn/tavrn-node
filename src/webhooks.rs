// SPDX-License-Identifier: AGPL-3.0-only
//! Incoming webhooks (protocol/APPLICATIONS.md §6.1, §6.1a): write-only URLs that post messages into one channel,
//! in plaintext into unencrypted channels and as sealed boxes into encrypted ones.
//!
//! - The URL is `<node>/api/v1/webhooks/<id>/<secret>`; the secret (32 random bytes, base64url) is shown once and
//!   stored as SHA-256, compared in constant time. An unknown id and a wrong secret both answer
//!   `404 webhook.not_found` after the same work (lookup, hash, comparison), so neither the answer nor its
//!   timing tells whether an id exists.
//! - Every webhook has a pseudo user (`kind = "webhook"`, username `wh.<lowercase id>`) as the author of its
//!   messages: no password, token, device, keys or memberships, so it never appears in member lists, rosters
//!   or presence, and DMs, friend requests and invites never reach it.
//! - Messages carry the node-set envelope field `webhook: { id, name }` with `device_id` and `signature` null.
//! - In encrypted channels a webhook is sealed by the sender or by the node ([`Sealing`], `ENCRYPTION.md` §5b):
//!   messages are stored only as sealed boxes to the channel's newest published inbox key; plaintext bodies of
//!   node-sealed posts are never logged, traced, audited or echoed in error messages. Switching the channel's
//!   encryption keeps the webhooks (sealed by the sender, waiting for a key / plaintext again); deleting the
//!   channel deletes its webhooks.
//! - Request logs show `/api/v1/webhooks/<id>/***` ([`redact_path`], [`RedactedSpan`]).

use std::borrow::Cow;

use axum::http::Request;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use utoipa::ToSchema;

use crate::{
    access::{Conv, ConvKind, RoomAccess},
    app::AppState,
    error::ApiError,
    models::{ChannelRow, Message, User, UserRow, media_url},
    store::{
        self,
        messages::{NewMessage, WebhookAuthor},
        webhooks::WebhookRow,
    },
    util,
    validate::bad,
};

/// Webhooks per room (the per-channel limit is `TAVRN_WEBHOOKS_PER_CHANNEL`).
pub const MAX_PER_ROOM: usize = 50;
/// Largest execution payload.
pub const MAX_PAYLOAD_BYTES: usize = 32 * 1024;
pub const SECRET_BYTES: usize = 32;
pub const MAX_NAME: usize = 32;
/// Channel kinds webhooks can post in (forum channels only into posts, with `thread_id`).
pub const CHANNEL_KINDS: &[&str] = &["text", "announcement", "forum"];

pub fn not_found() -> ApiError {
    ApiError::NotFound { code: "webhook.not_found", what: "Webhook".into() }
}

pub fn disabled() -> ApiError {
    ApiError::Forbidden { code: "webhook.disabled", detail: "Webhooks are switched off on this node".into() }
}

/// How a webhook in an encrypted channel seals its messages (APPLICATIONS.md §6.1a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealing {
    /// The service seals to the inbox key itself; the node accepts only sealed bodies.
    Sender,
    /// The service posts plaintext over HTTPS; the node seals it in memory and stores only the sealed box.
    Node,
}

impl Sealing {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "sender" => Ok(Self::Sender),
            "node" => Ok(Self::Node),
            _ => Err(bad("webhook.sealing_invalid", "sealing: sender or node")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Node => "node",
        }
    }

    /// The mode of a stored webhook in an encrypted channel (`sender` unless set to `node`).
    pub fn of(row: &WebhookRow) -> Self {
        if row.sealing.as_deref() == Some("node") { Self::Node } else { Self::Sender }
    }
}

fn pending_key() -> ApiError {
    ApiError::conflict("webhook.pending_key", "No member of the encrypted channel has published an inbox key yet")
}

fn payload_invalid(detail: impl Into<String>) -> ApiError {
    bad("webhook.payload_invalid", detail)
}

/// `403 webhook.disabled` while `TAVRN_WEBHOOKS_ENABLED=false`.
pub fn require_enabled(state: &AppState) -> Result<(), ApiError> {
    if state.config.webhooks_enabled { Ok(()) } else { Err(disabled()) }
}

/// A fresh secret and its stored hash.
pub fn new_secret() -> (String, String) {
    let secret = util::random_token(SECRET_BYTES);
    let hash = util::sha256_b64(&secret);
    (secret, hash)
}

/// The execution URL shown once to the creator.
pub fn url(state: &AppState, id: &str, secret: &str) -> String {
    format!("{}/api/v1/webhooks/{id}/{secret}", state.config.public_url())
}

/// A webhook as shown to holders of `manage_webhooks` (never its secret).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Webhook {
    pub id: String,
    pub room_id: String,
    pub channel_id: String,
    pub name: String,
    /// Path of the avatar on this node (animated variant if any), null without one.
    pub avatar: Option<String>,
    pub avatar_still: Option<String>,
    /// The pseudo user that authors the webhook's messages (`kind = "webhook"`).
    pub user: User,
    /// Address of the creator (null if unknown).
    pub created_by: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// Always false since webhooks post into encrypted channels as well (kept for compatibility).
    pub suspended: bool,
    /// Executions may set `mentions_everyone` (only a creator holding `mention_everyone` can allow it).
    pub allow_mentions_everyone: bool,
    /// Encrypted channels: `sender` (the service seals) or `node` (the node seals what it receives); null in
    /// unencrypted channels (APPLICATIONS.md §6.1a).
    pub sealing: Option<String>,
    /// Sealed, but no member has published the channel's inbox key yet: executions answer
    /// `409 webhook.pending_key`.
    pub pending_key: bool,
}

pub fn to_api(row: &WebhookRow, user: &UserRow) -> Webhook {
    let public = user.to_public();
    Webhook {
        id: row.id.clone(),
        room_id: row.room_id.clone(),
        channel_id: row.channel_id.clone(),
        name: row.name.clone(),
        avatar: media_url(user.avatar_blob_id.as_deref(), user.avatar_animated != 0),
        avatar_still: media_url(user.avatar_blob_id.as_deref(), false),
        user: public,
        created_by: row.creator.clone(),
        created_at: row.created_at.clone(),
        last_used_at: row.last_used_at.clone(),
        suspended: false,
        allow_mentions_everyone: row.allow_mentions_everyone != 0,
        sealing: row.sealing.clone(),
        pending_key: row.pending_key != 0,
    }
}

/// The webhook with its pseudo user, as an API object.
pub async fn view(state: &AppState, row: &WebhookRow) -> Result<Webhook, ApiError> {
    let user = store::users::by_id(&state.db, &row.user_id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("webhook without pseudo user")))?;
    Ok(to_api(row, &user))
}

/// Webhook name (1–32 characters, one line).
pub fn validate_name(name: &str) -> Result<String, ApiError> {
    crate::validate::name("name", name, MAX_NAME)
}

/// The per-message `username`: 1–32 characters, no `@`, `#` or `:`, no control characters, not `everyone` or
/// `here` (`400 webhook.username_invalid`).
pub fn validate_username(name: &str) -> Result<String, ApiError> {
    let trimmed = name.trim();
    let n = trimmed.chars().count();
    let lower = trimmed.to_lowercase();
    let reserved = matches!(lower.as_str(), "everyone" | "here" | "@everyone" | "@here");
    if n == 0
        || n > MAX_NAME
        || reserved
        || trimmed.chars().any(|c| matches!(c, '@' | '#' | ':') || c.is_control())
        || trimmed
            .chars()
            .any(|c| matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}'..='\u{200f}'))
    {
        return Err(bad(
            "webhook.username_invalid",
            "username: 1 to 32 characters without @, # or :, not everyone or here",
        ));
    }
    Ok(trimmed.to_string())
}

/// Compares the hash of `secret` with `hash` in constant time.
fn secret_matches(secret: &str, hash: &str) -> bool {
    let given = util::sha256_b64(secret);
    bool::from(given.as_bytes().ct_eq(hash.as_bytes()))
}

/// Looks up the webhook of an execution URL. Unknown ids and wrong secrets do the same work and both answer
/// `404 webhook.not_found`.
pub async fn authenticate(state: &AppState, id: &str, secret: &str) -> Result<WebhookRow, ApiError> {
    // A hash no secret produces (not base64url), compared when there is no webhook, so both paths hash and compare.
    const NO_WEBHOOK: &str = "--------------------------------------------";
    let row = if util::is_ulid(id) { store::webhooks::by_id(&state.db, id).await? } else { None };
    let hash = row.as_ref().map_or(NO_WEBHOOK, |r| r.token_hash.as_str());
    let ok = secret.len() <= 128 && secret_matches(secret, hash);
    match row {
        Some(r) if ok => Ok(r),
        _ => Err(not_found()),
    }
}

/// The execution payload (§6.1). Unknown fields (for example `attachments`) are refused.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebhookPayload {
    /// A plaintext `text` content object (PROTOCOL.md §7), optionally with `embeds` (§6.4).
    #[schema(value_type = Object)]
    pub content: Value,
    /// Name shown for this message instead of the webhook's name.
    pub username: Option<String>,
    /// Addresses to mention; addresses that are not members of the room are dropped.
    #[serde(default)]
    pub mentions: Vec<String>,
    /// Needs `allow_mentions_everyone` on the webhook.
    #[serde(default)]
    pub mentions_everyone: bool,
    /// A message of the same channel this one replies to.
    pub reply_to: Option<String>,
    /// A thread of the channel to post into; required in forum channels (a post), which show no loose messages.
    pub thread_id: Option<String>,
}

/// A `Conv` for publishing into the webhook's channel: no member, no permissions (webhooks cannot read).
async fn channel_conv(state: &AppState, channel: ChannelRow) -> Result<Conv, ApiError> {
    let room = store::rooms::room_by_id(&state.db, &channel.room_id)
        .await?
        .ok_or_else(|| crate::access::not_found("Room", "room.not_found"))?;
    let everyone = store::rooms::roles(&state.db, &room.id)
        .await?
        .into_iter()
        .find(|r| r.is_everyone != 0)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("room without @everyone")))?;
    let access = RoomAccess {
        room,
        member: None,
        everyone,
        member_roles: Vec::new(),
        is_owner: false,
        is_node_admin: false,
        room_perms: 0,
        kind: "webhook".into(),
        scopes: None,
        // Webhooks only post (into channels their room manager chose); `channel_conv` never checks the gate here.
        adult: true,
        moved_channel: None,
    };
    Ok(Conv {
        id: channel.id.clone(),
        encrypted: false,
        perms: 0,
        kind: ConvKind::Channel { access: Box::new(access), channel },
    })
}

/// Mentions of members of the room only; role mentions and everybody else are dropped.
async fn member_mentions(state: &AppState, room_id: &str, mentions: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    for m in mentions {
        let Some((name, domain)) = util::parse_address(m) else { continue };
        let Some(user) = store::federation::user_by_address(&state.db, name, domain).await? else { continue };
        if store::rooms::member(&state.db, room_id, &user.id).await?.is_some() && !out.contains(m) {
            out.push(m.clone());
        }
    }
    Ok(out)
}

/// A sender-sealed execution body (APPLICATIONS.md §6.1a): the sealed box and the epoch of the key used.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedPayload {
    /// `crypto_box_seal` of the inner JSON `{ "content": {…}, "username"? }` to the inbox key, base64url.
    pub sealed: String,
    /// The epoch of the inbox key (from `GET …/inbox-key`).
    pub epoch: i64,
    /// A thread of the channel to post into (routing metadata outside the box); required in forum channels.
    pub thread_id: Option<String>,
}

/// The inner payload a sealed box carries (validated by readers, never by the node in `sender` mode).
#[derive(Serialize)]
struct Inner<'a> {
    content: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
}

/// A message ready to be stored.
struct Prepared {
    content: String,
    encrypted: bool,
    epoch: Option<i64>,
    mentions: Vec<String>,
    mentions_everyone: bool,
    reply_to: Option<String>,
    thread_id: Option<String>,
    name: String,
}

/// Runs an execution of `webhook` with the raw `body` (≤ 32 KiB, checked by the route). Returns the message.
pub async fn execute(state: &AppState, webhook: &WebhookRow, body: &[u8]) -> Result<Message, ApiError> {
    // §2.7: 5 per 2 seconds and 30 per minute per webhook (after the secret check: a stranger who knows only
    // the id cannot use up the webhook's budget).
    let key = [format!("wh:{}", webhook.id)];
    state.webhook_burst_limiter.check_all(&key).await?;
    state.webhook_minute_limiter.check_all(&key).await?;
    let channel = store::rooms::channel_by_id(&state.db, &webhook.channel_id).await?.ok_or_else(not_found)?;
    let prepared = if channel.encrypted == 0 {
        prepare_plain(state, webhook, &channel, body).await?
    } else {
        let inbox = store::webhooks::inbox_key(&state.db, &channel.id).await?.ok_or_else(pending_key)?;
        match Sealing::of(webhook) {
            Sealing::Sender => prepare_sender_sealed(webhook, &inbox, body)?,
            // Nothing of a refused node-sealed payload may reach logs or answers: details are withheld.
            Sealing::Node => prepare_node_sealed(state, webhook, &channel, &inbox, body).await.map_err(opaque)?,
        }
    };
    let thread = target_thread(state, &channel, prepared.thread_id.as_deref()).await?;
    let id = util::ulid();
    store::messages::insert_webhook(
        &state.db,
        NewMessage {
            id: &id,
            conversation_id: &channel.id,
            author_id: &webhook.user_id,
            device_id: None,
            encrypted: prepared.encrypted,
            format: 1,
            epoch: prepared.epoch,
            content: &prepared.content,
            reply_to_id: prepared.reply_to.as_deref(),
            thread_id: thread.as_ref().map(|t| t.id.as_str()),
            mentions: &prepared.mentions,
            mentions_everyone: prepared.mentions_everyone,
            signature: None,
        },
        WebhookAuthor { id: &webhook.id, name: &prepared.name },
    )
    .await?;
    store::webhooks::touch(&state.db, &webhook.id).await?;
    let message = crate::routes::messages::enrich_one(state, &webhook.user_id, &id).await?;
    if let Some(t) = &thread {
        // Like a member's reply (an archived thread reopens), without following: the pseudo user reads nothing.
        store::threads::record_message(&state.db, &t.id, &message.id, &message.created_at).await?;
        crate::threads::publish(state, "thread.update", &t.id).await?;
    }
    let conv = channel_conv(state, channel).await?;
    let event_id = state.hub.room(&webhook.room_id, "message.create", &message);
    crate::subscriptions::record(state, &webhook.room_id, "message.create", &event_id, &message).await;
    crate::federation::social::notify_members(state, &conv, &message, &webhook.user_id).await;
    // Plaintext channels only; sealed webhook messages are encrypted (`index` skips them).
    if !conv.encrypted {
        crate::search::index(state, &message, true).await;
    }
    tracing::info!(webhook = webhook.id, message = id, "webhook executed");
    Ok(message)
}

/// The thread a post goes into (PROTOCOL.md §7e): a thread of the webhook's channel (`404 thread.not_found`), not
/// locked (`403 thread.locked`); forum channels take posts only (`400 message.thread_required` without one).
async fn target_thread(
    state: &AppState,
    channel: &ChannelRow,
    thread_id: Option<&str>,
) -> Result<Option<store::threads::ThreadRow>, ApiError> {
    let Some(thread_id) = thread_id else {
        if channel.kind == "forum" {
            return Err(bad("message.thread_required", "Forum channels take posts only: name the post in thread_id"));
        }
        return Ok(None);
    };
    if !util::is_ulid(thread_id) {
        return Err(crate::threads::not_found());
    }
    match store::threads::by_id(&state.db, &thread_id.to_ascii_uppercase()).await? {
        Some(t) if t.channel_id == channel.id => {
            if t.is_locked() {
                return Err(ApiError::Forbidden { code: "thread.locked", detail: "This thread is locked".into() });
            }
            Ok(Some(t))
        }
        _ => Err(crate::threads::not_found()),
    }
}

/// The checks of a plaintext payload shared by unencrypted channels and `node` sealing: content, username,
/// mentions, `@everyone` and the reply target.
async fn check_payload(
    state: &AppState,
    webhook: &WebhookRow,
    channel: &ChannelRow,
    payload: &WebhookPayload,
) -> Result<(crate::routes::messages::Validated, Option<String>, Vec<String>), ApiError> {
    let username = payload.username.as_deref().map(validate_username).transpose()?;
    if payload.content.get("type").and_then(Value::as_str) != Some("text") {
        return Err(payload_invalid("content must be a text content object"));
    }
    let hosts = state.gifs.as_ref().map(|g| g.allowed_hosts()).unwrap_or(&[]);
    let v = crate::routes::messages::validate_content(hosts, false, &payload.content, &payload.mentions)?;
    // Webhooks never carry components (APPLICATIONS.md §5.10.1): nothing could answer their interactions.
    crate::components::refuse_unless_bot(&payload.content, false)?;
    let mentions = member_mentions(state, &webhook.room_id, &v.mentions).await?;
    if payload.mentions_everyone && webhook.allow_mentions_everyone == 0 {
        return Err(ApiError::Forbidden {
            code: "message.mention_everyone_forbidden",
            detail: "This webhook may not mention @everyone".into(),
        });
    }
    if let Some(reply) = &payload.reply_to {
        match store::messages::by_id(&state.db, reply).await? {
            Some(m) if m.conversation_id == channel.id => {}
            _ => return Err(bad("message.reply_target_missing", "The message to reply to does not exist")),
        }
    }
    Ok((v, username, mentions))
}

async fn prepare_plain(
    state: &AppState,
    webhook: &WebhookRow,
    channel: &ChannelRow,
    body: &[u8],
) -> Result<Prepared, ApiError> {
    let payload: WebhookPayload =
        serde_json::from_slice(body).map_err(|e| payload_invalid(format!("Invalid payload: {e}")))?;
    let (v, username, mentions) = check_payload(state, webhook, channel, &payload).await?;
    Ok(Prepared {
        content: v.content,
        encrypted: false,
        epoch: None,
        mentions,
        mentions_everyone: payload.mentions_everyone,
        reply_to: payload.reply_to,
        thread_id: payload.thread_id,
        name: username.unwrap_or_else(|| webhook.name.clone()),
    })
}

/// The stored content of a sealed webhook message (the ciphertext slot of the envelope).
fn sealed_content(epoch: i64, sealed: &str, by: Sealing) -> String {
    json!({ "type": "webhook.sealed", "epoch": epoch, "sealed": sealed, "sealed_by": by.as_str() }).to_string()
}

/// `sender` mode: only `{ sealed, epoch }` bodies, an epoch the channel has published (at most the newest one) and
/// a well-formed box; the node cannot check anything inside it.
fn prepare_sender_sealed(
    webhook: &WebhookRow,
    inbox: &store::webhooks::InboxKeyRow,
    body: &[u8],
) -> Result<Prepared, ApiError> {
    let payload: SealedPayload = serde_json::from_slice(body).map_err(|_| {
        bad(
            "webhook.sealed_required",
            "This webhook accepts only sealed bodies { sealed, epoch } (APPLICATIONS.md §6.1a)",
        )
    })?;
    if payload.epoch < 0 || payload.epoch > inbox.epoch {
        return Err(bad("webhook.epoch_invalid", "epoch: the epoch of a published inbox key"));
    }
    let bytes = tavrn_crypto::util::b64url_decode(&payload.sealed).map_err(|_| payload_invalid("sealed: base64url"))?;
    if bytes.len() <= tavrn_crypto::sealed::SEAL_OVERHEAD {
        return Err(payload_invalid("sealed: too short for a sealed box"));
    }
    Ok(Prepared {
        content: sealed_content(payload.epoch, &payload.sealed, Sealing::Sender),
        encrypted: true,
        epoch: Some(payload.epoch),
        mentions: Vec::new(),
        mentions_everyone: false,
        reply_to: None,
        thread_id: payload.thread_id,
        name: webhook.name.clone(),
    })
}

/// `node` mode: the payload is checked like a plaintext one, then sealed in memory to the newest inbox key; the
/// per-message `username` goes into the box as well. Only mentions, `@everyone` and the reply target stay
/// visible, as for every encrypted message (PROTOCOL.md §7).
async fn prepare_node_sealed(
    state: &AppState,
    webhook: &WebhookRow,
    channel: &ChannelRow,
    inbox: &store::webhooks::InboxKeyRow,
    body: &[u8],
) -> Result<Prepared, ApiError> {
    let payload: WebhookPayload = serde_json::from_slice(body).map_err(|_| payload_invalid("Invalid payload"))?;
    let (_, username, mentions) = check_payload(state, webhook, channel, &payload).await?;
    let inner = zeroize::Zeroizing::new(
        serde_json::to_vec(&Inner { content: &payload.content, username: username.as_deref() })
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("inner payload not serializable")))?,
    );
    let public_key: [u8; 32] = tavrn_crypto::util::b64url_decode(&inbox.public_key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("stored inbox key malformed")))?;
    let sealed = tavrn_crypto::sealed::seal(&public_key, &inner)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("sealing failed")))?;
    let sealed = tavrn_crypto::util::b64url_encode(&sealed);
    Ok(Prepared {
        content: sealed_content(inbox.epoch, &sealed, Sealing::Node),
        encrypted: true,
        epoch: Some(inbox.epoch),
        mentions,
        mentions_everyone: payload.mentions_everyone,
        reply_to: payload.reply_to,
        thread_id: payload.thread_id,
        name: webhook.name.clone(),
    })
}

/// A refused `node`-sealed payload: the code and status stay, the detail (which may quote the payload) goes.
fn opaque(e: ApiError) -> ApiError {
    const DETAIL: &str = "The payload was refused (details are withheld in encrypted channels)";
    match e {
        ApiError::BadRequest { code, .. } | ApiError::BadRequestMeta { code, .. } => bad(code, DETAIL),
        ApiError::Forbidden { code, .. } => ApiError::Forbidden { code, detail: DETAIL.into() },
        ApiError::PayloadTooLarge { code, meta, .. } => ApiError::PayloadTooLarge { code, detail: DETAIL.into(), meta },
        other => other,
    }
}

/// The encryption of a channel was switched (APPLICATIONS.md §6.1a): its webhooks stay. Encrypted: sealed by the
/// sender (unless set otherwise) and pending until a member publishes the inbox key; unencrypted: plaintext again.
/// The channel's inbox key is forgotten both ways. Audited as `webhook.update` with the new mode.
pub async fn encryption_changed(
    state: &AppState,
    room_id: &str,
    channel_id: &str,
    encrypted: bool,
    actor: &UserRow,
) -> Result<(), ApiError> {
    store::webhooks::delete_inbox_key(&state.db, channel_id).await?;
    for w in store::webhooks::set_sealing_in_channel(&state.db, channel_id, encrypted).await? {
        store::rooms::audit(
            &state.db,
            Some(room_id),
            Some(&actor.id),
            "webhook.update",
            &w.id,
            "",
            json!({ "webhook_id": w.id, "channel_id": channel_id, "changed": ["sealing"],
                    "sealing": encrypted.then_some("sender") }),
        )
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- inbox keys (ENCRYPTION.md §5b)

/// The newest inbox key of an encrypted channel, as served to sender-sealing services and to publishers.
#[derive(Debug, Serialize, ToSchema)]
pub struct InboxKey {
    /// The epoch the key belongs to; sealed bodies name it.
    pub epoch: i64,
    /// X25519 public key, base64url (32 bytes).
    pub public_key: String,
    /// `x25519-xsalsa20poly1305-sealedbox`: libsodium's `crypto_box_seal`.
    pub algorithm: String,
}

impl From<store::webhooks::InboxKeyRow> for InboxKey {
    fn from(k: store::webhooks::InboxKeyRow) -> Self {
        Self { epoch: k.epoch, public_key: k.public_key, algorithm: tavrn_crypto::sealed::ALGORITHM.into() }
    }
}

/// `GET /webhooks/{id}/{secret}/inbox-key`: the key a sender seals to (`409 webhook.not_sealed` in unencrypted
/// channels, `409 webhook.pending_key` before a member published one).
pub async fn inbox_key_of(state: &AppState, webhook: &WebhookRow) -> Result<InboxKey, ApiError> {
    let key = [format!("whk:{}", webhook.id)];
    state.webhook_burst_limiter.check_all(&key).await?;
    let channel = store::rooms::channel_by_id(&state.db, &webhook.channel_id).await?.ok_or_else(not_found)?;
    if channel.encrypted == 0 {
        return Err(ApiError::conflict("webhook.not_sealed", "The channel is not encrypted: post plaintext payloads"));
    }
    Ok(store::webhooks::inbox_key(&state.db, &channel.id).await?.ok_or_else(pending_key)?.into())
}

/// `PUT /conversations/{id}/inbox-key` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishInboxKeyRequest {
    pub epoch: i64,
    /// X25519 public key derived from the epoch's content key, base64url (32 bytes).
    pub public_key: String,
    /// Ed25519 signature of the publishing (session) device over
    /// `"tavrn webhook inbox key v1" || 0x00 || str16(qualified conversation id) || u64(epoch) || public_key`.
    pub signature: String,
}

fn inbox_invalid(detail: &str) -> ApiError {
    bad("inbox_key.invalid", detail.to_string())
}

/// Publishes an inbox key: an attested device of a member entitled to the encrypted channel, a channel with
/// webhooks, an epoch the group has reached, a valid device signature; only newer epochs replace the stored key
/// (the same key again is accepted, anything else for an older or the same epoch answers `409 inbox_key.stale`).
pub async fn publish_inbox_key(
    state: &AppState,
    auth: &crate::auth::AuthUser,
    conversation_id: &str,
    req: &PublishInboxKeyRequest,
) -> Result<InboxKey, ApiError> {
    let conv = crate::access::conversation(state, conversation_id, &auth.user).await?;
    conv.require_entitled()?;
    let ConvKind::Channel { channel, .. } = &conv.kind else {
        return Err(bad("inbox_key.not_encrypted", "Inbox keys exist only for encrypted channels"));
    };
    if !conv.encrypted {
        return Err(bad("inbox_key.not_encrypted", "Inbox keys exist only for encrypted channels"));
    }
    if channel.has_webhooks == 0 {
        return Err(ApiError::conflict("inbox_key.no_webhooks", "The channel has no webhooks"));
    }
    let current = store::e2ee::group_epoch(&state.db, &conv.id)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "mls.no_group", what: "MLS group".into() })?;
    if req.epoch < 0 || req.epoch > current {
        return Err(inbox_invalid("epoch: an epoch the group has reached"));
    }
    let public_key: [u8; 32] = tavrn_crypto::util::b64url_decode(&req.public_key)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| inbox_invalid("public_key: 32 bytes base64url"))?;
    let signature =
        tavrn_crypto::util::b64url_decode(&req.signature).map_err(|_| inbox_invalid("signature: base64url"))?;
    let device_key = crate::e2ee::attested_session_key(state, auth).await?;
    let qualified = crate::e2ee::qualified(state, &conv.id);
    #[allow(clippy::cast_sign_loss)]
    let epoch = req.epoch as u64;
    tavrn_crypto::sealed::verify_inbox_key(&device_key, &qualified, epoch, &public_key, &signature)
        .map_err(|_| bad("inbox_key.bad_signature", "The signature does not verify with the session device's key"))?;
    let stored = store::webhooks::put_inbox_key(
        &state.db,
        store::webhooks::NewInboxKey {
            conversation_id: &conv.id,
            epoch: req.epoch,
            public_key: &req.public_key,
            signature: &req.signature,
            user_id: &auth.user.id,
            device_id: auth.public_device_id(),
        },
    )
    .await?;
    let newest = store::webhooks::inbox_key(&state.db, &conv.id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("inbox key missing after publishing")))?;
    if !stored && (newest.epoch != req.epoch || newest.public_key != req.public_key) {
        return Err(ApiError::Conflict {
            code: "inbox_key.stale",
            detail: "A key of this or a newer epoch is already published".into(),
            meta: json!({ "epoch": newest.epoch }),
        });
    }
    Ok(newest.into())
}

/// `/api/v1/webhooks/<id>/<secret>…` → `/api/v1/webhooks/<id>/***` for logs (wherever `/webhooks/` appears outside
/// the management routes under `/rooms/`, so mistyped prefixes are redacted as well). Other paths stay as they are.
pub fn redact_path(path: &str) -> Cow<'_, str> {
    const SEGMENT: &str = "/webhooks/";
    let Some(start) = path.find(SEGMENT).filter(|_| !path.contains("/rooms/")) else { return Cow::Borrowed(path) };
    let after = start + SEGMENT.len();
    match path[after..].find('/') {
        Some(slash) => Cow::Owned(format!("{}/***", &path[..after + slash])),
        None => Cow::Borrowed(path),
    }
}

/// The request span of the HTTP trace layer: method, the redacted path (never the query string) and version.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactedSpan;

impl<B> tower_http::trace::MakeSpan<B> for RedactedSpan {
    fn make_span(&mut self, request: &Request<B>) -> tracing::Span {
        tracing::debug_span!(
            "request",
            method = %request.method(),
            path = %redact_path(request.uri().path()),
            version = ?request.version(),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn secrets_are_random_and_hashed() {
        let (a, ha) = new_secret();
        let (b, _) = new_secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43, "32 bytes base64url");
        assert!(secret_matches(&a, &ha));
        assert!(!secret_matches(&b, &ha));
        assert!(!secret_matches(&a, "--------------------------------------------"));
    }

    #[test]
    fn usernames_follow_the_rules() {
        assert_eq!(validate_username(" CI ").unwrap(), "CI");
        assert_eq!(validate_username(&"ä".repeat(32)).unwrap().chars().count(), 32);
        for bad in ["", "   ", "a@b", "#chan", "a:b", "everyone", "Here", "@everyone", "line\nbreak", "\u{202e}x"] {
            assert_eq!(validate_username(bad).unwrap_err().code(), "webhook.username_invalid", "{bad:?}");
        }
        assert_eq!(validate_username(&"x".repeat(33)).unwrap_err().code(), "webhook.username_invalid");
    }

    #[test]
    fn the_secret_segment_is_redacted() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        assert_eq!(redact_path(&format!("/api/v1/webhooks/{id}/s3cr3t")), format!("/api/v1/webhooks/{id}/***"));
        assert_eq!(redact_path(&format!("/api/v1/webhooks/{id}/s3cr3t/extra")), format!("/api/v1/webhooks/{id}/***"));
        assert_eq!(redact_path(&format!("//api/v1//webhooks/{id}/s3cr3t")), format!("//api/v1//webhooks/{id}/***"));
        assert_eq!(redact_path("/api/v1/rooms/r1/webhooks"), "/api/v1/rooms/r1/webhooks");
        assert_eq!(redact_path("/api/v1/rooms/r1/webhooks/w1/avatar"), "/api/v1/rooms/r1/webhooks/w1/avatar");
        assert_eq!(redact_path("/api/v1/node"), "/api/v1/node");
    }
}
