// SPDX-License-Identifier: AGPL-3.0-only
//! Web push (PROTOCOL.md §6d, capability `push.webpush`; RFC 8030, 8291, 8292).
//!
//! Local users register the push subscriptions of their browsers (`routes::push`). When something would notify a
//! user under their notification settings (`notifications.rs`) and the user has **no open WebSocket** on any
//! instance of this node, the node sends a push to every deliverable subscription of the user:
//!
//! - messages in conversations hosted here (channels, DMs, group DMs): [`message`], called for every new message;
//! - call rings of DMs and group DMs hosted here: [`call`];
//! - conversations on other nodes: the `notify` hints of FEDERATION.md §5.2 (DMs, group DMs, mentions, call rings)
//!   that this node receives as the user's home node, after the user's settings were applied: [`hint`];
//! - other features (`custom`): a notice for one user, coalesced like messages.
//!
//! Content: for encrypted conversations the payload names the conversation, its room/channel/group name and the
//! sender's display name, never ciphertext or plaintext. For unencrypted conversations a preview of at most
//! [`PREVIEW_CHARS`] characters is added only when the user turned on `global.push_text` (default off). The payload
//! is encrypted for the browser (RFC 8291); push services see only its size.
//!
//! Limits: at most one push per conversation and user every [`COALESCE`] (call rings excepted), at most
//! `TAVRN_PUSH_MAX_PER_MINUTE` per user; with several instances both counters live in the cache. Work is queued
//! (bounded, [`QUEUE`]) and done by a background task, never on the request path; a full queue drops pushes.
//! Delivery: `404`/`410` delete the subscription, `429`/`5xx`/network errors hold it back (exponential backoff,
//! `Retry-After` honored) and delete it after `store::push::MAX_FAILURES` failures in a row.

pub mod crypto;

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Url, header};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, mpsc};

use crate::{
    access::{self, ConvKind},
    app::AppState,
    cache::limiter::SharedLimiter,
    config::Config,
    error::ApiError,
    federation::client::{AddressForbidden, Lookup, VettingResolver, forbidden_ip, user_agent},
    models::{Message, UserRow},
    store::{self, push::SubscriptionRow},
    util,
};

pub use crypto::VapidKey;

/// Capability announced while push is on.
pub const CAPABILITY: &str = "push.webpush";
/// At most one push per conversation and user within this time.
pub const COALESCE: Duration = Duration::from_secs(30);
/// Jobs waiting for the sender; more are dropped (logged).
pub const QUEUE: usize = 1024;
/// Jobs worked on at once.
const PARALLEL: usize = 16;
/// Characters of a message preview (unencrypted conversations with `push_text` only).
pub const PREVIEW_CHARS: usize = 120;
/// Names in a payload are cut to this many characters.
const NAME_CHARS: usize = 100;
/// Longest accepted endpoint URL.
pub const MAX_ENDPOINT: usize = 2048;
/// Timeout of one delivery.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Lifetime of a push at the push service (`TTL`): messages and notices, call rings, test pushes.
const TTL_MESSAGE: u32 = 6 * 3600;
const TTL_CALL: u32 = 45;
const TTL_TEST: u32 = 300;
/// Longest hold-back after failures.
const MAX_BACKOFF_SECS: i64 = 6 * 3600;

/// What happened, as the client shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A message in a channel (mode `all`).
    Message,
    /// A mention of the user, one of their roles or `@everyone`.
    Mention,
    /// A message in a DM or group DM.
    Dm,
    /// A call rings.
    Call,
    /// Something else for the user (`title`/`body` of the notice).
    Notice,
    /// The test push of the settings.
    Test,
    /// A new report for a moderator or node admin (`report_kind` and the room only, MODERATION.md §1.5).
    Report,
}

/// The decrypted payload a browser's service worker receives (`v` = 1). Field order is stable; absent fields are
/// left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PushPayload {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: Option<Kind>,
    /// The node that hosts the conversation.
    pub node: String,
    /// `node` is the node that sent the push (else the conversation is on another node: a forwarded hint).
    pub local: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    /// `channel`, `dm` or `group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_kind: Option<String>,
    /// Room name (channels).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// Channel name or group DM name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<String>,
    /// Display name of the author or caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// Preview of an unencrypted message (only with `push_text`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub encrypted: bool,
    /// Notices of other features: a short title and body in the node's words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Reports: `message`, `user` or `room`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_kind: Option<String>,
}

/// A job of the sender.
#[derive(Debug, Clone)]
pub enum Job {
    /// A new message in a conversation hosted here.
    Message { message: Box<Message>, author_id: String },
    /// A call in a DM or group DM hosted here rings `user_id`.
    Call { conversation_id: String, user_id: String, caller_id: String, group: bool },
    /// A received `notify` hint for a conversation on `node` (already filtered by the user's settings).
    Hint {
        user_id: String,
        node: String,
        conversation_id: String,
        room_id: Option<String>,
        mention: bool,
        call: Option<String>,
    },
    /// A notice of another feature for one user, coalesced per `conversation_id` when given.
    Notice { user_id: String, payload: PushPayload },
    /// The test push of one user (every deliverable subscription).
    Test { user_id: String },
}

/// The web push service of this node.
pub struct Push {
    enabled: bool,
    vapid: Option<VapidKey>,
    contact: String,
    domain: String,
    tx: mpsc::Sender<Job>,
    rx: Mutex<Option<mpsc::Receiver<Job>>>,
    http: reqwest::Client,
    resolver: VettingResolver,
    allow_private: bool,
    allow_http: bool,
    conversation_limiter: SharedLimiter,
    user_limiter: SharedLimiter,
    /// Test pushes per user (`push-test:<user id>`, 5 per 10 minutes).
    pub test_limiter: SharedLimiter,
    /// Subscription registrations per user (`push-sub:<user id>`, 30 per hour).
    pub register_limiter: SharedLimiter,
}

impl Push {
    /// Loads or creates the VAPID key (only while push is on) and builds the outbound client: the vetting resolver of
    /// the federation client (every address must be public; development nodes also reach loopback and plain http).
    pub fn new(config: &Config, cluster: &Arc<crate::cache::Cluster>, lookup: Arc<dyn Lookup>) -> anyhow::Result<Self> {
        let enabled = config.push.on();
        let vapid = if enabled {
            Some(VapidKey::load_or_create(&std::path::Path::new(&config.data_dir).join("keys"))?)
        } else {
            None
        };
        let allow_private = config.dev;
        let resolver = VettingResolver::new(lookup, allow_private, HashSet::new());
        let http = reqwest::Client::builder()
            .user_agent(user_agent(&config.domain))
            .dns_resolver(Arc::new(resolver.clone()))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(SEND_TIMEOUT)
            .timeout(SEND_TIMEOUT)
            .no_proxy()
            .build()?;
        let (tx, rx) = mpsc::channel(QUEUE);
        let shared = |name: &'static str, max: u32, window: Duration| SharedLimiter::new(name, max, window, cluster);
        Ok(Self {
            enabled,
            vapid,
            contact: config.push_contact(),
            domain: config.domain.clone(),
            tx,
            rx: Mutex::new(Some(rx)),
            http,
            resolver,
            allow_private,
            allow_http: config.dev,
            conversation_limiter: shared("push-conv", 1, COALESCE),
            user_limiter: shared("push-user", config.push_max_per_minute, Duration::from_secs(60)),
            test_limiter: shared("push-test", 5, Duration::from_secs(600)),
            register_limiter: shared("push-sub", if config.dev { 1000 } else { 30 }, Duration::from_secs(3600)),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The VAPID public key (base64url of the uncompressed point) while push is on.
    pub fn public_key(&self) -> Option<&str> {
        self.vapid.as_ref().map(VapidKey::public_key)
    }

    /// Queues a job; never waits. A full queue drops the job.
    pub fn queue(&self, job: Job) {
        if !self.enabled {
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(job) {
            tracing::warn!("web push queue full, a push was dropped");
        }
    }

    /// Checks an endpoint URL: `https://` (development nodes also `http://`), a host, no credentials or fragment,
    /// at most [`MAX_ENDPOINT`] characters. The addresses are vetted again at every delivery.
    pub fn check_endpoint(&self, raw: &str) -> Result<Url, ApiError> {
        let invalid = |detail: &str| ApiError::BadRequest { code: "push.endpoint_invalid", detail: detail.into() };
        if raw.is_empty() || raw.len() > MAX_ENDPOINT {
            return Err(invalid("endpoint: 1 to 2048 characters"));
        }
        let url = Url::parse(raw).map_err(|_| invalid("endpoint is not a URL"))?;
        if !(url.scheme() == "https" || (self.allow_http && url.scheme() == "http")) {
            return Err(invalid("endpoint must be an https:// URL"));
        }
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(invalid("endpoint must not contain credentials or a fragment"));
        }
        let Some(host) = url.host_str().filter(|h| !h.is_empty()) else { return Err(invalid("endpoint needs a host")) };
        if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>()
            && !self.allow_private
            && forbidden_ip(ip)
        {
            return Err(invalid("endpoint must be a public address"));
        }
        Ok(url)
    }
}

// ---------------------------------------------------------------- entry points (never block)

/// A new message in a conversation hosted here (every message path calls this through
/// `federation::social::notify_members`).
pub fn message(state: &AppState, message: &Message, author_id: &str) {
    state.push.queue(Job::Message { message: Box::new(message.clone()), author_id: author_id.to_string() });
}

/// A call in a DM or group DM hosted here rings the local user `user_id`.
pub fn call(state: &AppState, conversation_id: &str, user_id: &str, caller_id: &str, group: bool) {
    state.push.queue(Job::Call {
        conversation_id: conversation_id.to_string(),
        user_id: user_id.to_string(),
        caller_id: caller_id.to_string(),
        group,
    });
}

/// A `notify` hint for a conversation on `node` that the user's settings let through (FEDERATION.md §5.2); `call`
/// is the caller's address of a ring hint.
pub fn hint(
    state: &AppState,
    user_id: &str,
    node: &str,
    conversation_id: &str,
    room_id: Option<&str>,
    mention: bool,
    call: Option<&str>,
) {
    state.push.queue(Job::Hint {
        user_id: user_id.to_string(),
        node: node.to_string(),
        conversation_id: conversation_id.to_string(),
        room_id: room_id.map(String::from),
        mention,
        call: call.map(String::from),
    });
}

/// A notice of another feature (e.g. a followed thread) for one local user. `payload.kind` defaults to
/// [`Kind::Notice`]; `node`, `local` and `v` are filled in. Coalesced per `payload.conversation_id` when set.
pub fn custom(state: &AppState, user_id: &str, mut payload: PushPayload) {
    payload.kind = Some(payload.kind.unwrap_or(Kind::Notice));
    state.push.queue(Job::Notice { user_id: user_id.to_string(), payload });
}

/// A new report for a local moderator or node admin (MODERATION.md §1.5): the report's kind and its room, nothing of
/// its content. The caller checks the user's `reports` setting; the limits of [`custom`] apply.
pub fn report(state: &AppState, user_id: &str, room_id: Option<&str>, room: Option<&str>, report_kind: &str) {
    custom(
        state,
        user_id,
        PushPayload {
            kind: Some(Kind::Report),
            room_id: room_id.map(String::from),
            room: room.map(|r| cut(r, NAME_CHARS)),
            report_kind: Some(report_kind.to_string()),
            ..PushPayload::default()
        },
    );
}

// ---------------------------------------------------------------- the sender

/// Starts the sender task (once per state; [`crate::app::AppState::init`] calls it).
pub fn start(state: &AppState) {
    let Some(mut rx) = state.push.rx.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
    if !state.push.enabled {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let permits = Arc::new(Semaphore::new(PARALLEL));
        while let Some(job) = rx.recv().await {
            let Ok(permit) = permits.clone().acquire_owned().await else { break };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = run(&state, job).await {
                    tracing::warn!(error = %e, "web push job failed");
                }
                drop(permit);
            });
        }
    });
}

async fn run(state: &AppState, job: Job) -> Result<(), ApiError> {
    match job {
        Job::Message { message, author_id } => run_message(state, &message, &author_id).await,
        Job::Call { conversation_id, user_id, caller_id, group } => {
            run_call(state, &conversation_id, &user_id, &caller_id, group).await
        }
        Job::Hint { user_id, node, conversation_id, room_id, mention, call } => {
            let kind = match (&call, &room_id, mention) {
                (Some(_), _, _) => Kind::Call,
                (None, Some(_), true) => Kind::Mention,
                (None, Some(_), false) => Kind::Message,
                (None, None, _) => Kind::Dm,
            };
            let payload = PushPayload {
                kind: Some(kind),
                node,
                local: false,
                conversation_kind: Some(if room_id.is_some() { "channel" } else { "direct" }.into()),
                conversation_id: Some(conversation_id.clone()),
                room_id,
                sender: call,
                // Hints never carry content (FEDERATION.md §5.2): nothing is known about it here.
                encrypted: true,
                ..PushPayload::default()
            };
            deliver_to_user(state, &user_id, Some(&conversation_id), kind == Kind::Call, payload).await
        }
        Job::Notice { user_id, payload } => {
            // Reports coalesce per room (or per node for node reports): one push per moderator and 30 seconds.
            let conversation = payload.conversation_id.clone().or_else(|| {
                (payload.kind == Some(Kind::Report))
                    .then(|| format!("report:{}", payload.room_id.as_deref().unwrap_or("node")))
            });
            let payload = PushPayload { node: state.config.domain.clone(), local: true, ..payload };
            deliver_to_user(state, &user_id, conversation.as_deref(), false, payload).await
        }
        Job::Test { user_id } => {
            let payload = PushPayload {
                kind: Some(Kind::Test),
                node: state.config.domain.clone(),
                local: true,
                ..PushPayload::default()
            };
            for s in store::push::deliverable(&state.db, &user_id).await? {
                deliver(state, &s, &payload, TTL_TEST, None).await;
            }
            Ok(())
        }
    }
}

fn cut(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The text of an unencrypted message for a preview (`content.body` of text messages).
fn preview_text(message: &Message) -> Option<String> {
    if message.encrypted {
        return None;
    }
    let body = message.content.get("body").and_then(Value::as_str)?;
    let text = cut(&body.split_whitespace().collect::<Vec<_>>().join(" "), PREVIEW_CHARS);
    (!text.is_empty()).then_some(text)
}

/// Does the message mention the user directly (address or one of their roles)?
fn direct_mention(message: &Message, user: &UserRow, role_ids: &[String]) -> bool {
    let address = user.address().to_lowercase();
    message.mentions.iter().any(|m| m.to_lowercase() == address)
        || role_ids.iter().any(|r| message.mentions.contains(&store::messages::role_mention(r)))
}

async fn run_message(state: &AppState, message: &Message, author_id: &str) -> Result<(), ApiError> {
    let Some(row) = store::social::conversation(&state.db, &message.conversation_id).await? else { return Ok(()) };
    // Candidates: the members with a subscription (rooms can be large; most members have none).
    let candidates = match (row.kind.as_str(), &row.room_id) {
        ("channel", Some(room_id)) => store::push::room_members_with_subscriptions(&state.db, room_id).await?,
        ("dm" | "group", _) => {
            let members = store::social::member_ids(&state.db, &row.id).await?;
            store::push::users_with_subscriptions(&state.db, &members).await?
        }
        _ => return Ok(()),
    };
    let author = store::users::by_id(&state.db, author_id).await?;
    let sender = message
        .author_room_profile
        .as_ref()
        .and_then(|p| p.nick.clone())
        .or_else(|| author.as_ref().map(|a| a.display_name.clone()));
    let now = util::now();
    // Thread messages (PROTOCOL.md §7e) reach the thread's followers; others only when mentioned directly.
    let followers: HashSet<String> = match &message.thread_id {
        Some(thread_id) => store::threads::follower_ids(&state.db, thread_id).await?.into_iter().collect(),
        None => HashSet::new(),
    };
    for user_id in candidates {
        if user_id == author_id || crate::presence::is_online(state, &user_id) {
            continue;
        }
        let Some(user) = store::users::by_id(&state.db, &user_id).await? else { continue };
        if user.domain != state.config.domain || user.disabled_at.is_some() {
            continue;
        }
        // The user's own view of the conversation: membership, `view_channel`, message requests.
        let conv = match access::conversation(state, &row.id, &user).await {
            Ok(c) => c,
            Err(ApiError::Forbidden { .. } | ApiError::NotFound { .. }) => continue,
            Err(e) => return Err(e),
        };
        if !conv.entitled() || conv.is_request_for(&user.id) {
            continue;
        }
        let (room_id, role_ids, room_name, channel_name) = match &conv.kind {
            ConvKind::Channel { access, channel } => {
                // Welcome and system channels never notify.
                if channel.kind == "system" {
                    continue;
                }
                let roles = store::rooms::member_role_ids(&state.db, &access.room.id, &user.id).await?;
                (Some(access.room.id.clone()), roles, Some(access.room.name.clone()), Some(channel.name.clone()))
            }
            ConvKind::Direct { row, .. } => (None, Vec::new(), None, row.name.clone()),
        };
        if let Some(author) = &author
            && store::social::blocked_either(&state.db, &user.id, &author.id).await?
        {
            continue;
        }
        let settings = crate::notifications::load(&state.db, &user.id).await?;
        let direct = direct_mention(message, &user, &role_ids);
        if message.thread_id.is_some() && !direct && !followers.contains(&user.id) {
            continue;
        }
        let Some(important) =
            settings.push_decision(room_id.as_deref(), &row.id, &now, direct, message.mentions_everyone)
        else {
            continue;
        };
        let kind = match (&room_id, important) {
            (None, _) => Kind::Dm,
            (Some(_), true) => Kind::Mention,
            (Some(_), false) => Kind::Message,
        };
        let payload = PushPayload {
            kind: Some(kind),
            node: state.config.domain.clone(),
            local: true,
            conversation_id: Some(row.id.clone()),
            room_id: room_id.clone(),
            conversation_kind: Some(row.kind.clone()),
            room: room_name.map(|n| cut(&n, NAME_CHARS)),
            conversation: channel_name.map(|n| cut(&n, NAME_CHARS)),
            sender: sender.as_deref().map(|n| cut(n, NAME_CHARS)),
            text: if settings.global.push_text { preview_text(message) } else { None },
            encrypted: message.encrypted,
            ..PushPayload::default()
        };
        deliver_to_user(state, &user.id, Some(&row.id), false, payload).await?;
    }
    Ok(())
}

async fn run_call(
    state: &AppState,
    conversation_id: &str,
    user_id: &str,
    caller_id: &str,
    group: bool,
) -> Result<(), ApiError> {
    if crate::presence::is_online(state, user_id) {
        return Ok(());
    }
    let Some(row) = store::social::conversation(&state.db, conversation_id).await? else { return Ok(()) };
    let settings = crate::notifications::load(&state.db, user_id).await?;
    let effective = settings.effective(None, conversation_id, &util::now());
    if effective.muted || effective.mode == crate::notifications::Mode::Nothing {
        return Ok(());
    }
    let caller = store::users::by_id(&state.db, caller_id).await?;
    let payload = PushPayload {
        kind: Some(Kind::Call),
        node: state.config.domain.clone(),
        local: true,
        conversation_id: Some(conversation_id.to_string()),
        conversation_kind: Some(if group { "group" } else { "dm" }.into()),
        conversation: row.name.map(|n| cut(&n, NAME_CHARS)),
        sender: caller.map(|c| cut(&c.display_name, NAME_CHARS)),
        encrypted: row.encrypted != 0,
        ..PushPayload::default()
    };
    deliver_to_user(state, user_id, Some(conversation_id), true, payload).await
}

/// Applies the limits and sends `payload` to every deliverable subscription of a local user without a connection.
async fn deliver_to_user(
    state: &AppState,
    user_id: &str,
    conversation_id: Option<&str>,
    ring: bool,
    payload: PushPayload,
) -> Result<(), ApiError> {
    if crate::presence::is_online(state, user_id) {
        return Ok(());
    }
    let subscriptions = store::push::deliverable(&state.db, user_id).await?;
    if subscriptions.is_empty() {
        return Ok(());
    }
    // Call rings are never coalesced away (they must arrive at once); everything counts per user and minute.
    if !ring
        && let Some(c) = conversation_id
        && state.push.conversation_limiter.check(&format!("{user_id}|{c}")).await.is_err()
    {
        return Ok(());
    }
    if state.push.user_limiter.check(user_id).await.is_err() {
        tracing::debug!(user_id, "push limit per minute reached");
        return Ok(());
    }
    let ttl = if ring { TTL_CALL } else { TTL_MESSAGE };
    let topic = conversation_id.map(topic);
    for s in &subscriptions {
        deliver(state, s, &payload, ttl, topic.as_deref()).await;
    }
    Ok(())
}

/// `Topic` header (RFC 8030 §5.4): a newer push of the same conversation replaces one not delivered yet.
fn topic(conversation_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(conversation_id.as_bytes()))[..22].to_string()
}

/// How one delivery ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// The push service no longer knows the subscription (404, 410): it is deleted.
    Gone,
    /// Try again later (429, 5xx, network, timeouts); `retry_after` seconds when the service said so.
    Retry {
        retry_after: Option<i64>,
    },
    /// Any other answer, or a refused address.
    Failed,
}

/// Sends one push and records the outcome on the subscription and in the metrics.
async fn deliver(state: &AppState, s: &SubscriptionRow, payload: &PushPayload, ttl: u32, topic: Option<&str>) {
    let outcome = send(state, s, payload, ttl, topic).await;
    let db = &state.db;
    let result = match outcome {
        Outcome::Sent => {
            state.metrics.push_sent.inc();
            store::push::mark_used(db, &s.id).await
        }
        Outcome::Gone => {
            state.metrics.push_failed.inc();
            store::push::remove(db, &s.id).await
        }
        Outcome::Retry { retry_after } => held_back(state, s, retry_after).await,
        Outcome::Failed => held_back(state, s, None).await,
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, "push subscription state not saved");
    }
}

/// A failed delivery: exponential backoff from 30 seconds up to 6 hours, or the service's `Retry-After`.
async fn held_back(state: &AppState, s: &SubscriptionRow, retry_after: Option<i64>) -> Result<(), ApiError> {
    state.metrics.push_failed.inc();
    let secs = retry_after.map_or_else(|| backoff_secs(s.failures), |r| r.clamp(1, 24 * 3600));
    store::push::mark_failed(&state.db, &s.id, &util::in_seconds(secs)).await.map(|_| ())
}

/// Hold-back after `failures` earlier failures in a row.
fn backoff_secs(failures: i64) -> i64 {
    (30i64 << failures.clamp(0, 20)).min(MAX_BACKOFF_SECS)
}

async fn send(state: &AppState, s: &SubscriptionRow, payload: &PushPayload, ttl: u32, topic: Option<&str>) -> Outcome {
    let push = &state.push;
    let Some(vapid) = &push.vapid else { return Outcome::Failed };
    let Ok(url) = push.check_endpoint(&s.endpoint) else { return Outcome::Gone };
    let Some(host) = url.host_str() else { return Outcome::Gone };
    // Vet the addresses before connecting (the resolver of the client vets them again for the connection itself).
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_err()
        && let Err(e) = push.resolver.vetted(bare).await
    {
        return if e.is::<AddressForbidden>() { Outcome::Failed } else { Outcome::Retry { retry_after: None } };
    }
    let plaintext = match serde_json::to_vec(&PushPayload { v: 1, ..payload.clone() }) {
        Ok(p) => p,
        Err(_) => return Outcome::Failed,
    };
    let body = match crypto::encrypt(&s.p256dh, &s.auth, &plaintext) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "push payload not encrypted");
            return Outcome::Failed;
        }
    };
    let audience = url.origin().ascii_serialization();
    let authorization = vapid.authorization(&audience, &push.contact, chrono::Utc::now().timestamp());
    let urgent = matches!(payload.kind, Some(Kind::Call | Kind::Dm | Kind::Mention | Kind::Test));
    let mut request = push
        .http
        .post(url)
        .header(header::AUTHORIZATION, authorization)
        .header(header::CONTENT_ENCODING, "aes128gcm")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("ttl", ttl.to_string())
        .header("urgency", if urgent { "high" } else { "normal" });
    if let Some(t) = topic {
        request = request.header("topic", t);
    }
    match request.body(body).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            match status {
                200..=299 => Outcome::Sent,
                404 | 410 => Outcome::Gone,
                429 | 500..=599 => Outcome::Retry {
                    retry_after: response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse().ok()),
                },
                _ => {
                    tracing::debug!(status, domain = %push.domain, "push refused by the push service");
                    Outcome::Failed
                }
            }
        }
        Err(e) => {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
            while let Some(err) = source {
                if err.downcast_ref::<AddressForbidden>().is_some() {
                    return Outcome::Failed;
                }
                source = err.source();
            }
            Outcome::Retry { retry_after: None }
        }
    }
}

/// Queues the test push of a user (`POST /users/me/push-subscriptions/test`).
pub fn test(state: &AppState, user_id: &str) {
    state.push.queue(Job::Test { user_id: user_id.to_string() });
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn cut_and_topic() {
        assert_eq!(cut("  short  ", 10), "short");
        assert_eq!(cut(&"a".repeat(130), PREVIEW_CHARS).chars().count(), PREVIEW_CHARS);
        assert!(cut(&"ä".repeat(130), PREVIEW_CHARS).ends_with('…'));
        let t = topic("01JAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(t.len(), 22);
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(t, topic("01JBBBBBBBBBBBBBBBBBBBBBBB"));
    }

    #[test]
    fn payload_shape() {
        let p = PushPayload {
            v: 1,
            kind: Some(Kind::Mention),
            node: "n.test".into(),
            local: true,
            conversation_id: Some("c".into()),
            encrypted: true,
            ..PushPayload::default()
        };
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!({ "v": 1, "type": "mention", "node": "n.test", "local": true, "conversation_id": "c", "encrypted": true })
        );
    }

    fn config(dev: bool, dir: &tempfile::TempDir) -> Config {
        Config {
            dev,
            domain: "n.test".into(),
            data_dir: dir.path().to_string_lossy().into(),
            ..Config::defaults_for(dev)
        }
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_secs(0), 30);
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(5), 960);
        assert_eq!(backoff_secs(29), MAX_BACKOFF_SECS);
    }

    #[tokio::test]
    async fn endpoint_rules() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = Arc::new(crate::cache::Cluster::standalone("n.test", &[0; 32]));
        let lookup: Arc<dyn Lookup> = Arc::new(crate::federation::client::SystemLookup);
        let prod = Push::new(&config(false, &dir), &cluster, lookup.clone()).unwrap();
        assert!(prod.public_key().is_some());
        assert!(prod.check_endpoint("https://push.example.net/send/abc").is_ok());
        for bad in [
            "",
            "http://push.example.net/x",
            "https://user:pw@push.example.net/x",
            "https://push.example.net/x#frag",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://10.1.2.3/x",
            "ftp://push.example.net/x",
            "not a url",
        ] {
            assert!(prod.check_endpoint(bad).is_err(), "{bad}");
        }
        assert!(prod.check_endpoint(&format!("https://push.example.net/{}", "a".repeat(MAX_ENDPOINT))).is_err());
        let dev = Push::new(&config(true, &dir), &cluster, lookup.clone()).unwrap();
        assert!(dev.check_endpoint("http://127.0.0.1:9/x").is_ok(), "development nodes reach local fakes");
        let off =
            Push::new(&Config { push: crate::config::Switch::Off, ..config(false, &dir) }, &cluster, lookup).unwrap();
        assert!(!off.enabled() && off.public_key().is_none());
    }
}
