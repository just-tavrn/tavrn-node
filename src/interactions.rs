// SPDX-License-Identifier: AGPL-3.0-only
//! Interactions (protocol/APPLICATIONS.md §5.5–§5.8): invoking an application command, delivering it to the
//! application (one WebSocket connection of the bot, round robin over its devices, or the interactions URL),
//! waiting at most 3 seconds for the first response, and the callbacks, follow-ups and ephemeral replies.
//!
//! Interactions live until they expire (15 minutes): the invocation is not a message and is never stored in the
//! database. All deadlines are read from an injectable [`Clock`], so tests can move time forward. Only the first
//! response counts; a callback first *claims* the interaction, is then validated and either completes it or gives it
//! back, so two concurrent callbacks can never both post an answer. Follow-ups take one of their ten places only
//! once they passed every check.
//!
//! Standalone the pending interactions live in memory. With a shared cache (`TAVRN_CACHE_URL`, docs/SCALING.md) they
//! live in the cache as well, sealed like connect codes ([`crate::cache::Cluster::put_sealed`], TTL = the lifetime):
//! `interaction-state:<id>` holds the facts, the lease `interaction-claim:<id>` the first response (a claim, or
//! `dropped` after the deadline) and the counter `interaction-followups:<id>` the follow-ups. Any instance, also one
//! restarted in between, takes callbacks and follow-ups; only the invoker's waiting request stays with the instance
//! that received the invocation (its memory). Each instance registers its receiving bot connections in the cache
//! (`cmdrecv:<bot user id>`, field `<instance>/<connection>`); without a local receiver the owner publishes the
//! invocation on the bus for one instance that has one ([`crate::cache::Message::Invoke`]), which delivers it to its
//! connection. The owner records itself under `interaction:<id>`, and callbacks and follow-ups that reach another
//! instance are relayed to the owner over HTTP while it lives (`cache::relay`), so the invoker gets the answer at
//! once.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    applications::{self as apps, AppPrincipal},
    auth::AuthUser,
    commands::{self, PaletteApplication, Target},
    error::ApiError,
    hub::Scope,
    models::{InteractionRef, Message},
    permissions as p,
    routes::messages as msgs,
    store, util,
};

/// The first response must arrive within this time (§5.5).
pub const ACK_TIMEOUT_SECS: i64 = 3;
/// An interaction (and its follow-ups) lives this long.
pub const LIFETIME_SECS: i64 = 15 * 60;
pub const MAX_FOLLOWUPS: u32 = 10;
/// `error` responses: a short plaintext notice.
pub const ERROR_MAX_CHARS: usize = 200;
/// Interactions in memory at once (DoS bound; the per-user rate limit keeps the real number far below).
pub const MAX_LIVE: usize = 100_000;
/// A claimed callback still being validated when the deadline passes gets this much longer.
const CLAIM_GRACE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------- errors

fn not_found() -> ApiError {
    ApiError::NotFound { code: "interaction.not_found", what: "Interaction".into() }
}

fn expired() -> ApiError {
    ApiError::Gone { code: "interaction.expired", detail: "This interaction has expired".into() }
}

fn already_acked() -> ApiError {
    ApiError::conflict("interaction.already_acked", "This interaction has been answered already")
}

fn not_owner() -> ApiError {
    ApiError::Forbidden {
        code: "interaction.not_owner",
        detail: "This interaction belongs to another application".into(),
    }
}

fn no_ack() -> ApiError {
    ApiError::GatewayTimeout { code: "interaction.no_ack", detail: "The application did not answer in time".into() }
}

fn offline() -> ApiError {
    ApiError::Unavailable { code: "interaction.app_offline", detail: "The application is not connected".into() }
}

fn mismatch(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "interaction.encryption_mismatch", detail: detail.into() }
}

/// Message codes of the content checks as interaction codes (§5.5 check 7, §5.7).
fn as_interaction_error(e: ApiError) -> ApiError {
    let code = match e.code() {
        "message.encryption_mismatch" => "interaction.encryption_mismatch",
        "message.ciphertext_invalid" | "message.epoch_mismatch" => "interaction.ciphertext_invalid",
        "message.epoch_unknown" => "interaction.epoch_unknown",
        _ => return e,
    };
    ApiError::BadRequest { code, detail: e.to_string() }
}

// ---------------------------------------------------------------- clock

/// The time source of the interaction deadlines (tests inject a [`ManualClock`]).
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    /// Resolves once `now() >= at`.
    fn sleep_until(&self, at: DateTime<Utc>) -> BoxFuture<'static, ()>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
    fn sleep_until(&self, at: DateTime<Utc>) -> BoxFuture<'static, ()> {
        let wait = (at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
        Box::pin(tokio::time::sleep(wait))
    }
}

/// A clock that only moves when told to.
pub struct ManualClock {
    now: watch::Sender<DateTime<Utc>>,
}

impl ManualClock {
    pub fn new(start: DateTime<Utc>) -> Self {
        Self { now: watch::Sender::new(start) }
    }
    pub fn advance(&self, by: chrono::Duration) {
        self.now.send_modify(|t| *t += by);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.borrow()
    }
    fn sleep_until(&self, at: DateTime<Utc>) -> BoxFuture<'static, ()> {
        let mut rx = self.now.subscribe();
        Box::pin(async move {
            loop {
                if *rx.borrow_and_update() >= at {
                    return;
                }
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        })
    }
}

// ---------------------------------------------------------------- objects

/// An ephemeral reply: shown to the invoker only, never stored (§5.7).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EphemeralReply {
    pub interaction_id: String,
    pub conversation_id: String,
    /// The thread the reply belongs to (null in the conversation itself).
    #[serde(default)]
    pub thread_id: Option<String>,
    pub application: PaletteApplication,
    /// The bot device that produced it (encrypted content is signed by it).
    pub device_id: Option<String>,
    /// A content object, or ciphertext (base64url) in encrypted conversations.
    #[schema(value_type = Value)]
    pub content: Value,
    pub epoch: Option<i64>,
    pub created_at: String,
}

/// What an invocation (or a callback) produced.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvokeResponse {
    pub interaction_id: String,
    /// `reply`, `defer` or `error`.
    pub outcome: String,
    pub message: Option<Message>,
    pub ephemeral: Option<EphemeralReply>,
    pub error: Option<String>,
}

/// `POST /conversations/{conversation_id}/interactions`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InvokeRequest {
    /// The thread of the channel the command is invoked in (PROTOCOL.md §7e); answers go there.
    #[serde(default)]
    pub thread_id: Option<String>,
    /// `<application ref>/<command id>`
    pub command: String,
    /// Unencrypted conversations: the arguments; null in encrypted ones.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub args: Option<Value>,
    /// Encrypted conversations: the `command.args` content object encrypted like a message (base64url).
    #[serde(default)]
    pub args_ciphertext: Option<String>,
    /// The epoch of `args_ciphertext`.
    #[serde(default)]
    pub epoch: Option<i64>,
}

/// The response of an application (`POST /interactions/{id}/callback` or the interactions URL's answer).
#[derive(Debug, Deserialize, ToSchema)]
pub struct Callback {
    /// `reply`, `defer` or `error`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `reply`: a content object, or ciphertext in encrypted conversations.
    #[serde(default)]
    #[schema(value_type = Value)]
    pub content: Option<Value>,
    #[serde(default)]
    pub epoch: Option<i64>,
    /// Interactions URL answers: the attested bot device that encrypted or sent the content.
    #[serde(default)]
    pub device_id: Option<String>,
    /// `reply` and `defer`: shown to the invoker only.
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub mentions: Vec<String>,
    /// `error`: at most 200 characters, shown to the invoker only.
    #[serde(default)]
    pub message: Option<String>,
    /// `reply`: a thread of the conversation to answer in; defaults to the interaction's thread.
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// `POST /interactions/{interaction_id}/messages`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FollowUp {
    /// A content object, or ciphertext in encrypted conversations.
    #[schema(value_type = Value)]
    pub content: Value,
    #[serde(default)]
    pub epoch: Option<i64>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub mentions: Vec<String>,
    /// A thread of the conversation to write in; defaults to the interaction's thread.
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// A follow-up: a stored message or an ephemeral reply.
#[derive(Debug, Serialize, ToSchema)]
pub struct FollowUpResponse {
    pub message: Option<Message>,
    pub ephemeral: Option<EphemeralReply>,
}

// ---------------------------------------------------------------- registry

/// The immutable facts of an interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub id: String,
    pub application_ref: String,
    pub application_name: String,
    pub bot_user_id: String,
    pub bot_address: String,
    /// Local application with an interactions URL (the URL answer names its device).
    pub local_application_id: Option<String>,
    pub command_id: String,
    pub command_name: String,
    pub conversation_id: String,
    /// The thread the command was invoked in (PROTOCOL.md §7e): answers go there unless they name another one.
    #[serde(default)]
    pub thread_id: Option<String>,
    pub encrypted: bool,
    pub user_id: String,
    pub user_address: String,
    /// The invoker's local device id (ephemeral replies skip the invoking connection's device).
    pub user_device: String,
    pub ack_deadline: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Info {
    pub fn application(&self) -> PaletteApplication {
        PaletteApplication {
            reference: self.application_ref.clone(),
            name: self.application_name.clone(),
            bot: self.bot_address.clone(),
        }
    }
    fn envelope(&self) -> InteractionRef {
        InteractionRef {
            id: self.id.clone(),
            command: self.command_name.clone(),
            application: self.application_ref.clone(),
            user: self.user_address.clone(),
        }
    }
}

/// What the first response was.
#[derive(Debug, Clone)]
pub enum Ack {
    Reply(Box<Message>),
    Ephemeral(Box<EphemeralReply>),
    Defer,
    Error(String),
}

impl Ack {
    pub fn response(&self, interaction_id: &str) -> InvokeResponse {
        let mut r = InvokeResponse {
            interaction_id: interaction_id.to_string(),
            outcome: "reply".into(),
            message: None,
            ephemeral: None,
            error: None,
        };
        match self {
            Self::Reply(m) => r.message = Some((**m).clone()),
            Self::Ephemeral(e) => r.ephemeral = Some((**e).clone()),
            Self::Defer => r.outcome = "defer".into(),
            Self::Error(e) => {
                r.outcome = "error".into();
                r.error = Some(e.clone());
            }
        }
        r
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the first response.
    Pending,
    /// A response is being validated.
    Claimed,
    Acked,
    /// No response in time: only `410` from now on.
    Dropped,
}

struct Entry {
    info: Arc<Info>,
    phase: Phase,
    waiter: Option<oneshot::Sender<Ack>>,
    followups: u32,
}

/// A claimed first response: given back with [`Interactions::release`] when it turns out invalid.
pub struct Claim {
    pub info: Arc<Info>,
    /// The holder of the claim lease (shared cache only).
    holder: Option<String>,
}

/// The holder of the claim lease of an interaction nobody answered in time.
const DROPPED: &str = "dropped";

fn state_key(id: &str) -> String {
    format!("interaction-state:{id}")
}

fn claim_key(id: &str) -> String {
    format!("interaction-claim:{id}")
}

fn followups_key(id: &str) -> String {
    format!("interaction-followups:{id}")
}

/// How long the cache keeps an interaction: its lifetime and a minute.
fn shared_ttl() -> Duration {
    Duration::from_secs(LIFETIME_SECS as u64 + 60)
}

/// Live connections of one bot that may receive `command.invoke` (token with the `commands` scope).
#[derive(Default)]
struct BotReceivers {
    /// (connection id, device id), oldest first.
    connections: Vec<(u64, String)>,
    turn: usize,
}

/// Live interactions and the bots' receiving connections.
pub struct Interactions {
    clock: RwLock<Arc<dyn Clock>>,
    entries: Mutex<HashMap<String, Entry>>,
    receivers: Mutex<HashMap<String, BotReceivers>>,
    next_connection: AtomicU64,
    /// Several instances: interactions and receivers are kept in the shared cache as well.
    cluster: Option<Arc<crate::cache::Cluster>>,
    /// Round robin over the other instances holding a receiver.
    remote_turn: AtomicU64,
}

impl Default for Interactions {
    fn default() -> Self {
        Self {
            clock: RwLock::new(Arc::new(SystemClock)),
            entries: Mutex::default(),
            receivers: Mutex::default(),
            next_connection: AtomicU64::new(1),
            cluster: None,
            remote_turn: AtomicU64::new(0),
        }
    }
}

/// Registrations of receivers in the shared cache outlive a crashed instance at most this long (live instances are
/// checked through their heartbeats anyway).
const SHARED_RECEIVER_TTL: Duration = Duration::from_secs(24 * 3600);

fn receivers_key(bot_user_id: &str) -> String {
    format!("cmdrecv:{bot_user_id}")
}

/// Cache key naming the instance that owns a pending interaction.
pub fn owner_key(interaction_id: &str) -> String {
    format!("interaction:{interaction_id}")
}

/// Keeps a bot connection registered as a receiver while it lives.
pub struct ReceiverGuard {
    owner: Arc<Interactions>,
    bot_user_id: String,
    pub id: u64,
}

impl Drop for ReceiverGuard {
    fn drop(&mut self) {
        if let Some(cluster) = &self.owner.cluster
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let (cluster, key) = (cluster.clone(), receivers_key(&self.bot_user_id));
            let field = format!("{}/{}", cluster.instance_id, self.id);
            runtime.spawn(async move {
                let _ = cluster.cache().hash_remove(&cluster.key(&key), &field).await;
            });
        }
        let mut all = self.owner.receivers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = all.get_mut(&self.bot_user_id) {
            r.connections.retain(|(id, _)| *id != self.id);
            if r.connections.is_empty() {
                all.remove(&self.bot_user_id);
            }
        }
    }
}

impl Interactions {
    /// The registry of one instance; with several instances it shares its interactions and receivers through the
    /// cache.
    pub fn new(cluster: &Arc<crate::cache::Cluster>) -> Self {
        Self { cluster: cluster.is_shared().then(|| cluster.clone()), ..Self::default() }
    }

    /// Replaces the clock (tests).
    pub fn set_clock(&self, clock: Arc<dyn Clock>) {
        *self.clock.write().unwrap_or_else(|e| e.into_inner()) = clock;
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a WebSocket connection of a bot (device `device_id`) as a receiver of invocations.
    pub fn register(self: &Arc<Self>, bot_user_id: &str, device_id: &str) -> ReceiverGuard {
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        if let Some(cluster) = &self.cluster
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let (cluster, key) = (cluster.clone(), receivers_key(bot_user_id));
            let field = format!("{}/{id}", cluster.instance_id);
            runtime.spawn(async move {
                let at = crate::cache::now_ms().to_string();
                if let Err(e) = cluster.cache().hash_put(&cluster.key(&key), &field, at, SHARED_RECEIVER_TTL).await {
                    tracing::warn!(error = %e, "command receiver not registered in the cache (reached on this instance only)");
                }
            });
        }
        let mut all = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        all.entry(bot_user_id.to_string()).or_default().connections.push((id, device_id.to_string()));
        ReceiverGuard { owner: self.clone(), bot_user_id: bot_user_id.to_string(), id }
    }

    /// Another live instance holding a receiving connection of the bot (round robin), from the shared registry.
    pub async fn remote_receiver(&self, bot_user_id: &str) -> Option<String> {
        let cluster = self.cluster.as_ref()?;
        let all = cluster.cache().hash_all(&cluster.key(&receivers_key(bot_user_id))).await.ok()?;
        let live: std::collections::HashSet<String> = cluster.peers().into_iter().collect();
        let mut instances: Vec<String> = all
            .keys()
            .filter_map(|f| f.split_once('/').map(|(i, _)| i.to_string()))
            .filter(|i| live.contains(i))
            .collect();
        instances.sort();
        instances.dedup();
        if instances.is_empty() {
            return None;
        }
        let turn = self.remote_turn.fetch_add(1, Ordering::Relaxed) as usize;
        Some(instances[turn % instances.len()].clone())
    }

    /// The interaction is pending in this instance's memory.
    pub fn contains(&self, id: &str) -> bool {
        self.entries().contains_key(id)
    }

    /// The connection that gets the next invocation for a bot: round robin over its devices (in the order
    /// they connected), the newest connection of the chosen device.
    pub fn pick(&self, bot_user_id: &str) -> Option<u64> {
        let mut all = self.receivers.lock().unwrap_or_else(|e| e.into_inner());
        let r = all.get_mut(bot_user_id)?;
        let mut devices: Vec<&str> = Vec::new();
        for (_, d) in &r.connections {
            if !devices.contains(&d.as_str()) {
                devices.push(d);
            }
        }
        if devices.is_empty() {
            return None;
        }
        let device = devices[r.turn % devices.len()].to_string();
        r.turn = r.turn.wrapping_add(1);
        r.connections.iter().rev().find(|(_, d)| *d == device).map(|(id, _)| *id)
    }

    /// Open receiving connections of a bot (tests, diagnostics).
    pub fn receivers(&self, bot_user_id: &str) -> usize {
        self.receivers.lock().unwrap_or_else(|e| e.into_inner()).get(bot_user_id).map_or(0, |r| r.connections.len())
    }

    /// Live (not yet swept) interactions in this instance's memory.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds an interaction (with a shared cache also there); its first response arrives on the returned receiver.
    async fn create(&self, info: Info) -> Result<oneshot::Receiver<Ack>, ApiError> {
        let now = self.clock().now();
        if let Some(cluster) = &self.cluster {
            cluster.put_sealed(&state_key(&info.id), &info, shared_ttl()).await.map_err(crate::cache::unavailable)?;
        }
        let mut entries = self.entries();
        if entries.len() > 256 {
            entries.retain(|_, e| e.info.expires_at > now);
        }
        if entries.len() >= MAX_LIVE {
            return Err(ApiError::Unavailable { code: "interaction.busy", detail: "Too many interactions".into() });
        }
        let (tx, rx) = oneshot::channel();
        let id = info.id.clone();
        entries.insert(id, Entry { info: Arc::new(info), phase: Phase::Pending, waiter: Some(tx), followups: 0 });
        Ok(rx)
    }

    /// The facts of interaction `id` for the bot `bot_user_id`, from memory or the shared cache:
    /// `404 interaction.not_found`, `403 interaction.not_owner`.
    async fn info(&self, id: &str, bot_user_id: &str) -> Result<Arc<Info>, ApiError> {
        let local = self.entries().get(id).map(|e| e.info.clone());
        let info = match (local, &self.cluster) {
            (Some(info), _) => info,
            (None, Some(cluster)) if util::is_ulid(id) => Arc::new(
                cluster
                    .get_sealed::<Info>(&state_key(id))
                    .await
                    .map_err(crate::cache::unavailable)?
                    .filter(|i| i.id == id)
                    .ok_or_else(not_found)?,
            ),
            _ => return Err(not_found()),
        };
        if info.bot_user_id != bot_user_id {
            return Err(not_owner());
        }
        Ok(info)
    }

    /// Claims the first response (`409 interaction.already_acked`, `410 interaction.expired`).
    pub async fn claim(&self, id: &str, bot_user_id: &str) -> Result<Claim, ApiError> {
        let now = self.clock().now();
        let Some(cluster) = &self.cluster else {
            let mut entries = self.entries();
            let entry = entries.get_mut(id).ok_or_else(not_found)?;
            if entry.info.bot_user_id != bot_user_id {
                return Err(not_owner());
            }
            return match entry.phase {
                Phase::Acked | Phase::Claimed => Err(already_acked()),
                Phase::Dropped => Err(expired()),
                Phase::Pending if now > entry.info.ack_deadline => {
                    entry.phase = Phase::Dropped;
                    entry.waiter = None;
                    Err(expired())
                }
                Phase::Pending => {
                    entry.phase = Phase::Claimed;
                    Ok(Claim { info: entry.info.clone(), holder: None })
                }
            };
        };
        let info = self.info(id, bot_user_id).await?;
        let key = cluster.key(&claim_key(id));
        let holder = util::ulid();
        if now > info.ack_deadline {
            // Nobody answered in time: the claim lease says so for every instance.
            let _ = cluster.cache().lease(&key, DROPPED, shared_ttl()).await;
            return Err(match cluster.cache().get(&key).await.ok().flatten().as_deref() {
                Some(DROPPED) | None => expired(),
                Some(_) => already_acked(),
            });
        }
        if !cluster.cache().lease(&key, &holder, shared_ttl()).await.map_err(crate::cache::unavailable)? {
            return Err(match cluster.cache().get(&key).await.ok().flatten().as_deref() {
                Some(DROPPED) => expired(),
                _ => already_acked(),
            });
        }
        Ok(Claim { info, holder: Some(holder) })
    }

    /// A claimed response was invalid: the interaction waits again (or is dropped after its deadline).
    pub async fn release(&self, claim: &Claim) {
        let id = claim.info.id.as_str();
        if let (Some(cluster), Some(holder)) = (&self.cluster, &claim.holder) {
            let _ = cluster.cache().release(&cluster.key(&claim_key(id)), holder).await;
            return;
        }
        let now = self.clock().now();
        if let Some(entry) = self.entries().get_mut(id)
            && entry.phase == Phase::Claimed
        {
            if now > entry.info.ack_deadline {
                entry.phase = Phase::Dropped;
                entry.waiter = None;
            } else {
                entry.phase = Phase::Pending;
            }
        }
    }

    /// The claimed response was accepted: the invoker gets it (when it waits on this instance). With a shared cache
    /// the claim lease stays until the interaction expires and keeps every later response out.
    pub fn complete(&self, id: &str, ack: Ack) {
        if let Some(entry) = self.entries().get_mut(id) {
            entry.phase = Phase::Acked;
            if let Some(tx) = entry.waiter.take() {
                let _ = tx.send(ack);
            }
        }
    }

    /// The deadline passed: drops a pending interaction (`true`); a claimed one keeps waiting (`false`).
    async fn timeout(&self, id: &str) -> bool {
        if let Some(cluster) = &self.cluster {
            let key = cluster.key(&claim_key(id));
            if cluster.cache().lease(&key, DROPPED, shared_ttl()).await.unwrap_or(true) {
                if let Some(entry) = self.entries().get_mut(id) {
                    entry.phase = Phase::Dropped;
                    entry.waiter = None;
                }
                return true;
            }
            // Claimed (or answered) somewhere: the response may still come within the grace.
            return matches!(cluster.cache().get(&key).await.ok().flatten().as_deref(), Some(DROPPED));
        }
        match self.entries().get_mut(id) {
            Some(entry) if entry.phase == Phase::Pending => {
                entry.phase = Phase::Dropped;
                entry.waiter = None;
                true
            }
            Some(entry) => entry.phase == Phase::Dropped,
            None => true,
        }
    }

    /// A follow-up may be sent: the interaction is the bot's and neither expired nor dropped
    /// (`404 interaction.not_found`, `403 interaction.not_owner`, `410 interaction.expired`). The place among the
    /// ten is taken with [`Interactions::take_followup`] once the follow-up passed its checks.
    pub async fn followup_allowed(&self, id: &str, bot_user_id: &str) -> Result<Arc<Info>, ApiError> {
        let now = self.clock().now();
        let info = self.info(id, bot_user_id).await?;
        if now > info.expires_at {
            return Err(expired());
        }
        let dropped = match &self.cluster {
            Some(cluster) => {
                let claim =
                    cluster.cache().get(&cluster.key(&claim_key(id))).await.map_err(crate::cache::unavailable)?;
                claim.as_deref() == Some(DROPPED) || (claim.is_none() && now > info.ack_deadline)
            }
            None => self.entries().get(id).is_none_or(|e| e.phase == Phase::Dropped),
        };
        if dropped {
            return Err(expired());
        }
        Ok(info)
    }

    /// Takes one of the ten follow-up places (`409 interaction.followup_limit`).
    pub async fn take_followup(&self, id: &str) -> Result<(), ApiError> {
        let limit = || ApiError::Conflict {
            code: "interaction.followup_limit",
            detail: format!("At most {MAX_FOLLOWUPS} follow-ups per interaction"),
            meta: json!({ "max": MAX_FOLLOWUPS }),
        };
        if let Some(cluster) = &self.cluster {
            let (n, _) = cluster
                .cache()
                .hit(&cluster.key(&followups_key(id)), shared_ttl())
                .await
                .map_err(crate::cache::unavailable)?;
            return if n > u64::from(MAX_FOLLOWUPS) { Err(limit()) } else { Ok(()) };
        }
        let mut entries = self.entries();
        let entry = entries.get_mut(id).ok_or_else(expired)?;
        if entry.followups >= MAX_FOLLOWUPS {
            return Err(limit());
        }
        entry.followups += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------- invoking (§5.5, §5.6)

/// The first language tag of `Accept-Language` (`en` without one).
pub fn locale(accept_language: Option<&str>) -> String {
    let first =
        accept_language.and_then(|v| v.split(',').next()).and_then(|t| t.split(';').next()).unwrap_or("").trim();
    if first.is_empty()
        || first.len() > 35
        || first == "*"
        || !first.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        "en".into()
    } else {
        first.to_string()
    }
}

/// Where an invocation goes.
enum Delivery {
    Url(reqwest::Url),
    Connection(u64),
    /// A connection on another instance (several instances, docs/SCALING.md).
    Instance(String),
}

/// A bus message [`crate::cache::Message::Invoke`] for this instance: delivers the invocation to one local
/// receiving connection of the bot. Without one (it closed meanwhile) nothing happens and the owner times out.
pub fn deliver_from_bus(state: &AppState, bot_user_id: &str, data: &str) {
    let Ok(data) = serde_json::from_str::<Value>(data) else { return };
    match state.interactions.pick(bot_user_id) {
        Some(connection) => {
            state.hub.publish("command.invoke", Scope::Connection(connection), &data);
        }
        None => tracing::info!(bot = bot_user_id, "invocation from another instance: the bot's connection is gone"),
    }
}

/// `POST /conversations/{conversation_id}/interactions`: checks 1–7 in order, delivery, wait for the first
/// response.
pub async fn invoke(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    req: InvokeRequest,
    accept_language: Option<&str>,
) -> Result<InvokeResponse, ApiError> {
    // 1.–5.
    let Target { offer, row, def } = commands::resolve_invocation(state, auth, conv, &req.command).await?;
    // 6. 5 interactions per 5 seconds and invoking user.
    state.interaction_limiter.check_all(&[format!("interaction:{}", auth.user.id)])?;
    // 7. the arguments in the conversation's mode.
    let (args, args_ciphertext, epoch) = if conv.encrypted {
        if req.args.as_ref().is_some_and(|a| !a.is_null()) {
            return Err(mismatch("This conversation is encrypted: send args_ciphertext, not args"));
        }
        let ct = req.args_ciphertext.as_deref().unwrap_or("");
        if ct.is_empty() || ct.len() > commands::MAX_ARGS_CIPHERTEXT {
            return Err(ApiError::BadRequest {
                code: "interaction.ciphertext_invalid",
                detail: "args_ciphertext: the encrypted command.args content".into(),
            });
        }
        let v = msgs::validate_content(&[], true, &Value::String(ct.to_string()), &[]).map_err(as_interaction_error)?;
        let epoch =
            msgs::check_ciphertext(state, auth, &conv.id, &v.content, req.epoch).await.map_err(as_interaction_error)?;
        (Value::Null, Some(v.content), Some(epoch))
    } else {
        if req.args_ciphertext.is_some() || req.epoch.is_some() {
            return Err(mismatch("This conversation is not encrypted: send args, not args_ciphertext"));
        }
        (commands::validate_args(&def, req.args.as_ref())?, None, None)
    };

    // A thread of the channel (PROTOCOL.md §7e): the invoker must be able to write there, answers go there.
    let thread = match &req.thread_id {
        Some(t) => {
            let row = crate::threads::of_conversation(state, conv, t).await?;
            crate::threads::check_write(conv, Some(&row))?;
            Some(row.id)
        }
        None => None,
    };
    // Delivery: the interactions URL of a local application, else one WebSocket connection of the bot.
    let url =
        offer.local.as_ref().and_then(|a| a.interactions_url.as_deref()).and_then(|u| state.hooks.check_url(u).ok());
    let delivery = match url {
        Some(u) => Delivery::Url(u),
        None => match state.interactions.pick(&offer.bot.id) {
            Some(connection) => Delivery::Connection(connection),
            None => Delivery::Instance(state.interactions.remote_receiver(&offer.bot.id).await.ok_or_else(offline)?),
        },
    };

    let clock = state.interactions.clock();
    let now = clock.now();
    let (room_id, channel_id) = match &conv.kind {
        ConvKind::Channel { access, channel } => (Some(access.room.id.clone()), Some(channel.id.clone())),
        ConvKind::Direct { .. } => (None, None),
    };
    let info = Info {
        id: util::ulid(),
        application_ref: offer.reference.clone(),
        application_name: offer.name.clone(),
        bot_user_id: offer.bot.id.clone(),
        bot_address: offer.bot.address(),
        local_application_id: offer.local.as_ref().map(|a| a.id.clone()),
        command_id: row.id.clone(),
        command_name: def.name.clone(),
        conversation_id: conv.id.clone(),
        thread_id: thread,
        encrypted: conv.encrypted,
        user_id: auth.user.id.clone(),
        user_address: auth.user.address(),
        user_device: auth.device_id.clone(),
        ack_deadline: now + chrono::Duration::seconds(ACK_TIMEOUT_SECS),
        expires_at: now + chrono::Duration::seconds(LIFETIME_SECS),
    };
    let data = json!({
        "interaction_id": info.id,
        "application_id": offer.local.as_ref().map_or_else(|| offer.reference.rsplit('/').next().unwrap_or("").to_string(), |a| a.id.clone()),
        "command": { "id": row.id, "name": def.name },
        "conversation_id": conv.id, "room_id": room_id, "channel_id": channel_id, "thread_id": info.thread_id,
        "encrypted": conv.encrypted,
        "user": info.user_address, "user_id": auth.user.id, "device_id": auth.public_device_id(),
        "permissions": conv.perms.to_string(),
        "args": if conv.encrypted { Value::Null } else { args },
        "args_ciphertext": args_ciphertext, "epoch": epoch,
        "locale": locale(accept_language), "expires_at": util::format_time(info.expires_at),
    });
    let id = info.id.clone();
    let deadline = info.ack_deadline;
    let started = std::time::Instant::now();
    let mut rx = state.interactions.create(info).await?;
    // Several instances: callbacks and follow-ups may reach any instance; they find this one through the cache.
    if state.cluster.is_shared() {
        let ttl = Duration::from_secs(LIFETIME_SECS as u64 + 60);
        if let Err(e) =
            state.cluster.cache().put(&state.cluster.key(&owner_key(&id)), state.cluster.instance_id.clone(), ttl).await
        {
            tracing::warn!(error = %e, "interaction owner not recorded (callbacks through other instances fail)");
        }
    }

    let result = match delivery {
        Delivery::Connection(connection) => {
            state.hub.publish("command.invoke", Scope::Connection(connection), &data);
            wait(state, &id, &mut rx, clock.sleep_until(deadline)).await
        }
        Delivery::Instance(instance) => {
            state.cluster.send(crate::cache::Message::Invoke {
                instance,
                bot: offer.bot.id.clone(),
                data: data.to_string(),
            });
            wait(state, &id, &mut rx, clock.sleep_until(deadline)).await
        }
        Delivery::Url(url) => {
            let body =
                json!({ "type": "command.invoke", "id": id, "at": util::format_time(now), "data": data }).to_string();
            let app_id = offer.local.as_ref().map(|a| a.id.clone()).unwrap_or_default();
            let send = crate::hooks::send(
                state,
                &app_id,
                &url,
                "command.invoke",
                &id,
                body.into_bytes(),
                crate::hooks::INVOKE_TIMEOUT,
            );
            tokio::select! {
                answer = send => {
                    match answer {
                        Ok(r) => url_answer(state, &id, &offer.bot.id, &r.body).await,
                        Err(e) => tracing::info!(interaction = id, error = e.label(), "interactions URL failed"),
                    }
                    wait(state, &id, &mut rx, std::future::ready(())).await
                }
                () = clock.sleep_until(deadline) => wait(state, &id, &mut rx, std::future::ready(())).await,
            }
        }
    };
    let outcome = match &result {
        Ok(Ack::Reply(_) | Ack::Ephemeral(_)) => "reply",
        Ok(Ack::Defer) => "defer",
        Ok(Ack::Error(_)) => "error",
        Err(_) => "no_ack",
    };
    tracing::info!(
        application = offer.reference,
        command = def.name,
        conversation = conv.id,
        outcome,
        latency_ms = started.elapsed().as_millis() as u64,
        "interaction"
    );
    Ok(result?.response(&id))
}

/// Waits for the first response until `deadline` resolves; a response being validated gets a short grace.
async fn wait(
    state: &AppState,
    id: &str,
    rx: &mut oneshot::Receiver<Ack>,
    deadline: impl std::future::Future<Output = ()>,
) -> Result<Ack, ApiError> {
    tokio::select! {
        biased;
        ack = &mut *rx => return ack.map_err(|_| no_ack()),
        () = deadline => {}
    }
    if state.interactions.timeout(id).await {
        return Err(no_ack());
    }
    match tokio::time::timeout(CLAIM_GRACE, rx).await {
        Ok(Ok(ack)) => Ok(ack),
        _ => Err(no_ack()),
    }
}

/// The interactions URL's answer is the callback (§5.6); an invalid answer leaves the interaction unanswered.
async fn url_answer(state: &AppState, id: &str, bot_user_id: &str, body: &[u8]) {
    let Ok(callback) = serde_json::from_slice::<Callback>(body) else {
        tracing::info!(interaction = id, "interactions URL answered with an invalid body");
        return;
    };
    let Ok(Some(bot)) = store::users::by_id(&state.db, bot_user_id).await else { return };
    let auth = match url_principal(state, &bot, callback.device_id.as_deref()).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(interaction = id, error = e.code(), "interactions URL answer refused");
            return;
        }
    };
    if let Err(e) = respond(state, &auth, id, callback).await {
        tracing::info!(interaction = id, error = e.code(), "interactions URL answer refused");
    }
}

/// The bot as the author of an interactions URL answer: its application's scopes, the named device (which must
/// be one of the bot's devices) or none.
async fn url_principal(
    state: &AppState,
    bot: &crate::models::UserRow,
    device_id: Option<&str>,
) -> Result<AuthUser, ApiError> {
    let app = store::applications::by_bot(&state.db, &bot.id).await?.ok_or_else(apps::not_found)?;
    let device = match device_id {
        Some(d) => {
            let devices = store::users::devices_of(&state.db, &bot.id).await?;
            if !devices.iter().any(|x| x.id == d) {
                return Err(ApiError::BadRequest {
                    code: "interaction.device_invalid",
                    detail: "device_id is not a device of the bot".into(),
                });
            }
            d.to_string()
        }
        None => String::new(),
    };
    let scopes = app.scopes();
    let mut user = bot.clone();
    user.app_scopes = Some(scopes.clone());
    Ok(AuthUser {
        user,
        device_id: device,
        home_device_id: None,
        app: Some(AppPrincipal {
            application_id: app.id,
            token_id: None,
            scopes,
            expires_at: None,
            lifetime_secs: None,
        }),
    })
}

// ---------------------------------------------------------------- responses (§5.7)

/// `POST /interactions/{id}/callback` (and the URL answer): the first response of the application.
pub async fn respond(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    callback: Callback,
) -> Result<InvokeResponse, ApiError> {
    let claim = state.interactions.claim(id, &auth.user.id).await?;
    let info = claim.info.clone();
    match acknowledge(state, auth, &info, callback).await {
        Ok(ack) => {
            if let Ack::Ephemeral(reply) = &ack {
                // The invoking connection gets it in the invocation response, the invoker's other ones here.
                state.hub.users_except_device(
                    vec![info.user_id.clone()],
                    &info.user_device,
                    "interaction.reply",
                    reply,
                );
            }
            let response = ack.response(id);
            state.interactions.complete(id, ack);
            Ok(response)
        }
        Err(e) => {
            state.interactions.release(&claim).await;
            Err(e)
        }
    }
}

async fn acknowledge(state: &AppState, auth: &AuthUser, info: &Info, callback: Callback) -> Result<Ack, ApiError> {
    match callback.kind.as_str() {
        "defer" => Ok(Ack::Defer),
        "error" => {
            let text = callback.message.as_deref().unwrap_or("").trim().to_string();
            let n = text.chars().count();
            if n == 0 || n > ERROR_MAX_CHARS || text.chars().any(char::is_control) {
                return Err(ApiError::BadRequest {
                    code: "validation.message",
                    detail: format!("message: 1 to {ERROR_MAX_CHARS} characters of plain text"),
                });
            }
            Ok(Ack::Error(text))
        }
        "reply" => {
            let content = callback.content.ok_or_else(|| ApiError::BadRequest {
                code: "message.content_invalid",
                detail: "A reply needs content".into(),
            })?;
            answer(
                state,
                auth,
                info,
                Answer {
                    content,
                    epoch: callback.epoch,
                    device_id: callback.device_id.as_deref(),
                    ephemeral: callback.ephemeral,
                    mentions: &callback.mentions,
                    thread_id: callback.thread_id.as_deref(),
                    followup: false,
                },
            )
            .await
        }
        _ => Err(ApiError::BadRequest { code: "validation.type", detail: "type: reply, defer or error".into() }),
    }
}

/// What a reply or follow-up carries.
struct Answer<'a> {
    content: Value,
    epoch: Option<i64>,
    device_id: Option<&'a str>,
    ephemeral: bool,
    mentions: &'a [String],
    /// A thread of the conversation; the interaction's thread when absent.
    thread_id: Option<&'a str>,
    /// A follow-up takes one of its ten places once every check passed.
    followup: bool,
}

/// A reply or follow-up: a message of the bot with the envelope field `interaction` (in the interaction's thread
/// unless it names another one), or an ephemeral reply.
async fn answer(state: &AppState, auth: &AuthUser, info: &Info, a: Answer<'_>) -> Result<Ack, ApiError> {
    let Answer { content, epoch, device_id, ephemeral, mentions, thread_id, followup } = a;
    // A token's (or federated session's) device is fixed; an interactions URL answer named its device already.
    if let Some(d) = device_id
        && !auth.device_id.is_empty()
        && d != auth.public_device_id()
    {
        return Err(ApiError::BadRequest {
            code: "interaction.device_invalid",
            detail: "device_id must be the token's device".into(),
        });
    }
    let conv = access::conversation(state, &info.conversation_id, &auth.user).await?;
    if let ConvKind::Channel { access, .. } = &conv.kind
        && access.member.is_none()
    {
        return Err(ApiError::Forbidden { code: "room.not_member", detail: "The bot is not a member here".into() });
    }
    conv.require(p::VIEW_CHANNEL | p::SEND_MESSAGES, "message.send_forbidden", "Send messages")?;
    let thread = match thread_id.or(info.thread_id.as_deref()) {
        Some(t) => {
            let row = crate::threads::of_conversation(state, &conv, t).await?;
            crate::threads::check_write(&conv, Some(&row))?;
            Some(row)
        }
        None => None,
    };
    let v = msgs::validate_content(msgs::gif_hosts(state), conv.encrypted, &content, mentions)
        .map_err(as_interaction_error)?;
    // A plaintext poll as an answer needs `create_polls` like any poll the node can see (PROTOCOL.md §7g).
    if !conv.encrypted && content.get("type").and_then(Value::as_str) == Some(crate::polls::POLL_TYPE) {
        conv.require(p::CREATE_POLLS, "message.poll_forbidden", "Create polls")?;
    }
    if conv.encrypted && auth.device_id.is_empty() {
        return Err(ApiError::BadRequest {
            code: "interaction.device_invalid",
            detail: "Encrypted content needs the device that encrypted it".into(),
        });
    }
    let epoch = if conv.encrypted {
        Some(msgs::check_ciphertext(state, auth, &conv.id, &v.content, epoch).await.map_err(as_interaction_error)?)
    } else {
        None
    };
    let device = (!auth.device_id.is_empty()).then(|| auth.public_device_id().to_string());
    if !ephemeral {
        state.bot_message_limiter.check_all(&[format!("bot-msg:{}:{}", auth.user.id, conv.id)])?;
    }
    if followup {
        state.interactions.take_followup(&info.id).await?;
    }
    if ephemeral {
        let stored: Value = if conv.encrypted { Value::String(v.content.clone()) } else { content };
        return Ok(Ack::Ephemeral(Box::new(EphemeralReply {
            interaction_id: info.id.clone(),
            conversation_id: info.conversation_id.clone(),
            thread_id: thread.as_ref().map(|t| t.id.clone()),
            application: info.application(),
            device_id: device,
            content: stored,
            epoch,
            created_at: util::now(),
        })));
    }
    let id = util::ulid();
    store::messages::insert(
        &state.db,
        store::messages::NewMessage {
            id: &id,
            conversation_id: &conv.id,
            author_id: &auth.user.id,
            device_id: device.as_deref(),
            encrypted: conv.encrypted,
            format: 1,
            epoch,
            content: &v.content,
            reply_to_id: None,
            thread_id: thread.as_ref().map(|t| t.id.as_str()),
            mentions: &v.mentions,
            mentions_everyone: false,
            signature: None,
        },
    )
    .await?;
    let envelope = serde_json::to_string(&info.envelope()).map_err(|e| ApiError::Internal(e.into()))?;
    store::messages::set_interaction(&state.db, &id, &envelope).await?;
    let message = msgs::enrich_one(state, &auth.user.id, &id).await?;
    if let Some(t) = &thread {
        crate::threads::after_message(state, &t.id, &message).await?;
    }
    conv.publish_recorded(state, "message.create", &message).await;
    crate::federation::social::notify_members(state, &conv, &message, &auth.user.id).await;
    Ok(Ack::Reply(Box::new(message)))
}

/// `POST /interactions/{id}/messages`: a follow-up until the interaction expires, at most 10.
pub async fn follow_up(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    req: FollowUp,
) -> Result<FollowUpResponse, ApiError> {
    let info = state.interactions.followup_allowed(id, &auth.user.id).await?;
    let a = Answer {
        content: req.content,
        epoch: req.epoch,
        device_id: req.device_id.as_deref(),
        ephemeral: req.ephemeral,
        mentions: &req.mentions,
        thread_id: req.thread_id.as_deref(),
        followup: true,
    };
    match answer(state, auth, &info, a).await {
        Ok(Ack::Ephemeral(reply)) => {
            state.hub.users(vec![info.user_id.clone()], "interaction.reply", &reply);
            Ok(FollowUpResponse { message: None, ephemeral: Some(*reply) })
        }
        Ok(Ack::Reply(message)) => Ok(FollowUpResponse { message: Some(*message), ephemeral: None }),
        Ok(_) => Ok(FollowUpResponse { message: None, ephemeral: None }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn info(id: &str, bot: &str, now: DateTime<Utc>) -> Info {
        Info {
            id: id.into(),
            application_ref: "a.test/X".into(),
            application_name: "App".into(),
            bot_user_id: bot.into(),
            bot_address: "bot@a.test".into(),
            local_application_id: None,
            command_id: "C".into(),
            command_name: "weather".into(),
            conversation_id: "conv".into(),
            thread_id: None,
            encrypted: false,
            user_id: "u".into(),
            user_address: "u@a.test".into(),
            user_device: "d".into(),
            ack_deadline: now + chrono::Duration::seconds(ACK_TIMEOUT_SECS),
            expires_at: now + chrono::Duration::seconds(LIFETIME_SECS),
        }
    }

    #[test]
    fn locales() {
        assert_eq!(locale(Some("de-DE,de;q=0.9,en;q=0.8")), "de-DE");
        assert_eq!(locale(Some("fr;q=0.5")), "fr");
        assert_eq!(locale(None), "en");
        assert_eq!(locale(Some("*")), "en");
        assert_eq!(locale(Some("<script>")), "en");
    }

    #[test]
    fn round_robin_over_devices_newest_connection() {
        let i = Arc::new(Interactions::default());
        assert_eq!(i.pick("bot"), None);
        let a1 = i.register("bot", "devA");
        let b1 = i.register("bot", "devB");
        let a2 = i.register("bot", "devA");
        let picks: Vec<u64> = (0..4).map(|_| i.pick("bot").unwrap()).collect();
        assert_eq!(picks, vec![a2.id, b1.id, a2.id, b1.id], "devices alternate, the newest connection of a device");
        drop(a2);
        assert_eq!(i.pick("bot"), Some(a1.id));
        drop((a1, b1));
        assert_eq!(i.pick("bot"), None);
        assert_eq!(i.receivers("bot"), 0);
    }

    #[tokio::test]
    async fn first_response_counts_and_deadlines_follow_the_clock() {
        let start = Utc::now();
        let clock = Arc::new(ManualClock::new(start));
        let i = Interactions::default();
        i.set_clock(clock.clone());
        let mut rx = i.create(info("i1", "bot", start)).await.unwrap();
        assert_eq!(i.claim("i1", "other").await.err().unwrap().code(), "interaction.not_owner");
        assert_eq!(i.claim("nope", "bot").await.err().unwrap().code(), "interaction.not_found");
        let claim = i.claim("i1", "bot").await.unwrap();
        assert_eq!(i.claim("i1", "bot").await.err().unwrap().code(), "interaction.already_acked", "claimed");
        i.release(&claim).await;
        i.claim("i1", "bot").await.unwrap();
        i.complete("i1", Ack::Defer);
        assert!(matches!(rx.try_recv().unwrap(), Ack::Defer));
        assert_eq!(i.claim("i1", "bot").await.err().unwrap().code(), "interaction.already_acked");

        // No response before the deadline: dropped, 410 afterwards.
        let _rx2 = i.create(info("i2", "bot", start)).await.unwrap();
        let sleeper = clock.sleep_until(start + chrono::Duration::seconds(ACK_TIMEOUT_SECS));
        clock.advance(chrono::Duration::seconds(ACK_TIMEOUT_SECS) + chrono::Duration::milliseconds(1));
        tokio::time::timeout(Duration::from_secs(1), sleeper).await.unwrap();
        assert_eq!(i.claim("i2", "bot").await.err().unwrap().code(), "interaction.expired");
        assert_eq!(i.followup_allowed("i2", "bot").await.unwrap_err().code(), "interaction.expired");

        // Follow-ups: at most ten, until the interaction expires.
        for _ in 0..MAX_FOLLOWUPS {
            i.followup_allowed("i1", "bot").await.unwrap();
            i.take_followup("i1").await.unwrap();
        }
        assert_eq!(i.take_followup("i1").await.unwrap_err().code(), "interaction.followup_limit");
        clock.advance(chrono::Duration::seconds(LIFETIME_SECS));
        assert_eq!(i.followup_allowed("i1", "bot").await.unwrap_err().code(), "interaction.expired");
    }

    fn shared(cache: &Arc<crate::cache::memory::InProcess>, instance: &str) -> Arc<crate::cache::Cluster> {
        let cache: Arc<dyn crate::cache::Cache> = cache.clone();
        Arc::new(crate::cache::Cluster::shared_with("a.test", instance, cache, &[7u8; 32], "http://127.0.0.1:1"))
    }

    use crate::cache::Cache as _;

    /// With a shared cache a pending interaction survives its instance (tavrn-node #14): a restarted or another
    /// instance takes the callback and the follow-ups, and the first response still counts once.
    #[tokio::test]
    async fn interactions_in_the_shared_cache_survive_a_restart() {
        let start = Utc::now();
        let clock = Arc::new(ManualClock::new(start));
        let cache = Arc::new(crate::cache::memory::InProcess::default());
        let before = Interactions::new(&shared(&cache, "one"));
        before.set_clock(clock.clone());
        let mut with_thread = info(&util::ulid(), "bot", start);
        with_thread.thread_id = Some("T".into());
        let id = with_thread.id.clone();
        let _rx = before.create(with_thread).await.unwrap();
        drop(before);

        // "Restart": a new registry on the same cache knows the interaction, sealed in the cache.
        let after = Interactions::new(&shared(&cache, "one"));
        after.set_clock(clock.clone());
        assert!(!after.contains(&id), "not in the new instance's memory");
        assert_eq!(after.claim(&id, "other").await.err().unwrap().code(), "interaction.not_owner");
        assert_eq!(after.claim(&util::ulid(), "bot").await.err().unwrap().code(), "interaction.not_found");
        let claim = after.claim(&id, "bot").await.unwrap();
        assert_eq!(claim.info.thread_id.as_deref(), Some("T"));
        // A second instance sees the claim; given back, it may claim itself; answered, nobody else.
        let other = Interactions::new(&shared(&cache, "two"));
        other.set_clock(clock.clone());
        assert_eq!(other.claim(&id, "bot").await.err().unwrap().code(), "interaction.already_acked");
        after.release(&claim).await;
        let claim = other.claim(&id, "bot").await.unwrap();
        other.complete(&id, Ack::Defer);
        assert_eq!(after.claim(&id, "bot").await.err().unwrap().code(), "interaction.already_acked");
        drop(claim);

        // Follow-ups from any instance share the ten places.
        for n in 0..MAX_FOLLOWUPS {
            let registry = if n % 2 == 0 { &after } else { &other };
            registry.followup_allowed(&id, "bot").await.unwrap();
            registry.take_followup(&id).await.unwrap();
        }
        assert_eq!(after.take_followup(&id).await.unwrap_err().code(), "interaction.followup_limit");
        clock.advance(chrono::Duration::seconds(LIFETIME_SECS + 1));
        assert_eq!(other.followup_allowed(&id, "bot").await.unwrap_err().code(), "interaction.expired");

        // Unanswered past the deadline: dropped for every instance, follow-ups refused.
        let late = info(&util::ulid(), "bot", clock.now());
        let late_id = late.id.clone();
        let _rx = after.create(late).await.unwrap();
        clock.advance(chrono::Duration::seconds(ACK_TIMEOUT_SECS + 1));
        assert!(after.timeout(&late_id).await, "nobody claimed it");
        assert_eq!(other.claim(&late_id, "bot").await.err().unwrap().code(), "interaction.expired");
        assert_eq!(other.followup_allowed(&late_id, "bot").await.unwrap_err().code(), "interaction.expired");

        // The cache holds the facts sealed: no plaintext of the interaction in it.
        let raw = cache.get(&shared(&cache, "x").key(&state_key(&id))).await.unwrap().unwrap();
        assert!(!raw.contains("weather") && !raw.contains("u@a.test"), "{raw}");
    }
}
