// SPDX-License-Identifier: AGPL-3.0-only
//! Several instances of one node (`TAVRN_CACHE_URL`, `docs/SCALING.md`).
//!
//! A node normally runs as one process and keeps short-lived state in memory. With `TAVRN_CACHE_URL` several
//! `tavrn-node serve` processes share one PostgreSQL and one Valkey (or Redis) and behave as one logical node:
//!
//! - [`Cache`] is the small interface over the shared store: fixed-window counters, single-use values, leases,
//!   hashes and a pub/sub bus. [`memory::InProcess`] implements it in this process (the default, and two
//!   `AppState`s sharing one in tests), [`valkey::Valkey`] over Valkey/Redis.
//! - [`Cluster`] is what the rest of the node sees (`AppState::cluster`): the instance id, the bus
//!   ([`Message`]), the leader lease ([`leader`]) and sealed single-use values. Without a cache URL it is
//!   "standalone": always the leader, the bus is never used, and every caller keeps its in-memory path.
//! - Events of the hub, presence, wakeups of the leader's workers, WebSocket limits of app tokens and voice side
//!   effects travel over the bus; the state of voice, calls and whiteboards lives on the leader, other
//!   instances relay those requests to it ([`relay`]).

pub mod leader;
pub mod limiter;
pub mod memory;
pub mod relay;
pub mod valkey;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{StreamExt, future::BoxFuture, stream::BoxStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::{Notify, mpsc};
use zeroize::Zeroizing;

use crate::{app::AppState, config::Config, hub};

/// Instances send a heartbeat this often.
pub const HEARTBEAT: Duration = Duration::from_secs(5);
/// An instance not heard from for this long is gone: its connections no longer count.
pub const PEER_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest wait between two attempts to subscribe to the bus again.
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// After a failed publish, further publishes are dropped (and counted as lost) for this long.
const PUBLISH_PAUSE: Duration = Duration::from_secs(1);
/// Messages waiting for the bus forwarder; beyond, new ones are dropped and counted as lost (the other instances'
/// clients resync), so a slow cache never lets the queue grow without bound.
pub const BUS_QUEUE: usize = 16_384;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct CacheError(pub String);

pub type CacheResult<T> = Result<T, CacheError>;

/// The shared store. Keys are full keys (the [`Cluster`] prefixes them with `tavrn:<domain>:`).
pub trait Cache: Send + Sync + 'static {
    fn ping(&self) -> BoxFuture<'_, CacheResult<()>>;
    /// Counts a hit on `key` in a fixed window that starts with the first hit: `(hits so far, time left)`.
    fn hit(&self, key: &str, window: Duration) -> BoxFuture<'_, CacheResult<(u64, Duration)>>;
    fn put(&self, key: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>>;
    fn get(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>>;
    /// Reads and deletes in one step: of several concurrent takers exactly one gets the value.
    fn take(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>>;
    fn delete(&self, key: &str) -> BoxFuture<'_, CacheResult<()>>;
    /// Acquires the lease `key` for `holder` if it is free, or renews it if `holder` has it: `true` if held now.
    fn lease(&self, key: &str, holder: &str, ttl: Duration) -> BoxFuture<'_, CacheResult<bool>>;
    /// Gives the lease up if `holder` has it.
    fn release(&self, key: &str, holder: &str) -> BoxFuture<'_, CacheResult<()>>;
    /// Sets a field; the whole hash expires `ttl` after the last write.
    fn hash_put(&self, key: &str, field: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>>;
    fn hash_remove(&self, key: &str, field: &str) -> BoxFuture<'_, CacheResult<()>>;
    fn hash_all(&self, key: &str) -> BoxFuture<'_, CacheResult<HashMap<String, String>>>;
    fn publish(&self, channel: &str, payload: String) -> BoxFuture<'_, CacheResult<()>>;
    /// The messages of `channel` from now on; the stream ends when the subscription breaks.
    fn subscribe(&self, channel: &str) -> BoxFuture<'_, CacheResult<BoxStream<'static, String>>>;
}

/// The node cannot start: `TAVRN_CACHE_URL` is set but the cache does not answer (exit code 3).
#[derive(Debug, thiserror::Error)]
#[error(
    "TAVRN_CACHE_URL: Valkey/Redis at {target} is not reachable ({reason}). Start it first, fix the URL or unset \
     TAVRN_CACHE_URL for a single instance."
)]
pub struct CacheUnreachable {
    pub target: String,
    pub reason: String,
}

/// `503 node.cache_unavailable`: a request needs the shared cache and it does not answer.
pub fn unavailable(e: CacheError) -> crate::error::ApiError {
    tracing::error!(error = %e, "cache unavailable");
    crate::error::ApiError::Unavailable {
        code: "node.cache_unavailable",
        detail: "The node's shared cache does not answer; try again shortly".into(),
    }
}

/// Exit code of `tavrn-node serve` when the configured cache is unreachable at startup.
pub const EXIT_CACHE_UNREACHABLE: i32 = 3;

/// Workers that run on the leader only and can be woken from any instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Job {
    Outbox,
    Subscriptions,
}

/// Side effects on voice that only the leader (which holds the voice state) may carry out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VoiceEffect {
    DisconnectUser {
        room_id: String,
        user_id: String,
    },
    CloseChannel {
        room_id: String,
        channel_id: String,
    },
    CloseRoom {
        room_id: String,
    },
    /// A member left a DM or group DM: their devices leave its running call.
    LeaveCall {
        conversation_id: String,
        user_id: String,
    },
    /// Sessions ended: the user's devices (`devices`, or all of them) leave every voice channel and call.
    DisconnectEverywhere {
        user_id: String,
        devices: Option<Vec<String>>,
    },
}

/// Open connections and idle/activity of one device of a user (part of a presence sync).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSync {
    pub connections: usize,
    pub idle: bool,
    pub activity: Option<crate::presence::Activity>,
}

/// A message on the bus `tavrn:<domain>:bus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Message {
    /// A hub event, serialized once by its sender (`frame` is the WebSocket frame).
    Event {
        id: String,
        kind: String,
        scope: hub::Scope,
        frame: String,
    },
    /// The sender lost events (it could not publish): every client resyncs.
    Resync,
    /// Liveness and the relay address of the sender.
    Heartbeat {
        url: String,
    },
    /// The sender (re)joined the bus: everyone answers with a [`Message::PresenceSync`].
    Hello {
        url: String,
    },
    /// The sender stops (graceful shutdown): its connections are gone now.
    Bye,
    /// All connected users of the sender (replaces what the receivers knew about it).
    PresenceSync {
        users: HashMap<String, HashMap<String, DeviceSync>>,
    },
    /// The open connections per device of one user on the sender (empty: none left).
    PresenceConn {
        user: String,
        devices: HashMap<String, usize>,
    },
    /// The idle flag and activity of a device, set through the sender.
    PresenceAttrs {
        user: String,
        device: String,
        idle: bool,
        activity: Option<crate::presence::Activity>,
    },
    Wake {
        job: Job,
    },
    /// A newer WebSocket of the app token replaced connection `id` of `instance`.
    AppConnReplaced {
        instance: String,
        token: String,
        id: u64,
    },
    /// For the leader.
    Voice {
        effect: VoiceEffect,
    },
    /// An interaction for a receiving connection of `bot` on `instance` (APPLICATIONS.md §5.6, §5.10); `data` is
    /// the data of the event `event` (`command.invoke`, `component.invoke` or `modal.submit`; empty from senders
    /// before components: `command.invoke`). The sender owns the pending interaction.
    Invoke {
        instance: String,
        bot: String,
        data: String,
        #[serde(default)]
        event: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    from: String,
    msg: Message,
}

/// What the hub and the rest of the node hand to the bus forwarder (in order).
pub enum Outbound {
    Event(Arc<hub::Event>),
    Message(Box<Message>),
}

/// The bounded queue to the bus forwarder ([`BUS_QUEUE`]): a full queue drops the message and counts it, and the
/// forwarder then publishes [`Message::Resync`] first, as after a failed publish.
#[derive(Clone)]
pub struct BusSender {
    tx: mpsc::Sender<Outbound>,
    dropped: Arc<AtomicU64>,
}

impl BusSender {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Outbound>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx, dropped: Arc::default() }, rx)
    }

    /// Queues `out`; never waits.
    pub fn send(&self, out: Outbound) {
        if self.tx.try_send(out).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Messages dropped since the last call.
    fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

struct Peer {
    url: String,
    seen: Instant,
}

/// This instance in its node: see the module documentation.
pub struct Cluster {
    pub instance_id: String,
    prefix: String,
    cache: Arc<dyn Cache>,
    shared: bool,
    tx: BusSender,
    rx: Mutex<Option<mpsc::Receiver<Outbound>>>,
    /// Unix milliseconds until which this instance holds the leader lease (`u64::MAX` standalone).
    leader_until: AtomicU64,
    /// The instance id of the current leader as last read.
    leader_id: Mutex<Option<String>>,
    /// Where other instances reach this one (relayed requests).
    url: Mutex<String>,
    peers: Mutex<HashMap<String, Peer>>,
    /// The bus subscription is up.
    healthy: AtomicBool,
    /// Ends the current subscription (it is renewed).
    restart: Notify,
    /// When this instance last received its own heartbeat back (proves the subscription works).
    last_echo: Mutex<Instant>,
    seal: Zeroizing<[u8; 32]>,
}

pub fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn seal_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, secret);
    let mut out = Zeroizing::new([0u8; 32]);
    if hk.expand(b"tavrn cache seal v1", out.as_mut()).is_err() {
        out.fill(0);
    }
    out
}

/// `[A-Za-z0-9._-]{1,64}`: an instance id (`TAVRN_INSTANCE_ID`).
pub fn valid_instance_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `redis://[user:pw@]host[:port][/db]` or `rediss://…` (TLS).
pub fn valid_url(url: &str) -> bool {
    (url.starts_with("redis://") || url.starts_with("rediss://")) && redis::Client::open(url).is_ok()
}

/// `host:port` of a cache URL without credentials (for messages and logs).
pub fn target_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.rsplit_once('@').map(|(_, r)| r).unwrap_or(rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() { "?".into() } else { host.to_string() }
}

/// The address other instances reach this one at: `TAVRN_INSTANCE_URL`, else the address of the interface that
/// routes to the cache host (other instances reach the same network) with the listen port.
fn detect_url(config: &Config, cache_url: &str) -> String {
    if let Some(url) = config.instance_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        return url.trim_end_matches('/').to_string();
    }
    let port = config.listen_port();
    let listen_ip =
        config.listen.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified());
    let ip = listen_ip.or_else(|| {
        let target = target_of(cache_url);
        let with_port = if target.contains(':') && !target.ends_with(']') { target } else { format!("{target}:6379") };
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        // UDP "connect" only picks the route; nothing is sent.
        socket.connect(with_port).ok()?;
        socket.local_addr().ok().map(|a| a.ip())
    });
    match ip.unwrap_or(std::net::IpAddr::from([127, 0, 0, 1])) {
        std::net::IpAddr::V6(v6) => format!("http://[{v6}]:{port}"),
        v4 => format!("http://{v4}:{port}"),
    }
}

impl Cluster {
    fn build(
        domain: &str,
        instance_id: String,
        cache: Arc<dyn Cache>,
        shared: bool,
        secret: &[u8; 32],
        url: String,
    ) -> Self {
        let (tx, rx) = BusSender::channel(BUS_QUEUE);
        Self {
            instance_id,
            prefix: format!("tavrn:{domain}:"),
            cache,
            shared,
            tx,
            rx: Mutex::new(Some(rx)),
            leader_until: AtomicU64::new(if shared { 0 } else { u64::MAX }),
            leader_id: Mutex::new(None),
            url: Mutex::new(url),
            peers: Mutex::new(HashMap::new()),
            healthy: AtomicBool::new(!shared),
            restart: Notify::new(),
            last_echo: Mutex::new(Instant::now()),
            seal: seal_key(secret),
        }
    }

    /// One instance on its own (no `TAVRN_CACHE_URL`): always the leader, nothing goes over a bus.
    pub fn standalone(domain: &str, secret: &[u8; 32]) -> Self {
        Self::build(domain, crate::util::ulid(), Arc::new(memory::InProcess::default()), false, secret, String::new())
    }

    /// An instance sharing `cache` with others (tests hand one [`memory::InProcess`] to several nodes).
    pub fn shared_with(domain: &str, instance_id: &str, cache: Arc<dyn Cache>, secret: &[u8; 32], url: &str) -> Self {
        Self::build(domain, instance_id.to_string(), cache, true, secret, url.to_string())
    }

    /// From the configuration: standalone without `TAVRN_CACHE_URL`, else connected to Valkey (fails fast).
    pub async fn from_config(config: &Config, secret: &[u8; 32]) -> Result<Self, CacheUnreachable> {
        let Some(url) = config.cache_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
            return Ok(Self::standalone(&config.domain, secret));
        };
        let target = target_of(url);
        let backend =
            valkey::Valkey::connect(url).await.map_err(|e| CacheUnreachable { target: target.clone(), reason: e.0 })?;
        let instance_id = config
            .instance_id
            .as_deref()
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .map(String::from)
            .unwrap_or_else(|| crate::util::ulid().to_lowercase());
        let me = detect_url(config, url);
        tracing::info!(instance = %instance_id, cache = %target, relay_url = %me, "joined the node's instances through the cache");
        Ok(Self::shared_with(&config.domain, &instance_id, Arc::new(backend), secret, &me))
    }

    /// Several instances share state (a cache URL, or a shared test cache).
    pub fn is_shared(&self) -> bool {
        self.shared
    }

    /// This instance runs the singleton jobs and holds voice, call and whiteboard state.
    pub fn is_leader(&self) -> bool {
        now_ms() < self.leader_until.load(Ordering::Relaxed)
    }

    /// The instance id of the leader as last seen (`None` while unknown).
    pub fn leader_id(&self) -> Option<String> {
        if self.is_leader() {
            return Some(self.instance_id.clone());
        }
        lock(&self.leader_id).clone()
    }

    /// The relay address of the leader (`None` if it is this instance or unknown).
    pub fn leader_url(&self) -> Option<String> {
        if self.is_leader() {
            return None;
        }
        let id = lock(&self.leader_id).clone()?;
        lock(&self.peers).get(&id).map(|p| p.url.clone())
    }

    pub fn url(&self) -> String {
        lock(&self.url).clone()
    }

    /// Sets the relay address (tests bind their listener after the state exists).
    pub fn set_url(&self, url: &str) {
        *lock(&self.url) = url.trim_end_matches('/').to_string();
    }

    /// The relay address of another live instance (`None` for this one or an unknown one).
    pub fn peer_url(&self, instance: &str) -> Option<String> {
        if instance == self.instance_id {
            return None;
        }
        let now = Instant::now();
        lock(&self.peers)
            .get(instance)
            .filter(|p| now.duration_since(p.seen) < PEER_TIMEOUT && !p.url.is_empty())
            .map(|p| p.url.clone())
    }

    /// Instances heard from recently (without this one).
    pub fn peers(&self) -> Vec<String> {
        let now = Instant::now();
        lock(&self.peers)
            .iter()
            .filter(|(_, p)| now.duration_since(p.seen) < PEER_TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The full key of `name` in this node's namespace.
    pub fn key(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }

    fn channel(&self) -> String {
        self.key("bus")
    }

    pub fn cache(&self) -> &Arc<dyn Cache> {
        &self.cache
    }

    /// `/readyz`: `None` standalone, else whether the cache answers and the bus is subscribed.
    pub async fn ready(&self) -> Option<bool> {
        if !self.shared {
            return None;
        }
        let ping = tokio::time::timeout(Duration::from_secs(2), self.cache.ping()).await;
        Some(matches!(ping, Ok(Ok(()))) && self.healthy.load(Ordering::Relaxed))
    }

    /// Hands a message to the bus (in order with the hub's events); nothing standalone.
    pub fn send(&self, msg: Message) {
        if self.shared {
            self.tx.send(Outbound::Message(Box::new(msg)));
        }
    }

    /// The sender the hub publishes its events through (only when shared).
    pub fn event_sender(&self) -> Option<BusSender> {
        self.shared.then(|| self.tx.clone())
    }

    fn seal(&self, aad: &str, plain: &[u8]) -> CacheResult<String> {
        let mut nonce = [0u8; 12];
        crate::util::fill_random(&mut nonce);
        let cipher = Aes256Gcm::new((&*self.seal).into());
        let ct = cipher
            .encrypt((&nonce).into(), Payload { msg: plain, aad: aad.as_bytes() })
            .map_err(|_| CacheError("seal failed".into()))?;
        Ok(URL_SAFE_NO_PAD.encode([nonce.as_slice(), &ct].concat()))
    }

    fn open(&self, aad: &str, sealed: &str) -> Option<Zeroizing<Vec<u8>>> {
        let blob = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if blob.len() < 12 + 16 {
            return None;
        }
        let cipher = Aes256Gcm::new((&*self.seal).into());
        cipher
            .decrypt(blob[..12].try_into().ok()?, Payload { msg: &blob[12..], aad: aad.as_bytes() })
            .ok()
            .map(Zeroizing::new)
    }

    /// Stores a single-use value for `ttl`, encrypted with a key derived from `secrets.key` (the cache never sees
    /// PKCE verifiers, nonces or identity claims in the clear). `name` should already be a hash of the secret.
    pub async fn put_sealed<T: Serialize>(&self, name: &str, value: &T, ttl: Duration) -> CacheResult<()> {
        let key = self.key(name);
        let plain = Zeroizing::new(serde_json::to_vec(value).map_err(|e| CacheError(e.to_string()))?);
        let sealed = self.seal(&key, &plain)?;
        self.cache.put(&key, sealed, ttl).await
    }

    /// Reads a value of [`Cluster::put_sealed`] without taking it; `Ok(None)` if absent, expired or not genuine.
    pub async fn get_sealed<T: DeserializeOwned>(&self, name: &str) -> CacheResult<Option<T>> {
        let key = self.key(name);
        let Some(sealed) = self.cache.get(&key).await? else { return Ok(None) };
        Ok(self.open(&key, &sealed).and_then(|plain| serde_json::from_slice(&plain).ok()))
    }

    /// Takes (and deletes) a value of [`Cluster::put_sealed`]; `Ok(None)` if absent, expired or not genuine.
    pub async fn take_sealed<T: DeserializeOwned>(&self, name: &str) -> CacheResult<Option<T>> {
        let key = self.key(name);
        let Some(sealed) = self.cache.take(&key).await? else { return Ok(None) };
        Ok(self.open(&key, &sealed).and_then(|plain| serde_json::from_slice(&plain).ok()))
    }

    fn envelope(&self, msg: Message) -> String {
        serde_json::to_string(&Envelope { from: self.instance_id.clone(), msg }).unwrap_or_default()
    }

    fn saw_peer(&self, id: &str, url: Option<&str>) {
        let mut peers = lock(&self.peers);
        let peer = peers.entry(id.to_string()).or_insert_with(|| Peer { url: String::new(), seen: Instant::now() });
        peer.seen = Instant::now();
        if let Some(url) = url {
            peer.url = url.to_string();
        }
    }

    /// Forgets instances not heard from for [`PEER_TIMEOUT`]; returns them.
    fn expire_peers(&self) -> Vec<String> {
        let now = Instant::now();
        let mut peers = lock(&self.peers);
        let gone: Vec<String> =
            peers.iter().filter(|(_, p)| now.duration_since(p.seen) >= PEER_TIMEOUT).map(|(k, _)| k.clone()).collect();
        for id in &gone {
            peers.remove(id);
        }
        gone
    }
}

/// Starts the bus tasks of a shared instance (forwarder, subscriber, heartbeat). Nothing standalone.
pub fn start(state: &AppState) {
    let cluster = &state.cluster;
    if !cluster.shared {
        return;
    }
    let Some(rx) = lock(&cluster.rx).take() else { return };
    tokio::spawn(forward(state.cluster.clone(), rx));
    tokio::spawn(subscribe_loop(state.clone()));
    tokio::spawn(heartbeat_loop(state.clone()));
}

/// Publishes outbound messages in order. A failed publish loses messages: once the cache answers again the
/// instance publishes [`Message::Resync`] first, so the clients of the others reload instead of missing events.
async fn forward(cluster: Arc<Cluster>, mut rx: mpsc::Receiver<Outbound>) {
    let channel = cluster.channel();
    let mut lost: u64 = 0;
    let mut paused_until: Option<Instant> = None;
    while let Some(out) = rx.recv().await {
        let dropped = cluster.tx.take_dropped();
        if dropped > 0 {
            if lost == 0 {
                tracing::warn!(
                    dropped,
                    "cache bus queue full: events of this instance are lost, the other instances' clients resync"
                );
            }
            lost += dropped;
        }
        if paused_until.is_some_and(|t| Instant::now() < t) {
            lost += 1;
            continue;
        }
        if lost > 0 {
            match cluster.cache.publish(&channel, cluster.envelope(Message::Resync)).await {
                Ok(()) => {
                    tracing::warn!(lost, "cache bus is back: events were lost, the other instances' clients resync");
                    lost = 0;
                }
                Err(_) => {
                    lost += 1;
                    paused_until = Some(Instant::now() + PUBLISH_PAUSE);
                    continue;
                }
            }
        }
        let payload = match out {
            Outbound::Event(ev) => cluster.envelope(Message::Event {
                id: ev.id.clone(),
                kind: ev.kind.clone(),
                scope: ev.scope.clone(),
                frame: ev.frame.as_str().to_string(),
            }),
            Outbound::Message(m) => cluster.envelope(*m),
        };
        if let Err(e) = cluster.cache.publish(&channel, payload).await {
            if lost == 0 {
                tracing::error!(error = %e, "cache bus: publishing failed, events of this instance are lost until it is back");
            }
            lost += 1;
            paused_until = Some(Instant::now() + PUBLISH_PAUSE);
        }
    }
}

/// Subscribes to the bus and dispatches its messages; subscribes again with backoff when the subscription breaks
/// and then makes every local client resync (it may have missed events in between).
async fn subscribe_loop(state: AppState) {
    let cluster = state.cluster.clone();
    let channel = cluster.channel();
    let mut backoff = Duration::from_millis(250);
    let mut first = true;
    loop {
        match cluster.cache.subscribe(&channel).await {
            Ok(mut stream) => {
                backoff = Duration::from_millis(250);
                cluster.healthy.store(true, Ordering::Relaxed);
                *lock(&cluster.last_echo) = Instant::now();
                if !first {
                    tracing::warn!("cache bus subscription restored: local clients resync");
                    state.hub.resync_all();
                }
                first = false;
                // Announce: the others answer with their presence; ours goes out right away.
                cluster.send(Message::Hello { url: cluster.url() });
                cluster.send(crate::presence::sync_message(&state));
                loop {
                    tokio::select! {
                        next = stream.next() => match next {
                            Some(payload) => dispatch(&state, &payload).await,
                            None => break,
                        },
                        () = cluster.restart.notified() => break,
                    }
                }
                cluster.healthy.store(false, Ordering::Relaxed);
                tracing::error!("cache bus subscription lost, reconnecting");
            }
            Err(e) => {
                cluster.healthy.store(false, Ordering::Relaxed);
                tracing::warn!(error = %e, retry_in = ?backoff, "cache bus: subscribing failed");
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Heartbeats, dead instances, and a subscription that silently stopped delivering (no own echo).
async fn heartbeat_loop(state: AppState) {
    let cluster = state.cluster.clone();
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        cluster.send(Message::Heartbeat { url: cluster.url() });
        for gone in cluster.expire_peers() {
            tracing::warn!(instance = %gone, "instance not heard from, its connections no longer count");
            crate::presence::forget_instance(&state, &gone);
        }
        let silent = lock(&cluster.last_echo).elapsed();
        if cluster.healthy.load(Ordering::Relaxed) && silent > PEER_TIMEOUT {
            tracing::error!(?silent, "cache bus delivers nothing (not even the own heartbeat), subscribing again");
            cluster.restart.notify_one();
        }
    }
}

/// Handles one bus message of another instance (own messages only prove the subscription works).
pub async fn dispatch(state: &AppState, payload: &str) {
    let cluster = &state.cluster;
    let Ok(Envelope { from, msg }) = serde_json::from_str::<Envelope>(payload) else {
        tracing::warn!("cache bus: unreadable message ignored");
        return;
    };
    if from == cluster.instance_id {
        *lock(&cluster.last_echo) = Instant::now();
        return;
    }
    match &msg {
        Message::Heartbeat { url } | Message::Hello { url } => cluster.saw_peer(&from, Some(url)),
        Message::Bye => {}
        _ => cluster.saw_peer(&from, None),
    }
    match msg {
        Message::Event { id, kind, scope, frame } => state.hub.inject(id, kind, scope, frame),
        Message::Resync => state.hub.resync_all(),
        Message::Heartbeat { .. } => {}
        Message::Hello { .. } => {
            // The newcomer learns this instance's relay address and its connections.
            cluster.send(Message::Heartbeat { url: cluster.url() });
            cluster.send(crate::presence::sync_message(state));
        }
        Message::Bye => {
            lock(&cluster.peers).remove(&from);
            crate::presence::forget_instance(state, &from);
        }
        Message::PresenceSync { users } => crate::presence::apply_sync(state, &from, users),
        Message::PresenceConn { user, devices } => crate::presence::apply_connections(state, &from, &user, devices),
        Message::PresenceAttrs { user, device, idle, activity } => {
            crate::presence::apply_attributes(state, &user, &device, idle, activity);
        }
        Message::Wake { job } => notify_local(state, job),
        Message::AppConnReplaced { instance, token, id } => {
            if instance == cluster.instance_id {
                state.app_connections.replace_local(&token, id);
            }
        }
        Message::Invoke { instance, bot, data, event } => {
            if instance == cluster.instance_id {
                crate::interactions::deliver_from_bus(state, &bot, &event, &data);
            }
        }
        Message::Voice { effect } => {
            if cluster.is_leader() {
                let state = state.clone();
                tokio::spawn(async move { crate::voice::run_effect(&state, effect).await });
            }
        }
    }
}

fn notify_local(state: &AppState, job: Job) {
    match job {
        Job::Outbox => state.outbox_wakeup.notify_one(),
        Job::Subscriptions => state.subscription_wakeup.notify_one(),
    }
}

/// Wakes a leader-only worker wherever the leader runs.
pub fn wake(state: &AppState, job: Job) {
    notify_local(state, job);
    state.cluster.send(Message::Wake { job });
}

/// Graceful stop: tells the others this instance's connections are gone and gives the leader lease up.
pub async fn shutdown(state: &AppState) {
    let cluster = &state.cluster;
    if !cluster.shared {
        return;
    }
    let _ = cluster.cache.publish(&cluster.channel(), cluster.envelope(Message::Bye)).await;
    leader::step_down(cluster).await;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn urls_and_instance_ids_are_validated() {
        for ok in [
            "redis://valkey:6379",
            "redis://:pw@valkey:6379/2",
            "rediss://user:pw@cache.example:6380",
            "redis://127.0.0.1",
        ] {
            assert!(valid_url(ok), "{ok}");
        }
        for bad in ["", "valkey:6379", "http://valkey:6379", "redis//x", "postgres://x"] {
            assert!(!valid_url(bad), "{bad}");
        }
        assert_eq!(target_of("redis://:secret@valkey:6379/1"), "valkey:6379");
        assert_eq!(target_of("rediss://u:p@h.example"), "h.example");
        assert!(valid_instance_id("tavrn-1") && valid_instance_id("a.b_c"));
        assert!(!valid_instance_id("") && !valid_instance_id("a b") && !valid_instance_id(&"x".repeat(65)));
    }

    /// A full bus queue drops new messages and counts them; the forwarder then publishes a resync before the
    /// next message, so the other instances' clients reload instead of missing events.
    #[tokio::test]
    async fn a_full_bus_queue_drops_and_the_forwarder_resyncs() {
        let (tx, _rx) = BusSender::channel(2);
        for _ in 0..3 {
            tx.send(Outbound::Message(Box::new(Message::Resync)));
        }
        assert_eq!((tx.take_dropped(), tx.take_dropped()), (1, 0));

        let cache: Arc<dyn Cache> = Arc::new(memory::InProcess::default());
        let cluster = Arc::new(Cluster::shared_with("n.test", "a", cache.clone(), &[0; 32], ""));
        let mut bus = cache.subscribe(&cluster.channel()).await.unwrap();
        for _ in 0..BUS_QUEUE + 3 {
            cluster.send(Message::Wake { job: Job::Outbox });
        }
        let rx = lock(&cluster.rx).take().unwrap();
        tokio::spawn(forward(cluster.clone(), rx));
        let first: Envelope = serde_json::from_str(&bus.next().await.unwrap()).unwrap();
        assert!(matches!(first.msg, Message::Resync), "the resync goes first");
        let second: Envelope = serde_json::from_str(&bus.next().await.unwrap()).unwrap();
        assert!(matches!(second.msg, Message::Wake { .. }));
    }

    #[tokio::test]
    async fn sealed_values_are_single_use_and_bound_to_their_key() {
        let cache: Arc<dyn Cache> = Arc::new(memory::InProcess::default());
        let a = Cluster::shared_with("n.test", "a", cache.clone(), &[7; 32], "");
        let b = Cluster::shared_with("n.test", "b", cache.clone(), &[7; 32], "");
        a.put_sealed("oidc:x", &serde_json::json!({ "v": 1 }), Duration::from_secs(5)).await.unwrap();
        let raw = cache.get("tavrn:n.test:oidc:x").await.unwrap().unwrap();
        assert!(!raw.contains("\"v\""), "stored encrypted");
        // Another instance (same secrets.key) takes it, once.
        assert_eq!(b.take_sealed::<serde_json::Value>("oidc:x").await.unwrap(), Some(serde_json::json!({ "v": 1 })));
        assert_eq!(a.take_sealed::<serde_json::Value>("oidc:x").await.unwrap(), None);
        // A value copied to another key does not open (the key is the associated data); a foreign key neither.
        cache.put("tavrn:n.test:oidc:y", raw.clone(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(a.take_sealed::<serde_json::Value>("oidc:y").await.unwrap(), None);
        let other = Cluster::shared_with("n.test", "c", cache.clone(), &[8; 32], "");
        cache.put("tavrn:n.test:oidc:x", raw, Duration::from_secs(5)).await.unwrap();
        assert_eq!(other.take_sealed::<serde_json::Value>("oidc:x").await.unwrap(), None);
    }

    #[test]
    fn standalone_is_always_the_leader_and_never_sends() {
        let c = Cluster::standalone("n.test", &[1; 32]);
        assert!(c.is_leader() && !c.is_shared());
        assert!(c.event_sender().is_none());
        c.send(Message::Resync);
        assert!(lock(&c.rx).as_mut().unwrap().try_recv().is_err(), "nothing queued");
        let s = Cluster::shared_with("n.test", "x", Arc::new(memory::InProcess::default()), &[1; 32], "");
        assert!(!s.is_leader(), "a shared instance leads only with the lease");
        assert_eq!(s.key("bus"), "tavrn:n.test:bus");
    }

    #[test]
    fn messages_round_trip() {
        let msgs = vec![
            Message::Event {
                id: "e".into(),
                kind: "message.create".into(),
                scope: hub::Scope::Room("r".into()),
                frame: "{\"op\":\"event\"}".into(),
            },
            Message::Voice { effect: VoiceEffect::CloseRoom { room_id: "r".into() } },
            Message::Voice {
                effect: VoiceEffect::DisconnectEverywhere { user_id: "u".into(), devices: Some(vec!["d".into()]) },
            },
            Message::Wake { job: Job::Outbox },
            Message::PresenceConn { user: "u".into(), devices: HashMap::from([("d".into(), 2)]) },
            Message::Invoke {
                instance: "i1".into(),
                bot: "b".into(),
                data: "{\"interaction_id\":\"x\"}".into(),
                event: "component.invoke".into(),
            },
        ];
        for m in msgs {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<Message>(&json).unwrap(), m);
        }
    }
}
