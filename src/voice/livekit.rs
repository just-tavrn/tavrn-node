// SPDX-License-Identifier: AGPL-3.0-only
//! `livekit-server` as a supervised child process.
//!
//! The node generates LiveKit's API key and secret once (`<data>/keys/livekit.key`, mode 0600, in
//! LiveKit's own `key_file` format, so the secret never appears in the environment, on a command line or
//! in the generated config), writes `<data>/livekit.yaml` from the `TAVRN_*` settings at every start and
//! runs the binary: signaling and the room service on 127.0.0.1 only (reached through the node's `/rtc`
//! proxy), media on the UDP range, optionally ICE over TCP and the embedded TURN server (VOICE.md §10); the
//! startup log names every address and port clients must reach. A crashed process is restarted with an
//! exponential backoff, its JSON log lines are forwarded to the node's log (target `livekit`), and a
//! node shutdown stops it with SIGTERM (SIGKILL after 10 seconds). When the announced addresses change
//! (hostnames in the address settings, [`super::advertise`]) the config is rewritten and LiveKit restarted
//! at once; sessions survive through the reconnect grace period.
//!
//! With several instances (`TAVRN_CACHE_URL`, docs/SCALING.md) every instance runs its own LiveKit and the
//! config gets a `redis:` section pointing at the shared Valkey: the LiveKit processes then form one distributed
//! LiveKit (rooms are placed on one node, signaling is relayed through Redis), so the `/rtc` proxy of any
//! instance reaches every room. The cache password goes to the child as `REDIS_PASSWORD` (LiveKit's
//! `--redis-password`), never into the file, and each instance writes its own `livekit-<instance id>.yaml`.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow, bail};
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::Notify,
    task::JoinHandle,
};

use crate::config::Config;

pub const KEY_FILE: &str = "livekit.key";
pub const CONFIG_FILE: &str = "livekit.yaml";
/// Codecs LiveKit accepts. VP8 and H.264 work with end-to-end encryption (insertable streams) in every
/// browser; Opus with RED for audio.
pub const CODECS: &[&str] = &["audio/opus", "audio/red", "video/vp8", "video/h264"];

const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A process that ran this long is considered healthy: the backoff starts over after its exit.
const HEALTHY_AFTER: Duration = Duration::from_secs(60);
const STOP_GRACE: Duration = Duration::from_secs(10);

/// What `/healthz` reports about voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LiveKitStatus {
    /// `TAVRN_VOICE_ENABLED=false`.
    Disabled,
    /// Not supervised by this process (library use, tests) or stopped at shutdown.
    Stopped,
    Starting,
    Running,
    /// Crashed; waiting for the next start attempt.
    Restarting,
}

/// API key and secret shared by the node and LiveKit.
#[derive(Clone)]
pub struct ApiKey {
    pub key: String,
    pub secret: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey").field("key", &self.key).finish_non_exhaustive()
    }
}

/// Loads `<dir>/livekit.key` (`<key>: <secret>`) or creates it with a random key and secret (mode 0600).
pub fn load_or_create_key(dir: &Path) -> anyhow::Result<ApiKey> {
    let path = dir.join(KEY_FILE);
    if !path.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create key directory {}", dir.display()))?;
        let key = format!("API{}", random_alnum(12));
        let secret = zeroize::Zeroizing::new(random_alnum(48));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                use std::io::Write;
                let line = zeroize::Zeroizing::new(format!("{key}: {}\n", secret.as_str()));
                file.write_all(line.as_bytes()).with_context(|| format!("cannot write {}", path.display()))?;
                tracing::info!(path = %path.display(), "LiveKit API key generated");
                return Ok(ApiKey { key, secret });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", path.display())),
        }
    }
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    parse_key(&text).ok_or_else(|| anyhow!("{} is corrupt (expected one line '<key>: <secret>')", path.display()))
}

fn parse_key(text: &str) -> Option<ApiKey> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (key, secret) = line.split_once(':')?;
    let (key, secret) = (key.trim(), secret.trim());
    let ok = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric()) && secret.len() >= 32;
    ok.then(|| ApiKey { key: key.to_string(), secret: zeroize::Zeroizing::new(secret.to_string()) })
}

fn random_alnum(n: usize) -> String {
    use rand::{Rng, distributions::Alphanumeric};
    rand::rngs::OsRng.sample_iter(&Alphanumeric).take(n).map(char::from).collect()
}

/// Which addresses LiveKit announces to clients (its ICE host candidates), derived from
/// `TAVRN_RTC_EXTERNAL_IP`, `TAVRN_RTC_ADVERTISE_IPS` and the mode (VOICE.md §10.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Advertise {
    /// LiveKit's `node_ip` (`v4`, `v6` or `v4,v6`): every local address of that family is announced as this
    /// address instead (the container's private addresses are useless to clients).
    pub node_ip: Option<String>,
    /// Detect the public addresses (IPv4 and IPv6) via STUN at start (`use_external_ip`).
    pub stun: bool,
    /// Configured addresses beyond one per family (LiveKit takes only one of each): handed to the clients,
    /// which add every host candidate of the node once more with this address.
    pub aliases: Vec<String>,
    /// Local address ranges never announced (`rtc.ips.excludes`).
    pub excludes: Vec<String>,
}

impl Advertise {
    /// The plan of the configured IP literals (hostnames are resolved by [`super::advertise`]).
    pub fn from_config(config: &Config) -> Self {
        let mut explicit: Vec<std::net::IpAddr> =
            config.rtc_external_ip().and_then(|ip| ip.parse().ok()).into_iter().collect();
        for ip in config.rtc_advertise_ips() {
            if !explicit.contains(&ip) {
                explicit.push(ip);
            }
        }
        plan(&explicit, config.dev)
    }

    /// One line for the startup log.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        match (&self.node_ip, self.stun) {
            (Some(ip), _) => parts.push(format!("node_ip={ip} (explicit)")),
            (None, true) => parts.push("node_ip=detected via STUN (IPv4 and IPv6)".into()),
            (None, false) => parts.push("node_ip=local interface addresses (development)".into()),
        }
        if !self.aliases.is_empty() {
            parts.push(format!("client-side extra addresses={}", self.aliases.join(",")));
        }
        if !self.excludes.is_empty() {
            parts.push(format!("never announced={}", self.excludes.join(",")));
        }
        parts.join("; ")
    }
}

/// Link-local addresses (`fe80::…%eth0`, `169.254.x.x`) are never reachable from clients.
const LINK_LOCAL: [&str; 2] = ["fe80::/10", "169.254.0.0/16"];
/// IPv6 unique local addresses (Docker's default IPv6 networks): useless unless rewritten to a global address.
const ULA: &str = "fc00::/7";

/// The address plan for explicitly configured addresses (in order: the external IP first) or none.
pub fn plan(explicit: &[std::net::IpAddr], dev: bool) -> Advertise {
    let v4 = explicit.iter().find(|ip| ip.is_ipv4());
    let v6 = explicit.iter().find(|ip| ip.is_ipv6());
    let node_ip = match (v4, v6) {
        (Some(a), Some(b)) => Some(format!("{a},{b}")),
        (Some(a), None) | (None, Some(a)) => Some(a.to_string()),
        (None, None) => None,
    };
    let aliases = explicit.iter().filter(|ip| Some(*ip) != v4 && Some(*ip) != v6).map(ToString::to_string).collect();
    let stun = node_ip.is_none() && !dev;
    let mut excludes = Vec::new();
    if !dev {
        excludes.extend(LINK_LOCAL.iter().map(|s| (*s).to_string()));
        // Without an IPv6 to rewrite them to (explicit addresses only IPv4), the container's ULAs would be
        // announced as they are. STUN mode needs them: they are the local side of the detected mapping.
        if node_ip.is_some() && v6.is_none() {
            excludes.push(ULA.to_string());
        }
    }
    Advertise { node_ip, stun, aliases, excludes }
}

/// LiveKit's embedded TURN server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Turn {
    /// Domain of `turns:<domain>:443` (only with a TLS port).
    pub domain: String,
    /// 0 = no TURN over UDP.
    pub udp_port: u16,
    /// Plain TCP behind the proxy's TLS termination; 0 = no TURN over TLS.
    pub tls_port: u16,
    pub relay_ports: (u16, u16),
}

/// Everything the generated LiveKit config depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub port: u16,
    pub udp_ports: (u16, u16),
    pub advertise: Advertise,
    /// `TAVRN_RTC_STUN_SERVERS` (empty: LiveKit's defaults).
    pub stun_servers: Vec<String>,
    /// ICE over TCP; 0 = off.
    pub tcp_port: u16,
    pub turn: Option<Turn>,
    pub key_file: PathBuf,
    pub api_key: String,
    pub webhook_url: String,
    pub max_participants: u32,
    /// LiveKit's distributed mode through the shared Valkey/Redis (several instances).
    pub redis: Option<Redis>,
}

/// The `redis:` section of LiveKit's config (without the password, which goes into the environment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redis {
    /// `host:port`
    pub address: String,
    pub username: Option<String>,
    pub db: u32,
    /// `rediss://`: TLS with the system's root certificates (LiveKit's `use_tls`).
    pub tls: bool,
}

/// LiveKit's Redis settings and password from `TAVRN_CACHE_URL` (`None` without a valid URL).
pub fn redis_of(url: Option<&str>) -> Option<(Redis, Option<zeroize::Zeroizing<String>>)> {
    let url = reqwest::Url::parse(url?.trim()).ok()?;
    let tls = match url.scheme() {
        "redis" => false,
        "rediss" => true,
        _ => return None,
    };
    let host = url.host_str().filter(|h| !h.is_empty())?;
    let decode = |s: &str| percent_decode(s);
    let username = Some(decode(url.username())).filter(|u| !u.is_empty());
    let password = url.password().map(|p| zeroize::Zeroizing::new(decode(p))).filter(|p| !p.is_empty());
    let db = url.path().trim_start_matches('/').parse::<u32>().unwrap_or(0);
    let address = format!("{host}:{}", url.port().unwrap_or(6379));
    Some((Redis { address, username, db, tls }, password))
}

/// `%XX` escapes of URL user info (no `+` handling: not a form).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(v) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The generated config file: `livekit.yaml`, or `livekit-<instance id>.yaml` when several instances share the
/// data directory.
pub fn config_path(config: &Config, cluster: &crate::cache::Cluster) -> PathBuf {
    let name = if cluster.is_shared() { format!("livekit-{}.yaml", cluster.instance_id) } else { CONFIG_FILE.into() };
    Path::new(&config.data_dir).join(name)
}

impl Settings {
    pub fn from_config(config: &Config, api_key: &str) -> Self {
        let turn = config.rtc_turn_enabled.then(|| Turn {
            domain: config.rtc_turn_domain(),
            udp_port: config.rtc_turn_udp_port,
            tls_port: config.rtc_turn_tls_port,
            relay_ports: config.rtc_turn_relay_port_range().unwrap_or((30000, 30999)),
        });
        Self {
            port: config.livekit_port,
            udp_ports: config.rtc_udp_port_range().unwrap_or((61000, 61100)),
            advertise: Advertise::from_config(config),
            stun_servers: config.rtc_stun_servers(),
            tcp_port: config.rtc_tcp_port,
            turn,
            key_file: Path::new(&config.data_dir).join("keys").join(KEY_FILE),
            api_key: api_key.to_string(),
            webhook_url: webhook_url(config),
            max_participants: config.voice_max_participants,
            redis: redis_of(config.cache_url.as_deref()).map(|(r, _)| r),
        }
    }

    /// What clients must be able to reach, for the startup log.
    pub fn describe(&self) -> String {
        let port = |p: u16| if p == 0 { "off".to_string() } else { p.to_string() };
        let mut out = format!(
            "{}; UDP {}-{}; ICE/TCP {}",
            self.advertise.describe(),
            self.udp_ports.0,
            self.udp_ports.1,
            port(self.tcp_port)
        );
        match &self.turn {
            Some(t) if t.tls_port != 0 => out.push_str(&format!(
                "; TURN udp={} tls={} (clients use turns:{}:443 through the proxy)",
                port(t.udp_port),
                t.tls_port,
                t.domain
            )),
            Some(t) => out.push_str(&format!("; TURN udp={} tls=off", port(t.udp_port))),
            None => out.push_str("; TURN off"),
        }
        out
    }
}

/// Where LiveKit posts its webhooks: this node's own listener on the loopback interface.
pub fn webhook_url(config: &Config) -> String {
    let host = match config.listen.parse::<std::net::SocketAddr>() {
        Ok(a) if a.ip().is_unspecified() && a.is_ipv6() => "[::1]".to_string(),
        Ok(a) if a.ip().is_unspecified() => "127.0.0.1".to_string(),
        Ok(a) if a.is_ipv6() => format!("[{}]", a.ip()),
        Ok(a) => a.ip().to_string(),
        Err(_) => "127.0.0.1".to_string(),
    };
    format!("http://{host}:{}/api/v1/voice/webhook", config.listen_port())
}

/// LiveKit's YAML config. Strings are written as JSON strings (valid YAML), everything else is a number
/// or a fixed keyword, so no value can inject configuration.
pub fn render_config(s: &Settings) -> String {
    let q = |v: &str| serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into());
    let list = |items: &[String]| format!("[{}]", items.iter().map(|i| q(i)).collect::<Vec<_>>().join(", "));
    let mut out = String::new();
    out.push_str("# Generated by tavrn-node at every start from the TAVRN_* settings. Do not edit.\n");
    out.push_str(&format!("port: {}\n", s.port));
    out.push_str("bind_addresses: [\"127.0.0.1\"]\n");
    out.push_str(&format!("key_file: {}\n", q(&s.key_file.to_string_lossy())));
    out.push_str("rtc:\n");
    out.push_str(&format!("  port_range_start: {}\n  port_range_end: {}\n", s.udp_ports.0, s.udp_ports.1));
    // ICE over TCP when UDP is blocked; LiveKit clients fall back to it (and to TURN/TLS) by themselves.
    out.push_str(&format!("  tcp_port: {}\n", s.tcp_port));
    let tcp_fallback = s.tcp_port != 0 || s.turn.as_ref().is_some_and(|t| t.tls_port != 0);
    out.push_str(&format!("  allow_tcp_fallback: {tcp_fallback}\n"));
    let a = &s.advertise;
    out.push_str(&format!("  use_external_ip: {}\n", a.stun));
    if a.stun {
        // Behind a router without NAT loopback LiveKit's self-check of a detected address fails although
        // clients outside reach it; the operator forwards the ports, so the detected address is used.
        out.push_str("  skip_external_ip_validation: true\n");
        // Announce only the mapped (public) IPv4 addresses, not every Docker network the container is in.
        out.push_str("  external_ip_only: true\n");
    }
    if let Some(ip) = &a.node_ip {
        out.push_str(&format!("  node_ip: {}\n", q(ip)));
    }
    if !s.stun_servers.is_empty() {
        out.push_str(&format!("  stun_servers: {}\n", list(&s.stun_servers)));
    }
    if s.turn.is_some() {
        // The relay reaches LiveKit inside the container (loopback): no hairpin through the router needed.
        out.push_str("  advertise_internal_ip: true\n  enable_loopback_candidate: true\n");
    }
    if !a.excludes.is_empty() {
        out.push_str(&format!("  ips:\n    excludes: {}\n", list(&a.excludes)));
    }
    match &s.turn {
        Some(t) => {
            out.push_str("turn:\n  enabled: true\n");
            if t.tls_port != 0 {
                // TLS is terminated by the reverse proxy: LiveKit speaks plain TCP behind it and
                // tells clients `turns:<domain>:443`.
                out.push_str(&format!(
                    "  domain: {}\n  tls_port: {}\n  external_tls: true\n",
                    q(&t.domain),
                    t.tls_port
                ));
            }
            if t.udp_port != 0 {
                out.push_str(&format!("  udp_port: {}\n", t.udp_port));
            }
            out.push_str(&format!(
                "  relay_range_start: {}\n  relay_range_end: {}\n",
                t.relay_ports.0, t.relay_ports.1
            ));
            // Relays may reach only LiveKit itself on the loopback interface, no other private address.
            out.push_str("  allow_restricted_peer_cidrs: [\"127.0.0.1/32\", \"::1/128\"]\n");
        }
        None => out.push_str("turn:\n  enabled: false\n"),
    }
    out.push_str("room:\n  auto_create: true\n  empty_timeout: 60\n  departure_timeout: 20\n");
    out.push_str(&format!("  max_participants: {}\n", s.max_participants));
    out.push_str("  enabled_codecs:\n");
    for c in CODECS {
        out.push_str(&format!("    - mime: {c}\n"));
    }
    if let Some(r) = &s.redis {
        // Distributed mode: every instance's LiveKit joins the others through the shared Valkey/Redis.
        out.push_str(&format!("redis:\n  address: {}\n", q(&r.address)));
        if let Some(user) = &r.username {
            out.push_str(&format!("  username: {}\n", q(user)));
        }
        out.push_str(&format!("  db: {}\n", r.db));
        if r.tls {
            out.push_str("  use_tls: true\n");
        }
    }
    out.push_str("webhook:\n");
    out.push_str(&format!("  api_key: {}\n  urls:\n    - {}\n", q(&s.api_key), q(&s.webhook_url)));
    out.push_str("logging:\n  level: info\n  json: true\n");
    out
}

/// Resolves `TAVRN_LIVEKIT_BINARY`: a path is used as is, a bare name is looked up in `PATH`.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.contains('/') {
        let p = PathBuf::from(name);
        return is_executable(&p).then_some(p);
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).map(|d| d.join(name)).find(|p| is_executable(p)))
        .unwrap_or_default()
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The startup error when voice is enabled but the binary is missing.
pub fn missing_binary_error(config: &Config) -> anyhow::Error {
    anyhow!(
        "livekit-server not found (TAVRN_LIVEKIT_BINARY='{}'). Voice channels need it: the Docker image includes \
         it; locally, install it with `just livekit-install` (downloads the release from \
         https://github.com/livekit/livekit/releases to ~/.local/bin), or set TAVRN_VOICE_ENABLED=false.",
        config.livekit_binary
    )
}

/// The supervised LiveKit process.
pub struct Supervisor {
    stop: Arc<Notify>,
    task: JoinHandle<()>,
    /// A per-instance config file (several instances) is removed at the stop.
    remove_on_stop: Option<PathBuf>,
}

impl Supervisor {
    /// Writes the config and starts the supervision loop. Fails right away if the binary is missing or the
    /// config cannot be written; later crashes are restarted.
    pub fn start(state: &crate::app::AppState) -> anyhow::Result<Self> {
        let config = &state.config;
        let binary = find_binary(&config.livekit_binary).ok_or_else(|| missing_binary_error(config))?;
        let key = state.voice.api_key().ok_or_else(|| anyhow!("LiveKit key missing (voice disabled?)"))?;
        let mut settings = Settings::from_config(config, &key.key);
        settings.advertise = state.voice.advertise();
        let config_path = config_path(config, &state.cluster);
        std::fs::write(&config_path, render_config(&settings))
            .with_context(|| format!("cannot write {}", config_path.display()))?;
        let stop = Arc::new(Notify::new());
        let voice = state.voice.clone();
        let password = redis_of(config.cache_url.as_deref()).and_then(|(_, p)| p);
        let remove_on_stop = state.cluster.is_shared().then(|| config_path.clone());
        let task = tokio::spawn(supervise(binary, config_path, settings.clone(), password, voice, stop.clone()));
        // Everything clients must reach, so a failing voice setup can be checked against the router and proxy.
        tracing::info!(
            port = settings.port,
            media = %settings.describe(),
            distributed = settings.redis.is_some(),
            "LiveKit starting"
        );
        Ok(Self { stop, task, remove_on_stop })
    }

    /// Stops LiveKit (SIGTERM, SIGKILL after 10 seconds) and waits for the loop to end.
    pub async fn stop(self) {
        self.stop.notify_one();
        if let Err(e) = self.task.await {
            tracing::warn!(error = %e, "LiveKit supervision ended unexpectedly");
        }
        if let Some(path) = self.remove_on_stop {
            let _ = std::fs::remove_file(path);
        }
    }
}

async fn supervise(
    binary: PathBuf,
    config_path: PathBuf,
    mut settings: Settings,
    redis_password: Option<zeroize::Zeroizing<String>>,
    voice: Arc<super::VoiceRuntime>,
    stop: Arc<Notify>,
) {
    let mut backoff = BACKOFF_START;
    loop {
        // The announced addresses may have changed since the last start (hostnames, `advertise`).
        let advertise = voice.advertise();
        if advertise != settings.advertise {
            settings.advertise = advertise;
            if let Err(e) = std::fs::write(&config_path, render_config(&settings)) {
                tracing::error!(error = %e, path = %config_path.display(), "cannot write LiveKit configuration");
            }
            tracing::info!(media = %settings.describe(), "LiveKit starting with new addresses");
        }
        voice.set_status(LiveKitStatus::Starting);
        let started = Instant::now();
        match spawn(&binary, &config_path, redis_password.as_deref().map(String::as_str)) {
            Ok(mut child) => {
                voice.set_status(LiveKitStatus::Running);
                tokio::select! {
                    exit = child.wait() => {
                        match exit {
                            Ok(status) => tracing::error!(%status, "livekit-server exited, restarting"),
                            Err(e) => tracing::error!(error = %e, "cannot supervise livekit-server, restarting"),
                        }
                    }
                    () = voice.restart_requested() => {
                        // A planned restart: no backoff, clients reconnect within the grace period.
                        terminate(&mut child).await;
                        continue;
                    }
                    () = stop.notified() => {
                        terminate(&mut child).await;
                        voice.set_status(LiveKitStatus::Stopped);
                        return;
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "livekit-server could not be started"),
        }
        if started.elapsed() >= HEALTHY_AFTER {
            backoff = BACKOFF_START;
        }
        voice.set_status(LiveKitStatus::Restarting);
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            // New addresses while waiting: try them at once.
            () = voice.restart_requested() => {}
            () = stop.notified() => {
                voice.set_status(LiveKitStatus::Stopped);
                return;
            }
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

fn spawn(binary: &Path, config_path: &Path, redis_password: Option<&str>) -> anyhow::Result<Child> {
    let mut command = Command::new(binary);
    command
        .arg("--config")
        .arg(config_path)
        // LiveKit reads these as overrides; make sure nothing from the node's environment leaks in.
        .env_remove("LIVEKIT_KEYS")
        .env_remove("LIVEKIT_CONFIG")
        .env_remove("REDIS_HOST")
        .env_remove("REDIS_PASSWORD")
        .env_remove("NODE_IP");
    // The cache password reaches LiveKit as `--redis-password` (environment), never through the config file.
    if let Some(pw) = redis_password {
        command.env("REDIS_PASSWORD", pw);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot start {}", binary.display()))?;
    if let Some(out) = child.stdout.take() {
        tokio::spawn(forward_logs(BufReader::new(out)));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(forward_logs(BufReader::new(err)));
    }
    Ok(child)
}

async fn terminate(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id().and_then(|p| i32::try_from(p).ok()) {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGTERM);
        if tokio::time::timeout(STOP_GRACE, child.wait()).await.is_ok() {
            tracing::info!("livekit-server stopped");
            return;
        }
        tracing::warn!("livekit-server does not respond to SIGTERM, killing it");
    }
    if let Err(e) = child.kill().await {
        tracing::warn!(error = %e, "livekit-server could not be killed");
    }
}

async fn forward_logs<R: tokio::io::AsyncRead + Unpin>(reader: BufReader<R>) {
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let (level, message) = parse_log_line(&line);
        match level {
            LogLevel::Error => tracing::error!(target: "livekit", "{message}"),
            LogLevel::Warn => tracing::warn!(target: "livekit", "{message}"),
            LogLevel::Info => tracing::info!(target: "livekit", "{message}"),
            LogLevel::Debug => tracing::debug!(target: "livekit", "{message}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

/// LiveKit logs JSON lines (`{"level":"info","msg":"…",…}`): level and message plus the remaining fields
/// as `key=value`. Other lines are forwarded unchanged at `info`.
pub fn parse_log_line(line: &str) -> (LogLevel, String) {
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_str::<serde_json::Value>(line) else {
        return (LogLevel::Info, line.to_string());
    };
    let level = match map.remove("level").as_ref().and_then(|v| v.as_str()) {
        Some("error" | "fatal" | "panic" | "dpanic") => LogLevel::Error,
        Some("warn") => LogLevel::Warn,
        Some("debug") => LogLevel::Debug,
        _ => LogLevel::Info,
    };
    let msg = map.remove("msg").and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
    map.remove("ts");
    map.remove("caller");
    map.remove("logger");
    let fields: Vec<String> = map
        .into_iter()
        .map(|(k, v)| match v {
            serde_json::Value::String(s) => format!("{k}={s}"),
            other => format!("{k}={other}"),
        })
        .collect();
    let message = if fields.is_empty() { msg } else { format!("{msg} {}", fields.join(" ")) };
    (level, message)
}

/// `true` if LiveKit answers on its local port (`GET /` → 200 "OK").
pub async fn reachable(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/");
    let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build();
    match client {
        Ok(c) => c.get(url).send().await.is_ok_and(|r| r.status().is_success()),
        Err(_) => false,
    }
}

/// Fails with the install hint if voice is enabled and the binary is missing (`serve`, `check-config`).
pub fn check_binary(config: &Config) -> anyhow::Result<()> {
    if config.voice_enabled && find_binary(&config.livekit_binary).is_none() {
        bail!(missing_binary_error(config));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn settings() -> Settings {
        Settings {
            port: 7880,
            udp_ports: (61000, 61100),
            advertise: plan(&[], false),
            stun_servers: Vec::new(),
            tcp_port: 7881,
            turn: None,
            key_file: PathBuf::from("/data/keys/livekit.key"),
            api_key: "APIabc".into(),
            webhook_url: "http://127.0.0.1:8080/api/v1/voice/webhook".into(),
            max_participants: 50,
            redis: None,
        }
    }

    #[test]
    fn several_instances_form_one_distributed_livekit() {
        assert!(!render_config(&settings()).contains("redis:"), "standalone: no Redis");
        let (redis, password) = redis_of(Some("rediss://tavrn:p%40ss%3Aw@valkey.internal:6380/2")).unwrap();
        assert_eq!(
            redis,
            Redis { address: "valkey.internal:6380".into(), username: Some("tavrn".into()), db: 2, tls: true }
        );
        assert_eq!(password.as_deref().map(String::as_str), Some("p@ss:w"));
        let yaml = render_config(&Settings { redis: Some(redis), ..settings() });
        assert!(
            yaml.contains(
                "redis:\n  address: \"valkey.internal:6380\"\n  username: \"tavrn\"\n  db: 2\n  use_tls: true\n"
            ),
            "{yaml}"
        );
        assert!(!yaml.contains("p@ss"), "the password goes into the environment, not the file");
        let (plain, none) = redis_of(Some("redis://valkey")).unwrap();
        assert_eq!(plain, Redis { address: "valkey:6379".into(), username: None, db: 0, tls: false });
        assert!(none.is_none());
        let yaml = render_config(&Settings { redis: Some(plain), ..settings() });
        assert!(yaml.contains("redis:\n  address: \"valkey:6379\"\n  db: 0\nwebhook:"), "{yaml}");
        // Values cannot inject YAML (written as JSON strings).
        let (evil, _) = redis_of(Some("redis://a%0Aport%3A1@h:1")).unwrap();
        let yaml = render_config(&Settings { redis: Some(evil), ..settings() });
        assert!(yaml.contains("  username: \"a\\nport:1\"\n"), "{yaml}");
        for bad in [None, Some("http://x"), Some("redis://")] {
            assert!(redis_of(bad).is_none(), "{bad:?}");
        }
        // Instances sharing the data directory write their own file.
        let config = Config { data_dir: "/data".into(), ..Config::default() };
        let standalone = crate::cache::Cluster::standalone("n.test", &[0; 32]);
        assert_eq!(config_path(&config, &standalone), PathBuf::from("/data/livekit.yaml"));
        let shared = crate::cache::Cluster::shared_with(
            "n.test",
            "tavrn-2",
            std::sync::Arc::new(crate::cache::memory::InProcess::default()),
            &[0; 32],
            "",
        );
        assert_eq!(config_path(&config, &shared), PathBuf::from("/data/livekit-tavrn-2.yaml"));
    }

    #[test]
    fn key_file_is_created_once_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_key(dir.path()).unwrap();
        assert!(first.key.starts_with("API") && first.key.len() == 15);
        assert_eq!(first.secret.len(), 48);
        let again = load_or_create_key(dir.path()).unwrap();
        assert_eq!((again.key.as_str(), again.secret.as_str()), (first.key.as_str(), first.secret.as_str()));
        let text = std::fs::read_to_string(dir.path().join(KEY_FILE)).unwrap();
        assert_eq!(text, format!("{}: {}\n", first.key, first.secret.as_str()), "LiveKit's key_file format");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "LiveKit refuses key files readable by others");
        }
        assert!(!format!("{first:?}").contains(first.secret.as_str()), "Debug never shows the secret");
    }

    #[test]
    fn broken_key_files_are_rejected() {
        for bad in ["", "nosecret", "API: short", "bad key: 0123456789abcdef0123456789abcdef"] {
            assert!(parse_key(bad).is_none(), "{bad}");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KEY_FILE), "garbage").unwrap();
        assert!(load_or_create_key(dir.path()).unwrap_err().to_string().contains("corrupt"));
    }

    #[test]
    fn config_binds_locally_and_detects_addresses_via_stun() {
        let yaml = render_config(&settings());
        for expected in [
            "port: 7880\n",
            "bind_addresses: [\"127.0.0.1\"]\n",
            "key_file: \"/data/keys/livekit.key\"\n",
            "  port_range_start: 61000\n  port_range_end: 61100\n",
            "  tcp_port: 7881\n  allow_tcp_fallback: true\n",
            "  use_external_ip: true\n  skip_external_ip_validation: true\n  external_ip_only: true\n",
            "  ips:\n    excludes: [\"fe80::/10\", \"169.254.0.0/16\"]\n",
            "turn:\n  enabled: false\n",
            "  max_participants: 50\n",
            "    - mime: audio/opus\n",
            "    - mime: video/vp8\n",
            "  api_key: \"APIabc\"\n",
            "    - \"http://127.0.0.1:8080/api/v1/voice/webhook\"\n",
            "  json: true\n",
        ] {
            assert!(yaml.contains(expected), "missing {expected:?} in\n{yaml}");
        }
        assert!(!yaml.contains("node_ip"), "STUN mode detects the addresses itself");
        assert!(!yaml.contains("fc00::/7"), "the container's ULA is the local side of the detected IPv6 mapping");
        assert!(!yaml.contains("keys:"), "secrets never go into the config file");
        assert!(!yaml.contains("advertise_internal_ip"));
    }

    #[test]
    fn external_ip_is_announced_and_values_cannot_inject_yaml() {
        let s = Settings {
            advertise: plan(&["203.0.113.7".parse().unwrap()], false),
            key_file: PathBuf::from("/data/x\"\nkeys:\n  evil: secret"),
            stun_servers: vec!["stun.example.org:3478\"\nkeys: x".into()],
            ..settings()
        };
        let yaml = render_config(&s);
        assert!(yaml.contains("  use_external_ip: false\n  node_ip: \"203.0.113.7\"\n"), "{yaml}");
        assert!(!yaml.contains("skip_external_ip_validation"));
        // Only IPv4 is known: the container's IPv6 ULA and link-local addresses would be useless candidates.
        assert!(yaml.contains("    excludes: [\"fe80::/10\", \"169.254.0.0/16\", \"fc00::/7\"]\n"), "{yaml}");
        assert!(!yaml.contains("\nkeys:"), "{yaml}");
    }

    #[test]
    fn address_plans_for_every_configuration() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        // Production without addresses: STUN for both families.
        let p = plan(&[], false);
        assert_eq!((p.node_ip.as_deref(), p.stun, p.aliases.len()), (None, true, 0));
        assert_eq!(p.excludes, vec!["fe80::/10", "169.254.0.0/16"]);
        // Development: the local interfaces as they are, nothing excluded.
        assert_eq!(plan(&[], true), Advertise::default());
        // Public IPv4 and the host's global IPv6: both rewrite the container's addresses; the ULA stays
        // (it is the local address that becomes the global IPv6).
        let p = plan(&[ip("203.0.113.7"), ip("2001:db8::5")], false);
        assert_eq!(p.node_ip.as_deref(), Some("203.0.113.7,2001:db8::5"));
        assert!(!p.stun && p.aliases.is_empty());
        assert!(!p.excludes.contains(&"fc00::/7".to_string()));
        // A LAN address for clients at home (no NAT loopback) beyond the first IPv4: a client-side alias.
        let p = plan(&[ip("203.0.113.7"), ip("2001:db8::5"), ip("192.168.0.23"), ip("2001:db8::6")], false);
        assert_eq!(p.node_ip.as_deref(), Some("203.0.113.7,2001:db8::5"));
        assert_eq!(p.aliases, vec!["192.168.0.23", "2001:db8::6"]);
        // Only an IPv6: no IPv4 rewrite, the order of the list decides.
        let p = plan(&[ip("2001:db8::1"), ip("198.51.100.4")], false);
        assert_eq!(p.node_ip.as_deref(), Some("198.51.100.4,2001:db8::1"));
        let p = plan(&[ip("2001:db8::1")], true);
        assert_eq!((p.node_ip.as_deref(), p.excludes.len()), (Some("2001:db8::1"), 0));
        assert!(p.describe().contains("node_ip=2001:db8::1 (explicit)"));
        assert!(plan(&[], false).describe().contains("STUN"));
    }

    #[test]
    fn tcp_fallback_and_turn_are_rendered_when_configured() {
        let off = Settings { tcp_port: 0, ..settings() };
        assert!(render_config(&off).contains("  tcp_port: 0\n  allow_tcp_fallback: false\n"));
        let turn = Settings {
            turn: Some(Turn {
                domain: "turn.chat.example.org".into(),
                udp_port: 3478,
                tls_port: 5349,
                relay_ports: (30000, 30999),
            }),
            ..settings()
        };
        let yaml = render_config(&turn);
        for expected in [
            "  advertise_internal_ip: true\n  enable_loopback_candidate: true\n",
            "turn:\n  enabled: true\n  domain: \"turn.chat.example.org\"\n  tls_port: 5349\n  external_tls: true\n  udp_port: 3478\n",
            "  relay_range_start: 30000\n  relay_range_end: 30999\n",
            "  allow_restricted_peer_cidrs: [\"127.0.0.1/32\", \"::1/128\"]\n",
        ] {
            assert!(yaml.contains(expected), "missing {expected:?} in\n{yaml}");
        }
        assert!(!yaml.contains("cert_file"), "TLS is terminated by the reverse proxy");
        let udp_only =
            Settings { tcp_port: 0, turn: Some(Turn { tls_port: 0, ..turn.turn.clone().unwrap() }), ..settings() };
        let yaml = render_config(&udp_only);
        assert!(yaml.contains("turn:\n  enabled: true\n  udp_port: 3478\n") && !yaml.contains("tls_port"), "{yaml}");
        assert!(yaml.contains("allow_tcp_fallback: false"));
        assert!(turn.describe().contains("TURN udp=3478 tls=5349 (clients use turns:turn.chat.example.org:443"));
        assert!(off.describe().contains("ICE/TCP off; TURN off"));
        assert!(udp_only.describe().ends_with("TURN udp=3478 tls=off"), "{}", udp_only.describe());
    }

    #[test]
    fn settings_follow_the_node_config() {
        let base = Config {
            domain: "chat.example.org".into(),
            database_url: "postgres://x@y/z".into(),
            data_dir: "/data".into(),
            ..Config::default()
        };
        let s = Settings::from_config(&base, "APIk");
        assert_eq!(s.webhook_url, "http://127.0.0.1:8080/api/v1/voice/webhook");
        assert!(s.advertise.stun && s.advertise.node_ip.is_none(), "production detects the public addresses");
        assert_eq!((s.tcp_port, s.udp_ports, s.turn.as_ref()), (7881, (61000, 61100), None));
        assert_eq!(s.key_file, PathBuf::from("/data/keys/livekit.key"));
        let fixed = Config {
            rtc_external_ip: Some("198.51.100.1".into()),
            rtc_advertise_ips: "2001:db8::7, 192.168.0.23,198.51.100.1".into(),
            rtc_stun_servers: "stun.example.org:3478".into(),
            rtc_turn_enabled: true,
            ..base.clone()
        };
        let s = Settings::from_config(&fixed, "APIk");
        assert_eq!(s.advertise.node_ip.as_deref(), Some("198.51.100.1,2001:db8::7"));
        assert_eq!(s.advertise.aliases, vec!["192.168.0.23"], "duplicates of the external IP are dropped");
        assert_eq!(s.stun_servers, vec!["stun.example.org:3478"]);
        let turn = s.turn.unwrap();
        assert_eq!((turn.domain.as_str(), turn.udp_port, turn.tls_port), ("turn.chat.example.org", 3478, 5349));
        let dev = Config { dev: true, listen: "127.0.0.1:8181".into(), rtc_tcp_port: 0, ..base.clone() };
        let s = Settings::from_config(&dev, "APIk");
        assert!(!s.advertise.stun, "development nodes use their local addresses");
        assert_eq!(s.webhook_url, "http://127.0.0.1:8181/api/v1/voice/webhook");
        let v6 = Config { listen: "[::]:9000".into(), ..base };
        assert_eq!(webhook_url(&v6), "http://[::1]:9000/api/v1/voice/webhook");
    }

    #[test]
    fn binaries_are_found_by_path_or_name() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("fake-livekit");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        assert!(find_binary(&bin.to_string_lossy()).is_none(), "not executable yet");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(find_binary(&bin.to_string_lossy()), Some(bin.clone()));
        }
        assert!(find_binary("definitely-not-a-livekit-binary-xyz").is_none());
        assert!(find_binary("sh").is_some(), "bare names are looked up in PATH");
        let config = Config { livekit_binary: "definitely-not-a-livekit-binary-xyz".into(), ..Config::default() };
        let err = check_binary(&config).unwrap_err().to_string();
        assert!(err.contains("just livekit-install") && err.contains("TAVRN_VOICE_ENABLED=false"), "{err}");
        let off = Config { voice_enabled: false, ..config };
        check_binary(&off).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_addresses_restart_livekit_with_a_rewritten_config() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A stand-in for livekit-server: notes every start next to its config and waits.
        let bin = dir.path().join("fake-livekit");
        std::fs::write(&bin, "#!/bin/sh\necho start >> \"$(dirname \"$2\")/starts\"\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = Config {
            domain: "chat.example.org".into(),
            database_url: "postgres://x@y/z".into(),
            data_dir: dir.path().to_string_lossy().into(),
            ..Config::default()
        };
        let voice = Arc::new(crate::voice::VoiceRuntime::new(&config).unwrap());
        let config_path = dir.path().join(CONFIG_FILE);
        std::fs::write(&config_path, render_config(&settings())).unwrap();
        let starts = || std::fs::read_to_string(dir.path().join("starts")).map(|s| s.lines().count()).unwrap_or(0);
        let wait_for = |n: usize| async move {
            for _ in 0..100 {
                if starts() >= n {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        };
        let stop = Arc::new(Notify::new());
        let task = tokio::spawn(supervise(bin, config_path.clone(), settings(), None, voice.clone(), stop.clone()));
        assert!(wait_for(1).await, "livekit started");
        assert_eq!(voice.status(), LiveKitStatus::Running);
        assert!(!std::fs::read_to_string(&config_path).unwrap().contains("node_ip"));

        // The hostname now resolves to another address: the config is rewritten and LiveKit restarted at once.
        voice.set_advertise(plan(&["8.8.8.8".parse().unwrap()], false));
        voice.request_restart();
        assert!(wait_for(2).await, "livekit restarted");
        assert!(std::fs::read_to_string(&config_path).unwrap().contains("  node_ip: \"8.8.8.8\"\n"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(starts(), 2, "one restart per request");

        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(15), task).await.unwrap().unwrap();
        assert_eq!(voice.status(), LiveKitStatus::Stopped);
    }

    #[test]
    fn log_lines_keep_level_message_and_fields() {
        let (level, msg) = parse_log_line(
            r#"{"level":"warn","ts":1.5,"logger":"livekit","caller":"x.go:1","msg":"could not connect","room":"r:c","n":3}"#,
        );
        assert_eq!(level, LogLevel::Warn);
        assert_eq!(msg, "could not connect n=3 room=r:c");
        assert_eq!(parse_log_line(r#"{"level":"error","msg":"boom"}"#), (LogLevel::Error, "boom".into()));
        assert_eq!(parse_log_line("plain text"), (LogLevel::Info, "plain text".into()));
    }
}
