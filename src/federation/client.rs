// SPDX-License-Identifier: AGPL-3.0-only
//! Outbound HTTP client for every request to another node (FEDERATION.md §1.3).
//!
//! Rules enforced here, for every request:
//! - URLs are built from a validated node domain and a path chosen by this node. The discovery document is
//!   always `https://<domain>/.well-known/tavrn`; API paths (`/api/v1/…`) go to the `api` endpoint that
//!   document names, which may live on another host (delegation, FEDERATION.md §1.4). The
//!   endpoint is cached like the document (5 minutes – 1 hour). Resolution order (FEDERATION.md §1.4):
//!   well-known → `_tavrn._tcp.<domain>` SRV record (when the domain serves no document: 404 or no HTTPS
//!   server at all; `TAVRN_FEDERATION_SRV_FALLBACK`) → `https://<domain>/api/v1` (only after a 404). A
//!   transport failure of a cached endpoint resolves the domain again (at most once a minute per domain), so
//!   a moved endpoint takes effect at once. Endpoint and SRV hosts are vetted like the domain itself.
//!   Only development peers (`TAVRN_FEDERATION_DEV_PEERS`, `--dev` only) may use `http` and other hosts.
//! - DNS is resolved by [`VettingResolver`]: if **any** address of the domain is in a non-public range
//!   the request fails with `federation.address_forbidden` (unless `TAVRN_FEDERATION_ALLOW_PRIVATE`).
//!   reqwest connects to exactly the addresses the resolver returned, so a second DNS answer (rebinding)
//!   can never change the target; TLS still verifies the certificate against the domain (SNI, `Host`).
//! - At most 3 redirects, same scheme, host and port only.
//! - Connect timeout 5 s, total 10 s (inbox 15 s); hard response size caps per kind; only 2xx answers are
//!   read, only with the expected content type.
//! - `User-Agent: tavrn-node/<version> (+https://<own domain>)`, no cookies, no environment proxies.
//! - At most 4 concurrent requests per peer and 64 overall; excess requests wait.
//! - GETs are retried once at once after a connection error; inbox POSTs are retried by the outbox.
//! - Domain policy (§1.5): disabled federation, blocklist and allowlist are checked before anything else.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use reqwest::{
    Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{app::SOFTWARE_VERSION, config::Config, error::ApiError};

pub const MAX_REDIRECTS: usize = 3;
/// Path of the discovery document (FEDERATION.md §1.1).
pub const WELL_KNOWN_PATH: &str = "/.well-known/tavrn";
/// Paths under this prefix are sent to the peer's `api` endpoint.
pub const API_PREFIX: &str = "/api/v1";
/// SRV targets tried at most (lowest priority first, then highest weight).
pub const MAX_SRV_TARGETS: usize = 3;
/// A cached endpoint whose requests fail at the transport level is resolved again at most this often per
/// domain (no amplification when a peer is simply down).
pub const RERESOLVE_INTERVAL: Duration = Duration::from_secs(60);
pub const PER_PEER_CONCURRENCY: usize = 4;
pub const TOTAL_CONCURRENCY: usize = 64;
/// A failed or invalid discovery fetch is remembered this long per domain (§1.4).
pub const DISCOVERY_FAILURE_TTL: Duration = Duration::from_secs(60);

/// What is fetched; decides the size cap and the accepted content types (§1.3 rules 5 and 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Discovery,
    Profile,
    Keys,
    Claim,
    Avatar,
    /// Profile headers (§2.7): images like avatars, up to 2 MiB.
    Header,
    Directory,
    /// Custom emoji images of other nodes: converted WebP (older emojis PNG/GIF/JPEG), ≤ 256 KiB.
    Emoji,
    /// Soundboard clips of other nodes: `audio/*`, ≤ 1 MiB.
    Sound,
    /// Public application documents (APPLICATIONS.md §1.8), ≤ 128 KiB.
    Application,
}

/// Content types of avatars (§2.7).
pub const AVATAR_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

impl Kind {
    pub fn max_bytes(self) -> usize {
        match self {
            Self::Discovery => 64 * 1024,
            Self::Profile => 16 * 1024,
            Self::Keys => 256 * 1024,
            Self::Claim => 512 * 1024,
            Self::Avatar | Self::Directory => 1024 * 1024,
            Self::Header => 2 * 1024 * 1024,
            Self::Emoji => 256 * 1024,
            Self::Sound => 1024 * 1024,
            Self::Application => 128 * 1024,
        }
    }

    fn content_types(self) -> &'static [&'static str] {
        match self {
            Self::Avatar | Self::Header | Self::Emoji => AVATAR_TYPES,
            Self::Sound => &[],
            _ => &["application/json"],
        }
    }

    /// Whether a (lowercase, parameter-free) content type is accepted.
    pub fn accepts(self, content_type: &str) -> bool {
        if self == Self::Sound {
            return content_type.strip_prefix("audio/").is_some_and(|sub| {
                !sub.is_empty()
                    && sub.len() <= 64
                    && sub
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'+' | b'-'))
            });
        }
        self.content_types().contains(&content_type)
    }

    fn accept_header(self) -> String {
        match self {
            Self::Avatar | Self::Header | Self::Emoji => AVATAR_TYPES.join(", "),
            Self::Sound => "audio/*".into(),
            _ => "application/json".into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub total: Duration,
    pub inbox: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { connect: Duration::from_secs(5), total: Duration::from_secs(10), inbox: Duration::from_secs(15) }
    }
}

/// Why a request to a peer failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("Federation is disabled on this node")]
    Disabled,
    #[error("This node does not federate with {0}")]
    Blocked(String),
    #[error("Not a valid node domain")]
    DomainInvalid,
    #[error("{0} points to a non-public address")]
    AddressForbidden(String),
    #[error("{0} is unreachable")]
    Unreachable(String),
    #[error("{0} does not answer in time")]
    Timeout(String),
    #[error("The answer from {0} is too large")]
    TooLarge(String),
    #[error("The answer from {0} has an unexpected content type")]
    ContentType(String),
    #[error("{0} sends a disallowed redirect")]
    Redirect(String),
    /// The discovery document names another domain or unusable endpoints.
    #[error("{0} serves an invalid discovery document ({1})")]
    Invalid(String, &'static str),
    #[error("{domain} answers with status {status}")]
    Status { domain: String, status: u16, retry_after: Option<u64> },
    /// A 4xx answer with a problem `code` (signed POSTs only, [`FederationClient::post_json`]).
    #[error("{domain} refuses ({code})")]
    Refused { domain: String, status: u16, code: String, retry_after: Option<u64> },
}

impl FetchError {
    /// Network errors, timeouts, 408, 429 and 5xx are worth retrying (§5.3); everything else is final.
    pub fn retryable(&self) -> bool {
        match self {
            Self::Unreachable(_) | Self::Timeout(_) => true,
            Self::Status { status, .. } | Self::Refused { status, .. } => matches!(status, 408 | 429) || *status >= 500,
            _ => false,
        }
    }

    /// HTTP status of the peer's answer, if there was one.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } | Self::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Status { retry_after, .. } | Self::Refused { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Short machine-readable form for logs and `federation_outbox.last_error` (never peer content).
    pub fn label(&self) -> String {
        match self {
            Self::Disabled => "disabled".into(),
            Self::Blocked(_) => "blocked".into(),
            Self::DomainInvalid => "domain_invalid".into(),
            Self::AddressForbidden(_) => "address_forbidden".into(),
            Self::Unreachable(_) => "unreachable".into(),
            Self::Timeout(_) => "timeout".into(),
            Self::TooLarge(_) => "too_large".into(),
            Self::ContentType(_) => "content_type".into(),
            Self::Redirect(_) => "redirect".into(),
            Self::Invalid(..) => "invalid".into(),
            Self::Status { status, .. } | Self::Refused { status, .. } => format!("status {status}"),
        }
    }

    /// API error for a client of this node whose request needed the peer.
    pub fn to_api(&self) -> ApiError {
        let detail = self.to_string();
        match self {
            Self::Disabled => ApiError::Forbidden { code: "federation.disabled", detail },
            Self::Blocked(_) => ApiError::Forbidden { code: "federation.peer_blocked", detail },
            Self::DomainInvalid => ApiError::BadRequest { code: "federation.domain_invalid", detail },
            Self::AddressForbidden(_) => ApiError::BadGateway { code: "federation.address_forbidden", detail },
            Self::TooLarge(_) | Self::ContentType(_) | Self::Invalid(..) => {
                ApiError::BadGateway { code: "federation.peer_invalid", detail }
            }
            Self::Unreachable(_) | Self::Timeout(_) | Self::Redirect(_) | Self::Status { .. } => {
                ApiError::BadGateway { code: "federation.peer_unreachable", detail }
            }
            Self::Refused { status, code, retry_after, .. } => passed_through(*status, code, *retry_after)
                .unwrap_or(ApiError::BadGateway { code: "federation.peer_unreachable", detail }),
        }
    }
}

/// The 4xx answers of a peer that are passed through to clients (FEDERATION.md §3.5). Codes are matched
/// against a fixed list, so a peer can never inject arbitrary codes or texts.
pub fn passed_through(status: u16, code: &str, retry_after: Option<u64>) -> Option<ApiError> {
    let retry_after_secs = retry_after.unwrap_or(60).clamp(1, 3600) as u32;
    Some(match (status, code) {
        (429, _) => ApiError::RateLimited { retry_after_secs },
        (404, "user.not_found") => ApiError::NotFound { code: "user.not_found", what: "User".into() },
        (403, "federation.claim_refused") => ApiError::Forbidden {
            code: "federation.claim_refused",
            detail: "The home node does not hand out key packages".into(),
        },
        (403, "federation.peer_blocked") => ApiError::Forbidden {
            code: "federation.peer_blocked",
            detail: "The other node does not federate with this node".into(),
        },
        (403, "federation.disabled") => {
            ApiError::Forbidden { code: "federation.disabled", detail: "The other node has disabled federation".into() }
        }
        _ => return None,
    })
}

/// A successful (2xx) answer.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// `Cache-Control: max-age` in seconds, if present.
    pub max_age: Option<u64>,
}

// ---------------------------------------------------------------- address checks

/// `true` if `ip` is not a public unicast address (§1.3 rule 3). IPv4-mapped (`::ffff:0:0/96`), NAT64
/// (`64:ff9b::/96`, `64:ff9b:1::/48`) and 6to4 (`2002::/16`) addresses are checked against their embedded IPv4
/// address; IPv4-compatible (`::/96`) and Teredo (`2001::/32`) addresses are refused.
pub fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    (a == 192 && b == 88 && c == 99) // 192.88.99.0/24 (6to4 relay anycast)
        || a == 0 // 0.0.0.0/8
        || a == 10 // 10.0.0.0/8
        || (a == 100 && (64..128).contains(&b)) // 100.64.0.0/10 (CGNAT)
        || a == 127 // 127.0.0.0/8
        || (a == 169 && b == 254) // 169.254.0.0/16 (link-local, cloud metadata)
        || (a == 172 && (16..32).contains(&b)) // 172.16.0.0/12
        || (a == 192 && b == 0 && (c == 0 || c == 2)) // 192.0.0.0/24, 192.0.2.0/24
        || (a == 192 && b == 168) // 192.168.0.0/16
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15
        || (a == 198 && b == 51 && c == 100) // 198.51.100.0/24
        || (a == 203 && b == 0 && c == 113) // 203.0.113.0/24
        || a >= 224 // 224.0.0.0/4 (multicast), 240.0.0.0/4 (reserved, broadcast)
}

fn embedded_v4(s: &[u16; 8]) -> Ipv4Addr {
    let [hi, lo] = [s[6], s[7]];
    Ipv4Addr::new((hi >> 8) as u8, (hi & 0xff) as u8, (lo >> 8) as u8, (lo & 0xff) as u8)
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if s[..6] == [0, 0, 0, 0, 0, 0xffff] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || s[..3] == [0x64, 0xff9b, 1] {
        // ::ffff:0:0/96 (IPv4-mapped), 64:ff9b::/96 (NAT64) and 64:ff9b:1::/48 (local-use NAT64, RFC 8215):
        // the embedded IPv4 address (the last 32 bits) decides.
        return forbidden_v4(embedded_v4(&s));
    }
    if s[0] == 0x2002 {
        // 2002::/16 (6to4): the IPv4 address in the next 32 bits decides.
        let v4 = Ipv4Addr::new((s[1] >> 8) as u8, (s[1] & 0xff) as u8, (s[2] >> 8) as u8, (s[2] & 0xff) as u8);
        return forbidden_v4(v4);
    }
    s[..6] == [0, 0, 0, 0, 0, 0] // ::/96 (IPv4-compatible, deprecated; includes :: and ::1)
        || (s[0] == 0x2001 && s[1] == 0) // 2001::/32 (Teredo)
        || s[..4] == [0x100, 0, 0, 0] // 100::/64 (discard)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 (documentation)
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 (unique local)
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
        || (s[0] & 0xff00) == 0xff00 // ff00::/8 (multicast)
}

/// The resolver refused a domain because one of its addresses is not public.
#[derive(Debug, thiserror::Error)]
#[error("{0} resolves to a non-public address")]
pub struct AddressForbidden(pub String);

/// DNS lookup, replaceable in tests.
pub trait Lookup: Send + Sync {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>>;
}

/// The operating system resolver (`getaddrinfo` through tokio).
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host.as_str(), 0)).await?.map(|a| a.ip()).collect()) })
    }
}

/// One SRV record (RFC 2782) of `_tavrn._tcp.<domain>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    /// Target host, lowercase, without the trailing dot.
    pub target: String,
}

/// SRV lookup, replaceable in tests.
pub trait SrvLookup: Send + Sync {
    fn srv(&self, name: String) -> BoxFuture<'static, std::io::Result<Vec<SrvRecord>>>;
}

/// SRV lookups with the system's DNS configuration (`/etc/resolv.conf`) through hickory; the resolver is
/// built on first use.
#[derive(Default)]
pub struct SystemSrv {
    resolver: tokio::sync::OnceCell<hickory_resolver::TokioResolver>,
}

impl SrvLookup for SystemSrv {
    fn srv(&self, name: String) -> BoxFuture<'static, std::io::Result<Vec<SrvRecord>>> {
        let resolver = self
            .resolver
            .get()
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| hickory_resolver::TokioResolver::builder_tokio().and_then(|b| b.build()));
        let resolver = match resolver {
            Ok(r) => {
                let _ = self.resolver.set(r.clone());
                r
            }
            Err(e) => return Box::pin(async move { Err(std::io::Error::other(e)) }),
        };
        Box::pin(async move {
            let lookup = resolver.srv_lookup(name).await.map_err(std::io::Error::other)?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    hickory_resolver::proto::rr::RData::SRV(srv) => Some(SrvRecord {
                        priority: srv.priority,
                        weight: srv.weight,
                        port: srv.port,
                        target: srv.target.to_ascii().trim_end_matches('.').to_ascii_lowercase(),
                    }),
                    _ => None,
                })
                .collect())
        })
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// reqwest resolver that vets every address before reqwest connects to it. reqwest connects only to
/// the addresses returned here, so the vetted answer is the one that is used (no second lookup).
#[derive(Clone)]
pub struct VettingResolver {
    lookup: Arc<dyn Lookup>,
    allow_private: bool,
    /// Hosts of development peers (§1.3 rule 8) are not vetted.
    exempt: Arc<HashSet<String>>,
}

impl VettingResolver {
    pub fn new(lookup: Arc<dyn Lookup>, allow_private: bool, exempt: HashSet<String>) -> Self {
        Self { lookup, allow_private, exempt: Arc::new(exempt) }
    }

    /// Resolves `host` and returns its addresses if all of them may be contacted.
    pub async fn vetted(&self, host: &str) -> Result<Vec<IpAddr>, BoxError> {
        let addrs = self.lookup.lookup(host.to_string()).await?;
        if addrs.is_empty() {
            return Err(format!("{host}: no addresses").into());
        }
        let checked = !self.allow_private && !self.exempt.contains(host);
        if checked && addrs.iter().any(|ip| forbidden_ip(*ip)) {
            return Err(Box::new(AddressForbidden(host.to_string())));
        }
        Ok(addrs)
    }
}

impl Resolve for VettingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let this = self.clone();
        Box::pin(async move {
            let addrs = this.vetted(&host).await?;
            let iter: Addrs = Box::new(addrs.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(iter)
        })
    }
}

// ---------------------------------------------------------------- client

/// Settings of the client that tests may change.
pub struct ClientOptions {
    pub timeouts: Timeouts,
    pub lookup: Arc<dyn Lookup>,
    pub srv: Arc<dyn SrvLookup>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self { timeouts: Timeouts::default(), lookup: Arc::new(SystemLookup), srv: Arc::new(SystemSrv::default()) }
    }
}

/// Where the discovery document of a peer was found and its API lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DelegationSource {
    /// `https://<domain>/.well-known/tavrn` (its `api` may name another host).
    WellKnown,
    /// The document came from the target of `_tavrn._tcp.<domain>` (the domain serves none).
    Srv,
    /// No document and no SRV record (404): `https://<domain>/api/v1`.
    #[serde(rename = "domain")]
    Fallback,
}

/// The endpoints of a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Where this node sends API requests: the `api` URL without trailing slash, e.g.
    /// `https://app.tavrn.org/api/v1` (in development possibly mapped to a development peer's base URL).
    pub api: Url,
    /// The `api` URL as the document declares it (`https://<domain>/api/v1` without a document): what
    /// browsers use, never a development mapping.
    pub public_api: Url,
    /// The WebSocket URL as declared, e.g. `wss://app.tavrn.org/api/v1/ws`.
    pub ws: Url,
    /// Origin of the peer's web client (`https://<domain>` when the document names none).
    pub web: Url,
    pub source: DelegationSource,
}

/// A cached delegation, valid `until`; `reresolved_at` (kept when the entry is replaced) bounds the
/// re-resolutions after failures ([`RERESOLVE_INTERVAL`]).
#[derive(Debug, Clone)]
struct CachedDelegation {
    delegation: Delegation,
    until: Instant,
    reresolved_at: Option<Instant>,
}

/// `true` for failures of a request that suggest the endpoint itself is gone (moved host, stale record):
/// connection refused or reset, timeouts, TLS errors and the 502/503/504 answers of a proxy without upstream.
pub fn endpoint_failure(e: &FetchError) -> bool {
    matches!(e, FetchError::Unreachable(_) | FetchError::Timeout(_)) || matches!(e.status(), Some(502..=504))
}

/// API paths go to the peer's (possibly delegated) `api` endpoint.
fn api_rest(path: &str) -> Option<&str> {
    path.strip_prefix(API_PREFIX).filter(|r| r.is_empty() || r.starts_with(['/', '?']))
}

pub struct FederationClient {
    http: reqwest::Client,
    /// The vetting resolver of `http`, kept for requests pinned to one address ([`Self::get_each_address`]).
    resolver: VettingResolver,
    own_domain: String,
    enabled: bool,
    blocklist: Vec<String>,
    allowlist: Vec<String>,
    dev_peers: HashMap<String, Url>,
    timeouts: Timeouts,
    total: Arc<Semaphore>,
    per_peer: Mutex<HashMap<String, Arc<Semaphore>>>,
    dev: bool,
    allow_private: bool,
    srv: Arc<dyn SrvLookup>,
    srv_fallback: bool,
    /// API endpoints of peers with their expiry (cached like the documents, §1.4).
    delegations: Mutex<HashMap<String, CachedDelegation>>,
    /// Domains whose endpoint moved: their cached document (and keys) is refetched on next use.
    stale_documents: Mutex<HashSet<String>>,
    /// How long a request waits for a connection slot of its peer and then a node-wide one.
    permit_timeout: Duration,
    /// Recent failed or invalid discovery fetches per domain, with the error to answer (§1.4).
    discovery_failures: Mutex<HashMap<String, (Instant, &'static str, String)>>,
}

impl FederationClient {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        Self::with_options(config, ClientOptions::default())
    }

    pub fn with_options(config: &Config, options: ClientOptions) -> anyhow::Result<Self> {
        let dev_peers =
            if config.dev { config.federation_dev_peers().map_err(anyhow::Error::msg)? } else { HashMap::new() };
        let exempt = dev_peers.values().filter_map(|u| u.host_str().map(String::from)).collect();
        let resolver = VettingResolver::new(options.lookup, config.federation_allow_private, exempt);
        let http = http_builder(&config.domain, &resolver, &options.timeouts).build()?;
        Ok(Self {
            http,
            resolver,
            own_domain: config.domain.clone(),
            enabled: config.federation_enabled,
            blocklist: config.federation_blocklist(),
            allowlist: config.federation_allowlist(),
            dev_peers,
            timeouts: options.timeouts,
            total: Arc::new(Semaphore::new(TOTAL_CONCURRENCY)),
            per_peer: Mutex::new(HashMap::new()),
            dev: config.dev,
            allow_private: config.federation_allow_private,
            srv: options.srv,
            srv_fallback: config.federation_srv_fallback,
            delegations: Mutex::new(HashMap::new()),
            stale_documents: Mutex::new(HashSet::new()),
            permit_timeout: Duration::from_secs(u64::from(config.federation_permit_timeout_secs.max(1))),
            discovery_failures: Mutex::new(HashMap::new()),
        })
    }

    /// Domain policy from the configuration (§1.5 steps 1–3; node bans are checked by the callers). A
    /// blocklist entry also blocks its subdomains; the allowlist names exact domains.
    pub fn check_policy(&self, domain: &str) -> Result<(), FetchError> {
        if !self.enabled {
            return Err(FetchError::Disabled);
        }
        if !super::valid_node_domain(domain) || domain == self.own_domain {
            return Err(FetchError::DomainInvalid);
        }
        if self.blocklist.iter().any(|d| domain == d || domain.ends_with(&format!(".{d}"))) {
            return Err(FetchError::Blocked(domain.to_string()));
        }
        if !self.allowlist.is_empty() && !self.allowlist.iter().any(|d| d == domain) {
            return Err(FetchError::Blocked(domain.to_string()));
        }
        Ok(())
    }

    /// `https://<domain><path>` on the domain itself (the discovery document, the 404 fallback), or the
    /// development peer's base URL with `path`.
    pub fn url(&self, domain: &str, path: &str) -> Result<Url, FetchError> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(FetchError::DomainInvalid);
        }
        match self.dev_peers.get(domain) {
            Some(base) => base.join(path).map_err(|_| FetchError::DomainInvalid),
            None => Url::parse(&format!("https://{domain}{path}")).map_err(|_| FetchError::DomainInvalid),
        }
    }

    /// A connection slot of the peer, then a node-wide one (§1.3 rule 5): requests queued for a slow peer never hold
    /// node-wide slots, so they cannot starve requests to every other peer. Both waits together are bounded by
    /// `TAVRN_FEDERATION_PERMIT_TIMEOUT_SECS` (then [`FetchError::Timeout`]).
    async fn permits(&self, domain: &str) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), FetchError> {
        let peer = {
            let mut map = self.per_peer.lock().unwrap_or_else(|e| e.into_inner());
            // Idle peers (no request holds or waits for a slot) are dropped: unsigned requests naming random
            // domains cannot grow the map.
            map.retain(|d, sem| d == domain || Arc::strong_count(sem) > 1);
            map.entry(domain.to_string()).or_insert_with(|| Arc::new(Semaphore::new(PER_PEER_CONCURRENCY))).clone()
        };
        let closed = |_| FetchError::Unreachable(domain.to_string());
        let acquire = async {
            let peer = peer.acquire_owned().await.map_err(closed)?;
            let total = self.total.clone().acquire_owned().await.map_err(closed)?;
            Ok::<_, FetchError>((total, peer))
        };
        match tokio::time::timeout(self.permit_timeout, acquire).await {
            Ok(permits) => permits,
            Err(_) => {
                tracing::warn!(domain, "no free connection slot for the peer in time");
                Err(FetchError::Timeout(domain.to_string()))
            }
        }
    }

    /// The error of a failed or invalid discovery fetch of `domain` within the last [`DISCOVERY_FAILURE_TTL`].
    pub fn recent_discovery_failure(&self, domain: &str) -> Option<ApiError> {
        let map = self.discovery_failures.lock().unwrap_or_else(|e| e.into_inner());
        map.get(domain)
            .filter(|(at, ..)| at.elapsed() < DISCOVERY_FAILURE_TTL)
            .map(|(_, code, detail)| ApiError::BadGateway { code, detail: detail.clone() })
    }

    /// Remembers a failed or invalid discovery fetch of `domain` (a peer error, `502`; bounded: expired entries are
    /// dropped first, and at most 10 000 domains are kept).
    pub fn note_discovery_failure(&self, domain: &str, error: &ApiError) {
        let ApiError::BadGateway { code, detail } = error else { return };
        let mut map = self.discovery_failures.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (at, ..)| at.elapsed() < DISCOVERY_FAILURE_TTL);
        if map.len() < 10_000 {
            map.insert(domain.to_string(), (Instant::now(), code, detail.clone()));
        }
    }

    /// Forgets a failure after a successful fetch.
    pub fn clear_discovery_failure(&self, domain: &str) {
        self.discovery_failures.lock().unwrap_or_else(|e| e.into_inner()).remove(domain);
    }

    /// The URL of `path` on `domain`: API paths on the peer's (possibly delegated) `api` endpoint, every other
    /// path on the domain itself.
    pub async fn target(&self, domain: &str, path: &str) -> Result<Url, FetchError> {
        let Some(rest) = api_rest(path) else {
            return self.url(domain, path);
        };
        let api = self.delegation(domain).await?.api;
        let url = Url::parse(&format!("{}{rest}", api.as_str().trim_end_matches('/')))
            .map_err(|_| FetchError::DomainInvalid)?;
        if url.host_str() != api.host_str() || url.port_or_known_default() != api.port_or_known_default() {
            return Err(FetchError::DomainInvalid);
        }
        Ok(url)
    }

    /// The endpoints of `domain` (FEDERATION.md §1.4): cached, otherwise resolved in the order
    /// well-known → SRV → `https://<domain>/api/v1` ([`Self::get_well_known`]); only a missing document with
    /// no usable SRV record falls back to the domain itself; every other error fails.
    pub async fn delegation(&self, domain: &str) -> Result<Delegation, FetchError> {
        if let Some(d) = self.cached_delegation(domain) {
            return Ok(d);
        }
        self.resolve(domain).await
    }

    /// Resolves `domain` without looking at the cache and caches the result.
    async fn resolve(&self, domain: &str) -> Result<Delegation, FetchError> {
        match self.get_well_known(domain).await {
            Ok((fetched, source)) => {
                let ttl = super::discovery::ttl(fetched.max_age);
                self.record_delegation(domain, &fetched.body, ttl, source)
                    .map_err(|reason| FetchError::Invalid(domain.to_string(), reason))
            }
            Err(FetchError::Status { status: 404, .. }) => {
                let api = self.url(domain, API_PREFIX)?;
                let public = |url: &str| Url::parse(url).map_err(|_| FetchError::DomainInvalid);
                let delegation = Delegation {
                    api,
                    public_api: public(&format!("https://{domain}{API_PREFIX}"))?,
                    ws: public(&format!("wss://{domain}{API_PREFIX}/ws"))?,
                    web: public(&format!("https://{domain}"))?,
                    source: DelegationSource::Fallback,
                };
                tracing::info!(domain, "no discovery document and no SRV record, using https://<domain>/api/v1");
                self.cache_delegation(domain, delegation.clone(), super::discovery::MIN_TTL_SECS);
                Ok(delegation)
            }
            Err(e) => Err(e),
        }
    }

    /// After a transport failure ([`endpoint_failure`]) of `failed`, a URL on the cached endpoint of
    /// `domain`: resolves the domain again, at most once per [`RERESOLVE_INTERVAL`] and domain, so a changed
    /// well-known or SRV record takes effect at once instead of after the cache lifetime. When the endpoint
    /// moved, the new one replaces the cached one, the cached document (keys) of the peer is marked for a
    /// refetch, and the URL of `path` on the new endpoint is returned. A failing re-resolution keeps the
    /// previous endpoint until its lifetime ends.
    pub async fn reresolve(&self, domain: &str, path: &str, failed: &Url) -> Option<Url> {
        api_rest(path)?;
        {
            let mut map = self.delegations.lock().unwrap_or_else(|e| e.into_inner());
            let entry = map.get_mut(domain)?;
            let now = Instant::now();
            if entry.reresolved_at.is_some_and(|at| now.duration_since(at) < RERESOLVE_INTERVAL) {
                return None;
            }
            // Claimed before resolving: concurrent failures do not resolve the same domain again.
            entry.reresolved_at = Some(now);
        }
        match self.resolve(domain).await {
            Ok(_) => {
                let url = self.target(domain, path).await.ok()?;
                if &url == failed {
                    tracing::debug!(domain, "peer endpoint unchanged after a failure");
                    return None;
                }
                tracing::info!(domain, old = %failed, new = %url, "peer endpoint moved, using the new one");
                self.stale_documents.lock().unwrap_or_else(|e| e.into_inner()).insert(domain.to_string());
                Some(url)
            }
            Err(e) => {
                tracing::warn!(domain, result = %e.label(), "peer not resolvable again, keeping its endpoint");
                None
            }
        }
    }

    /// Whether the endpoint of `domain` moved since its document was cached (the flag is cleared): the
    /// document and its keys must be fetched again ([`super::discovery::document`]).
    pub fn take_stale_document(&self, domain: &str) -> bool {
        self.stale_documents.lock().unwrap_or_else(|e| e.into_inner()).remove(domain)
    }

    /// The cached API endpoint of `domain`, if still fresh.
    pub fn cached_delegation(&self, domain: &str) -> Option<Delegation> {
        let map = self.delegations.lock().unwrap_or_else(|e| e.into_inner());
        map.get(domain).filter(|c| c.until > Instant::now()).map(|c| c.delegation.clone())
    }

    /// How long the cached API endpoint of `domain` stays valid (`None` when there is none).
    pub fn delegation_expires_in(&self, domain: &str) -> Option<Duration> {
        let map = self.delegations.lock().unwrap_or_else(|e| e.into_inner());
        map.get(domain).and_then(|c| c.until.checked_duration_since(Instant::now()))
    }

    fn cache_delegation(&self, domain: &str, delegation: Delegation, ttl_secs: u64) {
        let mut map = self.delegations.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let reresolved_at = map.get(domain).and_then(|c| c.reresolved_at);
        map.retain(|_, c| c.until > now);
        map.insert(
            domain.to_string(),
            CachedDelegation { delegation, until: now + Duration::from_secs(ttl_secs), reresolved_at },
        );
    }

    /// Validates the endpoints of a discovery document fetched for `domain` (the document must name
    /// `domain`; `api` and `ws` must be `https`/`wss` URLs without credentials, query or fragment, `http`
    /// only in development mode; IP hosts only in development mode and, unless private peers are allowed,
    /// public) and caches the API endpoint for `ttl_secs`. Hosts are vetted again on every connection.
    pub fn record_delegation(
        &self,
        domain: &str,
        body: &[u8],
        ttl_secs: u64,
        source: DelegationSource,
    ) -> Result<Delegation, &'static str> {
        let delegation = self.parse_delegation(domain, body, source)?;
        self.cache_delegation(domain, delegation.clone(), ttl_secs);
        Ok(delegation)
    }

    fn parse_delegation(
        &self,
        domain: &str,
        body: &[u8],
        source: DelegationSource,
    ) -> Result<Delegation, &'static str> {
        let doc: serde_json::Value = serde_json::from_slice(body).map_err(|_| "not JSON")?;
        if doc.get("domain").and_then(|d| d.as_str()) != Some(domain) {
            return Err("domain does not match");
        }
        let text = |field: &str| doc.get(field).and_then(|v| v.as_str()).ok_or("required field missing");
        let api = endpoint(text("api")?, "https", "http", self.dev, self.allow_private)?;
        if !api.path().trim_end_matches('/').ends_with(API_PREFIX) {
            return Err("api does not end in /api/v1");
        }
        let ws = endpoint(text("ws")?, "wss", "ws", self.dev, self.allow_private)?;
        // `web` only matters to browsers (the node's peer resolution): an unusable one is ignored.
        let web = match doc
            .get("web")
            .and_then(|v| v.as_str())
            .map(|w| endpoint(w, "https", "http", self.dev, self.allow_private))
        {
            Some(Ok(web)) => web,
            _ => Url::parse(&format!("https://{domain}")).map_err(|_| "invalid endpoint")?,
        };
        let api = Url::parse(api.as_str().trim_end_matches('/')).map_err(|_| "invalid endpoint")?;
        Ok(self.map_dev_host(Delegation { api: api.clone(), public_api: api, ws, web, source }))
    }

    /// Puts the endpoint of a cached document (`federation_peers`) into the cache when it is not there yet,
    /// so a restarted node does not refetch a fresh document just for its endpoints.
    pub fn seed_delegation(&self, domain: &str, body: &[u8], ttl_secs: u64) {
        if ttl_secs > 0 && self.cached_delegation(domain).is_none() {
            let _ = self.record_delegation(domain, body, ttl_secs, DelegationSource::WellKnown);
        }
    }

    /// Development: an endpoint on the host of a development peer (`a.test`) is reached through its mapping
    /// (only this node's transport; browsers get the declared endpoints).
    fn map_dev_host(&self, mut delegation: Delegation) -> Delegation {
        if let Some(base) = delegation.api.host_str().and_then(|h| self.dev_peers.get(h))
            && let Ok(mapped) = base.join(delegation.api.path())
        {
            delegation.api = mapped;
        }
        delegation
    }

    /// The discovery document of `domain` (FEDERATION.md §1.4), in this order:
    ///
    /// 1. `https://<domain>/.well-known/tavrn`;
    /// 2. when the domain serves none (404, or no HTTPS server at all: connection refused, TLS failure,
    ///    timeout) and `TAVRN_FEDERATION_SRV_FALLBACK` is on: the targets of `_tavrn._tcp.<domain>` (vetted
    ///    hosts; the caller checks that the document names `domain`). Development peers use SRV only after a
    ///    404 (a stopped development peer fails at once);
    /// 3. otherwise the original error; a 404 then makes [`Self::delegation`] fall back to
    ///    `https://<domain>/api/v1`. A refused address is final at every step.
    ///
    /// Returns where the document was found.
    pub async fn get_well_known(&self, domain: &str) -> Result<(Fetched, DelegationSource), FetchError> {
        self.check_policy(domain)?;
        let url = self.url(domain, WELL_KNOWN_PATH)?;
        let err = match self.get_url(domain, url, Kind::Discovery).await {
            Ok(fetched) => return Ok((fetched, DelegationSource::WellKnown)),
            Err(e) => e,
        };
        let missing = matches!(err, FetchError::Status { status: 404, .. });
        let no_server =
            matches!(err, FetchError::Unreachable(_) | FetchError::Timeout(_)) && !self.dev_peers.contains_key(domain);
        if !self.srv_fallback || !(missing || no_server) {
            return Err(err);
        }
        match self.srv_well_known(domain).await {
            Some(Ok(fetched)) => Ok((fetched, DelegationSource::Srv)),
            Some(Err(e @ FetchError::AddressForbidden(_))) => Err(e),
            // No reachable target: a website without a document still gets the direct attempt.
            Some(Err(_)) if missing => Err(err),
            Some(Err(e)) => Err(e),
            None => Err(err),
        }
    }

    /// The discovery document from the SRV targets of `domain` (`None` when there is no usable record).
    /// Targets must be node domains (no IP literals); they are vetted like any other host. The record only says
    /// where to connect (§1.3): the request goes to the target's vetted addresses and port, but as
    /// `https://<domain>:<port>/.well-known/tavrn`, so SNI, `Host` and the certificate check are for `domain`; a
    /// target whose certificate is valid only for itself fails the TLS handshake. DNS alone never decides whose keys
    /// these are.
    async fn srv_well_known(&self, domain: &str) -> Option<Result<Fetched, FetchError>> {
        let records = match self.srv.srv(format!("_tavrn._tcp.{domain}.")).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(domain, error = %e, "no SRV record");
                return None;
            }
        };
        let mut records: Vec<SrvRecord> =
            records.into_iter().filter(|r| r.port != 0 && super::valid_node_domain(&r.target)).collect();
        records.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));
        let scheme = if self.dev { "http" } else { "https" };
        let mut last = None;
        for record in records.iter().take(MAX_SRV_TARGETS) {
            let Some(url) = srv_url(scheme, domain, record.port) else { continue };
            match self.get_via_target(domain, url, &record.target, record.port).await {
                Ok(fetched) => {
                    tracing::info!(domain, target = record.target, port = record.port, "discovery document via SRV");
                    return Some(Ok(fetched));
                }
                Err(e @ FetchError::AddressForbidden(_)) => return Some(Err(e)),
                Err(e) => {
                    tracing::warn!(domain, target = record.target, result = %e.label(), "SRV target failed");
                    last = Some(Err(e));
                }
            }
        }
        last
    }

    /// GET the discovery document `url` (on `domain`) through the vetted addresses of an SRV `target`: a client of
    /// its own resolves `domain` to exactly those addresses, everything else (TLS name, `Host`) stays `domain`'s.
    async fn get_via_target(&self, domain: &str, url: Url, target: &str, port: u16) -> Result<Fetched, FetchError> {
        let addrs = self.resolver.vetted(target).await.map_err(|e| {
            if e.downcast_ref::<AddressForbidden>().is_some() {
                FetchError::AddressForbidden(domain.to_string())
            } else {
                FetchError::Unreachable(domain.to_string())
            }
        })?;
        let addrs: Vec<SocketAddr> = addrs.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
        let http = http_builder(&self.own_domain, &self.resolver, &self.timeouts)
            .resolve_to_addrs(domain, &addrs)
            .build()
            .map_err(|_| FetchError::Unreachable(domain.to_string()))?;
        let _permits = self.permits(domain).await?;
        let response = http
            .get(url)
            .header(header::ACCEPT, Kind::Discovery.accept_header())
            .send()
            .await
            .map_err(|e| classify(domain, &e))?;
        read_get(domain, response, Kind::Discovery).await
    }

    /// GET a public document of a peer (the discovery document through [`Self::get_well_known`]).
    pub async fn get(&self, domain: &str, path: &str, kind: Kind) -> Result<Fetched, FetchError> {
        self.check_policy(domain)?;
        if path == WELL_KNOWN_PATH {
            return self.get_well_known(domain).await.map(|(fetched, _)| fetched);
        }
        let url = self.target(domain, path).await?;
        match self.get_url(domain, url.clone(), kind).await {
            // GETs are idempotent: once more on the endpoint the domain names now, if it moved.
            Err(e) if endpoint_failure(&e) => match self.reresolve(domain, path, &url).await {
                Some(moved) => self.get_url(domain, moved, kind).await,
                None => Err(e),
            },
            other => other,
        }
    }

    /// GET `url` (already resolved for `domain`) with the rules of [`Self::get`].
    async fn get_url(&self, domain: &str, url: Url, kind: Kind) -> Result<Fetched, FetchError> {
        let _permits = self.permits(domain).await?;
        let accept = kind.accept_header();
        let send = || self.http.get(url.clone()).header(header::ACCEPT, accept.clone()).send();
        // GETs are idempotent: a connection error (e.g. a pooled keep-alive connection the peer just
        // closed) is retried once at once; timeouts and HTTP errors are not.
        let response = match send().await.map_err(|e| classify(domain, &e)) {
            Err(FetchError::Unreachable(_)) => send().await.map_err(|e| classify(domain, &e))?,
            other => other?,
        };
        read_get(domain, response, kind).await
    }

    /// GET `path` from **every** address `domain` resolves to (at most [`MAX_ADDRESSES`], each vetted like
    /// any other request), one request per address, with the same rules as [`Self::get`] but no retry.
    /// Used by `keys.consistent` (FEDERATION.md §9.1) to detect a peer that shows different documents on
    /// different addresses (for example IPv4 and IPv6). A development peer mapped to an IP literal has
    /// that single address.
    pub async fn get_each_address(
        &self,
        domain: &str,
        path: &str,
        kind: Kind,
    ) -> Result<Vec<(IpAddr, Result<Fetched, FetchError>)>, FetchError> {
        self.check_policy(domain)?;
        let url = self.url(domain, path)?;
        let host = url.host_str().ok_or(FetchError::DomainInvalid)?.to_string();
        let port = url.port_or_known_default().ok_or(FetchError::DomainInvalid)?;
        let mut addrs = match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.resolver.vetted(&host).await.map_err(|e| {
                if e.downcast_ref::<AddressForbidden>().is_some() {
                    FetchError::AddressForbidden(domain.to_string())
                } else {
                    FetchError::Unreachable(domain.to_string())
                }
            })?,
        };
        let mut seen = HashSet::new();
        addrs.retain(|ip| seen.insert(*ip));
        addrs.truncate(MAX_ADDRESSES);
        let accept = if kind == Kind::Avatar { AVATAR_TYPES.join(", ") } else { "application/json".into() };
        let mut out = Vec::with_capacity(addrs.len());
        for ip in addrs {
            // A client of its own that knows exactly this (already vetted) address for the host.
            let pinned = http_builder(&self.own_domain, &self.resolver, &self.timeouts)
                .resolve(&host, SocketAddr::new(ip, port))
                .build()
                .map_err(|_| FetchError::Unreachable(domain.to_string()));
            let result = match pinned {
                Ok(http) => {
                    let _permits = self.permits(domain).await?;
                    match http.get(url.clone()).header(header::ACCEPT, accept.clone()).send().await {
                        Ok(response) => read_get(domain, response, kind).await,
                        Err(e) => Err(classify(domain, &e)),
                    }
                }
                Err(e) => Err(e),
            };
            out.push((ip, result));
        }
        Ok(out)
    }

    /// POST a signed JSON request (node token in `token`) and read the JSON answer with the cap of `kind`.
    /// A 4xx answer becomes [`FetchError::Refused`] carrying the problem `code` (at most 64 characters).
    pub async fn post_json(
        &self,
        domain: &str,
        path: &str,
        token: &str,
        body: Vec<u8>,
        kind: Kind,
    ) -> Result<Fetched, FetchError> {
        self.check_policy(domain)?;
        let url = self.target(domain, path).await?;
        let result = self.post_json_to(domain, url.clone(), token, body, kind).await;
        self.after_failure(domain, path, &url, &result).await;
        result
    }

    /// Signed POSTs are not repeated (claims consume key packages, the outbox retries the inbox): a transport
    /// failure only resolves the domain again, so the next attempt reaches a moved endpoint.
    async fn after_failure<T>(&self, domain: &str, path: &str, url: &Url, result: &Result<T, FetchError>) {
        if let Err(e) = result
            && endpoint_failure(e)
        {
            self.reresolve(domain, path, url).await;
        }
    }

    async fn post_json_to(
        &self,
        domain: &str,
        url: Url,
        token: &str,
        body: Vec<u8>,
        kind: Kind,
    ) -> Result<Fetched, FetchError> {
        let _permits = self.permits(domain).await?;
        let response = self
            .http
            .post(url)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .map_err(|e| classify(domain, &e))?;
        let status = response.status();
        if status.is_client_error() {
            let retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok());
            let problem = read_capped(domain, response, 16 * 1024).await.unwrap_or_default();
            let code = serde_json::from_slice::<serde_json::Value>(&problem)
                .ok()
                .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(|c| c.chars().take(64).collect()))
                .unwrap_or_default();
            return Err(FetchError::Refused { domain: domain.to_string(), status: status.as_u16(), code, retry_after });
        }
        let response = success(domain, response)?;
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
            .unwrap_or_default();
        if !kind.accepts(&content_type) {
            return Err(FetchError::ContentType(domain.to_string()));
        }
        let status = response.status().as_u16();
        let body = read_capped(domain, response, kind.max_bytes()).await?;
        Ok(Fetched { status, content_type, body, max_age: None })
    }

    /// POST a signed notification to the peer's inbox. Returns the (2xx) status; the body is not read.
    pub async fn post_inbox(&self, domain: &str, token: &str, body: Vec<u8>) -> Result<u16, FetchError> {
        self.check_policy(domain)?;
        let url = self.target(domain, super::inbox::INBOX_PATH).await?;
        let result = self.post_inbox_to(domain, url.clone(), token, body).await;
        self.after_failure(domain, super::inbox::INBOX_PATH, &url, &result).await;
        result
    }

    async fn post_inbox_to(&self, domain: &str, url: Url, token: &str, body: Vec<u8>) -> Result<u16, FetchError> {
        let _permits = self.permits(domain).await?;
        let response = self
            .http
            .post(url)
            .timeout(self.timeouts.inbox)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(body)
            .send()
            .await
            .map_err(|e| classify(domain, &e))?;
        Ok(success(domain, response)?.status().as_u16())
    }
}

/// The answer of a peer to a conformance probe ([`FederationClient::probe`]), whatever its status.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    /// The problem `code` of an error answer (at most 64 characters), if any.
    pub code: Option<String>,
    pub retry_after: Option<u64>,
    /// The `Date` header (§9.1 `time.skew`).
    pub date: Option<String>,
    pub body: Vec<u8>,
}

/// Largest answer read by a conformance probe (MLS group information, Welcomes).
pub const PROBE_MAX_BYTES: usize = 1024 * 1024;

impl FederationClient {
    /// A request of the conformance checks (FEDERATION.md §9.1) to the normal client API or the inbox of
    /// a peer: same target, address, redirect, timeout and concurrency rules as every other request,
    /// but every status is returned (the checks need to see refusals), the body is read up to
    /// [`PROBE_MAX_BYTES`] whatever its content type, and nothing is retried.
    pub async fn probe(
        &self,
        domain: &str,
        method: reqwest::Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<ProbeResponse, FetchError> {
        self.check_policy(domain)?;
        let url = self.target(domain, path).await?;
        let result = self.probe_to(domain, method, url.clone(), bearer, body).await;
        self.after_failure(domain, path, &url, &result).await;
        result
    }

    async fn probe_to(
        &self,
        domain: &str,
        method: reqwest::Method,
        url: Url,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<ProbeResponse, FetchError> {
        let _permits = self.permits(domain).await?;
        let mut request = self.http.request(method, url).header(header::ACCEPT, "application/json");
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json").body(body);
        }
        let response = request.send().await.map_err(|e| classify(domain, &e))?;
        let status = response.status().as_u16();
        let text = |name: header::HeaderName| {
            response.headers().get(name).and_then(|v| v.to_str().ok()).map(|v| v.trim().to_string())
        };
        let retry_after = text(header::RETRY_AFTER).and_then(|v| v.parse().ok());
        let date = text(header::DATE);
        let body = read_capped(domain, response, PROBE_MAX_BYTES).await?;
        let code = (status >= 400)
            .then(|| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .flatten()
            .and_then(|v| v.get("code").and_then(|c| c.as_str()).map(|c| c.chars().take(64).collect()));
        Ok(ProbeResponse { status, code, retry_after, date, body })
    }
}

/// Addresses of one peer fetched by [`FederationClient::get_each_address`].
pub const MAX_ADDRESSES: usize = 8;

/// The URL of the discovery document reached through an SRV record (§1.3): on the identity domain, with the
/// record's port, so TLS and `Host` are for the domain whichever host serves it.
pub fn srv_url(scheme: &str, domain: &str, port: u16) -> Option<Url> {
    Url::parse(&format!("{scheme}://{domain}:{port}{WELL_KNOWN_PATH}")).ok()
}

/// The settings every client of this module shares (resolver, redirects, timeouts, no proxies).
fn http_builder(own_domain: &str, resolver: &VettingResolver, timeouts: &Timeouts) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(user_agent(own_domain))
        .dns_resolver(Arc::new(resolver.clone()))
        .redirect(redirect_policy())
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.total)
        .no_proxy()
}

/// Reads a GET answer: 2xx only, the content type of `kind`, at most `kind`'s size.
async fn read_get(domain: &str, response: reqwest::Response, kind: Kind) -> Result<Fetched, FetchError> {
    let response = success(domain, response)?;
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !kind.accepts(&content_type) {
        return Err(FetchError::ContentType(domain.to_string()));
    }
    let max_age = response.headers().get(header::CACHE_CONTROL).and_then(|v| v.to_str().ok()).and_then(parse_max_age);
    let status = response.status().as_u16();
    let body = read_capped(domain, response, kind.max_bytes()).await?;
    Ok(Fetched { status, content_type, body, max_age })
}

pub fn user_agent(own_domain: &str) -> String {
    format!("tavrn-node/{SOFTWARE_VERSION} (+https://{own_domain})")
}

fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let previous = attempt.previous();
        let next = attempt.url();
        let allowed = previous.len() <= MAX_REDIRECTS
            && previous.first().is_some_and(|first| {
                next.scheme() == first.scheme()
                    && next.host_str() == first.host_str()
                    && next.port_or_known_default() == first.port_or_known_default()
            });
        if allowed { attempt.follow() } else { attempt.error("redirect refused") }
    })
}

/// Non-2xx answers become [`FetchError::Status`] (with `Retry-After` in seconds if present).
fn success(domain: &str, response: reqwest::Response) -> Result<reqwest::Response, FetchError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if status.is_redirection() {
        return Err(FetchError::Redirect(domain.to_string()));
    }
    let retry_after =
        response.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    Err(FetchError::Status { domain: domain.to_string(), status: status.as_u16(), retry_after })
}

fn classify(domain: &str, e: &reqwest::Error) -> FetchError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if err.downcast_ref::<AddressForbidden>().is_some() {
            return FetchError::AddressForbidden(domain.to_string());
        }
        source = err.source();
    }
    if e.is_redirect() {
        FetchError::Redirect(domain.to_string())
    } else if e.is_timeout() {
        FetchError::Timeout(domain.to_string())
    } else {
        FetchError::Unreachable(domain.to_string())
    }
}

async fn read_capped(domain: &str, mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, FetchError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(FetchError::TooLarge(domain.to_string()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| classify(domain, &e))? {
        if body.len() + chunk.len() > max {
            return Err(FetchError::TooLarge(domain.to_string()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// An endpoint URL of a discovery document: scheme `secure` (`insecure` only in development
/// mode), a host, no credentials, query or fragment. IP hosts are never resolved (so the vetting resolver
/// would not see them): they are accepted only in development mode and only public ones unless private
/// peers are allowed. Domain hosts are vetted on every connection.
pub fn endpoint(raw: &str, secure: &str, insecure: &str, dev: bool, allow_private: bool) -> Result<Url, &'static str> {
    let url = Url::parse(raw).map_err(|_| "invalid endpoint")?;
    if url.scheme() != secure && !(dev && url.scheme() == insecure) {
        return Err("endpoint without TLS");
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err("invalid endpoint");
    }
    let host = url.host_str().ok_or("invalid endpoint")?;
    match host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        Ok(ip) if !dev || (!allow_private && forbidden_ip(ip)) => Err("endpoint address not allowed"),
        Ok(_) => Ok(url),
        Err(_) if crate::util::valid_domain(host) => Ok(url),
        Err(_) => Err("invalid endpoint"),
    }
}

/// `max-age=<n>` from a `Cache-Control` header value.
pub fn parse_max_age(value: &str) -> Option<u64> {
    value.split(',').find_map(|d| d.trim().strip_prefix("max-age=").and_then(|n| n.trim().parse().ok()))
}
