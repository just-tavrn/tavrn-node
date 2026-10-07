// SPDX-License-Identifier: AGPL-3.0-only
//! Hostnames in `TAVRN_RTC_EXTERNAL_IP` and `TAVRN_RTC_ADVERTISE_IPS` (VOICE.md §10.2).
//!
//! ICE candidates are always addresses (RFC 8445), so LiveKit needs IP addresses. Operators with a dynamic
//! address name a hostname (dynamic DNS) instead: the node resolves it at start and periodically (every
//! minute, or after the DNS TTL when that is longer, at most every hour), A and AAAA, all addresses, public
//! ones only unless `TAVRN_RTC_ADVERTISE_PRIVATE` (or `--dev`). When the resolved set changes the new plan is
//! stored in the voice runtime and LiveKit is restarted by its supervisor (sessions survive through the
//! reconnect grace period). A failing lookup keeps the host's last known addresses and warns; a host that
//! never resolved is left out (voice never blocks the node). When no address remains at all, LiveKit falls
//! back to the STUN detection and `/healthz` reports the problem (`voice_problem`).

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use tokio::task::JoinHandle;

use super::{
    VoiceRuntime,
    livekit::{Advertise, plan},
};
use crate::{
    app::AppState,
    config::{AdvertiseEntry, Config},
    federation::client::forbidden_ip,
};

/// Shortest interval between two resolutions.
pub const MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Longest interval (a long DNS TTL is followed up to this).
pub const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// One lookup at most this long (a hanging DNS server must not delay the start of the node much).
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// All addresses of a host and how long the answer is valid (if the resolver knows).
pub type HostAnswer = (Vec<IpAddr>, Option<Duration>);

/// A/AAAA lookup with the record lifetime, replaceable in tests.
pub trait HostLookup: Send + Sync {
    /// All addresses of `host` and how long the answer is valid (if the resolver knows).
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<HostAnswer>>;
}

/// Lookups with the system's DNS configuration through hickory (A and AAAA in parallel, the TTL of the
/// answer); the resolver is built on first use.
#[derive(Default)]
pub struct SystemHosts {
    resolver: tokio::sync::OnceCell<hickory_resolver::TokioResolver>,
}

impl HostLookup for SystemHosts {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<HostAnswer>> {
        let resolver = match self.resolver.get() {
            Some(r) => Ok(r.clone()),
            None => hickory_resolver::TokioResolver::builder_tokio().and_then(|b| b.build()).inspect(|r| {
                let _ = self.resolver.set(r.clone());
            }),
        };
        Box::pin(async move {
            let resolver = resolver.map_err(std::io::Error::other)?;
            // A fully qualified name: no search domains of the container.
            let lookup = resolver.lookup_ip(format!("{host}.")).await.map_err(std::io::Error::other)?;
            let ttl = lookup.valid_until().checked_duration_since(Instant::now());
            Ok((lookup.iter().collect(), ttl))
        })
    }
}

/// The result of one resolution round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// The announced addresses in configuration order (literals as configured, hostnames expanded).
    pub addresses: Vec<IpAddr>,
    /// The addresses differ from the previous round.
    pub changed: bool,
    /// A setup problem for `/healthz`: no address remains although hostnames are configured.
    pub problem: Option<String>,
    /// When to resolve again.
    pub next: Duration,
}

/// Resolves the configured entries and remembers the last known addresses of every hostname.
pub struct Advertiser {
    entries: Vec<AdvertiseEntry>,
    allow_private: bool,
    dev: bool,
    last: HashMap<String, Vec<IpAddr>>,
    current: Vec<IpAddr>,
}

impl Advertiser {
    pub fn new(config: &Config) -> Self {
        let entries = config.rtc_advertise_entries();
        let current = entries
            .iter()
            .filter_map(|e| match e {
                AdvertiseEntry::Ip(ip) => Some(*ip),
                AdvertiseEntry::Host(_) => None,
            })
            .collect();
        Self {
            entries,
            allow_private: config.rtc_advertise_private || config.dev,
            dev: config.dev,
            last: HashMap::new(),
            current,
        }
    }

    /// Whether any entry is a hostname (otherwise nothing is ever resolved).
    pub fn has_hosts(&self) -> bool {
        self.entries.iter().any(|e| matches!(e, AdvertiseEntry::Host(_)))
    }

    /// The address plan for LiveKit of the current addresses.
    pub fn plan(&self) -> Advertise {
        plan(&self.current, self.dev)
    }

    /// Whether an address of a hostname may be announced: never unspecified, multicast or link-local;
    /// non-public ones only with `TAVRN_RTC_ADVERTISE_PRIVATE`.
    fn usable(&self, ip: IpAddr) -> bool {
        let unusable = match ip {
            IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_link_local() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
        !unusable && (self.allow_private || !forbidden_ip(ip))
    }

    /// Resolves every hostname once (each lookup bounded by [`LOOKUP_TIMEOUT`]).
    pub async fn refresh(&mut self, lookup: &dyn HostLookup) -> Round {
        let mut addresses: Vec<IpAddr> = Vec::new();
        let mut ttl: Option<Duration> = None;
        let push = |list: &mut Vec<IpAddr>, ip: IpAddr| {
            if !list.contains(&ip) {
                list.push(ip);
            }
        };
        for entry in self.entries.clone() {
            let host = match entry {
                AdvertiseEntry::Ip(ip) => {
                    push(&mut addresses, ip);
                    continue;
                }
                AdvertiseEntry::Host(host) => host,
            };
            let answer = tokio::time::timeout(LOOKUP_TIMEOUT, lookup.lookup(host.clone())).await;
            let resolved = match answer {
                Ok(Ok((ips, valid))) => {
                    let usable: Vec<IpAddr> = ips.iter().copied().filter(|ip| self.usable(*ip)).collect();
                    if usable.is_empty() {
                        tracing::warn!(host, addresses = ?ips, "media hostname has no usable (public) address");
                        None
                    } else {
                        ttl = Some(ttl.map_or(valid.unwrap_or(MIN_INTERVAL), |t| t.min(valid.unwrap_or(MIN_INTERVAL))));
                        Some(usable)
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(host, error = %e, "media hostname not resolvable");
                    None
                }
                Err(_) => {
                    tracing::warn!(host, "media hostname: DNS lookup timed out");
                    None
                }
            };
            let ips = match resolved {
                Some(ips) => {
                    self.last.insert(host, ips.clone());
                    ips
                }
                // Keep what worked last time (an outage of the DNS server must not drop the address).
                None => self.last.get(&host).cloned().unwrap_or_default(),
            };
            for ip in ips {
                push(&mut addresses, ip);
            }
        }
        let changed = addresses != self.current;
        self.current = addresses.clone();
        let problem = (addresses.is_empty() && self.has_hosts()).then(|| {
            let hosts: Vec<&str> = self
                .entries
                .iter()
                .filter_map(|e| match e {
                    AdvertiseEntry::Host(h) => Some(h.as_str()),
                    AdvertiseEntry::Ip(_) => None,
                })
                .collect();
            format!(
                "No media address resolvable ({}): check TAVRN_RTC_EXTERNAL_IP/TAVRN_RTC_ADVERTISE_IPS, until then LiveKit detects the address via STUN",
                hosts.join(", ")
            )
        });
        let next = ttl.unwrap_or(MIN_INTERVAL).clamp(MIN_INTERVAL, MAX_INTERVAL);
        Round { addresses, changed, problem, next }
    }
}

/// Resolves the hostnames of the address settings before LiveKit starts and keeps them current: returns the
/// task that resolves them again (`None` without hostnames or with voice off).
pub async fn start(state: &AppState) -> Option<JoinHandle<()>> {
    start_with(state, Arc::new(SystemHosts::default())).await
}

/// [`start`] with another lookup (tests).
pub async fn start_with(state: &AppState, lookup: Arc<dyn HostLookup>) -> Option<JoinHandle<()>> {
    if !state.config.voice_enabled {
        return None;
    }
    let mut advertiser = Advertiser::new(&state.config);
    if !advertiser.has_hosts() {
        return None;
    }
    let round = advertiser.refresh(lookup.as_ref()).await;
    apply(&state.voice, &advertiser, &round, false);
    let voice = state.voice.clone();
    Some(tokio::spawn(async move {
        let mut next = round.next;
        loop {
            tokio::time::sleep(next).await;
            let round = advertiser.refresh(lookup.as_ref()).await;
            apply(&voice, &advertiser, &round, true);
            next = round.next;
        }
    }))
}

/// Stores the plan of a round; a changed set restarts LiveKit (after the first round, which LiveKit starts with).
fn apply(voice: &VoiceRuntime, advertiser: &Advertiser, round: &Round, restart: bool) {
    if let Some(problem) = &round.problem {
        tracing::warn!("{problem}");
    }
    voice.set_problem(round.problem.clone());
    if !round.changed && restart {
        return;
    }
    let plan = advertiser.plan();
    let addresses: Vec<String> = round.addresses.iter().map(ToString::to_string).collect();
    if restart {
        tracing::info!(addresses = addresses.join(","), "media addresses changed, LiveKit restarts");
        voice.set_advertise(plan);
        voice.request_restart();
    } else {
        tracing::info!(addresses = addresses.join(","), "media hostnames resolved");
        voice.set_advertise(plan);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::sync::Mutex;

    use super::*;

    /// Answers from a table that tests change between rounds; `None` = lookup error.
    #[derive(Default)]
    struct Table(Mutex<HashMap<String, Option<HostAnswer>>>);

    impl Table {
        fn set(&self, host: &str, ips: &[&str], ttl: Option<u64>) {
            let ips = ips.iter().map(|s| s.parse().unwrap()).collect();
            self.0.lock().unwrap().insert(host.into(), Some((ips, ttl.map(Duration::from_secs))));
        }
        fn fail(&self, host: &str) {
            self.0.lock().unwrap().insert(host.into(), None);
        }
    }

    impl HostLookup for Table {
        fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<HostAnswer>> {
            let answer = self.0.lock().unwrap().get(&host).cloned().flatten();
            Box::pin(async move { answer.ok_or_else(|| std::io::Error::other("NXDOMAIN")) })
        }
    }

    fn config(external: Option<&str>, list: &str) -> Config {
        Config {
            domain: "chat.example.org".into(),
            database_url: "postgres://x@y/z".into(),
            rtc_external_ip: external.map(String::from),
            rtc_advertise_ips: list.into(),
            ..Config::default()
        }
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[tokio::test]
    async fn hostnames_expand_to_all_public_addresses_in_order() {
        let table = Table::default();
        table.set("home.dyndns.example", &["8.8.8.8", "2a00:1450::1", "192.168.0.23", "fe80::1"], Some(30));
        let mut a = Advertiser::new(&config(Some("home.dyndns.example"), "9.9.9.9, 192.168.1.7"));
        assert!(a.has_hosts());
        let round = a.refresh(&table).await;
        assert_eq!(round.addresses, ips(&["8.8.8.8", "2a00:1450::1", "9.9.9.9", "192.168.1.7"]), "LAN literals stay");
        assert!(round.changed && round.problem.is_none());
        assert_eq!(round.next, MIN_INTERVAL, "a short TTL: once a minute");
        let plan = a.plan();
        assert_eq!(plan.node_ip.as_deref(), Some("8.8.8.8,2a00:1450::1"));
        assert_eq!(plan.aliases, vec!["9.9.9.9", "192.168.1.7"]);
        assert!(!plan.stun);

        // Private addresses of a hostname only when allowed (or in development).
        let mut private =
            Advertiser::new(&Config { rtc_advertise_private: true, ..config(Some("home.dyndns.example"), "") });
        assert_eq!(private.refresh(&table).await.addresses, ips(&["8.8.8.8", "2a00:1450::1", "192.168.0.23"]));
    }

    #[tokio::test]
    async fn only_a_changed_set_is_reported_and_ttls_are_followed() {
        let table = Table::default();
        table.set("home.dyndns.example", &["8.8.8.8"], Some(300));
        let mut a = Advertiser::new(&config(None, "home.dyndns.example"));
        let first = a.refresh(&table).await;
        assert!(first.changed);
        assert_eq!(first.next, Duration::from_secs(300), "the TTL when longer than a minute");
        let same = a.refresh(&table).await;
        assert!(!same.changed, "unchanged: no restart");
        table.set("home.dyndns.example", &["8.8.4.4"], Some(86_400));
        let moved = a.refresh(&table).await;
        assert!(moved.changed);
        assert_eq!(moved.addresses, ips(&["8.8.4.4"]));
        assert_eq!(moved.next, MAX_INTERVAL);
        assert_eq!(a.plan().node_ip.as_deref(), Some("8.8.4.4"));
    }

    #[tokio::test]
    async fn a_failing_lookup_keeps_the_last_known_addresses() {
        let table = Table::default();
        table.set("home.dyndns.example", &["8.8.8.8"], None);
        let mut a = Advertiser::new(&config(None, "home.dyndns.example"));
        assert!(a.refresh(&table).await.changed);
        table.fail("home.dyndns.example");
        let round = a.refresh(&table).await;
        assert_eq!(round.addresses, ips(&["8.8.8.8"]));
        assert!(!round.changed && round.problem.is_none());
        // Only private addresses now: also kept (never announce nothing because of a broken record).
        table.set("home.dyndns.example", &["10.0.0.5"], None);
        assert_eq!(a.refresh(&table).await.addresses, ips(&["8.8.8.8"]));
    }

    #[tokio::test]
    async fn an_unresolvable_host_at_start_is_left_out_and_reported_only_when_nothing_remains() {
        let table = Table::default();
        let mut a = Advertiser::new(&config(Some("203.0.113.7"), "gone.example"));
        let round = a.refresh(&table).await;
        assert_eq!(round.addresses, ips(&["203.0.113.7"]), "the other entries continue");
        assert!(!round.changed, "the literal was there from the start");
        assert!(round.problem.is_none());

        let mut only = Advertiser::new(&config(None, "gone.example, also-gone.example"));
        let round = only.refresh(&table).await;
        assert!(round.addresses.is_empty());
        let problem = round.problem.unwrap();
        assert!(problem.contains("gone.example, also-gone.example") && problem.contains("STUN"), "{problem}");
        assert!(only.plan().stun, "LiveKit falls back to STUN");
        // It resolves later: the problem is gone and LiveKit restarts with the address.
        table.set("gone.example", &["8.8.8.8"], None);
        let round = only.refresh(&table).await;
        assert!(round.changed && round.problem.is_none());
    }

    #[test]
    fn literals_only_need_no_resolution() {
        let a = Advertiser::new(&config(Some("203.0.113.7"), "2001:db8::5"));
        assert!(!a.has_hosts());
        assert_eq!(a.plan(), Advertise::from_config(&config(Some("203.0.113.7"), "2001:db8::5")));
        assert!(!Advertiser::new(&config(None, "")).has_hosts());
    }

    #[tokio::test]
    async fn a_changed_set_asks_the_supervisor_for_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config { data_dir: dir.path().to_string_lossy().into(), ..config(None, "home.dyndns.example") };
        let voice = VoiceRuntime::new(&cfg).unwrap();
        let table = Table::default();
        table.set("home.dyndns.example", &["8.8.8.8"], None);
        let mut a = Advertiser::new(&cfg);
        let restarted = |voice: &VoiceRuntime| futures::FutureExt::now_or_never(voice.restart_requested()).is_some();
        // Start: the plan is stored, LiveKit starts with it (no restart).
        let round = a.refresh(&table).await;
        apply(&voice, &a, &round, false);
        assert_eq!(voice.advertise().node_ip.as_deref(), Some("8.8.8.8"));
        assert!(!restarted(&voice));
        // Unchanged: nothing happens.
        let round = a.refresh(&table).await;
        apply(&voice, &a, &round, true);
        assert!(!restarted(&voice));
        // Changed: new plan and one restart request.
        table.set("home.dyndns.example", &["8.8.4.4", "2a00:1450::1"], None);
        let round = a.refresh(&table).await;
        apply(&voice, &a, &round, true);
        assert_eq!(voice.advertise().node_ip.as_deref(), Some("8.8.4.4,2a00:1450::1"));
        assert!(restarted(&voice));
        assert!(!restarted(&voice), "one request per change");
        // A problem is reported while nothing resolves and cleared afterwards.
        let mut broken = Advertiser::new(&config(None, "gone.example"));
        let round = broken.refresh(&Table::default()).await;
        apply(&voice, &broken, &round, true);
        assert!(voice.problem().is_some());
        let round = a.refresh(&table).await;
        apply(&voice, &a, &round, true);
        assert!(voice.problem().is_none());
    }

    #[tokio::test]
    async fn a_hanging_lookup_is_bounded() {
        struct Hang;
        impl HostLookup for Hang {
            fn lookup(&self, _: String) -> BoxFuture<'static, std::io::Result<HostAnswer>> {
                Box::pin(futures::future::pending())
            }
        }
        tokio::time::pause();
        let mut a = Advertiser::new(&config(None, "slow.example"));
        let round = a.refresh(&Hang).await;
        assert!(round.addresses.is_empty() && round.problem.is_some());
    }
}
