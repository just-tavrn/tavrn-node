// SPDX-License-Identifier: AGPL-3.0-only
//! Tests of the outbound federation client (FEDERATION.md §1.3) against local HTTP servers.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use futures::future::BoxFuture;
use serde_json::json;

use super::client::*;
use crate::config::Config;

/// DNS answers from a table; counts lookups. A host can answer differently on later lookups.
#[derive(Default)]
struct MapLookup {
    answers: Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
    calls: AtomicUsize,
}

impl MapLookup {
    fn with(entries: &[(&str, &[&str])]) -> Arc<Self> {
        let l = Self::default();
        for (host, ips) in entries {
            l.answers
                .lock()
                .unwrap()
                .insert(host.to_string(), vec![ips.iter().map(|ip| ip.parse().unwrap()).collect()]);
        }
        Arc::new(l)
    }

    fn then(&self, host: &str, ips: &[&str]) {
        self.answers.lock().unwrap().get_mut(host).unwrap().push(ips.iter().map(|ip| ip.parse().unwrap()).collect());
    }
}

impl Lookup for MapLookup {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let result = match answers.get_mut(&host) {
            Some(list) if list.len() > 1 => Ok(list.remove(0)),
            Some(list) => Ok(list[0].clone()),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unknown host")),
        };
        Box::pin(async move { result })
    }
}

/// SRV answers from a table; counts lookups.
#[derive(Default)]
struct MapSrv {
    answers: Mutex<HashMap<String, Vec<SrvRecord>>>,
    calls: AtomicUsize,
}

impl MapSrv {
    fn with(name: &str, records: &[(&str, u16)]) -> Arc<Self> {
        let s = Self::default();
        let records = records
            .iter()
            .enumerate()
            .map(|(i, (target, port))| SrvRecord {
                priority: i as u16,
                weight: 0,
                port: *port,
                target: target.to_string(),
            })
            .collect();
        s.answers.lock().unwrap().insert(name.to_string(), records);
        Arc::new(s)
    }
}

impl SrvLookup for MapSrv {
    fn srv(&self, name: String) -> BoxFuture<'static, std::io::Result<Vec<SrvRecord>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self
            .answers
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no SRV record"));
        Box::pin(async move { result })
    }
}

fn config(dev_peers: &str, allow_private: bool) -> Config {
    Config {
        dev: true,
        domain: "own.test".into(),
        database_url: "sqlite::memory:".into(),
        federation_dev_peers: dev_peers.into(),
        federation_allow_private: allow_private,
        ..Config::defaults_for(true)
    }
}

fn client(config: &Config, lookup: Arc<MapLookup>) -> FederationClient {
    let timeouts = Timeouts {
        connect: Duration::from_millis(500),
        total: Duration::from_millis(800),
        inbox: Duration::from_millis(800),
    };
    FederationClient::with_options(config, ClientOptions { timeouts, lookup, srv: Arc::new(MapSrv::default()) })
        .unwrap()
}

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static MAX_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

fn json_doc(bytes: usize) -> Response {
    let body = format!("{{\"pad\":\"{}\"}}", "x".repeat(bytes));
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn serve() -> SocketAddr {
    let app = Router::new()
        .route("/ok", get(|| async { ([(header::CACHE_CONTROL, "public, max-age=900")], Json(json!({ "ok": true }))) }))
        .route(
            "/echo",
            get(|headers: HeaderMap| async move {
                let h = |name: header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok()).map(String::from);
                Json(json!({
                    "host": h(header::HOST), "user_agent": h(header::USER_AGENT), "accept": h(header::ACCEPT),
                    "cookie": h(header::COOKIE),
                }))
            }),
        )
        .route(
            "/redirect/{n}",
            get(|Path(n): Path<u32>| async move {
                if n == 0 {
                    Redirect::temporary("/ok").into_response()
                } else {
                    Redirect::temporary(&format!("/redirect/{}", n - 1)).into_response()
                }
            }),
        )
        .route("/redirect-host", get(|| async { Redirect::temporary("http://localhost:1/ok") }))
        .route("/redirect-port", get(|| async { Redirect::temporary("http://127.0.0.1:1/ok") }))
        .route("/big", get(|| async { json_doc(70 * 1024) }))
        .route(
            "/big-chunked",
            get(|| async {
                let chunks = (0..80).map(|_| Ok::<_, std::io::Error>(vec![b' '; 1024]));
                ([(header::CONTENT_TYPE, "application/json")], Body::from_stream(futures::stream::iter(chunks)))
            }),
        )
        .route("/html", get(|| async { ([(header::CONTENT_TYPE, "text/html")], "<html>") }))
        .route("/png", get(|| async { ([(header::CONTENT_TYPE, "image/png")], vec![0x89u8, b'P', b'N', b'G']) }))
        .route("/svg", get(|| async { ([(header::CONTENT_TYPE, "image/svg+xml")], "<svg/>") }))
        .route(
            "/status/{code}",
            get(|Path(code): Path<u16>| async move {
                (StatusCode::from_u16(code).unwrap(), [(header::RETRY_AFTER, "120")], "no")
            }),
        )
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                Json(json!({}))
            }),
        )
        .route(
            "/counted",
            get(|| async {
                let now = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
                MAX_IN_FLIGHT.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(150)).await;
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                Json(json!({}))
            }),
        )
        .route(
            "/api/v1/federation/inbox",
            post(|headers: HeaderMap, body: String| async move {
                let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
                let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
                if auth == "Bearer tok" && ct == "application/json" && body == "{\"a\":1}" {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::BAD_REQUEST
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// A client whose development peer `peer.test` is the local server.
async fn peer_client() -> (FederationClient, SocketAddr) {
    let addr = serve().await;
    let c = client(&config(&format!("peer.test=http://{addr}"), true), MapLookup::with(&[]));
    (c, addr)
}

#[test]
fn forbidden_address_ranges() {
    let forbidden = [
        "0.0.0.0",
        "0.255.1.1",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.8.8.8",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.8",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.7",
        "203.0.113.9",
        "224.0.0.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.1.2.3",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "100::1",
        "2001:db8::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "febf::1",
        "ff02::1",
        "ff00::",
    ];
    for ip in forbidden {
        assert!(forbidden_ip(ip.parse().unwrap()), "{ip} must be refused");
    }
    let public = [
        "1.1.1.1",
        "8.8.8.8",
        "9.255.255.255",
        "11.0.0.1",
        "100.63.255.255",
        "100.128.0.1",
        "126.255.255.255",
        "169.253.1.1",
        "172.15.255.255",
        "172.32.0.1",
        "192.0.1.1",
        "192.0.3.1",
        "192.167.1.1",
        "198.17.255.255",
        "198.20.0.1",
        "198.51.101.1",
        "203.0.114.1",
        "223.255.255.255",
        "2606:4700::1111",
        "2a00:1450::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "2001:db9::1",
        "fec0::1",
    ];
    for ip in public {
        assert!(!forbidden_ip(ip.parse().unwrap()), "{ip} is public");
    }
}

#[tokio::test]
async fn resolver_refuses_if_any_address_is_private() {
    let lookup = MapLookup::with(&[
        ("public.test", &["8.8.8.8", "2a00:1450::1"]),
        ("mixed.test", &["8.8.8.8", "10.0.0.1"]),
        ("mapped.test", &["::ffff:127.0.0.1"]),
        ("empty.test", &[]),
    ]);
    let strict = VettingResolver::new(lookup.clone(), false, Default::default());
    assert_eq!(strict.vetted("public.test").await.unwrap().len(), 2);
    for host in ["mixed.test", "mapped.test"] {
        let err = strict.vetted(host).await.unwrap_err();
        assert!(err.downcast_ref::<AddressForbidden>().is_some(), "{host}: {err}");
    }
    assert!(strict.vetted("empty.test").await.is_err());
    assert!(strict.vetted("unknown.test").await.is_err());
    let open = VettingResolver::new(lookup.clone(), true, Default::default());
    assert!(open.vetted("mixed.test").await.is_ok(), "TAVRN_FEDERATION_ALLOW_PRIVATE lifts the check");
    let exempt = VettingResolver::new(lookup, false, ["mixed.test".to_string()].into());
    assert!(exempt.vetted("mixed.test").await.is_ok(), "development peers are not vetted");
}

#[tokio::test]
async fn private_targets_are_refused_before_connecting() {
    for ip in ["127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "::ffff:192.168.0.1"] {
        let lookup = MapLookup::with(&[("evil.test", &[ip])]);
        let c = client(&config("", false), lookup);
        let err = c.get("evil.test", "/.well-known/tavrn", Kind::Discovery).await.unwrap_err();
        assert_eq!(err, FetchError::AddressForbidden("evil.test".into()), "{ip}");
        assert!(!err.retryable());
        assert_eq!(err.to_api().code(), "federation.address_forbidden");
    }
}

#[tokio::test]
async fn the_connection_uses_the_vetted_address_only() {
    let addr = serve().await;
    // First answer: the test server. A later answer (rebinding) would point elsewhere.
    let lookup = MapLookup::with(&[("pin.test", &["127.0.0.1"])]);
    lookup.then("pin.test", &["10.66.66.66"]);
    let c = client(&config(&format!("pin.test=http://pin.test:{}", addr.port()), false), lookup.clone());
    let echo = c.get("pin.test", "/echo", Kind::Discovery).await.unwrap();
    let echo: serde_json::Value = serde_json::from_slice(&echo.body).unwrap();
    assert_eq!(echo["host"], format!("pin.test:{}", addr.port()), "Host stays the domain");
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1, "one lookup per connection, no second resolution");
}

#[tokio::test]
async fn headers_identify_the_node_and_carry_no_cookies() {
    let (c, _) = peer_client().await;
    let echo = c.get("peer.test", "/echo", Kind::Discovery).await.unwrap();
    assert_eq!(echo.status, 200);
    let echo: serde_json::Value = serde_json::from_slice(&echo.body).unwrap();
    assert_eq!(echo["user_agent"], format!("tavrn-node/{} (+https://own.test)", crate::app::SOFTWARE_VERSION));
    assert_eq!(echo["accept"], "application/json");
    assert_eq!(echo["cookie"], serde_json::Value::Null);
}

#[tokio::test]
async fn redirects_only_to_the_same_host_and_at_most_three() {
    let (c, _) = peer_client().await;
    let ok = c.get("peer.test", "/redirect/2", Kind::Discovery).await.unwrap();
    assert_eq!(ok.status, 200, "three redirects are fine");
    for path in ["/redirect/3", "/redirect-host", "/redirect-port"] {
        let err = c.get("peer.test", path, Kind::Discovery).await.unwrap_err();
        assert_eq!(err, FetchError::Redirect("peer.test".into()), "{path}");
        assert_eq!(err.to_api().code(), "federation.peer_unreachable");
    }
}

#[tokio::test]
async fn response_sizes_are_capped_per_kind() {
    let (c, _) = peer_client().await;
    for path in ["/big", "/big-chunked"] {
        let err = c.get("peer.test", path, Kind::Discovery).await.unwrap_err();
        assert_eq!(err, FetchError::TooLarge("peer.test".into()), "{path}");
        assert_eq!(err.to_api().code(), "federation.peer_invalid");
        let profile = c.get("peer.test", path, Kind::Profile).await.unwrap_err();
        assert_eq!(profile, FetchError::TooLarge("peer.test".into()));
        assert!(c.get("peer.test", path, Kind::Keys).await.is_ok(), "{path}: keys may be 256 KiB");
    }
    assert_eq!(Kind::Discovery.max_bytes(), 64 * 1024);
    assert_eq!(Kind::Profile.max_bytes(), 16 * 1024);
    assert_eq!(Kind::Claim.max_bytes(), 512 * 1024);
    assert_eq!(Kind::Avatar.max_bytes(), 1024 * 1024);
}

#[tokio::test]
async fn only_expected_content_types_are_read() {
    let (c, _) = peer_client().await;
    assert_eq!(
        c.get("peer.test", "/html", Kind::Discovery).await.unwrap_err(),
        FetchError::ContentType("peer.test".into())
    );
    assert_eq!(c.get("peer.test", "/png", Kind::Avatar).await.unwrap().content_type, "image/png");
    assert!(c.get("peer.test", "/svg", Kind::Avatar).await.is_err(), "SVG avatars are refused");
    assert!(c.get("peer.test", "/png", Kind::Profile).await.is_err());
    assert_eq!(c.get("peer.test", "/ok", Kind::Discovery).await.unwrap().max_age, Some(900));
}

#[tokio::test]
async fn non_success_statuses_and_retry_classes() {
    let (c, _) = peer_client().await;
    let err = c.get("peer.test", "/status/503", Kind::Discovery).await.unwrap_err();
    assert_eq!(err, FetchError::Status { domain: "peer.test".into(), status: 503, retry_after: Some(120) });
    assert!(err.retryable());
    for (code, retry) in [(408, true), (429, true), (500, true), (404, false), (400, false), (401, false), (403, false)]
    {
        let err = c.get("peer.test", &format!("/status/{code}"), Kind::Discovery).await.unwrap_err();
        assert_eq!(err.status(), Some(code));
        assert_eq!(err.retryable(), retry, "{code}");
    }
}

#[tokio::test]
async fn timeouts_and_unreachable_peers() {
    let (c, _) = peer_client().await;
    let err = c.get("peer.test", "/slow", Kind::Discovery).await.unwrap_err();
    assert_eq!(err, FetchError::Timeout("peer.test".into()));
    assert!(err.retryable());
    // A closed port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let c = client(&config(&format!("down.test=http://127.0.0.1:{port}"), true), MapLookup::with(&[]));
    let err = c.get("down.test", "/ok", Kind::Discovery).await.unwrap_err();
    assert_eq!(err, FetchError::Unreachable("down.test".into()));
    assert!(err.retryable());
    assert_eq!(err.to_api().code(), "federation.peer_unreachable");
}

#[tokio::test]
async fn at_most_four_concurrent_requests_per_peer() {
    let (c, _) = peer_client().await;
    let c = Arc::new(c);
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let c = c.clone();
            tokio::spawn(async move { c.get("peer.test", "/counted", Kind::Discovery).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let max = MAX_IN_FLIGHT.load(Ordering::SeqCst);
    assert!((1..=PER_PEER_CONCURRENCY).contains(&max), "max in flight {max}");
}

#[tokio::test]
async fn inbox_posts_carry_the_token_and_exact_body() {
    let (c, _) = peer_client().await;
    assert_eq!(c.post_inbox("peer.test", "tok", b"{\"a\":1}".to_vec()).await.unwrap(), 202);
    let err = c.post_inbox("peer.test", "other", b"{\"a\":1}".to_vec()).await.unwrap_err();
    assert_eq!(err.status(), Some(400));
}

#[test]
fn domain_policy_and_url_building() {
    let mut cfg = config("", false);
    cfg.dev = false;
    cfg.federation_blocklist = "evil.example".into();
    let c = client(&cfg, MapLookup::with(&[]));
    assert!(c.check_policy("good.example").is_ok());
    assert_eq!(c.check_policy("evil.example"), Err(FetchError::Blocked("evil.example".into())));
    assert_eq!(c.check_policy("sub.evil.example"), Err(FetchError::Blocked("sub.evil.example".into())));
    assert!(c.check_policy("notevil.example").is_ok(), "only the domain and its subdomains");
    for bad in ["own.test", "localhost", "127.0.0.1", "Good.example", "good.example:8443", "a@good.example"] {
        assert_eq!(c.check_policy(bad), Err(FetchError::DomainInvalid), "{bad}");
    }
    assert_eq!(c.url("good.example", "/.well-known/tavrn").unwrap().as_str(), "https://good.example/.well-known/tavrn");
    assert!(c.url("good.example", "//evil.example/x").is_err());
    assert!(c.url("good.example", "relative").is_err());

    cfg.federation_allowlist = "friend.example".into();
    let c = client(&cfg, MapLookup::with(&[]));
    assert!(c.check_policy("friend.example").is_ok());
    assert_eq!(c.check_policy("good.example"), Err(FetchError::Blocked("good.example".into())));
    assert!(c.check_policy("evil.example").is_err(), "the blocklist wins");

    cfg.federation_enabled = false;
    let c = client(&cfg, MapLookup::with(&[]));
    assert_eq!(c.check_policy("friend.example"), Err(FetchError::Disabled));
    assert_eq!(FetchError::Disabled.to_api().code(), "federation.disabled");
    assert_eq!(FetchError::Blocked("x".into()).to_api().code(), "federation.peer_blocked");
}

#[test]
fn development_peers_need_dev_mode() {
    let mut cfg = config("a.test=http://127.0.0.1:1", true);
    let c = client(&cfg, MapLookup::with(&[]));
    assert_eq!(c.url("a.test", "/x").unwrap().as_str(), "http://127.0.0.1:1/x");
    cfg.dev = false;
    let c = client(&cfg, MapLookup::with(&[]));
    assert_eq!(c.url("a.test", "/x").unwrap().as_str(), "https://a.test/x", "mapping ignored without --dev");
}

#[test]
fn cache_control_parsing() {
    assert_eq!(parse_max_age("public, max-age=300"), Some(300));
    assert_eq!(parse_max_age("max-age=7200, public"), Some(7200));
    assert_eq!(parse_max_age("no-store"), None);
    assert_eq!(parse_max_age("max-age=abc"), None);
}

#[tokio::test]
async fn a_dropped_connection_is_retried_once_for_gets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            // The first connection is closed without an answer, later ones are served.
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                drop(stream);
                continue;
            }
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = "{\"ok\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });
    let c = client(&config(&format!("flaky.test=http://{addr}"), true), MapLookup::with(&[]));
    let fetched = c.get("flaky.test", "/ok", Kind::Discovery).await.unwrap();
    assert_eq!(fetched.body, b"{\"ok\":true}");
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "exactly one retry");
}

#[test]
fn only_known_refusals_of_peers_are_passed_through() {
    let code = |status, code: &str| {
        passed_through(status, code, Some(30)).map(|e| (e.status().as_u16(), e.code().to_string()))
    };
    assert_eq!(code(404, "user.not_found"), Some((404, "user.not_found".into())));
    assert_eq!(code(403, "federation.claim_refused"), Some((403, "federation.claim_refused".into())));
    assert_eq!(code(429, "anything"), Some((429, "rate_limited".into())));
    assert_eq!(code(403, "auth.node_admin_required"), None, "unknown codes become peer_unreachable");
    assert_eq!(code(404, "federation.claim_refused"), None, "status and code must match");
    let refused =
        FetchError::Refused { domain: "peer.test".into(), status: 400, code: "<script>".into(), retry_after: None };
    assert_eq!(refused.to_api().code(), "federation.peer_unreachable");
    assert!(!refused.retryable());
    let limited =
        FetchError::Refused { domain: "peer.test".into(), status: 429, code: String::new(), retry_after: Some(9) };
    assert!(limited.retryable());
    assert_eq!(limited.retry_after(), Some(9));
}

// ---------------------------------------------------------------- delegation

/// A host that serves `/.well-known/tavrn` (`None`: 404, `Some((status, doc))`) and `/api/v1/ping`, which
/// answers with `name` so a test sees which host an API request reached.
async fn site(well_known: Option<(u16, serde_json::Value)>, name: &'static str) -> SocketAddr {
    let app = Router::new().route("/api/v1/ping", get(move || async move { Json(json!({ "host": name })) }));
    let app = match well_known {
        Some((status, doc)) => app.route(
            "/.well-known/tavrn",
            get(move || async move {
                (StatusCode::from_u16(status).unwrap(), [(header::CACHE_CONTROL, "max-age=900")], Json(doc.clone()))
            }),
        ),
        None => app,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn delegating_doc(domain: &str, api_base: &str) -> serde_json::Value {
    json!({
        "tavrn": 1, "domain": domain, "api": format!("{api_base}/api/v1"),
        "ws": format!("{}/api/v1/ws", api_base.replacen("http", "ws", 1)),
    })
}

fn delegation_client(
    dev_peers: &str,
    allow_private: bool,
    lookup: Arc<MapLookup>,
    srv: Arc<MapSrv>,
    srv_on: bool,
) -> FederationClient {
    let mut cfg = config(dev_peers, allow_private);
    cfg.federation_srv_fallback = srv_on;
    let timeouts = Timeouts {
        connect: Duration::from_millis(500),
        total: Duration::from_millis(800),
        inbox: Duration::from_millis(800),
    };
    FederationClient::with_options(&cfg, ClientOptions { timeouts, lookup, srv }).unwrap()
}

async fn ping(c: &FederationClient, domain: &str) -> Result<String, FetchError> {
    let f = c.get(domain, "/api/v1/ping", Kind::Profile).await?;
    Ok(serde_json::from_slice::<serde_json::Value>(&f.body).unwrap()["host"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn api_requests_follow_the_endpoints_of_the_well_known() {
    // The identity domain `deleg.test` (its website) delegates to the app host `app.test`.
    let app = site(None, "app").await;
    let website =
        site(Some((200, delegating_doc("deleg.test", &format!("http://app.test:{}", app.port())))), "website").await;
    let lookup = MapLookup::with(&[("app.test", &["127.0.0.1"])]);
    let srv = Arc::new(MapSrv::default());
    let c = delegation_client(&format!("deleg.test=http://{website}"), true, lookup.clone(), srv.clone(), true);
    assert_eq!(ping(&c, "deleg.test").await.unwrap(), "app", "the API lives on the delegated host");
    let d = c.cached_delegation("deleg.test").unwrap();
    assert_eq!(d.api.as_str(), format!("http://app.test:{}/api/v1", app.port()));
    assert_eq!(d.source, DelegationSource::WellKnown);
    // Cached with the document's max-age (900 s).
    let left = c.delegation_expires_in("deleg.test").unwrap().as_secs();
    assert!((890..=900).contains(&left), "{left}");
    // Signed POSTs and query strings go there too; the discovery document itself stays on the domain.
    assert_eq!(c.target("deleg.test", "/api/v1/federation/inbox").await.unwrap().host_str(), Some("app.test"));
    assert_eq!(c.target("deleg.test", "/api/v1/x?y=1").await.unwrap().query(), Some("y=1"));
    assert_eq!(c.target("deleg.test", "/other").await.unwrap().port(), Some(website.port()));
    assert_eq!(srv.calls.load(Ordering::SeqCst), 0);

    // SSRF: the endpoint host is vetted like the domain itself.
    let strict = delegation_client(&format!("deleg.test=http://{website}"), false, lookup, srv, true);
    assert_eq!(ping(&strict, "deleg.test").await.unwrap_err(), FetchError::AddressForbidden("deleg.test".into()));
}

#[tokio::test]
async fn a_document_naming_another_domain_or_bad_endpoints_is_refused() {
    let app = site(None, "app").await;
    let other = site(Some((200, delegating_doc("other.test", &format!("http://{app}")))), "website").await;
    let c = delegation_client(
        &format!("deleg.test=http://{other}"),
        true,
        MapLookup::with(&[]),
        Arc::new(MapSrv::default()),
        true,
    );
    let err = ping(&c, "deleg.test").await.unwrap_err();
    assert_eq!(err, FetchError::Invalid("deleg.test".into(), "domain does not match"));
    assert_eq!(err.to_api().code(), "federation.peer_invalid");
    assert!(!err.retryable());
    assert!(c.cached_delegation("deleg.test").is_none());

    // A private IP endpoint while private peers are not allowed: refused before any connection.
    let private = site(Some((200, delegating_doc("deleg.test", "http://10.0.0.1:8080"))), "website").await;
    let c = delegation_client(
        &format!("deleg.test=http://{private}"),
        false,
        MapLookup::with(&[]),
        Arc::new(MapSrv::default()),
        true,
    );
    assert_eq!(
        ping(&c, "deleg.test").await.unwrap_err(),
        FetchError::Invalid("deleg.test".into(), "endpoint address not allowed")
    );
}

#[tokio::test]
async fn only_a_missing_document_falls_back_to_the_domain() {
    // 404 and no usable SRV record (its target does not resolve): the API is expected at <domain>/api/v1
    // (here the development peer's base URL).
    let plain = site(None, "domain").await;
    let srv = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", 1)]);
    let c = delegation_client(&format!("deleg.test=http://{plain}"), true, MapLookup::with(&[]), srv.clone(), true);
    assert_eq!(ping(&c, "deleg.test").await.unwrap(), "domain");
    let d = c.cached_delegation("deleg.test").unwrap();
    assert_eq!(d.source, DelegationSource::Fallback);
    assert_eq!(d.api.as_str(), format!("http://{plain}/api/v1"), "this node reaches the development peer");
    assert_eq!(
        (d.public_api.as_str(), d.ws.as_str(), d.web.as_str()),
        ("https://deleg.test/api/v1", "wss://deleg.test/api/v1/ws", "https://deleg.test/"),
        "browsers get the domain itself"
    );
    assert_eq!(srv.calls.load(Ordering::SeqCst), 1, "the SRV record is consulted before the direct attempt");
    let left = c.delegation_expires_in("deleg.test").unwrap().as_secs();
    assert!((290..=300).contains(&left), "a fallback is cached for the minimum lifetime: {left}");

    // No SRV record at all: the same direct attempt.
    let none = Arc::new(MapSrv::default());
    let c = delegation_client(&format!("deleg.test=http://{plain}"), true, MapLookup::with(&[]), none.clone(), true);
    assert_eq!(ping(&c, "deleg.test").await.unwrap(), "domain");
    assert_eq!(none.calls.load(Ordering::SeqCst), 1);

    // Any other answer is an error, without fallback and without SRV.
    let broken = site(Some((500, json!({}))), "domain").await;
    let srv = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", 1)]);
    let c = delegation_client(&format!("deleg.test=http://{broken}"), true, MapLookup::with(&[]), srv.clone(), true);
    assert_eq!(ping(&c, "deleg.test").await.unwrap_err().status(), Some(500));
    assert!(c.cached_delegation("deleg.test").is_none());
    assert_eq!(srv.calls.load(Ordering::SeqCst), 0, "SRV only when the domain serves no document");

    // SRV switched off: a 404 goes straight to the domain.
    let off = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", 1)]);
    let c = delegation_client(&format!("deleg.test=http://{plain}"), true, MapLookup::with(&[]), off.clone(), false);
    assert_eq!(ping(&c, "deleg.test").await.unwrap(), "domain");
    assert_eq!(off.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_website_without_document_uses_the_srv_record() {
    // The identity domain's website has no well-known (404); `_tavrn._tcp.deleg.test` names the node's host.
    let website = site(None, "website").await;
    let app = site(None, "srv-app").await;
    let host =
        site(Some((200, delegating_doc("deleg.test", &format!("http://target.test:{}", app.port())))), "x").await;
    let lookup = MapLookup::with(&[("target.test", &["127.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", host.port())]);
    let c = delegation_client(&format!("deleg.test=http://{website}"), true, lookup, srv.clone(), true);
    assert_eq!(ping(&c, "deleg.test").await.unwrap(), "srv-app", "found through SRV, never the website's API");
    let d = c.cached_delegation("deleg.test").unwrap();
    assert_eq!(d.source, DelegationSource::Srv);
    assert_eq!(d.web.as_str(), "https://deleg.test/", "no web in the document: the domain");
    assert_eq!(srv.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_srv_target_claiming_another_domain_is_refused() {
    let website = site(None, "website").await;
    let host = site(Some((200, delegating_doc("other.test", "http://target.test:1"))), "x").await;
    let lookup = MapLookup::with(&[("target.test", &["127.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", host.port())]);
    let c = delegation_client(&format!("deleg.test=http://{website}"), true, lookup, srv, true);
    let err = ping(&c, "deleg.test").await.unwrap_err();
    assert_eq!(err, FetchError::Invalid("deleg.test".into(), "domain does not match"));
    assert_eq!(err.to_api().code(), "federation.peer_invalid");
    assert!(c.cached_delegation("deleg.test").is_none(), "no direct fallback after a refused SRV target");

    // A private SRV target after a 404 is refused as well (no direct attempt either).
    let lookup = MapLookup::with(&[("target.test", &["10.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.deleg.test.", &[("target.test", 443)]);
    let c = delegation_client(&format!("deleg.test=http://{website}"), false, lookup, srv, true);
    assert_eq!(c.get_well_known("deleg.test").await.unwrap_err(), FetchError::AddressForbidden("deleg.test".into()));
    assert!(c.cached_delegation("deleg.test").is_none());
}

#[tokio::test]
async fn a_network_error_uses_the_srv_record_when_enabled() {
    // `srv.test` does not resolve; `_tavrn._tcp.srv.test` names the host that serves the node.
    let target = site(None, "srv-target").await;
    let doc = delegating_doc("srv.test", &format!("http://target.test:{}", target.port()));
    let host = site(Some((200, doc)), "srv-target").await;
    let lookup = MapLookup::with(&[("target.test", &["127.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.srv.test.", &[("bad_name", 1), ("127.0.0.1", 1), ("target.test", host.port())]);
    let c = delegation_client("", true, lookup.clone(), srv, true);
    // The document comes from the SRV target, the API from the endpoint it names.
    let (_, source) = c.get_well_known("srv.test").await.unwrap();
    assert_eq!(source, DelegationSource::Srv);
    assert_eq!(ping(&c, "srv.test").await.unwrap(), "srv-target");
    assert_eq!(c.cached_delegation("srv.test").unwrap().source, DelegationSource::Srv);

    // Switched off: the network error stands.
    let srv_off = MapSrv::with("_tavrn._tcp.srv.test.", &[("target.test", host.port())]);
    let off = delegation_client("", true, lookup, srv_off.clone(), false);
    assert_eq!(ping(&off, "srv.test").await.unwrap_err(), FetchError::Unreachable("srv.test".into()));
    assert_eq!(srv_off.calls.load(Ordering::SeqCst), 0);

    // No usable record: the original error.
    let none = delegation_client("", true, MapLookup::with(&[]), Arc::new(MapSrv::default()), true);
    assert_eq!(ping(&none, "srv.test").await.unwrap_err(), FetchError::Unreachable("srv.test".into()));
}

#[tokio::test]
async fn an_srv_target_on_a_private_address_is_refused() {
    let lookup = MapLookup::with(&[("target.test", &["10.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.srv.test.", &[("target.test", 443)]);
    let c = delegation_client("", false, lookup, srv.clone(), true);
    assert_eq!(c.get_well_known("srv.test").await.unwrap_err(), FetchError::AddressForbidden("srv.test".into()));
    assert_eq!(srv.calls.load(Ordering::SeqCst), 1);
    // A refused address on the domain itself is final: no SRV lookup.
    let lookup = MapLookup::with(&[("srv.test", &["127.0.0.1"])]);
    let srv = MapSrv::with("_tavrn._tcp.srv.test.", &[("target.test", 443)]);
    let c = delegation_client("", false, lookup, srv.clone(), true);
    assert_eq!(c.get_well_known("srv.test").await.unwrap_err(), FetchError::AddressForbidden("srv.test".into()));
    assert_eq!(srv.calls.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------- moved endpoints

/// The website of `moved.test`: serves the document in `doc` and counts its fetches.
async fn moving_site(doc: Arc<Mutex<serde_json::Value>>, fetches: Arc<AtomicUsize>) -> SocketAddr {
    let app = Router::new().route(
        "/.well-known/tavrn",
        get(move || {
            let (doc, fetches) = (doc.clone(), fetches.clone());
            async move {
                fetches.fetch_add(1, Ordering::SeqCst);
                let doc = doc.lock().unwrap().clone();
                ([(header::CACHE_CONTROL, "max-age=3600")], Json(doc))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// An app host answering `/api/v1/ping` with `name` and taking inbox POSTs; `503` (a proxy without upstream)
/// once `down` is set. Counts the inbox POSTs.
async fn app_host(name: &'static str, down: Arc<std::sync::atomic::AtomicBool>, posts: Arc<AtomicUsize>) -> SocketAddr {
    let is_down = down.clone();
    let app = Router::new()
        .route(
            "/api/v1/ping",
            get(move || {
                let down = is_down.clone();
                async move {
                    if down.load(Ordering::SeqCst) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    Json(json!({ "host": name })).into_response()
                }
            }),
        )
        .route(
            "/api/v1/federation/inbox",
            post(move || {
                let (down, posts) = (down.clone(), posts.clone());
                async move {
                    if down.load(Ordering::SeqCst) {
                        return StatusCode::BAD_GATEWAY;
                    }
                    posts.fetch_add(1, Ordering::SeqCst);
                    StatusCode::ACCEPTED
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

struct Moving {
    client: FederationClient,
    doc: Arc<Mutex<serde_json::Value>>,
    fetches: Arc<AtomicUsize>,
}

impl Moving {
    async fn new() -> Self {
        let doc = Arc::new(Mutex::new(json!({})));
        let fetches = Arc::new(AtomicUsize::new(0));
        let website = moving_site(doc.clone(), fetches.clone()).await;
        let lookup = MapLookup::with(&[
            ("app1.test", &["127.0.0.1"]),
            ("app2.test", &["127.0.0.1"]),
            ("app3.test", &["127.0.0.1"]),
        ]);
        let client =
            delegation_client(&format!("moved.test=http://{website}"), true, lookup, Arc::new(MapSrv::default()), true);
        Self { client, doc, fetches }
    }

    fn point_to(&self, host: &str, addr: SocketAddr) {
        *self.doc.lock().unwrap() = delegating_doc("moved.test", &format!("http://{host}:{}", addr.port()));
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

fn flag() -> Arc<std::sync::atomic::AtomicBool> {
    Arc::new(std::sync::atomic::AtomicBool::new(false))
}

#[tokio::test]
async fn a_failing_cached_endpoint_resolves_the_domain_again_once_a_minute() {
    let m = Moving::new().await;
    let (down1, down2) = (flag(), flag());
    let app1 = app_host("app1", down1.clone(), Arc::new(AtomicUsize::new(0))).await;
    let app2 = app_host("app2", down2.clone(), Arc::new(AtomicUsize::new(0))).await;
    m.point_to("app1.test", app1);
    assert_eq!(ping(&m.client, "moved.test").await.unwrap(), "app1");
    assert_eq!(m.fetches(), 1);
    assert!(!m.client.take_stale_document("moved.test"));

    // The operator moves the node: the record changes, the old host answers 503. The cached endpoint (one
    // hour) is dropped at the first failure, the request is repeated on the new endpoint.
    m.point_to("app2.test", app2);
    down1.store(true, Ordering::SeqCst);
    assert_eq!(ping(&m.client, "moved.test").await.unwrap(), "app2");
    assert_eq!(m.fetches(), 2, "exactly one re-resolution");
    assert_eq!(m.client.cached_delegation("moved.test").unwrap().api.host_str(), Some("app2.test"));
    assert!(m.client.take_stale_document("moved.test"), "the cached document and keys are refetched");
    assert!(!m.client.take_stale_document("moved.test"), "once");

    // It moves again within the minute: the failure stands, no second re-resolution (no amplification).
    let app3 = app_host("app3", flag(), Arc::new(AtomicUsize::new(0))).await;
    m.point_to("app3.test", app3);
    down2.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(ping(&m.client, "moved.test").await.unwrap_err().status(), Some(503));
    }
    assert_eq!(m.fetches(), 2, "at most one re-resolution per domain and minute");
    assert_eq!(m.client.cached_delegation("moved.test").unwrap().api.host_str(), Some("app2.test"));
}

#[tokio::test]
async fn an_unchanged_or_unresolvable_endpoint_is_kept_after_a_failure() {
    let m = Moving::new().await;
    let down = flag();
    let app1 = app_host("app1", down.clone(), Arc::new(AtomicUsize::new(0))).await;
    m.point_to("app1.test", app1);
    assert_eq!(ping(&m.client, "moved.test").await.unwrap(), "app1");
    // The record still names the failing host: resolved again once, nothing repeated, the document stays.
    down.store(true, Ordering::SeqCst);
    assert_eq!(ping(&m.client, "moved.test").await.unwrap_err().status(), Some(503));
    assert_eq!(m.fetches(), 2, "resolved again once");
    assert!(!m.client.take_stale_document("moved.test"), "same endpoint: the document stays");
    assert_eq!(ping(&m.client, "moved.test").await.unwrap_err().status(), Some(503));
    assert_eq!(m.fetches(), 2, "not again within the minute");
    let doc = m.doc.lock().unwrap().to_string();

    // The website fails as well: the cached endpoint stays until its lifetime ends.
    let m = Moving::new().await;
    m.client.seed_delegation("moved.test", doc.as_bytes(), 3600);
    *m.doc.lock().unwrap() = json!({ "domain": "evil.test" });
    assert_eq!(ping(&m.client, "moved.test").await.unwrap_err().status(), Some(503));
    assert_eq!(m.client.cached_delegation("moved.test").unwrap().api.host_str(), Some("app1.test"));
    assert!(m.client.delegation_expires_in("moved.test").unwrap().as_secs() > 3000);

    // Errors that say nothing about the endpoint (here a 404 of the peer) never resolve again.
    let m = Moving::new().await;
    m.client.seed_delegation("moved.test", doc.as_bytes(), 3600);
    let err = m.client.get("moved.test", "/api/v1/missing", Kind::Profile).await.unwrap_err();
    assert_eq!(err.status(), Some(404));
    assert_eq!(m.fetches(), 0);
}

#[tokio::test]
async fn a_failed_inbox_post_moves_the_endpoint_without_repeating_the_post() {
    let m = Moving::new().await;
    let (down1, posts1, posts2) = (flag(), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let app1 = app_host("app1", down1.clone(), posts1.clone()).await;
    let app2 = app_host("app2", flag(), posts2.clone()).await;
    m.point_to("app1.test", app1);
    let doc = m.doc.lock().unwrap().to_string();
    m.client.seed_delegation("moved.test", doc.as_bytes(), 3600);
    m.point_to("app2.test", app2);
    down1.store(true, Ordering::SeqCst);
    let err = m.client.post_inbox("moved.test", "tok", b"{}".to_vec()).await.unwrap_err();
    assert_eq!(err.status(), Some(502), "the outbox retries the notification later");
    assert_eq!(posts2.load(Ordering::SeqCst), 0, "a signed POST is never repeated at once");
    assert_eq!(m.client.cached_delegation("moved.test").unwrap().api.host_str(), Some("app2.test"));
    assert_eq!(m.client.post_inbox("moved.test", "tok", b"{}".to_vec()).await.unwrap(), 202);
    assert_eq!((posts1.load(Ordering::SeqCst), posts2.load(Ordering::SeqCst)), (0, 1));
}

#[test]
fn endpoint_failures_are_transport_errors_and_gateway_answers() {
    let status = |status| FetchError::Status { domain: "x.test".into(), status, retry_after: None };
    for e in
        [FetchError::Unreachable("x".into()), FetchError::Timeout("x".into()), status(502), status(503), status(504)]
    {
        assert!(endpoint_failure(&e), "{e:?}");
    }
    for e in [
        status(500),
        status(404),
        status(429),
        FetchError::AddressForbidden("x".into()),
        FetchError::TooLarge("x".into()),
    ] {
        assert!(!endpoint_failure(&e), "{e:?}");
    }
}

#[test]
fn delegation_records_validate_the_document_and_map_development_peers() {
    let c = client(&config("b.test=http://127.0.0.1:1", true), MapLookup::with(&[]));
    let record = |doc: serde_json::Value| {
        c.record_delegation("a.test", doc.to_string().as_bytes(), 300, DelegationSource::WellKnown)
    };
    assert_eq!(
        record(delegating_doc("a.test", "https://app.a.test")).unwrap().api.as_str(),
        "https://app.a.test/api/v1"
    );
    assert_eq!(
        record(delegating_doc("a.test", "http://127.0.0.1:9")).unwrap().api.as_str(),
        "http://127.0.0.1:9/api/v1"
    );
    // An endpoint on another development peer's host is reached through its mapping; browsers get the
    // declared endpoints.
    let mapped = record(delegating_doc("a.test", "http://b.test:8080")).unwrap();
    assert_eq!(mapped.api.as_str(), "http://127.0.0.1:1/api/v1");
    assert_eq!(mapped.public_api.as_str(), "http://b.test:8080/api/v1");
    assert_eq!(mapped.ws.as_str(), "ws://b.test:8080/api/v1/ws");
    assert_eq!(record(delegating_doc("b.test", "https://x.test")).unwrap_err(), "domain does not match");
    assert_eq!(
        record(json!({ "domain": "a.test", "api": "https://x.test/v2", "ws": "wss://x.test/ws" })).unwrap_err(),
        "api does not end in /api/v1"
    );
    assert_eq!(
        record(json!({ "domain": "a.test", "api": "https://x.test/api/v1" })).unwrap_err(),
        "required field missing"
    );
    assert_eq!(c.record_delegation("a.test", b"<html>", 300, DelegationSource::WellKnown).unwrap_err(), "not JSON");
    // seed() never replaces a fresh entry.
    c.seed_delegation("a.test", delegating_doc("a.test", "https://other.test").to_string().as_bytes(), 300);
    assert_eq!(
        c.cached_delegation("a.test").unwrap().api.as_str(),
        "http://127.0.0.1:1/api/v1",
        "the last valid record"
    );
    c.seed_delegation("c.test", delegating_doc("c.test", "https://app.c.test").to_string().as_bytes(), 0);
    assert!(c.cached_delegation("c.test").is_none(), "an expired document seeds nothing");
}

#[test]
fn endpoint_urls() {
    let prod = |u: &str| endpoint(u, "https", "http", false, false);
    assert!(prod("https://app.tavrn.org/api/v1").is_ok());
    assert!(prod("https://chat.example.net:8443/tavrn/api/v1").is_ok());
    for bad in [
        "http://app.tavrn.org/api/v1",
        "https://user@app.tavrn.org/api/v1",
        "https://app.tavrn.org/api/v1?x=1",
        "https://app.tavrn.org/api/v1#x",
        "https://8.8.8.8/api/v1",
        "https://[2a00:1450::1]/api/v1",
        "https://app_x.tavrn.org/api/v1",
        "javascript:alert(1)",
        "/api/v1",
    ] {
        assert!(prod(bad).is_err(), "{bad}");
    }
    assert!(endpoint("wss://app.tavrn.org/api/v1/ws", "wss", "ws", false, false).is_ok());
    assert!(endpoint("ws://app.tavrn.org/api/v1/ws", "wss", "ws", false, false).is_err());
    // Development: http and public IPs; private IPs only with TAVRN_FEDERATION_ALLOW_PRIVATE.
    assert!(endpoint("http://8.8.8.8/api/v1", "https", "http", true, false).is_ok());
    assert!(endpoint("http://127.0.0.1:1/api/v1", "https", "http", true, false).is_err());
    assert!(endpoint("http://127.0.0.1:1/api/v1", "https", "http", true, true).is_ok());
}

#[test]
fn document_and_delegation_lifetimes() {
    use super::discovery::ttl;
    assert_eq!((ttl(None), ttl(Some(10)), ttl(Some(900)), ttl(Some(86_400))), (300, 300, 900, 3600));
}
