// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Identity domain vs. node host (FEDERATION.md §1.4): a node whose identity domain `a.test`
//! is served by a website that only carries `/.well-known/tavrn`, while the node itself runs on
//! `TAVRN_PUBLIC_URL`. Peers verify its keys through the identity domain and send every API request to the
//! delegated endpoint.

use crate::common;

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
};

use axum::http::{Method, StatusCode};
use common::federation::{A, B, FedNode, SiteMode, delegated_pair, delegated_pair_with};
use futures::future::BoxFuture;
use serde_json::json;
use tavrn_node::{
    app::router,
    federation::{
        client::{ClientOptions, DelegationSource, FederationClient, Kind, Lookup, SrvLookup, SrvRecord},
        discovery,
    },
    store, util,
};

#[tokio::test]
async fn a_delegating_node_federates_through_its_endpoints() {
    let (a, b, site) = delegated_pair().await;
    let (_, wk) = a.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert_eq!(wk["domain"], A, "the identity stays the domain");
    assert_eq!(wk["api"], format!("http://127.0.0.1:{}/api/v1", a.port));
    assert_eq!(wk["ws"], format!("ws://127.0.0.1:{}/api/v1/ws", a.port));

    // A user of A signs in on B: B verifies A's token with the keys from the identity domain.
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    assert_eq!(remote.response["user"]["address"], "alice@a.test");
    let delegation = b.state.federation.cached_delegation(A).unwrap();
    assert_eq!(delegation.api.as_str(), format!("http://127.0.0.1:{}/api/v1", a.port));
    assert_eq!(delegation.source, DelegationSource::WellKnown);

    // The endpoint is cached as long as the document (and its keys).
    let row = store::federation::peer(&b.state.db, A).await.unwrap().unwrap();
    let doc_left = (util::parse_time(&row.expires_at).unwrap() - chrono::Utc::now()).num_seconds();
    let endpoint_left = b.state.federation.delegation_expires_in(A).unwrap().as_secs() as i64;
    assert!((doc_left - endpoint_left).abs() <= 5, "document {doc_left} s, endpoint {endpoint_left} s");

    // B → A: a friend request goes to A's inbox on the delegated host, never to the website.
    let bob = b.register("bob").await;
    let (st, j) = b.post("/api/v1/users/me/friends/requests", &bob.token, json!({ "user": "alice@a.test" })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(b.deliver().await.delivered, 1);
    let (_, friends) = a.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(friends["incoming"][0]["user"]["address"], "bob@b.test", "{friends}");
    let rid = friends["incoming"][0]["id"].as_str().unwrap();
    let (st, _) = a.post(&format!("/api/v1/users/me/friends/requests/{rid}/accept"), &alice.token, json!({})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(a.deliver().await.delivered, 1);
    let (_, friends) = b.get_auth("/api/v1/users/me/friends", &bob.token).await;
    assert_eq!(friends["friends"][0]["user"]["address"], "alice@a.test", "{friends}");

    // Keys of a remote user come from the home node's delegated API.
    let keys = b.state.federation.get(A, "/api/v1/users/alice/keys", tavrn_node::federation::client::Kind::Keys).await;
    assert!(keys.is_ok(), "{keys:?}");
    assert_eq!(site.other_requests.load(Ordering::SeqCst), 0, "the website only served the well-known");
}

#[tokio::test]
async fn a_restarted_peer_takes_the_endpoint_from_its_cached_document() {
    let (a, mut b, site) = delegated_pair().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    // "Restart" B's federation client: the endpoint cache is empty, the document cache (database) is not.
    b.node.state.federation = Arc::new(FederationClient::from_config(&b.state.config).unwrap());
    b.node.router = router(b.node.state.clone());
    assert!(b.state.federation.cached_delegation(A).is_none());
    // A fresh document in the database seeds the endpoint without asking the website again.
    *site.mode.lock().unwrap() = SiteMode::WrongDomain;
    discovery::document(&b.state, A).await.unwrap();
    assert_eq!(
        b.state.federation.cached_delegation(A).unwrap().api.as_str(),
        format!("http://127.0.0.1:{}/api/v1", a.port)
    );
}

#[tokio::test]
async fn a_well_known_naming_another_domain_is_refused() {
    let (a, b, site) = delegated_pair().await;
    *site.mode.lock().unwrap() = SiteMode::WrongDomain;
    let alice = a.register("alice").await;
    let token = a.federation_token(&alice, B).await;
    let (status, j) = b.federated_login(&token).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{j}");
    assert_eq!(j["code"], "federation.peer_invalid");
    assert!(b.state.federation.cached_delegation(A).is_none());
    assert_eq!(site.other_requests.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------- resolution for browsers, moved endpoints

#[tokio::test]
async fn browsers_get_the_resolution_of_their_node() {
    let (a, b, site) = delegated_pair_with(|c| c.federation_blocklist = "blocked.test".into()).await;
    let (_, wk) = a.req(Method::GET, "/.well-known/tavrn", None, None).await;
    let (status, r) = b.get_auth("/api/v1/federation/resolve/a.test", "").await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["domain"], A);
    assert_eq!(r["api"], format!("http://127.0.0.1:{}/api/v1", a.port));
    assert_eq!(r["ws"], wk["ws"]);
    assert_eq!(r["web"], wk["web"]);
    assert_eq!(r["source"], "well_known");
    assert_eq!(r.as_object().unwrap().len(), 5, "only the endpoints, never the peer's body: {r}");

    // The checks of the peer document route: no self, node domains only, the domain policy.
    let (status, j) = b.get_auth("/api/v1/federation/resolve/b.test", "").await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.target_self")));
    for bad in ["localhost", "127.0.0.1", "a.test:8080", "A_B.test", "169.254.169.254", "%2e%2e"] {
        let (status, j) = b.get_auth(&format!("/api/v1/federation/resolve/{bad}"), "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert_eq!(j["code"], "federation.domain_invalid", "{bad}");
    }
    let (status, j) = b.get_auth("/api/v1/federation/resolve/blocked.test", "").await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
    drop(site);
}

#[tokio::test]
async fn a_resolution_naming_another_domain_is_refused() {
    let (_a, b, site) = delegated_pair().await;
    *site.mode.lock().unwrap() = SiteMode::WrongDomain;
    let (status, j) = b.get_auth("/api/v1/federation/resolve/a.test", "").await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("federation.peer_invalid")), "{j}");
    assert!(b.state.federation.cached_delegation(A).is_none());
}

#[tokio::test]
async fn peer_resolutions_are_rate_limited_per_ip() {
    let (_a, b, _site) = delegated_pair().await;
    // Development nodes allow 1000 lookups a minute per IP (production 10), shared with /federation/peer.
    let mut limited = None;
    for i in 0..1100 {
        let path = if i % 2 == 0 { "/api/v1/federation/resolve/x.test" } else { "/api/v1/federation/peer/x.test" };
        let (status, j) = b.get_auth(path, "").await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(j["code"], "rate_limited");
            limited = Some(i);
            break;
        }
    }
    assert!(limited.is_some_and(|i| i >= 999), "{limited:?}");
}

/// DNS answers from a table (the SRV path needs hosts that are not development peers).
struct Hosts(Vec<(&'static str, IpAddr)>);

impl Lookup for Hosts {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        let found: Vec<IpAddr> = self.0.iter().filter(|(h, _)| *h == host).map(|(_, ip)| *ip).collect();
        Box::pin(async move {
            if found.is_empty() {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unknown host"))
            } else {
                Ok(found)
            }
        })
    }
}

/// SRV records from a table.
struct Srv(Vec<(&'static str, &'static str, u16)>);

impl SrvLookup for Srv {
    fn srv(&self, name: String) -> BoxFuture<'static, std::io::Result<Vec<SrvRecord>>> {
        let records: Vec<SrvRecord> = self
            .0
            .iter()
            .filter(|(n, _, _)| *n == name)
            .map(|(_, target, port)| SrvRecord { priority: 0, weight: 0, port: *port, target: target.to_string() })
            .collect();
        Box::pin(async move {
            if records.is_empty() {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no record"))
            } else {
                Ok(records)
            }
        })
    }
}

/// A static website: `/.well-known/tavrn` answers `doc` (404 when `None`), everything else 404.
async fn static_site(doc: Option<serde_json::Value>) -> SocketAddr {
    let mut app = axum::Router::new();
    if let Some(doc) = doc {
        app = app.route("/.well-known/tavrn", axum::routing::get(move || async move { axum::Json(doc.clone()) }));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// B's federation client with mock DNS and SRV, plus `extra_peers` as development peers.
fn with_dns(b: &mut FedNode, extra_peers: &str, hosts: Hosts, srv: Srv) {
    let mut config = (*b.state.config).clone();
    config.federation_dev_peers = format!("{},{extra_peers}", config.federation_dev_peers);
    let options = ClientOptions { lookup: Arc::new(hosts), srv: Arc::new(srv), ..ClientOptions::default() };
    b.node.state.federation = Arc::new(FederationClient::with_options(&config, options).unwrap());
    b.node.router = router(b.node.state.clone());
}

#[tokio::test]
async fn srv_only_setups_resolve_for_browsers_too() {
    let (a, mut b, _site) = delegated_pair().await;
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    // `srv.test` has no HTTPS server at all; `web.test` has a website without a document. Both publish
    // `_tavrn._tcp` records naming a host that serves their document.
    let doc = |domain: &str| {
        json!({ "tavrn": 1, "domain": domain, "api": format!("http://127.0.0.1:{}/api/v1", a.port),
                "ws": format!("ws://127.0.0.1:{}/api/v1/ws", a.port), "web": "http://127.0.0.1:1" })
    };
    let srv_host = static_site(Some(doc("srv.test"))).await;
    let web_host = static_site(Some(doc("web.test"))).await;
    let liar = static_site(Some(doc("other.test"))).await;
    let website = static_site(None).await;
    let plain = static_site(None).await;
    with_dns(
        &mut b,
        &format!("web.test=http://{website},liar.test=http://{website},plain.test=http://{plain}"),
        Hosts(vec![("node.srv.test", localhost), ("node.web.test", localhost), ("node.liar.test", localhost)]),
        Srv(vec![
            ("_tavrn._tcp.srv.test.", "node.srv.test", srv_host.port()),
            ("_tavrn._tcp.web.test.", "node.web.test", web_host.port()),
            ("_tavrn._tcp.liar.test.", "node.liar.test", liar.port()),
        ]),
    );
    for domain in ["srv.test", "web.test"] {
        let (status, r) = b.get_auth(&format!("/api/v1/federation/resolve/{domain}"), "").await;
        assert_eq!(status, StatusCode::OK, "{domain}: {r}");
        assert_eq!((r["source"].as_str(), r["domain"].as_str()), (Some("srv"), Some(domain)));
        assert_eq!(r["api"], format!("http://127.0.0.1:{}/api/v1", a.port));
    }
    // No document, no SRV record: the domain itself, last.
    let (status, r) = b.get_auth("/api/v1/federation/resolve/plain.test", "").await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["source"], "domain");
    assert_eq!(r["api"], "https://plain.test/api/v1", "the declared endpoints, never a development mapping");
    assert_eq!(r["ws"], "wss://plain.test/api/v1/ws");
    assert_eq!(r["web"], "https://plain.test");
    // An SRV target whose document claims another domain is refused.
    let (status, j) = b.get_auth("/api/v1/federation/resolve/liar.test", "").await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("federation.peer_invalid")), "{j}");
    // Neither SRV record nor server: unreachable.
    let (status, j) = b.get_auth("/api/v1/federation/resolve/nothing.test", "").await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("federation.peer_unreachable")), "{j}");
}

#[tokio::test]
async fn a_moved_node_is_found_again_at_the_first_failure_and_its_keys_refetched() {
    let (a, b, site) = delegated_pair().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    let before = store::federation::peer(&b.state.db, A).await.unwrap().unwrap();
    assert!(b.state.federation.delegation_expires_in(A).unwrap().as_secs() > 200);

    // A moves to another host: the website's document names it, the old host is gone.
    let moved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new_port = moved.local_addr().unwrap().port();
    let a_router = a.node.router.clone();
    tokio::spawn(async move {
        axum::serve(moved, a_router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    *site.mode.lock().unwrap() = SiteMode::MovedTo(new_port);
    a.stop().await;

    // The next request finds the new host instead of failing until the cached endpoint expires.
    let keys = b.state.federation.get(A, "/api/v1/users/alice/keys", Kind::Keys).await;
    assert!(keys.is_ok(), "{keys:?}");
    assert_eq!(
        b.state.federation.cached_delegation(A).unwrap().api.as_str(),
        format!("http://127.0.0.1:{new_port}/api/v1")
    );
    // The cached document (and the keys in it) is fetched again on its next use.
    discovery::document(&b.state, A).await.unwrap();
    let after = store::federation::peer(&b.state.db, A).await.unwrap().unwrap();
    assert!(after.document.contains(&format!("127.0.0.1:{new_port}")), "{}", after.document);
    assert_ne!(before.document, after.document);
}
