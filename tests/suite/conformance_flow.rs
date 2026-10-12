// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Conformance checks and reputation (FEDERATION.md §9, phase 3 step 7). `a.test` checks `b.test`
//! through the real federation client; `b.test` is either conforming or a deliberately broken
//! development node (`TAVRN_DEV_MISBEHAVE`): it accepts bad signatures, replays, plaintext in encrypted
//! channels, or never rate-limits.

use crate::common;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::http::{Method, StatusCode};
use common::{
    Session,
    federation::{A, B, FedNode, two_nodes, two_nodes_with},
};
use serde_json::{Value, json};
use tavrn_node::{
    app::AppState,
    federation::{
        announce,
        client::{ClientOptions, FederationClient, Lookup},
        conformance::{self, PROBE_USERNAME},
        tokens::body_sha256,
    },
    store, util,
};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The first user registered on a node is its admin.
async fn admin(node: &FedNode) -> Session {
    node.register("root").await
}

async fn check(node: &FedNode, admin: &Session, peer: &str) -> Value {
    let (status, json) =
        node.post(&format!("/api/v1/admin/federation/peers/{peer}/check"), &admin.token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    json
}

/// Result of check `id` in a peer answer.
fn result<'a>(peer: &'a Value, id: &str) -> &'a str {
    peer["record"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("check {id} missing: {peer}"))["result"]
        .as_str()
        .unwrap()
}

async fn status_of(node: &FedNode, peer: &str) -> String {
    store::conformance::peer_state(&node.state.db, peer).await.unwrap().map(|p| p.status).unwrap_or_default()
}

/// Posts `body` to `to`'s inbox with a node token of `from` whose `body_sha256` covers `signed`.
async fn deliver_signed(from: &FedNode, to: &FedNode, signed: &[u8], body: &[u8]) -> (StatusCode, Value) {
    let n = now();
    let claims = json!({
        "iss": from.domain(), "sub": from.domain(), "aud": to.domain(), "iat": n, "exp": n + 300,
        "jti": util::ulid(), "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox",
        "body_sha256": body_sha256(signed),
    });
    let token = from.sign(&claims);
    let (status, _, bytes) = to
        .raw(Method::POST, "/api/v1/federation/inbox", &token, &[("content-type", "application/json")], body.to_vec())
        .await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

fn envelope(kind: &str, from: &str, to: &str, payload: Value) -> Vec<u8> {
    json!({ "id": util::ulid(), "type": kind, "from": from, "to": to, "at": util::now(), "payload": payload })
        .to_string()
        .into_bytes()
}

async fn audit_actions(node: &FedNode, admin: &Session) -> Vec<String> {
    let (status, log) = node.get_auth("/api/v1/admin/audit-log?limit=50", &admin.token).await;
    assert_eq!(status, StatusCode::OK, "{log}");
    log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap().to_string()).collect()
}

const ALL_CHECKS: &[&str] = &[
    "wk.fetch",
    "wk.schema",
    "keys.consistent",
    "token.accept",
    "mls.sequence",
    "mls.reject",
    "msg.plaintext",
    "msg.ciphertext",
    "token.replay",
    "token.bad_signature",
    "token.alg",
    "token.aud",
    "token.expired",
    "token.issuer_mismatch",
    "s2s.unsigned",
    "s2s.body_hash",
    "s2s.replay",
    "time.skew",
    "rate.limits",
];

#[tokio::test]
async fn a_conforming_peer_passes_every_check() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.reference_nodes = A.into()).await;
    let root = admin(&a).await;
    // b.test is listed in a.test's directory (announce), so its card shows the result.
    let payload = serde_json::to_value(announce::own_announce(&b.state).await.unwrap()).unwrap();
    let body = envelope("node.announce", B, A, payload);
    let (status, json) = deliver_signed(&b, &a, &body, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{json}");
    let (_, nodes) = a.req(Method::GET, "/api/v1/directory/nodes", None, None).await;
    assert_eq!(nodes["items"][1]["domain"], B, "after a.test itself");
    assert_eq!(nodes["items"][1]["conformance"], "unknown");

    let peer = check(&a, &root, B).await;
    for id in ALL_CHECKS {
        assert_eq!(result(&peer, id), "pass", "{id}: {peer}");
    }
    assert_eq!(peer["conformance"], "pass", "{peer}");
    assert_eq!(peer["status"], "ok");
    assert_eq!(peer["hard_failures"], 0);
    assert_eq!(peer["record"]["history"].as_array().unwrap().len(), 1);
    assert!(peer["record"]["software"].as_str().unwrap().starts_with("tavrn-node/"), "{peer}");

    // The conformance room on b.test was deleted by the probe; nothing else was created there.
    let rooms: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM rooms").fetch_one(&b.state.db).await.unwrap();
    assert_eq!(rooms, 0);
    // The run was audited and is listed.
    assert!(audit_actions(&a, &root).await.contains(&"admin.federation_check".to_string()));
    let (status, peers) = a.get_auth("/api/v1/admin/federation/peers", &root.token).await;
    assert_eq!(status, StatusCode::OK, "{peers}");
    assert!(peers.as_array().unwrap().iter().any(|p| p["domain"] == B && p["conformance"] == "pass"), "{peers}");
    // The directory card and the public peer state show the result.
    let (_, nodes) = a.req(Method::GET, "/api/v1/directory/nodes", None, None).await;
    assert_eq!(nodes["items"][1]["conformance"], "pass", "{nodes}");
    let (status, state) = a.req(Method::GET, "/api/v1/federation/peers/b.test/state", None, None).await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert_eq!(state["conformance"], "pass");
    assert_eq!(state["blocked"], false);
    assert_eq!(state["keys"].as_array().unwrap().len(), 1, "{state}");

    // Unforced runs within the hour return the stored record.
    let again = conformance::run(&a.state, B, false).await.unwrap();
    assert_eq!(again.checked_at, peer["record"]["checked_at"].as_str().unwrap());
}

// ---------------------------------------------------------------- keys.consistent across addresses

/// Test DNS: `b-multi.test` resolves to two loopback addresses, like a domain with an IPv4 and an IPv6
/// address (or several hosts).
struct TwoAddresses;

impl Lookup for TwoAddresses {
    fn lookup(&self, host: String) -> futures::future::BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            if host == "b-multi.test" {
                Ok(vec![IpAddr::from([127, 0, 0, 1]), IpAddr::from([127, 0, 0, 2])])
            } else {
                Err(std::io::Error::other("unknown host"))
            }
        })
    }
}

/// a.test's state, but its federation client reaches b.test through `b-multi.test`.
fn multi_address_checker(a: &FedNode, b: &FedNode) -> AppState {
    let mut config = (*a.state.config).clone();
    config.federation_dev_peers = format!("{B}=http://b-multi.test:{}", b.port);
    let options = ClientOptions { lookup: Arc::new(TwoAddresses), ..Default::default() };
    let mut state = a.state.clone();
    state.federation = Arc::new(FederationClient::with_options(&config, options).unwrap());
    state
}

/// Serves `router` on `127.0.0.2:port` (beside a node on `127.0.0.1:port`).
fn serve_on_second_address(router: axum::Router, port: u16) -> tokio::task::JoinHandle<()> {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind(SocketAddr::from(([127, 0, 0, 2], port))).unwrap();
    let listener = socket.listen(64).unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    })
}

#[tokio::test]
async fn keys_must_be_the_same_on_every_address_of_a_peer() {
    let (a, b) = two_nodes().await;
    let checker = multi_address_checker(&a, &b);

    // b.test itself on both addresses: the same keys everywhere.
    let same = serve_on_second_address(b.router.clone(), b.port);
    let seen = conformance::keys_by_address(&checker, B).await;
    assert_eq!(seen.iter().map(|(ip, _)| ip.to_string()).collect::<Vec<_>>(), vec!["127.0.0.1", "127.0.0.2"]);
    assert_eq!(conformance::compare_address_keys(&seen), Ok(()));
    same.abort();
    let _ = same.await;

    // Another node answers for b.test on the second address with other keys: a split view.
    let impostor = common::test_node(B).await;
    let _split = serve_on_second_address(impostor.router.clone(), b.port);
    let seen = conformance::keys_by_address(&checker, B).await;
    assert_eq!(seen.len(), 2);
    let detail = conformance::compare_address_keys(&seen).unwrap_err();
    assert!(detail.contains("127.0.0.1 and 127.0.0.2"), "{detail}");

    // In a run that is a hard failure: the peer is blocked automatically.
    let record = conformance::run(&checker, B, true).await.unwrap();
    let keys = record.checks.iter().find(|c| c.id == "keys.consistent").unwrap();
    assert_eq!(serde_json::to_value(keys.result).unwrap(), "fail", "{:?}", record.checks);
    assert!(keys.detail.as_deref().unwrap_or("").contains("127.0.0.2"));
    assert_eq!(record.result, "fail");
    assert_eq!(status_of(&a, B).await, "blocked_auto");
}

#[tokio::test]
async fn accepting_bad_signatures_is_a_hard_failure_that_blocks() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.dev_misbehave = "accept_bad_signatures".into()).await;
    let root = admin(&a).await;
    let alice = a.register("alice").await;
    // bob of b.test has a federated session on a.test before the check.
    let bob = b.register("bob").await;
    let remote = a.sign_in_from(&b, &bob).await;
    let (status, _) = a.get_auth("/api/v1/users/me", &remote.token).await;
    assert_eq!(status, StatusCode::OK);

    // `doctor --peer` prints the table and exits with 1; the result is stored like an admin's run.
    let (report, code) = conformance::doctor(&a.state, B).await;
    assert_eq!(code, 1, "{report}");
    assert!(report.starts_with("Conformance check of b.test: FAIL"), "{report}");
    assert!(report.lines().any(|l| l.starts_with("token.bad_signature") && l.contains("fail")), "{report}");
    // A second run within the minute of the rate burst is refused.
    let (status, json) = a.post("/api/v1/admin/federation/peers/b.test/check", &root.token, json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{json}");

    let (_, peers) = a.get_auth("/api/v1/admin/federation/peers", &root.token).await;
    let peer = peers.as_array().unwrap().iter().find(|p| p["domain"] == B).unwrap().clone();
    assert_eq!(result(&peer, "token.bad_signature"), "fail", "{peer}");
    assert_eq!(result(&peer, "token.alg"), "fail", "{peer}");
    assert_eq!(result(&peer, "token.accept"), "pass", "{peer}");
    assert_eq!(peer["conformance"], "fail");
    assert_eq!(peer["status"], "blocked_auto");
    assert!(peer["blocked_reason"].as_str().unwrap().contains("token.bad_signature"), "{peer}");
    assert!(peer["hard_failures"].as_i64().unwrap() >= 2, "{peer}");

    // Blocked in both directions; bob's session ended.
    let (status, json) = a.post("/api/v1/federation/token", &alice.token, json!({ "target": B })).await;
    assert_eq!((status, json["code"].as_str().unwrap()), (StatusCode::FORBIDDEN, "federation.peer_blocked"));
    let token = b.federation_token(&bob, A).await;
    let (status, json) = a.federated_login(&token).await;
    assert_eq!((status, json["code"].as_str().unwrap()), (StatusCode::FORBIDDEN, "federation.peer_blocked"));
    let (status, _) = a.get_auth("/api/v1/users/me", &remote.token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, state) = a.req(Method::GET, "/api/v1/federation/peers/b.test/state", None, None).await;
    assert_eq!((state["blocked"].as_bool(), state["conformance"].as_str()), (Some(true), Some("fail")));
    assert!(audit_actions(&a, &root).await.contains(&"federation.block_auto".to_string()));
}

#[tokio::test]
async fn accepting_replays_is_a_hard_failure() {
    let (a, _b) = two_nodes_with(|_| {}, |c| c.dev_misbehave = "replay_ok".into()).await;
    let root = admin(&a).await;
    let peer = check(&a, &root, B).await;
    assert_eq!(result(&peer, "token.replay"), "fail", "{peer}");
    assert_eq!(result(&peer, "s2s.replay"), "fail", "{peer}");
    assert_eq!(result(&peer, "token.bad_signature"), "pass", "{peer}");
    assert_eq!(peer["status"], "blocked_auto");
}

#[tokio::test]
async fn accepting_plaintext_in_encrypted_channels_is_a_hard_failure() {
    let (a, _b) = two_nodes_with(|_| {}, |c| c.dev_misbehave = "plaintext_ok".into()).await;
    let root = admin(&a).await;
    let peer = check(&a, &root, B).await;
    assert_eq!(result(&peer, "msg.plaintext"), "fail", "{peer}");
    assert_eq!(result(&peer, "mls.sequence"), "pass", "{peer}");
    assert_eq!(result(&peer, "mls.reject"), "pass", "{peer}");
    assert_eq!(peer["status"], "blocked_auto");
}

#[tokio::test]
async fn a_missing_rate_limit_only_warns_and_does_not_block() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.dev_misbehave = "no_rate_limit".into()).await;
    let root = admin(&a).await;
    let alice = a.register("alice").await;
    let peer = check(&a, &root, B).await;
    assert_eq!(result(&peer, "rate.limits"), "warn", "{peer}");
    assert_eq!(peer["conformance"], "warn", "{peer}");
    assert_eq!(peer["status"], "ok");
    assert_eq!(peer["soft_failures"], 1);
    // Warnings never block: federation works in both directions.
    a.federation_token(&alice, B).await;
    let bob = b.register("bob").await;
    a.sign_in_from(&b, &bob).await;
    let (_, state) = a.req(Method::GET, "/api/v1/federation/peers/b.test/state", None, None).await;
    assert_eq!((state["blocked"].as_bool(), state["conformance"].as_str()), (Some(false), Some("warn")));
}

/// Waits until `node` has a conformance result for `peer` (a background run).
async fn wait_for_result(node: &FedNode, peer: &str) -> String {
    for _ in 0..common::rounds(300) {
        if let Some(r) =
            store::conformance::peer_state(&node.state.db, peer).await.unwrap().and_then(|p| p.conformance_result)
            && !node.state.conformance.is_running(peer)
        {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no conformance result for {peer}");
}

#[tokio::test]
async fn require_conformance_waits_for_the_first_run() {
    let (a, b) = two_nodes_with(|c| c.federation_require_conformance = true, |_| {}).await;
    // A token that does not verify is refused as such and starts no check (anyone can name any `iss`).
    let n = now();
    let forged = json!({ "iss": B, "sub": "bob@b.test", "aud": A, "iat": n, "exp": n + 300, "jti": util::ulid(),
                         "typ": "federation", "kind": "user", "device": util::ulid(), "pv": 1 });
    let key = tavrn_node::keys::NodeKey::generate(&b.state.signing_key().kid);
    let (status, json) = a.federated_login(&tavrn_node::jwt::sign(&key.signing, &key.kid, &forged).unwrap()).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("federation.token_invalid")));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!a.state.conformance.is_running(B));
    assert!(
        store::conformance::peer_state(&a.state.db, B).await.unwrap().and_then(|p| p.conformance_checked_at).is_none()
    );

    let bob = b.register("bob").await;
    let token = b.federation_token(&bob, A).await;
    let (status, json) = a.federated_login(&token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(json["code"], "federation.conformance_pending");
    assert_eq!(json["meta"]["retry_after_secs"], 60);
    let body = envelope("conformance.probe", B, A, json!({}));
    let (status, json) = deliver_signed(&b, &a, &body, &body).await;
    assert_eq!(
        (status, json["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("federation.conformance_pending"))
    );

    // The refused login started a check of b.test; once it passed, b.test is welcome.
    assert_eq!(wait_for_result(&a, B).await, "pass");
    a.sign_in_from(&b, &bob).await;
    let body = envelope("conformance.probe", B, A, json!({}));
    let (status, json) = deliver_signed(&b, &a, &body, &body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{json}");
}

#[tokio::test]
async fn require_conformance_refuses_failing_peers() {
    let (a, b) =
        two_nodes_with(|c| c.federation_require_conformance = true, |c| c.dev_misbehave = "plaintext_ok".into()).await;
    let bob = b.register("bob").await;
    let token = b.federation_token(&bob, A).await;
    let (status, _) = a.federated_login(&token).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(wait_for_result(&a, B).await, "fail");
    let token = b.federation_token(&bob, A).await;
    let (status, json) = a.federated_login(&token).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
}

#[tokio::test]
async fn admins_block_and_unblock_peers_and_it_is_audited() {
    let (a, b) = two_nodes().await;
    let root = admin(&a).await;
    let alice = a.register("alice").await;
    // Admin routes only.
    let (status, _) = a.post("/api/v1/admin/federation/peers/b.test/block", &alice.token, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, json) = a.post("/api/v1/admin/federation/peers/a.test/block", &root.token, json!({})).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.target_self")));
    let (status, json) = a.post("/api/v1/admin/federation/peers/not_a_domain/check", &root.token, json!({})).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.domain_invalid")));

    let (status, peer) =
        a.post("/api/v1/admin/federation/peers/b.test/block", &root.token, json!({ "reason": "spam" })).await;
    assert_eq!(status, StatusCode::OK, "{peer}");
    assert_eq!((peer["status"].as_str(), peer["blocked_reason"].as_str()), (Some("blocked"), Some("spam")));
    let (status, json) = a.post("/api/v1/admin/federation/peers/b.test/block", &root.token, json!({})).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::CONFLICT, Some("federation.already_blocked")));
    let (status, _) = a.post("/api/v1/federation/token", &alice.token, json!({ "target": B })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A run without hard failures does not lift a manual block. (While blocked here, the peer cannot
    // claim the probe's KeyPackages from this node, so the MLS sequence only warns.)
    let peer = check(&a, &root, B).await;
    assert_eq!((peer["conformance"].as_str(), peer["status"].as_str()), (Some("warn"), Some("blocked")), "{peer}");
    assert_eq!(result(&peer, "mls.sequence"), "warn");

    let (status, peer) = a.post("/api/v1/admin/federation/peers/b.test/unblock", &root.token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{peer}");
    assert_eq!(peer["status"], "ok");
    assert!(peer["blocked_at"].is_null());
    let (status, json) = a.post("/api/v1/admin/federation/peers/b.test/unblock", &root.token, json!({})).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::CONFLICT, Some("federation.not_blocked")));
    a.federation_token(&alice, B).await;
    let actions = audit_actions(&a, &root).await;
    for action in ["admin.federation_block", "admin.federation_unblock", "admin.federation_check"] {
        assert!(actions.contains(&action.to_string()), "{action}: {actions:?}");
    }
    drop(b);
}

#[tokio::test]
async fn an_automatic_block_is_lifted_by_a_clean_run_and_unblocking_is_audited() {
    let (a, b) = two_nodes().await;
    let root = admin(&a).await;
    conformance::block_auto(&a.state, B, "test").await.unwrap();
    assert_eq!(status_of(&a, B).await, "blocked_auto");
    let peer = check(&a, &root, B).await;
    assert_eq!((peer["conformance"].as_str(), peer["status"].as_str()), (Some("warn"), Some("ok")), "{peer}");
    assert!(audit_actions(&a, &root).await.contains(&"federation.unblock_auto".to_string()));

    // An operator can lift an automatic block at once.
    conformance::block_auto(&a.state, B, "test").await.unwrap();
    let (status, peer) = a.post("/api/v1/admin/federation/peers/b.test/unblock", &root.token, json!({})).await;
    assert_eq!((status, peer["status"].as_str()), (StatusCode::OK, Some("ok")));
    let log = a.get_auth("/api/v1/admin/audit-log?limit=5", &root.token).await.1;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "admin.federation_unblock").unwrap();
    assert_eq!(entry["target"], B);
    assert_eq!(entry["meta"]["previous"], "blocked_auto");
    drop(b);
}

#[tokio::test]
async fn the_probe_account_cannot_log_in_and_is_hidden() {
    let (a, b) = two_nodes().await;
    let probe = conformance::ensure_probe(&a.state).await.unwrap();
    assert_eq!(probe.address(), "tavrn-conformance@a.test");
    assert!(probe.user.password_hash.is_none());
    assert!(probe.user.identity_pubkey.is_some());
    // Stable keys: a second call keeps identity and devices.
    let again = conformance::ensure_probe(&a.state).await.unwrap();
    assert_eq!(again.user.identity_pubkey, probe.user.identity_pubkey);
    assert_eq!(again.device_ids, probe.device_ids);
    assert_eq!(store::e2ee::attested_devices(&a.state.db, &probe.user.id).await.unwrap().len(), 2);

    // The first real user is still the admin; the probe is neither listed nor counted.
    let root = admin(&a).await;
    let (_, me) = a.get_auth("/api/v1/users/me", &root.token).await;
    assert_eq!(me["is_node_admin"], true, "{me}");
    let (_, users) = a.get_auth("/api/v1/admin/users?q=conformance", &root.token).await;
    assert_eq!(users.as_array().unwrap().len(), 0, "{users}");
    let (_, overview) = a.get_auth("/api/v1/admin/overview", &root.token).await;
    assert_eq!(overview["users"], 1, "{overview}");

    // No login with any password; the name is reserved on every node, also before the probe exists.
    for password in ["", "password-tavrn-conformance-123"] {
        let (status, json) = a
            .req(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some(json!({ "username": PROBE_USERNAME, "date_of_birth": "1990-01-01", "password": password })),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
    }
    for node in [&a, &b] {
        let (status, json) = node
            .req(
                Method::POST,
                "/api/v1/auth/register",
                None,
                Some(json!({ "username": PROBE_USERNAME, "date_of_birth": "1990-01-01", "password": "password-long-enough-123" })),
            )
            .await;
        assert_eq!((status, json["code"].as_str()), (StatusCode::CONFLICT, Some("auth.username_taken")));
    }
}

#[tokio::test]
async fn conformance_rooms_are_for_probes_only_and_expire() {
    let (a, b) = two_nodes().await;
    let probe = conformance::ensure_probe(&a.state).await.unwrap();
    let token = conformance::probe_token(&a.state, &probe, 0, B).await.unwrap();
    let (status, session) = b.federated_login(&token).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let s = session["access_token"].as_str().unwrap();

    // Created regardless of TAVRN_ROOM_CREATION (remote users may not create rooms on b.test).
    let (status, json) = b.post("/api/v1/rooms", s, json!({ "name": "x" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{json}");
    let (status, first) = b.post(conformance::ROOM_PATH, s, json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_eq!(first["conversation_id"], first["channel_id"]);
    let (status, room) = b.get_auth(&format!("/api/v1/rooms/{}", first["room_id"].as_str().unwrap()), s).await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let encrypted: Vec<(String, bool)> = room["channels"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == "text")
        .map(|c| (c["id"].as_str().unwrap().to_string(), c["encrypted"].as_bool().unwrap()))
        .collect();
    assert!(encrypted.contains(&(first["channel_id"].as_str().unwrap().to_string(), true)), "{room}");
    assert!(encrypted.contains(&(first["plaintext_channel_id"].as_str().unwrap().to_string(), false)), "{room}");
    let (_, discover) = b.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover.as_array().unwrap().len(), 0);

    // Not for local users or other remote users.
    let carol = b.register("carol").await;
    let (status, json) = b.post(conformance::ROOM_PATH, &carol.token, json!({})).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("conformance.probe_only")));
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (status, _) = b.post(conformance::ROOM_PATH, &remote.token, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let path = format!("{}/{}", conformance::ROOM_PATH, first["room_id"].as_str().unwrap());
    let (status, _) = b.delete(&path, &remote.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // One at a time: a new room replaces the old one.
    let (status, second) = b.post(conformance::ROOM_PATH, s, json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let (status, _) = b.get_auth(&format!("/api/v1/rooms/{}", first["room_id"].as_str().unwrap()), s).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = b.delete(&path, s).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Housekeeping deletes it after 15 minutes.
    assert_eq!(conformance::housekeeping(&b.state, chrono::Utc::now()).await.unwrap(), 0);
    let later = chrono::Utc::now() + chrono::Duration::minutes(16);
    assert_eq!(conformance::housekeeping(&b.state, later).await.unwrap(), 1);
    let (status, _) = b.get_auth(&format!("/api/v1/rooms/{}", second["room_id"].as_str().unwrap()), s).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn observed_spoofing_blocks_the_sender() {
    let (a, b) = two_nodes().await;
    let root_b = admin(&b).await;
    let unblock = || async {
        let (status, json) = b.post("/api/v1/admin/federation/peers/a.test/unblock", &root_b.token, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{json}");
    };

    // A body that does not match the signed hash: three within ten minutes block (the probe's own
    // `conformance.probe` envelopes do not count).
    let probe_body = envelope("conformance.probe", A, B, json!({}));
    for _ in 0..3 {
        let (status, json) = deliver_signed(&a, &b, b"{}", &probe_body).await;
        assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("federation.body_hash_mismatch")));
    }
    assert_eq!(status_of(&b, A).await, "ok");
    let body = envelope("friend.request", "alice@a.test", "bob@b.test", json!({ "request_id": util::ulid() }));
    for i in 0..3 {
        assert_eq!(status_of(&b, A).await, "ok", "after {i}");
        let (status, _) = deliver_signed(&a, &b, b"{}", &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(status_of(&b, A).await, "blocked_auto");
    let (status, json) = deliver_signed(&a, &b, &body, &body).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
    unblock().await;
    sqlx::query("DELETE FROM federation_violations").execute(&b.state.db).await.unwrap();

    // A validly signed federation token for a user of another domain blocks at once (not the probe's).
    let n = now();
    let claims = |sub: &str| {
        json!({ "iss": A, "sub": sub, "aud": B, "iat": n, "exp": n + 300, "jti": util::ulid(), "typ": "federation",
                "kind": "user", "device": util::ulid(), "pv": 1 })
    };
    let (status, json) = b.federated_login(&a.sign(&claims("tavrn-conformance@c.test"))).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("federation.issuer_mismatch")));
    assert_eq!(status_of(&b, A).await, "ok");
    let (status, _) = b.federated_login(&a.sign(&claims("mallory@c.test"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(status_of(&b, A).await, "blocked_auto");
    unblock().await;

    // An inbox message with a `from` its sender may not use blocks at once.
    b.register("bob").await;
    let forged = envelope("friend.request", "carol@c.test", "bob@b.test", json!({ "request_id": util::ulid() }));
    let (status, json) = deliver_signed(&a, &b, &forged, &forged).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.type_forbidden")));
    assert_eq!(status_of(&b, A).await, "blocked_auto");

    // The record lists the violations.
    let (_, peers) = b.get_auth("/api/v1/admin/federation/peers", &root_b.token).await;
    let peer = peers.as_array().unwrap().iter().find(|p| p["domain"] == A).unwrap();
    assert!(peer["violations"].as_i64().unwrap() >= 5, "{peer}");
    let kinds: Vec<&str> =
        peer["recent_violations"].as_array().unwrap().iter().map(|v| v["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["issuer_mismatch", "type_forbidden"], "{peer}");
    assert!(peer["blocked_reason"].as_str().unwrap().contains("type_forbidden"), "{peer}");
}

#[tokio::test]
async fn doctor_prints_a_table_and_exits_with_zero_on_pass() {
    let (a, _b) = two_nodes().await;
    let (report, code) = conformance::doctor(&a.state, B).await;
    assert_eq!(code, 0, "{report}");
    assert!(report.starts_with("Conformance check of b.test: PASS"), "{report}");
    for id in ALL_CHECKS {
        assert!(report.lines().any(|l| l.starts_with(id)), "{id}: {report}");
    }
    let (report, code) = conformance::doctor(&a.state, "unknown.test").await;
    assert_eq!(code, 0, "an unreachable peer only warns: {report}");
    assert!(report.contains("WARN"), "{report}");
    let (report, code) = conformance::doctor(&a.state, "not a domain").await;
    assert_eq!(code, 2, "{report}");
}
