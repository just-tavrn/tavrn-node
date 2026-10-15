// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Federation, phase 3 steps 1 and 2 (FEDERATION.md §1, §2, §5): two nodes on real loopback ports talk
//! through the real federation client.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::federation::{A, B, FedNode, two_nodes, two_nodes_with};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_node::{
    federation::{guard::LOCAL_ONLY, tokens::body_sha256},
    keys::NodeKey,
    util,
};
use tokio_tungstenite::tungstenite::Message;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Claims of a valid federation token of alice@a.test for b.test.
fn federation_claims(device: &str) -> Value {
    let n = now();
    json!({
        "iss": A, "sub": "alice@a.test", "aud": B, "iat": n, "exp": n + 600, "jti": util::ulid(),
        "typ": "federation", "kind": "user", "device": device, "pv": 1,
    })
}

async fn code_of(b: &FedNode, token: &str) -> (StatusCode, String) {
    let (status, json) = b.federated_login(token).await;
    (status, json["code"].as_str().unwrap_or("").to_string())
}

async fn sql_exec(node: &FedNode, sql: &str, binds: &[&str]) {
    let mut q = sqlx::query(sql);
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(&node.state.db).await.unwrap();
}

async fn sql_text(node: &FedNode, sql: &str, bind: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(sql).bind(bind).fetch_optional(&node.state.db).await.unwrap().flatten()
}

// ---------------------------------------------------------------- federation tokens and sessions

#[tokio::test]
async fn a_user_of_a_signs_in_on_b() {
    let (a, b) = two_nodes().await;
    let (_, wk) = b.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert!(wk["capabilities"].as_array().unwrap().contains(&json!("federation.v1")), "{wk}");
    assert_eq!(wk["federation"]["version"], 1);
    assert_eq!(wk["federation"]["limits"]["federated_logins_per_minute"], 60);

    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let r = &remote.response;
    assert_eq!(r["status"], "ok");
    assert_eq!(r["user"]["address"], "alice@a.test");
    assert_eq!(r["user"]["domain"], A);
    assert_eq!(r["user"]["is_node_admin"], false);
    assert_eq!(r["user"]["email"], Value::Null);
    assert_eq!(remote.device_id, alice.device_id, "the device is known by its home device id");
    assert_eq!(r["expires_in"], 3600);
    let ends = util::parse_time(r["session_expires_at"].as_str().unwrap()).unwrap();
    let week = chrono::Utc::now() + chrono::Duration::days(7);
    assert!((ends - week).num_seconds().abs() < 60, "session ends 7 days after the login");

    let (status, me) = b.get_auth("/api/v1/users/me", &remote.token).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["address"], "alice@a.test");
    assert_ne!(me["id"], alice.user_id.as_str(), "user ids are node-local");

    // The remote user has no password, email or factors on B; the device row is keyed separately.
    let hash = sql_text(&b, "SELECT password_hash FROM users WHERE username = $1 AND domain = 'a.test'", "alice").await;
    assert_eq!(hash, None);
    let local_row = sql_text(&b, "SELECT id FROM devices WHERE home_device_id = $1", &alice.device_id).await.unwrap();
    assert_ne!(local_row, alice.device_id, "a remote device never takes a local device row id");
    // A remembers the target for revocations.
    let target = sql_text(&a, "SELECT target FROM federation_targets WHERE user_id = $1", &alice.user_id).await;
    assert_eq!(target.as_deref(), Some(B));
    // B cached A's document for at most an hour (A sends max-age=300).
    let (fetched, expires): (String, String) =
        sqlx::query_as("SELECT fetched_at, expires_at FROM federation_peers WHERE domain = 'a.test'")
            .fetch_one(&b.state.db)
            .await
            .unwrap();
    let ttl = util::parse_time(&expires).unwrap() - util::parse_time(&fetched).unwrap();
    assert_eq!(ttl.num_seconds(), 300);

    // Refresh keeps the home device id; logout works for remote users.
    let (status, refreshed) =
        b.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": remote.refresh }))).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(refreshed["device_id"], alice.device_id.as_str());
    let (status, _) = b.post("/api/v1/auth/logout", refreshed["access_token"].as_str().unwrap(), json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn one_session_per_device_and_tokens_are_single_use() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let token = a.federation_token(&alice, B).await;
    let (status, first) = b.federated_login(&token).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(code_of(&b, &token).await, (StatusCode::UNAUTHORIZED, "federation.token_replayed".into()));

    let second = b.sign_in_from(&a, &alice).await;
    let (status, body) = b
        .req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": first["refresh_token"] })))
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("auth.refresh_invalid")),
        "the previous session of the device ended"
    );
    let (status, _) = b.get_auth("/api/v1/users/me", &second.token).await;
    assert_eq!(status, StatusCode::OK);
    let devices: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM devices WHERE home_device_id = $1")
        .bind(&alice.device_id)
        .fetch_one(&b.state.db)
        .await
        .unwrap();
    assert_eq!(devices, 1);
}

#[tokio::test]
async fn the_session_cap_holds_whatever_the_refreshes() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let soon = util::in_seconds(120);
    sql_exec(&b, "UPDATE sessions SET max_expires_at = $1, expires_at = $1 WHERE revoked_at IS NULL", &[&soon]).await;
    let (status, refreshed) =
        b.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": remote.refresh }))).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let expires =
        sql_text(&b, "SELECT expires_at FROM sessions WHERE revoked_at IS NULL AND max_expires_at = $1", &soon).await;
    assert_eq!(expires.as_deref(), Some(soon.as_str()), "a refresh never extends beyond the cap");
    // After the cap: neither the access token nor the refresh token works.
    let past = util::in_seconds(-1);
    sql_exec(&b, "UPDATE sessions SET max_expires_at = $1, expires_at = $1", &[&past]).await;
    let (status, body) = b.get_auth("/api/v1/users/me", refreshed["access_token"].as_str().unwrap()).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.token_invalid")));
    let (status, body) = b
        .req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": refreshed["refresh_token"] })))
        .await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.refresh_invalid")));
}

#[tokio::test]
async fn issuing_federation_tokens() {
    let (a, _b) = two_nodes_with(|c| c.federation_blocklist = "evil.example".into(), |_| {}).await;
    let alice = a.register("alice").await;
    let token = a.federation_token(&alice, B).await;
    // The claims of §2.2.
    let payload = token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&tavrn_crypto::util::b64url_decode(payload).unwrap()).unwrap();
    assert_eq!(claims["iss"], A);
    assert_eq!(claims["sub"], "alice@a.test");
    assert_eq!(claims["aud"], B);
    assert_eq!(claims["typ"], "federation");
    assert_eq!(claims["kind"], "user");
    assert_eq!(claims["device"], alice.device_id.as_str());
    assert_eq!(claims["pv"], 1);
    assert_eq!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(), 600);
    assert!(util::is_ulid(claims["jti"].as_str().unwrap()));
    assert!(claims.get("owner").is_none());

    let cases = [
        ("", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("localhost", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("127.0.0.1", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("B.test", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("b.test:443", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("https://b.test", StatusCode::BAD_REQUEST, "federation.domain_invalid"),
        ("a.test", StatusCode::BAD_REQUEST, "federation.target_self"),
        ("evil.example", StatusCode::FORBIDDEN, "federation.peer_blocked"),
        ("sub.evil.example", StatusCode::FORBIDDEN, "federation.peer_blocked"),
    ];
    for (target, status, code) in cases {
        let (s, j) = a.post("/api/v1/federation/token", &alice.token, json!({ "target": target })).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{target}: {j}");
    }
    // Pre-auth tokens and missing sessions are refused.
    let pre = a.login_preauth("alice", &common::password("alice")).await;
    let (s, j) =
        a.post("/api/v1/federation/token", pre["preauth_token"].as_str().unwrap(), json!({ "target": B })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")));
    let (s, _) = a.req(Method::POST, "/api/v1/federation/token", None, Some(json!({ "target": B }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn federation_disabled_refuses_tokens_logins_and_the_inbox() {
    let (a, b) = two_nodes_with(|c| c.federation_enabled = false, |c| c.federation_enabled = false).await;
    let alice = a.register("alice").await;
    let (s, j) = a.post("/api/v1/federation/token", &alice.token, json!({ "target": B })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.disabled")));
    let token = a.sign(&federation_claims(&alice.device_id));
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.disabled".into()));
    let (status, _, body) = b
        .raw(Method::POST, "/api/v1/federation/inbox", "x", &[("content-type", "application/json")], b"{}".to_vec())
        .await;
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.disabled")));
    let (_, wk) = b.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert!(!wk["capabilities"].as_array().unwrap().contains(&json!("federation.v1")));
    assert!(wk.get("federation").is_none());
}

/// Every rejection of §2.5 with its code.
#[tokio::test]
async fn federated_login_rejections() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let dev = alice.device_id.clone();
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = federation_claims(&dev);
        f(&mut c);
        c
    };
    let n = now();
    let cases: Vec<(Value, StatusCode, &str)> = vec![
        (with(&|c| c["aud"] = json!("c.test")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["aud"] = json!(A)), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (
            with(&|c| {
                c["iat"] = json!(n - 700);
                c["exp"] = json!(n - 100)
            }),
            StatusCode::UNAUTHORIZED,
            "federation.token_expired",
        ),
        (with(&|c| c["exp"] = json!(n + 601)), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (
            with(&|c| {
                c["iat"] = json!(n + 400);
                c["exp"] = json!(n + 900)
            }),
            StatusCode::UNAUTHORIZED,
            "federation.token_invalid",
        ),
        (with(&|c| c["typ"] = json!("session")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["typ"] = json!("s2s")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["sub"] = json!("alice@c.test")), StatusCode::UNAUTHORIZED, "federation.issuer_mismatch"),
        (with(&|c| c["sub"] = json!("alice")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["kind"] = json!("admin")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["owner"] = json!("bob@a.test")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (
            with(&|c| {
                c["kind"] = json!("bot");
                c["owner"] = json!("bob@c.test")
            }),
            StatusCode::UNAUTHORIZED,
            "federation.issuer_mismatch",
        ),
        (with(&|c| c["kind"] = json!("bot")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["device"] = json!("../../etc")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["jti"] = json!("one")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["iss"] = json!(B)), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["iss"] = json!("127.0.0.1")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
    ];
    for (claims, status, code) in cases {
        let token = a.sign(&claims);
        assert_eq!(code_of(&b, &token).await, (status, code.to_string()), "{claims}");
        // A `sub` of another domain is spoofing and blocks a.test (FEDERATION.md §9.4): lift it for the next case.
        let _ = tavrn_node::federation::conformance::set_manual_block(&b.state, A, false, "").await;
    }
    // Forged signatures: another key under A's kid, a kid A never published, garbage.
    let kid = a.state.signing_key().kid.clone();
    let forged = tavrn_node::jwt::sign(&NodeKey::generate(&kid).signing, &kid, &federation_claims(&dev)).unwrap();
    assert_eq!(code_of(&b, &forged).await, (StatusCode::UNAUTHORIZED, "federation.token_invalid".into()));
    let unknown = tavrn_node::jwt::sign(&NodeKey::generate("nope").signing, "nope", &federation_claims(&dev)).unwrap();
    assert_eq!(code_of(&b, &unknown).await, (StatusCode::UNAUTHORIZED, "federation.token_invalid".into()));
    for garbage in ["", "not.a.token", "a.b.c.d", &format!("{}.", a.sign(&federation_claims(&dev)))] {
        assert_eq!(
            code_of(&b, garbage).await,
            (StatusCode::UNAUTHORIZED, "federation.token_invalid".into()),
            "{garbage}"
        );
    }
    // A's own session token is not a federation token.
    assert_eq!(code_of(&b, &alice.token).await.0, StatusCode::UNAUTHORIZED);
    // The valid one still works and is single use.
    let token = a.sign(&federation_claims(&dev));
    assert_eq!(b.federated_login(&token).await.0, StatusCode::OK);
    assert_eq!(code_of(&b, &token).await, (StatusCode::UNAUTHORIZED, "federation.token_replayed".into()));
}

/// FEDERATION.md §1.3/§1.4: unsigned requests naming a stalling domain as issuer cannot starve federation with
/// every other peer: they queue for that domain's slots (never holding node-wide ones), give up after the permit
/// timeout, and once the fetch failed, further ones are answered from the negative cache without a fetch.
#[tokio::test]
async fn a_stalling_issuer_does_not_starve_other_peers() {
    use base64::Engine;
    use tower::ServiceExt;
    // A host that accepts connections and never answers.
    let stall = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_port = stall.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = stall.accept().await {
            held.push(sock);
        }
    });
    let (a, b) = two_nodes_with(
        |_| {},
        |c| c.federation_dev_peers.push_str(&format!(",slow.test=http://127.0.0.1:{stall_port}")),
    )
    .await;
    let alice = a.register("alice").await;
    // A is a peer B knows (an earlier sign-in) whose cached document expired: the next sign-in needs a fetch
    // through the shared connection slots, which the flood must not have taken.
    b.sign_in_from(&a, &alice).await;
    sql_exec(&b, "UPDATE federation_peers SET expires_at = $1 WHERE domain = $2", &[&util::in_seconds(-1), A]).await;
    let b64 = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let n = now();
    let forged = format!(
        "{}.{}.{}",
        b64(json!({ "alg": "EdDSA", "typ": "JWT", "kid": "k" })),
        b64(json!({ "iss": "slow.test", "sub": "slow.test", "aud": B, "iat": n, "exp": n + 300, "jti": util::ulid(),
                    "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox", "body_sha256": "x" })),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 64])
    );
    let mut flood = Vec::new();
    for _ in 0..70 {
        let router = b.router.clone();
        let token = forged.clone();
        flood.push(tokio::spawn(async move {
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/api/v1/federation/inbox")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap();
            router.oneshot(req).await.unwrap().status()
        }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Meanwhile a real peer signs in: B fetches A's document and verifies the token at once.
    let token = a.federation_token(&alice, B).await;
    let login = tokio::time::timeout(Duration::from_secs(4), b.federated_login(&token)).await;
    let (s, j) = login.expect("the login of a healthy peer waited for the stalling one");
    assert_eq!(s, StatusCode::OK, "{j}");
    for task in flood {
        let status = task.await.unwrap();
        assert!(status.is_client_error() || status.is_server_error(), "{status}");
    }
    // The failure is remembered: the next forged request fails at once, without another fetch.
    let started = std::time::Instant::now();
    let (st, _, _) = b
        .raw(Method::POST, "/api/v1/federation/inbox", &forged, &[("content-type", "application/json")], b"{}".to_vec())
        .await;
    assert_eq!(st, StatusCode::BAD_GATEWAY);
    assert!(started.elapsed() < Duration::from_secs(1), "answered from the negative cache");
}

/// FEDERATION.md §1.5/§3.3: a domain ban covers the domain's subdomains, like the blocklist: a banned domain does not
/// come back as `x.<domain>`. Other domains that merely end in the same letters are not affected.
#[tokio::test]
async fn domain_bans_cover_subdomains() {
    let (_a, b) = two_nodes().await;
    let admin = b.register("admin").await;
    let (s, j) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "evil.test" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let n = now();
    let forged = |iss: &str| {
        b.sign(&json!({ "iss": iss, "sub": format!("mallory@{iss}"), "aud": B, "iat": n, "exp": n + 600,
                        "jti": util::ulid(), "typ": "federation", "kind": "user", "device": util::ulid(), "pv": 1 }))
    };
    for banned in ["evil.test", "a.evil.test", "x.y.evil.test"] {
        assert_eq!(
            code_of(&b, &forged(banned)).await,
            (StatusCode::FORBIDDEN, "federation.peer_blocked".into()),
            "{banned}"
        );
    }
    assert_ne!(code_of(&b, &forged("notevil.test")).await.1, "federation.peer_blocked");
    let db = &b.state.db;
    assert!(tavrn_node::store::rooms::is_banned(db, None, "mallory@a.evil.test", "a.evil.test").await.unwrap());
    assert!(!tavrn_node::store::rooms::is_banned(db, None, "mallory@notevil.test", "notevil.test").await.unwrap());
}

#[tokio::test]
async fn domain_policy_bans_and_bots_on_the_target() {
    let alice_claims = |a: &FedNode, dev: &str| a.sign(&federation_claims(dev));
    let dev = util::ulid();

    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_blocklist = A.into()).await;
    assert_eq!(code_of(&b, &alice_claims(&a, &dev)).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_allowlist = "c.test".into()).await;
    assert_eq!(code_of(&b, &alice_claims(&a, &dev)).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));

    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_remote_bots = false).await;
    let admin = b.register("admin").await;
    // Node bans of a domain and of a user (POST /admin/bans).
    let (s, j) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "mallory@a.test" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let mut mallory = federation_claims(&dev);
    mallory["sub"] = json!("mallory@a.test");
    assert_eq!(code_of(&b, &a.sign(&mallory)).await, (StatusCode::FORBIDDEN, "federation.user_banned".into()));
    let mut bot = federation_claims(&dev);
    bot["sub"] = json!("helper@a.test");
    bot["kind"] = json!("bot");
    bot["owner"] = json!("mallory@a.test");
    assert_eq!(
        code_of(&b, &a.sign(&bot)).await,
        (StatusCode::FORBIDDEN, "federation.user_banned".into()),
        "banned owner"
    );
    bot["owner"] = json!("alice@a.test");
    bot["jti"] = json!(util::ulid());
    assert_eq!(code_of(&b, &a.sign(&bot)).await, (StatusCode::FORBIDDEN, "federation.bots_refused".into()));
    assert_eq!(b.federated_login(&alice_claims(&a, &dev)).await.0, StatusCode::OK, "alice herself is fine");
    let (s, _) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": A })).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(code_of(&b, &alice_claims(&a, &dev)).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));

    // Remote bots are accepted by default, with their owner as a remote user.
    let (a, b) = two_nodes().await;
    let mut bot = federation_claims(&dev);
    bot["sub"] = json!("helper@a.test");
    bot["kind"] = json!("bot");
    bot["owner"] = json!("alice@a.test");
    let (s, j) = b.federated_login(&a.sign(&bot)).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["user"]["kind"], "bot");
    let owner = sql_text(
        &b,
        "SELECT o.username FROM users u JOIN users o ON o.id = u.owner_id WHERE u.username = $1",
        "helper",
    )
    .await;
    assert_eq!(owner.as_deref(), Some("alice"));
}

#[tokio::test]
async fn remote_user_quotas() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_max_remote_users = 1).await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    b.sign_in_from(&a, &alice).await;
    let token = a.federation_token(&bob, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.remote_limit".into()));
    b.sign_in_from(&a, &alice).await; // existing remote users keep working

    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_max_remote_users_per_domain = 1).await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    b.sign_in_from(&a, &alice).await;
    let token = a.federation_token(&bob, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.remote_limit".into()));
}

#[tokio::test]
async fn federated_logins_are_rate_limited_per_domain() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_rate_logins = 2).await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    b.sign_in_from(&a, &alice).await;
    let token = a.federation_token(&alice, B).await;
    let (status, json) = b.federated_login(&token).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{json}");
    assert!(json["meta"]["retry_after_secs"].as_u64().unwrap() >= 1);
}

// ---------------------------------------------------------------- discovery and keys

#[tokio::test]
async fn unreachable_and_invalid_peers() {
    // B maps c.test to A's port: A's document names a.test, not c.test.
    let (a, b) = two_nodes_with(
        |_| {},
        |c| {
            let a_url = c.federation_dev_peers.split(',').next().unwrap().split_once('=').unwrap().1.to_string();
            c.federation_dev_peers = format!("{},c.test={a_url}", c.federation_dev_peers);
        },
    )
    .await;
    let dev = util::ulid();
    let mut claims = federation_claims(&dev);
    claims["iss"] = json!("c.test");
    claims["sub"] = json!("alice@c.test");
    assert_eq!(code_of(&b, &a.sign(&claims)).await, (StatusCode::BAD_GATEWAY, "federation.peer_invalid".into()));

    a.stop().await;
    let token = a.sign(&federation_claims(&dev));
    assert_eq!(code_of(&b, &token).await, (StatusCode::BAD_GATEWAY, "federation.peer_unreachable".into()));
}

#[tokio::test]
async fn cached_documents_are_used_while_fresh_and_never_when_stale() {
    let (a, b) = two_nodes().await;
    let dev = util::ulid();
    assert_eq!(b.federated_login(&a.sign(&federation_claims(&dev))).await.0, StatusCode::OK);
    a.stop().await;
    assert_eq!(
        b.federated_login(&a.sign(&federation_claims(&dev))).await.0,
        StatusCode::OK,
        "the fresh cache verifies tokens while A is down"
    );
    sql_exec(&b, "UPDATE federation_peers SET expires_at = $1", &[&util::in_seconds(-1)]).await;
    assert_eq!(
        code_of(&b, &a.sign(&federation_claims(&dev))).await,
        (StatusCode::BAD_GATEWAY, "federation.peer_unreachable".into()),
        "a stale document is not used"
    );
    a.start().await;
    // The failed fetch is remembered for a minute (§1.4): A back up is noticed once that has passed.
    assert_eq!(
        code_of(&b, &a.sign(&federation_claims(&dev))).await,
        (StatusCode::BAD_GATEWAY, "federation.peer_unreachable".into()),
        "answered from the negative cache"
    );
    b.state.federation.clear_discovery_failure(A); // as if the minute had passed
    assert_eq!(b.federated_login(&a.sign(&federation_claims(&dev))).await.0, StatusCode::OK);
}

#[tokio::test]
async fn key_rotation_is_learned_through_the_unknown_kid_refresh() {
    let (mut a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await; // B caches A's document with the first key
    let mut keys: Vec<NodeKey> = a.state.keys.iter().cloned().collect();
    keys.push(NodeKey::generate("zz-rotated"));
    a.restart_with_keys(keys).await;
    assert_eq!(a.state.signing_key().kid, "zz-rotated");
    let remote = b.sign_in_from(&a, &alice).await; // unknown kid → one refetch → accepted
    assert_eq!(remote.response["status"], "ok");
    let refreshed = sql_text(&b, "SELECT kid_refresh_at FROM federation_peers WHERE domain = $1", A).await;
    assert!(refreshed.is_some());

    // A second unknown kid within 5 minutes does not refetch.
    let mut keys: Vec<NodeKey> = a.state.keys.iter().cloned().collect();
    keys.push(NodeKey::generate("zzz-again"));
    a.restart_with_keys(keys).await;
    let token = a.federation_token(&alice, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::UNAUTHORIZED, "federation.token_invalid".into()));
    let again = sql_text(&b, "SELECT kid_refresh_at FROM federation_peers WHERE domain = $1", A).await;
    assert_eq!(again, refreshed, "no second refetch within 5 minutes");
}

#[tokio::test]
async fn a_kid_naming_another_key_blocks_the_peer() {
    let (mut a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let earlier = b.sign_in_from(&a, &alice).await;
    let kid = a.state.signing_key().kid.clone();
    let original: Vec<NodeKey> = a.state.keys.iter().cloned().collect();
    a.restart_with_keys(vec![NodeKey::generate(&kid)]).await;
    sql_exec(&b, "UPDATE federation_peers SET expires_at = $1", &[&util::in_seconds(-1)]).await;
    let alice = a.login("alice").await; // A's own sessions are signed with the new key now
    let token = a.federation_token(&alice, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));
    let status = sql_text(&b, "SELECT status FROM federation_peers WHERE domain = $1", A).await;
    assert_eq!(status.as_deref(), Some("key_conflict"));
    // Sessions of the peer's users that existed before the conflict end with the block (§2.5).
    let (s, _) = b.get_auth("/api/v1/users/me", &earlier.token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the earlier federated session ended");
    // Stays blocked even with the original key back, until an operator decides.
    a.restart_with_keys(original).await;
    let alice = a.login("alice").await;
    let token = a.federation_token(&alice, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));
}

// ---------------------------------------------------------------- profiles

#[tokio::test]
async fn profiles_carry_version_and_avatar_hash() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let (s, p) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p["address"], "alice@a.test");
    assert_eq!(p["profile_version"], 1);
    assert_eq!(p["avatar_sha256"], Value::Null);
    let (s, _) = a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice A." })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, p) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(p["profile_version"], 2, "a display name change increments the version");
    a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice A." })).await;
    let (_, p) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(p["profile_version"], 2, "no change, no new version");
    let (s, j) = a.req(Method::GET, "/api/v1/users/alice/avatar", None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("avatar.not_found")));
    let (s, _) = a.req(Method::GET, "/api/v1/users/nobody/avatar", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = a.req(Method::GET, "/api/v1/users/..%2F..%2Fetc/avatar", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// Gives alice on A an avatar (stored directly, without the media pipeline, so any bytes do).
async fn set_avatar(a: &FedNode, alice: &common::Session, bytes: &[u8], mime: &str) -> String {
    let id = util::ulid();
    let sha = body_sha256(bytes);
    a.state.storage.write(&id, bytes).await.unwrap();
    sqlx::query("INSERT INTO media (id, kind, owner_id, mime, still_size, still_sha256, created_at) VALUES ($1, 'avatar', $2, $3, $4, $5, $6)")
        .bind(&id)
        .bind(&alice.user_id)
        .bind(mime)
        .bind(bytes.len() as i64)
        .bind(&sha)
        .bind(util::now())
        .execute(&a.state.db)
        .await
        .unwrap();
    sql_exec(
        a,
        "UPDATE users SET avatar_blob_id = $1, profile_version = profile_version + 1 WHERE id = $2",
        &[&id, &alice.user_id],
    )
    .await;
    sha
}

/// Anonymous profile reads of a remote user start at most one background refresh per user and minute: reads of a
/// user whose home node fails cannot pile up refresh tasks.
#[tokio::test]
async fn profile_reads_start_at_most_one_refresh_per_minute() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    a.stop().await;
    let id = sql_text(&b, "SELECT id FROM users WHERE username = $1 AND domain = 'a.test'", "alice").await.unwrap();
    for _ in 0..5 {
        let (s, _) = b.req(axum::http::Method::GET, "/api/v1/users/alice@a.test/profile", None, None).await;
        assert_eq!(s, StatusCode::OK);
    }
    assert!(b.state.profile_refresh_limiter.check(&id).is_err(), "the first read took this minute's refresh");
    assert!(b.state.profile_refresh_limiter.check("someone-else").is_ok());
}

#[tokio::test]
async fn the_profile_mirror_follows_pv_and_age() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice" })).await;
    b.sign_in_from(&a, &alice).await;
    let name = || sql_text(&b, "SELECT display_name FROM users WHERE username = $1 AND domain = 'a.test'", "alice");
    assert_eq!(name().await.as_deref(), Some("Alice"), "mirrored at the first login");

    // (a) a newer `pv` in the token refreshes the mirror.
    a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice New" })).await;
    b.sign_in_from(&a, &alice).await;
    assert_eq!(name().await.as_deref(), Some("Alice New"));

    // Same `pv` and a fresh mirror: no refresh.
    sql_exec(&a, "UPDATE users SET display_name = 'Sneaky' WHERE id = $1", &[&alice.user_id]).await;
    b.sign_in_from(&a, &alice).await;
    assert_eq!(name().await.as_deref(), Some("Alice New"));
    // (b) a mirror older than 24 hours is refreshed at the login.
    sql_exec(&b, "UPDATE remote_users SET profile_fetched_at = $1", &[&util::in_seconds(-25 * 3600)]).await;
    b.sign_in_from(&a, &alice).await;
    assert_eq!(name().await.as_deref(), Some("Sneaky"));

    // Avatars are copied into B's storage and served by B.
    let png = b"\x89PNG\r\n\x1a\nnot really a png";
    let sha = set_avatar(&a, &alice, png, "image/png").await;
    let (_, p) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(p["avatar_sha256"], sha.as_str());
    let resp = a.get("/api/v1/users/alice/avatar").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "image/png");
    assert_eq!(common::body_bytes(resp).await.as_ref(), png);
    b.sign_in_from(&a, &alice).await;
    let resp = b.get("/api/v1/users/alice@a.test/avatar").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-security-policy"], "default-src 'none'; sandbox");
    assert_eq!(common::body_bytes(resp).await.as_ref(), png);
    let mirrored = sql_text(&b, "SELECT avatar_sha256 FROM remote_users WHERE avatar_sha256 = $1", &sha).await;
    assert_eq!(mirrored.as_deref(), Some(sha.as_str()));

    // An avatar that does not match its announced hash is not mirrored.
    let blob = sql_text(&a, "SELECT avatar_blob_id FROM users WHERE id = $1", &alice.user_id).await.unwrap();
    a.state.storage.write(&blob, b"\x89PNG other bytes").await.unwrap();
    sql_exec(&a, "UPDATE media SET still_sha256 = $1 WHERE id = $2", &[&body_sha256(b"something else"), &blob]).await;
    sql_exec(&a, "UPDATE users SET profile_version = profile_version + 1 WHERE id = $1", &[&alice.user_id]).await;
    b.sign_in_from(&a, &alice).await;
    let resp = b.get("/api/v1/users/alice@a.test/avatar").await;
    assert_eq!(common::body_bytes(resp).await.as_ref(), png, "the old mirror stays");
}

// ---------------------------------------------------------------- local-only routes

/// Every entry of `LOCAL_ONLY` with a concrete request; the test fails if an entry is missing here.
const LOCAL_ONLY_REQUESTS: &[(&str, &str, &str)] = &[
    ("PATCH", "/api/v1/users/me", "/api/v1/users/me"),
    ("DELETE", "/api/v1/users/me", "DELETE /api/v1/users/me"),
    ("*", "/api/v1/users/me/export", "GET /api/v1/users/me/export"),
    ("*", "/api/v1/users/me/data", "GET /api/v1/users/me/data"),
    ("*", "/api/v1/users/me/terms", "GET /api/v1/users/me/terms"),
    ("*", "/api/v1/users/me/terms/accept", "POST /api/v1/users/me/terms/accept"),
    ("*", "/api/v1/users/me/legal-notices", "GET /api/v1/users/me/legal-notices"),
    (
        "*",
        "/api/v1/users/me/legal-notices/*",
        "POST /api/v1/users/me/legal-notices/01J00000000000000000000000/counter-notice",
    ),
    ("*", "/api/v1/users/me/password", "POST /api/v1/users/me/password"),
    ("DELETE", "/api/v1/users/me/devices/{device_id}", "DELETE /api/v1/users/me/devices/01J00000000000000000000000"),
    ("*", "/api/v1/auth/factors", "GET /api/v1/auth/factors"),
    ("*", "/api/v1/auth/totp", "DELETE /api/v1/auth/totp"),
    ("*", "/api/v1/auth/totp/enroll", "POST /api/v1/auth/totp/enroll"),
    ("*", "/api/v1/auth/totp/confirm", "POST /api/v1/auth/totp/confirm"),
    ("*", "/api/v1/auth/recovery-codes/regenerate", "POST /api/v1/auth/recovery-codes/regenerate"),
    ("*", "/api/v1/auth/webauthn/register/start", "POST /api/v1/auth/webauthn/register/start"),
    ("*", "/api/v1/auth/webauthn/register/finish", "POST /api/v1/auth/webauthn/register/finish"),
    ("*", "/api/v1/auth/webauthn/credentials", "GET /api/v1/auth/webauthn/credentials"),
    ("*", "/api/v1/auth/webauthn/credentials/{credential_id}", "DELETE /api/v1/auth/webauthn/credentials/abc"),
    ("*", "/api/v1/auth/oidc/identity", "GET /api/v1/auth/oidc/identity"),
    ("*", "/api/v1/users/me/secret-storage", "GET /api/v1/users/me/secret-storage"),
    ("*", "/api/v1/users/me/secret-storage/recovery", "PUT /api/v1/users/me/secret-storage/recovery"),
    ("*", "/api/v1/users/me/secret-storage/passkey/{credential_id}", "PUT /api/v1/users/me/secret-storage/passkey/abc"),
    ("*", "/api/v1/users/me/identity", "PUT /api/v1/users/me/identity"),
    ("*", "/api/v1/users/me/identity/reset", "POST /api/v1/users/me/identity/reset"),
    ("*", "/api/v1/users/me/identity/rotate", "POST /api/v1/users/me/identity/rotate"),
    ("*", "/api/v1/users/me/identity/blob", "GET /api/v1/users/me/identity/blob"),
    ("*", "/api/v1/users/me/devices/{device_id}/key", "PUT /api/v1/users/me/devices/DEVICE/key"),
    ("*", "/api/v1/users/me/devices/{device_id}/share-key", "PUT /api/v1/users/me/devices/DEVICE/share-key"),
    ("*", "/api/v1/users/me/devices/{device_id}/key-packages", "POST /api/v1/users/me/devices/DEVICE/key-packages"),
    ("*", "/api/v1/users/me/backups", "GET /api/v1/users/me/backups"),
    (
        "*",
        "/api/v1/users/me/backups/{domain}/{conversation_id}",
        "GET /api/v1/users/me/backups/b.test/01J00000000000000000000000",
    ),
    ("*", "/api/v1/users/me/notification-settings", "GET /api/v1/users/me/notification-settings"),
    ("*", "/api/v1/users/me/emojis", "GET /api/v1/users/me/emojis"),
    ("*", "/api/v1/users/me/emojis/{emoji_id}", "DELETE /api/v1/users/me/emojis/01J00000000000000000000000"),
    ("*", "/api/v1/users/me/sounds", "POST /api/v1/users/me/sounds"),
    ("*", "/api/v1/users/me/sounds/{sound_id}", "PATCH /api/v1/users/me/sounds/01J00000000000000000000000"),
    ("*", "/api/v1/users/me/friends", "GET /api/v1/users/me/friends"),
    ("*", "/api/v1/users/me/friends/requests", "POST /api/v1/users/me/friends/requests"),
    (
        "*",
        "/api/v1/users/me/friends/requests/{request_id}",
        "DELETE /api/v1/users/me/friends/requests/01J00000000000000000000000",
    ),
    (
        "*",
        "/api/v1/users/me/friends/requests/{request_id}/accept",
        "POST /api/v1/users/me/friends/requests/01J00000000000000000000000/accept",
    ),
    ("*", "/api/v1/users/me/friends/{username}", "DELETE /api/v1/users/me/friends/bob"),
    ("*", "/api/v1/users/me/blocks", "POST /api/v1/users/me/blocks"),
    ("*", "/api/v1/users/me/avatar", "PUT /api/v1/users/me/avatar"),
    ("*", "/api/v1/users/me/header", "DELETE /api/v1/users/me/header"),
    ("*", "/api/v1/users/me/background", "GET /api/v1/users/me/background"),
    ("*", "/api/v1/users/me/background/{variant}", "GET /api/v1/users/me/background/still"),
    ("*", "/api/v1/users/me/whiteboards", "GET /api/v1/users/me/whiteboards"),
    ("*", "/api/v1/users/me/whiteboards/background", "POST /api/v1/users/me/whiteboards/background"),
    ("*", "/api/v1/users/me/whiteboards/{scene_id}", "GET /api/v1/users/me/whiteboards/01J00000000000000000000000"),
    (
        "*",
        "/api/v1/users/me/whiteboards/{scene_id}/thumbnail",
        "PUT /api/v1/users/me/whiteboards/01J00000000000000000000000/thumbnail",
    ),
    ("*", "/api/v1/users/me/blocks/{username}", "DELETE /api/v1/users/me/blocks/bob"),
    ("*", "/api/v1/users/me/invites", "GET /api/v1/users/me/invites"),
    ("*", "/api/v1/users/me/push-subscriptions", "GET /api/v1/users/me/push-subscriptions"),
    (
        "*",
        "/api/v1/users/me/push-subscriptions/*",
        "DELETE /api/v1/users/me/push-subscriptions/01J00000000000000000000000",
    ),
    ("*", "/api/v1/users/me/invites/{invite_id}", "DELETE /api/v1/users/me/invites/01J00000000000000000000000"),
    ("POST", "/api/v1/conversations", "POST /api/v1/conversations"),
    ("POST", "/api/v1/directory/reports", "POST /api/v1/directory/reports"),
    ("*", "/api/v1/applications", "POST /api/v1/applications"),
    ("*", "/api/v1/applications/*", "POST /api/v1/applications/01J00000000000000000000000/tokens"),
    ("*", "/api/v1/unfurl", "GET /api/v1/unfurl?url=https%3A%2F%2Fexample.com%2F"),
    ("*", "/api/v1/federation/token", "POST /api/v1/federation/token"),
    ("*", "/api/v1/admin/*", "GET /api/v1/admin/users"),
    ("*", "/api/v1/users/me/date-of-birth", "PUT /api/v1/users/me/date-of-birth"),
];

#[tokio::test]
async fn local_only_routes_refuse_remote_users() {
    let (a, b) = two_nodes().await;
    b.register("admin").await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;

    for rule in LOCAL_ONLY {
        assert!(
            LOCAL_ONLY_REQUESTS.iter().any(|(m, t, _)| (*m, *t) == *rule),
            "no test request for local-only rule {rule:?}"
        );
    }
    let mut requests: Vec<(String, String)> = LOCAL_ONLY_REQUESTS
        .iter()
        .map(|(m, _, req)| match req.split_once(' ') {
            Some((method, path)) => (method.to_string(), path.replace("DEVICE", &remote.device_id)),
            None => (m.to_string(), req.to_string()),
        })
        .collect();
    for path in ["/api/v1/admin/overview", "/api/v1/admin/bans", "/api/v1/admin/audit-log"] {
        requests.push(("GET".into(), path.into()));
    }
    requests.push(("POST".into(), "/api/v1/rooms".into())); // TAVRN_ROOM_CREATION=local
    for (method, path) in requests {
        let (status, json) =
            b.req(Method::from_bytes(method.as_bytes()).unwrap(), &path, Some(&remote.token), Some(json!({}))).await;
        assert_eq!(
            (status, json["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("federation.local_only")),
            "{method} {path}: {json}"
        );
    }
    // What a remote user may do on B.
    for path in ["/api/v1/users/me", "/api/v1/rooms", "/api/v1/users/me/devices", "/api/v1/conversations"] {
        let (status, json) = b.get_auth(path, &remote.token).await;
        assert_eq!(status, StatusCode::OK, "{path}: {json}");
    }
}

#[tokio::test]
async fn remote_users_may_create_rooms_only_when_federated_creation_is_allowed() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.room_creation = tavrn_node::config::RoomCreation::Federated).await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (status, room) = b.post("/api/v1/rooms", &remote.token, json!({ "name": "Guests" })).await;
    assert_eq!(status, StatusCode::CREATED, "{room}");
}

// ---------------------------------------------------------------- revocation

async fn me_status(b: &FedNode, token: &str) -> StatusCode {
    b.get_auth("/api/v1/users/me", token).await.0
}

#[tokio::test]
async fn revocation_end_to_end() {
    let (a, b) = two_nodes().await;
    let admin = a.register("admin").await;
    let alice = a.register("alice").await;
    let laptop = a.login("alice").await;
    let s_phone = b.sign_in_from(&a, &alice).await;
    let s_laptop = b.sign_in_from(&a, &laptop).await;

    // Deleting a device on A ends that device's session on B only.
    let (status, _) = a.delete(&format!("/api/v1/users/me/devices/{}", laptop.device_id), &alice.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let kinds: Vec<String> = a.outbox().await.into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec!["session.revoke", "devices.changed"]);
    let report = a.deliver().await;
    assert_eq!(report.delivered, 2, "{report:?}");
    assert!(a.outbox().await.is_empty());
    assert_eq!(me_status(&b, &s_laptop.token).await, StatusCode::UNAUTHORIZED);
    assert_eq!(me_status(&b, &s_phone.token).await, StatusCode::OK);

    // A password change ends every session of the user on B.
    let (status, j) = a
        .post(
            "/api/v1/users/me/password",
            &alice.token,
            json!({ "current_password": common::password("alice"), "new_password": "a-new-password-1" }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(a.deliver().await.delivered, 1);
    assert_eq!(me_status(&b, &s_phone.token).await, StatusCode::UNAUTHORIZED);
    let (status, j) =
        b.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": s_phone.refresh }))).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.refresh_invalid")));

    // A fresh federation token renews; an admin reset of the second factor and disabling end it again.
    let s_phone = b.sign_in_from(&a, &alice).await;
    let (status, _) =
        a.post(&format!("/api/v1/admin/users/{}/second-factor/reset", alice.user_id), &admin.token, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(a.deliver().await.delivered, 1);
    assert_eq!(me_status(&b, &s_phone.token).await, StatusCode::UNAUTHORIZED);

    let bob = a.register("bob").await;
    let s_bob = b.sign_in_from(&a, &bob).await;
    let (status, _) =
        a.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &admin.token, json!({ "disabled": true })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(a.deliver().await.delivered, 1);
    assert_eq!(me_status(&b, &s_bob.token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_revoked_session_closes_its_websocket() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(b.ws_url()).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": remote.token }).to_string().into())).await.unwrap();
    let ready = ws.next().await.unwrap().unwrap();
    assert!(ready.to_text().unwrap().contains("\"ready\""), "{ready:?}");
    a.post(
        "/api/v1/users/me/password",
        &alice.token,
        json!({ "current_password": common::password("alice"), "new_password": "a-new-password-1" }),
    )
    .await;
    assert_eq!(a.deliver().await.delivered, 1);
    let closed = loop {
        match tokio::time::timeout(common::timeout(Duration::from_secs(5)), ws.next()).await.unwrap() {
            Some(Ok(Message::Close(frame))) => break frame.map(|f| u16::from(f.code)),
            Some(Ok(_)) => continue,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(closed, Some(4001));
}

#[tokio::test]
async fn an_identity_reset_on_a_reaches_b() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    let key = NodeKey::generate("identity").public_info().x;
    let (status, j) = a
        .post(
            "/api/v1/users/me/identity/reset",
            &alice.token,
            json!({ "identity_public_key": key, "password": common::password("alice") }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
    let entries = a.outbox().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "identity.changed");
    assert_eq!(a.deliver().await.delivered, 1);
    let mirrored =
        sql_text(&b, "SELECT identity_pubkey FROM users WHERE username = $1 AND domain = 'a.test'", "alice").await;
    assert_eq!(mirrored.as_deref(), Some(key.as_str()));
}

#[tokio::test]
async fn users_without_federation_targets_cause_no_traffic() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let second = a.login("alice").await;
    a.delete(&format!("/api/v1/users/me/devices/{}", second.device_id), &alice.token).await;
    assert!(a.outbox().await.is_empty());
}

// ---------------------------------------------------------------- inbox

fn envelope(id: &str, kind: &str, from: &str, to: &str, payload: Value) -> Vec<u8> {
    json!({ "id": id, "type": kind, "from": from, "to": to, "at": util::now(), "payload": payload })
        .to_string()
        .into_bytes()
}

fn node_claims(body: &[u8]) -> Value {
    let n = now();
    json!({
        "iss": A, "sub": A, "aud": B, "iat": n, "exp": n + 300, "jti": util::ulid(), "typ": "s2s",
        "htm": "POST", "htu": "/api/v1/federation/inbox", "body_sha256": body_sha256(body),
    })
}

async fn post_inbox(b: &FedNode, token: &str, body: &[u8]) -> (StatusCode, Value) {
    let (status, _, bytes) = b
        .raw(Method::POST, "/api/v1/federation/inbox", token, &[("content-type", "application/json")], body.to_vec())
        .await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

async fn deliver_signed(a: &FedNode, b: &FedNode, body: &[u8]) -> (StatusCode, Value) {
    post_inbox(b, &a.sign(&node_claims(body)), body).await
}

fn revoke_all(id: &str) -> Vec<u8> {
    envelope(id, "session.revoke", "alice@a.test", B, json!({ "device": null }))
}

#[tokio::test]
async fn inbox_delivery_and_duplicates() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let id = util::ulid();
    let (status, body) = deliver_signed(&a, &b, &revoke_all(&id)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body, Value::Null, "202 has an empty body");
    assert_eq!(me_status(&b, &remote.token).await, StatusCode::UNAUTHORIZED);

    // The same message again (fresh token, retried delivery): accepted, not applied twice.
    let remote = b.sign_in_from(&a, &alice).await;
    let (status, _) = deliver_signed(&a, &b, &revoke_all(&id)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(me_status(&b, &remote.token).await, StatusCode::OK, "a duplicate is not processed again");
    let seen: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM federation_inbox_seen")
        .fetch_one(&b.state.db)
        .await
        .unwrap();
    assert_eq!(seen, 1);

    // Unknown types are accepted and ignored; announced but unimplemented types are stored.
    let (status, _) = deliver_signed(&a, &b, &envelope(&util::ulid(), "future.thing", A, B, json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    b.register("bob").await;
    let request =
        envelope(&util::ulid(), "friend.request", "alice@a.test", "bob@b.test", json!({ "request_id": util::ulid() }));
    assert_eq!(deliver_signed(&a, &b, &request).await.0, StatusCode::ACCEPTED);
    // Messages about users B does not know are fine.
    let unknown = envelope(&util::ulid(), "session.revoke", "zoe@a.test", B, json!({ "device": null }));
    assert_eq!(deliver_signed(&a, &b, &unknown).await.0, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn inbox_token_and_body_checks() {
    let (a, b) = two_nodes().await;
    let body = revoke_all(&util::ulid());
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = node_claims(&body);
        f(&mut c);
        a.sign(&c)
    };
    let n = now();
    let cases = [
        (
            with(&|c| c["body_sha256"] = json!(body_sha256(b"other"))),
            StatusCode::UNAUTHORIZED,
            "federation.body_hash_mismatch",
        ),
        (with(&|c| c["htu"] = json!("/api/v1/federation/other")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["htu"] = json!("/api/v1/auth/federated")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["htm"] = json!("PUT")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["sub"] = json!("c.test")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["aud"] = json!("c.test")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["typ"] = json!("federation")), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (with(&|c| c["exp"] = json!(n + 301)), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        (
            with(&|c| {
                c["iat"] = json!(n - 400);
                c["exp"] = json!(n - 100)
            }),
            StatusCode::UNAUTHORIZED,
            "federation.token_expired",
        ),
        (with(&|c| c["iss"] = json!(B)), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
        ("no-token".to_string(), StatusCode::UNAUTHORIZED, "federation.token_invalid"),
    ];
    for (token, status, code) in cases {
        let (s, j) = post_inbox(&b, &token, &body).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{j}");
    }
    let (s, _, bytes) = b
        .raw(Method::POST, "/api/v1/federation/inbox", "", &[("content-type", "application/json")], body.clone())
        .await;
    let j: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("federation.token_invalid")));

    // A replayed token.
    let token = a.sign(&node_claims(&body));
    assert_eq!(post_inbox(&b, &token, &body).await.0, StatusCode::ACCEPTED);
    let (s, j) = post_inbox(&b, &token, &body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("federation.token_replayed")));

    // Payload limit: 64 KiB, checked before reading further.
    let mut big = revoke_all(&util::ulid());
    big.truncate(big.len() - 1);
    big.extend_from_slice(format!(",\"pad\":\"{}\"}}", "x".repeat(64 * 1024)).as_bytes());
    let (s, j) = deliver_signed(&a, &b, &big).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("federation.payload_too_large")));

    // Not an envelope.
    let (s, j) = deliver_signed(&a, &b, b"[1,2,3]").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.envelope_invalid")));
}

#[tokio::test]
async fn inbox_envelope_rules() {
    let (a, b) = two_nodes().await;
    b.register("bob").await;
    let at = |t: chrono::DateTime<chrono::Utc>| ulid::Ulid::from_datetime(std::time::SystemTime::from(t)).to_string();
    let old = at(chrono::Utc::now() - chrono::Duration::days(8));
    let future = at(chrono::Utc::now() + chrono::Duration::minutes(10));
    let cases = [
        (revoke_all(&old), StatusCode::BAD_REQUEST, "federation.message_stale"),
        (revoke_all(&future), StatusCode::BAD_REQUEST, "federation.message_stale"),
        (revoke_all("not-a-ulid"), StatusCode::BAD_REQUEST, "federation.envelope_invalid"),
        // `from` of another domain than the sender: spoofing.
        (
            envelope(&util::ulid(), "session.revoke", "alice@c.test", B, json!({})),
            StatusCode::FORBIDDEN,
            "federation.type_forbidden",
        ),
        (
            envelope(&util::ulid(), "friend.request", A, "bob@b.test", json!({})),
            StatusCode::FORBIDDEN,
            "federation.type_forbidden",
        ),
        (
            envelope(&util::ulid(), "node.announce", "c.test", B, json!({})),
            StatusCode::FORBIDDEN,
            "federation.type_forbidden",
        ),
        (
            envelope(&util::ulid(), "session.revoke", "alice@a.test", "bob@b.test", json!({})),
            StatusCode::FORBIDDEN,
            "federation.type_forbidden",
        ),
        (
            envelope(&util::ulid(), "notify", "alice@a.test", "bob@b.test", json!({})),
            StatusCode::FORBIDDEN,
            "federation.type_forbidden",
        ),
        (
            envelope(&util::ulid(), "friend.request", "alice@a.test", "nobody@b.test", json!({})),
            StatusCode::NOT_FOUND,
            "federation.recipient_unknown",
        ),
        (
            envelope(&util::ulid(), "session.revoke", "alice@a.test", B, json!({ "device": "../x" })),
            StatusCode::BAD_REQUEST,
            "federation.envelope_invalid",
        ),
    ];
    for (body, status, code) in cases {
        let (s, j) = deliver_signed(&a, &b, &body).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{}: {j}", String::from_utf8_lossy(&body));
        // A forged `from` is spoofing and blocks a.test (FEDERATION.md §9.4): lift it for the next case.
        let _ = tavrn_node::federation::conformance::set_manual_block(&b.state, A, false, "").await;
    }
}

#[tokio::test]
async fn inbox_policy_and_rate_limit() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_rate_inbox = 2).await;
    for _ in 0..2 {
        assert_eq!(deliver_signed(&a, &b, &revoke_all(&util::ulid())).await.0, StatusCode::ACCEPTED);
    }
    let (s, j) = deliver_signed(&a, &b, &revoke_all(&util::ulid())).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");

    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_blocklist = A.into()).await;
    let (s, j) = deliver_signed(&a, &b, &revoke_all(&util::ulid())).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
}

/// `profile.changed` (§2.7 (d), §5.2): only for users B knows and only for a newer version; limited per sender and
/// user with `429` before the message counts as received.
#[tokio::test]
async fn profile_changed_is_ignored_for_old_versions_and_unknown_users() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice" })).await;
    b.sign_in_from(&a, &alice).await;
    let name = || sql_text(&b, "SELECT display_name FROM users WHERE username = $1 AND domain = 'a.test'", "alice");
    let stored = sqlx::query_scalar::<_, i64>(
        "SELECT r.profile_version FROM remote_users r JOIN users u ON u.id = r.user_id WHERE u.username = 'alice'",
    )
    .fetch_one(&b.state.db)
    .await
    .unwrap();
    let changed = |from: &str, version: Value| {
        envelope(&util::ulid(), "profile.changed", from, B, json!({ "profile_version": version }))
    };

    // A user B does not know: accepted, no stub is created.
    assert_eq!(deliver_signed(&a, &b, &changed("zoe@a.test", json!(5))).await.0, StatusCode::ACCEPTED);
    assert_eq!(sql_text(&b, "SELECT id FROM users WHERE username = $1", "zoe").await, None);

    // The same or an older version: ignored, the mirror is not fetched again.
    sql_exec(&a, "UPDATE users SET display_name = 'Sneaky' WHERE id = $1", &[&alice.user_id]).await;
    for v in [stored, stored - 1] {
        assert_eq!(deliver_signed(&a, &b, &changed("alice@a.test", json!(v))).await.0, StatusCode::ACCEPTED);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(name().await.as_deref(), Some("Alice"));

    // A newer version refreshes in the background, without a new federation token.
    assert_eq!(deliver_signed(&a, &b, &changed("alice@a.test", json!(stored + 1))).await.0, StatusCode::ACCEPTED);
    for _ in 0..100 {
        if name().await.as_deref() == Some("Sneaky") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(name().await.as_deref(), Some("Sneaky"));

    // Malformed payloads are refused.
    let (s, j) = deliver_signed(&a, &b, &changed("alice@a.test", json!("7"))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.envelope_invalid")));

    // Limited per sender and user: the first refresh above counted, nine more pass, then 429 and the message
    // is not recorded as seen (the sender's retry is not a duplicate).
    for _ in 0..9 {
        assert_eq!(deliver_signed(&a, &b, &changed("alice@a.test", json!(1000))).await.0, StatusCode::ACCEPTED);
    }
    let id = util::ulid();
    let limited = envelope(&id, "profile.changed", "alice@a.test", B, json!({ "profile_version": 1000 }));
    let (s, j) = deliver_signed(&a, &b, &limited).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    assert_eq!(sql_text(&b, "SELECT id FROM federation_inbox_seen WHERE id = $1", &id).await, None);

    // A user of another domain is a spoofing attempt (last: it counts towards blocking A, §9.4).
    let (s, j) = deliver_signed(&a, &b, &changed("carol@c.test", json!(7))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.type_forbidden")));
}

// ---------------------------------------------------------------- outbox

async fn change_password(a: &FedNode, s: &common::Session, new: &str) {
    let (status, j) = a
        .post(
            "/api/v1/users/me/password",
            &s.token,
            json!({ "current_password": common::password(&s.username), "new_password": new }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
}

#[tokio::test]
async fn outbox_retries_while_b_is_down_and_delivers_after() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    b.stop().await;
    change_password(&a, &alice, "a-new-password-1").await;

    let started = chrono::Utc::now();
    let report = a.deliver().await;
    assert_eq!((report.delivered, report.retried, report.given_up), (0, 1, 0), "{report:?}");
    let entry = &a.outbox().await[0];
    assert_eq!(entry.attempts, 1);
    assert_eq!(entry.last_error.as_deref(), Some("unreachable"));
    let delay = (util::parse_time(&entry.next_at).unwrap() - started).num_seconds();
    assert!((53..=67).contains(&delay), "first retry after 1 min ± 10 %: {delay}");
    assert_eq!(a.deliver().await, Default::default(), "nothing due before the retry time");

    // Second failure: 5 minutes.
    let report = a.deliver_at(70).await;
    assert_eq!(report.retried, 1);
    let entry = &a.outbox().await[0];
    assert_eq!(entry.attempts, 2);
    let delay = (util::parse_time(&entry.next_at).unwrap() - (started + chrono::Duration::seconds(70))).num_seconds();
    assert!((268..=332).contains(&delay), "second retry after 5 min ± 10 %: {delay}");

    // B is back: the next due round delivers.
    b.start().await;
    let report = a.deliver_at(70 + 340).await;
    assert_eq!(report.delivered, 1, "{report:?}");
    assert!(a.outbox().await.is_empty());
    assert_eq!(me_status(&b, &remote.token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn outbox_gives_up_after_three_days() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    b.stop().await;
    change_password(&a, &alice, "a-new-password-1").await;
    assert_eq!(a.deliver().await.retried, 1);
    let entry = &a.outbox().await[0];
    let lifetime = util::parse_time(&entry.expires_at).unwrap() - util::parse_time(&entry.created_at).unwrap();
    assert_eq!(lifetime.num_seconds(), 3 * 24 * 3600);
    b.start().await;
    let report = a.deliver_at(3 * 24 * 3600 + 1).await;
    assert_eq!((report.delivered, report.given_up), (0, 1), "{report:?}");
    assert!(a.outbox().await.is_empty());
    assert_eq!(me_status(&b, &remote.token).await, StatusCode::OK, "never delivered");
}

#[tokio::test]
async fn outbox_final_errors_and_unauthorized_retry() {
    let (mut a, b) = two_nodes().await;
    // 404 (unknown recipient) is final: given up at once.
    tavrn_node::federation::outbox::enqueue(&a.state, B, "friend.request", "alice@a.test", "nobody@b.test", json!({}))
        .await
        .unwrap();
    let report = a.deliver().await;
    assert_eq!(report.given_up, 1, "{report:?}");
    assert!(a.outbox().await.is_empty());

    // 401: B cannot verify our new key (its unknown-kid refetch was just used): retried once after
    // 5 minutes, then given up.
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    sql_exec(&b, "UPDATE federation_peers SET kid_refresh_at = $1", &[&util::now()]).await;
    let mut keys: Vec<NodeKey> = a.state.keys.iter().cloned().collect();
    keys.push(NodeKey::generate("zz-new"));
    a.restart_with_keys(keys).await;
    change_password(&a, &alice, "a-new-password-1").await;
    let started = chrono::Utc::now();
    let report = a.deliver().await;
    assert_eq!(report.retried, 1, "{report:?}");
    let entry = &a.outbox().await[0];
    assert_eq!(entry.last_status, Some(401));
    let delay = (util::parse_time(&entry.next_at).unwrap() - started).num_seconds();
    assert!((299..=301).contains(&delay), "401 is retried after 5 minutes: {delay}");
    let report = a.deliver_at(301).await;
    assert_eq!(report.given_up, 1, "the second 401 is final: {report:?}");
}

#[tokio::test]
async fn a_failed_target_delays_its_whole_queue() {
    let (a, b) = two_nodes().await;
    b.stop().await;
    for _ in 0..3 {
        tavrn_node::federation::outbox::enqueue(&a.state, B, "devices.changed", "alice@a.test", B, json!({}))
            .await
            .unwrap();
    }
    let report = a.deliver().await;
    assert_eq!(report.retried, 1, "one attempt, the rest of the queue waits: {report:?}");
    let entries = a.outbox().await;
    assert_eq!(entries.iter().map(|e| e.attempts).collect::<Vec<_>>(), vec![1, 0, 0]);
    assert!(entries.iter().all(|e| e.next_at == entries[0].next_at), "all wait for the same retry");
    b.start().await;
    assert_eq!(a.deliver_at(120).await.delivered, 3);
}

#[tokio::test]
async fn outbox_envelopes_are_well_formed() {
    let (a, _b) = two_nodes().await;
    let id = tavrn_node::federation::outbox::enqueue(
        &a.state,
        B,
        "session.revoke",
        "alice@a.test",
        B,
        json!({ "device": null }),
    )
    .await
    .unwrap();
    let entry = &a.outbox().await[0];
    let body: Value = serde_json::from_str(&entry.body).unwrap();
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["type"], "session.revoke");
    assert_eq!(body["from"], "alice@a.test");
    assert_eq!(body["to"], B);
    assert_eq!(body["payload"], json!({ "device": null }));
    let ulid_time = chrono::DateTime::<chrono::Utc>::from(ulid::Ulid::from_string(&id).unwrap().datetime());
    assert_eq!(body["at"], util::format_time(ulid_time), "`at` is the ULID time");
}

// ---------------------------------------------------------------- review of the federation hardening

/// FEDERATION.md §1.4: a document that now comes from another source (here: SRV before, the well-known now) is
/// accepted when it keeps a known key (a real move), and is a key conflict when it shares none (a takeover); the
/// conflict ends the peer's sessions.
#[tokio::test]
async fn a_document_from_another_source_without_a_known_key_is_a_key_conflict() {
    let (mut a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let earlier = b.sign_in_from(&a, &alice).await;
    let original: Vec<NodeKey> = a.state.keys.iter().cloned().collect();
    let past = util::in_seconds(-1);
    sql_exec(&b, "UPDATE federation_peers SET source = 'srv', expires_at = $1", &[&past]).await;
    let mut moved = original.clone();
    moved.push(NodeKey::generate("zz-moved"));
    a.restart_with_keys(moved).await;
    let alice = a.login("alice").await;
    let token = a.federation_token(&alice, B).await;
    let (s, j) = b.federated_login(&token).await;
    assert_eq!(s, StatusCode::OK, "a move that keeps a key: {j}");
    let source = sql_text(&b, "SELECT source FROM federation_peers WHERE domain = $1", A).await;
    assert_eq!(source.as_deref(), Some("well_known"));

    sql_exec(&b, "UPDATE federation_peers SET source = 'srv', expires_at = $1", &[&past]).await;
    a.restart_with_keys(vec![NodeKey::generate("zzz-takeover")]).await;
    let alice = a.login("alice").await;
    let token = a.federation_token(&alice, B).await;
    assert_eq!(code_of(&b, &token).await, (StatusCode::FORBIDDEN, "federation.peer_blocked".into()));
    let status = sql_text(&b, "SELECT status FROM federation_peers WHERE domain = $1", A).await;
    assert_eq!(status.as_deref(), Some("key_conflict"));
    let (s, _) = b.get_auth("/api/v1/users/me", &earlier.token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the earlier federated session ended");
}

/// FEDERATION.md §1.4: the cap is for peers known *only from unverified requests*. Peers this node looked up itself
/// (here: listed in its directory) must not lock out the first signed request of a new, honest peer.
#[tokio::test]
async fn peers_from_the_directory_do_not_count_against_the_unverified_peer_cap() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_max_unverified_peers = 10).await;
    let alice = a.register("alice").await;
    let now = util::now();
    for i in 0..10 {
        let d = format!("listed{i}.example");
        sql_exec(
            &b,
            "INSERT INTO federation_peers (domain, document, fetched_at, expires_at, source)
             VALUES ($1, '{}', $2, $2, 'well_known')",
            &[&d, &now],
        )
        .await;
        sql_exec(
            &b,
            "INSERT INTO directory_nodes (domain, name, description, software_name, software_version, capabilities,
             registration, source, first_seen, last_seen) VALUES ($1, 'n', '', 'tavrn-node', '0', '[]', 'open', 'relay', $2, $2)",
            &[&d, &now],
        )
        .await;
    }
    sql_exec(&b, "DELETE FROM federation_peers WHERE domain = $1", &[A]).await;
    let token = a.federation_token(&alice, B).await;
    let (s, j) = b.federated_login(&token).await;
    assert_eq!(s, StatusCode::OK, "the first sign-in of a new peer: {j}");
}

/// FEDERATION.md §1.3 rule 5, §1.4: unsigned requests naming many *different* stalling domains (a wildcard DNS name
/// of the attacker) cannot starve federation with the peers this node knows either: fetches for unknown issuers
/// run in their own few slots, and requests beyond them are refused at once (`503 federation.busy`).
#[tokio::test]
async fn stalling_issuers_on_many_domains_do_not_starve_other_peers() {
    use base64::Engine;
    use tower::ServiceExt;
    let stall = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_port = stall.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = stall.accept().await {
            held.push(sock);
        }
    });
    let peers: String = (0..70).map(|i| format!(",s{i}.slow.test=http://127.0.0.1:{stall_port}")).collect();
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_dev_peers.push_str(&peers)).await;
    let alice = a.register("alice").await;
    // A is a peer B knows (an earlier sign-in) whose cached document expired: the next sign-in needs a fetch
    // through the shared connection slots, which the flood must not have taken.
    b.sign_in_from(&a, &alice).await;
    sql_exec(&b, "UPDATE federation_peers SET expires_at = $1 WHERE domain = $2", &[&util::in_seconds(-1), A]).await;
    let b64 = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let n = now();
    let mut flood = Vec::new();
    for i in 0..70 {
        let iss = format!("s{i}.slow.test");
        let forged = format!(
            "{}.{}.{}",
            b64(json!({ "alg": "EdDSA", "typ": "JWT", "kid": "k" })),
            b64(json!({ "iss": iss, "sub": iss, "aud": B, "iat": n, "exp": n + 300, "jti": util::ulid(),
                        "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox", "body_sha256": "x" })),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 64])
        );
        let router = b.router.clone();
        flood.push(tokio::spawn(async move {
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/api/v1/federation/inbox")
                .header("authorization", format!("Bearer {forged}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap();
            router.oneshot(req).await.unwrap().status()
        }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let token = a.federation_token(&alice, B).await;
    let login = tokio::time::timeout(Duration::from_secs(4), b.federated_login(&token)).await;
    let (s, j) = login.expect("the login of a healthy peer waited for the stalling ones");
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut busy = 0;
    for task in flood {
        let status = tokio::time::timeout(Duration::from_millis(100), task).await;
        if matches!(status, Ok(Ok(s)) if s == StatusCode::SERVICE_UNAVAILABLE) {
            busy += 1;
        }
    }
    assert!(busy >= 70 - 12, "requests beyond the discovery slots are refused at once: {busy}");
}

/// Given-up notifications are counted in one statement: concurrent give-ups (up to 16 targets at once) lose no
/// increment.
#[tokio::test]
async fn concurrent_undeliverable_counts_add_up() {
    let node = common::test_node("a.test").await;
    let db = &node.state.db;
    futures::future::join_all((0..10).map(|_| tavrn_node::store::federation::count_undeliverable(db)))
        .await
        .into_iter()
        .for_each(|r| r.unwrap());
    assert_eq!(tavrn_node::store::federation::undeliverable_count(db).await.unwrap(), 10);
    tavrn_node::store::federation::count_undeliverable(db).await.unwrap();
    assert_eq!(tavrn_node::store::federation::undeliverable_count(db).await.unwrap(), 11);
}
