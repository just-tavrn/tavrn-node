// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Signing in with an account of another node (FEDERATION.md §8): the connect flow with PKCE, the peer
//! document proxy, the `web` field of the discovery document and CORS for web clients of other nodes.

use crate::common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    TestNode, body_bytes,
    federation::{A, B, two_nodes, two_nodes_with},
    test_node,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const ORIGIN: &str = "https://b.test";

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `POST /auth/connect/token` as a browser on `origin` sends it (no authentication).
async fn exchange(node: &TestNode, origin: Option<&str>, code: &str, verifier: &str) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/connect/token")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(o) = origin {
        builder = builder.header(header::ORIGIN, o);
    }
    let body = json!({ "code": code, "code_verifier": verifier }).to_string();
    let resp = node.router.clone().oneshot(builder.body(Body::from(body)).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn code_for(node: &TestNode, token: &str, origin: &str) -> String {
    let (status, json) = node
        .post(
            "/api/v1/auth/connect/code",
            token,
            json!({ "origin": origin, "code_challenge": challenge(VERIFIER), "device_name": "Browser on b.test" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["expires_in"], 120);
    json["code"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn code_and_verifier_give_a_session_of_a_new_device() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let code = code_for(&a, &alice.token, ORIGIN).await;

    let (status, session) = exchange(&a, Some(ORIGIN), &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["status"], "ok");
    assert_eq!(session["user"]["address"], "alice@a.test");
    let device = session["device_id"].as_str().unwrap();
    assert_ne!(device, alice.device_id, "the visiting web client is a new device");

    let token = session["access_token"].as_str().unwrap();
    let (status, me) = a.get_auth("/api/v1/users/me", token).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    let (_, devices) = a.get_auth("/api/v1/users/me/devices", token).await;
    let named = devices.as_array().unwrap().iter().find(|d| d["id"] == device).unwrap();
    assert_eq!(named["name"], "Browser on b.test");
    assert_eq!(named["current"], true);

    // Single use.
    let (status, again) = exchange(&a, Some(ORIGIN), &code, VERIFIER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(again["code"], "connect.code_invalid");
}

#[tokio::test]
async fn wrong_verifier_origin_or_code_fail_and_spend_the_code() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;

    let other_verifier = "x".repeat(43);
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (status, json) = exchange(&a, Some(ORIGIN), &code, &other_verifier).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));
    let (status, _) = exchange(&a, Some(ORIGIN), &code, VERIFIER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a failed attempt spends the code");

    for origin in [Some("https://evil.test"), Some("http://b.test"), None] {
        let code = code_for(&a, &alice.token, ORIGIN).await;
        let (status, json) = exchange(&a, origin, &code, VERIFIER).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{origin:?}");
        assert_eq!(json["code"], "connect.code_invalid", "{origin:?}");
    }

    let (status, json) = exchange(&a, Some(ORIGIN), "not-a-code", VERIFIER).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));
    let (status, _) = exchange(&a, Some(ORIGIN), "", VERIFIER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn codes_need_a_full_session_a_valid_origin_and_challenge() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let body = json!({ "origin": ORIGIN, "code_challenge": challenge(VERIFIER) });

    let (status, json) = a.req(Method::POST, "/api/v1/auth/connect/code", None, Some(body.clone())).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.required")));
    let preauth = a.login_preauth("alice", &common::password("alice")).await;
    let (status, json) = a.post("/api/v1/auth/connect/code", preauth["preauth_token"].as_str().unwrap(), body).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")));

    for origin in [
        "b.test",
        "https://b.test/",
        "https://b.test/connect",
        "javascript:alert(1)",
        "https://user@b.test",
        "ftp://b.test",
    ] {
        let (status, json) = a
            .post(
                "/api/v1/auth/connect/code",
                &alice.token,
                json!({ "origin": origin, "code_challenge": challenge(VERIFIER) }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{origin}");
        assert_eq!(json["code"], "connect.origin_invalid", "{origin}");
    }
    for c in ["", "plain", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="] {
        let (status, json) =
            a.post("/api/v1/auth/connect/code", &alice.token, json!({ "origin": ORIGIN, "code_challenge": c })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(json["code"], "connect.challenge_invalid");
    }
}

#[tokio::test]
async fn a_code_dies_with_the_session_that_confirmed_it() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (status, _) = a.post("/api/v1/auth/logout", &alice.token, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, json) = exchange(&a, Some(ORIGIN), &code, VERIFIER).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));
}

#[tokio::test]
async fn remote_users_cannot_issue_codes_and_the_new_session_federates() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;

    // bob@b.test with a federated session on A: the connect flow belongs to his home node.
    let remote = a.sign_in_from(&b, &bob).await;
    let (status, json) = a
        .post(
            "/api/v1/auth/connect/code",
            &remote.token,
            json!({ "origin": ORIGIN, "code_challenge": challenge(VERIFIER) }),
        )
        .await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));

    // alice signs in on B's web client through the connect flow, then gets a federated session on B.
    let code = code_for(&a, &alice.token, "http://b.test:5274").await;
    let (status, session) = exchange(&a, Some("http://b.test:5274"), &code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let token = session["access_token"].as_str().unwrap();
    let (status, fed) = a.post("/api/v1/federation/token", token, json!({ "target": B })).await;
    assert_eq!(status, StatusCode::OK, "{fed}");
    let (status, login) = b.federated_login(fed["token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{login}");
    assert_eq!(login["user"]["address"], "alice@a.test");
    assert_eq!(login["device_id"], session["device_id"], "B knows the new device by its id on A");
}

#[tokio::test]
async fn peer_documents_are_served_through_the_federation_client() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_blocklist = "blocked.test".into()).await;
    let (status, doc) = b.get_auth("/api/v1/federation/peer/a.test", "").await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["domain"], A);
    assert_eq!(doc["web"], "https://a.test", "the web client origin (TAVRN_WEBAUTHN_ORIGIN)");
    assert!(doc["api"].as_str().unwrap().ends_with("/api/v1"));
    assert!(doc["capabilities"].as_array().unwrap().contains(&json!("federation.v1")));

    let (status, json) = b.get_auth("/api/v1/federation/peer/b.test", "").await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.target_self")));
    for bad in ["localhost", "127.0.0.1", "a.test:8080", "A_B.test"] {
        let (status, json) = b.get_auth(&format!("/api/v1/federation/peer/{bad}"), "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(json["code"], "federation.domain_invalid", "{bad}");
    }
    // The domain policy applies: nothing is fetched for a blocked domain.
    let (status, json) = b.get_auth("/api/v1/federation/peer/blocked.test", "").await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
    drop(a);
}

#[tokio::test]
async fn well_known_names_the_web_client() {
    let a = test_node(A).await;
    let (status, doc) = a.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["web"], "https://a.test");
}

#[tokio::test]
async fn cors_allows_bearer_requests_from_any_origin_without_credentials() {
    let a = test_node(A).await;
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/users/me/conversations-index")
        .header(header::ORIGIN, "https://visited.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization, content-type, if-match, tavrn-client")
        .body(Body::empty())
        .unwrap();
    let resp = a.router.clone().oneshot(preflight).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let h = resp.headers();
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert!(h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none());
    assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "600");
    let allowed = h[header::ACCESS_CONTROL_ALLOW_HEADERS].to_str().unwrap().to_lowercase();
    for name in ["authorization", "content-type", "if-match", "tavrn-client", "idempotency-key", "accept-language"] {
        assert!(allowed.contains(name), "{name} in {allowed}");
    }

    let alice = a.register("alice").await;
    let get = Request::get("/api/v1/users/me/conversations-index")
        .header(header::ORIGIN, "https://visited.example")
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .body(Body::empty())
        .unwrap();
    let resp = a.router.clone().oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    let exposed = h[header::ACCESS_CONTROL_EXPOSE_HEADERS].to_str().unwrap().to_lowercase();
    for name in ["etag", "retry-after", "location"] {
        assert!(exposed.contains(name), "{name} in {exposed}");
    }
}

/// `POST /auth/connect/token` with a device proof (ENCRYPTION.md §3.4).
async fn exchange_with(node: &TestNode, code: &str, device: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/connect/token")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from(json!({ "code": code, "code_verifier": VERIFIER, "device": device }).to_string()))
        .unwrap();
    let resp = node.router.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn nonce(node: &TestNode) -> String {
    let (s, j) = node.req(Method::POST, "/api/v1/auth/device-nonce", None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j["nonce"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn the_exchange_continues_a_device_the_browser_proves_to_hold() {
    use tavrn_crypto::{Device, MasterSecret, util::b64url_encode as b64};
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let master = MasterSecret::generate().unwrap();
    let (s, j) = a
        .put(
            "/api/v1/users/me/identity",
            &alice.token,
            json!({ "identity_public_key": b64(&master.identity_public_key()) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // The first connect sign-in of this browser creates its device, which then attests its key.
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (_, first) = exchange(&a, Some(ORIGIN), &code, VERIFIER).await;
    let visiting = first["device_id"].as_str().unwrap().to_string();
    let device = Device::generate("alice@a.test", &visiting).unwrap();
    let att = device.attest(&master).unwrap();
    let (s, j) = a
        .put(
            &format!("/api/v1/users/me/devices/{visiting}/key"),
            first["access_token"].as_str().unwrap(),
            json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // The next connect sign-in proves the device: no new device.
    let n = nonce(&a).await;
    let proof = json!({ "id": visiting, "nonce": n, "proof": b64(&device.sign_login(&n).unwrap()) });
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (s, again) = exchange_with(&a, &code, proof.clone()).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["device_id"], visiting.as_str(), "the same device");

    // A spent nonce, a wrong signature or a device of another user only mean a new device.
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (_, spent) = exchange_with(&a, &code, proof).await;
    assert_ne!(spent["device_id"], visiting.as_str());
    let n = nonce(&a).await;
    let forged = Device::generate("alice@a.test", &visiting).unwrap();
    let code = code_for(&a, &alice.token, ORIGIN).await;
    let (s, other) =
        exchange_with(&a, &code, json!({ "id": visiting, "nonce": n, "proof": b64(&forged.sign_login(&n).unwrap()) }))
            .await;
    assert_eq!(s, StatusCode::OK, "{other}");
    assert_ne!(other["device_id"], visiting.as_str());
    let bob = a.register("bob").await;
    let n = nonce(&a).await;
    let code = code_for(&a, &bob.token, ORIGIN).await;
    let (_, stolen) =
        exchange_with(&a, &code, json!({ "id": visiting, "nonce": n, "proof": b64(&device.sign_login(&n).unwrap()) }))
            .await;
    assert_eq!(stolen["user"]["address"], "bob@a.test");
    assert_ne!(stolen["device_id"], visiting.as_str(), "never another user's device");
}

// ---- App sessions (FEDERATION.md §8 step 3, capability `connect.app`): the desktop app polls instead of a redirect.

async fn create_session(node: &TestNode, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, "/api/v1/auth/connect/session", None, Some(body)).await
}

async fn new_session(node: &TestNode, device_name: &str) -> String {
    let (status, json) =
        create_session(node, json!({ "code_challenge": challenge(VERIFIER), "device_name": device_name })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["expires_in"], 600);
    let id = json["session_id"].as_str().unwrap().to_string();
    assert_eq!(id.len(), 43, "32 random bytes in base64url");
    id
}

async fn poll(node: &TestNode, id: &str) -> (StatusCode, Value) {
    node.req(Method::GET, &format!("/api/v1/auth/connect/session/{id}"), None, None).await
}

async fn confirm(node: &TestNode, token: &str, body: Value) -> (StatusCode, Value) {
    node.post("/api/v1/auth/connect/code", token, body).await
}

#[tokio::test]
async fn an_app_session_polls_the_code_and_exchanges_it_for_a_new_device() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let id = new_session(&a, "Tavrn on the laptop").await;

    // The page reads the device name before the confirmation; the app sees "pending".
    let (status, pending) = poll(&a, &id).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["device_name"], "Tavrn on the laptop");
    assert!(pending["expires_in"].as_u64().unwrap() <= 600);
    assert!(pending.get("code").is_none());

    // The home client confirms with the session id (no origin, no challenge needed: the session has it).
    let (status, issued) = confirm(&a, &alice.token, json!({ "session_id": id, "device_name": "ignored" })).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(issued["expires_in"], 120);

    // The app gets the code exactly once, then the session is gone.
    let (status, ready) = poll(&a, &id).await;
    assert_eq!(status, StatusCode::OK, "{ready}");
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["node"], A);
    assert_eq!(ready["code"], issued["code"]);
    assert!(ready["expires_in"].as_u64().unwrap() <= 120);
    let (status, gone) = poll(&a, &id).await;
    assert_eq!((status, gone["code"].as_str()), (StatusCode::GONE, Some("connect.session_expired")));

    // The app's page runs on tauri://localhost: no origin check for a code bound to an app session.
    let code = ready["code"].as_str().unwrap();
    let (status, session) = exchange(&a, Some("tauri://localhost"), code, VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user"]["address"], "alice@a.test");
    let device = session["device_id"].as_str().unwrap();
    assert_ne!(device, alice.device_id);
    let (_, devices) = a.get_auth("/api/v1/users/me/devices", session["access_token"].as_str().unwrap()).await;
    let named = devices.as_array().unwrap().iter().find(|d| d["id"] == device).unwrap();
    assert_eq!(named["name"], "Tavrn on the laptop", "the session's device name wins over the page's");

    // Replay of the code.
    let (status, json) = exchange(&a, None, code, VERIFIER).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));
}

#[tokio::test]
async fn an_app_session_code_without_an_origin_header_and_the_audit() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let id = new_session(&a, "Desktop app").await;
    let (status, _) = confirm(&a, &alice.token, json!({ "session_id": id })).await;
    assert_eq!(status, StatusCode::OK);
    let (_, ready) = poll(&a, &id).await;
    let (status, session) = exchange(&a, None, ready["code"].as_str().unwrap(), VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    // Audited like the origin flow: target the account, `app` instead of the origin, the device in the details.
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'user.connect' AND target = 'alice@a.test' AND reason = 'app' AND meta LIKE $1",
    )
    .bind(format!("%{}%", session["device_id"].as_str().unwrap()))
    .fetch_one(&a.state.db)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn an_app_session_is_confirmed_once_and_a_wrong_verifier_spends_its_code() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let id = new_session(&a, "Desktop app").await;
    let (status, _) = confirm(&a, &alice.token, json!({ "session_id": id })).await;
    assert_eq!(status, StatusCode::OK);
    // A second confirmation (another account that learned the id) cannot replace alice's code.
    let (status, json) = confirm(&a, &bob.token, json!({ "session_id": id })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::GONE, Some("connect.session_expired")));

    let (_, ready) = poll(&a, &id).await;
    let code = ready["code"].as_str().unwrap();
    let (status, json) = exchange(&a, None, code, &"x".repeat(43)).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));
    let (status, _) = exchange(&a, None, code, VERIFIER).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a failed attempt spends the code");
}

#[tokio::test]
async fn expired_and_unknown_app_sessions() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;

    let (status, json) = poll(&a, &"A".repeat(43)).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::NOT_FOUND, Some("connect.session_invalid")));
    for bad in ["short", "x".repeat(44).as_str(), "a+b"] {
        let (status, json) = poll(&a, bad).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
        assert_eq!(json["code"], "connect.session_invalid", "{bad}");
    }
    let (status, json) = confirm(&a, &alice.token, json!({ "session_id": "A".repeat(43) })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.session_invalid")));
    let (status, json) = confirm(&a, &alice.token, json!({ "session_id": "nope" })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.session_invalid")));

    // A session that ran out: polling and confirming say so.
    a.state.connect_sessions.set_lifetimes_for_tests(std::time::Duration::from_millis(200));
    let id = new_session_short(&a).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (status, json) = poll(&a, &id).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::GONE, Some("connect.session_expired")));
    let (status, json) = confirm(&a, &alice.token, json!({ "session_id": id })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::GONE, Some("connect.session_expired")));

    // A confirmed session lives as long as its code: not polled in time, it is gone too.
    let id = new_session_short(&a).await;
    let (status, _) = confirm(&a, &alice.token, json!({ "session_id": id })).await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (status, json) = poll(&a, &id).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::GONE, Some("connect.session_expired")));
}

/// A session under the shortened lifetimes of [`expired_and_unknown_app_sessions`].
async fn new_session_short(node: &TestNode) -> String {
    let (status, json) = create_session(node, json!({ "code_challenge": challenge(VERIFIER) })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    json["session_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn origin_and_session_id_are_exclusive_and_the_challenge_must_match() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let id = new_session(&a, "Desktop app").await;
    for body in [
        json!({ "origin": ORIGIN, "session_id": id, "code_challenge": challenge(VERIFIER) }),
        json!({ "code_challenge": challenge(VERIFIER) }),
        json!({}),
    ] {
        let (status, json) = confirm(&a, &alice.token, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(json["code"], "connect.target_invalid", "{body}");
    }
    // The origin flow still needs its challenge.
    let (status, json) = confirm(&a, &alice.token, json!({ "origin": ORIGIN })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.challenge_invalid")));
    // A challenge given with a session must be the session's.
    let (status, json) =
        confirm(&a, &alice.token, json!({ "session_id": id, "code_challenge": challenge(&"y".repeat(43)) })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.challenge_invalid")));
    let (status, json) =
        confirm(&a, &alice.token, json!({ "session_id": id, "code_challenge": challenge(VERIFIER) })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
}

#[tokio::test]
async fn creating_an_app_session_validates_its_input() {
    let a = test_node(A).await;
    for c in ["", "plain", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="] {
        let (status, json) = create_session(&a, json!({ "code_challenge": c })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{c}");
        assert_eq!(json["code"], "connect.challenge_invalid", "{c}");
    }
    let (status, json) =
        create_session(&a, json!({ "code_challenge": challenge(VERIFIER), "device_name": "x".repeat(200) })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let (_, pending) = poll(&a, json["session_id"].as_str().unwrap()).await;
    assert_eq!(pending["device_name"].as_str().unwrap().chars().count(), 64, "cut to 64 characters");
    let (status, json) = create_session(&a, json!({ "code_challenge": challenge(VERIFIER) })).await;
    let (_, pending) = poll(&a, json["session_id"].as_str().unwrap()).await;
    assert_eq!((status, pending["device_name"].as_str()), (StatusCode::OK, Some("Desktop app")), "the default name");
}

#[tokio::test]
async fn app_sessions_are_rate_limited_per_ip_and_polls_per_session() {
    let a = test_node(A).await;
    let limit = tavrn_node::connect_sessions::create_limit(true);
    let body = json!({ "code_challenge": challenge(VERIFIER) });
    let mut last = String::new();
    for i in 0..limit {
        let (status, json) = create_session(&a, body.clone()).await;
        assert_eq!(status, StatusCode::OK, "creation {i}: {json}");
        last = json["session_id"].as_str().unwrap().to_string();
    }
    let (status, json) = create_session(&a, body).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{json}");

    for i in 0..tavrn_node::connect_sessions::POLLS_PER_SESSION {
        let (status, json) = poll(&a, &last).await;
        assert_eq!(status, StatusCode::OK, "poll {i}: {json}");
    }
    let (status, _) = poll(&a, &last).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn an_app_session_code_dies_with_the_confirming_session_and_remote_users_cannot_confirm() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let id = new_session(&a, "Desktop app").await;
    let (status, _) = confirm(&a, &alice.token, json!({ "session_id": id })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = a.post("/api/v1/auth/logout", &alice.token, json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, ready) = poll(&a, &id).await;
    let (status, json) = exchange(&a, None, ready["code"].as_str().unwrap(), VERIFIER).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")));

    let bob = b.register("bob").await;
    let remote = a.sign_in_from(&b, &bob).await;
    let id = new_session(&a, "Desktop app").await;
    let (status, json) = confirm(&a, &remote.token, json!({ "session_id": id })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));
}

#[tokio::test]
async fn well_known_announces_app_sessions() {
    let a = test_node_with_federation_off().await;
    let (status, doc) = a.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(doc["capabilities"].as_array().unwrap().contains(&json!("connect.app")), "{doc}");
}

async fn test_node_with_federation_off() -> TestNode {
    common::test_node_with(A, |c| c.federation_enabled = false).await
}
