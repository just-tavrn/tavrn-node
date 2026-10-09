// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Sessions and devices (PROTOCOL.md §5b): refresh rotation with reuse grace, configurable lifetimes,
//! device reuse at login with a device proof, the devices list and the stale device cleanup.
use crate::common;

use axum::http::{Method, StatusCode};
use chrono::{Duration, Utc};
use common::{
    Session, TestNode,
    e2ee::{Dev, address, b64},
    oidc::{FakeIdp, Login, configure, pkce, until_callback},
    password, test_node, test_node_with,
};
use serde_json::{Value, json};
use tavrn_crypto::{Device, MasterSecret};
use tavrn_node::{store, util};

async fn refresh(node: &TestNode, token: &str) -> (StatusCode, Value) {
    node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": token }))).await
}

/// Moves the last rotation of every session of `device_id` into the past.
async fn age_rotation(node: &TestNode, device_id: &str, secs: i64) {
    sqlx::query("UPDATE sessions SET rotated_at = $1 WHERE device_id = $2")
        .bind(util::format_time(Utc::now() - Duration::seconds(secs)))
        .bind(device_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn parallel_refreshes_get_the_same_pair_and_reuse_after_the_grace_revokes() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    // Two tabs (or two requests after the access token expired) refresh with the same token at once.
    let ((s1, a), (s2, b)) = tokio::join!(refresh(&node, &alice.refresh), refresh(&node, &alice.refresh));
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK), "{a} {b}");
    assert_eq!(a["refresh_token"], b["refresh_token"], "both end with the same refresh token");
    assert_ne!(a["refresh_token"], alice.refresh.as_str());
    let current = a["refresh_token"].as_str().unwrap().to_string();
    for pair in [&a, &b] {
        let (s, _) = node.get_auth("/api/v1/users/me", pair["access_token"].as_str().unwrap()).await;
        assert_eq!(s, StatusCode::OK);
    }
    // A third tab that still holds the old token within the grace: the same pair again, no revocation.
    let (s, c) = refresh(&node, &alice.refresh).await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["refresh_token"], current.as_str());

    // After the grace the old token is a reuse: the whole session is revoked (theft suspected).
    age_rotation(&node, &alice.device_id, 31).await;
    let (s, j) = refresh(&node, &alice.refresh).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    assert_eq!(j["code"], "auth.refresh_invalid");
    let (s, _) = refresh(&node, &current).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the current token died with the session");
}

#[tokio::test]
async fn grace_never_extends_a_token_beyond_the_next_rotation() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (_, first) = refresh(&node, &alice.refresh).await;
    let first = first["refresh_token"].as_str().unwrap().to_string();
    let (s, second) = refresh(&node, &first).await;
    assert_eq!(s, StatusCode::OK, "{second}");
    let second = second["refresh_token"].as_str().unwrap().to_string();
    // The token two rotations back is neither current nor the previous one: refused, even within 30 seconds.
    let (s, _) = refresh(&node, &alice.refresh).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The previous one within the grace answers with the current token, never a newer one.
    let (s, again) = refresh(&node, &first).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(again["refresh_token"], second.as_str());
    // Refresh tokens are stored hashed only.
    let stored: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT refresh_token_hash, prev_refresh_token_hash FROM sessions WHERE device_id = $1")
            .bind(&alice.device_id)
            .fetch_all(&node.state.db)
            .await
            .unwrap();
    assert_eq!(stored, vec![(util::sha256_b64(&second), Some(util::sha256_b64(&first)))]);
}

#[tokio::test]
async fn rotation_is_atomic() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let db = &node.state.db;
    let session = store::users::session_by_hash(db, &util::sha256_b64(&alice.refresh)).await.unwrap().unwrap();
    let expires = util::in_seconds(3600);
    assert!(!store::users::rotate_session(db, &session.id, "not-the-current-hash", "x", &expires).await.unwrap());
    let old = util::sha256_b64(&alice.refresh);
    assert!(store::users::rotate_session(db, &session.id, &old, "new-hash", &expires).await.unwrap());
    assert!(
        !store::users::rotate_session(db, &session.id, &old, "other-hash", &expires).await.unwrap(),
        "second one loses"
    );
    store::users::revoke_session(db, &session.id).await.unwrap();
    assert!(!store::users::rotate_session(db, &session.id, "new-hash", "z", &expires).await.unwrap(), "revoked");
}

#[tokio::test]
async fn lifetimes_follow_the_configuration_and_refresh_slides() {
    let node = test_node_with("t.local", |c| {
        c.session_access_minutes = 15;
        c.session_refresh_days = 30;
    })
    .await;
    let alice = node.register("alice").await;
    sqlx::query("UPDATE devices SET last_seen_at = '2020-01-01T00:00:00.000Z' WHERE id = $1")
        .bind(&alice.device_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, pair) = refresh(&node, &alice.refresh).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(pair["expires_in"], 900);
    let expires: String = sqlx::query_scalar("SELECT expires_at FROM sessions WHERE device_id = $1")
        .bind(&alice.device_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    let days = (chrono::DateTime::parse_from_rfc3339(&expires).unwrap().with_timezone(&Utc) - Utc::now()).num_days();
    assert!((29..=30).contains(&days), "sliding 30 days: {expires}");
    let (_, devices) = node.get_auth("/api/v1/users/me/devices", pair["access_token"].as_str().unwrap()).await;
    assert!(devices[0]["last_seen_at"].as_str().unwrap() > "2026", "a refresh counts as seen: {devices}");
}

#[tokio::test]
async fn expired_access_tokens_are_refused_with_token_expired() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (s, _) = node.req(Method::POST, "/api/v1/dev/expire-access-tokens", None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.token_expired")));
    let (_, pair) = refresh(&node, &alice.refresh).await;
    let (s, _) = node.get_auth("/api/v1/users/me", pair["access_token"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK, "the refreshed token works");
}

#[tokio::test]
async fn dev_hook_forgets_a_retired_device() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let second = node.second_device(&alice).await;
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", alice.session.device_id), second.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["retired"].as_array().unwrap().len(), 1);
    let body = json!({ "device_id": alice.session.device_id });
    let (s, _) = node.req(Method::POST, "/api/v1/dev/forget-retired-device", None, Some(body)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["retired"], json!([]));
}

// ---------------------------------------------------------------- Device proof

async fn nonce(node: &TestNode) -> String {
    let (s, j) = node.req(Method::POST, "/api/v1/auth/device-nonce", None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["expires_in"], 300);
    j["nonce"].as_str().unwrap().to_string()
}

fn proof(device: &Device, nonce: &str) -> Value {
    json!({ "id": device.device_id(), "nonce": nonce, "proof": b64(&device.sign_login(nonce).unwrap()) })
}

/// Password + TOTP login with an optional device proof; returns the session response.
async fn login_with(node: &TestNode, username: &str, device: Option<Value>) -> Value {
    let body =
        json!({ "username": username, "password": password(username), "device_name": "Browser", "device": device });
    let (s, pre) = node.req(Method::POST, "/api/v1/auth/login", None, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{pre}");
    node.verify_second_factor(username, pre["preauth_token"].as_str().unwrap()).await
}

async fn device_ids(node: &TestNode, token: &str) -> Vec<String> {
    let (_, j) = node.get_auth("/api/v1/users/me/devices", token).await;
    j.as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap().to_string()).collect()
}

fn token(session: &Value) -> &str {
    session["access_token"].as_str().unwrap()
}

#[tokio::test]
async fn login_with_a_device_proof_continues_the_device() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let device = alice.client.device();
    let n = nonce(&node).await;
    let session = login_with(&node, "alice", Some(proof(device, &n))).await;
    assert_eq!(session["device_id"], alice.session.device_id.as_str(), "same device, no new row");
    assert_eq!(device_ids(&node, token(&session)).await, vec![alice.session.device_id.clone()]);
    // The device's earlier session ended (the client replaced its tokens).
    let (s, _) = refresh(&node, &alice.session.refresh).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Repeated logins keep one device.
    for _ in 0..2 {
        let s = login_with(&node, "alice", Some(proof(device, &nonce(&node).await))).await;
        assert_eq!(s["device_id"], alice.session.device_id.as_str());
    }
    let (_, devices) = node.get_auth("/api/v1/users/me/devices", token(&session)).await;
    assert_eq!(devices.as_array().unwrap().len(), 1, "{devices}");
}

#[tokio::test]
async fn invalid_device_proofs_fall_back_to_a_new_device() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    let device = alice.client.device();
    let own = alice.session.device_id.clone();

    // Wrong signature: a key that is not the device's attested key.
    let stranger = Device::generate(&address(&alice.session), &own).unwrap();
    let s = login_with(&node, "alice", Some(proof(&stranger, &nonce(&node).await))).await;
    assert_ne!(s["device_id"], own.as_str(), "wrong key");
    // Signature over another nonce than the one sent.
    let (n1, n2) = (nonce(&node).await, nonce(&node).await);
    let mut p = proof(device, &n1);
    p["nonce"] = json!(n2);
    let s = login_with(&node, "alice", Some(p)).await;
    assert_ne!(s["device_id"], own.as_str(), "proof for another nonce");
    // A nonce that is not one of this node's.
    let s = login_with(&node, "alice", Some(proof(device, "made-up-nonce"))).await;
    assert_ne!(s["device_id"], own.as_str(), "forged nonce");
    // Replay: the same nonce and proof a second time.
    let n = nonce(&node).await;
    let first = login_with(&node, "alice", Some(proof(device, &n))).await;
    assert_eq!(first["device_id"], own.as_str());
    let replay = login_with(&node, "alice", Some(proof(device, &n))).await;
    assert_ne!(replay["device_id"], own.as_str(), "a nonce is single use");
    // Another user's device, with a valid proof by that device: never taken over.
    let bob_device = bob.client.device();
    let s = login_with(&node, "alice", Some(proof(bob_device, &nonce(&node).await))).await;
    assert_ne!(s["device_id"], bob.session.device_id.as_str(), "no login onto another user's device");
    assert_eq!(s["user"]["username"], "alice");
    let (_, bobs) = node.get_auth("/api/v1/users/me/devices", &bob.session.token).await;
    assert_eq!(bobs.as_array().unwrap().len(), 1, "bob's device untouched: {bobs}");
    // Malformed fields.
    let s = login_with(&node, "alice", Some(json!({ "id": "x", "nonce": nonce(&node).await, "proof": "!!" }))).await;
    assert_ne!(s["device_id"], own.as_str());
}

#[tokio::test]
async fn deleted_and_unattested_devices_are_not_reused() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let second = node.second_device(&alice).await;
    // Deleted on the other device: a proof for it creates a new device.
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", alice.session.device_id), second.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let session = login_with(&node, "alice", Some(proof(alice.client.device(), &nonce(&node).await))).await;
    assert_ne!(session["device_id"], alice.session.device_id.as_str(), "a deleted device stays deleted");

    // A device whose key was never attested (no master secret on it yet).
    let fresh = node.login("alice").await;
    let unattested = Device::generate(&address(&fresh), &fresh.device_id).unwrap();
    let s = login_with(&node, "alice", Some(proof(&unattested, &nonce(&node).await))).await;
    assert_ne!(s["device_id"], fresh.device_id.as_str(), "no attested key: nothing to prove");
}

#[tokio::test]
async fn device_proof_works_for_passkey_and_sso_logins() {
    use common::webauthn::{Authenticator, user_handle};
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let mut key = Authenticator::new();
    let cred = node.add_passkey(alice.token(), &mut key, "Handy").await;
    let cred_id = cred["credential"]["id"].as_str().unwrap().to_string();
    let (_, start) = node.req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({}))).await;
    let assertion =
        key.authenticate_discoverable(&start["options"], &cred_id, Some(&user_handle(&alice.session.user_id)), true);
    let body = json!({
        "challenge_id": start["challenge_id"], "response": assertion, "device_name": "Handy",
        "device": proof(alice.client.device(), &nonce(&node).await),
    });
    let (s, session) = node.req(Method::POST, "/api/v1/auth/webauthn/login/finish", None, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{session}");
    assert_eq!(session["device_id"], alice.session.device_id.as_str(), "passkey-only login keeps the device");

    // SSO: the token exchange carries the proof.
    let idp = FakeIdp::start().await;
    let sso = test_node_with("sso.test", |c| configure(c, &idp)).await;
    idp.set_login(Login::new("sub-sam", "sam"));
    let exchange = |device: Option<Value>| {
        let sso = &sso;
        async move {
            let (verifier, challenge) = pkce();
            let query = until_callback(sso, "login", None, &challenge).await.unwrap();
            let body = json!({ "code": query["code"], "code_verifier": verifier, "device": device });
            let (s, j) = sso.req(Method::POST, "/api/v1/auth/oidc/token", None, Some(body)).await;
            assert_eq!(s, StatusCode::OK, "{j}");
            j
        }
    };
    let first = exchange(None).await;
    let sam = Session {
        token: token(&first).into(),
        refresh: first["refresh_token"].as_str().unwrap().into(),
        user_id: first["user"]["id"].as_str().unwrap().into(),
        username: "sam".into(),
        device_id: first["device_id"].as_str().unwrap().into(),
        totp_secret: vec![],
        recovery_codes: vec![],
    };
    // The provisioned account adds its date of birth first (PROTOCOL.md §5e).
    let (s, j) = sso
        .put("/api/v1/users/me/date-of-birth", &sam.token, json!({ "date_of_birth": common::ADULT_DATE_OF_BIRTH }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let master = MasterSecret::generate().unwrap();
    sso.put_identity(&sam, &master).await;
    let device = Device::generate("sam@sso.test", &sam.device_id).unwrap();
    let att = device.attest(&master).unwrap();
    let (s, j) = sso
        .put(
            &format!("/api/v1/users/me/devices/{}/key", sam.device_id),
            &sam.token,
            json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, n) = sso.req(Method::POST, "/api/v1/auth/device-nonce", None, None).await;
    let n = n["nonce"].as_str().unwrap().to_string();
    let again = exchange(Some(proof(&device, &n))).await;
    assert_eq!(again["device_id"], sam.device_id.as_str(), "SSO login keeps the device");
    let (_, devices) = sso.get_auth("/api/v1/users/me/devices", token(&again)).await;
    assert_eq!(devices.as_array().unwrap().len(), 1);
    // The SSO session keeps its hard end.
    let max: Option<String> =
        sqlx::query_scalar("SELECT max_expires_at FROM sessions WHERE device_id = $1 AND revoked_at IS NULL")
            .bind(&sam.device_id)
            .fetch_one(&sso.state.db)
            .await
            .unwrap();
    assert!(max.is_some());
}

// ---------------------------------------------------------------- Devices list and stale devices

#[tokio::test]
async fn devices_list_marks_current_and_stale_devices() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let second = node.login("alice").await;
    sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
        .bind(util::format_time(Utc::now() - Duration::days(100)))
        .bind(&alice.device_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (_, list) = node.get_auth("/api/v1/users/me/devices", &second.token).await;
    let by_id = |id: &str| list.as_array().unwrap().iter().find(|d| d["id"] == id).unwrap().clone();
    let old = by_id(&alice.device_id);
    let me = by_id(&second.device_id);
    assert_eq!((old["current"].as_bool(), old["stale"].as_bool()), (Some(false), Some(true)), "{old}");
    assert!(old["stale_at"].as_str().is_some());
    assert_eq!((me["current"].as_bool(), me["stale"].as_bool()), (Some(true), Some(false)), "{me}");
    assert!(me["stale_at"].is_null());
}

async fn set_last_seen(node: &TestNode, device_id: &str, days_ago: i64) {
    sqlx::query("UPDATE devices SET last_seen_at = $1 WHERE id = $2")
        .bind(util::format_time(Utc::now() - Duration::days(days_ago)))
        .bind(device_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn housekeeping_deletes_stale_devices_but_never_the_only_or_a_live_one() {
    let node = test_node("t.local").await;
    let alice: Dev = node.crypto_user("alice").await;
    let second = node.second_device(&alice).await;
    let third = node.login("alice").await;
    let bob = node.register("bob").await;
    let db = &node.state.db;
    // alice's first device: not seen for 200 days and logged out → stale. Her second device is just as old but
    // still has a live session; bob's only device is old and logged out.
    for d in [&alice.session.device_id, &second.session.device_id, &bob.device_id] {
        set_last_seen(&node, d, 200).await;
    }
    store::users::revoke_device_sessions(db, &alice.session.device_id).await.unwrap();
    store::users::revoke_device_sessions(db, &bob.device_id).await.unwrap();
    let deleted = tavrn_node::device_cleanup::prune_stale_devices(&node.state, Utc::now()).await.unwrap();
    assert_eq!(deleted, 1);
    let left = device_ids(&node, &third.token).await;
    assert!(!left.contains(&alice.session.device_id), "stale device deleted");
    assert!(left.contains(&second.session.device_id), "live session keeps a device");
    let bobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = $1")
        .bind(&bob.user_id)
        .fetch_one(db)
        .await
        .unwrap();
    assert_eq!(bobs, 1, "never the only device");

    // Switched off with 0.
    let off = test_node_with("o.local", |c| c.device_stale_days = 0).await;
    let carol = off.register("carol").await;
    off.login("carol").await;
    set_last_seen(&off, &carol.device_id, 10_000).await;
    store::users::revoke_device_sessions(&off.state.db, &carol.device_id).await.unwrap();
    assert_eq!(tavrn_node::device_cleanup::prune_stale_devices(&off.state, Utc::now()).await.unwrap(), 0);
}

#[tokio::test]
async fn logout_can_forget_the_device() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let second = node.login("alice").await;
    // A plain logout keeps the device (its keys may still be on the device).
    let (s, _) = node.post("/api/v1/auth/logout", &second.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ids = device_ids(&node, alice.token()).await;
    assert!(ids.contains(&second.device_id));
    // With forget_device the device goes as well (the client deleted its keys).
    let third = node.login("alice").await;
    let (s, _) = node.req(Method::POST, "/api/v1/auth/logout?forget_device=true", Some(&third.token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let ids = device_ids(&node, alice.token()).await;
    assert!(!ids.contains(&third.device_id), "{ids:?}");
    assert_eq!(ids.len(), 2);
}
