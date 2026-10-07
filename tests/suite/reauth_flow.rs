// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Sudo mode (PROTOCOL.md §5c) and retired devices (ENCRYPTION.md §2.3, §5.2).
use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    TestNode,
    e2ee::{address, b64},
    password, test_node,
    webauthn::Authenticator,
};
use serde_json::{Value, json};
use tavrn_crypto::Device;

async fn reauth(node: &TestNode, token: &str, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, "/api/v1/auth/reauth", Some(token), Some(body)).await
}

#[tokio::test]
async fn sensitive_changes_need_a_fresh_reauthentication() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let second = node.login("alice").await;
    // Right after the login the session carries a reauth token (the login was the proof).
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", second.device_id), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // A session without one (e.g. a stolen or refreshed access token) is refused, with the methods.
    let third = node.login("alice").await;
    node.forget_reauth(&alice.token);
    let refused = |(s, j): (StatusCode, Value)| {
        assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")), "{j}");
        j
    };
    let j = refused(node.delete(&format!("/api/v1/users/me/devices/{}", third.device_id), &alice.token).await);
    assert_eq!(j["meta"]["methods"], json!(["password"]));
    refused(node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await);
    refused(node.post("/api/v1/auth/recovery-codes/regenerate", &alice.token, json!({})).await);
    refused(node.req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({ "code": "123456" }))).await);
    refused(
        node.put(
            "/api/v1/users/me/secret-storage/passkey/AAAA",
            &alice.token,
            json!({ "wrapped": "AA", "params": {} }),
        )
        .await,
    );

    // Wrong password: 403 (the session itself is fine), never 401.
    let (s, j) = reauth(&node, &alice.token, json!({ "password": "wrong-wrong-1" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_failed")));
    let (s, j) = reauth(&node, &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, token) = reauth(&node, &alice.token, json!({ "password": password("alice") })).await;
    assert_eq!(s, StatusCode::OK, "{token}");
    assert_eq!(token["expires_in"], 300);
    let rt = token["reauth_token"].as_str().unwrap().to_string();
    node.reauth.lock().unwrap().insert(alice.token.clone(), rt.clone());
    let (s, j) = node.delete(&format!("/api/v1/users/me/devices/{}", third.device_id), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, j) = node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "reusable for five minutes: {j}");

    // Bound to the session: another session of the same user cannot use it.
    let other = node.login("alice").await;
    node.reauth.lock().unwrap().insert(other.token.clone(), rt.clone());
    refused(node.post("/api/v1/auth/webauthn/register/start", &other.token, json!({})).await);
    // A reauth token is no access token.
    let (s, _) = node.get_auth("/api/v1/users/me", &rt).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Ends with the session.
    node.post("/api/v1/auth/logout", &other.token, json!({})).await;
    let fourth = node.login("alice").await;
    let (_, t) = reauth(&node, &fourth.token, json!({ "password": password("alice") })).await;
    let rt4 = t["reauth_token"].as_str().unwrap().to_string();
    node.post("/api/v1/auth/logout", &fourth.token, json!({})).await;
    assert!(!tavrn_node::reauth::valid(&node.state, &auth_of(&node, &alice.token).await, &rt4).await.unwrap());
}

async fn auth_of(node: &TestNode, token: &str) -> tavrn_node::auth::AuthUser {
    tavrn_node::auth::authenticate(&node.state, token).await.unwrap()
}

#[tokio::test]
async fn reauthentication_with_a_passkey() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let mut key = Authenticator::new();
    node.add_passkey(&alice.token, &mut key, "Handy").await;
    node.forget_reauth(&alice.token);
    let (s, start) = node.post("/api/v1/auth/reauth/webauthn/start", &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let assertion = key.authenticate(&start["options"]);
    let (s, j) =
        reauth(&node, &alice.token, json!({ "challenge_id": start["challenge_id"], "response": assertion })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The challenge is single use.
    let (s, _) =
        reauth(&node, &alice.token, json!({ "challenge_id": start["challenge_id"], "response": assertion })).await;
    assert_ne!(s, StatusCode::OK);
    // Another user's challenge does not count.
    let bob = node.register("bob").await;
    let (_, start) = node.post("/api/v1/auth/reauth/webauthn/start", &alice.token, json!({})).await;
    let assertion = key.authenticate(&start["options"]);
    let (s, _) =
        reauth(&node, &bob.token, json!({ "challenge_id": start["challenge_id"], "response": assertion })).await;
    assert_ne!(s, StatusCode::OK);
}

#[tokio::test]
async fn deleted_devices_stay_verifiable_as_retired() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let second = node.second_device(&alice).await;
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", alice.session.device_id), second.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    let active: Vec<&str> =
        keys["devices"].as_array().unwrap().iter().map(|d| d["device_id"].as_str().unwrap()).collect();
    assert_eq!(active, vec![second.session.device_id.as_str()], "deleted devices are not active");
    let retired = keys["retired"].as_array().unwrap();
    assert_eq!(retired.len(), 1, "{keys}");
    assert_eq!(retired[0]["device_id"], alice.session.device_id.as_str());
    assert_eq!(retired[0]["device_public_key"], b64(&alice.client.device().public_key()).as_str());
    assert!(retired[0]["deleted_at"].as_str().is_some());
    // Not claimable, not in the device list.
    let (_, claimed) = node.post("/api/v1/users/alice/key-packages/claim", second.token(), json!({})).await;
    assert!(
        claimed["key_packages"].as_array().unwrap().iter().all(|k| k["device_id"] != alice.session.device_id.as_str())
    );
    let (_, list) = node.get_auth("/api/v1/users/me/devices", second.token()).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn own_devices_deleted_earlier_can_be_attested_again_as_retired() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let second = node.second_device(&alice).await;
    // A device that was deleted before retired keys existed: its row is gone.
    let gone = "01J9ZK3G5M8Q2W4E6R8T0Y2V4X";
    let old = Device::generate(&address(&alice.session), gone).unwrap();
    let att = old.attest(&alice.master).unwrap();
    let body = |sig: &[u8]| json!({ "device_id": gone, "public_key": b64(&att.device_public_key), "identity_signature": b64(sig) });
    // A signature by another identity key is refused.
    let foreign = old.attest(&tavrn_crypto::MasterSecret::generate().unwrap()).unwrap();
    let (s, j) = node.post("/api/v1/users/me/devices/retired", second.token(), body(&foreign.signature)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("e2ee.attestation_invalid")));
    // Only ids this node deleted itself (a tombstone, ENCRYPTION.md §2.3): an unknown id is refused.
    let (s, j) = node.post("/api/v1/users/me/devices/retired", second.token(), body(&att.signature)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("device.unknown")), "{j}");
    // A device the node deleted whose retired key got lost: its tombstone allows the re-attestation.
    sqlx::query("INSERT INTO device_tombstones (device_id, user_id, deleted_at) VALUES ($1, $2, $3)")
        .bind(gone)
        .bind(&alice.session.user_id)
        .bind(tavrn_node::util::now())
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) = node.post("/api/v1/users/me/devices/retired", second.token(), body(&att.signature)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, _) = node.post("/api/v1/users/me/devices/retired", second.token(), body(&att.signature)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "idempotent");
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["retired"][0]["device_id"], gone);
    // Another key for the same id is refused.
    let other = Device::generate(&address(&alice.session), gone).unwrap().attest(&alice.master).unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/devices/retired",
            second.token(),
            json!({ "device_id": gone, "public_key": b64(&other.device_public_key), "identity_signature": b64(&other.signature) }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("device.retired_conflict")));
    // Active device ids are refused (they are not retired).
    let active = alice.client.device().attest(&alice.master).unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/devices/retired",
            second.token(),
            json!({ "device_id": alice.session.device_id, "public_key": b64(&active.device_public_key), "identity_signature": b64(&active.signature) }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("device.active")));
}
