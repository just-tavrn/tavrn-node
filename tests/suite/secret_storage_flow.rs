// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Secret storage (ENCRYPTION.md §2.4): the wrapped master secret on the home node.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::{
    e2ee::{b64, unb64},
    password, test_node,
    webauthn::Authenticator,
};
use serde_json::json;
use tavrn_crypto::{
    MasterSecret, RecoveryKey,
    secret_storage::{METHOD_RECOVERY, passkey_method, passkey_wrapping_key, unwrap_master_secret, wrap_master_secret},
};
use tavrn_node::auth::RateLimiter;

const ALICE: &str = "alice@t.local";

#[tokio::test]
async fn recovery_entry_roundtrip_crud_and_validation() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, list) = node.get_auth("/api/v1/users/me/secret-storage", &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list, json!({ "items": [] }));

    // Registration: the client wraps the master secret with the recovery key and uploads it.
    let master = MasterSecret::generate().unwrap();
    let recovery = RecoveryKey::generate().unwrap();
    let wrapped = wrap_master_secret(&master, &recovery.wrapping_key(), ALICE, METHOD_RECOVERY).unwrap();
    let params = json!({ "created_by": "tavrn-web/0.1" });
    let (s, j) = node
        .put(
            "/api/v1/users/me/secret-storage/recovery",
            &alice.token,
            json!({ "wrapped": b64(&wrapped), "params": params }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // New device: full login (password + second factor), fetch, unwrap with the typed words.
    let phone = node.login("alice").await;
    let (s, list) = node.get_auth("/api/v1/users/me/secret-storage", &phone.token).await;
    assert_eq!(s, StatusCode::OK);
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["method"], "recovery");
    assert_eq!(items[0]["params"], params);
    assert!(items[0]["updated_at"].is_string());
    let typed = RecoveryKey::from_text(&recovery.to_words().unwrap()).unwrap();
    let unwrapped =
        unwrap_master_secret(&unb64(&items[0]["wrapped"]), &typed.wrapping_key(), ALICE, "recovery").unwrap();
    assert_eq!(*unwrapped.to_bytes(), *master.to_bytes());

    // Regenerating the recovery key replaces the entry (same master secret).
    let new_key = RecoveryKey::generate().unwrap();
    let rewrapped = wrap_master_secret(&master, &new_key.wrapping_key(), ALICE, METHOD_RECOVERY).unwrap();
    let (s, _) = node
        .put(
            "/api/v1/users/me/secret-storage/recovery",
            &phone.token,
            json!({ "wrapped": b64(&rewrapped), "params": {} }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", &alice.token).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(unb64(&list["items"][0]["wrapped"]), rewrapped);

    // Malformed entries and params.
    let mut v2 = wrapped.clone();
    v2[0] = 2;
    let big = "x".repeat(3000);
    let cases = [
        (json!({ "wrapped": "not base64!", "params": {} }), StatusCode::BAD_REQUEST, "secret_storage.invalid"),
        (json!({ "wrapped": b64(&wrapped[..60]), "params": {} }), StatusCode::BAD_REQUEST, "secret_storage.invalid"),
        (
            json!({ "wrapped": b64(&[wrapped.clone(), vec![0]].concat()), "params": {} }),
            StatusCode::BAD_REQUEST,
            "secret_storage.invalid",
        ),
        (json!({ "wrapped": b64(&v2), "params": {} }), StatusCode::BAD_REQUEST, "secret_storage.invalid"),
        (
            json!({ "wrapped": b64(&wrapped), "params": [1, 2] }),
            StatusCode::BAD_REQUEST,
            "secret_storage.params_invalid",
        ),
        (json!({ "wrapped": b64(&wrapped), "params": "x" }), StatusCode::BAD_REQUEST, "secret_storage.params_invalid"),
        (
            json!({ "wrapped": b64(&wrapped), "params": { "x": big } }),
            StatusCode::PAYLOAD_TOO_LARGE,
            "secret_storage.params_too_large",
        ),
        (json!({ "params": {} }), StatusCode::BAD_REQUEST, "request.invalid_json"),
    ];
    for (body, status, code) in cases {
        let (s, j) = node.put("/api/v1/users/me/secret-storage/recovery", &alice.token, body.clone()).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{body}: {j}");
        if code == "secret_storage.invalid" {
            // API texts are English (the client localizes by code).
            assert_eq!(j["detail"], "wrapped: expected 61 bytes of base64url with version 1", "{j}");
        }
    }
    let (s, j) = node
        .put(
            "/api/v1/users/me/secret-storage/recovery",
            &alice.token,
            json!({ "wrapped": b64(&wrapped), "params": { "x": "y".repeat(40 * 1024) } }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("request.too_large")), "{j}");
    let (s, _) = node
        .put(
            "/api/v1/users/me/secret-storage/password",
            &alice.token,
            json!({ "wrapped": b64(&wrapped), "params": {} }),
        )
        .await;
    assert!(s == StatusCode::NOT_FOUND || s == StatusCode::METHOD_NOT_ALLOWED, "no password method: {s}");
}

#[tokio::test]
async fn only_fully_authenticated_owners_get_their_entries() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let wrapped = wrap_master_secret(&MasterSecret::generate().unwrap(), &[1u8; 32], ALICE, METHOD_RECOVERY).unwrap();
    let body = json!({ "wrapped": b64(&wrapped), "params": {} });
    node.put("/api/v1/users/me/secret-storage/recovery", &alice.token, body.clone()).await;

    // A stolen password alone (pre-auth token) is not enough.
    let pre = node.login_preauth("alice", &password("alice")).await;
    let pre = pre["preauth_token"].as_str().unwrap();
    let (s, j) = node.get_auth("/api/v1/users/me/secret-storage", pre).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")), "{j}");
    let (s, _) = node.put("/api/v1/users/me/secret-storage/recovery", pre, body.clone()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, j) = node.req(Method::GET, "/api/v1/users/me/secret-storage", None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.required")));

    // Bob only ever sees his own (empty) storage.
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", &bob.token).await;
    assert_eq!(list, json!({ "items": [] }));
}

#[tokio::test]
async fn passkey_entries_belong_to_a_prf_credential_and_go_with_it() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let master = MasterSecret::generate().unwrap();

    // A credential whose registration announced no PRF accepts an entry (the entry proves the PRF works, for
    // example a platform authenticator that reports the extension only at assertion time) and gains the flag.
    let mut plain = Authenticator::new();
    let plain_id = node.add_passkey(&alice.token, &mut plain, "Old security key").await["credential"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let entry = |id: &str| {
        let key = passkey_wrapping_key(&[7u8; 32]).unwrap();
        json!({ "wrapped": b64(&wrap_master_secret(&master, &key, ALICE, &passkey_method(id).unwrap()).unwrap()), "params": { "prf": "v1" } })
    };
    let (_, factors) = node.get_auth("/api/v1/auth/factors", &alice.token).await;
    let flag = |f: &serde_json::Value| {
        f["webauthn"].as_array().unwrap().iter().find(|c| c["id"] == plain_id).unwrap()["prf_supported"].clone()
    };
    assert_eq!(flag(&factors), false, "{factors}");
    let (s, j) =
        node.put(&format!("/api/v1/users/me/secret-storage/passkey/{plain_id}"), &alice.token, entry(&plain_id)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, factors) = node.get_auth("/api/v1/auth/factors", &alice.token).await;
    assert_eq!(flag(&factors), true, "the stored entry marks the credential as PRF-capable: {factors}");
    let (s, _) = node.delete(&format!("/api/v1/users/me/secret-storage/passkey/{plain_id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Two PRF credentials, one entry each.
    let mut prf_ids = Vec::new();
    for name in ["Windows Hello", "Android"] {
        let mut key = Authenticator::new();
        let (s, j) = node
            .try_add_passkey(&alice.token, &mut key, name, |c| {
                c.as_object_mut().unwrap().remove("extensions");
                c["clientExtensionResults"] = json!({ "prf": { "enabled": true } });
            })
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
        let id = j["credential"]["id"].as_str().unwrap().to_string();
        let (s, j) = node.put(&format!("/api/v1/users/me/secret-storage/passkey/{id}"), &alice.token, entry(&id)).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
        prf_ids.push(id);
    }
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", &alice.token).await;
    let methods: Vec<&str> = list["items"].as_array().unwrap().iter().map(|i| i["method"].as_str().unwrap()).collect();
    assert_eq!(methods.len(), 2);
    for id in &prf_ids {
        assert!(methods.contains(&format!("passkey:{id}").as_str()), "{methods:?}");
    }
    let item =
        list["items"].as_array().unwrap().iter().find(|i| i["method"] == format!("passkey:{}", prf_ids[0])).unwrap();
    let key = passkey_wrapping_key(&[7u8; 32]).unwrap();
    let out = unwrap_master_secret(&unb64(&item["wrapped"]), &key, ALICE, &format!("passkey:{}", prf_ids[0])).unwrap();
    assert_eq!(*out.to_bytes(), *master.to_bytes());

    // Unknown credentials, other users' credentials and malformed ids.
    let bob_id = {
        let mut key = Authenticator::new();
        let (_, j) = node
            .try_add_passkey(&bob.token, &mut key, "Bob", |c| {
                c.as_object_mut().unwrap().remove("extensions");
                c["clientExtensionResults"] = json!({ "prf": { "enabled": true } });
            })
            .await;
        j["credential"]["id"].as_str().unwrap().to_string()
    };
    for id in ["AAAAAAAA", bob_id.as_str()] {
        let (s, j) = node.put(&format!("/api/v1/users/me/secret-storage/passkey/{id}"), &alice.token, entry(id)).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("webauthn.not_found")), "{id}: {j}");
    }
    let (s, j) = node.put("/api/v1/users/me/secret-storage/passkey/a%20b", &alice.token, entry("ab")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    // Delete an entry explicitly; deleting the credential removes the other one.
    let (s, _) = node.delete(&format!("/api/v1/users/me/secret-storage/passkey/{}", prf_ids[0]), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = node.delete(&format!("/api/v1/users/me/secret-storage/passkey/{}", prf_ids[0]), &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("secret_storage.not_found")), "{j}");
    let (s, _) = node.delete(&format!("/api/v1/auth/webauthn/credentials/{}", prf_ids[1]), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", &alice.token).await;
    assert_eq!(list, json!({ "items": [] }));
    // Bob's entry space is untouched by all this.
    let (s, _) =
        node.put(&format!("/api/v1/users/me/secret-storage/passkey/{bob_id}"), &bob.token, entry(&bob_id)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn identity_reset_deletes_all_entries() {
    let node = test_node("t.local").await;
    let alice = node.crypto_user("alice").await;
    let wrapped =
        wrap_master_secret(&alice.master, &RecoveryKey::generate().unwrap().wrapping_key(), ALICE, METHOD_RECOVERY)
            .unwrap();
    let (s, _) = node
        .put(
            "/api/v1/users/me/secret-storage/recovery",
            alice.token(),
            json!({ "wrapped": b64(&wrapped), "params": {} }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let new_master = MasterSecret::generate().unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&new_master.identity_public_key()), "password": password("alice") }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", alice.token()).await;
    assert_eq!(list, json!({ "items": [] }));
}

#[tokio::test]
async fn secret_storage_writes_are_rate_limited() {
    let mut node = test_node("t.local").await;
    node.state.secret_storage_limiter = Arc::new(RateLimiter::new(3, Duration::from_secs(3600)));
    node.router = tavrn_node::app::router(node.state.clone());
    let alice = node.register("alice").await;
    let wrapped = wrap_master_secret(&MasterSecret::generate().unwrap(), &[1u8; 32], ALICE, METHOD_RECOVERY).unwrap();
    let body = json!({ "wrapped": b64(&wrapped), "params": {} });
    for _ in 0..3 {
        let (s, _) = node.put("/api/v1/users/me/secret-storage/recovery", &alice.token, body.clone()).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    }
    let (s, j) = node.put("/api/v1/users/me/secret-storage/recovery", &alice.token, body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    // Reading is not limited.
    let (s, _) = node.get_auth("/api/v1/users/me/secret-storage", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
}
