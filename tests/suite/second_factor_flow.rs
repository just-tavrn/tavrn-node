// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Mandatory second factor (PROTOCOL.md §5a): pre-auth tokens, TOTP, recovery
//! codes, WebAuthn (second factor and passkey-only login) and the attacks against them.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::{
    TestNode, now_secs, password, test_node, totp_code,
    webauthn::{Authenticator, user_handle},
};
use serde_json::{Value, json};
use tavrn_node::cache::limiter::SharedLimiter;

async fn verify(node: &TestNode, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, "/api/v1/auth/second-factor/verify", None, Some(body)).await
}

async fn audit_actions(node: &TestNode, admin_token: &str) -> Vec<String> {
    let (s, log) = node.get_auth("/api/v1/admin/audit-log?limit=200", admin_token).await;
    assert_eq!(s, StatusCode::OK, "{log}");
    log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap().to_string()).collect()
}

async fn discoverable_start(node: &TestNode) -> Value {
    let (s, start) = node.req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{start}");
    start
}

async fn discoverable_finish(node: &TestNode, start: Value, assertion: Value) -> (StatusCode, Value) {
    node.req(
        Method::POST,
        "/api/v1/auth/webauthn/login/finish",
        None,
        Some(json!({ "challenge_id": start["challenge_id"], "response": assertion, "device_name": "Handy" })),
    )
    .await
}

fn preauth(json: &Value) -> String {
    json["preauth_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn registration_requires_enrollment_before_the_account_is_usable() {
    let node = test_node("t.local").await;
    let (s, reg) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": password("alice") })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{reg}");
    assert_eq!(reg["status"], "enrollment_required");
    assert_eq!(reg["methods"], json!(["totp", "webauthn"]));
    assert_eq!(reg["expires_in"], 600);
    assert!(reg.get("access_token").is_none() && reg.get("refresh_token").is_none());
    let pre = preauth(&reg);

    // A pre-auth token opens no normal route.
    for path in ["/api/v1/users/me", "/api/v1/rooms", "/api/v1/users/me/devices", "/api/v1/auth/factors"] {
        let (s, j) = node.get_auth(path, &pre).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}: {j}");
        assert_eq!(j["code"], "auth.second_factor_required", "{path}");
    }
    let (s, j) = node.post("/api/v1/rooms", &pre, json!({ "name": "x" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")));

    // Enrollment: secret, otpauth URL; a wrong code does not activate it.
    let (s, enroll) = node.post("/api/v1/auth/totp/enroll", &pre, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{enroll}");
    assert_eq!(enroll["issuer"], "t.local");
    let url = enroll["otpauth_url"].as_str().unwrap();
    assert!(url.starts_with("otpauth://totp/"), "{url}");
    assert!(url.contains(enroll["secret"].as_str().unwrap()), "{url}");
    let secret = common::totp_secret(enroll["secret"].as_str().unwrap());
    assert_eq!(secret.len(), 20, "160-bit secret");
    let wrong = if totp_code(&secret, now_secs()) == "000000" { "111111" } else { "000000" };
    let (s, j) = node.post("/api/v1/auth/totp/confirm", &pre, json!({ "code": wrong })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_invalid")), "{j}");
    let (s, j) = node.post("/api/v1/auth/totp/confirm", &pre, json!({ "code": "12ab56" })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");

    let (s, confirmed) =
        node.post("/api/v1/auth/totp/confirm", &pre, json!({ "code": totp_code(&secret, now_secs()) })).await;
    assert_eq!(s, StatusCode::OK, "{confirmed}");
    let codes = confirmed["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    let session = &confirmed["session"];
    assert_eq!(session["status"], "ok");
    let token = session["access_token"].as_str().unwrap();
    let (s, me) = node.get_auth("/api/v1/users/me", token).await;
    assert_eq!(s, StatusCode::OK, "{me}");
    assert_eq!(me["address"], "alice@t.local");
    let (s, devices) = node.get_auth("/api/v1/users/me/devices", token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(devices.as_array().unwrap().len(), 1, "the device is only created with the session");

    // The pre-auth token is spent.
    let (s, j) = node.post("/api/v1/auth/totp/enroll", &pre, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");

    let (s, factors) = node.get_auth("/api/v1/auth/factors", token).await;
    assert_eq!(s, StatusCode::OK, "{factors}");
    assert_eq!(factors, json!({ "totp": true, "webauthn": [], "recovery_codes_left": 10 }));

    // A second TOTP enrollment over a confirmed one is refused (remove it first).
    let (s, j) = node.post("/api/v1/auth/totp/enroll", token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("auth.totp_exists")), "{j}");
}

#[tokio::test]
async fn accounts_without_factor_land_in_enrollment_at_login() {
    let node = test_node("t.local").await;
    node.register_preauth("alice").await;
    let pre = node.login_preauth("alice", &password("alice")).await;
    assert_eq!(pre["status"], "enrollment_required");
    assert_eq!(pre["methods"], json!(["totp", "webauthn"]));
    // The verify route does not accept an enrollment token.
    let (s, j) = verify(&node, json!({ "preauth_token": preauth(&pre), "totp_code": "123456" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");
    // Wrong password: no pre-auth token, generic error.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "wrong-wrong-wrong" })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")));
    assert!(j.get("preauth_token").is_none());
}

#[tokio::test]
async fn login_needs_the_second_factor_and_refuses_replayed_codes() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let pre = node.login_preauth("alice", &password("alice")).await;
    assert_eq!(pre["status"], "second_factor_required");
    assert_eq!(pre["methods"], json!(["totp", "recovery_code"]));
    assert!(pre.get("access_token").is_none());
    let (s, j) = node.get_auth("/api/v1/users/me", &preauth(&pre)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")));

    // A code from long ago (outside ±1 step) and garbage are refused with the generic error.
    for code in [totp_code(&alice.totp_secret, now_secs() - 300), "abcdef".into(), "".into(), "1".repeat(100)] {
        let (s, j) = verify(&node, json!({ "preauth_token": preauth(&pre), "totp_code": code })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_invalid")), "{j}");
    }
    let (s, j) = verify(&node, json!({ "preauth_token": preauth(&pre) })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("auth.second_factor_missing")), "{j}");

    // A fresh code (the next step; the current one was used at enrollment) gives a session.
    let next = totp_code(&alice.totp_secret, now_secs() + 30);
    let (s, ok) = verify(&node, json!({ "preauth_token": preauth(&pre), "totp_code": next })).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["status"], "ok");
    assert_eq!(ok["recovery_code_used"], false);
    assert_ne!(ok["device_id"], alice.device_id.as_str(), "new device");
    let (s, _) = node.get_auth("/api/v1/users/me", ok["access_token"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK);

    // The pre-auth token is single use, even with another valid factor.
    let (s, j) =
        verify(&node, json!({ "preauth_token": preauth(&pre), "recovery_code": alice.recovery_codes[0] })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");

    // Replay: the same code in a second login is refused, and so is the older one.
    let pre2 = node.login_preauth("alice", &password("alice")).await;
    let (s, j) = verify(&node, json!({ "preauth_token": preauth(&pre2), "totp_code": next })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_invalid")), "{j}");
    let current = totp_code(&alice.totp_secret, now_secs());
    let (s, _) = verify(&node, json!({ "preauth_token": preauth(&pre2), "totp_code": current })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_expired_and_foreign_tokens_are_refused() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    let code = totp_code(&alice.totp_secret, now_secs() + 30);

    // A session token is no pre-auth token and vice versa.
    let (s, j) = verify(&node, json!({ "preauth_token": alice.token, "totp_code": code })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");
    let mut tampered = pre.clone();
    tampered.replace_range(tampered.len() - 4.., "AAAA");
    let (s, j) = verify(&node, json!({ "preauth_token": tampered, "totp_code": code })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");

    // Expired (signed with the node key, so only the expiry is wrong).
    let key = node.state.signing_key();
    let now = tavrn_node::jwt::now_unix();
    let claims = json!({ "iss": "t.local", "aud": "t.local", "sub": alice.user_id, "iat": now - 700, "exp": now - 100,
        "jti": "01J0000000000000000000000Z", "typ": "preauth", "stage": "verify", "dn": "x" });
    let expired = tavrn_node::jwt::sign(&key.signing, &key.kid, &claims).unwrap();
    let (s, j) = verify(&node, json!({ "preauth_token": expired, "totp_code": code })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");
    let (s, j) = node.get_auth("/api/v1/users/me", &expired).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");

    // Bob's code does not complete Alice's login (wrong user).
    let bob = node.register("bob").await;
    let bob_code = totp_code(&bob.totp_secret, now_secs() + 30);
    let (s, _) = verify(&node, json!({ "preauth_token": pre, "totp_code": bob_code })).await;
    if bob_code != code {
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    // A verify-stage token cannot enroll a new factor (only the password is known).
    for path in ["/api/v1/auth/totp/enroll", "/api/v1/auth/webauthn/register/start", "/api/v1/auth/totp/confirm"] {
        let (s, j) = node.post(path, &pre, json!({ "code": "123456" })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_required")), "{path}");
    }
}

#[tokio::test]
async fn an_outdated_enrollment_token_cannot_add_a_second_factor() {
    // Attacker and owner both know the password of an account without factor. Once the owner has
    // enrolled, the attacker's enrollment token is worthless.
    let node = test_node("t.local").await;
    let owner = node.register_preauth("alice").await;
    let attacker = preauth(&node.login_preauth("alice", &password("alice")).await);
    node.enroll_totp(&owner).await;
    let (s, j) = node.post("/api/v1/auth/totp/enroll", &attacker, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");
    let (s, j) = node.post("/api/v1/auth/webauthn/register/start", &attacker, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");
}

#[tokio::test]
async fn second_factor_attempts_are_rate_limited_per_account_and_ip() {
    let mut node = test_node("t.local").await;
    let cluster = node.state.cluster.clone();
    node.state.second_factor_user_limiter =
        Arc::new(SharedLimiter::new("2fa-user", 5, Duration::from_secs(300), &cluster));
    node.state.second_factor_ip_limiter =
        Arc::new(SharedLimiter::new("2fa-ip", 20, Duration::from_secs(300), &cluster));
    node.router = tavrn_node::app::router(node.state.clone());
    let alice = node.register("alice").await; // the enrollment counts as one attempt
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    for _ in 0..4 {
        let (s, _) = verify(&node, json!({ "preauth_token": pre, "totp_code": "000000" })).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    // Brute force is cut off: even the right code is refused now.
    let good = totp_code(&alice.totp_secret, now_secs() + 30);
    let (s, j) = verify(&node, json!({ "preauth_token": pre, "totp_code": good })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    let (s, _) = verify(&node, json!({ "preauth_token": pre, "recovery_code": alice.recovery_codes[0] })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "recovery codes too");

    // Per IP: many accounts from one address (all test requests share the IP "unknown").
    node.state.second_factor_user_limiter =
        Arc::new(SharedLimiter::new("2fa-user", 1000, Duration::from_secs(300), &node.state.cluster));
    node.router = tavrn_node::app::router(node.state.clone());
    let bob = node.register("bob").await;
    let pre = preauth(&node.login_preauth("bob", &password("bob")).await);
    let mut limited = false;
    for _ in 0..25 {
        let (s, _) = verify(&node, json!({ "preauth_token": pre, "totp_code": "000000" })).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "IP limit applies");
    drop(bob);
}

#[tokio::test]
async fn recovery_codes_work_once_can_be_regenerated_and_are_audited() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let code = alice.recovery_codes[3].clone();
    assert_eq!(code.len(), 14, "format xxxx-xxxx-xxxx: {code}");
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    let sloppy = format!(" {} ", code.to_uppercase().replace('-', " "));
    let (s, ok) = verify(&node, json!({ "preauth_token": pre, "recovery_code": sloppy })).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["recovery_code_used"], true);
    let token = ok["access_token"].as_str().unwrap().to_string();
    let (_, factors) = node.get_auth("/api/v1/auth/factors", &token).await;
    assert_eq!(factors["recovery_codes_left"], 9);

    // Single use; unknown codes fail generically.
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    for c in [code.as_str(), "aaaa-bbbb-cccc", "x", ""] {
        let (s, j) = verify(&node, json!({ "preauth_token": pre, "recovery_code": c })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.second_factor_invalid")), "{c}");
    }

    // Regenerate: needs the password, invalidates the old set.
    let (s, j) =
        node.post("/api/v1/auth/recovery-codes/regenerate", &token, json!({ "password": "wrong-12345" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")), "{j}");
    let (s, fresh) =
        node.post("/api/v1/auth/recovery-codes/regenerate", &token, json!({ "password": password("alice") })).await;
    assert_eq!(s, StatusCode::OK, "{fresh}");
    let fresh: Vec<String> =
        fresh["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(fresh.len(), 10);
    let (s, _) = verify(&node, json!({ "preauth_token": pre, "recovery_code": alice.recovery_codes[0] })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old set invalid");
    let (s, _) = verify(&node, json!({ "preauth_token": pre, "recovery_code": fresh[0] })).await;
    assert_eq!(s, StatusCode::OK);

    let (s, j) =
        node.post("/api/v1/auth/recovery-codes/regenerate", &pre, json!({ "password": password("alice") })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "only with a full session: {j}");

    let actions = audit_actions(&node, &token).await;
    for action in ["user.second_factor_enroll", "user.recovery_code_used", "user.recovery_codes_regenerate"] {
        assert!(actions.iter().any(|a| a == action), "{action} missing in {actions:?}");
    }
}

#[tokio::test]
async fn removing_totp_needs_proof_and_never_the_last_factor() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, j) = node.req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({}))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("auth.proof_required")), "{j}");
    let (s, j) = node
        .req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({ "password": "wrong-12345" })))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")), "{j}");
    let (s, j) = node
        .req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({ "password": password("alice") })))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("auth.last_factor")), "{j}");

    // With a passkey as second factor TOTP can go (proved with a current code).
    let mut key = Authenticator::new();
    node.add_passkey(&alice.token, &mut key, "Laptop").await;
    let code = totp_code(&alice.totp_secret, now_secs() + 30);
    let (s, j) = node.req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({ "code": code }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, factors) = node.get_auth("/api/v1/auth/factors", &alice.token).await;
    assert_eq!(factors["totp"], false);
    let (s, j) = node
        .req(Method::DELETE, "/api/v1/auth/totp", Some(&alice.token), Some(json!({ "password": password("alice") })))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("auth.totp_not_found")), "{j}");

    // Now the passkey is the last factor.
    let pre = node.login_preauth("alice", &password("alice")).await;
    assert_eq!(pre["methods"], json!(["webauthn", "recovery_code"]));
    let id = factors["webauthn"][0]["id"].as_str().unwrap().to_string();
    let (s, j) = node.delete(&format!("/api/v1/auth/webauthn/credentials/{id}"), &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("auth.last_factor")), "{j}");
    let actions = audit_actions(&node, &alice.token).await;
    assert!(actions.iter().any(|a| a == "user.second_factor_remove"), "{actions:?}");
}

#[tokio::test]
async fn several_passkeys_with_names_login_with_either_and_delete_one() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;

    let (s, start) = node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let pk = &start["options"]["publicKey"];
    assert_eq!(pk["rp"]["id"], "t.local");
    assert_eq!(pk["user"]["name"], "alice@t.local");
    assert_eq!(pk["attestation"], "none");
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert!(pk["extensions"]["prf"].is_object(), "PRF requested: {pk}");

    let mut windows = Authenticator::new();
    let mut usb = Authenticator::new();
    let first = node.add_passkey(&alice.token, &mut windows, "Windows Hello").await;
    assert_eq!(first["credential"]["name"], "Windows Hello");
    assert_eq!(first["credential"]["prf_supported"], false);
    assert!(first["credential"]["last_used_at"].is_null());
    assert!(first["recovery_codes"].is_null(), "codes already exist (TOTP)");
    assert!(first["session"].is_null(), "the full session stays");
    let second = node.add_passkey(&alice.token, &mut usb, "  USB key ").await;
    assert_eq!(second["credential"]["name"], "USB key");

    let (s, list) = node.get_auth("/api/v1/auth/webauthn/credentials", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    let names: Vec<&str> = list.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Windows Hello", "USB key"]);
    for c in list.as_array().unwrap() {
        assert!(c["id"].is_string() && c["created_at"].is_string() && c.get("prf_supported").is_some(), "{c}");
    }

    // Login with either credential.
    for key in [&mut windows, &mut usb] {
        let pre = node.login_preauth("alice", &password("alice")).await;
        assert_eq!(pre["methods"], json!(["totp", "webauthn", "recovery_code"]));
        let (s, ok) = node.passkey_second_factor(&preauth(&pre), key).await;
        assert_eq!(s, StatusCode::OK, "{ok}");
        assert_eq!(ok["status"], "ok");
        let (s, _) = node.get_auth("/api/v1/users/me", ok["access_token"].as_str().unwrap()).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (_, list) = node.get_auth("/api/v1/auth/webauthn/credentials", &alice.token).await;
    assert!(list[0]["last_used_at"].is_string() && list[1]["last_used_at"].is_string(), "{list}");

    // Delete one; it no longer works, the other does.
    let usb_id = second["credential"]["id"].as_str().unwrap();
    let (s, j) = node.delete(&format!("/api/v1/auth/webauthn/credentials/{usb_id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, j) = node.delete(&format!("/api/v1/auth/webauthn/credentials/{usb_id}"), &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("webauthn.not_found")));
    let pre = node.login_preauth("alice", &password("alice")).await;
    let (s, start) = node
        .req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({ "preauth_token": preauth(&pre) })))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(start["options"]["publicKey"]["allowCredentials"].as_array().unwrap().len(), 1);
    let (s, _) = node.passkey_second_factor(&preauth(&pre), &mut windows).await;
    assert_eq!(s, StatusCode::OK);

    // Another user cannot see or delete Alice's credentials.
    let bob = node.register("bob").await;
    let win_id = first["credential"]["id"].as_str().unwrap();
    let (s, _) = node.delete(&format!("/api/v1/auth/webauthn/credentials/{win_id}"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = node.get_auth("/api/v1/auth/webauthn/credentials", &bob.token).await;
    assert!(list.as_array().unwrap().is_empty());
    let actions = audit_actions(&node, &alice.token).await;
    assert!(actions.iter().filter(|a| *a == "user.second_factor_enroll").count() >= 3, "{actions:?}");
}

#[tokio::test]
async fn passkey_names_are_validated_and_capped_at_ten() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let mut key = Authenticator::new();
    for (name, code) in [
        ("", "validation.length"),
        ("   ", "validation.length"),
        (&*"x".repeat(65), "validation.length"),
        ("a\nb", "validation.multiline"),
        ("a\u{0}b", "validation.control_chars"),
    ] {
        let (s, j) = node.try_add_passkey(&alice.token, &mut key, name, |_| {}).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{name:?}: {j}");
    }
    node.add_passkey(&alice.token, &mut key, &"x".repeat(64)).await;
    for i in 2..=10 {
        node.add_passkey(&alice.token, &mut key, &format!("Key {i}")).await;
    }
    let (s, j) = node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("webauthn.limit")), "{j}");
    let (_, list) = node.get_auth("/api/v1/auth/webauthn/credentials", &alice.token).await;
    assert_eq!(list.as_array().unwrap().len(), 10);
}

#[tokio::test]
async fn passkey_as_first_factor_at_registration() {
    let node = test_node("t.local").await;
    let pre = node.register_preauth("alice").await;
    let mut key = Authenticator::new();
    let finish = node.add_passkey(&pre, &mut key, "Handy").await;
    assert_eq!(finish["recovery_codes"].as_array().unwrap().len(), 10);
    let token = finish["session"]["access_token"].as_str().unwrap();
    let (s, _) = node.get_auth("/api/v1/users/me", token).await;
    assert_eq!(s, StatusCode::OK);
    let pre = node.login_preauth("alice", &password("alice")).await;
    assert_eq!(pre["status"], "second_factor_required");
    assert_eq!(pre["methods"], json!(["webauthn", "recovery_code"]));
    let (s, ok) = node.passkey_second_factor(&preauth(&pre), &mut key).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
}

#[tokio::test]
async fn webauthn_ceremonies_resist_replay_phishing_and_cloned_authenticators() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let mut key = Authenticator::new();

    // Challenges are single use and bound to the user who started them.
    let (_, start) = node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await;
    let credential = key.register(&start["options"]);
    let finish = json!({ "challenge_id": start["challenge_id"], "name": "Laptop", "response": credential });
    let (s, j) = node.post("/api/v1/auth/webauthn/register/finish", &bob.token, finish.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.challenge_invalid")), "{j}");
    // Any attempt consumes the challenge, also a failed one.
    let (s, j) = node.post("/api/v1/auth/webauthn/register/finish", &alice.token, finish).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.challenge_invalid")), "{j}");
    let (_, start) = node.post("/api/v1/auth/webauthn/register/start", &alice.token, json!({})).await;
    let credential = key.register(&start["options"]);
    let finish = json!({ "challenge_id": start["challenge_id"], "name": "Laptop", "response": credential });
    let (s, j) = node.post("/api/v1/auth/webauthn/register/finish", &alice.token, finish.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.post("/api/v1/auth/webauthn/register/finish", &alice.token, finish).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.challenge_invalid")), "{j}");
    let (s, j) = node
        .post(
            "/api/v1/auth/webauthn/register/finish",
            &alice.token,
            json!({ "challenge_id": "01J0000000000000000000000Z", "name": "x", "response": {} }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    // A ceremony on another origin (a subdomain the browser would allow for this rp id) fails.
    let mut phished = Authenticator::with_origin("https://evil.t.local");
    let (s, j) = node.try_add_passkey(&alice.token, &mut phished, "Phish", |_| {}).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.registration_failed")), "{j}");

    // Second factor: an assertion is bound to its challenge and the pre-auth token's user.
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    let (_, start) =
        node.req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({ "preauth_token": pre }))).await;
    let assertion = key.authenticate(&start["options"]);
    let bob_pre = preauth(&node.login_preauth("bob", &password("bob")).await);
    let body =
        |token: &str| json!({ "challenge_id": start["challenge_id"], "response": assertion, "preauth_token": token });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/webauthn/login/finish", None, Some(body(&bob_pre))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.challenge_invalid")), "{j}");
    // The failed attempt consumed the challenge: replaying the assertion does not work either.
    let (s, j) = node.req(Method::POST, "/api/v1/auth/webauthn/login/finish", None, Some(body(&pre))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.challenge_invalid")), "{j}");
    // An invalid pre-auth token gets no challenge.
    let (s, j) = node
        .req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({ "preauth_token": "x.y.z" })))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.preauth_invalid")), "{j}");

    // Cloned authenticator: the stored counter is ahead of the one the key presents.
    let (s, ok) = node.passkey_second_factor(&pre, &mut key).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    let rows =
        sqlx::query("SELECT credential_id, passkey FROM webauthn_credentials").fetch_all(&node.state.db).await.unwrap();
    for row in rows {
        use sqlx::Row;
        let id: String = row.get("credential_id");
        let mut passkey: Value = serde_json::from_str(&row.get::<String, _>("passkey")).unwrap();
        passkey["cred"]["counter"] = json!(1000);
        sqlx::query("UPDATE webauthn_credentials SET passkey = $1 WHERE credential_id = $2")
            .bind(passkey.to_string())
            .bind(id)
            .execute(&node.state.db)
            .await
            .unwrap();
    }
    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    let (s, j) = node.passkey_second_factor(&pre, &mut key).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("webauthn.counter_mismatch")), "{j}");
    let actions = audit_actions(&node, &alice.token).await;
    assert!(actions.iter().any(|a| a == "user.webauthn_counter_mismatch"), "{actions:?}");
}

#[tokio::test]
async fn passkey_only_login_requires_user_verification_and_the_right_user() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let mut key = Authenticator::new();
    let cred = node.add_passkey(&alice.token, &mut key, "Handy").await;
    let cred_id = cred["credential"]["id"].as_str().unwrap().to_string();

    let s1 = discoverable_start(&node).await;
    assert!(s1["options"]["publicKey"]["allowCredentials"].as_array().is_none_or(|a| a.is_empty()), "{s1}");
    assert_eq!(s1["options"]["publicKey"]["userVerification"], "required");
    assert!(s1["options"].get("mediation").is_none(), "the client decides on conditional UI");

    // Assertion without user verification (presence only): refused.
    let a = key.authenticate_discoverable(&s1["options"], &cred_id, Some(&user_handle(&alice.user_id)), false);
    let (s, j) = discoverable_finish(&node, s1, a).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");

    // Wrong user handle (Bob's) or none: refused.
    let s2 = discoverable_start(&node).await;
    let a = key.authenticate_discoverable(&s2["options"], &cred_id, Some(&user_handle(&bob.user_id)), true);
    let (s, j) = discoverable_finish(&node, s2, a).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    let s3 = discoverable_start(&node).await;
    let a = key.authenticate_discoverable(&s3["options"], &cred_id, None, true);
    let (s, j) = discoverable_finish(&node, s3, a).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");

    // Correct: session tokens directly, no password involved.
    let s4 = discoverable_start(&node).await;
    let a = key.authenticate_discoverable(&s4["options"], &cred_id, Some(&user_handle(&alice.user_id)), true);
    let (s, ok) = discoverable_finish(&node, s4, a).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["status"], "ok");
    assert_eq!(ok["user"]["address"], "alice@t.local");
    let (_, devices) = node.get_auth("/api/v1/users/me/devices", ok["access_token"].as_str().unwrap()).await;
    assert!(devices.as_array().unwrap().iter().any(|d| d["name"] == "Handy"), "{devices}");

    // Disabled accounts cannot log in with a passkey either.
    let mut bob_key = Authenticator::new();
    let bob_cred = node.add_passkey(&bob.token, &mut bob_key, "Bob's phone").await;
    let (s, j) =
        node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &alice.token, json!({ "disabled": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let s5 = discoverable_start(&node).await;
    let bob_id = bob_cred["credential"]["id"].as_str().unwrap();
    let a = bob_key.authenticate_discoverable(&s5["options"], bob_id, Some(&user_handle(&bob.user_id)), true);
    let (s, j) = discoverable_finish(&node, s5, a).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.account_disabled")), "{j}");
}

#[tokio::test]
async fn webauthn_requests_are_size_limited_and_prf_outputs_are_refused() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let huge = "A".repeat(200 * 1024);
    let (s, j) = node
        .post(
            "/api/v1/auth/webauthn/register/finish",
            &alice.token,
            json!({ "challenge_id": "x", "name": "x", "response": { "id": huge } }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("request.too_large")), "{j}");
    let (s, j) =
        node.req(Method::POST, "/api/v1/auth/webauthn/login/finish", None, Some(json!({ "challenge_id": huge }))).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");

    // A client that forwards the PRF result would hand the wrapping key to the node: refused loudly.
    let mut key = Authenticator::new();
    let (s, j) = node
        .try_add_passkey(&alice.token, &mut key, "Laptop", |c| {
            c.as_object_mut().unwrap().remove("extensions");
            c["clientExtensionResults"] = json!({ "prf": { "enabled": true, "results": { "first": "AAAA" } } });
        })
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.prf_output_sent")), "{j}");
    let (s, j) = node
        .try_add_passkey(&alice.token, &mut key, "Laptop", |c| {
            c.as_object_mut().unwrap().remove("extensions");
            c["clientExtensionResults"] = json!({ "prf": { "enabled": true } });
        })
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["credential"]["prf_supported"], true);

    let pre = preauth(&node.login_preauth("alice", &password("alice")).await);
    let (_, start) =
        node.req(Method::POST, "/api/v1/auth/webauthn/login/start", None, Some(json!({ "preauth_token": pre }))).await;
    assert_eq!(
        start["options"]["publicKey"]["extensions"]["prf"]["eval"]["first"],
        tavrn_crypto::util::b64url_encode(tavrn_crypto::secret_storage::PRF_INPUT)
    );
    let mut assertion = key.authenticate(&start["options"]);
    assertion["clientExtensionResults"] = json!({ "prf": { "results": { "first": "AAAA" } } });
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/webauthn/login/finish",
            None,
            Some(json!({ "challenge_id": start["challenge_id"], "response": assertion, "preauth_token": pre })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webauthn.prf_output_sent")), "{j}");
}

#[tokio::test]
async fn node_admin_resets_a_locked_out_users_second_factor() {
    use tavrn_crypto::{
        MasterSecret, RecoveryKey,
        secret_storage::{METHOD_RECOVERY, unwrap_master_secret, wrap_master_secret},
    };
    let node = test_node("t.local").await;
    let admin = node.register("admin").await; // first account = node admin
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;

    // Bob has TOTP, a PRF passkey with a secret storage entry and a recovery entry.
    let mut key = Authenticator::new();
    let (s, j) = node
        .try_add_passkey(&bob.token, &mut key, "Handy", |c| {
            c.as_object_mut().unwrap().remove("extensions");
            c["clientExtensionResults"] = json!({ "prf": { "enabled": true } });
        })
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let cred_id = j["credential"]["id"].as_str().unwrap().to_string();
    let master = MasterSecret::generate().unwrap();
    let recovery = RecoveryKey::generate().unwrap();
    let b64 = tavrn_crypto::util::b64url_encode;
    let entry = wrap_master_secret(&master, &recovery.wrapping_key(), "bob@t.local", METHOD_RECOVERY).unwrap();
    let (s, _) = node
        .put("/api/v1/users/me/secret-storage/recovery", &bob.token, json!({ "wrapped": b64(&entry), "params": {} }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let pk = tavrn_crypto::secret_storage::passkey_wrapping_key(&[1u8; 32]).unwrap();
    let pk_entry = wrap_master_secret(&master, &pk, "bob@t.local", &format!("passkey:{cred_id}")).unwrap();
    let (s, _) = node
        .put(
            &format!("/api/v1/users/me/secret-storage/passkey/{cred_id}"),
            &bob.token,
            json!({ "wrapped": b64(&pk_entry), "params": {} }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let path = |id: &str| format!("/api/v1/admin/users/{id}/second-factor/reset");
    // Not for normal users, not for the admin's own account, not for unknown users.
    let (s, j) = node.post(&path(&bob.user_id), &carol.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")), "{j}");
    let (s, j) = node.post(&path(&admin.user_id), &admin.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("admin.second_factor_self")), "{j}");
    let (s, j) = node.post(&path("01J0000000000000000000000Z"), &admin.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("user.not_found")), "{j}");
    let pre = node.login_preauth("bob", &password("bob")).await;
    let (s, _) = node.post(&path(&bob.user_id), pre["preauth_token"].as_str().unwrap(), json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "pre-auth token is no admin session");

    let (s, j) = node.post(&path(&bob.user_id), &admin.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // All sessions are gone: the refresh token no longer works.
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": bob.refresh }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Old factors are useless, the next login lands in enrollment.
    let pre = node.login_preauth("bob", &password("bob")).await;
    assert_eq!(pre["status"], "enrollment_required");
    let pre = pre["preauth_token"].as_str().unwrap().to_string();
    let (s, _) = verify(&node, json!({ "preauth_token": pre, "recovery_code": bob.recovery_codes[0] })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Bob enrolls again and still unlocks his master secret with the recovery key.
    let (_, confirmed) = node.enroll_totp(&pre).await;
    assert_eq!(confirmed["recovery_codes"].as_array().unwrap().len(), 10, "new codes");
    let token = confirmed["session"]["access_token"].as_str().unwrap();
    let (_, factors) = node.get_auth("/api/v1/auth/factors", token).await;
    assert_eq!(factors["webauthn"], json!([]));
    let (_, list) = node.get_auth("/api/v1/users/me/secret-storage", token).await;
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the recovery entry is left: {list}");
    assert_eq!(items[0]["method"], "recovery");
    let wrapped = tavrn_crypto::util::b64url_decode(items[0]["wrapped"].as_str().unwrap()).unwrap();
    let out = unwrap_master_secret(&wrapped, &recovery.wrapping_key(), "bob@t.local", METHOD_RECOVERY).unwrap();
    assert_eq!(*out.to_bytes(), *master.to_bytes());

    let actions = audit_actions(&node, &admin.token).await;
    assert!(actions.iter().any(|a| a == "admin.second_factor_reset"), "{actions:?}");
    let (_, log) = node.get_auth("/api/v1/admin/audit-log?limit=200", &admin.token).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "admin.second_factor_reset").unwrap();
    assert_eq!(entry["meta"]["admin_id"], admin.user_id.as_str(), "{entry}");
    drop(carol);
}
