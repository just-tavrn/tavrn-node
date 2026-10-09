// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{Method, StatusCode};
use common::test_node;
use serde_json::json;

#[tokio::test]
async fn first_account_is_node_admin_later_ones_are_not() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (_, me) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!(me["is_node_admin"], true);
    assert_eq!(me["address"], "alice@t.local");
    assert_eq!(me["has_identity_key"], false);
    let (_, me) = node.get_auth("/api/v1/users/me", &bob.token).await;
    assert_eq!(me["is_node_admin"], false);
}

#[tokio::test]
async fn registration_validation_and_conflicts() {
    let node = test_node("t.local").await;
    node.register("alice").await;
    let cases = [
        (
            json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" }),
            StatusCode::CONFLICT,
            "auth.username_taken",
        ),
        (
            json!({ "username": "Alice Two", "date_of_birth": "1990-01-01", "password": "password-long-enough" }),
            StatusCode::BAD_REQUEST,
            "auth.username_invalid",
        ),
        (
            json!({ "username": "carol", "date_of_birth": "1990-01-01", "password": "short" }),
            StatusCode::BAD_REQUEST,
            "auth.password_weak",
        ),
        (
            json!({ "username": "carol", "date_of_birth": "1990-01-01", "password": "password-long-enough", "email": "not-an-email" }),
            StatusCode::BAD_REQUEST,
            "auth.email_invalid",
        ),
        (
            json!({ "username": "carol", "date_of_birth": "1990-01-01", "password": "password-long-enough", "display_name": "x\u{0}y" }),
            StatusCode::BAD_REQUEST,
            "validation.control_chars",
        ),
    ];
    for (body, status, code) in cases {
        let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body.clone())).await;
        assert_eq!(s, status, "{body}: {j}");
        assert_eq!(j["code"], code, "{body}");
    }
    // Case-insensitive: ALICE is alice.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "ALICE", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
}

#[tokio::test]
async fn registration_modes() {
    let closed = common::test_node_with("t.local", |c| c.registration = tavrn_node::config::Registration::Closed).await;
    let (s, j) = closed
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "auth.registration_closed");

    let invite = common::test_node_with("t.local", |c| c.registration = tavrn_node::config::Registration::Invite).await;
    invite.register("admin").await; // the first account may always register
    let (s, j) = invite
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "bob", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "auth.invite_required");
}

#[tokio::test]
async fn email_required_mode_needs_verification_before_login() {
    let node = common::test_node_with("t.local", |c| {
        c.email = tavrn_node::config::EmailMode::Required;
        c.smtp_url = Some("smtp://x".into());
    })
    .await;
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "auth.email_required");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough", "email": "Alice@Example.org" })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "auth.email_unverified");

    // Redeem the token from the (logged) mail.
    let outbox = node.state.mailer.outbox.lock().unwrap().clone();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].0, "alice@example.org");
    let token = outbox[0].2.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    let (s, _) = node.req(Method::POST, "/api/v1/auth/verify-email", None, Some(json!({ "token": token }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.req(Method::POST, "/api/v1/auth/verify-email", None, Some(json!({ "token": token }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "token can be redeemed only once");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Verified, so the password step passes; the account has no second factor yet.
    assert_eq!(j["status"], "enrollment_required");
}

#[tokio::test]
async fn login_success_failure_and_rate_limit() {
    let node = test_node("t.local").await;
    node.register("alice").await;
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(
                json!({ "username": "alice@t.local", "date_of_birth": "1990-01-01", "password": "password-alice-123" }),
            ),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["status"], "second_factor_required");
    assert!(j["preauth_token"].is_string());
    assert!(j.get("access_token").is_none(), "session only after the second factor");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "wrong-wrong-wrong" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j["code"], "auth.invalid_credentials");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "nobody", "date_of_birth": "1990-01-01", "password": "wrong-wrong-wrong" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "an unknown user looks identical");
    assert_eq!(j["code"], "auth.invalid_credentials");
    // Reproduce the production limit (10 attempts per minute) directly on the limiter.
    for _ in 0..1000 {
        if node.state.login_limiter.check("user:alice").await.is_err() {
            break;
        }
    }
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-alice-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert_eq!(j["code"], "rate_limited");
}

#[tokio::test]
async fn refresh_rotates_and_detects_reuse() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, first) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": alice.refresh }))).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let new_refresh = first["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, alice.refresh);
    assert_eq!(first["device_id"], alice.device_id);
    let (s, _) = node.get_auth("/api/v1/users/me", first["access_token"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK);

    // Reuse the old token after the grace period (30 s): suspected theft, the whole session is revoked.
    sqlx::query("UPDATE sessions SET rotated_at = '2020-01-01T00:00:00.000Z' WHERE device_id = $1")
        .bind(&alice.device_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": alice.refresh }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": new_refresh }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the new token is dead after the reuse too");
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": "does-not-exist" }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_refresh_and_tokens_are_checked() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, _) = node.post("/api/v1/auth/logout", &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": alice.refresh }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, j) = node.req(Method::GET, "/api/v1/users/me", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j["code"], "auth.required");
    let mut tampered = alice.token.clone();
    tampered.replace_range(tampered.len() - 4.., "AAAA");
    let (s, j) = node.get_auth("/api/v1/users/me", &tampered).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(j["code"], "auth.token_invalid");
    let (s, _) = node.get_auth("/api/v1/users/me", "not.a.jwt").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn profile_update_devices_and_public_profile() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, j) = node.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "  Alice A.  " })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["display_name"], "Alice A.");
    let (s, j) = node.get_auth("/api/v1/users/me/devices", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j.as_array().unwrap().len(), 1);
    assert_eq!(j[0]["current"], true);
    let (s, j) = node.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["display_name"], "Alice A.");
    assert!(j.get("email").is_none(), "public profile without email");
    let (s, _) = node.req(Method::GET, "/api/v1/users/nobody/profile", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn captcha_is_enforced_when_enabled() {
    let mut node = common::test_node_with("t.local", |c| {
        c.captcha_provider = tavrn_node::config::CaptchaProvider::Turnstile;
        c.turnstile_site_key = Some("site".into());
        c.turnstile_secret_key = Some("secret".into());
        c.captcha_register = true;
        c.captcha_login = true;
    })
    .await;
    node.state.captcha = tavrn_node::captcha::CaptchaVerifier::Static { accept: "good".into() };
    node.router = tavrn_node::app::router(node.state.clone());

    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["captcha"]["provider"], "turnstile");
    assert_eq!(info["captcha"]["site_key"], "site");
    assert_eq!(info["captcha"]["login"], true);

    let body = json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body.clone())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "auth.captcha_required");
    let mut with_bad = body.clone();
    with_bad["captcha_token"] = json!("wrong");
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(with_bad)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "auth.captcha_invalid");
    let mut with_good = body.clone();
    with_good["captcha_token"] = json!("good");
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(with_good)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "auth.captcha_required");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "password-long-enough", "captcha_token": "good" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn captcha_is_not_required_without_provider() {
    let node = test_node("t.local").await;
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert!(info["captcha"].is_null());
}

#[tokio::test]
async fn password_change_revokes_other_devices() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let second = node.login("alice").await;
    let second_token = second.token.clone();
    let second_refresh = second.refresh.clone();

    let (s, j) = node
        .post(
            "/api/v1/users/me/password",
            &alice.token,
            json!({ "current_password": "wrong-wrong-1", "new_password": "new-password-123" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    let (s, j) = node
        .post(
            "/api/v1/users/me/password",
            &alice.token,
            json!({ "current_password": "password-alice-123", "new_password": "short" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, _) = node
        .post(
            "/api/v1/users/me/password",
            &alice.token,
            json!({ "current_password": "password-alice-123", "new_password": "new-password-123" }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": "new-password-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": second_refresh }))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the second device is signed out");
    let (s, _) = node.get_auth("/api/v1/users/me", &second_token).await;
    assert_eq!(s, StatusCode::OK, "the access token stays valid until it expires (1 h)");

    // Remove devices
    let (_, devices) = node.get_auth("/api/v1/users/me/devices", &alice.token).await;
    let before = devices.as_array().unwrap().len();
    let other =
        devices.as_array().unwrap().iter().find(|d| d["current"] == false).unwrap()["id"].as_str().unwrap().to_string();
    let (s, j) = node.delete(&format!("/api/v1/users/me/devices/{}", alice.device_id), &alice.token).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{other}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, devices) = node.get_auth("/api/v1/users/me/devices", &alice.token).await;
    assert_eq!(devices.as_array().unwrap().len(), before - 1);
}
