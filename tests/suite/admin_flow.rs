// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{Method, StatusCode};
use common::{test_node, test_node_with};
use serde_json::{Value, json};

#[tokio::test]
async fn admin_routes_require_node_admin() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    for path in [
        "/api/v1/admin/overview",
        "/api/v1/admin/users",
        "/api/v1/admin/invites",
        "/api/v1/admin/bans",
        "/api/v1/admin/audit-log",
    ] {
        let (s, j) = node.get_auth(path, &bob.token).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{path}: {j}");
        assert_eq!(j["code"], "auth.node_admin_required");
        let (s, _) = node.get_auth(path, &admin.token).await;
        assert_eq!(s, StatusCode::OK, "{path}");
    }
    let (_, overview) = node.get_auth("/api/v1/admin/overview", &admin.token).await;
    assert_eq!(overview["users"], 2);
    assert_eq!(overview["domain"], "t.local");
    assert_eq!(overview["smtp_enabled"], false);
}

#[tokio::test]
async fn account_invites_gate_registration() {
    let node = test_node_with("t.local", |c| c.registration = tavrn_node::config::Registration::Invite).await;
    let admin = node.register("admin").await;
    let (s, inv) = node.post("/api/v1/admin/invites", &admin.token, json!({ "note": "For Bob", "max_uses": 1 })).await;
    assert_eq!(s, StatusCode::CREATED, "{inv}");
    let code = inv["code"].as_str().unwrap().to_string();
    let (s, j) = node.req(Method::GET, &format!("/api/v1/account-invites/{code}"), None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["note"], "For Bob");

    let reg = |invite: Option<&str>, name: &str| json!({ "username": name, "date_of_birth": "1990-01-01", "password": "password-long-enough", "invite": invite });
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(reg(None, "bob"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "auth.invite_required");
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(reg(Some("wrong"), "bob"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "auth.invite_invalid");
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(reg(Some(&code), "bob"))).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(reg(Some(&code), "carol"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "used up: {j}");
    let (s, _) = node.req(Method::GET, &format!("/api/v1/account-invites/{code}"), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (_, list) = node.get_auth("/api/v1/admin/invites", &admin.token).await;
    assert_eq!(list[0]["uses"], 1);
    let (s, _) = node.delete(&format!("/api/v1/admin/invites/{code}"), &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, log) = node.get_auth("/api/v1/admin/audit-log", &admin.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"admin.invite_create") && actions.contains(&"user.register"), "{actions:?}");
}

async fn invite_uses(node: &common::TestNode, admin: &str, code: &str) -> i64 {
    let (_, list) = node.get_auth("/api/v1/admin/invites", admin).await;
    list.as_array().unwrap().iter().find(|i| i["code"] == code).unwrap()["uses"].as_i64().unwrap()
}

/// A registration that fails (missing e-mail, captcha, password, taken username, ...) must not use up the invite:
/// the invite is redeemed only together with the account, in one transaction.
#[tokio::test]
async fn failed_registration_keeps_the_invite() {
    let mut node = test_node_with("t.local", |c| {
        c.registration = tavrn_node::config::Registration::Invite;
        c.email = tavrn_node::config::EmailMode::Required;
        c.smtp_url = Some("smtp://x".into());
        c.captcha_provider = tavrn_node::config::CaptchaProvider::Turnstile;
        c.turnstile_site_key = Some("site".into());
        c.turnstile_secret_key = Some("secret".into());
        c.captcha_register = true;
    })
    .await;
    node.state.captcha = tavrn_node::captcha::CaptchaVerifier::Static { accept: "good".into() };
    node.router = tavrn_node::app::router(node.state.clone());

    // The first account bootstraps the node (no invite needed).
    let body = |name: &str, invite: Option<&str>| {
        json!({ "username": name, "date_of_birth": "1990-01-01", "password": "password-long-enough",
                "email": format!("{name}@example.org"), "captcha_token": "good", "invite": invite })
    };
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body("admin", None))).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, confirmed) = node.enroll_totp(j["preauth_token"].as_str().unwrap()).await;
    let admin = confirmed["session"]["access_token"].as_str().unwrap().to_string();
    let (s, inv) = node.post("/api/v1/admin/invites", &admin, json!({ "max_uses": 1 })).await;
    assert_eq!(s, StatusCode::CREATED, "{inv}");
    let code = inv["code"].as_str().unwrap().to_string();

    // Bob's otherwise valid registration with one field changed.
    let bob = |field: &str, value: Value| {
        let mut b = body("bob", Some(&code));
        b[field] = value;
        b
    };
    let attempts: Vec<(&str, Value, StatusCode, &str)> = vec![
        ("no e-mail", bob("email", Value::Null), StatusCode::BAD_REQUEST, "auth.email_required"),
        ("invalid e-mail", bob("email", json!("nope")), StatusCode::BAD_REQUEST, "auth.email_invalid"),
        ("no captcha", bob("captcha_token", Value::Null), StatusCode::BAD_REQUEST, "auth.captcha_required"),
        ("wrong captcha", bob("captcha_token", json!("bad")), StatusCode::BAD_REQUEST, "auth.captcha_invalid"),
        ("weak password", bob("password", json!("short")), StatusCode::BAD_REQUEST, "auth.password_weak"),
        ("bad username", body("-x-", Some(&code)), StatusCode::BAD_REQUEST, "auth.username_invalid"),
        ("no date of birth", bob("date_of_birth", Value::Null), StatusCode::BAD_REQUEST, "validation.date_of_birth"),
        ("too young", bob("date_of_birth", json!("2024-01-01")), StatusCode::FORBIDDEN, "age.below_minimum"),
        ("long display name", bob("display_name", json!("x".repeat(65))), StatusCode::BAD_REQUEST, "validation.length"),
        // The INSERT fails on the unique name: the invite use rolls back with it.
        ("taken username", body("admin", Some(&code)), StatusCode::CONFLICT, "auth.username_taken"),
    ];
    for (what, attempt, status, err) in attempts {
        let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(attempt)).await;
        assert_eq!(s, status, "{what}: {j}");
        assert_eq!(j["code"], err, "{what}");
        assert_eq!(invite_uses(&node, &admin, &code).await, 0, "{what} must not use the invite");
    }

    // The same code still works, exactly once.
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body("bob", Some(&code)))).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(invite_uses(&node, &admin, &code).await, 1);
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body("carol", Some(&code)))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "auth.invite_invalid");
    assert_eq!(invite_uses(&node, &admin, &code).await, 1);
    // An unknown code is refused the same way; neither attempt created an account.
    let (s, j) = node.req(Method::POST, "/api/v1/auth/register", None, Some(body("carol", Some("wrong")))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "auth.invite_invalid");
    let (_, overview) = node.get_auth("/api/v1/admin/overview", &admin).await;
    assert_eq!(overview["users"], 2, "{overview}");
}

#[tokio::test]
async fn admin_manages_users_bans_and_purges() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&bob.token, "Bob's room").await;
    let channel = common::TestNode::text_channel(&room);
    node.send(&bob.token, room["id"].as_str().unwrap(), &channel, "hello").await;

    let (s, users) = node.get_auth("/api/v1/admin/users?q=bo", &admin.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(users.as_array().unwrap().len(), 1);
    assert_eq!(users[0]["username"], "bob");
    assert_eq!(users[0]["disabled"], false);

    let (s, j) =
        node.patch(&format!("/api/v1/admin/users/{}", admin.user_id), &admin.token, json!({ "disabled": true })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/admin/users/{}", bob.user_id),
            &admin.token,
            json!({ "room_creation_grant": 3, "node_admin": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["room_creation_grant"], 3);
    assert_eq!(j["is_node_admin"], true);
    let (s, j) = node
        .patch(
            &format!("/api/v1/admin/users/{}", bob.user_id),
            &admin.token,
            json!({ "node_admin": false, "disabled": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["disabled"], true);
    let (s, j) = node.get_auth("/api/v1/users/me", &bob.token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    assert_eq!(j["code"], "auth.account_disabled");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "bob", "date_of_birth": "1990-01-01", "password": "password-bob-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &admin.token, json!({ "disabled": false })).await;

    // Delete everything of Bob's: preview + confirmation
    let (_, preview) = node.post(&format!("/api/v1/admin/users/{}/purge", bob.user_id), &admin.token, json!({})).await;
    // His message; his join entry in the welcome channel stays (protocol MODERATION.md §3).
    assert_eq!(preview["messages"], 1);
    let (s, done) = node
        .post(
            &format!("/api/v1/admin/users/{}/purge", bob.user_id),
            &admin.token,
            json!({ "confirm_token": preview["confirm_token"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert_eq!(done["messages"], 1);

    // Node ban: the local account is locked; a domain ban blocks joins from foreign domains (later)
    let (s, j) =
        node.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "bob@t.local", "reason": "Test" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "bob", "date_of_birth": "1990-01-01", "password": "password-bob-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, j) = node.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "t.local" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (_, bans) = node.get_auth("/api/v1/admin/bans", &admin.token).await;
    assert_eq!(bans.as_array().unwrap().len(), 1);
    let (s, _) = node.delete("/api/v1/admin/bans/bob@t.local", &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn password_reset_by_email() {
    let node = test_node_with("t.local", |c| c.smtp_url = Some("smtp://127.0.0.1:1".into())).await;
    // Without an SMTP connection sending fails but still lands in the outbox (the transport is checked only on send).
    let node = {
        let _ = node;
        test_node("t.local").await
    };
    let alice = node.register("alice").await;
    // Without a confirmed email nothing happens (always 204).
    let (s, _) =
        node.req(Method::POST, "/api/v1/auth/forgot-password", None, Some(json!({ "account": "alice" }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(node.mails().await.is_empty());

    // Set the email and mark it confirmed (registration with email + token from the outbox).
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "carol", "date_of_birth": "1990-01-01", "password": "password-long-enough", "email": "carol@example.org" })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let token = node
        .state
        .mailer
        .outbox
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .2
        .split("token=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    node.req(Method::POST, "/api/v1/auth/verify-email", None, Some(json!({ "token": token }))).await;

    let (s, _) = node
        .req(Method::POST, "/api/v1/auth/forgot-password", None, Some(json!({ "account": "Carol@Example.org" })))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Delivered after the answer (no timing difference to unknown accounts).
    let mail = node.mails().await.last().unwrap().clone();
    assert!(mail.1.contains("password"), "{}", mail.1);
    let reset = mail.2.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();

    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/reset-password",
            None,
            Some(json!({ "token": "wrong", "new_password": "new-password-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "auth.reset_invalid");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/reset-password",
            None,
            Some(json!({ "token": reset, "new_password": "new-password-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/reset-password",
            None,
            Some(json!({ "token": reset, "new_password": "another-one-123456" })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "token only once");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "carol", "date_of_birth": "1990-01-01", "password": "new-password-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let _ = alice;
}

/// Reset mails per account are limited (three per hour; the answer stays 204), and a request while a link is pending
/// keeps that link valid instead of replacing it.
#[tokio::test]
async fn password_reset_requests_keep_the_pending_link_and_are_limited_per_account() {
    let node = test_node("t.local").await;
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "dora", "date_of_birth": "1990-01-01", "password": "password-long-enough", "email": "dora@example.org" })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let user_id: String =
        sqlx::query_scalar("SELECT id FROM users WHERE username = 'dora'").fetch_one(&node.state.db).await.unwrap();
    tavrn_node::store::users::set_email_verified(&node.state.db, &user_id).await.unwrap();
    let mails = async || node.mails().await.iter().filter(|m| m.1.contains("password")).count();
    let forgot = || node.req(Method::POST, "/api/v1/auth/forgot-password", None, Some(json!({ "account": "dora" })));
    assert_eq!(forgot().await.0, StatusCode::NO_CONTENT);
    assert_eq!(mails().await, 1);
    let first = node.mails().await.last().unwrap().2.clone();
    let link = first.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
    // Further requests send nothing while the link is pending, and the link stays valid.
    for _ in 0..5 {
        assert_eq!(forgot().await.0, StatusCode::NO_CONTENT);
    }
    assert_eq!(mails().await, 1, "no new mail, the first link stays the valid one");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/reset-password",
            None,
            Some(json!({ "token": link, "new_password": "new-password-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    // Once it is used, new links come again, at most three per hour.
    for _ in 0..6 {
        assert_eq!(forgot().await.0, StatusCode::NO_CONTENT);
        sqlx::query("DELETE FROM password_resets").execute(&node.state.db).await.unwrap();
    }
    assert_eq!(mails().await, 3, "the first mail plus two more in the hour, then none");
}

/// Without SMTP a production node sends no reset link (it could only end up in the log): `503 mail.unavailable`.
#[tokio::test]
async fn forgot_password_without_smtp_is_unavailable_in_production() {
    use tower::ServiceExt;
    let node = test_node("t.local").await;
    let mut state = node.state.clone();
    let production = tavrn_node::config::Config { dev: false, ..(*state.config).clone() };
    state.mailer = tavrn_node::mail::Mailer::from_config(&production);
    let req = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/forgot-password")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json!({ "account": "x" }).to_string()))
        .unwrap();
    let resp = tavrn_node::app::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let j = common::body_json(resp).await;
    assert_eq!(j["code"], "mail.unavailable", "{j}");
}
