// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{Method, StatusCode};
use common::{test_node, test_node_with};
use serde_json::json;

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
    assert!(node.state.mailer.outbox.lock().unwrap().is_empty());

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
    let mail = node.state.mailer.outbox.lock().unwrap().last().unwrap().clone();
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
