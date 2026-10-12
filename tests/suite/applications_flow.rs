// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 5 step 1 (protocol/APPLICATIONS.md §1–§3): applications, app tokens, scopes, the bot route table,
//! owner cascades, "no bots" zones and remote bots.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, crossnode, e2ee, federation, test_node, test_node_with};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_crypto::{Client, Device, MasterSecret};
use tavrn_node::{jwt, permissions as p, util};
use tokio_tungstenite::tungstenite::Message;

const D: &str = e2ee::DOMAIN;

/// A bot with one token.
struct Bot {
    app_id: String,
    user_id: String,
    username: String,
    token_id: String,
    device_id: String,
    secret: String,
}

impl Bot {
    fn address(&self, domain: &str) -> String {
        format!("{}@{domain}", self.username)
    }
}

async fn create_app(node: &TestNode, owner: &Session, body: Value) -> Value {
    let (s, j) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j
}

async fn create_token(node: &TestNode, owner: &Session, app_id: &str, body: Value) -> Value {
    let (s, j) = node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j
}

/// A public application named `name` (all scopes) and a token with `scopes` (`None` = all).
async fn bot(node: &TestNode, owner: &Session, name: &str, scopes: Option<&[&str]>) -> Bot {
    let app = create_app(node, owner, json!({ "name": name, "public": true })).await;
    let app_id = app["id"].as_str().unwrap().to_string();
    let body = match scopes {
        Some(s) => json!({ "name": "main", "scopes": s }),
        None => json!({ "name": "main" }),
    };
    let t = create_token(node, owner, &app_id, body).await;
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        token_id: t["token"]["id"].as_str().unwrap().into(),
        device_id: t["token"]["device_id"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
    }
}

/// A room manager installs the bot (APPLICATIONS.md §4.2) without permissions.
async fn join(node: &TestNode, installer: &Session, room_id: &str, bot: &Bot) -> (StatusCode, Value) {
    let domain = node.state.config.domain.clone();
    node.post(
        &format!("/api/v1/rooms/{room_id}/applications"),
        &installer.token,
        json!({ "application": format!("{domain}/{}", bot.app_id) }),
    )
    .await
}

async fn joined(node: &TestNode, installer: &Session, room_id: &str, bot: &Bot) {
    let (s, j) = join(node, installer, room_id, bot).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn claims(node: &TestNode, bot: &Bot, typ: &str, exp_offset: i64) -> Value {
    let n = jwt::now_unix();
    json!({
        "iss": node.state.config.domain, "aud": node.state.config.domain, "sub": bot.user_id, "typ": typ,
        "iat": n, "exp": n + exp_offset, "jti": util::ulid(), "dev": bot.device_id, "app": bot.app_id,
        "owner": "x@y", "scp": ["messages:read"],
    })
}

fn sign(node: &TestNode, claims: &Value) -> String {
    let key = node.state.signing_key();
    jwt::sign(&key.signing, &key.kid, claims).unwrap()
}

async fn sql(node: &TestNode, q: &str, arg: &str) {
    sqlx::query(q).bind(arg).execute(&node.state.db).await.unwrap();
}

// ---------------------------------------------------------------- applications

#[tokio::test]
async fn add_links_point_to_the_public_url() {
    // Delegation: the node's identity is D, its web client lives on another host.
    let node = test_node_with(D, |c| {
        c.public_url = Some("https://app.example.net".into());
        c.webauthn_rp_id = Some("example.net".into());
        c.webauthn_origin = None;
    })
    .await;
    let alice = node.register("alice").await;
    let app = create_app(&node, &alice, json!({ "name": "Linker" })).await;
    assert_eq!(app["add_link"], format!("https://app.example.net/add/{}", app["id"].as_str().unwrap()));
    assert_eq!(app["owner"], format!("alice@{D}"), "addresses keep the identity domain");
}

#[tokio::test]
async fn create_list_and_validate_applications() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;

    let app = create_app(
        &node,
        &alice,
        json!({ "name": "Weather Bot!", "description": "Forecasts", "requested_permissions": "3",
                "scopes": ["commands", "messages:read", "messages:write"] }),
    )
    .await;
    assert_eq!(app["bot"]["kind"], "bot");
    assert_eq!(app["bot"]["username"], "weather-bot");
    assert_eq!(app["bot"]["owner"], format!("alice@{D}"));
    assert_eq!(app["bot"]["application_id"], app["id"]);
    assert_eq!(app["bot"]["display_name"], "Weather Bot!");
    assert_eq!(app["owner"], format!("alice@{D}"));
    assert_eq!(app["ref"], format!("{D}/{}", app["id"].as_str().unwrap()));
    assert_eq!(app["scopes"], json!(["messages:read", "messages:write", "commands"]), "canonical order");
    assert_eq!(app["tokens"], 0);
    assert_eq!(app["public"], false);
    assert_eq!(app["add_link"], format!("{}/add/{}", node.state.config.public_url(), app["id"].as_str().unwrap()));
    let id = app["id"].as_str().unwrap();

    // Name collisions get a suffix; an explicit username must be free.
    let second = create_app(&node, &alice, json!({ "name": "Weather Bot" })).await;
    assert_eq!(second["bot"]["username"], "weather-bot-2");
    assert_eq!(second["scopes"].as_array().unwrap().len(), p::SCOPES.len(), "all scopes by default");
    let (s, j) = node.post("/api/v1/applications", &alice.token, json!({ "name": "X Y", "username": "bob" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.username_taken"));
    for (body, expected) in [
        (json!({ "name": "Admin", "requested_permissions": p::ADMINISTRATOR.to_string() }), "app.permissions_invalid"),
        (json!({ "name": "Bits", "requested_permissions": (1u64 << 40).to_string() }), "app.permissions_invalid"),
        (json!({ "name": "Scopes", "scopes": ["messages:read", "root"] }), "app.scope_invalid"),
        (json!({ "name": "x" }), "validation.length"),
        (json!({ "name": "Name", "username": "Bad Name" }), "validation.username"),
        (json!({ "name": "Long", "description": "d".repeat(401) }), "validation.length"),
    ] {
        let (s, j) = node.post("/api/v1/applications", &alice.token, body).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, expected), "{j}");
    }

    let (s, list) = node.get_auth("/api/v1/applications", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
    let (s, list) = node.get_auth("/api/v1/applications", &bob.token).await;
    assert_eq!((s, list.as_array().unwrap().len()), (StatusCode::OK, 0));
    // No oracle: somebody else's application is not found.
    let (s, j) = node.get_auth(&format!("/api/v1/applications/{id}"), &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
    let (s, j) = node.patch(&format!("/api/v1/applications/{id}"), &bob.token, json!({ "name": "Mine" })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));

    // Update: name renames the bot, scopes narrow, administrator never requested, origins checked.
    let (s, j) = node
        .patch(
            &format!("/api/v1/applications/{id}"),
            &alice.token,
            json!({ "name": "Sky", "public": true, "scopes": ["messages:read"], "rpc_origins": ["https://app.example"], "dm_policy": "friends" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["name"].as_str(), j["bot"]["display_name"].as_str()), (Some("Sky"), Some("Sky")));
    assert_eq!(j["scopes"], json!(["messages:read"]));
    assert_eq!((j["public"].as_bool(), j["dm_policy"].as_str()), (Some(true), Some("friends")));
    for (body, expected) in [
        (json!({ "requested_permissions": p::ADMINISTRATOR.to_string() }), "app.permissions_invalid"),
        (json!({ "rpc_origins": ["http://app.example"] }), "app.url_invalid"),
        (json!({ "rpc_origins": ["https://app.example/path"] }), "app.url_invalid"),
        (json!({ "scopes": ["everything"] }), "app.scope_invalid"),
    ] {
        let (s, j) = node.patch(&format!("/api/v1/applications/{id}"), &alice.token, body).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, expected), "{j}");
    }
    // Audited on the node.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action IN ('app.create', 'app.update')")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert!(n >= 3);
}

#[tokio::test]
async fn creation_modes_limits_and_rate() {
    let node = test_node_with(D, |c| {
        c.apps_per_user = 2;
        c.app_creation = tavrn_node::config::AppCreation::Invite;
    })
    .await;
    let admin = node.register("admin").await; // the first account is node admin
    let alice = node.register("alice").await;
    let (s, j) = node.post("/api/v1/applications", &alice.token, json!({ "name": "One" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.creation_forbidden"));
    let (s, j) = node
        .patch(&format!("/api/v1/admin/users/{}", alice.user_id), &admin.token, json!({ "app_creation_grant": 1 }))
        .await;
    assert_eq!((s, j["app_creation_grant"].as_i64()), (StatusCode::OK, Some(1)), "{j}");
    create_app(&node, &alice, json!({ "name": "One" })).await;
    let (s, j) = node.post("/api/v1/applications", &alice.token, json!({ "name": "Two" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.creation_forbidden"), "the grant was consumed");

    // Admins are not exempt from the limit.
    create_app(&node, &admin, json!({ "name": "A1" })).await;
    create_app(&node, &admin, json!({ "name": "A2" })).await;
    let (s, j) = node.post("/api/v1/applications", &admin.token, json!({ "name": "A3" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.limit_reached"));
    assert_eq!(j["meta"]["max"], 2);

    // `admins` mode.
    let node = test_node_with(D, |c| c.app_creation = tavrn_node::config::AppCreation::Admins).await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let (s, j) = node.post("/api/v1/applications", &bob.token, json!({ "name": "Bob's" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.creation_forbidden"));
    create_app(&node, &admin, json!({ "name": "Allowed" })).await;

    // 5 creations per day and user (deleting does not give them back).
    let node = test_node_with(D, |c| c.apps_per_user = 100).await;
    let carol = node.register("carol").await;
    for i in 0..5 {
        create_app(&node, &carol, json!({ "name": format!("Bot {i}") })).await;
    }
    let (s, _) = node.post("/api/v1/applications", &carol.token, json!({ "name": "Bot 6" })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------- tokens

#[tokio::test]
async fn tokens_are_shown_once_hashed_and_bound_to_a_device() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let app = create_app(&node, &alice, json!({ "name": "Helper", "scopes": ["messages:read", "members:read"] })).await;
    let id = app["id"].as_str().unwrap();
    let t = create_token(&node, &alice, id, json!({ "name": "prod", "expires_in_days": 30 })).await;
    let secret = t["secret"].as_str().unwrap();
    assert_eq!(t["token"]["scopes"], json!(["messages:read", "members:read"]));
    assert!(t["token"]["expires_at"].as_str().unwrap() > util::in_seconds(29 * 86_400).as_str());

    // Stored only as a hash, never as the secret.
    let (hash, stored_secret): (String, i64) = sqlx::query_as(
        "SELECT token_hash, CAST((SELECT COUNT(*) FROM application_tokens WHERE token_hash = $1) AS BIGINT) FROM application_tokens",
    )
    .bind(secret)
    .fetch_one(&node.state.db)
    .await
    .unwrap();
    assert_eq!(hash, util::sha256_b64(secret));
    assert_eq!(stored_secret, 0);
    let (s, list) = node.get_auth(&format!("/api/v1/applications/{id}/tokens"), &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert!(list[0].get("secret").is_none() && !list.to_string().contains(secret));

    // The token authenticates the bot on its device.
    let (s, me) = node.get_auth("/api/v1/users/me", secret).await;
    assert_eq!(s, StatusCode::OK, "{me}");
    assert_eq!((me["kind"].as_str(), me["owner"].as_str()), (Some("bot"), Some(format!("alice@{D}").as_str())));
    let (s, mine) = node.get_auth("/api/v1/applications/me", secret).await;
    assert_eq!(s, StatusCode::OK, "{mine}");
    assert_eq!(mine["id"], id);
    assert!(mine.get("interactions_url").is_none(), "{mine}");
    let (s, _) = node.get_auth("/api/v1/applications/me", &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "users have no application context");

    // Validation and limits.
    for (body, expected) in [
        (json!({ "name": "x", "scopes": ["voice"] }), "app.scope_invalid"),
        (json!({ "name": "x", "scopes": ["nope"] }), "app.scope_invalid"),
        (json!({ "name": "x", "expires_in_days": 366 }), "validation.range"),
        (json!({ "name": "x", "expires_in_days": 0 }), "validation.range"),
        (json!({ "name": "" }), "validation.length"),
    ] {
        let (s, j) = node.post(&format!("/api/v1/applications/{id}/tokens"), &alice.token, body).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, expected), "{j}");
    }
    for i in 0..4 {
        create_token(&node, &alice, id, json!({ "name": format!("t{i}") })).await;
    }
    let (s, j) = node.post(&format!("/api/v1/applications/{id}/tokens"), &alice.token, json!({ "name": "six" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.token_limit"));
    // Five tokens = five bot devices.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE user_id = $1")
        .bind(app["bot"]["id"].as_str().unwrap())
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 5);

    // Somebody else cannot manage them.
    let bob = node.register("bob").await;
    let (s, _) = node.get_auth(&format!("/api/v1/applications/{id}/tokens"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn token_creation_and_reset_are_rate_limited() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Busy", None).await;
    let reset = format!("/api/v1/applications/{}/tokens/{}/reset", b.app_id, b.token_id);
    for _ in 0..9 {
        let (s, j) = node.post(&reset, &alice.token, json!({})).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    let (s, _) = node.post(&reset, &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "10 creations and resets per hour and application");
}

#[tokio::test]
async fn tampered_expired_revoked_reset_and_rotated_tokens() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Guard", Some(&["messages:read"])).await;
    let node_ref = &node;
    let me = |t: String| async move { node_ref.get_auth("/api/v1/users/me", &t).await };

    // Wrong alg: an HS256/none header is refused before anything else.
    let payload = b.secret.split('.').nth(1).unwrap();
    for header in [r#"{"alg":"none","typ":"JWT","kid":"k"}"#, r#"{"alg":"HS256","typ":"JWT","kid":"k"}"#] {
        let h = base64_url(header.as_bytes());
        let (s, j) = me(format!("{h}.{payload}.x")).await;
        assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.token_invalid"));
    }
    // A forged signature.
    let mut parts: Vec<&str> = b.secret.split('.').collect();
    let other = base64_url(&[7u8; 64]);
    parts[2] = &other;
    assert_eq!(me(parts.join(".")).await.0, StatusCode::UNAUTHORIZED);
    // Session claims for a bot (even signed by the node): local bots never have sessions.
    let mut session = claims(&node, &b, "session", 600);
    session["dev"] = json!(b.device_id);
    let (s, j) = me(sign(&node, &session)).await;
    assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.token_invalid"));
    // App claims the node signed but never stored: the hash does not match any token row.
    let (s, j) = me(sign(&node, &claims(&node, &b, "app", 600))).await;
    assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.token_invalid"));
    // The stored jti with different content (more scopes) fails the hash comparison.
    let jti: String = sqlx::query_scalar("SELECT jti FROM application_tokens WHERE id = $1")
        .bind(&b.token_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    let mut wider = claims(&node, &b, "app", 600);
    wider["jti"] = json!(jti);
    wider["scp"] = json!(p::all_scopes());
    let (s, j) = me(sign(&node, &wider)).await;
    assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.token_invalid"));
    // An app token naming a user is nothing.
    let mut user = claims(&node, &b, "app", 600);
    user["sub"] = json!(alice.user_id);
    assert_eq!(me(sign(&node, &user)).await.0, StatusCode::UNAUTHORIZED);
    // Expired.
    let (s, j) = me(sign(&node, &claims(&node, &b, "app", -5))).await;
    assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.token_expired"));
    // A lifetime beyond TAVRN_APP_TOKEN_MAX_DAYS is refused even when signed.
    let (s, _) = me(sign(&node, &claims(&node, &b, "app", 400 * 86_400))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Reset: the old secret is invalid at once, the new one works on the same device.
    let (s, j) = node
        .post(&format!("/api/v1/applications/{}/tokens/{}/reset", b.app_id, b.token_id), &alice.token, json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let fresh = j["secret"].as_str().unwrap().to_string();
    assert_eq!(j["token"]["device_id"], b.device_id);
    assert_eq!(me(b.secret.clone()).await.0, StatusCode::UNAUTHORIZED, "old secret after reset");
    assert_eq!(me(fresh.clone()).await.0, StatusCode::OK);
    let (s, j) = node
        .post(&format!("/api/v1/applications/{}/tokens/{}/reset", b.app_id, util::ulid()), &alice.token, json!({}))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.token_not_found"));

    // Rotation by the bot: the previous secret stays valid for 24 hours, a second rotation is refused.
    let (s, j) = node.post("/api/v1/applications/me/tokens/rotate", &fresh, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let rotated = j["secret"].as_str().unwrap().to_string();
    assert_eq!(me(rotated.clone()).await.0, StatusCode::OK);
    assert_eq!(me(fresh.clone()).await.0, StatusCode::OK, "within 24 h");
    let (s, _) = node.post("/api/v1/applications/me/tokens/rotate", &rotated, json!({})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    // 24 hours later the previous secret is gone.
    sql(
        &node,
        "UPDATE application_tokens SET prev_valid_until = '2000-01-01T00:00:00.000Z' WHERE id = $1",
        &b.token_id,
    )
    .await;
    assert_eq!(me(fresh.clone()).await.0, StatusCode::UNAUTHORIZED, "rotated secret after 24 h");
    assert_eq!(me(rotated.clone()).await.0, StatusCode::OK);

    // Revoked: the token and its device are gone.
    let (s, _) = node.delete(&format!("/api/v1/applications/{}/tokens/{}", b.app_id, b.token_id), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(me(rotated.clone()).await.0, StatusCode::UNAUTHORIZED);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE id = $1")
        .bind(&b.device_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action IN ('app.token_create', 'app.token_reset', 'app.token_revoke')",
    )
    .fetch_one(&node.state.db)
    .await
    .unwrap();
    assert_eq!(audit, 3);
    // Look for the exact secrets the test handed out (and their signatures), compared in Rust: a pattern like
    // LIKE '%eyJ%' is case-insensitive on SQLite and matched random ULIDs in the rows (tavrn-node #18).
    let metas: Vec<String> = sqlx::query_scalar("SELECT meta FROM audit_log").fetch_all(&node.state.db).await.unwrap();
    for secret in [&b.secret, &fresh, &rotated] {
        let signature = secret.rsplit('.').next().unwrap();
        for meta in &metas {
            assert!(!meta.contains(secret.as_str()), "secrets never reach the audit log: {meta}");
            assert!(!meta.contains(signature), "token signatures never reach the audit log: {meta}");
        }
    }
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------- route table and scopes

#[tokio::test]
async fn bots_are_refused_on_never_allowed_routes() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Nosy", None).await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    joined(&node, &alice, room_id, &b).await;
    let app_path = format!("/api/v1/applications/{}", b.app_id);
    let cases: Vec<(Method, String, Value)> = vec![
        (Method::POST, "/api/v1/users/me/password".into(), json!({ "current_password": "x", "new_password": "y" })),
        (Method::POST, "/api/v1/auth/totp/enroll".into(), json!({})),
        (Method::GET, "/api/v1/auth/factors".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/secret-storage".into(), Value::Null),
        (
            Method::POST,
            "/api/v1/users/me/identity/reset".into(),
            json!({ "identity_public_key": "x", "password": "y" }),
        ),
        (Method::PATCH, "/api/v1/users/me".into(), json!({ "display_name": "Evil" })),
        (Method::DELETE, "/api/v1/users/me/avatar".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/whiteboards".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/friends".into(), Value::Null),
        (Method::POST, "/api/v1/users/me/blocks".into(), json!({ "user": "alice" })),
        (Method::GET, "/api/v1/users/me/invites".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/devices".into(), Value::Null),
        (Method::POST, "/api/v1/rooms".into(), json!({ "name": "Mine" })),
        (Method::POST, format!("/api/v1/rooms/{room_id}/join"), json!({})),
        (Method::DELETE, format!("/api/v1/rooms/{room_id}"), Value::Null),
        (Method::POST, "/api/v1/auth/connect/code".into(), json!({ "client": "x" })),
        (Method::POST, "/api/v1/directory/reports".into(), json!({})),
        (Method::POST, "/api/v1/applications".into(), json!({ "name": "Child" })),
        (Method::GET, "/api/v1/applications".into(), Value::Null),
        (Method::GET, app_path.clone(), Value::Null),
        (Method::POST, format!("{app_path}/tokens"), json!({ "name": "more" })),
        (Method::GET, "/api/v1/admin/users".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/notification-settings".into(), Value::Null),
        (Method::GET, "/api/v1/users/me/conversations-index".into(), Value::Null),
    ];
    for (m, path, body) in cases {
        let body = (!body.is_null()).then_some(body);
        let (s, j) = node.req(m.clone(), &path, Some(&b.secret), body).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{m} {path}: {j}");
    }
    // A password login with the bot's username fails like a wrong password.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": b.username, "date_of_birth": "1990-01-01", "password": "whatever-123" })),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::UNAUTHORIZED, "auth.invalid_credentials"));
    // Group DMs are refused, with or as a bot.
    let bob = node.register("bob").await;
    let (s, j) = node
        .post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": [b.username, "bob"] }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.bot_forbidden"));
    let (s, j) =
        node.post("/api/v1/conversations", &b.secret, json!({ "kind": "group", "members": ["alice", "bob"] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.bot_forbidden"));
    let _ = bob;
    // A bot that writes to its owner starts a normal conversation, not a message request.
    let helper = bot(&node, &alice, "Helper", Some(&["dms", "messages:write"])).await;
    let (s, j) =
        node.post("/api/v1/conversations", &helper.secret, json!({ "kind": "dm", "members": ["alice"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["pending"], json!([]), "{j}");
    // The owner gets a normal (accepted) DM with the bot.
    let (s, j) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": [b.username] })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let members = j["members"].as_array().unwrap();
    assert!(members.iter().any(|m| m["kind"] == "bot"));
}

#[tokio::test]
async fn every_scope_boundary_and_administrator_masking() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    // A role with administrator for the bot.
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &alice.token,
            json!({ "name": "Admins", "permissions": p::ADMINISTRATOR.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap();

    // (scope, method, path, body): a representative route of every scope with routes.
    let msg = format!("/api/v1/rooms/{room_id}/channels/{channel}/messages");
    let cases: Vec<(&str, Method, String, Option<Value>)> = vec![
        ("messages:read", Method::GET, msg.clone(), None),
        ("messages:write", Method::POST, msg.clone(), Some(json!({ "content": { "type": "text", "body": "hi" } }))),
        ("members:read", Method::GET, format!("/api/v1/rooms/{room_id}/members"), None),
        ("moderation", Method::GET, format!("/api/v1/rooms/{room_id}/audit-log"), None),
        ("rooms:manage", Method::PATCH, format!("/api/v1/rooms/{room_id}"), Some(json!({ "description": "by bot" }))),
        ("voice", Method::GET, format!("/api/v1/rooms/{room_id}/voice"), None),
        ("voice", Method::GET, "/api/v1/users/me/voice".into(), None),
        ("whiteboard", Method::GET, format!("/api/v1/conversations/{channel}/whiteboard"), None),
        ("presence", Method::GET, "/api/v1/users/me/presence".into(), None),
        ("dms", Method::POST, "/api/v1/conversations".into(), Some(json!({ "kind": "dm", "members": ["alice"] }))),
    ];
    let mut n = 0;
    for (scope, m, path, body) in &cases {
        // Without the scope: refused with meta.scope. With it: not refused for the scope.
        let others: Vec<&str> = p::SCOPES.iter().map(|(s, _)| *s).filter(|s| s != scope).collect();
        n += 1;
        // One owner per case: app creation is limited to 5 per day and user.
        let owner = node.register(&format!("owner{n}")).await;
        let without = bot(&node, &owner, &format!("Without {n}"), Some(&others)).await;
        joined(&node, &alice, &room_id, &without).await;
        let (s, j) = node.req(m.clone(), path, Some(&without.secret), body.clone()).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{scope}: {j}");
        assert_eq!(j["meta"]["scope"], *scope);
        let with = bot(&node, &owner, &format!("With {n}"), Some(&[scope])).await;
        joined(&node, &alice, &room_id, &with).await;
        node.patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", with.user_id),
            &alice.token,
            json!({ "roles": [role_id] }),
        )
        .await;
        let (s, j) = node.req(m.clone(), path, Some(&with.secret), body.clone()).await;
        assert_ne!(code(&j), "app.scope_missing", "{scope}: {j}");
        assert_ne!(code(&j), "app.bot_forbidden", "{scope}: {j}");
        assert!(
            s.is_success() || s == StatusCode::SERVICE_UNAVAILABLE || s == StatusCode::FORBIDDEN,
            "{scope}: {s} {j}"
        );
    }

    // Administrator is masked by the scopes: with messages:read only, the room permissions are BOT_ALWAYS plus
    // read_history (the one bit of that scope).
    let reader = bot(&node, &alice, "Reader", Some(&["messages:read"])).await;
    joined(&node, &alice, &room_id, &reader).await;
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", reader.user_id),
            &alice.token,
            json!({ "roles": [role_id] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &reader.secret).await;
    assert_eq!(detail["my_permissions"], (p::BOT_ALWAYS | p::READ_HISTORY).to_string());
    // With every scope the administrator role gives every bit except administrator itself and restore_history, which
    // no scope covers (ENCRYPTION.md §7b).
    let full = bot(&node, &alice, "Full", None).await;
    joined(&node, &alice, &room_id, &full).await;
    node.patch(
        &format!("/api/v1/rooms/{room_id}/members/{}", full.user_id),
        &alice.token,
        json!({ "roles": [role_id] }),
    )
    .await;
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &full.secret).await;
    assert_eq!(detail["my_permissions"], (p::ALL & !(p::ADMINISTRATOR | p::RESTORE_HISTORY)).to_string());
    // Nor through overrides: `administrator` is room-wide and never part of an override (channel-scoped bits only).
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &full.secret,
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member", "subject_id": full.user_id,
                    "allow": p::ADMINISTRATOR.to_string(), "deny": "0" }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "permissions.not_channel_scoped"), "{j}");
    // Whiteboard ephemeral events need the whiteboard scope on top of messages:write.
    let writer = bot(&node, &alice, "Writer", Some(&["messages:write"])).await;
    joined(&node, &alice, &room_id, &writer).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/ephemeral"),
            &writer.secret,
            json!({ "type": "whiteboard.update", "content": {} }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");
}

#[tokio::test]
async fn messages_carry_author_kind_and_bot_limits_apply() {
    let node = test_node_with(D, |c| c.app_rate_requests = 40).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let b = bot(&node, &alice, "Chatty", None).await;
    joined(&node, &alice, room_id, &b).await;
    for i in 0..5 {
        let (s, j) = node.send(&b.secret, room_id, &channel, &format!("hello {i}")).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        assert_eq!(j["author_kind"], "bot");
    }
    let (s, j) = node.send(&b.secret, room_id, &channel, "one too many").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "5 messages per 5 s and conversation: {j}");
    let (_, j) = node.send(&alice.token, room_id, &channel, "human").await;
    assert_eq!(j["author_kind"], "user");
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"), &alice.token).await;
    assert!(list.to_string().contains("\"author_kind\":\"bot\""), "{list}");
    // Members carry kind, owner and application id.
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    let m = members.as_array().unwrap().iter().find(|m| m["user"]["id"] == b.user_id.as_str()).unwrap();
    assert_eq!(
        (m["user"]["kind"].as_str(), m["user"]["owner"].as_str()),
        (Some("bot"), Some(format!("alice@{D}").as_str()))
    );
    assert_eq!(m["user"]["application_id"], b.app_id);
    // The keys document carries the kind.
    let (_, keys) = node.get_auth(&format!("/api/v1/users/{}/keys", b.username), &alice.token).await;
    assert_eq!(keys["kind"], "bot");

    // Per-application request limit (TAVRN_APP_RATE_REQUESTS, here 40 per minute, all tokens).
    let mut limited = false;
    for _ in 0..40 {
        if node.get_auth("/api/v1/users/me", &b.secret).await.0 == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "the application's request budget runs out");
}

// ---------------------------------------------------------------- joining rooms

#[tokio::test]
async fn bots_never_join_by_themselves() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Joiner", None).await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "join_mode": "public" })).await;
    // Public join, invite links and direct invites are refused: bots enter through an installation only.
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/join"), &b.secret, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &b.secret, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &alice.token, json!({ "user": b.address(D) }))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
    let (s, j) = node
        .post(&format!("/api/v1/invites/{}/join", j["invite"]["code"].as_str().unwrap()), &b.secret, json!({}))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    // A bot cannot install itself (or another bot).
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &b.secret,
            json!({ "application": format!("{D}/{}", b.app_id) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    // The installation works; leaving is always allowed and uninstalls the bot.
    joined(&node, &alice, room_id, &b).await;
    let (s, _) = node.post(&format!("/api/v1/rooms/{room_id}/leave"), &b.secret, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), &alice.token).await;
    assert_eq!(list, json!([]));
    let meta: String = sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'app.uninstall'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert!(meta.contains("\"left\""), "{meta}");
}

// ---------------------------------------------------------------- no bots

#[tokio::test]
async fn no_bots_at_room_category_and_channel_level() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let b = bot(&node, &alice, "Zoned", None).await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    joined(&node, &alice, &room_id, &b).await;
    let msgs = format!("/api/v1/rooms/{room_id}/channels/{channel}/messages");
    assert_eq!(node.get_auth(&msgs, &b.secret).await.0, StatusCode::OK);

    // Channel level: only owner / manage_room (and manage_channels).
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel}");
    let (s, j) = node.patch(&path, &bob.token, json!({ "no_bots": true })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "no_bots": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["no_bots"].as_bool(), j["no_bots_effective"].as_bool()), (Some(true), Some(true)));
    let (s, j) = node.get_auth(&msgs, &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "channel.view_forbidden"));
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &b.secret).await;
    assert!(
        !detail["channels"].as_array().unwrap().iter().any(|c| c["id"] == channel.as_str()),
        "invisible to the bot"
    );
    assert_eq!(node.get_auth(&msgs, &bob.token).await.0, StatusCode::OK, "people are not affected");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert!(detail["channels"].as_array().unwrap().iter().any(|c| c["id"] == channel.as_str()));
    node.patch(&path, &alice.token, json!({ "no_bots": false })).await;
    assert_eq!(node.get_auth(&msgs, &b.secret).await.0, StatusCode::OK);

    // Category level: every channel in it.
    let (s, cat) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &alice.token, json!({ "name": "Humans" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let cat_id = cat["id"].as_str().unwrap();
    node.patch(&path, &alice.token, json!({ "category_id": cat_id })).await;
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/categories/{cat_id}"), &bob.token, json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/categories/{cat_id}"), &alice.token, json!({ "no_bots": true }))
        .await;
    assert_eq!((s, j["no_bots"].as_bool()), (StatusCode::OK, Some(true)), "{j}");
    assert_eq!(node.get_auth(&msgs, &b.secret).await.0, StatusCode::FORBIDDEN);
    let (_, room_now) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let c = room_now["channels"].as_array().unwrap().iter().find(|c| c["id"] == channel.as_str()).unwrap().clone();
    assert_eq!((c["no_bots"].as_bool(), c["no_bots_effective"].as_bool()), (Some(false), Some(true)));
    node.patch(&format!("/api/v1/rooms/{room_id}/categories/{cat_id}"), &alice.token, json!({ "no_bots": false }))
        .await;

    // Room level: removes every bot and refuses new ones.
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &bob.token, json!({ "no_bots": true })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "no_bots": true })).await;
    assert_eq!((s, j["no_bots"].as_bool()), (StatusCode::OK, Some(true)), "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"));
    let (s, j) = join(&node, &alice, &room_id, &b).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.room_no_bots"));
    let meta: String = sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'room.no_bots'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert!(meta.contains("\"bots_removed\":1"), "{meta}");
    for action in ["channel.no_bots", "category.no_bots", "app.uninstall"] {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1")
            .bind(action)
            .fetch_one(&node.state.db)
            .await
            .unwrap();
        assert!(n >= 1, "{action}");
    }
}

#[tokio::test]
async fn no_bots_refuses_external_join_and_adds_and_asks_for_removal() {
    let (node, _other) = federation::two_nodes().await;
    let domain = node.domain().to_string();
    let mut alice = node.crypto_user("alice", 3).await;
    let room = node.create_room(alice.token(), "Lobby").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    // New rooms keep bots out of encrypted channels unless the channel allows them.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), alice.token(), json!({ "bots_allowed": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let gi = alice.client.create_group(&format!("{domain}/{channel}")).unwrap();
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/mls/group"),
            alice.token(),
            json!({ "group_info": e2ee::b64(&gi) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // The bot: identity, attested device of its token, KeyPackages.
    let b = bot(&node, &alice.session, "Crypto", None).await;
    joined(&node, &alice.session, &room_id, &b).await;
    let bot_master = MasterSecret::generate().unwrap();
    let (s, j) = node
        .put(
            "/api/v1/users/me/identity",
            &b.secret,
            json!({ "identity_public_key": e2ee::b64(&bot_master.identity_public_key()) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let device = Device::generate(&b.address(&domain), &b.device_id).unwrap();
    let att = device.attest(&bot_master).unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/users/me/devices/{}/key", b.device_id),
            &b.secret,
            json!({ "device_public_key": e2ee::b64(&att.device_public_key), "identity_signature": e2ee::b64(&att.signature) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let bot_client = Client::new(device);
    let kps: Vec<String> = (0..3).map(|_| e2ee::b64(&bot_client.create_key_package().unwrap())).collect();
    let (s, j) = node
        .post(
            &format!("/api/v1/users/me/devices/{}/key-packages", b.device_id),
            &b.secret,
            json!({ "key_packages": kps }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Alice adds the bot's device (allowed while the channel admits bots).
    let (s, j) = node.post(&format!("/api/v1/users/{}/key-packages/claim", b.username), alice.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let kp: Vec<Vec<u8>> =
        j["key_packages"].as_array().unwrap().iter().map(|k| e2ee::unb64(&k["key_package"])).collect();
    let out = alice.client.add_members(&format!("{domain}/{channel}"), &kp).unwrap();
    let (s, j) = node.commit(alice.token(), &channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    alice.client.merge_pending_commit(&format!("{domain}/{channel}")).unwrap();

    // Setting "no bots" asks the members to remove the bot's leaf.
    let mut ws = crossnode::ws(&node, alice.token()).await;
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), alice.token(), json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let ev = crossnode::event(&mut ws, "mls.remove_needed").await;
    assert_eq!(ev["conversation_id"], channel.as_str());
    assert_eq!(ev["identities"], json!([format!("{}/{}", b.address(&domain), b.device_id)]));

    // The bot cannot fetch the group info (no external join) …
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{channel}/mls/group-info"), &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"));
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{channel}/mls/commits"),
            &b.secret,
            json!({ "epoch": 1, "commit": "AA", "group_info": "AA" }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"));
    // … the removal is accepted (the bot is no longer entitled) …
    let out = alice
        .client
        .remove_members(&format!("{domain}/{channel}"), &[format!("{}/{}", b.address(&domain), b.device_id)])
        .unwrap();
    let (s, j) = node.commit(alice.token(), &channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    alice.client.merge_pending_commit(&format!("{domain}/{channel}")).unwrap();
    // … and adding the bot's device again is refused.
    let (s, j) = node.post(&format!("/api/v1/users/{}/key-packages/claim", b.username), alice.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let kp: Vec<Vec<u8>> =
        j["key_packages"].as_array().unwrap().iter().map(|k| e2ee::unb64(&k["key_package"])).collect();
    let out = alice.client.add_members(&format!("{domain}/{channel}"), &kp).unwrap();
    let (s, j) = node.commit(alice.token(), &channel, &out).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"), "{j}");
}

// ---------------------------------------------------------------- cascades

#[tokio::test]
async fn owner_disabled_disables_the_bot_and_closes_its_websocket() {
    let (node, _other) = federation::two_nodes().await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Follower", None).await;
    let (url, secret) = (node.ws_url(), b.secret.clone());
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": secret }).to_string().into())).await.unwrap();
    let ready: Value = serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(ready["application_id"], b.app_id);
    assert_eq!(ready["user"]["kind"], "bot");

    let (s, j) =
        node.patch(&format!("/api/v1/admin/users/{}", alice.user_id), &admin.token, json!({ "disabled": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(close_code(&mut ws).await, Some(4001));
    let (s, j) = node.get_auth("/api/v1/users/me", &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.disabled"));
    assert_eq!(j["meta"]["reason"], "owner_disabled");
    // A WebSocket hello is refused as well.
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": b.secret }).to_string().into())).await.unwrap();
    assert_eq!(close_code(&mut ws).await, Some(4001));
    // Re-enabling the owner re-enables the bot.
    node.patch(&format!("/api/v1/admin/users/{}", alice.user_id), &admin.token, json!({ "disabled": false })).await;
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::OK);
    // Bots never become node admins.
    let (s, j) =
        node.patch(&format!("/api/v1/admin/users/{}", b.user_id), &admin.token, json!({ "node_admin": true })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.bot_forbidden"));
}

async fn close_code(ws: &mut crossnode::Ws) -> Option<u16> {
    loop {
        match tokio::time::timeout(common::timeout(Duration::from_secs(5)), ws.next()).await.expect("closed in time") {
            Some(Ok(Message::Close(frame))) => return frame.map(|f| u16::from(f.code)),
            Some(Ok(_)) => {}
            _ => return None,
        }
    }
}

#[tokio::test]
async fn websocket_limits_and_scope_filtering() {
    let (node, _other) = federation::two_nodes().await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let quiet = bot(&node, &alice, "Quiet", Some(&["members:read"])).await;
    let reader = bot(&node, &alice, "Reader", Some(&["messages:read"])).await;
    joined(&node, &alice, room_id, &quiet).await;
    joined(&node, &alice, room_id, &reader).await;
    let mut q = crossnode::ws(&node, &quiet.secret).await;
    let mut r = crossnode::ws(&node, &reader.secret).await;
    node.send(&alice.token, room_id, &channel, "hello bots").await;
    assert_eq!(crossnode::event(&mut r, "message.create").await["content"]["body"], "hello bots");
    assert!(crossnode::no_event(&mut q, "message.create", 300).await, "no messages:read, no message events");

    // A third connection of the same token closes the oldest with 4004.
    let mut second = crossnode::ws(&node, &reader.secret).await;
    let _third = crossnode::ws(&node, &reader.secret).await;
    assert_eq!(close_code(&mut r).await, Some(4004));
    // Resetting the token closes its connections with 4001.
    node.post(
        &format!("/api/v1/applications/{}/tokens/{}/reset", reader.app_id, reader.token_id),
        &alice.token,
        json!({}),
    )
    .await;
    assert_eq!(close_code(&mut second).await, Some(4001));
}

#[tokio::test]
async fn owner_ban_removes_the_bot_and_blocks_its_return() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let mallory = node.register("mallory").await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let b = bot(&node, &mallory, "Sneaky", None).await;
    // Alice (the room owner) invites mallory's bot directly.
    joined(&node, &alice, room_id, &b).await;
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": format!("mallory@{D}") }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"));
    // It cannot come back: the owner's ban covers the bot.
    let (s, j) = join(&node, &alice, room_id, &b).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.owner_banned"));
    let meta: String = sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'app.uninstall'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert!(meta.contains("owner_banned"), "{meta}");
}

#[tokio::test]
async fn delete_application_leaves_a_tombstone() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let b = bot(&node, &alice, "Gone", None).await;
    joined(&node, &alice, room_id, &b).await;
    let (s, msg) = node.send(&b.secret, room_id, &channel, "last words").await;
    assert_eq!(s, StatusCode::CREATED);
    let path = format!("/api/v1/applications/{}", b.app_id);
    let (s, j) = node.req(Method::DELETE, &path, Some(&alice.token), Some(json!({ "name": "Wrong" }))).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.name_confirm"));
    let (s, j) = node.req(Method::DELETE, &path, Some(&alice.token), Some(json!({ "name": "Gone" }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(node.get_auth(&path, &alice.token).await.0, StatusCode::NOT_FOUND);
    // The membership is gone, the message keeps its author, the username is never reused.
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    assert!(!members.to_string().contains(&b.user_id));
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"), &alice.token).await;
    assert!(list.to_string().contains(msg["id"].as_str().unwrap()));
    let (s, j) =
        node.post("/api/v1/applications", &alice.token, json!({ "name": "Again", "username": b.username })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.username_taken"));
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": b.username, "date_of_birth": "1990-01-01", "password": "a-long-password-1", "device_name": "x" })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn transfer_gives_fresh_credentials() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let b = bot(&node, &alice, "Moving", None).await;
    let base = format!("/api/v1/applications/{}/transfer", b.app_id);
    let (s, j) = node.post(&base, &alice.token, json!({ "to": "nobody" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.transfer_target_invalid"));
    let (s, j) = node.post(&base, &alice.token, json!({ "to": b.username })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.transfer_target_invalid"), "never to a bot");
    let (s, _) = node.post(&base, &alice.token, json!({ "to": "bob" })).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (s, j) = node.post(&base, &alice.token, json!({ "to": "carol" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.transfer_pending"));
    let (_, app) = node.get_auth(&format!("/api/v1/applications/{}", b.app_id), &alice.token).await;
    assert_eq!(app["transfer"]["to"], format!("bob@{D}"));
    // Only the target sees and accepts it.
    let (_, incoming) = node.get_auth("/api/v1/applications/transfers", &bob.token).await;
    assert_eq!(incoming[0]["application_id"], b.app_id);
    let (s, j) = node.post(&format!("{base}/accept"), &carol.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.transfer_not_found"));
    // Cancel and offer again, decline, offer again, accept.
    assert_eq!(node.delete(&base, &alice.token).await.0, StatusCode::NO_CONTENT);
    assert_eq!(node.post(&format!("{base}/accept"), &bob.token, json!({})).await.0, StatusCode::NOT_FOUND);
    node.post(&base, &alice.token, json!({ "to": "bob" })).await;
    assert_eq!(node.post(&format!("{base}/decline"), &bob.token, json!({})).await.0, StatusCode::NO_CONTENT);
    node.post(&base, &alice.token, json!({ "to": "bob" })).await;
    let (s, j) = node.post(&format!("{base}/accept"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(
        (j["owner"].as_str(), j["bot"]["owner"].as_str()),
        (Some(format!("bob@{D}").as_str()), Some(format!("bob@{D}").as_str()))
    );
    assert_eq!(j["tokens"], 0, "every token was revoked");
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        node.get_auth(&format!("/api/v1/applications/{}", b.app_id), &alice.token).await.0,
        StatusCode::NOT_FOUND
    );
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'app.transfer'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn owner_resets_the_bot_identity() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, "Keyed", None).await;
    let master = MasterSecret::generate().unwrap();
    let body = json!({ "identity_public_key": e2ee::b64(&master.identity_public_key()) });
    assert_eq!(node.put("/api/v1/users/me/identity", &b.secret, body.clone()).await.0, StatusCode::NO_CONTENT);
    let (s, j) = node.put("/api/v1/users/me/identity", &b.secret, body).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "e2ee.identity_exists"));
    // Bots cannot reset themselves (no password); the owner can.
    let (s, _) = node
        .post("/api/v1/users/me/identity/reset", &b.secret, json!({ "identity_public_key": "x", "password": "y" }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let bob = node.register("bob").await;
    let reset = format!("/api/v1/applications/{}/identity/reset", b.app_id);
    assert_eq!(node.post(&reset, &bob.token, json!({})).await.0, StatusCode::NOT_FOUND);
    assert_eq!(node.post(&reset, &alice.token, json!({})).await.0, StatusCode::NO_CONTENT);
    let (_, me) = node.get_auth("/api/v1/users/me", &b.secret).await;
    assert_eq!(me["has_identity_key"], false);
    let fresh = MasterSecret::generate().unwrap();
    let body = json!({ "identity_public_key": e2ee::b64(&fresh.identity_public_key()) });
    assert_eq!(node.put("/api/v1/users/me/identity", &b.secret, body).await.0, StatusCode::NO_CONTENT);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'app.identity_reset'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

// ---------------------------------------------------------------- federation

#[tokio::test]
async fn remote_bot_with_narrowed_scopes_and_local_only_owner_routes() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let bot_a = bot(&a, &alice, "Traveller", Some(&["messages:read"])).await;
    // The federation token carries kind, owner, app and the effective scopes.
    let (s, j) = a.post("/api/v1/federation/token", &bot_a.secret, json!({ "target": federation::B })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let token = j["token"].as_str().unwrap();
    let payload: Value = serde_json::from_slice(&base64_decode(token.split('.').nth(1).unwrap())).unwrap();
    assert_eq!(payload["kind"], "bot");
    assert_eq!(payload["owner"], format!("alice@{}", federation::A));
    assert_eq!(payload["app"], bot_a.app_id);
    assert_eq!(payload["scopes"], json!(["messages:read"]));
    let (s, login) = b.federated_login(token).await;
    assert_eq!(s, StatusCode::OK, "{login}");
    let remote = login["access_token"].as_str().unwrap();
    assert_eq!(login["user"]["application_id"], format!("{}/{}", federation::A, bot_a.app_id));
    assert_eq!(login["user"]["owner"], format!("alice@{}", federation::A));

    // On B: a room of carol; carol installs the bot (B fetches the public document from A).
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Remote").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (s, j) = b
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": format!("{}/{}", federation::A, bot_a.app_id) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // Scopes apply on T: reading yes, writing no; never-allowed routes stay closed; owner routes are local-only.
    let msgs = format!("/api/v1/rooms/{room_id}/channels/{channel}/messages");
    assert_eq!(b.get_auth(&msgs, remote).await.0, StatusCode::OK);
    let (s, j) = b.post(&msgs, remote, json!({ "content": { "type": "text", "body": "hi" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let (s, j) = b.post("/api/v1/rooms", remote, json!({ "name": "x" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (_, detail) = b.get_auth(&format!("/api/v1/rooms/{room_id}"), remote).await;
    assert_eq!(detail["my_permissions"], (p::BOT_ALWAYS | p::READ_HISTORY).to_string());
    // A remote *user* cannot use the owner routes on B.
    let remote_alice = b.sign_in_from(&a, &alice).await;
    let (s, j) = b.post("/api/v1/applications", &remote_alice.token, json!({ "name": "Elsewhere" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"));
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

#[tokio::test]
async fn bots_refused_in_both_directions() {
    // H does not let its bots federate.
    let (a, _b) = federation::two_nodes_with(|c| c.apps_federate = false, |_| {}).await;
    let alice = a.register("alice").await;
    let bot_a = bot(&a, &alice, "Homebound", None).await;
    let (s, j) = a.post("/api/v1/federation/token", &bot_a.secret, json!({ "target": federation::B })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.bots_refused"));
    assert_eq!(
        a.post("/api/v1/federation/token", &alice.token, json!({ "target": federation::B })).await.0,
        StatusCode::OK
    );

    // T does not accept remote bots (H still issues the token).
    let (a, b) = federation::two_nodes_with(|_| {}, |c| c.federation_remote_bots = false).await;
    let alice = a.register("alice").await;
    let bot_a = bot(&a, &alice, "Visitor", None).await;
    let (s, j) = a.post("/api/v1/federation/token", &bot_a.secret, json!({ "target": federation::B })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = b.federated_login(j["token"].as_str().unwrap()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.bots_refused"));
}

/// Authorization audit (2026-10-09): a node ban of a bot's owner refuses the bot's federated login; a session the
/// bot already holds ends with it as well (FEDERATION.md §3.2, APPLICATIONS.md §1.7).
#[tokio::test]
async fn authz_owner_node_ban_ends_a_remote_bots_session() {
    let (a, b) = federation::two_nodes().await;
    let admin = b.register("admin").await;
    let alice = a.register("alice").await;
    let bot_a = bot(&a, &alice, "Lingerer", None).await;
    let (s, j) = a.post("/api/v1/federation/token", &bot_a.secret, json!({ "target": federation::B })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, login) = b.federated_login(j["token"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK, "{login}");
    let remote = login["access_token"].as_str().unwrap().to_string();
    assert_eq!(b.get_auth("/api/v1/rooms", &remote).await.0, StatusCode::OK);
    let (s, j) =
        b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": format!("alice@{}", federation::A) })).await;
    assert!(s.is_success(), "{j}");
    assert_eq!(b.get_auth("/api/v1/rooms", &remote).await.0, StatusCode::UNAUTHORIZED);
}
