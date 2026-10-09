// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! GDPR data rights (protocol/LEGAL.md §3): export, account deletion with tombstones, the
//! admin undo, the grace period, admin actions on request and `user.deleted` across nodes.
use crate::common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, federation::two_nodes, password, test_node};
use serde_json::{Value, json};
use tower::ServiceExt;

struct World {
    node: TestNode,
    admin: Session,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

/// Admin owns a plaintext room; alice and bob are members and friends; both posted.
async fn world() -> World {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&admin.token, "Hall").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &admin.token, json!({})).await;
    for s in [&alice, &bob] {
        let (st, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &s.token, json!({})).await;
        assert!(st.is_success(), "{j}");
    }
    let (s, req) = node.post("/api/v1/users/me/friends/requests", &alice.token, json!({ "user": "bob@t.local" })).await;
    assert_eq!(s, StatusCode::CREATED, "{req}");
    let id = req["request_id"].as_str().unwrap();
    let (s, j) = node.post(&format!("/api/v1/users/me/friends/requests/{id}/accept"), &bob.token, json!({})).await;
    assert!(s.is_success(), "{j}");
    World { node, admin, alice, bob, room_id, channel }
}

async fn upload(node: &TestNode, token: &str, room: &str, channel: &str, data: &[u8]) -> Value {
    let req = Request::post(format!("/api/v1/rooms/{room}/channels/{channel}/uploads"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .header("tavrn-file-name", "notes.txt")
        .body(Body::from(data.to_vec()))
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success());
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

async fn export(node: &TestNode, token: &str) -> (StatusCode, String) {
    let mut builder = Request::get("/api/v1/users/me/export").header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(r) = node.reauth.lock().unwrap().get(token) {
        builder = builder.header("tavrn-reauth", r.as_str());
    }
    let resp = node.router.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    (status, String::from_utf8(body_bytes(resp).await.to_vec()).unwrap())
}

fn messages_path(w: &World) -> String {
    format!("/api/v1/rooms/{}/channels/{}/messages", w.room_id, w.channel)
}

/// Waits until the deletion's content job is done (status link).
async fn wait_done(node: &TestNode, started: &Value) -> Value {
    let path = format!(
        "/api/v1/account-deletions/{}?token={}",
        started["id"].as_str().unwrap(),
        started["status_token"].as_str().unwrap()
    );
    for _ in 0..100 {
        let (s, st) = node.req(Method::GET, &path, None, None).await;
        assert_eq!(s, StatusCode::OK, "{st}");
        if st["state"] == "done" {
            return st;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("content deletion did not finish");
}

#[tokio::test]
async fn the_export_holds_the_accounts_plaintext_data_and_no_secrets() {
    let w = world().await;
    let node = &w.node;
    node.send(&w.alice.token, &w.room_id, &w.channel, "alice says hello").await;
    node.send(&w.bob.token, &w.room_id, &w.channel, "bob's private thought").await;
    // Secrets that must never leave: secret storage, key backups, an encrypted message's ciphertext.
    sqlx::query("INSERT INTO secret_storage (user_id, method, wrapped, params, updated_at) VALUES ($1, 'recovery', $2, '{\"salt\":\"SALTSECRET\"}', $3)")
        .bind(&w.alice.user_id)
        .bind(b"WRAPPEDKEYSECRET".to_vec())
        .bind(tavrn_node::util::now())
        .execute(&node.state.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO key_backups (user_id, conversation, blob, etag, updated_at) VALUES ($1, 'c', $2, 'BACKUPETAG', $3)")
        .bind(&w.alice.user_id)
        .bind(b"BACKUPSECRET".to_vec())
        .bind(tavrn_node::util::now())
        .execute(&node.state.db)
        .await
        .unwrap();
    let encrypted_room = node.create_room(&w.alice.token, "E2EE").await;
    sqlx::query("INSERT INTO messages (id, conversation_id, author_id, device_id, encrypted, content, content_size, created_at) VALUES ($1, $2, $3, $4, 1, 'CIPHERTEXTSECRET', 16, $5)")
        .bind(tavrn_node::util::ulid())
        .bind(TestNode::text_channel(&encrypted_room))
        .bind(&w.alice.user_id)
        .bind(&w.alice.device_id)
        .bind(tavrn_node::util::now())
        .execute(&node.state.db)
        .await
        .unwrap();

    // Re-authentication is required; remote users and other users' data are out.
    node.forget_reauth(&w.alice.token);
    let (s, body) = export(node, &w.alice.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("auth.reauth_required"));
    let fresh = node.login("alice").await;
    let (s, body) = export(node, &fresh.token).await;
    assert_eq!(s, StatusCode::OK);
    let archive: Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(archive["format"], "tavrn.export.v1");
    assert_eq!(archive["account"]["address"], "alice@t.local");
    assert!(archive["devices"].as_array().unwrap().len() >= 2);
    assert_eq!(archive["friends"][0]["address"], "bob@t.local");
    assert!(archive["rooms"].as_array().unwrap().iter().any(|r| r["name"] == "Hall"));
    let msgs = archive["messages"].as_array().unwrap();
    assert!(msgs.iter().any(|m| m["content"]["body"] == "alice says hello"), "{body}");
    assert!(msgs.iter().any(|m| m["encrypted"] == true && m["content"].is_null()));
    for secret in
        ["WRAPPEDKEYSECRET", "SALTSECRET", "BACKUPSECRET", "CIPHERTEXTSECRET", "$argon2", "bob's private thought"]
    {
        assert!(!body.contains(secret), "{secret} leaked");
    }
    for code in &fresh.recovery_codes {
        assert!(!body.contains(code.as_str()), "recovery code leaked");
    }
    assert!(!body.contains(&fresh.refresh), "refresh token leaked");
    let (s, _) = node.get_auth("/api/v1/users/me/export", "garbage").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The summary ("My data").
    let (_, summary) = node.get_auth("/api/v1/users/me/data", &fresh.token).await;
    let cat = |k: &str| {
        summary["categories"].as_array().unwrap().iter().find(|c| c["key"] == k).unwrap()["count"].as_i64().unwrap()
    };
    assert_eq!((cat("messages"), cat("encrypted_messages"), cat("friends")), (1, 1, 1), "{summary}");
    assert_eq!(summary["retention"]["account_delete_grace_days"], 30);
}

#[tokio::test]
async fn deleting_keeps_messages_as_deleted_user_and_the_admin_can_undo() {
    let w = world().await;
    let node = &w.node;
    let (_, m) = node.send(&w.alice.token, &w.room_id, &w.channel, "I will be a ghost").await;
    let message_id = m["id"].as_str().unwrap().to_string();
    let (_, reply) = node
        .post(
            &messages_path(&w),
            &w.bob.token,
            json!({ "content": { "type": "text", "body": "reply" }, "reply_to_id": message_id }),
        )
        .await;
    let alice_room = node.create_room(&w.alice.token, "Mine").await;

    // Checks: re-auth, the confirmation phrase, owned rooms.
    node.forget_reauth(&w.alice.token);
    let (s, j) =
        node.req(Method::DELETE, "/api/v1/users/me", Some(&w.alice.token), Some(json!({ "confirm": "alice" }))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")));
    let alice = node.login("alice").await;
    let (s, j) =
        node.req(Method::DELETE, "/api/v1/users/me", Some(&alice.token), Some(json!({ "confirm": "bob" }))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("account.confirm_mismatch")));
    let (s, j) =
        node.req(Method::DELETE, "/api/v1/users/me", Some(&alice.token), Some(json!({ "confirm": "alice" }))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("account.owns_rooms")), "{j}");
    assert_eq!(j["meta"]["rooms"][0]["name"], "Mine");
    node.delete(&format!("/api/v1/rooms/{}", alice_room["id"].as_str().unwrap()), &alice.token).await;
    let (s, started) =
        node.req(Method::DELETE, "/api/v1/users/me", Some(&alice.token), Some(json!({ "confirm": "Alice" }))).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{started}");
    assert_eq!(started["state"], "done");
    assert!(started["status_token"].is_string());
    assert!(started["address"].as_str().unwrap().is_empty(), "the status view names no address");

    // The account is gone at once.
    let (s, j) = node.get_auth("/api/v1/rooms", &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.account_disabled")));
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": password("alice") })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.account_deleted")));
    let (s, _) = node.req(Method::GET, "/api/v1/users/alice@t.local/profile", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "alice", "date_of_birth": "1990-01-01", "password": password("alice") })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "username reserved: {j}");
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "deleted-abc", "date_of_birth": "1990-01-01", "password": password("x") })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "the tombstone prefix is reserved");
    let (_, friends) = node.get_auth("/api/v1/users/me/friends", &w.bob.token).await;
    assert!(!friends.to_string().contains("alice"), "{friends}");
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{}/members", w.room_id), &w.bob.token).await;
    assert!(!members.to_string().contains("alice@t.local"));

    // The message stays as "Deleted user"; the reply still points at it; nothing links back.
    let (_, msgs) = node.get_auth(&messages_path(&w), &w.bob.token).await;
    let ghost = msgs.as_array().unwrap().iter().find(|m| m["id"] == message_id.as_str()).unwrap();
    assert_eq!(ghost["author_deleted"], true, "{ghost}");
    assert!(ghost["author"].as_str().unwrap().starts_with("deleted-"));
    assert_ne!(ghost["author_id"], alice.user_id.as_str());
    assert!(ghost["device_id"].is_null() && ghost["signature"].is_null());
    assert_eq!(ghost["content"]["body"], "I will be a ghost");
    let r = msgs.as_array().unwrap().iter().find(|m| m["id"] == reply["id"]).unwrap();
    assert_eq!((r["reply_to_id"].as_str(), r["reply_deleted"].as_bool()), (Some(message_id.as_str()), None));
    // The audit log is pseudonymised.
    let (_, log) = node.get_auth("/api/v1/admin/audit-log?limit=200", &w.admin.token).await;
    assert!(!log.to_string().contains("alice@t.local"), "{log}");
    assert!(log.as_array().unwrap().iter().any(|e| e["action"] == "user.delete"));

    // The admin sees the deletion and undoes it: the account and its messages come back.
    let (_, deletions) = node.get_auth("/api/v1/admin/account-deletions", &w.admin.token).await;
    assert_eq!(deletions[0]["address"], "alice@t.local");
    let (s, _) = node.post(&format!("/api/v1/admin/users/{}/undelete", alice.user_id), &w.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, d) = node.post(&format!("/api/v1/admin/users/{}/undelete", alice.user_id), &w.admin.token, json!({})).await;
    assert_eq!((s, d["state"].as_str()), (StatusCode::OK, Some("undone")), "{d}");
    let pre = node.login_preauth("alice", &password("alice")).await;
    assert_eq!(pre["status"], "enrollment_required", "factors were deleted: {pre}");
    let (_, msgs) = node.get_auth(&messages_path(&w), &w.bob.token).await;
    let back = msgs.as_array().unwrap().iter().find(|m| m["id"] == message_id.as_str()).unwrap();
    assert_eq!(back["author"], "alice@t.local");
    let (s, j) = node.post(&format!("/api/v1/admin/users/{}/undelete", alice.user_id), &w.admin.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("account.deletion_not_found")));
}

#[tokio::test]
async fn deleting_with_messages_removes_content_and_files_and_the_grace_period_ends() {
    let w = world().await;
    let node = &w.node;
    let blob = upload(node, &w.bob.token, &w.room_id, &w.channel, b"bob's file").await;
    let (_, m) = node
        .post(
            &messages_path(&w),
            &w.bob.token,
            json!({ "content": { "type": "text", "body": "with file" }, "attachments": [blob["id"]] }),
        )
        .await;
    let (_, m2) = node.send(&w.bob.token, &w.room_id, &w.channel, "searchable words").await;
    let (_, hits) = node.get_auth(&format!("/api/v1/rooms/{}/search?q=searchable", w.room_id), &w.admin.token).await;
    assert_eq!(
        hits["results"].as_array().map(Vec::len).unwrap_or(0) + hits["hits"].as_array().map(Vec::len).unwrap_or(0),
        1,
        "{hits}"
    );
    let (s, started) = node
        .req(
            Method::DELETE,
            "/api/v1/users/me",
            Some(&w.bob.token),
            Some(json!({ "confirm": "bob", "delete_messages": true })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{started}");
    assert_eq!(started["delete_messages"], true);
    let done = wait_done(node, &started).await;
    assert_eq!(done["messages_done"], done["messages_total"]);
    assert!(done["messages_total"].as_i64().unwrap() >= 2);

    let (_, msgs) = node.get_auth(&messages_path(&w), &w.admin.token).await;
    for id in [&m["id"], &m2["id"]] {
        let gone = msgs.as_array().unwrap().iter().find(|x| &x["id"] == id).unwrap();
        assert_eq!(gone["content"], json!({ "type": "system.deleted" }), "{gone}");
        assert_eq!(gone["author_deleted"], true);
        assert!(gone["attachments"].as_array().unwrap().is_empty());
    }
    let resp = node.get_with(&format!("/api/v1/blobs/{}", blob["id"].as_str().unwrap()), &w.admin.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "the file is gone");
    let (_, hits) = node.get_auth(&format!("/api/v1/rooms/{}/search?q=searchable", w.room_id), &w.admin.token).await;
    assert!(!hits.to_string().contains("searchable words"), "{hits}");

    // After the grace period the account row is erased and the username is free again.
    sqlx::query("UPDATE account_deletions SET purge_after = '2000-01-01T00:00:00Z'")
        .execute(&node.state.db)
        .await
        .unwrap();
    let (_, _, erased) = tavrn_node::legal::housekeeping(&node.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(erased, 1);
    let gone: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(&w.bob.user_id)
        .fetch_optional(&node.state.db)
        .await
        .unwrap();
    assert!(gone.is_none());
    let (s, j) = node.post(&format!("/api/v1/admin/users/{}/undelete", w.bob.user_id), &w.admin.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let again = node.register("bob").await;
    let (_, msgs) = node.get_auth(&messages_path(&w), &w.admin.token).await;
    assert!(
        msgs.as_array().unwrap().iter().all(|x| x["author_id"] != again.user_id.as_str()),
        "a new bob owns nothing"
    );
}

#[tokio::test]
async fn admins_export_and_delete_on_request_with_reauth_and_audit() {
    let w = world().await;
    let node = &w.node;
    let alice_path = |action: &str| format!("/api/v1/admin/users/{}/{action}", w.alice.user_id);
    let (s, _) = node.get_auth(&alice_path("export"), &w.bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = node
        .post("/api/v1/admin/tokens", &w.admin.token, json!({ "name": "x", "scopes": ["users:write", "users:read"] }))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let token = j["secret"].as_str().unwrap();
    let (s, j) = node.post(&alice_path("delete"), token, json!({ "confirm": "alice" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("admin_token.route_forbidden")));
    let (s, _) = node.get_auth(&alice_path("export"), token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    node.forget_reauth(&w.admin.token);
    let (s, j) = node.get_auth(&alice_path("export"), &w.admin.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")));
    let admin = node.login("admin").await;
    let resp = node.get_with(&alice_path("export"), &admin.token).await;
    // `get_with` sends no reauth header: refused as well.
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let (s, archive) = node.get_auth(&alice_path("export"), &admin.token).await;
    assert_eq!((s, archive["account"]["address"].as_str()), (StatusCode::OK, Some("alice@t.local")));
    let (s, j) = node
        .post(&format!("/api/v1/admin/users/{}/delete", admin.user_id), &admin.token, json!({ "confirm": "admin" }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("admin.self")));
    let (s, j) = node.post(&alice_path("delete"), &admin.token, json!({ "confirm": "nope" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("account.confirm_mismatch")));
    let (s, d) = node.post(&alice_path("delete"), &admin.token, json!({ "confirm": "alice" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{d}");
    assert_eq!(d["by_admin"], true);
    let (_, log) = node.get_auth("/api/v1/admin/audit-log?limit=100", &admin.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"admin.user_export") && actions.contains(&"admin.user_delete"), "{actions:?}");
    let (s, j) = node.post(&alice_path("delete"), &admin.token, json!({ "confirm": "alice" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("account.deleted")));
}

#[tokio::test]
async fn other_nodes_tombstone_the_user_on_user_deleted() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "On B").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (s, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, m) = b.send(&remote.token, room_id, &channel, "from alice on b").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    // Remote users cannot delete or export on a node that is not their home.
    let (s, j) =
        b.req(Method::DELETE, "/api/v1/users/me", Some(&remote.token), Some(json!({ "confirm": "alice" }))).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));
    let (s, _) = b.get_auth("/api/v1/users/me/export", &remote.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, started) = a
        .req(
            Method::DELETE,
            "/api/v1/users/me",
            Some(&alice.token),
            Some(json!({ "confirm": "alice", "delete_messages": true })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{started}");
    assert!(a.outbox().await.iter().any(|o| o.kind == "user.deleted" && o.target == "b.test"));
    a.deliver().await;

    let mut content = Value::Null;
    for _ in 0..100 {
        let (_, msgs) = b.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"), &carol.token).await;
        let msg = msgs.as_array().unwrap().iter().find(|x| x["id"] == m["id"]).cloned().unwrap();
        assert_eq!(msg["author_deleted"], true, "{msg}");
        content = msg["content"].clone();
        if content == json!({ "type": "system.deleted" }) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(content, json!({ "type": "system.deleted" }));
    let (_, members) = b.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &carol.token).await;
    assert!(!members.to_string().contains("alice@a.test"), "{members}");
    let (s, _) = b.get_auth("/api/v1/rooms", &remote.token).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the federated session ended");
    let admin_b = carol; // first account of b is its admin
    let (_, log) = b.get_auth("/api/v1/admin/audit-log?limit=50", &admin_b.token).await;
    assert!(
        log.as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "federation.user_deleted" && e["meta"]["origin"] == "a.test"),
        "{log}"
    );
}

#[tokio::test]
async fn bots_cannot_reach_the_data_rights_terms_or_notices_of_their_account() {
    let node = test_node("t.local").await;
    let owner = node.register("owner").await;
    let (s, app) = node.post("/api/v1/applications", &owner.token, json!({ "name": "Helper" })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let (s, t) = node
        .post(
            &format!("/api/v1/applications/{}/tokens", app["id"].as_str().unwrap()),
            &owner.token,
            json!({ "name": "main" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let bot = t["secret"].as_str().unwrap().to_string();
    for (method, path) in [
        (Method::GET, "/api/v1/users/me/data"),
        (Method::GET, "/api/v1/users/me/export"),
        (Method::DELETE, "/api/v1/users/me"),
        (Method::GET, "/api/v1/users/me/terms"),
        (Method::POST, "/api/v1/users/me/terms/accept"),
        (Method::GET, "/api/v1/users/me/legal-notices"),
        (Method::GET, "/api/v1/admin/legal/notices"),
    ] {
        let (s, j) = node.req(method.clone(), path, Some(&bot), Some(json!({ "confirm": "x", "version": 1 }))).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {path}: {j}");
    }
}
