// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Entitlements (protocol/ENTITLEMENTS.md): plans and grants API, evaluation at the
//! enforcement points, and the admin API tokens with their security properties.
use crate::common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tower::ServiceExt;

const PLANS: &str = "/api/v1/admin/entitlements/plans";
const GRANTS: &str = "/api/v1/admin/entitlements/grants";

/// A node with the admin registered first (the first account is a node admin).
async fn node_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> (TestNode, Session, Session) {
    let node = test_node_with("t.local", tweak).await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    (node, admin, bob)
}

async fn audit_actions(node: &TestNode, admin: &Session) -> Vec<Value> {
    let (s, log) = node.get_auth("/api/v1/admin/audit-log?limit=200", &admin.token).await;
    assert_eq!(s, StatusCode::OK, "{log}");
    log.as_array().unwrap().clone()
}

async fn upload(node: &TestNode, token: &str, room: &str, channel: &str, data: Vec<u8>) -> (StatusCode, Value) {
    let req = Request::post(format!("/api/v1/rooms/{room}/channels/{channel}/uploads"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .header("tavrn-file-name", "a.txt")
        .body(Body::from(data))
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

#[tokio::test]
async fn entitlement_routes_are_for_node_admins_only() {
    let (node, admin, bob) = node_with(|_| {}).await;
    for path in [
        "/api/v1/admin/entitlements/keys",
        PLANS,
        GRANTS,
        "/api/v1/admin/entitlements/effective?user=bob",
        "/api/v1/admin/tokens",
    ] {
        let (s, j) = node.get_auth(path, &bob.token).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")), "{path}");
        let (s, j) = node.get_auth(path, &admin.token).await;
        assert_eq!(s, StatusCode::OK, "{path}: {j}");
    }
    let (s, _) = node.post(PLANS, &bob.token, json!({ "name": "x", "limits": {} })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, keys) = node.get_auth("/api/v1/admin/entitlements/keys", &admin.token).await;
    assert_eq!(keys.as_array().unwrap().len(), 14);
    let retention = keys.as_array().unwrap().iter().find(|k| k["key"] == "attachments.retention_days").unwrap();
    assert_eq!(retention["rule"], "shortest_non_zero");
}

#[tokio::test]
async fn plans_crud_with_validation_and_audit() {
    let (node, admin, _bob) = node_with(|_| {}).await;
    for (body, code) in [
        (json!({ "name": "Gold", "limits": { "no.such.key": 1 } }), "entitlements.invalid_limits"),
        (json!({ "name": "Gold", "limits": { "rooms.max_owned": -1 } }), "entitlements.invalid_limits"),
        (json!({ "name": "Gold", "limits": { "rooms.max_owned": 2.5 } }), "entitlements.invalid_limits"),
        (
            json!({ "name": "Gold", "limits": { "upload.max_bytes": 9_223_372_036_854_775_807i64 } }),
            "entitlements.invalid_limits",
        ),
        (json!({ "name": "Gold", "limits": { "files_channels.enabled": 2 } }), "entitlements.invalid_limits"),
        (json!({ "name": "", "limits": {} }), "validation.length"),
    ] {
        let (s, j) = node.post(PLANS, &admin.token, body.clone()).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}: {j}");
    }
    let (s, j) = node.post(PLANS, &admin.token, json!({ "name": "Gold", "limits": {}, "evil": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown fields are refused: {j}");

    let (s, gold) = node
        .post(
            PLANS,
            &admin.token,
            json!({ "name": "Gold", "limits": { "rooms.max_owned": 20, "upload.max_bytes": 104857600 } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{gold}");
    assert_eq!(gold["limits"]["rooms.max_owned"], 20);
    assert_eq!(gold["grants"], 0);
    let id = gold["id"].as_str().unwrap();
    let (s, j) = node.post(PLANS, &admin.token, json!({ "name": "Gold", "limits": {} })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("entitlements.plan_name_taken")));

    let (s, j) = node
        .patch(
            &format!("{PLANS}/{id}"),
            &admin.token,
            json!({ "name": "Platinum", "limits": { "emoji.max_per_room": 500 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["name"], "Platinum");
    assert_eq!(j["limits"], json!({ "emoji.max_per_room": 500 }), "limits are replaced");
    let (_, list) = node.get_auth(PLANS, &admin.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    // In use: refused; after the grant is gone: deleted.
    let (s, grant) = node.post(GRANTS, &admin.token, json!({ "subject": "user:bob", "plan_id": id })).await;
    assert_eq!(s, StatusCode::CREATED, "{grant}");
    let (s, j) = node.delete(&format!("{PLANS}/{id}"), &admin.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("entitlements.plan_in_use")));
    node.delete(&format!("{GRANTS}/{}", grant["id"].as_str().unwrap()), &admin.token).await;
    let (s, _) = node.delete(&format!("{PLANS}/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.delete(&format!("{PLANS}/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let actions: Vec<String> =
        audit_actions(&node, &admin).await.iter().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    for a in [
        "entitlements.plan_create",
        "entitlements.plan_update",
        "entitlements.plan_delete",
        "entitlements.grant_create",
        "entitlements.grant_delete",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a} missing in {actions:?}");
    }
}

#[tokio::test]
async fn grants_validate_subjects_expiry_and_list_filters() {
    let (node, admin, bob) = node_with(|_| {}).await;
    let room = node.create_room(&bob.token, "Bob's room").await;
    let room_id = room["id"].as_str().unwrap();
    for (body, status, code) in [
        (
            json!({ "subject": "bob", "overrides": { "rooms.max_owned": 9 } }),
            StatusCode::BAD_REQUEST,
            "entitlements.subject_invalid",
        ),
        (
            json!({ "subject": "group:x", "overrides": { "rooms.max_owned": 9 } }),
            StatusCode::BAD_REQUEST,
            "entitlements.subject_invalid",
        ),
        (
            json!({ "subject": "user:carol", "overrides": { "rooms.max_owned": 9 } }),
            StatusCode::NOT_FOUND,
            "user.not_found",
        ),
        // A grant can never extend what a user of another node may do.
        (
            json!({ "subject": "user:mallory@evil.example", "overrides": { "rooms.max_owned": 9 } }),
            StatusCode::BAD_REQUEST,
            "entitlements.subject_not_local",
        ),
        (
            json!({ "subject": "room:01J9ZZZZZZZZZZZZZZZZZZZZZZ", "overrides": { "rooms.max_owned": 9 } }),
            StatusCode::NOT_FOUND,
            "room.not_found",
        ),
        (json!({ "subject": "user:bob" }), StatusCode::BAD_REQUEST, "entitlements.grant_empty"),
        (
            json!({ "subject": "user:bob", "plan_id": "01J9ZZZZZZZZZZZZZZZZZZZZZZ" }),
            StatusCode::NOT_FOUND,
            "entitlements.plan_not_found",
        ),
        (
            json!({ "subject": "user:bob", "overrides": { "rooms.max_owned": 9 }, "expires_at": "2020-01-01T00:00:00Z" }),
            StatusCode::BAD_REQUEST,
            "entitlements.expiry_past",
        ),
        (
            json!({ "subject": "user:bob", "overrides": { "rooms.max_owned": 9 }, "expires_at": "tomorrow" }),
            StatusCode::BAD_REQUEST,
            "validation.time",
        ),
        (
            json!({ "subject": "user:bob", "overrides": { "rooms.max_owned": 9 }, "note": "x".repeat(501) }),
            StatusCode::BAD_REQUEST,
            "validation.length",
        ),
    ] {
        let (s, j) = node.post(GRANTS, &admin.token, body.clone()).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{body}: {j}");
    }

    let (s, g1) = node
        .post(GRANTS, &admin.token, json!({ "subject": "user:bob@t.local", "overrides": { "rooms.max_owned": 9 }, "expires_at": "2099-01-01T00:00:00+02:00", "note": "Subscription #1" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g1}");
    assert_eq!(g1["subject"], format!("user:{}", bob.user_id));
    assert_eq!(g1["subject_label"], "bob@t.local");
    assert_eq!(g1["expires_at"], "2098-12-31T22:00:00.000Z", "normalized to UTC");
    assert_eq!(g1["values"]["rooms.max_owned"], 9);
    let (s, g2) = node
        .post(
            GRANTS,
            &admin.token,
            json!({ "subject": format!("room:{room_id}"), "overrides": { "emoji.max_per_room": 7 } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{g2}");
    assert_eq!(g2["subject_label"], "Bob's room");

    let (_, all) = node.get_auth(GRANTS, &admin.token).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, of_room) = node.get_auth(&format!("{GRANTS}?subject=room:{room_id}"), &admin.token).await;
    assert_eq!(of_room.as_array().unwrap().len(), 1);
    let (_, page) = node.get_auth(&format!("{GRANTS}?limit=1"), &admin.token).await;
    assert_eq!(page.as_array().unwrap().len(), 1);
    let (_, next) =
        node.get_auth(&format!("{GRANTS}?limit=1&after={}", page[0]["id"].as_str().unwrap()), &admin.token).await;
    assert_eq!(next[0]["id"], g2["id"]);

    // Expired grants are listed only on request and are ignored by the evaluation.
    let id1 = g1["id"].as_str().unwrap();
    sqlx::query("UPDATE entitlement_grants SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = $1")
        .bind(id1)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (_, bobs) = node.get_auth(&format!("{GRANTS}?subject=user:{}", bob.user_id), &admin.token).await;
    assert_eq!(bobs.as_array().unwrap().len(), 0);
    let (_, bobs) = node.get_auth(&format!("{GRANTS}?subject=user:bob&include_expired=true"), &admin.token).await;
    assert_eq!(bobs[0]["expired"], true);
    let (_, eff) = node.get_auth("/api/v1/admin/entitlements/effective?user=bob", &admin.token).await;
    assert_eq!(eff["values"]["rooms.max_owned"], 5, "expired grant ignored: {eff}");

    // PATCH: extend the expiry, clear it, change overrides; past expiry refused.
    let (s, j) =
        node.patch(&format!("{GRANTS}/{id1}"), &admin.token, json!({ "expires_at": "2020-01-01T00:00:00Z" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("entitlements.expiry_past")));
    let (s, j) = node
        .patch(
            &format!("{GRANTS}/{id1}"),
            &admin.token,
            json!({ "expires_at": null, "overrides": { "rooms.max_owned": 0 } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["expires_at"], Value::Null);
    assert_eq!(j["expired"], false);
    assert_eq!(j["note"], "Subscription #1", "untouched fields stay");
    let (_, eff) =
        node.get_auth(&format!("/api/v1/admin/entitlements/effective?user=bob&room={room_id}"), &admin.token).await;
    assert_eq!(eff["values"]["rooms.max_owned"], 0, "0 = unlimited: {eff}");
    assert_eq!(eff["values"]["emoji.max_per_room"], 100, "a lower room grant never shrinks the node default");
    assert_eq!(eff["node_defaults"]["emoji.max_per_room"], 100);
    let (s, j) = node.patch(&format!("{GRANTS}/{id1}"), &admin.token, json!({ "overrides": {} })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("entitlements.grant_empty")));
    let (s, _) =
        node.patch(&format!("{GRANTS}/01J9ZZZZZZZZZZZZZZZZZZZZZZ"), &admin.token, json!({ "note": "x" })).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Housekeeping removes grants a week after their expiry and grants of deleted subjects.
    sqlx::query("UPDATE entitlement_grants SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = $1")
        .bind(id1)
        .execute(&node.state.db)
        .await
        .unwrap();
    let cutoff = tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::days(7));
    assert_eq!(tavrn_node::store::entitlements::prune_grants(&node.state.db, &cutoff).await.unwrap(), 1);
    let (_, left) = node.get_auth(&format!("{GRANTS}?include_expired=true"), &admin.token).await;
    assert_eq!(left.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn room_creation_follows_rooms_max_owned() {
    let (node, admin, bob) = node_with(|c| c.max_rooms_per_user = 1).await;
    node.create_room(&bob.token, "One").await;
    let (s, j) = node.post("/api/v1/rooms", &bob.token, json!({ "name": "Two" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.limit_reached")), "{j}");
    assert_eq!(j["meta"]["max"], 1);
    let (s, _) =
        node.post(GRANTS, &admin.token, json!({ "subject": "user:bob", "overrides": { "rooms.max_owned": 2 } })).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, j) = node.post("/api/v1/rooms", &bob.token, json!({ "name": "Two" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, _) = node.post("/api/v1/rooms", &bob.token, json!({ "name": "Three" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Node admins are unlimited.
    for name in ["A", "B"] {
        let (s, j) = node.post("/api/v1/rooms", &admin.token, json!({ "name": name })).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    let (_, me) = node.get_auth("/api/v1/users/me/entitlements", &bob.token).await;
    assert_eq!(me["values"]["rooms.max_owned"], 2);
    assert_eq!(me["retention_bound_days"], Value::Null);
}

#[tokio::test]
async fn upload_size_and_room_storage_follow_grants() {
    let (node, admin, bob) = node_with(|c| {
        c.upload_max_bytes = 1000;
        c.upload_max_bytes_ceiling = 10_000;
        c.storage_quota_per_room_bytes = 3000;
    })
    .await;
    let carol = node.register("carol").await;
    let room = node.plaintext_room(&bob.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &bob.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;

    let (s, j) = upload(&node, &bob.token, &room_id, &channel, vec![b'a'; 2000]).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("upload.too_large")), "{j}");
    assert_eq!(j["meta"]["max_bytes"], 1000);

    // A user grant raises bob's uploads everywhere, not carol's.
    node.post(GRANTS, &admin.token, json!({ "subject": "user:bob", "overrides": { "upload.max_bytes": 5000 } })).await;
    let (s, j) = upload(&node, &bob.token, &room_id, &channel, vec![b'a'; 2000]).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, _) = upload(&node, &carol.token, &room_id, &channel, vec![b'a'; 2000]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let conv = &channel;
    let (_, policy) = node.get_auth(&format!("/api/v1/conversations/{conv}/upload-policy"), &bob.token).await;
    assert_eq!(policy["max_bytes"], 5000);
    let (_, policy) = node.get_auth(&format!("/api/v1/conversations/{conv}/upload-policy"), &carol.token).await;
    assert_eq!(policy["max_bytes"], 1000);
    // Unlimited in a grant still stops at the ceiling.
    node.post(
        GRANTS,
        &admin.token,
        json!({ "subject": format!("room:{room_id}"), "overrides": { "upload.max_bytes": 0 } }),
    )
    .await;
    let (_, me) = node.get_auth(&format!("/api/v1/users/me/entitlements?room={room_id}"), &carol.token).await;
    assert_eq!(me["upload_max_bytes"], 10_000, "{me}");
    let (s, _) = upload(&node, &carol.token, &room_id, &channel, vec![b'a'; 10_001]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    // Storage per room: 2000 used of 3000.
    let (s, j) = upload(&node, &carol.token, &room_id, &channel, vec![b'a'; 1500]).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("upload.quota_exceeded")), "{j}");
    node.post(
        GRANTS,
        &admin.token,
        json!({ "subject": format!("room:{room_id}"), "overrides": { "storage.max_bytes_per_room": 100_000 } }),
    )
    .await;
    let (s, j) = upload(&node, &carol.token, &room_id, &channel, vec![b'a'; 1500]).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Non-members cannot read a room's entitlements.
    let dave = node.register("dave").await;
    let (s, _) = node.get_auth(&format!("/api/v1/users/me/entitlements?room={room_id}"), &dave.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn emoji_and_sound_counts_use_the_owners_and_rooms_grants() {
    let (node, admin, bob) = node_with(|c| {
        c.emoji_max_per_room = 1;
        c.sounds_max_per_room = 0;
    })
    .await;
    let room = node.create_room(&bob.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let emoji = |name: &'static str| {
        let req = Request::post(format!("/api/v1/rooms/{room_id}/emojis"))
            .header(header::AUTHORIZATION, format!("Bearer {}", bob.token))
            .header(header::CONTENT_TYPE, "image/png")
            .header("tavrn-emoji-name", name)
            // A valid 1×1 PNG: emojis are converted by the media pipeline.
            .body(Body::from(b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0d\x49\x44\x41\x54\x78\xda\x63\x64\xf8\xcf\x50\x0f\x00\x03\x86\x01\x80\x5a\x34\x7d\x6b\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82".to_vec()))
            .unwrap();
        let router = node.router.clone();
        async move { router.oneshot(req).await.unwrap().status() }
    };
    assert_eq!(emoji("one").await, StatusCode::CREATED);
    assert_eq!(emoji("two").await, StatusCode::FORBIDDEN);
    node.post(GRANTS, &admin.token, json!({ "subject": "user:bob", "overrides": { "emoji.max_per_room": 3 } })).await;
    assert_eq!(emoji("two").await, StatusCode::CREATED, "the owner's grant covers the room");
    let (_, me) = node.get_auth(&format!("/api/v1/users/me/entitlements?room={room_id}"), &bob.token).await;
    assert_eq!(me["values"]["emoji.max_per_room"], 3);
    assert_eq!(me["values"]["sounds.max_per_room"], 0, "0 = unlimited");
}

#[tokio::test]
async fn voice_participant_cap_and_stream_limits_come_with_the_token() {
    let (node, admin, bob) = node_with(|c| {
        c.voice_channel_max_participants = 1;
        c.stream_max_height = 720;
    })
    .await;
    let carol = node.register("carol").await;
    let room = node.create_room(&bob.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let voice = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &bob.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    let join = format!("/api/v1/rooms/{room_id}/channels/{voice}/voice/join");
    let (s, j) = node.post(&join, &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["limits"]["stream_max_height"], 720);
    assert_eq!(j["limits"]["stream_max_fps"], 0);
    assert_eq!(j["limits"]["camera_max_height"], 0);
    let (s, j) = node.post(&join, &carol.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.participant_limit")), "{j}");
    assert_eq!(j["meta"]["limit"], 1);
    // A room grant raises the cap; a user grant raises carol's stream height.
    node.post(
        GRANTS,
        &admin.token,
        json!({ "subject": format!("room:{room_id}"), "overrides": { "voice.max_participants": 5 } }),
    )
    .await;
    node.post(GRANTS, &admin.token, json!({ "subject": "user:carol", "overrides": { "stream.max_height": 1440 } }))
        .await;
    let (s, j) = node.post(&join, &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["limits"]["stream_max_height"], 1440);
}

// ---------------------------------------------------------------- Admin API tokens

async fn create_token(node: &TestNode, admin: &Session, scopes: &[&str]) -> (String, String) {
    let (s, j) = node.post("/api/v1/admin/tokens", &admin.token, json!({ "name": "Billing", "scopes": scopes })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    (j["id"].as_str().unwrap().to_string(), j["secret"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn admin_tokens_are_scoped_to_admin_routes() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let bob = node.register("bob").await;
    let (id, secret) = create_token(&node, &admin, &["entitlements"]).await;
    assert!(secret.starts_with("tavrn_adm_"), "{secret}");

    // Allowed: the entitlements routes.
    let (s, j) = node.post(PLANS, &secret, json!({ "name": "Basic", "limits": { "rooms.max_owned": 3 } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.post(GRANTS, &secret, json!({ "subject": "user:bob", "plan_id": j["id"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["created_by"], admin.user_id.as_str(), "the token acts as its creator");

    // Not an admin route: 401, whatever the route (fail closed).
    for path in ["/api/v1/users/me", "/api/v1/rooms", "/api/v1/users/me/entitlements", "/api/v1/conversations"] {
        let (s, j) = node.get_auth(path, &secret).await;
        assert_eq!(
            (s, j["code"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("auth.admin_token_not_allowed")),
            "{path}: {j}"
        );
    }
    let err = tavrn_node::auth::authenticate(&node.state, &secret).await.unwrap_err();
    assert_eq!(err.code(), "auth.admin_token_not_allowed", "the WebSocket authenticates through this function");
    let (s, _) = node.post("/api/v1/rooms", &secret, json!({ "name": "x" })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Admin routes outside the scopes.
    let (s, j) = node.get_auth("/api/v1/admin/users", &secret).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("admin_token.scope_missing")), "{j}");
    assert_eq!(j["meta"]["scope"], "users:read");
    for path in ["/api/v1/admin/overview", "/api/v1/admin/audit-log", "/api/v1/admin/bans", "/api/v1/admin/tokens"] {
        let (s, j) = node.get_auth(path, &secret).await;
        assert_eq!(
            (s, j["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("admin_token.route_forbidden")),
            "{path}: {j}"
        );
    }
    // A token cannot mint tokens or escalate.
    let (s, _) = node.post("/api/v1/admin/tokens", &secret, json!({ "name": "x", "scopes": ["users:write"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) =
        node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &secret, json!({ "node_admin": true })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Every call is audit-logged with the token's name; the secret appears nowhere.
    let log = audit_actions(&node, &admin).await;
    let calls: Vec<&Value> = log.iter().filter(|e| e["action"] == "admin.token_call").collect();
    assert!(calls.len() >= 2, "{log:?}");
    assert!(calls.iter().all(|e| e["reason"] == "Billing"), "{calls:?}");
    assert!(!serde_json::to_string(&log).unwrap().contains(secret.split('.').nth(1).unwrap()));
    let (_, list) = node.get_auth("/api/v1/admin/tokens", &admin.token).await;
    assert_eq!(list[0]["id"], id.as_str());
    assert_eq!(list[0]["name"], "Billing");
    assert!(list[0]["last_used_at"].is_string());
    assert!(list[0].get("secret").is_none() && list[0].get("token_hash").is_none(), "{list}");
    assert!(!list.to_string().contains(secret.split('.').nth(1).unwrap()));
}

#[tokio::test]
async fn admin_tokens_scopes_expiry_revocation_and_creator() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let admin2 = node.register("admin2").await;
    node.patch(&format!("/api/v1/admin/users/{}", admin2.user_id), &admin.token, json!({ "node_admin": true })).await;
    let bob = node.register("bob").await;

    // Validation.
    for body in [
        json!({ "name": "x", "scopes": [] }),
        json!({ "name": "x", "scopes": ["root"] }),
        json!({ "name": "", "scopes": ["invites"] }),
        json!({ "name": "x", "scopes": ["invites"], "expires_at": "2001-01-01T00:00:00Z" }),
    ] {
        let (s, j) = node.post("/api/v1/admin/tokens", &admin.token, body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}: {j}");
    }
    let (s, _) = node.post("/api/v1/admin/tokens", &bob.token, json!({ "name": "x", "scopes": ["invites"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // users:read reads, users:write writes; invites.
    let (_, read) = create_token(&node, &admin2, &["users:read", "invites"]).await;
    let (s, j) = node.get_auth("/api/v1/admin/users", &read).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &read, json!({ "disabled": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("admin_token.scope_missing")));
    let (s, j) = node.post("/api/v1/admin/invites", &read, json!({ "note": "per API" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, write) = create_token(&node, &admin2, &["users:write"]).await;
    let (s, j) =
        node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &write, json!({ "room_creation_grant": 3 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Destructive routes stay closed to tokens even with users:write.
    let (s, _) = node.post(&format!("/api/v1/admin/users/{}/purge", bob.user_id), &write, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Tampered secret, unknown id, garbage.
    let tampered = format!("{}x", &write[..write.len() - 1]);
    for bad in [tampered.as_str(), "tavrn_adm_01J9ZZZZZZZZZZZZZZZZZZZZZZ.abc", "tavrn_adm_", "tavrn_adm_x.y"] {
        let (s, j) = node.get_auth("/api/v1/admin/users", bad).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.token_invalid")), "{bad}: {j}");
    }

    // Expired.
    let (eid, expired) = create_token(&node, &admin2, &["users:read"]).await;
    sqlx::query("UPDATE admin_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = $1")
        .bind(&eid)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) = node.get_auth("/api/v1/admin/users", &expired).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.token_expired")), "{j}");
    let (_, list) = node.get_auth("/api/v1/admin/tokens", &admin.token).await;
    assert!(list.as_array().unwrap().iter().any(|t| t["id"] == eid.as_str() && t["expired"] == true));

    // Revoked.
    let (rid, revoked) = create_token(&node, &admin, &["users:read"]).await;
    let (s, _) = node.get_auth("/api/v1/admin/users", &revoked).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node.delete(&format!("/api/v1/admin/tokens/{rid}"), &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.get_auth("/api/v1/admin/users", &revoked).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = node.delete(&format!("/api/v1/admin/tokens/{rid}"), &admin.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The creator loses the admin right: the token stops working.
    node.patch(&format!("/api/v1/admin/users/{}", admin2.user_id), &admin.token, json!({ "node_admin": false })).await;
    let (s, j) = node.get_auth("/api/v1/admin/users", &read).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")), "{j}");

    let actions: Vec<String> =
        audit_actions(&node, &admin).await.iter().map(|e| e["action"].as_str().unwrap().to_string()).collect();
    assert!(actions.contains(&"admin.token_create".to_string()) && actions.contains(&"admin.token_revoke".to_string()));
}
