// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Direct messages and group DMs.
use crate::common;

use axum::http::{Method, StatusCode};
use common::e2ee::{DOMAIN, qualified};
use common::{body_bytes, test_node, test_node_with};
use serde_json::json;
use tavrn_node::{config::DmPolicy, hub::Scope};

#[tokio::test]
async fn dm_requires_friendship_and_is_idempotent() {
    // The operator's bound `friends`: no message requests at all.
    let node = test_node_with(DOMAIN, |c| c.dm_policy = DmPolicy::Friends).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;

    let dm = |members: serde_json::Value| json!({ "kind": "dm", "members": members });
    let (s, j) = node.post("/api/v1/conversations", &alice.token, dm(json!(["bob@t.local"]))).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "dm.not_friends");
    node.befriend(&alice, &bob).await;

    let mut rx = node.state.hub.subscribe();
    let (s, first) = node.post("/api/v1/conversations", &alice.token, dm(json!(["bob@t.local"]))).await;
    assert_eq!(s, StatusCode::CREATED, "{first}");
    assert_eq!(first["kind"], "dm");
    assert_eq!(first["encrypted"], true);
    let members: Vec<&str> =
        first["members"].as_array().unwrap().iter().map(|m| m["address"].as_str().unwrap()).collect();
    assert_eq!(members.len(), 2);
    assert!(members.contains(&"alice@t.local") && members.contains(&"bob@t.local"));
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.kind, "conversation.create");
    assert!(matches!(&ev.scope, Scope::Users(u) if u.contains(&bob.user_id) && u.contains(&alice.user_id)));

    // Idempotent in both directions, also with a bare username.
    let (s, again) = node.post("/api/v1/conversations", &alice.token, dm(json!(["bob"]))).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["id"], first["id"]);
    let (s, back) = node.post("/api/v1/conversations", &bob.token, dm(json!(["alice@t.local"]))).await;
    assert_eq!(s, StatusCode::OK, "{back}");
    assert_eq!(back["id"], first["id"]);

    for (body, status, code) in [
        (dm(json!(["alice@t.local"])), StatusCode::BAD_REQUEST, "conversation.self"),
        (dm(json!(["nobody@t.local"])), StatusCode::NOT_FOUND, "user.not_found"),
        (dm(json!(["bob@other.invalid"])), StatusCode::BAD_GATEWAY, "federation.peer_unreachable"),
        (dm(json!(["bob@t.local", "carol@t.local"])), StatusCode::BAD_REQUEST, "conversation.members_invalid"),
        (dm(json!([])), StatusCode::BAD_REQUEST, "conversation.members_invalid"),
        (dm(json!(["not a valid name"])), StatusCode::BAD_REQUEST, "conversation.member_invalid"),
        (json!({ "kind": "channel", "members": ["bob@t.local"] }), StatusCode::BAD_REQUEST, "validation.enum"),
    ] {
        let (s, j) = node.post("/api/v1/conversations", &alice.token, body.clone()).await;
        assert_eq!(s, status, "{body}: {j}");
        assert_eq!(j["code"], code, "{body}");
    }

    let id = first["id"].as_str().unwrap();
    let (_, list) = node.get_auth("/api/v1/conversations", &bob.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"], id);
    let (_, list) = node.get_auth("/api/v1/conversations", &carol.token).await;
    assert_eq!(list, json!([]));
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{id}"), &carol.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "conversation.not_found");
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{id}/messages"), &carol.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _) = node.get_auth("/api/v1/conversations/01J9ZK3G5M8Q2W4E6R8T0Y2V00", &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A room channel id is not a DM: GET /conversations/{id} only serves DMs and group DMs.
    let room = node.create_room(&alice.token, "Room").await;
    let channel = common::TestNode::text_channel(&room);
    let (s, _) = node.get_auth(&format!("/api/v1/conversations/{channel}"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn open_policy_blocks_and_bots() {
    let node = test_node_with(DOMAIN, |c| c.dm_policy = DmPolicy::Everyone).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (s, j) = node.patch("/api/v1/users/me", &carol.token, json!({ "dm_policy": "everyone" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["carol"] })).await;
    assert_eq!(s, StatusCode::CREATED, "open policy: {j}");
    assert_eq!(j["pending"], json!(["carol@t.local"]), "a message request for carol");
    let dm = j["id"].as_str().unwrap().to_string();

    // Carol blocks Alice: no new DMs, no messages in the existing one.
    let (s, j) = node.post("/api/v1/users/me/blocks", &carol.token, json!({ "user": "alice" })).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, j) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["carol"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "dm.blocked");
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{dm}/messages"),
            &alice.token,
            json!({ "content": "Y2lwaGVy", "epoch": 0 }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "dm.blocked");
    let (s, j) =
        node.post("/api/v1/conversations", &carol.token, json!({ "kind": "group", "members": ["alice", "bob"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "whoever blocks does not invite either: {j}");
    let (s, _) = node.delete("/api/v1/users/me/blocks/alice", &carol.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["carol"] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Bots: always reachable by their owner, even under the friends policy.
    let friends_node = test_node_with(DOMAIN, |c| c.dm_policy = DmPolicy::Friends).await;
    let owner = friends_node.register("owner").await;
    let other = friends_node.register("other").await;
    sqlx::query("INSERT INTO users (id, username, domain, display_name, kind, owner_id, created_at) VALUES ('01J9ZK3G5M8Q2W4E6R8T0Y2VB0', 'helper', 't.local', 'Helper', 'bot', $1, '2026-10-04T00:00:00.000Z')")
        .bind(&owner.user_id)
        .execute(&friends_node.state.db)
        .await
        .unwrap();
    let (s, j) =
        friends_node.post("/api/v1/conversations", &owner.token, json!({ "kind": "dm", "members": ["helper"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) =
        friends_node.post("/api/v1/conversations", &other.token, json!({ "kind": "dm", "members": ["helper"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "dm.not_friends");
    let _ = bob;
}

#[tokio::test]
async fn group_dm_membership() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let dave = node.register("dave").await;
    node.befriend(&alice, &bob).await;
    node.befriend(&alice, &carol).await;
    node.befriend(&bob, &dave).await;

    let (s, j) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["bob", "dave"] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "dave is not a friend of alice: {j}");
    assert_eq!(j["code"], "dm.no_shared_room");
    let (s, j) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let fifty: Vec<String> = (0..50).map(|i| format!("user{i}")).collect();
    let (s, j) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": fifty })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "conversation.members_invalid");
    let (s, j) = node
        .post(
            "/api/v1/conversations",
            &alice.token,
            json!({ "kind": "group", "members": ["bob", "carol"], "name": " Team " }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["name"], "Team");
    assert_eq!(j["members"].as_array().unwrap().len(), 3);
    let id = j["id"].as_str().unwrap().to_string();
    let base = format!("/api/v1/conversations/{id}");

    // Any member may add their friends; the new member is told about the conversation.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.post(&format!("{base}/members"), &bob.token, json!({ "user": "dave" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["members"].as_array().unwrap().len(), 4);
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        evs.iter().any(|e| e.kind == "conversation.create"
            && matches!(&e.scope, Scope::Users(u) if u == &vec![dave.user_id.clone()]))
    );
    assert!(evs.iter().any(|e| e.kind == "conversation.update" && matches!(&e.scope, Scope::Users(u) if u.len() == 4)));
    let (s, j) = node.post(&format!("{base}/members"), &bob.token, json!({ "user": "dave" })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "conversation.member_exists");
    let (s, j) = node.post(&format!("{base}/members"), &carol.token, json!({ "user": "nobody" })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");

    // Rename by a member; DMs have no name.
    let (s, j) = node.patch(&base, &dave.token, json!({ "name": "New" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["name"], "New");
    let (s, j) = node.patch(&base, &dave.token, json!({ "name": "x".repeat(101) })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    // Only the creator removes others; everybody may leave.
    let (s, j) = node.delete(&format!("{base}/members/carol"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "conversation.remove_forbidden");
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.delete(&format!("{base}/members/carol"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        evs.iter().any(|e| e.kind == "conversation.leave"
            && matches!(&e.scope, Scope::Users(u) if u == &vec![carol.user_id.clone()]))
    );
    let (s, _) = node.get_auth(&base, &carol.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = node.delete(&format!("{base}/members/dave"), &dave.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "left");
    let (s, _) = node.delete(&format!("{base}/members/dave"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, j) = node.get_auth(&base, &alice.token).await;
    assert_eq!(j["members"].as_array().unwrap().len(), 2);

    // DMs are not groups.
    let dm = node.create_dm(&alice, &bob).await;
    let (s, j) = node.patch(&format!("/api/v1/conversations/{dm}"), &alice.token, json!({ "name": "x" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "conversation.not_group");
    let (s, j) =
        node.post(&format!("/api/v1/conversations/{dm}/members"), &alice.token, json!({ "user": "carol" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "conversation.not_group");
    let (s, j) = node.delete(&format!("/api/v1/conversations/{dm}/members/bob"), &alice.token).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
}

#[tokio::test]
async fn group_dm_leave_asks_for_mls_removal() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let carol = node.crypto_user("carol").await;
    node.befriend(&alice.session, &bob.session).await;
    node.befriend(&alice.session, &carol.session).await;
    let (_, j) = node
        .post("/api/v1/conversations", alice.token(), json!({ "kind": "group", "members": ["bob", "carol"] }))
        .await;
    let id = j["id"].as_str().unwrap().to_string();
    node.create_group(&mut alice, &id).await;
    node.add_user(&mut alice, &id, "bob").await;
    node.accept_welcomes(&mut bob).await;

    let mut rx = node.state.hub.subscribe();
    let (s, _) = node.delete(&format!("/api/v1/conversations/{id}/members/bob"), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let needed = evs.iter().find(|e| e.kind == "mls.remove_needed").expect("mls.remove_needed");
    assert_eq!(needed.data["identities"], json!([bob.identity()]));
    assert!(
        matches!(&needed.scope, Scope::Users(u) if !u.contains(&bob.session.user_id) && u.contains(&carol.session.user_id))
    );
    let rm = alice.client.remove_members(&qualified(&id), &[bob.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &id, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{id}/mls/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
}

#[tokio::test]
async fn dm_messages_reactions_pins_and_attachments() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    node.add_user(&mut alice, &dm, "bob").await;
    node.accept_welcomes(&mut bob).await;
    let base = format!("/api/v1/conversations/{dm}");

    // Encrypted attachment: the node stores no name and no type.
    let (s, headers, body) = node
        .raw(
            Method::POST,
            &format!("{base}/uploads"),
            alice.token(),
            &[("content-type", "image/png"), ("tavrn-file-name", "secret.png")],
            vec![7u8; 100],
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{headers:?}");
    let blob: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(blob["name"], "");
    assert_eq!(blob["mime"], "application/octet-stream");
    let (s, _, _) = node.raw(Method::POST, &format!("{base}/uploads"), &carol.token, &[], vec![1u8; 10]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let mut rx = node.state.hub.subscribe();
    let conv = qualified(&dm);
    let content = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"Bild"}"#).unwrap();
    let (s, m) = node
        .post(
            &format!("{base}/messages"),
            alice.token(),
            json!({ "content": content, "epoch": 1, "attachments": [blob["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["attachments"][0]["name"], "");
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.kind, "message.create");
    assert!(matches!(&ev.scope, Scope::Users(u) if u.contains(&bob.session.user_id) && u.len() == 2));
    let mid = m["id"].as_str().unwrap();

    let blob_id = blob["id"].as_str().unwrap();
    let resp = node.get_with(&format!("/api/v1/blobs/{blob_id}"), bob.token()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(body_bytes(resp).await.len(), 100);
    let resp = node.get_with(&format!("/api/v1/blobs/{blob_id}"), &carol.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let (s, j) = node.put(&format!("{base}/messages/{mid}/reactions/👍"), bob.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["reactions"][0]["count"], 1);
    let (s, j) = node.put(&format!("{base}/pins/{mid}"), bob.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["pinned"], true);
    let (_, pins) = node.get_auth(&format!("{base}/pins"), alice.token()).await;
    assert_eq!(pins["messages"].as_array().unwrap().len(), 1);
    let (s, _) = node.put(&format!("{base}/messages/{mid}/reactions/👍"), &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, j) = node.delete(&format!("{base}/messages/{mid}"), bob.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "other people's messages in DMs cannot be deleted: {j}");
    let (s, _) = node.delete(&format!("{base}/messages/{mid}"), alice.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth(&format!("{base}/messages"), bob.token()).await;
    assert_eq!(list, json!([]));
    let (_, convs) = node.get_auth("/api/v1/conversations", bob.token()).await;
    assert!(convs[0]["last_message_id"].is_null());
}
