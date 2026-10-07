// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Reports with evidence (protocol MODERATION.md §1): targets and routing, evidence for encrypted messages and
//! snapshots of plaintext ones, the inbox of room moderators and node admins, merging, limits, action shortcuts,
//! events and retention.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_node::hub::Event;
use tokio::sync::broadcast;

const DOMAIN: &str = "t.local";

/// A node with an admin (the first account), a room owned by alice with a plaintext channel, a moderator
/// (role with `moderate_members`, `manage_messages`, `kick_members`, `ban_members`, `purge`) and two members.
struct World {
    node: TestNode,
    admin: Session,
    alice: Session,
    moder: Session,
    bob: Session,
    carol: Session,
    room_id: String,
    channel: String,
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

async fn world_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> World {
    let node = test_node_with(DOMAIN, tweak).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let moder = node.register("moder").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.plaintext_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    for who in [&moder, &bob, &carol] {
        join(&node, &alice, &room_id, who).await;
    }
    let perms = common::perms(&[1 << 0, 1 << 1, 1 << 2, 1 << 11, 1 << 12, 1 << 13, 1 << 14, 1 << 15]);
    let (s, role) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Mods", "permissions": perms }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", moder.user_id),
            &alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    World { node, admin, alice, moder, bob, carol, room_id, channel }
}

async fn world() -> World {
    world_with(|_| {}).await
}

async fn report(node: &TestNode, token: &str, body: Value) -> (StatusCode, Value) {
    node.post("/api/v1/reports", token, body).await
}

fn ids(list: &Value) -> Vec<String> {
    list["reports"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
}

async fn hub_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str) -> Arc<Event> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind {
            return ev;
        }
    }
}

fn audience(ev: &Event) -> Vec<String> {
    match &ev.scope {
        tavrn_node::hub::Scope::Users(ids) => {
            let mut v = ids.clone();
            v.sort();
            v
        }
        other => panic!("unexpected scope {other:?}"),
    }
}

#[tokio::test]
async fn a_plaintext_message_report_reaches_the_room_moderators_with_a_snapshot() {
    let w = world().await;
    let (s, msg) = w.node.send(&w.carol.token, &w.room_id, &w.channel, "buy cheap coins now").await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let mid = msg["id"].as_str().unwrap();
    let mut rx = w.node.state.hub.subscribe();

    // Evidence is only for encrypted messages: the node links plaintext ones itself.
    let body = json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "spam",
        "evidence": [{ "message_id": mid, "author": "carol@t.local", "created_at": msg["created_at"], "text": "x", "attachments": [] }] });
    let (s, j) = report(&w.node, &w.bob.token, body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.evidence_not_allowed")), "{j}");

    let (s, created) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "spam", "detail": "Coin spam" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    assert_eq!((created["status"].as_str(), created["merged"].as_bool()), (Some("open"), Some(false)));
    let id = created["id"].as_str().unwrap().to_string();

    // report.create to the owner, the moderator and the node admin; never to the reported user.
    let ev = hub_event(&mut rx, "report.create").await;
    let mut expected = vec![w.admin.user_id.clone(), w.alice.user_id.clone(), w.moder.user_id.clone()];
    expected.sort();
    assert_eq!(audience(&ev), expected);
    assert_eq!(ev.data["report"]["id"], id.as_str());
    assert_eq!(ev.data["report"]["room_name"], "Guild");
    assert!(ev.data["report"].get("detail").is_none(), "no detail in the event: {}", ev.data);

    // The inbox: moderators and node admins; members and the reported user get 403.
    let path = format!("/api/v1/rooms/{}/reports", w.room_id);
    for token in [&w.bob.token, &w.carol.token] {
        let (s, j) = w.node.get_auth(&path, token).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("report.view_forbidden")), "{j}");
        let (s, _) = w.node.get_auth(&format!("/api/v1/reports/{id}"), token).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "a report is invisible to whoever may not see it");
    }
    for token in [&w.moder.token, &w.alice.token, &w.admin.token] {
        let (s, list) = w.node.get_auth(&path, token).await;
        assert_eq!(s, StatusCode::OK, "{list}");
        assert_eq!(ids(&list), vec![id.clone()]);
        assert_eq!(list["open"], 1);
    }
    let (_, list) = w.node.get_auth(&path, &w.moder.token).await;
    let r = &list["reports"][0];
    assert_eq!(
        (r["scope"].as_str(), r["kind"].as_str(), r["source"].as_str()),
        (Some("room"), Some("message"), Some("user"))
    );
    assert_eq!(r["reporter"]["address"], "bob@t.local", "reports are not anonymous");
    assert_eq!(r["target"]["address"], "carol@t.local");
    assert_eq!(r["snapshot"]["text"], "buy cheap coins now");
    assert_eq!(r["snapshot"]["author"], "carol@t.local");
    assert_eq!(r["conversation_kind"], "channel");
    assert!(r["evidence"].is_null() && r["evidence_count"] == 0, "{r}");

    // The snapshot outlives the message.
    let (s, _) = w.node.delete(&format!("/api/v1/conversations/{}/messages/{mid}", w.channel), &w.carol.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, detail) = w.node.get_auth(&format!("/api/v1/reports/{id}"), &w.moder.token).await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    assert_eq!(detail["snapshot"]["text"], "buy cheap coins now");
    assert_eq!(detail["message_exists"], false);
    let (_, admin_list) = w.node.get_auth("/api/v1/admin/reports", &w.admin.token).await;
    assert_eq!(ids(&admin_list), vec![id.clone()]);
    let (s, j) = w.node.get_auth("/api/v1/admin/reports", &w.moder.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")));
}

#[tokio::test]
async fn targets_are_checked() {
    let w = world().await;
    let (_, msg) = w.node.send(&w.carol.token, &w.room_id, &w.channel, "hello").await;
    let mid = msg["id"].as_str().unwrap();
    let outsider = w.node.register("outsider").await;
    let cases = [
        (
            json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "nope" }),
            "report.category_invalid",
        ),
        (json!({ "kind": "thing", "category": "spam" }), "report.target_invalid"),
        (json!({ "kind": "message", "conversation_id": w.channel, "category": "spam" }), "report.target_invalid"),
        (json!({ "kind": "user", "category": "spam" }), "report.target_invalid"),
        (json!({ "kind": "user", "user": "bob@t.local", "category": "spam" }), "report.self"),
        (
            json!({ "kind": "user", "user": "carol@t.local", "category": "spam", "detail": "x".repeat(2001) }),
            "validation.length",
        ),
    ];
    for (body, code) in cases {
        let (s, j) = report(&w.node, &w.bob.token, body.clone()).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}: {j}");
    }
    // Not readable for the reporter: the same 404 as an unknown message.
    let (s, j) = report(
        &w.node,
        &outsider.token,
        json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "spam" }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "message", "conversation_id": w.channel, "message_id": "01J00000000000000000000000", "category": "spam" }),
    )
    .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("message.not_found")), "{j}");
    let (s, j) =
        report(&w.node, &w.bob.token, json!({ "kind": "user", "user": "ghost@t.local", "category": "spam" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("user.not_found")), "{j}");
    // A room context the reporter does not belong to.
    let (s, j) = report(
        &w.node,
        &outsider.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "harassment" }),
    )
    .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.not_member")), "{j}");
    // Rooms: members and public rooms only (the room is invite-only).
    let (s, j) =
        report(&w.node, &outsider.token, json!({ "kind": "room", "room_id": w.room_id, "category": "illegal" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("room.not_found")), "{j}");
}

#[tokio::test]
async fn routing_room_owner_dms_users_and_rooms_go_to_the_node_admins() {
    let w = world().await;
    // A user reported with the room as context: the room's moderators.
    let (s, in_room) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "harassment" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{in_room}");
    // The owner reported: node admins only, moderators cannot act against the owner.
    let (s, owner) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "alice@t.local", "room_id": w.room_id, "category": "harassment" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{owner}");
    // A user without context and a room: node admins.
    let (s, user) =
        report(&w.node, &w.bob.token, json!({ "kind": "user", "user": "carol@t.local", "category": "spam" })).await;
    assert_eq!(s, StatusCode::CREATED, "{user}");
    let (s, room) =
        report(&w.node, &w.bob.token, json!({ "kind": "room", "room_id": w.room_id, "category": "illegal" })).await;
    assert_eq!(s, StatusCode::CREATED, "{room}");

    let path = format!("/api/v1/rooms/{}/reports", w.room_id);
    let (_, list) = w.node.get_auth(&path, &w.moder.token).await;
    assert_eq!(ids(&list), vec![in_room["id"].as_str().unwrap().to_string()]);
    let (_, list) = w.node.get_auth("/api/v1/admin/reports?scope=node", &w.admin.token).await;
    let mut got = ids(&list);
    got.sort();
    let mut want: Vec<String> = [&owner, &user, &room].iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    want.sort();
    assert_eq!(got, want);
    let (_, list) = w.node.get_auth("/api/v1/admin/reports", &w.admin.token).await;
    assert_eq!(list["reports"].as_array().unwrap().len(), 4);
    assert_eq!(list["open"], 4);
    // A moderator never sees reports about themselves.
    let (s, about_mod) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "moder@t.local", "room_id": w.room_id, "category": "other" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{about_mod}");
    let (_, list) = w.node.get_auth(&path, &w.moder.token).await;
    assert!(!ids(&list).contains(&about_mod["id"].as_str().unwrap().to_string()));
    let (s, _) =
        w.node.get_auth(&format!("/api/v1/reports/{}", about_mod["id"].as_str().unwrap()), &w.moder.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = w.node.get_auth(&path, &w.alice.token).await;
    assert!(ids(&list).contains(&about_mod["id"].as_str().unwrap().to_string()), "the owner sees it");
}

#[tokio::test]
async fn encrypted_messages_carry_reporter_released_evidence() {
    let node = test_node(DOMAIN).await;
    let admin = node.register("admin").await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(alice.token(), "Secret").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    join(&node, &alice.session, &room_id, &bob).await;
    node.create_group(&mut alice, &channel).await;
    let (s, older) = node.send_encrypted(&alice, &channel, "you are all idiots").await;
    assert_eq!(s, StatusCode::CREATED, "{older}");
    let (s, msg) = node.send_encrypted(&alice, &channel, "i know where you live").await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let mid = msg["id"].as_str().unwrap().to_string();
    let entry = |m: &Value, text: &str| json!({ "message_id": m["id"], "author": "alice@t.local", "device_id": m["device_id"], "created_at": m["created_at"], "text": text, "attachments": ["photo.jpg"] });
    // The reported message must be part of the evidence, entries are limited.
    let bad = json!({ "kind": "message", "conversation_id": channel, "message_id": mid, "category": "harassment",
        "evidence": [entry(&older, "you are all idiots")] });
    let (s, j) = report(&node, &bob.token, bad).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.evidence_invalid")), "{j}");
    let too_many: Vec<Value> = (0..12).map(|_| entry(&msg, "x")).collect();
    let (s, j) = report(
        &node,
        &bob.token,
        json!({ "kind": "message", "conversation_id": channel, "message_id": mid, "category": "harassment", "evidence": too_many }),
    )
    .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.evidence_invalid")), "{j}");
    let long = json!({ "kind": "message", "conversation_id": channel, "message_id": mid, "category": "harassment",
        "evidence": [entry(&msg, &"y".repeat(4001))] });
    let (s, j) = report(&node, &bob.token, long).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.evidence_invalid")), "{j}");

    let body = json!({ "kind": "message", "conversation_id": channel, "message_id": mid, "category": "harassment",
        "evidence": [entry(&older, "you are all idiots"), entry(&msg, "i know where you live")] });
    let (s, created) = report(&node, &bob.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap();
    // Alice owns the room: the report goes to the node admins only.
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/reports"), alice.token()).await;
    assert_eq!(list["reports"], json!([]));
    let (_, list) = node.get_auth("/api/v1/admin/reports", &admin.token).await;
    assert_eq!(list["reports"][0]["scope"], "node");
    assert_eq!(list["reports"][0]["evidence_count"], 2);
    assert!(list["reports"][0]["evidence"].is_null(), "lists leave the evidence out");
    assert!(list["reports"][0]["snapshot"].is_null(), "no snapshot of ciphertext");
    let (s, detail) = node.get_auth(&format!("/api/v1/reports/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    assert_eq!(detail["evidence_source"], "reporter");
    assert_eq!(detail["evidence"][1]["text"], "i know where you live");
    assert_eq!(detail["evidence"][1]["attachments"][0], "photo.jpg");
    assert_eq!(detail["message_exists"], true);

    // Deleting the report deletes its evidence: node admins only.
    let (s, j) = node.delete(&format!("/api/v1/reports/{id}"), alice.token()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")), "{j}");
    let (s, _) = node.delete(&format!("/api/v1/reports/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let n: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM reports").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn dm_reports_go_to_the_home_node_admins_also_for_dms_on_other_nodes() {
    let node = test_node(DOMAIN).await;
    let admin = node.register("admin").await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.register("bob").await;
    node.befriend(&alice.session, &bob).await;
    let dm = node.create_dm(&alice.session, &bob).await;
    node.create_group(&mut alice, &dm).await;
    let (s, msg) = node.send_encrypted(&alice, &dm, "threat").await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let evidence = json!([{ "message_id": msg["id"], "author": "alice@t.local", "device_id": msg["device_id"], "created_at": msg["created_at"], "text": "threat", "attachments": [] }]);
    let (s, created) = report(
        &node,
        &bob.token,
        json!({ "kind": "message", "conversation_id": dm, "message_id": msg["id"], "category": "violence", "evidence": evidence }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let (_, list) = node.get_auth("/api/v1/admin/reports?scope=node", &admin.token).await;
    assert_eq!(list["reports"][0]["conversation_kind"], "dm");
    assert_eq!(list["reports"][0]["target"]["address"], "alice@t.local");
    assert!(list["reports"][0]["room_id"].is_null());

    // A DM hosted on another node: the home node takes the report with the reporter's evidence only.
    let remote_id = "01J00000000000000000000001";
    let base = json!({ "kind": "message", "conversation_id": remote_id, "message_id": remote_id, "node": "other.example",
        "category": "spam", "evidence": [{ "message_id": remote_id, "author": "mallory@other.example", "created_at": "2026-10-01T10:00:00Z", "text": "spam", "attachments": [] }] });
    let mut no_user = base.clone();
    no_user.as_object_mut().unwrap().remove("user");
    let (s, j) = report(&node, &bob.token, no_user).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.target_invalid")), "{j}");
    let mut with_user = base.clone();
    with_user["user"] = json!("mallory@other.example");
    let (s, created) = report(&node, &bob.token, with_user).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let (_, detail) =
        node.get_auth(&format!("/api/v1/reports/{}", created["id"].as_str().unwrap()), &admin.token).await;
    assert_eq!(
        (detail["node"].as_str(), detail["target_address"].as_str()),
        (Some("other.example"), Some("mallory@other.example"))
    );
    assert!(detail["target"].is_null(), "an address this node does not know");
    assert_eq!(detail["evidence"][0]["text"], "spam");
    // A remote message is no case for the delete shortcut.
    let (s, j) = node
        .post(
            &format!("/api/v1/reports/{}/actions", created["id"].as_str().unwrap()),
            &admin.token,
            json!({ "action": "delete_message" }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("report.target_remote")), "{j}");
}

#[tokio::test]
async fn duplicates_are_merged_and_reports_are_limited_per_hour() {
    let w = world_with(|c| c.reports_rate_per_hour = 2).await;
    let body = |detail: &str| json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "spam", "detail": detail });
    let (s, first) = report(&w.node, &w.bob.token, body("first")).await;
    assert_eq!(s, StatusCode::CREATED, "{first}");
    let (s, again) = report(&w.node, &w.bob.token, body("second")).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!((again["id"].as_str(), again["merged"].as_bool()), (first["id"].as_str(), Some(true)));
    let (_, list) = w.node.get_auth(&format!("/api/v1/rooms/{}/reports", w.room_id), &w.moder.token).await;
    assert_eq!(list["reports"].as_array().unwrap().len(), 1);
    assert_eq!(list["reports"][0]["detail"], "second");
    // Another reporter is another report.
    let (s, _) = report(&w.node, &w.moder.token, body("mod")).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) =
        report(&w.node, &w.bob.token, json!({ "kind": "room", "room_id": w.room_id, "category": "other" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, j) =
        report(&w.node, &w.bob.token, json!({ "kind": "user", "user": "alice@t.local", "category": "other" })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert!(j["meta"]["retry_after_secs"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn bots_cannot_report_or_read_reports() {
    let w = world().await;
    let (s, app) =
        w.node.post("/api/v1/applications", &w.alice.token, json!({ "name": "Snitch", "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let (s, token) = w
        .node
        .post(
            &format!("/api/v1/applications/{}/tokens", app["id"].as_str().unwrap()),
            &w.alice.token,
            json!({ "name": "main" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{token}");
    let secret = token["secret"].as_str().unwrap();
    let (s, j) = report(&w.node, secret, json!({ "kind": "user", "user": "carol@t.local", "category": "spam" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = w.node.get_auth(&format!("/api/v1/rooms/{}/reports", w.room_id), secret).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

#[tokio::test]
async fn moderators_resolve_assign_and_note_reports() {
    let w = world().await;
    let (_, created) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "spam" }),
    )
    .await;
    let path = format!("/api/v1/reports/{}", created["id"].as_str().unwrap());
    let mut rx = w.node.state.hub.subscribe();
    let (s, j) = w.node.patch(&path, &w.bob.token, json!({ "status": "resolved" })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let (s, j) = w.node.patch(&path, &w.moder.token, json!({ "status": "closed" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.status_invalid")), "{j}");
    let (s, j) = w.node.patch(&path, &w.moder.token, json!({ "assignee_id": w.bob.user_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.assignee_invalid")), "{j}");
    let (s, j) = w
        .node
        .patch(
            &path,
            &w.moder.token,
            json!({ "status": "resolved", "assignee_id": w.moder.user_id, "note": "Warned carol" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["status"].as_str(), j["note"].as_str()), (Some("resolved"), Some("Warned carol")));
    assert_eq!(j["assignee"]["address"], "moder@t.local");
    assert!(j["resolved_at"].is_string());
    let ev = hub_event(&mut rx, "report.update").await;
    assert_eq!(ev.data["status"], "resolved");
    let (_, open) = w.node.get_auth(&format!("/api/v1/rooms/{}/reports?status=open", w.room_id), &w.moder.token).await;
    assert_eq!((open["reports"].as_array().unwrap().len(), open["open"].as_i64()), (0, Some(0)));
    let (_, done) =
        w.node.get_auth(&format!("/api/v1/rooms/{}/reports?status=resolved", w.room_id), &w.moder.token).await;
    assert_eq!(done["reports"].as_array().unwrap().len(), 1);
    let (s, j) = w.node.patch(&path, &w.moder.token, json!({ "assignee_id": null, "status": "open" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["assignee"].is_null() && j["resolved_at"].is_null(), "{j}");
}

#[tokio::test]
async fn action_shortcuts_run_the_moderation_routes_and_record_the_report() {
    let w = world().await;
    let (_, msg) = w.node.send(&w.carol.token, &w.room_id, &w.channel, "nasty").await;
    let (_, created) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "message", "conversation_id": w.channel, "message_id": msg["id"], "category": "harassment" }),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();
    let actions = format!("/api/v1/reports/{id}/actions");
    // The caller's own permissions apply: a plain member cannot act, the report is invisible to them.
    let (s, _) = w.node.post(&actions, &w.bob.token, json!({ "action": "timeout", "minutes": 10 })).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, j) = w.node.post(&actions, &w.moder.token, json!({ "action": "explode" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.action_invalid")), "{j}");
    let (s, j) = w.node.post(&actions, &w.moder.token, json!({ "action": "timeout", "minutes": 0 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    let (s, j) = w.node.post(&actions, &w.moder.token, json!({ "action": "delete_message" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = w
        .node
        .post(
            &actions,
            &w.moder.token,
            json!({ "action": "timeout", "minutes": 60, "reason": "insults", "resolve": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["report"]["status"], "resolved");
    let done: Vec<&str> =
        j["report"]["actions"].as_array().unwrap().iter().map(|a| a["action"].as_str().unwrap()).collect();
    assert_eq!(done, vec!["delete_message", "timeout"]);
    assert_eq!(j["report"]["actions"][1]["actor"], "moder@t.local");
    assert_eq!(j["report"]["actions"][1]["minutes"], 60);
    let (_, m) = w.node.get_auth(&format!("/api/v1/conversations/{}/messages", w.channel), &w.moder.token).await;
    assert!(m.as_array().unwrap().iter().all(|x| x["id"] != msg["id"]), "message deleted");
    let (_, members) = w.node.get_auth(&format!("/api/v1/rooms/{}/members", w.room_id), &w.moder.token).await;
    let carol = members.as_array().unwrap().iter().find(|m| m["user"]["address"] == "carol@t.local").unwrap();
    assert!(carol["timeout_until"].is_string(), "{carol}");

    // The audit entries of the routes carry the report id.
    let (_, log) = w.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", w.room_id), &w.alice.token).await;
    for action in ["message.delete", "member.timeout"] {
        let e =
            log.as_array().unwrap().iter().find(|e| e["action"] == action).unwrap_or_else(|| panic!("{action}: {log}"));
        assert_eq!(e["meta"]["report_id"], id.as_str(), "{e}");
    }
    let e = log.as_array().unwrap().iter().find(|e| e["action"] == "member.timeout").unwrap();
    assert_eq!(e["reason"], "insults");

    // Purge is two-step like the route it calls; the welcome channel's entries stay.
    let (s, preview) = w.node.post(&actions, &w.moder.token, json!({ "action": "purge" })).await;
    assert_eq!(s, StatusCode::OK, "{preview}");
    assert_eq!(preview["purge"]["dry_run"], true);
    let token = preview["purge"]["confirm_token"].as_str().unwrap();
    let (s, done) = w.node.post(&actions, &w.moder.token, json!({ "action": "purge", "confirm_token": token })).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert_eq!(done["purge"]["dry_run"], false);

    // Kick and ban follow the hierarchy of the routes: the moderator cannot act against the owner.
    let (_, owner_report) = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "spam", "detail": "again" }),
    )
    .await;
    let (s, j) = w
        .node
        .post(
            &format!("/api/v1/reports/{}/actions", owner_report["id"].as_str().unwrap()),
            &w.moder.token,
            json!({ "action": "ban", "reason": "spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, bans) = w.node.get_auth(&format!("/api/v1/rooms/{}/bans", w.room_id), &w.moder.token).await;
    assert_eq!(bans[0]["subject"], "carol@t.local");
}

#[tokio::test]
async fn node_admins_act_on_node_reports_with_node_bans() {
    let w = world().await;
    let (_, created) =
        report(&w.node, &w.bob.token, json!({ "kind": "user", "user": "carol@t.local", "category": "spam" })).await;
    let actions = format!("/api/v1/reports/{}/actions", created["id"].as_str().unwrap());
    let (s, j) = w.node.post(&actions, &w.admin.token, json!({ "action": "timeout", "minutes": 5 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.action_invalid")), "{j}");
    let (s, j) = w.node.post(&actions, &w.admin.token, json!({ "action": "ban", "reason": "spammer" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, bans) = w.node.get_auth("/api/v1/admin/bans", &w.admin.token).await;
    assert!(bans.as_array().unwrap().iter().any(|b| b["subject"] == "carol@t.local"), "{bans}");
    let (_, log) = w.node.get_auth("/api/v1/admin/audit-log", &w.admin.token).await;
    let e = log.as_array().unwrap().iter().find(|e| e["action"] == "admin.ban").unwrap();
    assert_eq!(e["meta"]["report_id"], created["id"]);
}

#[tokio::test]
async fn retention_removes_closed_reports() {
    let w = world_with(|c| c.reports_retention_days = 1).await;
    let mut made = Vec::new();
    for user in ["carol@t.local", "alice@t.local", "moder@t.local"] {
        let (_, r) = report(&w.node, &w.bob.token, json!({ "kind": "user", "user": user, "category": "spam" })).await;
        made.push(r["id"].as_str().unwrap().to_string());
    }
    let (s, _) =
        w.node.patch(&format!("/api/v1/reports/{}", made[0]), &w.admin.token, json!({ "status": "resolved" })).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) =
        w.node.patch(&format!("/api/v1/reports/{}", made[1]), &w.admin.token, json!({ "status": "dismissed" })).await;
    assert_eq!(s, StatusCode::OK);
    let old = tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::days(2));
    sqlx::query("UPDATE reports SET resolved_at = $1, updated_at = $1, created_at = $1")
        .bind(&old)
        .execute(&w.node.state.db)
        .await
        .unwrap();
    let removed = tavrn_node::reports::prune(&w.node.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(removed, 2);
    let (_, list) = w.node.get_auth("/api/v1/admin/reports", &w.admin.token).await;
    assert_eq!(ids(&list), vec![made[2].clone()], "open reports stay");
}

#[tokio::test]
async fn the_report_routes_need_a_session() {
    let w = world().await;
    // Clients offer reports and the rules editor only where the node announces them.
    let (_, info) = w.node.req(Method::GET, "/api/v1/node", None, None).await;
    let caps = info["capabilities"].as_array().unwrap();
    assert!(caps.contains(&json!("reports.v1")) && caps.contains(&json!("automod.v1")), "{info}");
    let (s, _) = w
        .node
        .req(
            Method::POST,
            "/api/v1/reports",
            None,
            Some(json!({ "kind": "room", "room_id": w.room_id, "category": "spam" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = w.node.req(Method::GET, &format!("/api/v1/rooms/{}/reports", w.room_id), None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_of_other_nodes_report_with_their_session_here() {
    let (a, b) = common::federation::two_nodes().await;
    let carol = b.register("carol").await;
    let mallory = b.register("mallory").await;
    let room = b.plaintext_room(&carol.token, "Meeting point").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let (s, _) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &mallory.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (_, msg) = b.send(&mallory.token, &room_id, &channel, "scam link").await;

    // Alice of a.test reports through her federated session on b.test: the room's moderators see her address.
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (s, _) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, created) = b
        .post(
            "/api/v1/reports",
            &remote.token,
            json!({ "kind": "message", "conversation_id": channel, "message_id": msg["id"], "category": "spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let (_, list) = b.get_auth(&format!("/api/v1/rooms/{room_id}/reports"), &carol.token).await;
    assert_eq!(list["reports"][0]["reporter"]["address"], "alice@a.test");
    assert_eq!(list["reports"][0]["scope"], "room");

    // Conversations of a third node are reported to the home node, never through a federated session.
    let (s, j) = b
        .post(
            "/api/v1/reports",
            &remote.token,
            json!({ "kind": "message", "conversation_id": channel, "message_id": msg["id"], "node": "c.test", "user": "x@c.test", "category": "spam" }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("report.target_invalid")), "{j}");
}
