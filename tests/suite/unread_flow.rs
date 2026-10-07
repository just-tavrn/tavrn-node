// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Read markers, unread and mention counts in the room and conversation lists (//! PROTOCOL.md §6).
use crate::common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::{hub::Scope, permissions as p, store, util};

/// Alice (owner) and Bob (member) in a plaintext room; returns the room and channel ids.
async fn room_with_bob(node: &TestNode, alice: &Session, bob: &Session) -> (String, String) {
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Timestamps have millisecond resolution: keep "before" and "after the join" apart.
    tokio::time::sleep(Duration::from_millis(5)).await;
    (room_id, channel_id)
}

async fn send_with(node: &TestNode, token: &str, room_id: &str, channel_id: &str, body: Value) -> String {
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j["id"].as_str().unwrap().to_string()
}

fn text(body: &str) -> Value {
    json!({ "content": { "type": "text", "body": body } })
}

/// The read state of `conversation_id` in a room detail.
fn state_of(room: &Value, conversation_id: &str) -> Option<Value> {
    room["read_states"].as_array().unwrap().iter().find(|s| s["conversation_id"] == conversation_id).cloned()
}

async fn room_state(node: &TestNode, token: &str, room_id: &str, channel_id: &str) -> Value {
    let (s, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), token).await;
    assert_eq!(s, StatusCode::OK, "{room}");
    state_of(&room, channel_id).expect("read state of the channel")
}

async fn mark(node: &TestNode, token: &str, conversation_id: &str, message_id: &str) -> (StatusCode, Value) {
    node.put(
        &format!("/api/v1/conversations/{conversation_id}/read"),
        token,
        json!({ "last_read_message_id": message_id }),
    )
    .await
}

#[tokio::test]
async fn channel_counts_mentions_and_monotonic_marker() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    // Written before Bob joined: never unread for him.
    send_with(&node, &alice.token, &room_id, &channel_id, text("before")).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    tokio::time::sleep(Duration::from_millis(5)).await;

    let empty = room_state(&node, &bob.token, &room_id, &channel_id).await;
    assert_eq!(empty["unread_count"], 0, "{empty}");
    assert_eq!(empty["mention_count"], 0);
    assert!(empty["last_read_message_id"].is_null());

    let m1 = send_with(&node, &alice.token, &room_id, &channel_id, text("one")).await;
    let m2 = send_with(
        &node,
        &alice.token,
        &room_id,
        &channel_id,
        json!({ "content": { "type": "text", "body": "@bob" }, "mentions": ["bob@t.local"] }),
    )
    .await;
    let m3 = send_with(
        &node,
        &alice.token,
        &room_id,
        &channel_id,
        json!({ "content": { "type": "text", "body": "@everyone" }, "mentions_everyone": true }),
    )
    .await;
    // A mention of a user whose name contains the other as a pattern (LIKE wildcards are escaped).
    send_with(
        &node,
        &alice.token,
        &room_id,
        &channel_id,
        json!({ "content": { "type": "text", "body": "@b_b" }, "mentions": ["b_b@t.local"] }),
    )
    .await;
    // Own messages are never unread.
    let own = send_with(&node, &bob.token, &room_id, &channel_id, text("mine")).await;

    let s = room_state(&node, &bob.token, &room_id, &channel_id).await;
    assert_eq!(s["unread_count"], 4, "{s}");
    assert_eq!(s["mention_count"], 2, "{s}");
    assert_eq!(s["last_message_id"], own.as_str());
    let a = room_state(&node, &alice.token, &room_id, &channel_id).await;
    assert_eq!(a["unread_count"], 1, "Alice sees only Bob's message: {a}");
    assert_eq!(a["mention_count"], 0);

    let mut rx = node.state.hub.subscribe();
    let (st, j) = mark(&node, &bob.token, &channel_id, &m2).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["last_read_message_id"], m2.as_str());
    assert_eq!(j["unread_count"], 2, "{j}");
    assert_eq!(j["mention_count"], 1, "{j}");
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.kind, "read.update");
    assert_eq!(ev.data, json!({ "conversation_id": channel_id, "last_read_message_id": m2 }));
    assert!(matches!(&ev.scope, Scope::Users(u) if u == &vec![bob.user_id.clone()]), "only Bob's own devices");

    // Never backwards; no event when nothing changed.
    let (st, j) = mark(&node, &bob.token, &channel_id, &m1).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["last_read_message_id"], m2.as_str());
    assert!(rx.try_recv().is_err(), "an older marker is ignored silently");
    let marker = store::messages::read_marker(&node.state.db, &channel_id, &bob.user_id).await.unwrap();
    assert_eq!(marker.as_deref(), Some(m2.as_str()));

    let (st, j) = mark(&node, &bob.token, &channel_id, &m3).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["unread_count"], 1);
    assert_eq!(j["mention_count"], 0);
    let (st, j) = mark(&node, &bob.token, &channel_id, &own).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["unread_count"], 0);
    let s = room_state(&node, &bob.token, &room_id, &channel_id).await;
    assert_eq!(s["unread_count"], 0, "{s}");
    assert_eq!(s["last_read_message_id"], own.as_str());
}

#[tokio::test]
async fn markers_are_validated_and_members_only() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, channel_id) = room_with_bob(&node, &alice, &bob).await;
    let m = send_with(&node, &alice.token, &room_id, &channel_id, text("hello")).await;

    // Non-members of the room: 403 like every room route; unknown conversations: 404.
    let (s, j) = mark(&node, &carol.token, &channel_id, &m).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.not_member");
    let (s, _) = mark(&node, &bob.token, "01J9ZK3G5M8Q2W4E6R8T0Y2V00", &m).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = mark(&node, &bob.token, "not-a-ulid", &m).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The message must be a ULID of this conversation.
    let (s, j) = mark(&node, &bob.token, &channel_id, "broken").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "validation.id");
    let other_room = node.plaintext_room(&alice.token, "Other").await;
    let other_id = other_room["id"].as_str().unwrap();
    let other_channel = TestNode::text_channel(&other_room);
    let foreign = send_with(&node, &alice.token, other_id, &other_channel, text("elsewhere")).await;
    let (s, j) = mark(&node, &bob.token, &channel_id, &foreign).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "message.not_found");
    let (s, j) = mark(&node, &bob.token, &channel_id, &util::ulid()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");

    // Hidden channels: no access and no counts in the room detail.
    let (_, hidden) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "text", "name": "secret", "encrypted": false }),
        )
        .await;
    let hidden_id = hidden["id"].as_str().unwrap().to_string();
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": hidden_id, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let secret = send_with(&node, &alice.token, &room_id, &hidden_id, text("psst")).await;
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert!(state_of(&room, &hidden_id).is_none(), "no counts for a hidden channel: {room}");
    assert!(state_of(&room, &channel_id).is_some());
    let (s, j) = mark(&node, &bob.token, &hidden_id, &secret).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "channel.view_forbidden");
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(state_of(&room, &hidden_id).unwrap()["unread_count"], 0, "own message");
}

/// Inserts `n` messages directly (DMs only accept ciphertext; the counts only look at metadata).
async fn insert_messages(node: &TestNode, conversation_id: &str, author_id: &str, n: usize, mentions: &[String]) {
    for _ in 0..n {
        store::messages::insert(
            &node.state.db,
            store::messages::NewMessage {
                id: &util::ulid(),
                conversation_id,
                author_id,
                device_id: None,
                encrypted: true,
                format: 1,
                epoch: Some(0),
                content: "Y2lwaGVy",
                reply_to_id: None,
                thread_id: None,
                mentions,
                mentions_everyone: false,
                signature: None,
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn conversation_list_counts_and_cap() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    let dm = node.create_dm(&alice, &bob).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    insert_messages(&node, &dm, &alice.user_id, 2, &[]).await;
    insert_messages(&node, &dm, &alice.user_id, 1, &["bob@t.local".to_string()]).await;
    insert_messages(&node, &dm, &bob.user_id, 1, &[]).await;

    let (s, list) = node.get_auth("/api/v1/conversations", &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let c = &list[0];
    assert_eq!(c["unread_count"], 3, "{c}");
    assert_eq!(c["mention_count"], 1, "{c}");
    assert!(c["last_read_message_id"].is_null());
    let last = c["last_message_id"].as_str().unwrap().to_string();
    let (_, list) = node.get_auth("/api/v1/conversations", &alice.token).await;
    assert_eq!(list[0]["unread_count"], 1, "{list}");

    // DMs are visible to their members only.
    let (s, j) = mark(&node, &carol.token, &dm, &last).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "conversation.not_found");
    let (s, j) = mark(&node, &bob.token, &dm, &last).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, list) = node.get_auth("/api/v1/conversations", &bob.token).await;
    assert_eq!(list[0]["unread_count"], 0, "{list}");
    assert_eq!(list[0]["last_read_message_id"], last.as_str());

    // Counts are capped at 999.
    insert_messages(&node, &dm, &alice.user_id, 1001, &["bob@t.local".to_string()]).await;
    let (_, list) = node.get_auth("/api/v1/conversations", &bob.token).await;
    assert_eq!(list[0]["unread_count"], 999, "{}", list[0]);
    assert_eq!(list[0]["mention_count"], 999);
}

#[tokio::test]
async fn history_pages_newest_first_with_validated_cursors() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(send_with(&node, &alice.token, &room_id, &channel_id, text(&format!("m{i}"))).await);
    }
    let path = format!("/api/v1/conversations/{channel_id}/messages");
    let (s, page) = node.get_auth(&format!("{path}?limit=2"), &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let got: Vec<&str> = page.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(got, vec![ids[4].as_str(), ids[3].as_str()]);
    let (_, older) = node.get_auth(&format!("{path}?limit=2&before={}", ids[3]), &alice.token).await;
    let got: Vec<&str> = older.as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(got, vec![ids[2].as_str(), ids[1].as_str()]);
    for bad in ["before=~", "after=x%27%20OR%201%3D1", "before=01J9ZK3G5M8Q2W4E6R8T0Y2V0"] {
        let (s, j) = node.get_auth(&format!("{path}?{bad}"), &alice.token).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert_eq!(j["code"], "validation.id", "{bad}");
    }
}
