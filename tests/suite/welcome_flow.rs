// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The welcome channel: a fixed system channel per room with `system.join`/`system.leave`
//! entries, read-only, undeletable, always visible, counted as "changed since last read" only.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};

const DOMAIN: &str = "t.local";

fn welcome(room: &Value) -> Value {
    room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").cloned().unwrap_or(Value::Null)
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

async fn entries(node: &TestNode, token: &str, channel: &str) -> Vec<Value> {
    let (s, msgs) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), token).await;
    assert_eq!(s, StatusCode::OK, "{msgs}");
    let mut list: Vec<Value> = msgs.as_array().unwrap().iter().map(|m| m["content"].clone()).collect();
    list.reverse();
    list
}

#[tokio::test]
async fn welcome_channel_records_joins_and_leaves_and_is_read_only() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let w = welcome(&room);
    assert_eq!((w["system_name"].as_str(), w["encrypted"].as_bool()), (Some("welcome"), Some(false)), "{room}");
    let wid = w["id"].as_str().unwrap().to_string();
    assert!(
        room["channels"].as_array().unwrap().iter().all(|c| c["position"].as_i64() >= w["position"].as_i64()),
        "pinned first"
    );

    join(&node, &alice, &room_id, &bob).await;
    join(&node, &alice, &room_id, &carol).await;
    let list = entries(&node, &bob.token, &wid).await;
    assert_eq!(list[0]["type"], "system.join");
    assert_eq!(list[0]["user"], "alice@t.local");
    assert_eq!((list[1]["type"].as_str(), list[1]["user"].as_str()), (Some("system.join"), Some("bob@t.local")));
    assert_eq!(list[2]["display_name"], "carol");

    // Nobody writes there, not even the owner; reactions are fine.
    for token in [&alice.token, &bob.token] {
        let (s, j) = node
            .post(
                &format!("/api/v1/conversations/{wid}/messages"),
                token,
                json!({ "content": { "type": "text", "body": "hi" } }),
            )
            .await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.read_only")), "{j}");
    }
    let (_, msgs) = node.get_auth(&format!("/api/v1/conversations/{wid}/messages"), &bob.token).await;
    let first = msgs.as_array().unwrap().last().unwrap()["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .req(
            axum::http::Method::PUT,
            &format!("/api/v1/conversations/{wid}/messages/{first}/reactions/👋"),
            Some(&bob.token),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{wid}/ephemeral"),
            &alice.token,
            json!({ "type": "whiteboard.open", "content": {} }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("whiteboard.open_forbidden")), "{j}");

    // Fixed: no renaming, moving or deleting.
    let path = format!("/api/v1/rooms/{room_id}/channels/{wid}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "name": "lobby" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.system_protected")), "{j}");
    let (s, j) = node.delete(&path, &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.system_protected")), "{j}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "topic": "Hello!" })).await;
    assert_eq!((s, j["topic"].as_str()), (StatusCode::OK, Some("Hello!")), "{j}");
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "system", "name": "x" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "clients cannot create system channels: {j}");

    // Leave, kick and ban are written as system.leave with the reason kind.
    let dave = node.register("dave").await;
    join(&node, &alice, &room_id, &dave).await;
    let (s, _) = node.post(&format!("/api/v1/rooms/{room_id}/leave"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node
        .req(
            axum::http::Method::DELETE,
            &format!("/api/v1/rooms/{room_id}/members/{}", carol.user_id),
            Some(&alice.token),
            Some(json!({ "reason": "spam" })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": "dave@t.local" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let list = entries(&node, &alice.token, &wid).await;
    let leaves: Vec<(&str, &str)> = list
        .iter()
        .filter(|e| e["type"] == "system.leave")
        .map(|e| (e["user"].as_str().unwrap(), e["reason_kind"].as_str().unwrap()))
        .collect();
    assert_eq!(leaves, vec![("bob@t.local", "leave"), ("carol@t.local", "kick"), ("dave@t.local", "ban")]);
    assert!(list.iter().all(|e| e.get("reason").is_none()), "the kick reason stays in the audit log");
    assert!(
        list.iter().all(|e| e.get("by").is_none() && e.get("moderator").is_none()),
        "no moderator names in the security log: {list:?}"
    );
}

#[tokio::test]
async fn welcome_channel_counts_changes_not_mentions_and_cannot_be_switched_off() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let wid = welcome(&room)["id"].as_str().unwrap().to_string();
    join(&node, &alice, &room_id, &bob).await;
    join(&node, &alice, &room_id, &carol).await;
    let state = |room: &Value| {
        room["read_states"].as_array().unwrap().iter().find(|r| r["conversation_id"] == wid.as_str()).cloned()
    };
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let s = state(&detail).unwrap();
    assert_eq!(
        (s["unread_count"].as_i64(), s["mention_count"].as_i64()),
        (Some(1), Some(0)),
        "changed, never a number: {s}"
    );

    // It can no longer be switched off or hidden (`security_log_flow.rs`).
    let (st, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "welcome_channel_enabled": false }))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(welcome(&j)["id"], wid.as_str(), "still there: {j}");
}

#[tokio::test]
async fn old_rooms_get_a_welcome_channel_at_start() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Alt").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let wid = welcome(&room)["id"].as_str().unwrap().to_string();
    sqlx::query("DELETE FROM conversations WHERE id = $1").bind(&wid).execute(&node.state.db).await.unwrap();
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.welcome_channels, 1);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(welcome(&detail)["system_name"], "welcome");
    assert_eq!(tavrn_node::fixups::run(&node.state.db).await.unwrap().welcome_channels, 0);
}
