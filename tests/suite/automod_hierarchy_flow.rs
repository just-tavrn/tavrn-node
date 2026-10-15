// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Auto-moderation as a moderator acts: its timeouts are announced like a moderator's (and take effect everywhere
//! at once), its rules reach only members their author outranks, and matching stays cheap for crafted rules and text.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::hub::Event;
use tokio::sync::broadcast;

const DOMAIN: &str = "t.local";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

async fn room_with(node: &TestNode, owner: &Session, members: &[&Session]) -> (String, String) {
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    for m in members {
        let (s, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &m.token, json!({})).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    (room_id, channel_id)
}

async fn member_update(rx: &mut broadcast::Receiver<Arc<Event>>, user_id: &str) -> Value {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("no member.update").unwrap();
        if ev.kind == "member.update" && ev.data["member"]["user"]["id"] == user_id {
            return ev.data.clone();
        }
    }
}

/// An auto-moderation timeout (a keyword rule with `action: timeout`) publishes `member.update` like a moderator's
/// timeout: clients learn it, and the room's visibility snapshot is dropped, so ephemeral events (cursors,
/// whiteboard strokes) and typing are refused at once, not only the REST routes.
#[tokio::test]
async fn automod_timeout_is_announced_and_stops_ephemeral_events() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel) = room_with(&node, &alice, &[&bob]).await;
    let rule = json!({ "name": "Hard", "terms": ["grr"], "whole_word": false, "links": "off", "domains": [],
        "exempt_roles": [], "exempt_channels": [], "action": "timeout", "timeout_minutes": 30 });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/automod"), &alice.token, json!({ "rules": [rule] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let path = format!("/api/v1/conversations/{channel}/ephemeral");
    let cursor = json!({ "type": "cursor", "content": { "x": 1, "y": 2 } });
    // Warms the room's snapshot (as any cursor, typing notice or message fan-out does).
    let (s, j) = node.post(&path, &bob.token, cursor.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.send(&bob.token, &room_id, &channel, "grr").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let update = member_update(&mut rx, &bob.user_id).await;
    assert!(update["member"]["timeout_until"].is_string(), "{update}");
    let (s, j) = node.send(&bob.token, &room_id, &channel, "hello").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "REST: bob is timed out now: {j}");

    let (s, j) = node.post(&path, &bob.token, cursor).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.timed_out"), "{j}");
}

/// The flood timeout of auto-moderation is announced the same way.
#[tokio::test]
async fn automod_flood_timeout_is_announced() {
    let node = common::test_node_with(DOMAIN, |c| {
        c.automod_burst_limit = 3;
        c.automod_timeout_minutes = 5;
    })
    .await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel) = room_with(&node, &alice, &[&bob]).await;
    let mut rx = node.state.hub.subscribe();
    for i in 0..4 {
        node.send(&bob.token, &room_id, &channel, &format!("spam {i}")).await;
    }
    let update = member_update(&mut rx, &bob.user_id).await;
    assert!(update["member"]["timeout_until"].is_string(), "{update}");
}
