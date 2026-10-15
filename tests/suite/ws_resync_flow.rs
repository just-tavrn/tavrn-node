// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A resync (events may have been lost on the cache bus between instances) reloads what a connection may receive:
//! a membership that ended while its `member.leave` was lost no longer receives the room's events.
use crate::common;

use std::time::Duration;

use common::{TestNode, test_node};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use super::ws_flow::{hello, serve};

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The frames that arrive within `ms`, presence updates left out.
async fn frames(ws: &mut Socket, ms: u64) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout_at(deadline, ws.next()).await {
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["type"] != "presence.update" {
            out.push(v);
        }
    }
    out
}

#[tokio::test]
async fn a_resync_reloads_the_rooms_of_a_connection() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let url = serve(&node).await;
    let mut ws = hello(&url, &bob.token).await;
    // Warm the room's snapshot for bob's connection.
    node.send(&alice.token, &room_id, &channel, "before").await;
    assert!(frames(&mut ws, 500).await.iter().any(|f| f["type"] == "message.create"));

    // Bob's membership ends without an event reaching this instance (lost on the bus), then the bus recovers.
    assert!(tavrn_node::store::rooms::remove_member(&node.state.db, &room_id, &bob.user_id).await.unwrap());
    node.state.hub.resync_all();
    let got = frames(&mut ws, 300).await;
    assert!(got.iter().any(|f| f["op"] == "resync"), "{got:?}");

    // Neither the room's metadata nor its messages reach bob any more.
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "name": "Renamed" })).await;
    assert!(s.is_success(), "{j}");
    node.send(&alice.token, &room_id, &channel, "after").await;
    let got = frames(&mut ws, 500).await;
    assert!(got.is_empty(), "bob still receives the room: {got:?}");
}
