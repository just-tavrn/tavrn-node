// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use std::time::Duration;

use common::test_node;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub(crate) async fn serve(node: &common::TestNode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{addr}/api/v1/ws")
}

async fn connect(url: &str) -> Socket {
    tokio_tungstenite::connect_async(url).await.unwrap().0
}

/// `true` if nothing but presence updates arrives within `ms`.
async fn silent(ws: &mut Socket, ms: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return true,
            Ok(Some(Ok(Message::Text(t)))) if t.contains("\"presence.update\"") => {}
            Ok(_) => return false,
        }
    }
}

/// The next frame, skipping presence updates (presence_flow.rs tests those).
async fn next_json(ws: &mut Socket) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap() {
            Message::Text(t) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] != "presence.update" {
                    return v;
                }
            }
            Message::Close(frame) => return json!({ "op": "close", "code": frame.map(|f| u16::from(f.code)) }),
            _ => {}
        }
    }
}

#[tokio::test]
async fn hello_is_required_and_token_is_checked() {
    let node = test_node("t.local").await;
    let url = serve(&node).await;
    let mut ws = connect(&url).await;
    ws.send(Message::Text(json!({ "op": "typing", "room_id": "x", "channel_id": "y" }).to_string().into()))
        .await
        .unwrap();
    assert_eq!(next_json(&mut ws).await, json!({ "op": "close", "code": 4002 }));
    let mut ws = connect(&url).await;
    ws.send(Message::Text(json!({ "op": "hello", "token": "broken" }).to_string().into())).await.unwrap();
    assert_eq!(next_json(&mut ws).await, json!({ "op": "close", "code": 4001 }));
}

#[tokio::test]
async fn events_flow_to_room_members_only() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = common::TestNode::text_channel(&room);
    let url = serve(&node).await;

    let mut alice_ws = connect(&url).await;
    alice_ws
        .send(Message::Text(
            json!({ "op": "hello", "token": alice.token, "capabilities": ["content.v1"] }).to_string().into(),
        ))
        .await
        .unwrap();
    let ready = next_json(&mut alice_ws).await;
    assert_eq!(ready["op"], "ready");
    assert_eq!(ready["user"]["username"], "alice");
    let mut bob_ws = connect(&url).await;
    bob_ws
        .send(Message::Text(json!({ "op": "hello", "token": bob.token, "last_event_id": "01J" }).to_string().into()))
        .await
        .unwrap();
    assert_eq!(next_json(&mut bob_ws).await["op"], "ready");
    assert_eq!(next_json(&mut bob_ws).await["op"], "resync", "last_event_id always leads to a resync in phase 1");

    let (_, msg) = node.send(&alice.token, &room_id, &channel_id, "hello").await;
    let ev = next_json(&mut alice_ws).await;
    assert_eq!(ev["op"], "event");
    assert_eq!(ev["type"], "message.create");
    assert_eq!(ev["data"]["id"], msg["id"]);

    // Bob is not a member: nothing arrives until he joins.
    assert!(silent(&mut bob_ws, 300).await);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(next_json(&mut alice_ws).await["type"], "member.join");
    let ev = next_json(&mut bob_ws).await;
    assert_eq!(ev["type"], "member.join", "{ev}");
    // The node's entry in the welcome channel.
    for ws in [&mut alice_ws, &mut bob_ws] {
        let ev = next_json(ws).await;
        assert_eq!(
            (ev["type"].as_str(), ev["data"]["content"]["type"].as_str()),
            (Some("message.create"), Some("system.join")),
            "{ev}"
        );
    }
    node.send(&alice.token, &room_id, &channel_id, "welcome").await;
    assert_eq!(next_json(&mut bob_ws).await["type"], "message.create");
    assert_eq!(next_json(&mut alice_ws).await["type"], "message.create");

    bob_ws
        .send(Message::Text(json!({ "op": "typing", "room_id": room_id, "channel_id": channel_id }).to_string().into()))
        .await
        .unwrap();
    let ev = next_json(&mut alice_ws).await;
    assert_eq!(ev["type"], "typing");
    assert_eq!(ev["data"]["user_id"], bob.user_id);

    bob_ws
        .send(Message::Text(
            json!({ "op": "ack", "conversation_id": channel_id, "message_id": msg["id"] }).to_string().into(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let marker = tavrn_node::store::messages::read_marker(&node.state.db, &channel_id, &bob.user_id).await.unwrap();
    assert_eq!(marker.as_deref(), msg["id"].as_str());
}

pub(crate) async fn hello(url: &str, token: &str) -> Socket {
    let mut ws = connect(url).await;
    ws.send(Message::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    assert_eq!(next_json(&mut ws).await["op"], "ready");
    ws
}

#[tokio::test]
async fn dm_typing_reaches_members_only_and_ack_needs_access() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    let dm = node.create_dm(&alice, &bob).await;
    let url = serve(&node).await;
    let mut alice_ws = hello(&url, &alice.token).await;
    let mut bob_ws = hello(&url, &bob.token).await;
    let mut carol_ws = hello(&url, &carol.token).await;

    // A non-member cannot type into the DM (nothing is delivered to anybody).
    carol_ws.send(Message::Text(json!({ "op": "typing", "conversation_id": dm }).to_string().into())).await.unwrap();
    assert!(silent(&mut alice_ws, 300).await);

    bob_ws.send(Message::Text(json!({ "op": "typing", "conversation_id": dm }).to_string().into())).await.unwrap();
    let ev = next_json(&mut alice_ws).await;
    assert_eq!(ev["type"], "typing", "{ev}");
    assert_eq!(ev["data"], json!({ "conversation_id": dm, "user_id": bob.user_id }));
    assert_eq!(next_json(&mut bob_ws).await["type"], "typing", "members' own connections get it too");
    assert!(silent(&mut carol_ws, 300).await, "outsiders see nothing");

    // `ack` goes through the same checks as PUT …/read: Carol cannot set a marker in the DM.
    // DMs only take ciphertext and this test has no MLS group: insert a message directly.
    let message_id = tavrn_node::util::ulid();
    tavrn_node::store::messages::insert(
        &node.state.db,
        tavrn_node::store::messages::NewMessage {
            id: &message_id,
            conversation_id: &dm,
            author_id: &alice.user_id,
            device_id: None,
            encrypted: true,
            format: 1,
            epoch: Some(0),
            content: "Y2lwaGVy",
            reply_to_id: None,
            thread_id: None,
            mentions: &[],
            mentions_everyone: false,
            signature: None,
        },
    )
    .await
    .unwrap();
    carol_ws
        .send(Message::Text(json!({ "op": "ack", "conversation_id": dm, "message_id": message_id }).to_string().into()))
        .await
        .unwrap();
    bob_ws
        .send(Message::Text(json!({ "op": "ack", "conversation_id": dm, "message_id": message_id }).to_string().into()))
        .await
        .unwrap();
    let ev = next_json(&mut bob_ws).await;
    assert_eq!(ev["type"], "read.update", "{ev}");
    assert_eq!(ev["data"]["last_read_message_id"], message_id.as_str());
    let db = &node.state.db;
    assert!(tavrn_node::store::messages::read_marker(db, &dm, &carol.user_id).await.unwrap().is_none());
    assert_eq!(tavrn_node::store::messages::read_marker(db, &dm, &bob.user_id).await.unwrap(), Some(message_id));
}

#[tokio::test]
async fn an_open_socket_gets_the_events_of_a_room_its_user_creates_later() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let url = serve(&node).await;
    // The socket is open before the room exists (the web client creates rooms while connected).
    let mut ws = hello(&url, &alice.token).await;
    let room = node.plaintext_room(&alice.token, "New").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = common::TestNode::text_channel(&room);
    let (st, _) = node.send(&alice.token, &room_id, &channel_id, "first").await;
    assert_eq!(st, axum::http::StatusCode::CREATED);
    loop {
        let ev = next_json(&mut ws).await;
        assert_eq!(ev["op"], "event", "{ev}");
        // The welcome channel's entry of the owner comes first; then the message.
        if ev["type"] == "message.create" && ev["data"]["conversation_id"] == channel_id.as_str() {
            break;
        }
    }
}
