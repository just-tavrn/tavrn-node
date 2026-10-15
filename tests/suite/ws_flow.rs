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
        match common::within(Duration::from_secs(5), "the next frame", ws.next()).await.unwrap().unwrap() {
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
    // The connection handles the ack in its own task: wait for it instead of a fixed delay.
    let read = msg["id"].as_str().unwrap().to_string();
    common::wait_until(Duration::from_secs(5), "the ack sets the read marker", || async {
        tavrn_node::store::messages::read_marker(&node.state.db, &channel_id, &bob.user_id).await.unwrap().as_deref()
            == Some(read.as_str())
    })
    .await;
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

/// Waits (at most 5 seconds scaled by `TAVRN_TEST_TIMEOUT_FACTOR`, still far below the 30-second heartbeat: the
/// `session.revoked` event must close it, not the re-check at the next ping) for the socket to close and returns the
/// close code; events before it are skipped.
async fn closed_with(ws: &mut Socket) -> Option<u16> {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(None | Some(Err(_))) => return Some(0),
            Ok(Some(Ok(Message::Close(frame)))) => return Some(frame.map(|f| u16::from(f.code)).unwrap_or(0)),
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// How a session of alice's second device ("victim") ends.
#[derive(Clone, Copy, Debug)]
enum Revocation {
    Logout,
    ChangePassword,
    ResetPassword,
    DeleteDevice,
    AdminDisable,
    NodeBan,
    AdminSecondFactorReset,
}

async fn revoke(
    node: &common::TestNode,
    how: Revocation,
    alice: &common::Session,
    victim: &common::Session,
    admin: &common::Session,
) {
    use axum::http::{Method, StatusCode};
    let (s, j) = match how {
        Revocation::Logout => node.post("/api/v1/auth/logout", &victim.token, json!({})).await,
        Revocation::ChangePassword => {
            node.post(
                "/api/v1/users/me/password",
                &alice.token,
                json!({ "current_password": common::password("alice"), "new_password": "a-brand-new-password" }),
            )
            .await
        }
        Revocation::ResetPassword => {
            let token = "reset-token-of-the-test";
            tavrn_node::store::admin::set_password_reset(
                &node.state.db,
                &alice.user_id,
                &tavrn_node::util::sha256_b64(token),
                3600,
            )
            .await
            .unwrap();
            node.req(
                Method::POST,
                "/api/v1/auth/reset-password",
                None,
                Some(json!({ "token": token, "new_password": "a-brand-new-password" })),
            )
            .await
        }
        Revocation::DeleteDevice => {
            node.delete(&format!("/api/v1/users/me/devices/{}", victim.device_id), &alice.token).await
        }
        Revocation::AdminDisable => {
            node.patch(&format!("/api/v1/admin/users/{}", alice.user_id), &admin.token, json!({ "disabled": true }))
                .await
        }
        Revocation::NodeBan => {
            node.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "alice@t.local" })).await
        }
        Revocation::AdminSecondFactorReset => {
            node.post(&format!("/api/v1/admin/users/{}/second-factor/reset", alice.user_id), &admin.token, json!({}))
                .await
        }
    };
    assert!(s == StatusCode::NO_CONTENT || s == StatusCode::OK || s == StatusCode::CREATED, "{how:?}: {s} {j}");
}

/// Every local revocation ends the access token at once and closes the WebSockets opened with it (4001), not only the
/// refresh token.
#[tokio::test]
async fn revoked_local_sessions_close_their_websockets_and_lose_the_access_token() {
    use axum::http::StatusCode;
    for how in [
        Revocation::Logout,
        Revocation::ChangePassword,
        Revocation::ResetPassword,
        Revocation::DeleteDevice,
        Revocation::AdminDisable,
        Revocation::NodeBan,
        Revocation::AdminSecondFactorReset,
    ] {
        let node = test_node("t.local").await;
        let admin = node.register("admin").await;
        let alice = node.register("alice").await;
        let victim = node.login("alice").await;
        let url = serve(&node).await;
        let mut ws = hello(&url, &victim.token).await;
        // A request just before the revocation (a cached liveness check must not outlive it).
        assert_eq!(node.get_auth("/api/v1/users/me", &victim.token).await.0, StatusCode::OK);
        revoke(&node, how, &alice, &victim, &admin).await;
        assert_eq!(closed_with(&mut ws).await, Some(4001), "{how:?}: the socket closes with 4001");
        let (s, j) = node.get_auth("/api/v1/users/me", &victim.token).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{how:?}: {j}");
        // A new socket with the old token is refused as well.
        let mut again = connect(&url).await;
        again.send(Message::Text(json!({ "op": "hello", "token": victim.token }).to_string().into())).await.unwrap();
        assert_eq!(next_json(&mut again).await["code"], 4001, "{how:?}");
    }
}

/// Deleting a device of another user changes nothing: no session of the other user ends.
#[tokio::test]
async fn deleting_another_users_device_revokes_nothing() {
    use axum::http::{Method, StatusCode};
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let url = serve(&node).await;
    let mut ws = hello(&url, &bob.token).await;
    let (s, j) = node.delete(&format!("/api/v1/users/me/devices/{}", bob.device_id), &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("device.not_found")), "{j}");
    let (s, j) =
        node.req(Method::POST, "/api/v1/auth/refresh", None, Some(json!({ "refresh_token": bob.refresh }))).await;
    assert_eq!(s, StatusCode::OK, "bob's session lives on: {j}");
    assert_eq!(node.get_auth("/api/v1/users/me", &bob.token).await.0, StatusCode::OK);
    assert!(silent(&mut ws, 500).await, "bob's socket stays open");
}

/// One user holds at most `TAVRN_WS_MAX_SOCKETS_PER_USER` connections (close 4002 `too_many_connections` beyond).
#[tokio::test]
async fn sockets_per_user_are_capped() {
    let node = common::test_node_with("t.local", |c| c.ws_max_sockets_per_user = 2).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let url = serve(&node).await;
    let _a = hello(&url, &alice.token).await;
    let _b = hello(&url, &alice.token).await;
    let mut third = connect(&url).await;
    third.send(Message::Text(json!({ "op": "hello", "token": alice.token }).to_string().into())).await.unwrap();
    loop {
        match common::within(Duration::from_secs(5), "the close of the third socket", third.next())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Close(Some(f)) => {
                assert_eq!((u16::from(f.code), f.reason.as_str()), (4002, "too_many_connections"));
                break;
            }
            Message::Close(None) => unreachable!("close without a code"),
            _ => {}
        }
    }
    let _c = hello(&url, &bob.token).await; // per user
    drop(_a);
    // The node notices the closed socket on its own time: wait for it, not for a fixed delay.
    common::wait_until(Duration::from_secs(5), "the closed socket frees its place", || {
        let open = node.state.hub.connections_of(&alice.user_id);
        async move { open < 2 }
    })
    .await;
    let _d = hello(&url, &alice.token).await; // a closed socket frees its place
}

/// `ack` is limited like `PUT …/read`: acks over the limit are dropped silently.
#[tokio::test]
async fn acks_over_the_read_limit_are_dropped() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = common::TestNode::text_channel(&room);
    let db = &node.state.db;
    let (_, m) = node.send(&alice.token, &room_id, &channel, "hello").await;
    // Sending may have set the author's own marker: start without one.
    sqlx::query("DELETE FROM read_markers").execute(db).await.unwrap();
    let url = serve(&node).await;
    let mut ws = hello(&url, &alice.token).await;
    while node.state.read_limiter.check(&format!("read:{}", alice.user_id)).is_ok() {}
    let ack = json!({ "op": "ack", "conversation_id": channel, "message_id": m["id"] });
    ws.send(Message::Text(ack.to_string().into())).await.unwrap();
    assert!(silent(&mut ws, 700).await, "no read.update over the limit");
    assert!(tavrn_node::store::messages::read_marker(db, &channel, &alice.user_id).await.unwrap().is_none());
}

/// A frame header announcing more than 64 KiB is refused as soon as it is read, before the hello and before any
/// payload is buffered (with only the message limit the node would wait for the payload until the hello timeout).
#[tokio::test]
async fn an_announced_large_frame_is_refused_before_its_payload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let node = test_node("t.local").await;
    let url = serve(&node).await;
    let addr = url.trim_start_matches("ws://").split('/').next().unwrap().to_string();
    let mut tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let handshake = format!(
        "GET /api/v1/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(handshake.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tcp.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"), "upgraded");
    // A masked text frame announcing 1 MiB (64-bit length), then no payload at all.
    let mut header = vec![0x81u8, 0xFF];
    header.extend_from_slice(&(1u64 << 20).to_be_bytes());
    header.extend_from_slice(&[1, 2, 3, 4]);
    tcp.write_all(&header).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf)).await;
    match answer {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => assert_eq!(buf[0] & 0x0F, 0x8, "a close frame, got {:?}", &buf[..n.min(8)]),
        Err(_) => unreachable!("the node waited for the payload of an oversized frame"),
    }
}

/// REVIEW: connecting counts against the general per-user limit (close 4002 `rate_limited` beyond it).
#[tokio::test]
async fn review_connecting_counts_against_the_user_limit() {
    let node = common::test_node_with("t.local", |c| c.rate_user_per_minute = 1000).await;
    let alice = node.register("alice").await;
    let url = serve(&node).await;
    let limiter = node.state.user_api_limiter.clone().unwrap();
    while limiter.check(&format!("user:{}", alice.user_id)).is_ok() {}
    let mut ws = connect(&url).await;
    ws.send(Message::Text(json!({ "op": "hello", "token": alice.token }).to_string().into())).await.unwrap();
    loop {
        match common::within(Duration::from_secs(5), "the close of the socket", ws.next()).await.unwrap().unwrap() {
            Message::Close(Some(f)) => {
                assert_eq!((u16::from(f.code), f.reason.as_str()), (4002, "rate_limited"));
                break;
            }
            Message::Close(None) => unreachable!("close without a code"),
            _ => {}
        }
    }
}

/// The heartbeat re-checks the session as a belt: a session that ended without the event (here: revoked directly in
/// the database) closes the socket at the next ping.
#[tokio::test]
async fn the_heartbeat_closes_a_socket_whose_session_ended() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let mut state = node.state.clone();
    state.ws_ping = Duration::from_millis(400);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = tavrn_node::app::router(state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut ws = hello(&format!("ws://{addr}/api/v1/ws"), &alice.token).await;
    assert_eq!(answer_pings(&mut ws, 1500).await, None, "open while the session lives");
    tavrn_node::store::users::revoke_device_sessions(&node.state.db, &alice.user_id, &alice.device_id).await.unwrap();
    node.state.live_sessions.forget(std::slice::from_ref(&alice.device_id));
    let next_ping = u64::try_from(common::timeout(Duration::from_secs(3)).as_millis()).unwrap();
    assert_eq!(answer_pings(&mut ws, next_ping).await, Some(4001), "closed at the next ping");
}

/// Answers the node's pings for `ms`; the close code if the socket closes meanwhile.
async fn answer_pings(ws: &mut Socket, ms: u64) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(None | Some(Err(_))) => return Some(0),
            Ok(Some(Ok(Message::Close(frame)))) => return Some(frame.map(|f| u16::from(f.code)).unwrap_or(0)),
            Ok(Some(Ok(Message::Text(t)))) if t.contains("\"op\":\"ping\"") => {
                ws.send(Message::Text(json!({ "op": "pong" }).to_string().into())).await.unwrap();
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}
