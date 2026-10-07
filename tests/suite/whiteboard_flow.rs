// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Whiteboard (protocol/WHITEBOARD.md): ephemeral events (access, limits, fan-out over
//! real WebSockets), the session the node derives from open/grant/close, and the scene library.
use crate::common;

use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use base64::Engine;
use common::{TestNode, perms, test_node};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_node::{permissions as p, whiteboard};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const DOMAIN: &str = "t.local";
type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn serve(node: &TestNode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{addr}/api/v1/ws")
}

async fn connect(url: &str, token: &str) -> Socket {
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    ws.send(WsMessage::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
        if let WsMessage::Text(t) = frame
            && serde_json::from_str::<Value>(&t).unwrap()["op"] == "ready"
        {
            return ws;
        }
    }
}

/// The next event of `kind` within `ms`, ignoring everything else.
async fn event(ws: &mut Socket, kind: &str, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(Some(Ok(WsMessage::Text(t)))) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == kind {
                    return Some(v["data"].clone());
                }
            }
            Ok(_) => return None,
        }
    }
}

struct Room {
    id: String,
    text: String,
    voice: String,
}

/// A plaintext room of `owner` that every other session joins.
async fn room(node: &TestNode, owner: &common::Session, others: &[&common::Session]) -> Room {
    let room = node.plaintext_room(&owner.token, "Raid").await;
    let id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &owner.token, json!({})).await;
    for o in others {
        let (st, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &o.token, json!({})).await;
        assert!(st.is_success(), "{j}");
    }
    let voice = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    Room { text: TestNode::text_channel(&room), id, voice }
}

async fn deny_member(node: &TestNode, owner: &str, room: &Room, channel: &str, user_id: &str, deny: &[u64]) {
    let (st, j) = node
        .put(
            &format!("/api/v1/rooms/{}/overrides", room.id),
            owner,
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member", "subject_id": user_id, "allow": "0", "deny": perms(deny) }),
        )
        .await;
    assert!(st.is_success(), "{j}");
}

async fn eph(node: &TestNode, token: &str, conversation: &str, body: Value) -> (StatusCode, Value) {
    node.post(&format!("/api/v1/conversations/{conversation}/ephemeral"), token, body).await
}

fn code(j: &Value) -> Option<&str> {
    j["code"].as_str()
}

#[tokio::test]
async fn ephemeral_events_reach_viewers_except_the_sending_device() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let dave = node.register("dave").await;
    let r = room(&node, &alice, &[&bob, &carol]).await;
    // Carol is a member but may not view the channel; dave is no member at all.
    deny_member(&node, &alice.token, &r, &r.text, &carol.user_id, &[p::VIEW_CHANNEL]).await;
    let alice2 = node.login("alice").await;
    let url = serve(&node).await;
    let mut ws_alice = connect(&url, &alice.token).await;
    let mut ws_alice2 = connect(&url, &alice2.token).await;
    let mut ws_bob = connect(&url, &bob.token).await;
    let mut ws_carol = connect(&url, &carol.token).await;
    let mut ws_dave = connect(&url, &dave.token).await;

    let content = json!({ "type": "whiteboard.update", "elements": [{ "id": "a", "version": 2 }] });
    let (st, j) = eph(&node, &alice.token, &r.text, json!({ "type": "whiteboard.update", "content": content })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["session"], Value::Null);

    let got = event(&mut ws_bob, "ephemeral", 3000).await.expect("bob receives it");
    assert_eq!(got["conversation_id"], r.text.as_str());
    assert_eq!(got["type"], "whiteboard.update");
    assert_eq!(got["from"], json!({ "user": "alice@t.local", "device_id": alice.device_id }));
    assert_eq!(got["content"], content);
    assert!(event(&mut ws_alice2, "ephemeral", 3000).await.is_some(), "the sender's other devices receive it");
    assert!(event(&mut ws_alice, "ephemeral", 300).await.is_none(), "never echoed to the sending device");
    assert!(event(&mut ws_carol, "ephemeral", 300).await.is_none(), "members without read access get nothing");
    assert!(event(&mut ws_dave, "ephemeral", 300).await.is_none(), "non-members get nothing");

    // Nothing is stored: there is no table for it and the message history stays empty.
    let (_, msgs) = node.get_auth(&format!("/api/v1/conversations/{}/messages", r.text), &bob.token).await;
    assert_eq!(msgs, json!([]));
}

#[tokio::test]
async fn ephemeral_requests_are_checked() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let dave = node.register("dave").await;
    let r = room(&node, &alice, &[&bob, &carol]).await;
    deny_member(&node, &alice.token, &r, &r.text, &carol.user_id, &[p::VIEW_CHANNEL]).await;
    let ok = json!({ "type": "cursor", "content": { "type": "cursor", "x": 1, "y": 2 } });

    for bad_type in ["", "chat", "whiteboard.", "whiteboard.Update", "whiteboard.a-b", "cursors"] {
        let (st, j) = eph(&node, &bob.token, &r.text, json!({ "type": bad_type, "content": {} })).await;
        assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.type_invalid")), "{bad_type}");
    }
    let (st, j) = eph(&node, &dave.token, &r.text, ok.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("room.not_member")));
    let (st, j) = eph(&node, &carol.token, &r.text, ok.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("channel.view_forbidden")));
    let (st, j) = eph(&node, &bob.token, "01J9ZK3G5M8Q2W4E6R8T0Y2V4X", ok.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("conversation.not_found")));
    let (st, j) = eph(&node, &bob.token, "../../x", ok.clone()).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{j}");

    // Plaintext channel: content must be an object of at most 64 KiB.
    let (st, j) = eph(&node, &bob.token, &r.text, json!({ "type": "cursor", "content": "AQID" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.encryption_mismatch")));
    let big = "x".repeat(whiteboard::MAX_CONTENT_BYTES);
    let (st, j) = eph(&node, &bob.token, &r.text, json!({ "type": "cursor", "content": { "pad": big } })).await;
    assert_eq!((st, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, Some("ephemeral.too_large")));
    let huge = "x".repeat(whiteboard::MAX_CONTENT_BYTES * 2);
    let (st, _) = eph(&node, &bob.token, &r.text, json!({ "type": "cursor", "content": { "pad": huge } })).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "the body limit stops larger requests early");

    // Encrypted channel (the voice channel): plaintext and malformed ciphertext are refused.
    let (st, j) = eph(&node, &bob.token, &r.voice, ok.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.encryption_mismatch")));
    let (st, j) = eph(&node, &bob.token, &r.voice, json!({ "type": "cursor", "content": "not+base64" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.ciphertext_invalid")));
    let (st, j) = eph(&node, &bob.token, &r.voice, json!({ "type": "cursor", "content": "AQID" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.ciphertext_invalid")));

    let (st, j) = eph(&node, &bob.token, &r.text, ok).await;
    assert_eq!(st, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn ephemeral_events_are_rate_limited_per_sender() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let r = room(&node, &alice, &[&bob]).await;
    let body = json!({ "type": "cursor", "content": { "type": "cursor", "x": 0, "y": 0 } });
    let mut limited = None;
    for i in 0..=whiteboard::EVENTS_PER_SECOND {
        let (st, j) = eph(&node, &alice.token, &r.text, body.clone()).await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            limited = Some((i, j));
            break;
        }
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let (i, j) = limited.expect("the 31st event within a second is refused");
    assert_eq!(i, whiteboard::EVENTS_PER_SECOND);
    assert_eq!(code(&j), Some("rate_limited"));
    assert!(j["meta"]["retry_after_secs"].as_u64().unwrap() >= 1);
    // Per sender: others are not affected; after the window the sender may continue.
    let (st, _) = eph(&node, &bob.token, &r.text, body.clone()).await;
    assert_eq!(st, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (st, _) = eph(&node, &alice.token, &r.text, body).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn encrypted_ephemeral_content_is_checked_like_a_message() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    let mallory = node.register("mallory").await; // no device key
    let created = node.create_room(alice.token(), "Encrypted").await;
    let room_id = created["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&created);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), alice.token(), json!({})).await;
    for t in [bob.token(), mallory.token.as_str()] {
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), t, json!({})).await;
    }
    node.create_group(&mut alice, &channel).await;
    let conv = common::e2ee::qualified(&channel);
    let content = alice.client.encrypt_content(&conv, r#"{"type":"whiteboard.update","elements":[]}"#).unwrap();

    let mut rx = node.state.hub.subscribe();
    let (st, j) = eph(&node, alice.token(), &channel, json!({ "type": "whiteboard.update", "content": content })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let ev = loop {
        let ev = rx.recv().await.unwrap();
        if ev.kind == "ephemeral" {
            break ev;
        }
    };
    assert_eq!(ev.data["content"], content.as_str(), "the ciphertext is forwarded untouched");
    assert_eq!(ev.data["from"]["device_id"], alice.session.device_id.as_str());

    // A device without attestation cannot send encrypted ephemeral events (ENCRYPTION.md §5.3).
    let (st, j) =
        eph(&node, &mallory.token, &channel, json!({ "type": "whiteboard.update", "content": content })).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("e2ee.device_not_attested")));
    // A channel without a group knows no epoch yet.
    let voice = created["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, j) = eph(&node, bob.token(), &voice, json!({ "type": "cursor", "content": content })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("ephemeral.epoch_unknown")));
}

#[tokio::test]
async fn ephemeral_events_in_direct_messages_reach_the_members() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    let carol = node.crypto_user("carol").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    let content = alice.client.encrypt_content(&common::e2ee::qualified(&dm), r#"{"type":"cursor"}"#).unwrap();
    let mut rx = node.state.hub.subscribe();
    let (st, j) = eph(&node, alice.token(), &dm, json!({ "type": "cursor", "content": content })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let ev = loop {
        let ev = rx.recv().await.unwrap();
        if ev.kind == "ephemeral" {
            break ev;
        }
    };
    let tavrn_node::hub::Scope::UsersExceptDevice { users, device } = &ev.scope else {
        unreachable!("ephemeral events go to users except the sending device: {:?}", ev.scope)
    };
    let mut users = users.clone();
    users.sort();
    let mut expected = vec![alice.session.user_id.clone(), bob.session.user_id.clone()];
    expected.sort();
    assert_eq!(users, expected);
    assert_eq!(device, &alice.session.device_id);
    // Others cannot even see the DM.
    let (st, j) = eph(&node, carol.token(), &dm, json!({ "type": "cursor", "content": content })).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("conversation.not_found")));
    // Opening a board in a DM is allowed for its members.
    let (st, j) = eph(&node, bob.token(), &dm, json!({ "type": "whiteboard.open", "content": content })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["session"]["owner"], "bob@t.local");
}

#[tokio::test]
async fn whiteboard_session_follows_open_grant_and_close() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let r = room(&node, &alice, &[&bob, &carol]).await;
    let session_path = format!("/api/v1/conversations/{}/whiteboard", r.text);
    let c = |kind: &str| json!({ "type": kind });
    let (st, j) = node.get_auth(&session_path, &bob.token).await;
    assert_eq!((st, &j), (StatusCode::OK, &json!({ "session": null })));

    let mut rx = node.state.hub.subscribe();
    let (st, j) = eph(
        &node,
        &bob.token,
        &r.text,
        json!({ "type": "whiteboard.open", "content": c("whiteboard.open"), "session": { "open_for_all": false, "grants": ["Carol@t.local "] } }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let s = &j["session"];
    assert_eq!((s["owner"].as_str(), s["owner_id"].as_str()), (Some("bob@t.local"), Some(bob.user_id.as_str())));
    assert_eq!((s["device_id"].as_str(), s["open_for_all"].as_bool()), (Some(bob.device_id.as_str()), Some(false)));
    assert_eq!(s["grants"], json!(["carol@t.local"]), "grants are normalized");
    assert!(s["started_at"].is_string());
    let (_, j) = node.get_auth(&session_path, &alice.token).await;
    assert_eq!(j["session"]["owner"], "bob@t.local");
    // Every viewer (also the owner's own devices) learns about the change.
    let announced = loop {
        let ev = rx.recv().await.unwrap();
        if ev.kind == "whiteboard.session" {
            break ev;
        }
    };
    assert_eq!(announced.data["session"]["owner"], "bob@t.local");
    assert!(matches!(&announced.scope, tavrn_node::hub::Scope::Users(u) if u.len() == 3));

    // One board per channel; only the owner grants; grant needs the state.
    let (st, j) = eph(&node, &carol.token, &r.text, json!({ "type": "whiteboard.open", "content": c("x") })).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, Some("whiteboard.session_exists")));
    assert_eq!(j["meta"]["owner"], "bob@t.local");
    let grant = json!({ "type": "whiteboard.grant", "content": c("whiteboard.grant"), "session": { "open_for_all": true, "grants": [] } });
    let (st, j) = eph(&node, &carol.token, &r.text, grant.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.not_owner")));
    let (st, j) = eph(&node, &bob.token, &r.text, json!({ "type": "whiteboard.grant", "content": c("x") })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.state_missing")));
    let (st, j) = eph(
        &node,
        &bob.token,
        &r.text,
        json!({ "type": "whiteboard.grant", "content": c("x"), "session": { "grants": ["not an address"] } }),
    )
    .await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.grants_invalid")));
    let (st, j) = eph(&node, &bob.token, &r.text, grant).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!((j["session"]["open_for_all"].as_bool(), &j["session"]["grants"]), (Some(true), &json!([])));

    // Closing: not by a member without manage_channels, but by the owner or a moderator.
    let (st, j) = eph(&node, &carol.token, &r.text, json!({ "type": "whiteboard.close", "content": c("x") })).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.close_forbidden")));
    let (st, j) = eph(&node, &alice.token, &r.text, json!({ "type": "whiteboard.close", "content": c("x") })).await;
    assert_eq!(st, StatusCode::OK, "the room owner moderates: {j}");
    assert_eq!(j["session"], Value::Null);
    let (_, j) = node.get_auth(&session_path, &bob.token).await;
    assert_eq!(j, json!({ "session": null }));
    let (st, j) = eph(&node, &bob.token, &r.text, json!({ "type": "whiteboard.close", "content": c("x") })).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("whiteboard.no_session")));
    let (st, j) = eph(
        &node,
        &bob.token,
        &r.text,
        json!({ "type": "whiteboard.grant", "content": c("x"), "session": { "open_for_all": true } }),
    )
    .await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("whiteboard.no_session")));

    // Opening needs use_whiteboard (voice channels also connect).
    deny_member(&node, &alice.token, &r, &r.text, &carol.user_id, &[p::USE_WHITEBOARD]).await;
    let (st, j) = eph(&node, &carol.token, &r.text, json!({ "type": "whiteboard.open", "content": c("x") })).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.open_forbidden")));
    let (st, j) = eph(&node, &carol.token, &r.text, json!({ "type": "cursor", "content": c("cursor") })).await;
    assert_eq!(st, StatusCode::OK, "viewers still send cursors and snapshot requests: {j}");
}

#[tokio::test]
async fn sessions_in_voice_channels_need_connect_and_expire() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let r = room(&node, &alice, &[&bob]).await;
    // The voice channel of a plaintext room is encrypted; make it plaintext to send objects.
    sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
        .bind(&r.voice)
        .execute(&node.state.db)
        .await
        .unwrap();
    deny_member(&node, &alice.token, &r, &r.voice, &bob.user_id, &[p::CONNECT]).await;
    let open = json!({ "type": "whiteboard.open", "content": { "type": "whiteboard.open" } });
    let (st, j) = eph(&node, &bob.token, &r.voice, open.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.open_forbidden")));
    let (st, j) = eph(&node, &alice.token, &r.voice, open).await;
    assert_eq!(st, StatusCode::OK, "{j}");

    // Without any event of the owner for SESSION_TTL the session ends and the viewers are told.
    let mut rx = node.state.hub.subscribe();
    assert_eq!(whiteboard::sweep(&node.state, Instant::now()).await, 0);
    let later = Instant::now() + whiteboard::SESSION_TTL + Duration::from_secs(1);
    assert_eq!(whiteboard::sweep(&node.state, later).await, 1);
    let ev = loop {
        let ev = rx.recv().await.unwrap();
        if ev.kind == "whiteboard.session" {
            break ev;
        }
    };
    assert_eq!(ev.data, json!({ "conversation_id": r.voice, "session": null }));
    let (_, j) = node.get_auth(&format!("/api/v1/conversations/{}/whiteboard", r.voice), &bob.token).await;
    assert_eq!(j["session"], Value::Null);
}

// ---------------------------------------------------------------- scene library

/// An encrypted-looking blob (version 1, nonce, tag) of `len` bytes.
fn blob(len: usize, fill: u8) -> Vec<u8> {
    let mut b = vec![fill; len.max(29)];
    b[0] = 1;
    b
}

async fn put_scene(node: &TestNode, token: &str, id: &str, name: Option<&str>, body: Vec<u8>) -> (StatusCode, Value) {
    let encoded;
    let mut headers = vec![("content-type", "application/octet-stream")];
    if let Some(n) = name {
        encoded = n.bytes().map(|b| format!("%{b:02X}")).collect::<String>();
        headers.push(("tavrn-scene-name", encoded.as_str()));
    }
    let (st, _, body) =
        node.raw(Method::PUT, &format!("/api/v1/users/me/whiteboards/{id}"), token, &headers, body).await;
    (st, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

const S1: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VS1";
const S2: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VS2";
const S3: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2VS3";

#[tokio::test]
async fn scenes_crud_is_owner_only() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (st, j) = node.get_auth("/api/v1/users/me/whiteboards", &alice.token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!((&j["items"], j["max_scenes"].as_u64()), (&json!([]), Some(50)));
    assert_eq!(j["max_scene_bytes"], 5 * 1024 * 1024);

    let (st, j) = put_scene(&node, &alice.token, S1, None, blob(100, 7)).await;
    assert_eq!(
        (st, code(&j)),
        (StatusCode::BAD_REQUEST, Some("whiteboard.scene_name_invalid")),
        "new scenes need a name"
    );
    let (st, j) = put_scene(&node, &alice.token, S1, Some("Raid plan ä"), blob(100, 7)).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!((j["id"].as_str(), j["name"].as_str(), j["size"].as_i64()), (Some(S1), Some("Raid plan ä"), Some(100)));
    assert_eq!(j["thumbnail_size"], 0);

    let resp = node.get_with(&format!("/api/v1/users/me/whiteboards/{S1}"), &alice.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    assert_eq!(common::body_bytes(resp).await.to_vec(), blob(100, 7));
    // Bob neither sees nor changes alice's scenes (same id, own namespace).
    let resp = node.get_with(&format!("/api/v1/users/me/whiteboards/{S1}"), &bob.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let (st, _) = node.delete(&format!("/api/v1/users/me/whiteboards/{S1}"), &bob.token).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (_, j) = node.get_auth("/api/v1/users/me/whiteboards", &bob.token).await;
    assert_eq!(j["items"], json!([]));

    // Replace without a name keeps the name; rename; thumbnails.
    let (st, j) = put_scene(&node, &alice.token, S1, None, blob(200, 8)).await;
    assert_eq!((st, j["name"].as_str(), j["size"].as_i64()), (StatusCode::OK, Some("Raid plan ä"), Some(200)));
    let (st, j) =
        node.patch(&format!("/api/v1/users/me/whiteboards/{S1}"), &alice.token, json!({ "name": "  Map " })).await;
    assert_eq!((st, j["name"].as_str()), (StatusCode::OK, Some("Map")));
    let (st, j) = node.patch(&format!("/api/v1/users/me/whiteboards/{S1}"), &alice.token, json!({ "name": "" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.scene_name_invalid")));
    let (st, j) = node.patch(&format!("/api/v1/users/me/whiteboards/{S2}"), &alice.token, json!({ "name": "x" })).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("whiteboard.scene_not_found")));
    let resp = node.get_with(&format!("/api/v1/users/me/whiteboards/{S1}/thumbnail"), &alice.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let thumb_path = format!("/api/v1/users/me/whiteboards/{S1}/thumbnail");
    let (st, _, _) = node.raw(Method::PUT, &thumb_path, &alice.token, &[], blob(64, 3)).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let resp = node.get_with(&thumb_path, &alice.token).await;
    assert_eq!(common::body_bytes(resp).await.to_vec(), blob(64, 3));
    let (st, _, _) = node
        .raw(Method::PUT, &format!("/api/v1/users/me/whiteboards/{S2}/thumbnail"), &alice.token, &[], blob(64, 3))
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "thumbnails belong to existing scenes");
    let (_, j) = node.get_auth("/api/v1/users/me/whiteboards", &alice.token).await;
    assert_eq!((j["items"][0]["thumbnail_size"].as_i64(), j["items"][0]["name"].as_str()), (Some(64), Some("Map")));

    let (st, _) = node.delete(&format!("/api/v1/users/me/whiteboards/{S1}"), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) = node.delete(&format!("/api/v1/users/me/whiteboards/{S1}"), &alice.token).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, Some("whiteboard.scene_not_found")));
}

#[tokio::test]
async fn scene_limits_are_enforced() {
    let node = common::test_node_with(DOMAIN, |c| c.whiteboard_max_scenes = 2).await;
    let alice = node.register("alice").await;
    for bad_id in ["not-a-ulid", "01J9ZK3G5M8Q2W4E6R8T0Y2Vs1"] {
        let (st, j) = put_scene(&node, &alice.token, bad_id, Some("x"), blob(40, 1)).await;
        assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.scene_id_invalid")), "{bad_id}");
    }
    let mut v2 = blob(40, 1);
    v2[0] = 2;
    for bad in [v2, vec![1u8; 28], Vec::new()] {
        let (st, j) = put_scene(&node, &alice.token, S1, Some("x"), bad).await;
        assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.blob_invalid")));
    }
    let (st, j) = put_scene(&node, &alice.token, S1, Some(&"n".repeat(65)), blob(40, 1)).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("whiteboard.scene_name_invalid")));
    let (st, j) = put_scene(&node, &alice.token, S1, Some("big"), blob(5 * 1024 * 1024 + 1, 1)).await;
    assert_eq!((st, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, Some("whiteboard.scene_too_large")));
    let (st, j) = put_scene(&node, &alice.token, S1, Some("max"), blob(5 * 1024 * 1024, 1)).await;
    assert_eq!(st, StatusCode::CREATED, "exactly 5 MB is fine: {j}");
    let (st, _) = put_scene(&node, &alice.token, S2, Some("two"), blob(40, 1)).await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, j) = put_scene(&node, &alice.token, S3, Some("three"), blob(40, 1)).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.scene_limit")));
    let (st, _) = put_scene(&node, &alice.token, S2, None, blob(41, 1)).await;
    assert_eq!(st, StatusCode::OK, "replacing works at the limit");
    let thumb = format!("/api/v1/users/me/whiteboards/{S2}/thumbnail");
    let (st, _, body) = node.raw(Method::PUT, &thumb, &alice.token, &[], blob(64 * 1024 + 1, 1)).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "whiteboard.thumbnail_too_large");

    // An identity reset makes the scenes unreadable (other backup key): they are deleted with it.
    let master = tavrn_crypto::MasterSecret::generate().unwrap();
    node.put_identity(&alice, &master).await;
    let fresh = tavrn_crypto::MasterSecret::generate().unwrap();
    let (st, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            &alice.token,
            json!({ "identity_public_key": common::e2ee::b64(&fresh.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert!(st.is_success(), "{j}");
    let (_, j) = node.get_auth("/api/v1/users/me/whiteboards", &alice.token).await;
    assert_eq!(j["items"], json!([]));
}

#[tokio::test]
async fn backgrounds_are_converted_but_not_stored() {
    let node = common::test_node_with(DOMAIN, |c| c.media_ffmpeg = "off".into()).await;
    let alice = node.register("alice").await;
    let png = base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
        .unwrap();
    let (st, headers, body) =
        node.raw(Method::POST, "/api/v1/users/me/whiteboards/background", &alice.token, &[], png).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(headers["content-type"], "image/png", "without ffmpeg the sanitized still comes back");
    assert_eq!(&body[1..4], b"PNG");
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM media").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(stored, 0);
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#.to_vec();
    let (st, _, body) = node.raw(Method::POST, "/api/v1/users/me/whiteboards/background", &alice.token, &[], svg).await;
    assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["code"], "media.type_not_allowed");
}
