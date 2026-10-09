// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! Channel visibility of realtime fan-out (PROTOCOL.md §6): the events of a room channel (messages, reactions, pins,
//! typing, threads, …) reach only the room members who may view the channel at delivery time; the room's metadata
//! events still reach every member. The same check gates the `notify` hints to other nodes (FEDERATION.md §5.2);
//! web push is covered in push_flow.rs.
use crate::common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_node::permissions as p;
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn serve(node: &TestNode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{addr}/api/v1/ws")
}

async fn hello(url: &str, token: &str) -> Socket {
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    ws.send(Message::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    let ready = next_event(&mut ws).await;
    assert_eq!(ready["op"], "ready", "{ready}");
    ws
}

/// The next frame, skipping presence updates.
async fn next_event(ws: &mut Socket) -> Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] != "presence.update" {
                return v;
            }
        }
    }
}

/// Every event up to (without) the `message.create` whose body is `marker`.
async fn until_marker(ws: &mut Socket, marker: &str) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let ev = next_event(ws).await;
        if ev["type"] == "message.create" && ev["data"]["content"]["body"] == marker {
            return seen;
        }
        seen.push(ev);
    }
}

fn kinds(events: &[Value]) -> Vec<&str> {
    events.iter().map(|e| e["type"].as_str().unwrap_or("")).collect()
}

fn text(body: &str) -> Value {
    json!({ "content": { "type": "text", "body": body } })
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// A plaintext room of Alice's with Bob and Carol, an open channel and the private channel `secret`, which
/// @everyone may not view and Carol may (member override). Returns the room, the open and the secret channel and
/// the @everyone role.
struct Room {
    node: TestNode,
    alice: Session,
    bob: Session,
    carol: Session,
    room_id: String,
    open: String,
    secret: String,
    everyone: String,
}

impl Room {
    async fn new() -> Self {
        let node = test_node("t.local").await;
        let alice = node.register("alice").await;
        let bob = node.register("bob").await;
        let carol = node.register("carol").await;
        let room = node.plaintext_room(&alice.token, "Room").await;
        let room_id = room["id"].as_str().unwrap().to_string();
        let open = TestNode::text_channel(&room);
        let everyone =
            room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
        let everyone = everyone.as_str().unwrap().to_string();
        join(&node, &alice, &room_id, &bob).await;
        join(&node, &alice, &room_id, &carol).await;
        let (s, ch) = node
            .post(
                &format!("/api/v1/rooms/{room_id}/channels"),
                &alice.token,
                json!({ "name": "secret", "kind": "text", "encrypted": false }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{ch}");
        let secret = ch["id"].as_str().unwrap().to_string();
        let r = Self { node, alice, bob, carol, room_id, open, secret, everyone };
        let everyone = r.everyone.clone();
        r.set_override("role", &everyone, 0, p::VIEW_CHANNEL).await;
        let carol_id = r.carol.user_id.clone();
        r.set_override("member", &carol_id, p::VIEW_CHANNEL, 0).await;
        r
    }

    async fn set_override(&self, subject_type: &str, subject_id: &str, allow: u64, deny: u64) {
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": self.secret, "subject_type": subject_type,
                        "subject_id": subject_id, "allow": allow.to_string(), "deny": deny.to_string() }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }

    fn messages(&self, channel: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{channel}/messages", self.room_id)
    }

    async fn post(&self, channel: &str, body: &str) -> Value {
        let (s, m) = self.node.post(&self.messages(channel), &self.alice.token, text(body)).await;
        assert_eq!(s, StatusCode::CREATED, "{m}");
        m
    }
}

/// Is any of the events about the channel `id` (its id anywhere in `data`)?
fn about(events: &[Value], id: &str) -> Vec<String> {
    events.iter().filter(|e| e["data"].to_string().contains(id)).map(|e| e["type"].to_string()).collect()
}

#[tokio::test]
async fn a_private_channel_s_events_reach_only_its_viewers() {
    let r = Room::new().await;
    let url = serve(&r.node).await;
    let mut alice_ws = hello(&url, &r.alice.token).await;
    let mut bob_ws = hello(&url, &r.bob.token).await;
    let mut carol_ws = hello(&url, &r.carol.token).await;

    // Everything that happens in the secret channel: message, edit, reaction, pin, typing, thread, deletion.
    let m = r.post(&r.secret, "for carol").await;
    let mid = m["id"].as_str().unwrap();
    let path = format!("{}/{mid}", r.messages(&r.secret));
    let (s, j) = r.node.patch(&path, &r.alice.token, text("for carol, edited")).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.put(&format!("{path}/reactions/%F0%9F%91%8D"), &r.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let pin = format!("/api/v1/rooms/{}/channels/{}/pins/{mid}", r.room_id, r.secret);
    let (s, j) = r.node.put(&pin, &r.alice.token, json!({})).await;
    assert!(s.is_success(), "{j}");
    alice_ws
        .send(Message::Text(json!({ "op": "typing", "room_id": r.room_id, "channel_id": r.secret }).to_string().into()))
        .await
        .unwrap();
    // Bob cannot view the channel: his typing there is dropped (nobody sees it, Carol included).
    bob_ws
        .send(Message::Text(json!({ "op": "typing", "room_id": r.room_id, "channel_id": r.secret }).to_string().into()))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let threads = format!("/api/v1/rooms/{}/channels/{}/threads", r.room_id, r.secret);
    let (s, thread) =
        r.node.post(&threads, &r.alice.token, json!({ "title": "Plans", "message": text("in a thread") })).await;
    assert_eq!(s, StatusCode::CREATED, "{thread}");
    let (s, j) = r.node.delete(&format!("/api/v1/threads/{}", thread["id"].as_str().unwrap()), &r.alice.token).await;
    assert!(s.is_success(), "{j}");
    let (s, j) = r.node.delete(&path, &r.alice.token).await;
    assert!(s.is_success(), "{j}");
    // A marker in the open channel: everything before it has been fanned out.
    r.post(&r.open, "marker 1").await;

    let bob_saw = until_marker(&mut bob_ws, "marker 1").await;
    assert_eq!(about(&bob_saw, &r.secret), Vec::<String>::new(), "bob saw: {bob_saw:?}");
    let carol_saw = until_marker(&mut carol_ws, "marker 1").await;
    let carol_kinds = kinds(&carol_saw);
    for kind in ["message.create", "message.update", "message.delete", "typing", "thread.create", "thread.delete"] {
        assert!(carol_kinds.contains(&kind), "carol misses {kind}: {carol_kinds:?}");
    }
    let typists: Vec<&Value> =
        carol_saw.iter().filter(|e| e["type"] == "typing").map(|e| &e["data"]["user_id"]).collect();
    assert_eq!(typists, vec![&json!(r.alice.user_id)], "only alice's typing: {carol_saw:?}");
    let alice_kinds = kinds(&until_marker(&mut alice_ws, "marker 1").await).len();
    assert!(alice_kinds >= carol_kinds.len() - 1, "the owner sees the channel too");

    // Lifting the @everyone deny (override removed): bob learns the channel, gets its overrides and then its events.
    let everyone = r.everyone.clone();
    r.set_override("role", &everyone, 0, 0).await;
    let ev = next_event(&mut bob_ws).await;
    assert_eq!((ev["type"].as_str(), ev["data"]["id"].as_str()), (Some("channel.create"), Some(r.secret.as_str())));
    assert_eq!(ev["data"]["name"], "secret");
    assert_eq!(next_event(&mut bob_ws).await["type"], "override.update", "now listed to bob");
    r.post(&r.secret, "for everyone now").await;
    let ev = next_event(&mut bob_ws).await;
    assert_eq!(
        (ev["type"].as_str(), ev["data"]["conversation_id"].as_str()),
        (Some("message.create"), Some(r.secret.as_str()))
    );

    // Denied again for bob only (member override): the channel disappears for him (hidden, not deleted), and his
    // socket stops at once.
    let bob_id = r.bob.user_id.clone();
    r.set_override("member", &bob_id, 0, p::VIEW_CHANNEL).await;
    let ev = next_event(&mut bob_ws).await;
    assert_eq!(ev["type"], "channel.delete", "{ev}");
    assert_eq!(ev["data"], json!({ "room_id": r.room_id, "id": r.secret, "hidden": true }));
    r.post(&r.secret, "not for bob").await;
    r.post(&r.open, "marker 2").await;
    let bob_saw = until_marker(&mut bob_ws, "marker 2").await;
    assert_eq!(about(&bob_saw, &r.secret), Vec::<String>::new(), "bob saw: {bob_saw:?}");
    assert_eq!(
        kinds(&until_marker(&mut carol_ws, "marker 2").await).iter().filter(|k| **k == "message.create").count(),
        2
    );
}

#[tokio::test]
async fn roles_and_membership_changes_apply_to_the_fan_out_at_once() {
    let r = Room::new().await;
    let url = serve(&r.node).await;
    let mut bob_ws = hello(&url, &r.bob.token).await;
    r.post(&r.secret, "before the role").await;
    // A role whose override lets its members view the channel, given to bob.
    let (s, role) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", r.room_id),
            &r.alice.token,
            json!({ "name": "Insiders", "permissions": "0" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap().to_string();
    r.set_override("role", &role_id, p::VIEW_CHANNEL, 0).await;
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", r.room_id, r.bob.user_id),
            &r.alice.token,
            json!({ "roles": [role_id] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    r.post(&r.secret, "with the role").await;
    // The message arrives (until_marker would time out otherwise); the one before the role did not.
    let saw = until_marker(&mut bob_ws, "with the role").await;
    assert_eq!(about(&saw, &r.secret).iter().filter(|k| k.contains("message")).count(), 0, "bob saw: {saw:?}");

    // The role is taken away again: nothing more from the channel.
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", r.room_id, r.bob.user_id),
            &r.alice.token,
            json!({ "roles": [] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    r.post(&r.secret, "without the role").await;
    r.post(&r.open, "marker").await;
    let saw = until_marker(&mut bob_ws, "marker").await;
    assert_eq!(about(&saw, &r.secret).iter().filter(|k| k.contains("message")).count(), 0, "bob saw: {saw:?}");
    assert!(kinds(&saw).contains(&"member.update"), "metadata still arrives: {saw:?}");
}

/// Remote members who cannot view a channel get no `notify` hint for its messages, `@everyone` and thread follows
/// included; once they may view it, they do.
#[tokio::test]
async fn notify_hints_only_for_remote_members_who_can_view_the_channel() {
    use common::federation::two_nodes;
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let room = a.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    a.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "join_mode": "public" })).await;
    let bob = b.register("bob").await;
    let carol = b.register("carol").await;
    let bob_on_a = a.sign_in_from(&b, &bob).await;
    let carol_on_a = a.sign_in_from(&b, &carol).await;
    for s in [&bob_on_a, &carol_on_a] {
        let (st, j) = a.post(&format!("/api/v1/rooms/{room_id}/join"), &s.token, json!({})).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let (s, ch) = a
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "secret", "kind": "text", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let secret = ch["id"].as_str().unwrap().to_string();
    // Bob follows a thread of the channel while he may still view it.
    let threads = format!("/api/v1/rooms/{room_id}/channels/{secret}/threads");
    let (st, thread) = a.post(&threads, &bob_on_a.token, json!({ "title": "Bob's", "message": text("mine") })).await;
    assert_eq!(st, StatusCode::CREATED, "{thread}");
    let thread_id = thread["id"].as_str().unwrap().to_string();
    fed_override(&a, &alice, &room_id, &secret, ("role", &everyone), 0, p::VIEW_CHANNEL).await;
    fed_override(
        &a,
        &alice,
        &room_id,
        &secret,
        ("member", carol_on_a.response["user"]["id"].as_str().unwrap()),
        p::VIEW_CHANNEL,
        0,
    )
    .await;
    a.deliver().await;

    let messages = format!("/api/v1/rooms/{room_id}/channels/{secret}/messages");
    let everyone_msg = json!({ "content": { "type": "text", "body": "@everyone" }, "mentions_everyone": true });
    let (st, j) = a.post(&messages, &alice.token, everyone_msg.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(notified(&a).await, vec!["carol@b.test"], "bob cannot view the channel");
    a.deliver().await;
    let in_thread =
        json!({ "content": { "type": "text", "body": "news" }, "thread_id": thread_id, "mentions": ["bob@b.test"] });
    let (st, j) = a.post(&messages, &alice.token, in_thread).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(notified(&a).await, Vec::<String>::new(), "neither following nor a mention reaches bob");

    // The deny is lifted: bob's hints come back.
    fed_override(&a, &alice, &room_id, &secret, ("role", &everyone), 0, 0).await;
    let (st, j) = a.post(&messages, &alice.token, everyone_msg).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(notified(&a).await, vec!["bob@b.test"], "carol's hint for the channel is coalesced");
}

async fn fed_override(
    node: &TestNode,
    owner: &Session,
    room_id: &str,
    channel: &str,
    (subject_type, subject_id): (&str, &str),
    allow: u64,
    deny: u64,
) {
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &owner.token,
            json!({ "target_type": "channel", "target_id": channel, "subject_type": subject_type,
                    "subject_id": subject_id, "allow": perms(&[allow]), "deny": perms(&[deny]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// The recipients of the queued `notify` hints.
async fn notified(node: &common::federation::FedNode) -> Vec<String> {
    let mut to: Vec<String> = node
        .outbox()
        .await
        .into_iter()
        .filter(|e| e.kind == "notify")
        .map(|e| serde_json::from_str::<Value>(&e.body).unwrap()["to"].as_str().unwrap().to_string())
        .collect();
    to.sort();
    to
}

/// PROTOCOL.md §6 "Audiences": the metadata of a private channel (`channel.*`, `override.update`) and of a category
/// whose channels are all hidden (`category.*`) reach only the members to whom they are listed; a real deletion is
/// not `hidden`. `GET /rooms/{id}` lists only the overrides of the listed channels and categories.
#[tokio::test]
async fn private_channel_and_category_metadata_reach_only_their_audience() {
    let r = Room::new().await;
    let url = serve(&r.node).await;
    let mut bob_ws = hello(&url, &r.bob.token).await;
    let mut carol_ws = hello(&url, &r.carol.token).await;
    let room = format!("/api/v1/rooms/{}", r.room_id);
    let secret = format!("{room}/channels/{}", r.secret);
    let (s, j) = r.node.patch(&secret, &r.alice.token, json!({ "name": "renamed", "topic": "plans" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let carol_id = r.carol.user_id.clone();
    r.set_override("member", &carol_id, p::VIEW_CHANNEL | p::SEND_MESSAGES, 0).await;
    let (_, detail) = r.node.get_auth(&room, &r.bob.token).await;
    assert!(!detail.to_string().contains(&r.secret), "bob's room detail names the channel: {detail}");

    // A category: listed to managers while empty, to bob once it holds a channel he can view.
    let (s, cat) = r.node.post(&format!("{room}/categories"), &r.alice.token, json!({ "name": "staff" })).await;
    assert_eq!(s, StatusCode::CREATED, "{cat}");
    let cat = cat["id"].as_str().unwrap().to_string();
    let (s, ch) = r
        .node
        .post(
            &format!("{room}/channels"),
            &r.alice.token,
            json!({ "kind": "text", "name": "notes", "encrypted": false, "category_id": cat }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let notes = ch["id"].as_str().unwrap().to_string();
    // Let bob's connection deliver the gain before the loss below: a connection checks each event against the
    // state at delivery time, so on a slow machine a gain and a loss that are both committed before it catches up
    // would cancel out (the end state is the same, the intermediate frames are not sent).
    r.post(&r.open, "sync").await;
    let mut bob_saw = until_marker(&mut bob_ws, "sync").await;
    // Hiding the category from @everyone: bob loses its channel and the category, both hidden.
    let (s, j) = r
        .node
        .put(
            &format!("{room}/overrides"),
            &r.alice.token,
            json!({ "target_type": "category", "target_id": cat, "subject_type": "role", "subject_id": r.everyone,
                    "allow": "0", "deny": p::VIEW_CHANNEL.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.delete(&secret, &r.alice.token).await;
    assert!(s.is_success(), "{j}");
    r.post(&r.open, "marker").await;

    bob_saw.extend(until_marker(&mut bob_ws, "marker").await);
    assert_eq!(about(&bob_saw, &r.secret), Vec::<String>::new(), "bob saw: {bob_saw:?}");
    let seen: Vec<(String, Value)> = bob_saw
        .iter()
        .filter(|e| {
            e["type"]
                .as_str()
                .is_some_and(|t| t.starts_with("channel.") || t.starts_with("category.") || t.starts_with("override."))
        })
        .map(|e| (e["type"].as_str().unwrap().to_string(), e["data"]["id"].clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("category.create".to_string(), json!(cat)),
            ("channel.create".to_string(), json!(notes)),
            ("channel.delete".to_string(), json!(notes)),
            ("category.delete".to_string(), json!(cat)),
        ],
        "bob saw: {bob_saw:?}"
    );
    let hidden: Vec<&Value> = bob_saw
        .iter()
        .filter(|e| e["type"].as_str().is_some_and(|t| t.ends_with(".delete")))
        .map(|e| &e["data"]["hidden"])
        .collect();
    assert_eq!(hidden, vec![&json!(true), &json!(true)]);

    let carol_saw = until_marker(&mut carol_ws, "marker").await;
    let kinds = kinds(&carol_saw);
    for kind in ["channel.update", "override.update", "channel.delete"] {
        assert!(kinds.contains(&kind), "carol misses {kind}: {kinds:?}");
    }
    let deleted =
        carol_saw.iter().find(|e| e["type"] == "channel.delete" && e["data"]["id"] == r.secret.as_str()).unwrap();
    assert!(deleted["data"].get("hidden").is_none(), "a real deletion: {deleted}");
}
