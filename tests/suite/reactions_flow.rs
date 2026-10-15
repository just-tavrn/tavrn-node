// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Reactions (protocol PROTOCOL.md §6 "Message events carry no per-viewer state", §7 "Reactions"): the
//! `message.update` of a reaction change names the emoji, the reactor and whether it was added; message events carry
//! `reactions[].me = false` for every recipient while HTTP responses keep the caller's flags; the paged reactors route
//! with the message's read rules; members of other nodes react through their federated session with the same shape.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    Session,
    crossnode::{Ws, event, no_event, ws},
    e2ee::DOMAIN,
    federation::{FedNode, two_nodes},
};
use serde_json::{Value, json};

const THUMBS: &str = "%F0%9F%91%8D";
const PARTY: &str = "%F0%9F%8E%89";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

/// `(emoji, count, me)` of a message's reactions.
fn chips(m: &Value) -> Vec<(String, i64, bool)> {
    m["reactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["emoji"].as_str().unwrap().to_string(), r["count"].as_i64().unwrap(), r["me"].as_bool().unwrap()))
        .collect()
}

fn chip(emoji: &str, count: i64, me: bool) -> (String, i64, bool) {
    (emoji.to_string(), count, me)
}

/// The next `message.update` on a socket.
async fn update(ws: &mut Ws) -> Value {
    event(ws, "message.update").await
}

struct World {
    node: FedNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
    /// App token of a bot installed in the room, scopes `messages:read` and `messages:write`.
    bot: String,
    bot_user_id: String,
    /// App token of the same bot without `messages:read`.
    bot_blind: String,
}

impl World {
    fn messages(&self) -> String {
        format!("/api/v1/conversations/{}/messages", self.channel)
    }

    fn reaction(&self, message_id: &str, emoji: &str) -> String {
        format!("{}/{message_id}/reactions/{emoji}", self.messages())
    }

    async fn react(&self, token: &str, message_id: &str, emoji: &str, add: bool) -> Value {
        let method = if add { Method::PUT } else { Method::DELETE };
        let (s, j) = self.node.req(method, &self.reaction(message_id, emoji), Some(token), None).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        j
    }

    async fn reactors(&self, token: &str, message_id: &str, emoji: &str, query: &str) -> (StatusCode, Value) {
        self.node.get_auth(&format!("{}{query}", self.reaction(message_id, emoji)), token).await
    }
}

async fn app_token(node: &FedNode, owner: &Session, app_id: &str, scopes: &[&str]) -> String {
    let (s, t) = node
        .post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, json!({ "name": "t", "scopes": scopes }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    t["secret"].as_str().unwrap().to_string()
}

async fn world() -> World {
    let node = FedNode::serve_one(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = id(&room);
    let channel = common::TestNode::text_channel(&room);
    let bob = node.register("bob").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, app) = node.post("/api/v1/applications", &alice.token, json!({ "name": "Counter", "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = id(&app);
    let bot = app_token(&node, &alice, &app_id, &["messages:read", "messages:write"]).await;
    let bot_blind = app_token(&node, &alice, &app_id, &["messages:write"]).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &alice.token,
            json!({ "application": format!("{DOMAIN}/{app_id}") }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let bot_user_id = app["bot"]["id"].as_str().unwrap().to_string();
    World { node, alice, bob, room_id, channel, bot, bot_user_id, bot_blind }
}

#[tokio::test]
async fn reaction_events_name_the_change_and_carry_no_viewer_flags() {
    let w = world().await;
    let (s, m) = w.node.send(&w.bob.token, &w.room_id, &w.channel, "React to me").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let mid = id(&m);
    let mut alice_ws = ws(&w.node, &w.alice.token).await;
    let mut bob_ws = ws(&w.node, &w.bob.token).await;
    let mut bot_ws = ws(&w.node, &w.bot).await;

    // Bob reacts first: his response has his flag, every event (his own connections included) has none.
    let r = w.react(&w.bob.token, &mid, PARTY, true).await;
    assert_eq!(chips(&r), vec![chip("🎉", 1, true)]);
    for sock in [&mut alice_ws, &mut bob_ws, &mut bot_ws] {
        let e = update(sock).await;
        assert_eq!(e["id"], mid.as_str());
        assert_eq!(chips(&e), vec![chip("🎉", 1, false)], "{e}");
        assert_eq!(
            e["reaction"],
            json!({ "emoji": "🎉", "user": format!("bob@{DOMAIN}"), "user_id": w.bob.user_id, "added": true })
        );
    }

    // Alice adds 👍: the reactor's flags never reach the others (the security aspect of node #83), and Bob's own
    // 🎉 flag is not in the event either.
    let r = w.react(&w.alice.token, &mid, THUMBS, true).await;
    assert_eq!(chips(&r), vec![chip("🎉", 1, false), chip("👍", 1, true)]);
    for sock in [&mut alice_ws, &mut bob_ws, &mut bot_ws] {
        let e = update(sock).await;
        assert_eq!(chips(&e), vec![chip("🎉", 1, false), chip("👍", 1, false)], "{e}");
        assert_eq!(e["reaction"]["emoji"], "👍");
        assert_eq!(e["reaction"]["user"], format!("alice@{DOMAIN}"));
        assert_eq!(e["reaction"]["user_id"], w.alice.user_id.as_str());
        assert_eq!(e["reaction"]["added"], true);
    }
    // The list keeps each caller's view.
    let (_, list) = w.node.get_auth(&w.messages(), &w.bob.token).await;
    assert_eq!(chips(&list[0]), vec![chip("🎉", 1, true), chip("👍", 1, false)]);

    // Adding an existing reaction changes nothing: the same answer, no event.
    let r = w.react(&w.alice.token, &mid, THUMBS, true).await;
    assert_eq!(chips(&r), vec![chip("🎉", 1, false), chip("👍", 1, true)]);
    assert!(no_event(&mut bob_ws, "message.update", 300).await, "a repeated reaction sends no event");

    // A removal names the change with added: false.
    let r = w.react(&w.alice.token, &mid, THUMBS, false).await;
    assert_eq!(chips(&r), vec![chip("🎉", 1, false)]);
    for sock in [&mut alice_ws, &mut bob_ws, &mut bot_ws] {
        let e = update(sock).await;
        assert_eq!(chips(&e), vec![chip("🎉", 1, false)], "{e}");
        assert_eq!(
            e["reaction"],
            json!({ "emoji": "👍", "user": format!("alice@{DOMAIN}"), "user_id": w.alice.user_id, "added": false })
        );
    }
    // Removing a missing reaction: no event either.
    w.react(&w.alice.token, &mid, THUMBS, false).await;
    assert!(no_event(&mut bob_ws, "message.update", 300).await, "removing a missing reaction sends no event");

    // A bot reacts like a member.
    let r = w.react(&w.bot, &mid, THUMBS, true).await;
    assert_eq!(chips(&r), vec![chip("🎉", 1, false), chip("👍", 1, true)]);
    let e = update(&mut alice_ws).await;
    assert_eq!(e["reaction"]["user_id"], w.bot_user_id.as_str());
    assert_eq!(chips(&e), vec![chip("🎉", 1, false), chip("👍", 1, false)]);
    update(&mut bob_ws).await;
    update(&mut bot_ws).await;

    // Other causes of message.update carry no reaction field and no flags either: Bob's edit, Alice's pin.
    let (s, edited) = w
        .node
        .patch(
            &format!("{}/{mid}", w.messages()),
            &w.bob.token,
            json!({ "content": { "type": "text", "body": "Edited" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{edited}");
    assert_eq!(chips(&edited), vec![chip("🎉", 1, true), chip("👍", 1, false)], "the editor's response keeps its view");
    for sock in [&mut alice_ws, &mut bob_ws, &mut bot_ws] {
        let e = update(sock).await;
        assert!(e.get("reaction").is_none(), "{e}");
        assert_eq!(chips(&e), vec![chip("🎉", 1, false), chip("👍", 1, false)], "{e}");
    }
    let (s, pinned) =
        w.node.put(&format!("/api/v1/conversations/{}/pins/{mid}", w.channel), &w.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "bob may not pin: {pinned}");
    let (s, pinned) =
        w.node.put(&format!("/api/v1/conversations/{}/pins/{mid}", w.channel), &w.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{pinned}");
    let e = update(&mut bob_ws).await;
    assert_eq!(e["pinned"], true);
    assert!(e.get("reaction").is_none(), "{e}");
    assert_eq!(chips(&e), vec![chip("🎉", 1, false), chip("👍", 1, false)], "{e}");
}

#[tokio::test]
async fn the_reactors_route_pages_who_reacted() {
    let w = world().await;
    let (s, m) = w.node.send(&w.alice.token, &w.room_id, &w.channel, "Sign up with 👍").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let mid = id(&m);
    w.react(&w.alice.token, &mid, THUMBS, true).await;
    w.react(&w.bob.token, &mid, THUMBS, true).await;
    w.react(&w.bot, &mid, THUMBS, true).await;
    w.react(&w.bob.token, &mid, PARTY, true).await;

    // Oldest first, everyone with address and id.
    let (s, all) = w.reactors(&w.bob.token, &mid, THUMBS, "").await;
    assert_eq!(s, StatusCode::OK, "{all}");
    let users: Vec<&str> = all["items"].as_array().unwrap().iter().map(|i| i["user"].as_str().unwrap()).collect();
    assert_eq!(users.len(), 3);
    assert_eq!(users[..2], [format!("alice@{DOMAIN}"), format!("bob@{DOMAIN}")]);
    assert_eq!(all["items"][0]["user_id"], w.alice.user_id.as_str());
    assert_eq!(all["items"][2]["user_id"], w.bot_user_id.as_str());
    assert!(all["items"][0]["created_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(all["next"], Value::Null);

    // Pages of one: the cursor walks the list without repeats.
    let (s, p1) = w.reactors(&w.bob.token, &mid, THUMBS, "?limit=1").await;
    assert_eq!(s, StatusCode::OK, "{p1}");
    assert_eq!(p1["items"].as_array().unwrap().len(), 1);
    assert_eq!(p1["items"][0]["user_id"], w.alice.user_id.as_str());
    let next = p1["next"].as_str().unwrap().to_string();
    let (_, p2) = w.reactors(&w.bob.token, &mid, THUMBS, &format!("?limit=1&after={}", urlencode(&next))).await;
    assert_eq!(p2["items"][0]["user_id"], w.bob.user_id.as_str(), "{p2}");
    let next = p2["next"].as_str().unwrap().to_string();
    let (_, p3) = w.reactors(&w.bob.token, &mid, THUMBS, &format!("?limit=1&after={}", urlencode(&next))).await;
    assert_eq!(p3["items"][0]["user_id"], w.bot_user_id.as_str(), "{p3}");
    // The last page may still say there is a next one only when more rows exist: here there are none.
    assert_eq!(p3["next"], Value::Null, "{p3}");
    // A cursor stays valid when its reactor removes the reaction meanwhile.
    w.react(&w.bob.token, &mid, THUMBS, false).await;
    let (_, p) = w.reactors(&w.alice.token, &mid, THUMBS, &format!("?after={}", urlencode(&next))).await;
    assert_eq!(p["items"].as_array().unwrap().len(), 1, "{p}");
    assert_eq!(p["items"][0]["user_id"], w.bot_user_id.as_str());

    // Other emoji are separate; an emoji nobody used lists no one.
    let (_, party) = w.reactors(&w.alice.token, &mid, PARTY, "").await;
    assert_eq!(party["items"].as_array().unwrap().len(), 1);
    assert_eq!(party["items"][0]["user_id"], w.bob.user_id.as_str());
    let (s, none) = w.reactors(&w.alice.token, &mid, "%E2%9D%A4", "").await;
    assert_eq!(s, StatusCode::OK, "{none}");
    assert_eq!(none, json!({ "items": [], "next": null }));

    // Limits and validation.
    let (s, big) = w.reactors(&w.alice.token, &mid, THUMBS, "?limit=1000").await;
    assert_eq!(s, StatusCode::OK, "{big}");
    for bad in
        ["nonsense", "2026-10-15T12:00:00.000Z_notanid", "_01J00000000000000000000000", "x_01J00000000000000000000000"]
    {
        let (s, j) = w.reactors(&w.alice.token, &mid, THUMBS, &format!("?after={}", urlencode(bad))).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "reaction.cursor_invalid"), "{bad}: {j}");
    }
    let (s, j) = w.reactors(&w.alice.token, &mid, "a%20b", "").await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "reaction.invalid"), "{j}");
    let (s, j) = w.reactors(&w.alice.token, "01J0000000000000000000000Z", THUMBS, "").await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "message.not_found"), "{j}");

    // Bots need messages:read.
    let (s, j) = w.reactors(&w.bot, &mid, THUMBS, "").await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = w.reactors(&w.bot_blind, &mid, THUMBS, "").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");

    // A non-member, and a member who cannot view the channel, are refused.
    let carol = w.node.register("carol").await;
    let (s, j) = w.reactors(&carol.token, &mid, THUMBS, "").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"), "{j}");
    let (s, j) = w
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", w.room_id),
            &w.alice.token,
            json!({ "target_type": "channel", "target_id": w.channel, "subject_type": "member",
                    "subject_id": w.bob.user_id, "allow": "0", "deny": tavrn_node::permissions::VIEW_CHANNEL.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = w.reactors(&w.bob.token, &mid, THUMBS, "").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "channel.view_forbidden"), "{j}");
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test]
async fn members_of_other_nodes_react_with_the_same_event_shape() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Meeting point").await;
    let room_id = id(&room);
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let channel = common::TestNode::text_channel(&room);
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (st, joined) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{joined}");
    let (st, msg) = b.send(&carol.token, &room_id, &channel, "Hello").await;
    assert_eq!(st, StatusCode::CREATED, "{msg}");
    let mid = id(&msg);
    let mut carol_ws = ws(&b, &carol.token).await;

    let url = format!("/api/v1/conversations/{channel}/messages/{mid}/reactions/{THUMBS}");
    let (st, reacted) = b.req(Method::PUT, &url, Some(&remote.token), None).await;
    assert_eq!(st, StatusCode::OK, "{reacted}");
    assert_eq!(chips(&reacted), vec![chip("👍", 1, true)]);
    let e = update(&mut carol_ws).await;
    assert_eq!(chips(&e), vec![chip("👍", 1, false)], "{e}");
    assert_eq!(e["reaction"]["user"], "alice@a.test");
    assert_eq!(e["reaction"]["added"], true);
    let alice_id = e["reaction"]["user_id"].as_str().unwrap().to_string();

    let (st, list) = b.get_auth(&url, &carol.token).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    assert_eq!(list["items"][0]["user"], "alice@a.test");
    assert_eq!(list["items"][0]["user_id"], alice_id.as_str());
}
