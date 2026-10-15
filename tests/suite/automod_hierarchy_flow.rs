// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Auto-moderation as a moderator acts: its timeouts are announced like a moderator's (and take effect everywhere
//! at once), its rules reach only members their author outranks, and matching stays cheap for crafted rules and text.
use crate::common;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::{hub::Event, permissions as p};
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

async fn role(node: &TestNode, owner: &str, room_id: &str, name: &str, bits: &[u64], position: i64) -> String {
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            owner,
            json!({ "name": name, "permissions": common::perms(bits), "position": position }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    role["id"].as_str().unwrap().to_string()
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

/// A `timeout` or `delete` rule written by a member reaches only members that member outranks: a low-ranked room
/// manager cannot time out or silence a higher moderator through a rule (permissions.md "Hierarchy"). Members below
/// the author are still caught.
#[tokio::test]
async fn automod_rules_reach_only_members_their_author_outranks() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await; // owner
    let bob = node.register("bob").await; // high moderator
    let carol = node.register("carol").await; // low room manager
    let dave = node.register("dave").await; // plain member
    let (room_id, channel) = room_with(&node, &alice, &[&bob, &carol, &dave]).await;
    let low = role(&node, &alice.token, &room_id, "Settings", &[p::MANAGE_ROOM], 1).await;
    let high = role(&node, &alice.token, &room_id, "Mod", &[p::MODERATE_MEMBERS, p::KICK_MEMBERS], 5).await;
    for (u, r) in [(&carol.user_id, &low), (&bob.user_id, &high)] {
        let (s, j) =
            node.patch(&format!("/api/v1/rooms/{room_id}/members/{u}"), &alice.token, json!({ "roles": [r] })).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    let rules = json!({ "rules": [
        { "name": "trap", "terms": ["hello"], "action": "timeout", "timeout_minutes": 40320 },
        { "name": "gone", "terms": ["vanish"], "action": "delete" },
    ] });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/automod"), &carol.token, rules).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let timeout_of = |user_id: String| {
        let db = node.state.db.clone();
        let room_id = room_id.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT timeout_until FROM room_members WHERE room_id = $1 AND user_id = $2",
            )
            .bind(&room_id)
            .bind(&user_id)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };
    let (s, j) = node.send(&bob.token, &room_id, &channel, "hello all").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(timeout_of(bob.user_id.clone()).await, None, "the rule's author does not outrank bob");
    let (s, kept) = node.send(&bob.token, &room_id, &channel, "vanish").await;
    assert_eq!(s, StatusCode::CREATED, "{kept}");
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), &alice.token).await;
    assert!(list.as_array().unwrap().iter().any(|m| m["id"] == kept["id"]), "bob's message stays");

    // dave ranks below carol: her rules apply to him.
    let (s, j) = node.send(&dave.token, &room_id, &channel, "hello all").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert!(timeout_of(dave.user_id.clone()).await.is_some(), "dave is timed out");

    // Rules the owner writes reach everybody but the owner.
    let rules = json!({ "rules": [{ "name": "trap", "terms": ["hello"], "action": "timeout", "timeout_minutes": 5 }] });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/automod"), &alice.token, rules).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.send(&bob.token, &room_id, &channel, "hello again").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert!(timeout_of(bob.user_id.clone()).await.is_some(), "the owner outranks bob");
}

/// Crafted room rules (20 × 500 two-literal wildcard terms) and a crafted 60 KB message of a custom type cost about
/// as much as an ordinary message: the matcher never walks every start of a literal for every term.
#[tokio::test]
async fn crafted_rules_and_text_stay_cheap() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let mallory = node.register("mallory").await;
    let (room_id, channel) = room_with(&node, &alice, &[&mallory]).await;
    let alpha: Vec<char> = "bcdefghijklmnopqrstuvwxyz".chars().collect();
    let mut pairs = Vec::new();
    for x in &alpha {
        for y in &alpha {
            pairs.push(format!("{x}{y}"));
        }
    }
    let terms: Vec<String> = pairs.iter().take(500).map(|p| format!("a*{p}")).collect();
    let rules: Vec<Value> = (0..20)
        .map(|i| json!({ "name": format!("r{i}"), "terms": terms, "whole_word": false, "action": "block" }))
        .collect();
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/automod"), &alice.token, json!({ "rules": rules })).await;
    assert_eq!(s, StatusCode::OK, "{}", code(&j));
    let url = format!("/api/v1/conversations/{channel}/messages");
    let (s, j) = node.post(&url, &mallory.token, json!({ "content": { "type": "text", "body": "hi" } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let head: String = pairs.iter().take(500).map(|p| format!("{p} ")).collect();
    // One long run of the first literal; spaced-out runs of it.
    let blobs =
        [format!("{head}{}", "a".repeat(60_000 - head.len())), format!("{head}{}", "a ".repeat(30_000 - head.len() / 2))];
    for blob in blobs {
        let started = Instant::now();
        let (s, j) = node.post(&url, &mallory.token, json!({ "content": { "type": "note", "x": blob } })).await;
        let took = started.elapsed();
        assert_eq!(s, StatusCode::CREATED, "{}", code(&j));
        assert!(took < common::timeout(Duration::from_secs(2)), "a crafted message took {took:?}");
    }
    // Matching still works: a term in a long run of its first literal.
    let blob = format!("{}xy{}", "a".repeat(30_000), "a".repeat(10));
    let rules = json!({ "rules": [{ "name": "r", "terms": ["a*xy"], "action": "block" }] });
    node.put(&format!("/api/v1/rooms/{room_id}/automod"), &alice.token, rules).await;
    let (s, j) = node.post(&url, &mallory.token, json!({ "content": { "type": "note", "x": blob } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "automod.blocked"), "{j}");
}
