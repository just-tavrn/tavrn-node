// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Presence (PROTOCOL.md §6): status, custom status, activity, invisible, idle across devices,
//! batching, privacy (hidden activity, hidden per room, blocks) and presence of remote users on a room node.
use crate::common;

use std::time::Duration;

use axum::http::StatusCode;
use common::crossnode::{Ws, ws};
use common::federation::{FedNode, two_nodes};
use futures::StreamExt;
use serde_json::{Value, json};

/// Waits (5 s, scaled) for a `presence.update` of `user` matching `status` and returns its data.
async fn presence(ws: &mut Ws, user: &str, status: &str) -> Value {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("no matching presence update in time")
            .unwrap()
            .unwrap();
        let Ok(v) = serde_json::from_str::<Value>(msg.to_text().unwrap_or("")) else { continue };
        if v["type"] == "presence.update" && v["data"]["user"] == user && v["data"]["status"] == status {
            return v["data"].clone();
        }
    }
}

/// All `presence.update` events of `user` arriving within `ms`.
async fn updates_within(ws: &mut Ws, user: &str, ms: u64) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut out = Vec::new();
    while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(deadline, ws.next()).await {
        if let Ok(v) = serde_json::from_str::<Value>(msg.to_text().unwrap_or(""))
            && v["type"] == "presence.update"
            && v["data"]["user"] == user
        {
            out.push(v["data"].clone());
        }
    }
    out
}

async fn visible(node: &FedNode, token: &str) -> Vec<Value> {
    let (st, list) = node.get_auth("/api/v1/presence", token).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    list.as_array().unwrap().clone()
}

fn status_of(list: &[Value], user: &str) -> Option<String> {
    list.iter().find(|p| p["user"] == user).map(|p| p["status"].as_str().unwrap().to_string())
}

async fn befriend(node: &FedNode, a: &common::Session, b: &common::Session) {
    node.post("/api/v1/users/me/friends/requests", &a.token, json!({ "user": b.username })).await;
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &b.token, json!({ "user": a.username })).await;
    assert_eq!(j["status"], "accepted", "{j}");
}

#[tokio::test]
async fn friends_see_status_custom_status_and_invisible_as_offline() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let dave = a.register("dave").await;
    befriend(&a, &alice, &bob).await;
    let mut bob_ws = ws(&a, &bob.token).await;
    let mut dave_ws = ws(&a, &dave.token).await;

    // Connecting makes alice online for her friend, never for strangers.
    let mut alice_ws = ws(&a, &alice.token).await;
    presence(&mut bob_ws, "alice@a.test", "online").await;
    assert_eq!(status_of(&visible(&a, &bob.token).await, "alice@a.test").as_deref(), Some("online"));
    assert_eq!(status_of(&visible(&a, &dave.token).await, "alice@a.test"), None);

    let custom = json!({ "text": "Raid at 8 pm", "emoji": "⚔️" });
    let (st, me) =
        a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "dnd", "custom_status": custom })).await;
    assert_eq!(st, StatusCode::OK, "{me}");
    assert_eq!((me["status"].as_str(), me["effective"].as_str()), (Some("dnd"), Some("dnd")));
    let p = presence(&mut bob_ws, "alice@a.test", "dnd").await;
    assert_eq!(p["custom_status"]["text"], "Raid at 8 pm");

    // Invisible: offline for everyone else, the own connections still see the truth.
    a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "invisible" })).await;
    let p = presence(&mut bob_ws, "alice@a.test", "offline").await;
    assert_eq!(p["custom_status"], Value::Null, "nothing leaks while invisible");
    presence(&mut alice_ws, "alice@a.test", "invisible").await;
    assert_eq!(status_of(&visible(&a, &bob.token).await, "alice@a.test"), None);
    let (_, me) = a.get_auth("/api/v1/users/me/presence", &alice.token).await;
    assert_eq!(me["effective"], "invisible");

    // Back online and away: the last connection closing makes her offline.
    a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "online", "custom_status": null })).await;
    let p = presence(&mut bob_ws, "alice@a.test", "online").await;
    assert_eq!(p["custom_status"], Value::Null);
    drop(alice_ws);
    presence(&mut bob_ws, "alice@a.test", "offline").await;
    assert!(updates_within(&mut dave_ws, "alice@a.test", 300).await.is_empty(), "strangers hear nothing");

    for (body, code) in [
        (json!({ "status": "busy" }), "presence.status_invalid"),
        (json!({ "custom_status": { "text": "x".repeat(129) } }), "presence.invalid"),
        (json!({ "custom_status": { "text": "x", "expires_at": "2000-01-01T00:00:00Z" } }), "presence.invalid"),
    ] {
        let (st, j) = a.put("/api/v1/users/me/presence", &alice.token, body.clone()).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}");
    }
}

#[tokio::test]
async fn idle_is_per_device_and_updates_are_batched() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    befriend(&a, &alice, &bob).await;
    let laptop = a.login("alice").await;
    let mut bob_ws = ws(&a, &bob.token).await;
    let _phone = ws(&a, &alice.token).await;
    let _laptop_ws = ws(&a, &laptop.token).await;
    presence(&mut bob_ws, "alice@a.test", "online").await;

    // One idle device of two: still online. Both idle: idle.
    a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "idle" })).await;
    let (_, me) = a.get_auth("/api/v1/users/me/presence", &alice.token).await;
    assert_eq!((me["idle"].as_bool(), me["effective"].as_str()), (Some(true), Some("online")));
    a.put("/api/v1/users/me/presence", &laptop.token, json!({ "status": "idle" })).await;
    presence(&mut bob_ws, "alice@a.test", "idle").await;
    a.put("/api/v1/users/me/presence", &laptop.token, json!({ "status": "online" })).await;
    presence(&mut bob_ws, "alice@a.test", "online").await;

    // A burst of changes: at most one update per second, the last one carries the final state.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for status in ["dnd", "online", "dnd", "online", "dnd"] {
        a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": status })).await;
    }
    let got = updates_within(&mut bob_ws, "alice@a.test", 1500).await;
    assert!(!got.is_empty() && got.len() <= 2, "batched: {got:?}");
    assert_eq!(got.last().unwrap()["status"], "dnd");
}

#[tokio::test]
async fn activity_and_privacy_switches() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let carol = a.register("carol").await;
    let room = a.create_room(&alice.token, "Guild").await;
    let id = room["id"].as_str().unwrap();
    let (_, invite) = a.post(&format!("/api/v1/rooms/{id}/invites"), &alice.token, json!({})).await;
    a.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    let mut carol_ws = ws(&a, &carol.token).await;
    let _alice_ws = ws(&a, &alice.token).await;
    presence(&mut carol_ws, "alice@a.test", "online").await;

    // Activity of the device, shown to room co-members.
    let (st, me) = a
        .put(
            "/api/v1/users/me/activity",
            &alice.token,
            json!({ "type": "playing", "name": "Factorio", "details": "Megabase" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{me}");
    let p = presence(&mut carol_ws, "alice@a.test", "online").await;
    assert_eq!(p["activity"]["name"], "Factorio");
    assert!(p["activity"]["started_at"].is_string());
    let (st, j) = a.put("/api/v1/users/me/activity", &alice.token, json!({ "type": "hacking", "name": "x" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("presence.activity_invalid")));

    // Hide the activity from everyone: carol sees the status only, alice still sees her activity.
    a.patch("/api/v1/users/me", &alice.token, json!({ "hide_activity": true })).await;
    let p = presence(&mut carol_ws, "alice@a.test", "online").await;
    assert_eq!(p["activity"], Value::Null);
    let (_, me) = a.get_auth("/api/v1/users/me/presence", &alice.token).await;
    assert_eq!((me["activity"]["name"].as_str(), me["hide_activity"].as_bool()), (Some("Factorio"), Some(true)));

    // Hide the presence in the room: carol (no friend) sees alice offline from now on.
    let (st, j) = a.put(&format!("/api/v1/rooms/{id}/presence"), &alice.token, json!({ "hidden": true })).await;
    assert_eq!((st, j["hidden"].as_bool()), (StatusCode::OK, Some(true)));
    presence(&mut carol_ws, "alice@a.test", "offline").await;
    assert_eq!(status_of(&visible(&a, &carol.token).await, "alice@a.test"), None);
    let (_, j) = a.get_auth(&format!("/api/v1/rooms/{id}/presence"), &alice.token).await;
    assert_eq!(j["hidden"], true);
    a.put(&format!("/api/v1/rooms/{id}/presence"), &alice.token, json!({ "hidden": false })).await;
    presence(&mut carol_ws, "alice@a.test", "online").await;
    let outsider = a.register("outsider").await;
    let (st, _) = a.put(&format!("/api/v1/rooms/{id}/presence"), &outsider.token, json!({ "hidden": true })).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Blocks hide presence in both directions.
    a.post("/api/v1/users/me/blocks", &carol.token, json!({ "user": "alice" })).await;
    presence(&mut carol_ws, "alice@a.test", "offline").await;
    assert_eq!(status_of(&visible(&a, &carol.token).await, "alice@a.test"), None);
    assert_eq!(status_of(&visible(&a, &alice.token).await, "carol@a.test"), None);
}

#[tokio::test]
async fn custom_statuses_expire_for_everyone() {
    let (a, _b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    befriend(&a, &alice, &bob).await;
    let mut bob_ws = ws(&a, &bob.token).await;
    let _alice_ws = ws(&a, &alice.token).await;
    presence(&mut bob_ws, "alice@a.test", "online").await;
    let expires = tavrn_node::util::in_seconds(2);
    a.put(
        "/api/v1/users/me/presence",
        &alice.token,
        json!({ "custom_status": { "text": "brb", "expires_at": expires } }),
    )
    .await;
    let p = presence(&mut bob_ws, "alice@a.test", "online").await;
    assert_eq!(p["custom_status"]["text"], "brb");
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let p = presence(&mut bob_ws, "alice@a.test", "online").await;
    assert_eq!(p["custom_status"], Value::Null, "{p}");
}

#[tokio::test]
async fn room_nodes_learn_presence_only_from_the_users_own_session() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let room = b.create_room(&bob.token, "Meeting point").await;
    let id = room["id"].as_str().unwrap();
    let (_, invite) = b.post(&format!("/api/v1/rooms/{id}/invites"), &bob.token, json!({})).await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (st, j) =
        b.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let mut bob_ws = ws(&b, &bob.token).await;

    // On her home node alice is online and busy; B knows nothing of it (no S2S presence).
    let _home = ws(&a, &alice.token).await;
    a.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "dnd" })).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(status_of(&visible(&b, &bob.token).await, "alice@a.test"), None);
    assert!(a.outbox().await.iter().all(|e| !e.kind.contains("presence")), "presence never travels between nodes");

    // Her client pushes the state to B through the federated session; B tells the room.
    let _on_b = ws(&b, &remote.token).await;
    let (st, j) = b.put("/api/v1/users/me/presence", &remote.token, json!({ "status": "dnd" })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    presence(&mut bob_ws, "alice@a.test", "dnd").await;
    assert_eq!(status_of(&visible(&b, &bob.token).await, "alice@a.test").as_deref(), Some("dnd"));
}
