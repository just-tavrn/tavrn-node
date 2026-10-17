// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Room rules on every join route and the room's privacy notice and legal notice (PROTOCOL.md §6b "Room rules",
//! "Room privacy notice and legal notice", "Room preview"): set and clear, limits, permission, audit and event, the
//! previews with and without access, and the same over federation.

use crate::common;

use axum::http::{Method, StatusCode};
use chrono::{Months, Utc};
use common::{
    TestNode,
    federation::{FedNode, two_nodes},
    test_node,
};
use serde_json::{Value, json};

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

async fn room_with(node: &TestNode, token: &str, settings: Value) -> String {
    let room_id = id(&node.create_room(token, "Guild hall").await);
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), token, settings).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    room_id
}

async fn invite(node: &TestNode, token: &str, room_id: &str) -> String {
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), token, json!({})).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j["code"].as_str().unwrap().to_string()
}

fn refused_for_rules((s, j): (StatusCode, Value)) {
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.rules_not_accepted")), "{j}");
}

async fn audit_actions(node: &TestNode, token: &str, room_id: &str) -> Vec<Value> {
    let (s, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), token).await;
    assert_eq!(s, StatusCode::OK, "{log}");
    log.as_array().unwrap().iter().filter(|e| e["action"] == "room.legal").cloned().collect()
}

// ---------------------------------------------------------------- rules on every join route

/// While a room has rules, every join route refuses a missing or false `accept_rules`: invite links, personal
/// invitations (address-bound codes) and public joins. A refused invite join gives its use back.
#[tokio::test]
async fn every_local_join_route_needs_the_rules_accepted() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room_id = room_with(&node, &alice.token, json!({ "join_mode": "public", "rules": "Be kind." })).await;

    // Public join.
    let bob = node.register("bob").await;
    let join = format!("/api/v1/rooms/{room_id}/join");
    refused_for_rules(node.req(Method::POST, &join, Some(&bob.token), None).await);
    refused_for_rules(node.post(&join, &bob.token, json!({})).await);
    refused_for_rules(node.post(&join, &bob.token, json!({ "accept_rules": false })).await);
    let (s, j) = node.post(&join, &bob.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Invite link with one use: refusals do not use it up.
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({ "max_uses": 1 })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let code = j["code"].as_str().unwrap().to_string();
    let carol = node.register("carol").await;
    let path = format!("/api/v1/invites/{code}/join");
    refused_for_rules(node.req(Method::POST, &path, Some(&carol.token), None).await);
    refused_for_rules(node.post(&path, &carol.token, json!({ "accept_rules": false })).await);
    let (s, j) = node.post(&path, &carol.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "the refusals gave the use back: {j}");

    // Personal invitation (member menu → invite; accepted from the invite list with its bound code).
    let dave = node.register("dave").await;
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &alice.token, json!({ "user": "dave" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
    let (_, list) = node.get_auth("/api/v1/users/me/invites", &dave.token).await;
    let bound = list["items"][0]["invite_code"].as_str().unwrap().to_string();
    let path = format!("/api/v1/invites/{bound}/join");
    refused_for_rules(node.post(&path, &dave.token, json!({})).await);
    let (s, j) = node.post(&path, &dave.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Rules that are only whitespace count as none.
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "rules": "   " })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let erin = node.register("erin").await;
    let (s, j) = node.post(&join, &erin.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// Remote users join with their federated session on the hosting node: the same requirement on both routes.
#[tokio::test]
async fn federated_joins_need_the_rules_accepted() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room_id = room_with(&b, &carol.token, json!({ "join_mode": "public", "rules": "No spoilers." })).await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let join = format!("/api/v1/rooms/{room_id}/join");
    refused_for_rules(b.post(&join, &remote.token, json!({})).await);
    let (s, j) = b.post(&join, &remote.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // A personal invitation of a user of A, accepted with the bound code on B.
    let dave = a.register("dave").await;
    let (s, j) = b
        .post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &carol.token, json!({ "user": "dave@a.test" }))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
    let code = j["invite"]["code"].as_str().unwrap().to_string();
    let remote_dave = b.sign_in_from(&a, &dave).await;
    let path = format!("/api/v1/invites/{code}/join");
    refused_for_rules(b.post(&path, &remote_dave.token, json!({ "accept_rules": false })).await);
    let (s, j) = b.post(&path, &remote_dave.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

// ---------------------------------------------------------------- privacy notice and legal notice

#[tokio::test]
async fn legal_documents_set_clear_limits_permission_audit_and_event() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room_id = room_with(&node, &alice.token, json!({})).await;
    let code = invite(&node, &alice.token, &room_id).await;
    let (s, _) = node.post(&format!("/api/v1/invites/{code}/join"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let path = format!("/api/v1/rooms/{room_id}");

    // Off by default.
    let (_, detail) = node.get_auth(&path, &bob.token).await;
    assert_eq!(
        (detail["privacy_notice_updated_at"].clone(), detail["legal_notice_updated_at"].clone()),
        (Value::Null, Value::Null)
    );

    // Only `manage_room`.
    let (s, j) = node.patch(&path, &bob.token, json!({ "privacy_notice": "Mine." })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.manage_forbidden")), "{j}");

    // Limits: 20,000 and 5,000 characters (counted after trimming, in characters, not bytes).
    let (s, j) = node.patch(&path, &alice.token, json!({ "privacy_notice": "ä".repeat(20_001) })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")), "{j}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "legal_notice": "x".repeat(5_001) })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")), "{j}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "legal_notice": "bell\u{7}" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.control_chars")), "{j}");
    let (s, j) = node.patch(&path, &alice.token, json!({ "privacy_notice": "ä".repeat(20_000) })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Set both: timestamps, one audit entry, `room.update` with the timestamps.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node
        .patch(
            &path,
            &alice.token,
            json!({ "privacy_notice": "  # Privacy\nWe store messages.  ", "legal_notice": "Run by Alice" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let privacy_at = j["privacy_notice_updated_at"].as_str().unwrap().to_string();
    let legal_at = j["legal_notice_updated_at"].as_str().unwrap().to_string();
    assert!(j.get("privacy_notice").is_none(), "the room object carries the timestamps, not the texts: {j}");
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "room.update").unwrap();
    assert_eq!(ev.data["privacy_notice_updated_at"], privacy_at.as_str());
    assert_eq!(ev.data["legal_notice_updated_at"], legal_at.as_str());
    let (_, preview) = node.get_auth(&format!("{path}/preview"), &bob.token).await;
    assert_eq!(preview["privacy_notice"], "# Privacy\nWe store messages.");
    assert_eq!(preview["legal_notice"], "Run by Alice");
    let entries = audit_actions(&node, &alice.token, &room_id).await;
    assert_eq!(entries[0]["meta"], json!({ "privacy_notice": "updated", "legal_notice": "added" }), "{entries:?}");

    // The same text again changes nothing (no new timestamp, no audit entry).
    let (_, j) = node.patch(&path, &alice.token, json!({ "legal_notice": "Run by Alice" })).await;
    assert_eq!(j["legal_notice_updated_at"], legal_at.as_str());
    assert_eq!(audit_actions(&node, &alice.token, &room_id).await.len(), entries.len());

    // Other settings keep the documents.
    let (_, j) = node.patch(&path, &alice.token, json!({ "description": "Hello" })).await;
    assert_eq!(j["privacy_notice_updated_at"], privacy_at.as_str());

    // Clearing.
    let (s, j) = node.patch(&path, &alice.token, json!({ "privacy_notice": "" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["privacy_notice_updated_at"], Value::Null);
    assert_eq!(j["legal_notice_updated_at"], legal_at.as_str());
    let (_, preview) = node.get_auth(&format!("{path}/preview"), &bob.token).await;
    assert_eq!(
        (preview["privacy_notice"].as_str(), preview["privacy_notice_updated_at"].clone()),
        (Some(""), Value::Null)
    );
    let entries = audit_actions(&node, &alice.token, &room_id).await;
    assert_eq!(entries[0]["meta"], json!({ "privacy_notice": "removed" }));
}

/// The room preview: everyone for public rooms (anonymous too), members and node admins for every room, nobody
/// else (404 as for an unknown room); the invite preview carries the same fields for whoever holds a valid code.
#[tokio::test]
async fn previews_with_and_without_access() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await; // the first account is the node admin
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let settings = json!({ "rules": "Be kind.", "privacy_notice": "Privacy text", "legal_notice": "Legal text" });
    let room_id = room_with(&node, &alice.token, settings).await;
    let path = format!("/api/v1/rooms/{room_id}/preview");

    // Invite-only room: no preview for outsiders (anonymous or signed in), unknown rooms look the same.
    let (s, j) = node.req(Method::GET, &path, None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("room.not_found")), "{j}");
    let (s, j) = node.get_auth(&path, &bob.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("room.not_found")), "{j}");
    let (s, _) = node.get_auth("/api/v1/rooms/01JUNBEKANNT00000000000000/preview", &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Members and node admins see it.
    let (s, j) = node.get_auth(&path, &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["room"]["name"].as_str(), j["rules"].as_str()), (Some("Guild hall"), Some("Be kind.")));
    assert_eq!((j["privacy_notice"].as_str(), j["legal_notice"].as_str()), (Some("Privacy text"), Some("Legal text")));
    assert!(j["privacy_notice_updated_at"].is_string() && j["legal_notice_updated_at"].is_string(), "{j}");
    let (s, _) = node.get_auth(&path, &admin.token).await;
    assert_eq!(s, StatusCode::OK);

    // With an invite: the invite preview (public, no session needed) carries the same fields.
    let code = invite(&node, &alice.token, &room_id).await;
    let (s, j) = node.req(Method::GET, &format!("/api/v1/invites/{code}"), None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["code"], code.as_str());
    assert_eq!((j["room"]["name"].as_str(), j["rules"].as_str()), (Some("Guild hall"), Some("Be kind.")));
    assert_eq!((j["privacy_notice"].as_str(), j["legal_notice"].as_str()), (Some("Privacy text"), Some("Legal text")));
    assert!(j["privacy_notice_updated_at"].is_string(), "{j}");

    // Public room: everyone, anonymous too.
    let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "join_mode": "public" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.req(Method::GET, &path, None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["privacy_notice"], "Privacy text");
    let (s, j) = node.get_auth(&path, &bob.token).await;
    assert_eq!((s, j["legal_notice"].as_str()), (StatusCode::OK, Some("Legal text")));

    // A public room with an age gate stays out of sight of minors and anonymous callers, as on Discover.
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "age_gate": "adults_only" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let born = Utc::now().date_naive().checked_sub_months(Months::new(12 * 16)).unwrap().format("%Y-%m-%d").to_string();
    let minor = node.register_born("young", &born).await;
    let (s, _) = node.get_auth(&path, &minor.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = node.req(Method::GET, &path, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::OK);
}

/// Anonymous previews are limited per client address like the other public directory reads.
#[tokio::test]
async fn anonymous_previews_are_rate_limited() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room_id = room_with(&node, &alice.token, json!({ "join_mode": "public" })).await;
    // The in-process router has no peer address: every anonymous request here comes from "unknown".
    while node.state.directory_limiter.check_all(&["room-preview-ip:unknown".to_string()]).is_ok() {}
    let path = format!("/api/v1/rooms/{room_id}/preview");
    let (s, j) = node.req(Method::GET, &path, None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    let (s, j) = node.get_auth(&path, &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// Remote users read the hosting node's documents: the preview of a public room with their federated session
/// before joining, and as members of an invite-only room afterwards.
#[tokio::test]
async fn remote_users_see_the_hosting_nodes_documents() {
    let (a, b): (FedNode, FedNode) = two_nodes().await;
    let carol = b.register("carol").await;
    let settings = json!({ "join_mode": "public", "privacy_notice": "B privacy", "legal_notice": "B legal" });
    let room_id = room_with(&b, &carol.token, settings).await;
    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let path = format!("/api/v1/rooms/{room_id}/preview");
    let (s, j) = b.get_auth(&path, &remote.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["privacy_notice"].as_str(), j["legal_notice"].as_str()), (Some("B privacy"), Some("B legal")));
    let (s, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "documents are information, never a condition of joining: {j}");
    assert!(j["privacy_notice_updated_at"].is_string(), "{j}");

    // Invite-only now: the member keeps access, outsiders of A do not.
    let (s, j) = b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "invite" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _) = b.get_auth(&path, &remote.token).await;
    assert_eq!(s, StatusCode::OK);
    let mallory = a.register("mallory").await;
    let remote_mallory = b.sign_in_from(&a, &mallory).await;
    let (s, _) = b.get_auth(&path, &remote_mallory.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
