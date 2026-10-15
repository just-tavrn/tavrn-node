// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{Method, StatusCode};
use common::test_node;
use serde_json::json;
use tavrn_node::permissions as p;

#[tokio::test]
async fn create_room_sets_up_defaults() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "  My room ").await;
    assert_eq!(room["name"], "My room");
    assert_eq!(room["join_mode"], "invite");
    assert_eq!(room["owner_id"], alice.user_id);
    assert_eq!(room["is_owner"], true);
    assert_eq!(room["my_permissions"], p::ALL.to_string());
    assert_eq!(room["member_count"], 1);
    let roles = room["roles"].as_array().unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0]["is_everyone"], true);
    assert_eq!(roles[0]["permissions"], p::DEFAULT_EVERYONE.to_string());
    assert_eq!(room["categories"].as_array().unwrap().len(), 1);
    let all = room["channels"].as_array().unwrap();
    assert_eq!(all.len(), 3);
    // The welcome channel comes first (welcome_flow.rs).
    assert_eq!((all[0]["kind"].as_str(), all[0]["system_name"].as_str()), (Some("system"), Some("welcome")));
    assert!(room.get("welcome_channel_enabled").is_none(), "the welcome channel cannot be switched off any more");
    let channels: Vec<&serde_json::Value> = all.iter().filter(|c| c["kind"] != "system").collect();
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0]["kind"], "text");
    assert_eq!(channels[0]["name"], "general");
    assert_eq!(channels[0]["system_name"], "general", "clients localize default names");
    assert_eq!(channels[1]["system_name"], "voice");
    assert_eq!(room["categories"][0]["system_name"], "general");
    assert_eq!(channels[0]["encrypted"], true, "text channels are end-to-end encrypted by default");
    assert_eq!(channels[1]["kind"], "voice");
    assert_eq!(channels[1]["encrypted"], true, "voice always encrypted");

    let (_, mine) = node.get_auth("/api/v1/rooms", &alice.token).await;
    assert_eq!(mine.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn room_creation_policies() {
    let none = common::test_node_with("t.local", |c| c.room_creation = tavrn_node::config::RoomCreation::None).await;
    let admin = none.register("admin").await;
    let bob = none.register("bob").await;
    none.create_room(&admin.token, "Admins may").await;
    let (s, j) = none.post("/api/v1/rooms", &bob.token, json!({ "name": "Bob" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.creation_forbidden");

    let limited = common::test_node_with("t.local", |c| c.max_rooms_per_user = 1).await;
    let admin = limited.register("admin").await;
    let bob = limited.register("bob").await;
    limited.create_room(&bob.token, "One").await;
    let (s, j) = limited.post("/api/v1/rooms", &bob.token, json!({ "name": "Two" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.limit_reached");

    let (s, j) = limited.post("/api/v1/rooms", &admin.token, json!({ "name": "" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "validation.length");
}

#[tokio::test]
async fn non_members_cannot_see_room_but_node_admin_can() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Private").await;
    let id = room["id"].as_str().unwrap();
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.not_member");
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["my_permissions"], p::ALL.to_string());
    let (s, j) = node.get_auth("/api/v1/rooms/01JUNBEKANNT00000000000000", &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(j["code"], "room.not_found");
}

#[tokio::test]
async fn public_join_invite_only_and_rules() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();

    let (s, j) = node.post(&format!("/api/v1/rooms/{id}/join"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.invite_required");

    let (s, j) = node.patch(&format!("/api/v1/rooms/{id}"), &bob.token, json!({ "join_mode": "public" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{id}"), &alice.token, json!({ "join_mode": "public", "rules": "Be nice." }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Public is not listed: only rooms marked discoverable appear under Discover (FEDERATION.md §7.3).
    let (_, discover) = node.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover, json!([]));
    let (s, j) = node.patch(&format!("/api/v1/rooms/{id}"), &alice.token, json!({ "discoverable": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, discover) = node.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover[0]["name"], "Room");

    let (s, j) = node.post(&format!("/api/v1/rooms/{id}/join"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.rules_not_accepted");
    let (s, j) = node.post(&format!("/api/v1/rooms/{id}/join"), &bob.token, json!({ "accept_rules": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["member_count"], 2);
    assert_eq!(j["my_permissions"], p::DEFAULT_EVERYONE.to_string());

    let (s, j) = node.post(&format!("/api/v1/rooms/{id}/leave"), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.owner_cannot_leave");
    let (s, _) = node.post(&format!("/api/v1/rooms/{id}/leave"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invites_preview_join_limits_and_management() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.create_room(&alice.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();

    let (s, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &alice.token, json!({ "max_uses": 1 })).await;
    assert_eq!(s, StatusCode::CREATED, "{invite}");
    let code = invite["code"].as_str().unwrap().to_string();

    let (s, preview) = node.req(Method::GET, &format!("/api/v1/invites/{code}"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(preview["room"]["name"], "Room");

    let (s, j) = node.post(&format!("/api/v1/invites/{code}/join"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.post(&format!("/api/v1/invites/{code}/join"), &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "max_uses exhausted: {j}");
    assert_eq!(j["code"], "invite.invalid");
    let (s, _) = node.req(Method::GET, "/api/v1/invites/unknown", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, list) = node.get_auth(&format!("/api/v1/rooms/{id}/invites"), &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 0, "used-up invites are not listed as active: {list}");
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{id}/invites"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a member without manage_room sees no invites");
    let (s, _) = node.delete(&format!("/api/v1/rooms/{id}/invites/{code}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.delete(&format!("/api/v1/rooms/{id}/invites/{code}"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_room_only_by_owner_or_node_admin() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let (s, j) = node.delete(&format!("/api/v1/rooms/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "room.owner_required");
    let (s, _) = node.delete(&format!("/api/v1/rooms/{id}"), &admin.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let room2 = node.create_room(&alice.token, "Room 2").await;
    let (s, _) = node.delete(&format!("/api/v1/rooms/{}", room2["id"].as_str().unwrap()), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

/// Discover lists each public room with its member count; anonymous callers are limited per address like the other
/// public directory reads, signed-in users are not counted there.
#[tokio::test]
async fn discover_counts_members_and_limits_anonymous_callers() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    for (name, joins) in [("Busy", true), ("Quiet", false)] {
        let room = node.create_room(&alice.token, name).await;
        let id = room["id"].as_str().unwrap().to_string();
        let (s, j) =
            node.patch(&format!("/api/v1/rooms/{id}"), &alice.token, json!({ "join_mode": "public", "discoverable": true })).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        if joins {
            let (s, j) = node.post(&format!("/api/v1/rooms/{id}/join"), &bob.token, json!({})).await;
            assert_eq!(s, StatusCode::OK, "{j}");
        }
    }
    let (s, list) = node.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let count = |name: &str| list.as_array().unwrap().iter().find(|r| r["name"] == name).unwrap()["member_count"].clone();
    assert_eq!((count("Busy"), count("Quiet")), (json!(2), json!(1)));

    // The in-process router has no peer address: every anonymous request here comes from "unknown".
    while node.state.directory_limiter.check_all(&["discover-ip:unknown".to_string()]).is_ok() {}
    let (s, j) = node.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    let (s, j) = node.get_auth("/api/v1/rooms/discover", &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}
