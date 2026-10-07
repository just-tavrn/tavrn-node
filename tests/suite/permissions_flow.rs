// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

/// Alice (owner), Bob (member), a room with a text channel.
async fn setup() -> (TestNode, Session, Session, String, String) {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    (node, alice, bob, room_id, channel_id)
}

async fn give_role(
    node: &TestNode,
    owner: &str,
    room_id: &str,
    user_id: &str,
    name: &str,
    bits: &[u64],
    position: i64,
) -> String {
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            owner,
            json!({ "name": name, "permissions": perms(bits), "position": position }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap().to_string();
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}/members/{user_id}"), owner, json!({ "roles": [role_id] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["roles"][0], role_id);
    role_id
}

#[tokio::test]
async fn channel_management_requires_permission_and_roles_grant_it() {
    let (node, alice, bob, room_id, _) = setup().await;
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &bob.token, json!({ "kind": "text", "name": "New" }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "channel.manage_forbidden");

    give_role(&node, &alice.token, &room_id, &bob.user_id, "Mod", &[p::MANAGE_CHANNELS], 5).await;
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &bob.token,
            json!({ "kind": "text", "name": "New Channel", "topic": "Topic" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    assert_eq!(ch["name"], "new-channel");
    assert_eq!(ch["encrypted"], true, "new text channels are end-to-end encrypted by default");
    let (s, plain) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &bob.token,
            json!({ "kind": "text", "name": "open", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{plain}");
    assert_eq!(plain["encrypted"], false);
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &bob.token, json!({ "kind": "podcast", "name": "x" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "validation.enum");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &bob.token,
            json!({ "kind": "voice", "name": "Loud", "bitrate_kbps": 400 }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "channel.bitrate_too_high");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &bob.token,
            json!({ "kind": "voice", "name": "Loud", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "channel.voice_always_encrypted");

    let (s, cat) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &bob.token, json!({ "name": "Topics" })).await;
    assert_eq!(s, StatusCode::CREATED);
    let cid = ch["id"].as_str().unwrap();
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/channels/{cid}"),
            &bob.token,
            json!({ "category_id": cat["id"], "slowmode_secs": 5 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["category_id"], cat["id"]);
    assert_eq!(j["slowmode_secs"], 5);
    // Renaming a default channel clears the system name
    let text_id = TestNode::text_channel(&node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await.1);
    let (_, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{text_id}"), &bob.token, json!({ "topic": "topic only" }))
        .await;
    assert_eq!(j["system_name"], "general", "changing the topic keeps the system name");
    let (_, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{text_id}"), &bob.token, json!({ "name": "lobby" }))
        .await;
    assert!(j["system_name"].is_null(), "{j}");
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/channels/{cid}"), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/channels/{cid}"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn roles_cannot_escalate_or_outrank() {
    let (node, alice, bob, room_id, _) = setup().await;
    give_role(&node, &alice.token, &room_id, &bob.user_id, "Role manager", &[p::MANAGE_ROLES], 5).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &bob.token,
            json!({ "name": "Banner", "permissions": perms(&[p::BAN_MEMBERS]), "position": 1 }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "role.escalation");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &bob.token,
            json!({ "name": "High", "permissions": "0", "position": 5 }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "role.hierarchy");
    let (s, ok) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &bob.token,
            json!({ "name": "Below me", "permissions": perms(&[p::MANAGE_ROLES]), "position": 2, "color": "#FFAA00" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ok}");
    assert_eq!(ok["color"], "#ffaa00");

    // Owner role above Bob: Bob must not touch it.
    let (_, top) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Top", "position": 50 }))
        .await;
    let top_id = top["id"].as_str().unwrap();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/roles/{top_id}"), &bob.token, json!({ "name": "Renamed role" }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/roles/{top_id}"), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{}", alice.user_id), &bob.token, json!({ "roles": [top_id] }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "role.hierarchy");

    // @everyone: only its permissions can change, never administrator, never deletable.
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
            &alice.token,
            json!({ "permissions": perms(&[p::ADMINISTRATOR]) }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}/roles/{everyone}"), &alice.token).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
            &alice.token,
            json!({ "permissions": perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert_eq!(room["my_permissions"], perms(&[p::VIEW_CHANNEL, p::MANAGE_ROLES]));
}

#[tokio::test]
async fn overrides_control_channel_visibility() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = room["roles"][0]["id"].as_str().unwrap().to_string();
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (s, _) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::OK);

    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, json!({ "target_type": "channel", "target_id": channel_id, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": perms(&[p::VIEW_CHANNEL]) })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "channel.view_forbidden");
    let (s, _) = node.get_auth(&path, &alice.token).await;
    assert_eq!(s, StatusCode::OK, "the owner sees everything");

    // The member override wins against the @everyone deny.
    let (s, _) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, json!({ "target_type": "channel", "target_id": channel_id, "subject_type": "member", "subject_id": bob.user_id, "allow": perms(&[p::VIEW_CHANNEL]), "deny": "0" })).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::OK);

    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, json!({ "target_type": "channel", "target_id": channel_id, "subject_type": "role", "subject_id": everyone, "allow": "1", "deny": "1" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "override.conflict");
    let (s, _) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &bob.token, json!({ "target_type": "channel", "target_id": channel_id, "subject_type": "role", "subject_id": everyone, "allow": "1", "deny": "0" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(room["overrides"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn kick_ban_timeout_respect_hierarchy() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    let carol = node.register("carol").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    give_role(
        &node,
        &alice.token,
        &room_id,
        &bob.user_id,
        "Mod",
        &[p::KICK_MEMBERS, p::BAN_MEMBERS, p::MODERATE_MEMBERS],
        5,
    )
    .await;

    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{}", alice.user_id), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "member.is_owner");
    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{}", carol.user_id), &carol.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");

    // Timeout: Carol can no longer write, but can read.
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/members/{}/timeout", carol.user_id),
            &bob.token,
            json!({ "minutes": 10, "reason": "Spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["timeout_until"].is_string());
    let (s, j) = node.send(&carol.token, &room_id, &channel_id, "hello").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "message.send_forbidden");
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), &carol.token).await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = node
        .put(&format!("/api/v1/rooms/{room_id}/members/{}/timeout", carol.user_id), &bob.token, json!({ "minutes": 0 }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["timeout_until"].is_null());
    let (s, _) = node.send(&carol.token, &room_id, &channel_id, "hello").await;
    assert_eq!(s, StatusCode::CREATED);

    // Kick and rejoin, then a ban blocks joining.
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{}", carol.user_id), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, ban) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/bans"),
            &bob.token,
            json!({ "subject": "carol@t.local", "reason": "Rule violation" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ban}");
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.banned");
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{room_id}/bans"), &bob.token, json!({ "subject": "alice@t.local" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/bans"), &bob.token, json!({ "subject": "not a valid subject" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/bans"), &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/bans/carol@t.local"), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);

    let (s, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for a in [
        "member.unban",
        "member.ban",
        "member.kick",
        "member.timeout_clear",
        "member.timeout",
        "member.roles",
        "role.create",
        "room.create",
    ] {
        assert!(actions.contains(&a), "{a} missing in {actions:?}");
    }
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &carol.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn members_listing_and_nicknames() {
    let (node, alice, bob, room_id, _) = setup().await;
    let (s, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(members.as_array().unwrap().len(), 2);
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{}", bob.user_id), &bob.token, json!({ "nickname": "Bobby" }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["nickname"], "Bobby");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", alice.user_id),
            &bob.token,
            json!({ "nickname": "Big boss" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", bob.user_id),
            &alice.token,
            json!({ "nickname": Value::Null }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["nickname"].is_null());
}
