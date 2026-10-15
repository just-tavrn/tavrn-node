// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Bots and their owners in moderation: a moderation bot is never shown reports about its own owner, and banning a
//! bot's owner is bound by the rank the bot holds in the room.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::{hub::Scope, permissions as p};

const DOMAIN: &str = "t.local";
const D: &str = DOMAIN;

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

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

/// permissions.md "Hierarchy" says members only kick or ban members whose highest role is lower. A
/// moderator cannot kick a bot that outranks them, and banning the bot's owner
/// (who is not a member) would remove the bot too: that ban needs the rank over the bot.
#[tokio::test]
async fn banning_a_bot_owner_respects_the_bots_rank() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await; // room owner
    let carol = node.register("carol").await; // moderator, low role
    let dave = node.register("dave").await; // bot developer, not a member
    let (room_id, _) = room_with(&node, &alice, &[&carol]).await;
    // dave's public application, installed by alice.
    let (s, app) = node.post("/api/v1/applications", &dave.token, json!({ "name": "Guard", "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let bot_id = app["bot"]["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &alice.token,
            json!({ "application": format!("{DOMAIN}/{}", app["id"].as_str().unwrap()) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::KICK_MEMBERS, p::BAN_MEMBERS], 1).await;
    let high = role(&node, &alice.token, &room_id, "Guard", &[p::VIEW_CHANNEL], 5).await;
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}/members/{}", carol.user_id), &alice.token, json!({ "roles": [mods] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}/members/{bot_id}"), &alice.token, json!({ "roles": [high] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Control: carol may not kick the bot (it outranks her).
    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{bot_id}"), &carol.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
    // Nor ban it by its own address.
    let bot_address = format!("{}@{DOMAIN}", app["bot"]["username"].as_str().unwrap());
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/bans"), &carol.token, json!({ "subject": bot_address })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");

    // Nor through its owner's address (not a member, nothing to outrank of their own).
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/bans"), &carol.token, json!({ "subject": format!("dave@{DOMAIN}") }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
    let bans = node.get_auth(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token).await.1;
    assert_eq!(bans, json!([]), "no ban was written");
    let still: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM room_members WHERE room_id = $1 AND user_id = $2")
            .bind(&room_id)
            .bind(&bot_id)
            .fetch_optional(&node.state.db)
            .await
            .unwrap();
    assert!(still.is_some(), "the bot stays");
    // The owner of the room may.
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": format!("dave@{DOMAIN}") }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn a_moderation_bot_never_sees_reports_about_its_owner() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let carol = node.register("carol").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&carol.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    for who in [&alice, &bob] {
        let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &carol.token, json!({})).await;
        let (s, j) = node
            .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({}))
            .await;
        assert!(s.is_success(), "{j}");
    }
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &carol.token,
            json!({ "name": "Mods", "permissions": mask(&[p::MODERATE_MEMBERS]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap().to_string();
    // Alice's public moderation bot, installed by the room owner and given the Mods role.
    let (s, app) = node.post("/api/v1/applications", &alice.token, json!({ "name": "Helper", "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let bot_id = app["bot"]["id"].as_str().unwrap().to_string();
    let (_, t) = node
        .post(
            &format!("/api/v1/applications/{app_id}/tokens"),
            &alice.token,
            json!({ "name": "main", "scopes": ["moderation"] }),
        )
        .await;
    let secret = t["secret"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": format!("{D}/{app_id}") }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{bot_id}"), &carol.token, json!({ "roles": [role_id] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut events = node.state.hub.subscribe();
    // Bob reports alice.
    let (s, rep) = node
        .post(
            "/api/v1/reports",
            &bob.token,
            json!({ "kind": "user", "user": format!("alice@{D}"), "room_id": room_id, "category": "harassment" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{rep}");
    // Alice cannot see it herself …
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{room_id}/reports"), &alice.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // … nor can her bot, and it gets no event about it.
    let (s, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/reports"), &secret).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list["reports"], json!([]), "{list}");
    let mut to_bot = Vec::new();
    while let Ok(ev) = events.try_recv() {
        if ev.kind.starts_with("report.") && matches!(&ev.scope, Scope::Users(u) if u.contains(&bot_id)) {
            to_bot.push(ev.kind.clone());
        }
    }
    assert_eq!(to_bot, Vec::<String>::new(), "no report event for the bot");
    // Reports about other members still reach the bot.
    let (s, rep) = node
        .post(
            "/api/v1/reports",
            &alice.token,
            json!({ "kind": "user", "user": format!("bob@{D}"), "room_id": room_id, "category": "spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{rep}");
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/reports"), &secret).await;
    assert_eq!(list["reports"].as_array().map(Vec::len), Some(1), "{list}");
    assert_eq!(list["reports"][0]["target_address"], format!("bob@{D}"));
}
