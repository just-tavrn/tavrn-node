// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Bots and their owners in moderation: a moderation bot is never shown reports about its own owner, and banning a
//! bot's owner is bound by the rank the bot holds in the room.
use crate::common;

use axum::http::StatusCode;
use common::test_node;
use serde_json::json;
use tavrn_node::{hub::Scope, permissions as p};

const D: &str = "t.local";

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
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
