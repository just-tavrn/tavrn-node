// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! Invites overview: never-expiring invites and validity beyond 30 days need
//! `manage_room`; the room's list shows active invites with their creator and the direct flag.
use crate::common;

use axum::http::StatusCode;
use common::test_node;
use serde_json::json;

#[tokio::test]
async fn invite_expiry_rules_and_overview() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    node.register("carol").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &alice.token, json!({})).await;
    assert!(invite["expires_at"].is_null(), "manage_room without expires_hours: never (older clients) {invite}");
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // create_invites alone: 7 days by default, at most 30 days, never "never".
    let invites = format!("/api/v1/rooms/{id}/invites");
    let (s, by_bob) = node.post(&invites, &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::CREATED, "{by_bob}");
    let expires = chrono::DateTime::parse_from_rfc3339(by_bob["expires_at"].as_str().unwrap()).unwrap();
    let days = (expires.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_hours();
    assert!((167..=168).contains(&days), "{days} hours");
    let (s, j) = node.post(&invites, &bob.token, json!({ "expires_hours": 0 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "invite.never_forbidden");
    let (s, _) = node.post(&invites, &bob.token, json!({ "expires_hours": 721 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = node.post(&invites, &bob.token, json!({ "expires_hours": 720, "max_uses": 3 })).await;
    assert_eq!(s, StatusCode::CREATED);

    // manage_room: never, and up to a year.
    let (s, never) = node.post(&invites, &alice.token, json!({ "expires_hours": 0, "max_uses": 5 })).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(never["expires_at"].is_null());
    let (s, _) = node.post(&invites, &alice.token, json!({ "expires_hours": 24 * 365 })).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, direct) = node.post(&format!("{invites}/direct"), &alice.token, json!({ "user": "carol" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{direct}");

    // The overview: every active invite with its creator and the direct flag.
    let (s, list) = node.get_auth(&invites, &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 6, "{list:?}");
    let by = |code: &serde_json::Value| list.iter().find(|i| i["code"] == *code).unwrap().clone();
    assert_eq!(by(&by_bob["code"])["creator"], "bob");
    assert_eq!(by(&never["code"])["creator"], "alice");
    assert_eq!(by(&never["code"])["direct"], false);
    let d = by(&direct["invite"]["code"]);
    assert_eq!(d["direct"], true);
    assert_eq!(d["user"], "carol@t.local");

    // Revoked and expired invites disappear.
    let (s, _) = node.delete(&format!("{invites}/{}", never["code"].as_str().unwrap()), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    sqlx::query("UPDATE invites SET expires_at = '2000-01-01T00:00:00.000Z' WHERE code = $1")
        .bind(by_bob["code"].as_str().unwrap())
        .execute(&node.state.db)
        .await
        .unwrap();
    let (_, list) = node.get_auth(&invites, &alice.token).await;
    assert_eq!(list.as_array().unwrap().len(), 4);
    let (s, _) = node.get_auth(&invites, &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "the overview needs manage_room");
}
