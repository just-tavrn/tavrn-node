// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! Rate limits of the authorization audit's second round (docs/HANDBOOK.md "Rate limits"): a general per-user API
//! limit (`TAVRN_RATE_USER_PER_MINUTE`) and the routes that had none (room presence, files list/search/upload,
//! purge previews, the unauthenticated emoji and sound proxy). The route limits are exhausted directly on the
//! node's limiter, then the route must answer `429`.
use crate::common;

use axum::http::StatusCode;
use common::{TestNode, test_node, test_node_with};
use serde_json::{Value, json};

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn exhaust(limiter: &tavrn_node::auth::RateLimiter, key: &str) {
    while limiter.check(key).is_ok() {}
}

#[tokio::test]
async fn every_user_has_a_general_api_limit() {
    let node = test_node_with("t.local", |c| c.rate_user_per_minute = 5).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let mut last = (StatusCode::OK, Value::Null);
    for _ in 0..6 {
        last = node.get_auth("/api/v1/users/me", &alice.token).await;
    }
    assert_eq!((last.0, code(&last.1)), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"), "{}", last.1);
    assert_eq!(node.get_auth("/api/v1/users/me", &bob.token).await.0, StatusCode::OK, "per user");
}

#[tokio::test]
async fn the_general_limit_is_off_with_zero() {
    let node = test_node_with("t.local", |c| c.rate_user_per_minute = 0).await;
    let alice = node.register("alice").await;
    for _ in 0..50 {
        assert_eq!(node.get_auth("/api/v1/users/me", &alice.token).await.0, StatusCode::OK);
    }
}

async fn room(node: &TestNode, token: &str) -> String {
    node.plaintext_room(token, "Room").await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn room_presence_toggles_are_limited() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room_id = room(&node, &alice.token).await;
    let path = format!("/api/v1/rooms/{room_id}/presence");
    assert_eq!(node.put(&path, &alice.token, json!({ "hidden": true })).await.0, StatusCode::OK);
    exhaust(&node.state.presence_limiter, &format!("presence-room:{}", alice.user_id));
    let (s, j) = node.put(&path, &alice.token, json!({ "hidden": false })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
}

#[tokio::test]
async fn files_list_search_and_upload_are_limited() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room_id = room(&node, &alice.token).await;
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "files", "name": "Shared", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let base = format!("/api/v1/rooms/{room_id}/channels/{}/files", ch["id"].as_str().unwrap());
    assert_eq!(node.get_auth(&base, &alice.token).await.0, StatusCode::OK);
    exhaust(&node.state.files_limiter, &format!("files:{}", alice.user_id));
    assert_eq!(node.get_auth(&base, &alice.token).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(node.get_auth(&format!("{base}?q=report"), &alice.token).await.0, StatusCode::TOO_MANY_REQUESTS);
    exhaust(&node.state.files_limiter, &format!("files-upload:{}", alice.user_id));
    let (s, j) = node.post(&format!("{base}/upload"), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
}

#[tokio::test]
async fn purge_previews_are_limited() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room_id = room(&node, &alice.token).await;
    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");
    let preview = json!({ "author_id": alice.user_id });
    let (s, j) = node.post(&path, &alice.token, preview.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    exhaust(&node.state.purge_limiter, &format!("purge:{}", alice.user_id));
    let (s, j) = node.post(&path, &alice.token, preview).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
}

#[tokio::test]
async fn the_emoji_and_sound_proxy_is_limited_per_address() {
    let node = test_node("t.local").await;
    exhaust(&node.state.media_proxy_limiter, "ip:unknown");
    let id = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";
    for path in [
        format!("/api/v1/emojis/{id}/image?host=other.example"),
        format!("/api/v1/sounds/{id}/audio?host=other.example"),
    ] {
        assert_eq!(node.get(&path).await.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
    }
    // The node's own emojis are no proxy.
    assert_eq!(node.get(&format!("/api/v1/emojis/{id}/image")).await.status(), StatusCode::NOT_FOUND);
}
