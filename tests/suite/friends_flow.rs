// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Friends and blocks (local node).
use crate::common;

use axum::http::StatusCode;
use common::test_node;
use serde_json::json;
use tavrn_node::hub::Scope;

#[tokio::test]
async fn request_accept_list_remove() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;

    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.post("/api/v1/users/me/friends/requests", &alice.token, json!({ "user": "bob@t.local" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["status"], "pending");
    assert_eq!(j["user"]["address"], "bob@t.local");
    let request_id = j["request_id"].as_str().unwrap().to_string();
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let to_bob = evs.iter().find(|e| matches!(&e.scope, Scope::Users(u) if u == &vec![bob.user_id.clone()])).unwrap();
    assert_eq!(to_bob.kind, "friend.request");
    assert_eq!(to_bob.data["request"]["direction"], "incoming");
    assert_eq!(to_bob.data["request"]["user"]["address"], "alice@t.local");

    for (who, body, status, code) in [
        (&alice, json!({ "user": "bob" }), StatusCode::CONFLICT, "friend.request_exists"),
        (&alice, json!({ "user": "alice" }), StatusCode::BAD_REQUEST, "friend.self"),
        (&alice, json!({ "user": "nobody" }), StatusCode::NOT_FOUND, "user.not_found"),
        // Users of other nodes are looked up at their home node (FEDERATION.md §6.2).
        (&alice, json!({ "user": "bob@other.invalid" }), StatusCode::BAD_GATEWAY, "federation.peer_unreachable"),
    ] {
        let (s, j) = node.post("/api/v1/users/me/friends/requests", &who.token, body.clone()).await;
        assert_eq!(s, status, "{body}: {j}");
        assert_eq!(j["code"], code);
    }

    let (_, list) = node.get_auth("/api/v1/users/me/friends", &bob.token).await;
    assert_eq!(list["incoming"][0]["id"], request_id.as_str());
    assert_eq!(list["outgoing"], json!([]));
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["outgoing"][0]["user"]["address"], "bob@t.local");

    // Only the recipient accepts.
    let accept = format!("/api/v1/users/me/friends/requests/{request_id}/accept");
    let (s, j) = node.post(&accept, &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "friend.request_not_found");
    let (s, j) = node.post(&accept, &carol.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.post(&accept, &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["user"]["address"], "alice@t.local");
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(evs.iter().filter(|e| e.kind == "friend.accept").count(), 2, "both sides");
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["friends"][0]["user"]["address"], "bob@t.local");
    assert_eq!(list["outgoing"], json!([]));
    let (s, j) = node.post("/api/v1/users/me/friends/requests", &bob.token, json!({ "user": "alice" })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "friend.exists");

    // Remove the friendship.
    let mut rx = node.state.hub.subscribe();
    let (s, _) = node.delete("/api/v1/users/me/friends/alice", &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(rx.try_recv().unwrap().kind, "friend.remove");
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["friends"], json!([]));
    let (s, j) = node.delete("/api/v1/users/me/friends/alice", &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "friend.not_found");

    // Decline and cancel.
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "alice" })).await;
    let id = j["request_id"].as_str().unwrap().to_string();
    let (s, _) = node.delete(&format!("/api/v1/users/me/friends/requests/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "uninvolved users do not see the request");
    let (s, _) = node.delete(&format!("/api/v1/users/me/friends/requests/{id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "decline");
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "alice" })).await;
    let id = j["request_id"].as_str().unwrap().to_string();
    let (s, _) = node.delete(&format!("/api/v1/users/me/friends/requests/{id}"), &carol.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "withdraw");
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["incoming"], json!([]));

    // Mutual request accepts automatically.
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "bob" })).await;
    assert_eq!(j["status"], "pending");
    let (s, j) = node.post("/api/v1/users/me/friends/requests", &bob.token, json!({ "user": "carol" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["status"], "accepted");
    assert!(j["request_id"].is_null());
}

#[tokio::test]
async fn blocks_and_rate_limits() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "alice" })).await;
    assert_eq!(j["status"], "pending");

    // Blocking ends friendship and pending requests in both directions.
    let (s, j) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "bob" })).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, _) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "carol" })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["friends"], json!([]));
    assert_eq!(list["incoming"], json!([]));
    assert_eq!(list["blocked"].as_array().unwrap().len(), 2);
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &bob.token).await;
    assert_eq!(list["friends"], json!([]));
    for (who, target) in [(&bob, "alice"), (&alice, "bob")] {
        let (s, j) = node.post("/api/v1/users/me/friends/requests", &who.token, json!({ "user": target })).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
        assert_eq!(j["code"], "friend.blocked");
    }
    let (s, j) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "alice" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (s, _) = node.delete("/api/v1/users/me/blocks/bob", &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = node.delete("/api/v1/users/me/blocks/bob", &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let (s, _) = node.post("/api/v1/users/me/friends/requests", &bob.token, json!({ "user": "alice" })).await;
    assert_eq!(s, StatusCode::CREATED);

    for _ in 0..10_000 {
        if node.state.friend_limiter.check(&format!("friend:{}", carol.user_id)).is_err() {
            break;
        }
    }
    let (s, j) = node.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "bob" })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
}
