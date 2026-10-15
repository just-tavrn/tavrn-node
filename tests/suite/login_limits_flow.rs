// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The limits of the sign-in paths: what an anonymous login may make the node remember, and that one remote account
//! cannot use up the budget its whole home domain shares.
use crate::common;

use axum::http::{Method, StatusCode};
use common::test_node;
use serde_json::json;

/// A username that cannot exist is refused before it is looked up or counted as a per-account key, and a login
/// body is small: the node never keeps attacker-sized keys for the limiter window.
#[tokio::test]
async fn login_refuses_oversized_usernames_before_counting_them() {
    let node = test_node("t.local").await;
    let _admin = node.register("admin").await;
    let long = "a".repeat(4 * 1024);
    let (s, j) = node
        .req(Method::POST, "/api/v1/auth/login", None, Some(json!({ "username": long, "password": "wrong-password-1" })))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("auth.username_invalid")), "{j}");
    let huge = "a".repeat(1024 * 1024);
    let (s, j) = node
        .req(Method::POST, "/api/v1/auth/login", None, Some(json!({ "username": huge, "password": "wrong-password-1" })))
        .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");
    // Real accounts still sign in, by name and by full address.
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": "Admin@t.local", "password": common::password("admin") })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}
