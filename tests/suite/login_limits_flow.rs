// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The limits of the sign-in paths: what an anonymous login may make the node remember, and that one remote account
//! cannot use up the budget its whole home domain shares.
use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{
    federation::{B, two_nodes_with},
    test_node,
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

/// A username that cannot exist is refused before it is looked up or counted as a per-account key, and a login
/// body is small: the node never keeps attacker-sized keys for the limiter window.
#[tokio::test]
async fn login_refuses_oversized_usernames_before_counting_them() {
    let node = test_node("t.local").await;
    let _admin = node.register("admin").await;
    let long = "a".repeat(4 * 1024);
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": long, "password": "wrong-password-1" })),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("auth.username_invalid")), "{j}");
    let huge = "a".repeat(1024 * 1024);
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": huge, "password": "wrong-password-1" })),
        )
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

/// Remote users count against their own limit before the budget of their home domain, and requests the own limit
/// refuses do not use up the domain's budget: one account cannot lock the other users of its domain out.
#[tokio::test]
async fn one_remote_user_cannot_use_up_the_budget_of_their_domain() {
    let (a, b) = two_nodes_with(
        |_| {},
        |c| {
            c.federation_rate_api = 6;
            c.federation_rate_api_per_user = 2;
        },
    )
    .await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let ra = b.sign_in_from(&a, &alice).await;
    let rb = b.sign_in_from(&a, &bob).await;
    for _ in 0..2 {
        assert_eq!(b.get_auth("/api/v1/users/me", &ra.token).await.0, StatusCode::OK);
    }
    for _ in 0..10 {
        assert_eq!(b.get_auth("/api/v1/users/me", &ra.token).await.0, StatusCode::TOO_MANY_REQUESTS);
    }
    for _ in 0..2 {
        assert_eq!(b.get_auth("/api/v1/users/me", &rb.token).await.0, StatusCode::OK, "bob is not affected");
    }
    // A rate-limited hello is no refused session (`4001` makes clients end it): the client tries again later.
    let mut ws = tokio_tungstenite::connect_async(b.ws_url()).await.unwrap().0;
    ws.send(Message::Text(json!({ "op": "hello", "token": ra.token }).to_string().into())).await.unwrap();
    let closed = loop {
        match common::within(Duration::from_secs(10), "the close frame", ws.next()).await {
            Some(Ok(Message::Close(Some(frame)))) => break (u16::from(frame.code), frame.reason.to_string()),
            Some(Ok(Message::Text(t))) => assert!(!t.contains("\"ready\""), "rate limited, no ready: {t}"),
            other => panic!("expected a close frame, got {other:?}"),
        }
    };
    assert_eq!((closed.0, closed.1.as_str()), (4002, "rate_limited"));
}

/// Federated logins: one account, and one client address, get a share of the domain's login budget, not all of it.
#[tokio::test]
async fn one_remote_user_cannot_use_up_the_login_budget_of_their_domain() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_rate_logins = 8).await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let url = format!("http://127.0.0.1:{}/api/v1/auth/federated", b.port);
    let http = reqwest::Client::new();
    let login = |token: String, from: &'static str| {
        let (http, url) = (http.clone(), url.clone());
        async move {
            let r = http
                .post(url)
                .header("x-forwarded-for", from)
                .json(&json!({ "token": token, "device_name": "Firefox" }))
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            (status, r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    // Per account: two of the eight.
    for from in ["198.51.100.1", "198.51.100.2"] {
        let (s, j) = login(a.federation_token(&alice, B).await, from).await;
        assert_eq!(s, 200, "{j}");
    }
    let (s, j) = login(a.federation_token(&alice, B).await, "198.51.100.3").await;
    assert_eq!(s, 429, "{j}");
    // Per address: two of the eight, whoever signs in.
    let (s, j) = login(a.federation_token(&bob, B).await, "198.51.100.3").await;
    assert_eq!(s, 200, "the refused attempt above did not count for the domain: {j}");
    let carol = a.register("carol").await;
    let (s, j) = login(a.federation_token(&carol, B).await, "198.51.100.3").await;
    assert_eq!(s, 429, "the address used its share: {j}");
    let (s, j) = login(a.federation_token(&carol, B).await, "198.51.100.4").await;
    assert_eq!(s, 200, "{j}");
}
