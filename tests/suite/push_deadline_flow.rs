// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Push endpoints that never answer cannot hold the node's push senders: a user's subscriptions are tried at once
//! under one deadline, a user's next push does not queue behind their slow one, and failures are kept when an
//! endpoint is registered again.
use crate::common;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Session, TestNode, test_node};
use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::{Value, json};
use tavrn_node::push::{Job, run};

const DOMAIN: &str = "t.local";

/// A server that accepts connections and never answers.
async fn tarpit() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    base
}

fn keys() -> Value {
    let secret = SecretKey::generate_from_rng(&mut tavrn_node::util::os_rng());
    let mut auth = [0u8; 16];
    tavrn_node::util::fill_random(&mut auth);
    json!({ "p256dh": URL_SAFE_NO_PAD.encode(secret.public_key().to_sec1_point(false).as_bytes()),
            "auth": URL_SAFE_NO_PAD.encode(auth) })
}

async fn subscribe(node: &TestNode, user: &Session, endpoint: &str) {
    let (s, j) = node
        .put("/api/v1/users/me/push-subscriptions", &user.token, json!({ "endpoint": endpoint, "keys": keys() }))
        .await;
    assert!(s.is_success(), "{j}");
}

async fn failures(node: &TestNode, user: &Session) -> Vec<i64> {
    sqlx::query_scalar("SELECT failures FROM push_subscriptions WHERE user_id = $1 ORDER BY endpoint")
        .bind(&user.user_id)
        .fetch_all(&node.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn silent_push_endpoints_cannot_hold_the_senders() {
    let node = test_node(DOMAIN).await;
    let bob = node.register("bob").await;
    let base = tarpit().await;
    for i in 0..5 {
        subscribe(&node, &bob, &format!("{base}/slow/{i}")).await;
    }
    let test = || Job::Test { user_id: bob.user_id.clone() };
    // Five silent endpoints are tried at once: the job ends at the user's deadline, not after five timeouts.
    let state = node.state.clone();
    let job = test();
    let first = tokio::spawn(async move {
        let started = Instant::now();
        run(&state, job).await.unwrap();
        started.elapsed()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Meanwhile another push for bob does not wait behind the first one.
    let started = Instant::now();
    run(&node.state, test()).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "the second job waited {:?}", started.elapsed());
    let took = first.await.unwrap();
    assert!(took < tavrn_node::push::USER_DEADLINE + Duration::from_secs(2), "one job took {took:?}");
    assert_eq!(failures(&node, &bob).await, vec![1; 5], "every silent endpoint counts a failure");
    // Registering an endpoint again keeps its failures (and its hold-back).
    subscribe(&node, &bob, &format!("{base}/slow/0")).await;
    assert_eq!(failures(&node, &bob).await, vec![1; 5]);
    let (s, _) = node.get_auth("/api/v1/users/me/push-subscriptions", &bob.token).await;
    assert_eq!(s, StatusCode::OK);
}
