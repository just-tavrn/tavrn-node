// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! `GET /metrics` (docs/HANDBOOK.md, "Metrics and health"): off by default, the bearer token, the loopback and
//! trusted-proxy rule without a token, and counters that move with requests and messages.
use crate::common;

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use common::{body_bytes, test_node, test_node_with};
use tower::ServiceExt;

const TOKEN: &str = "scrape-token-0123456789";

async fn scrape(node: &common::TestNode, peer: Option<&str>, bearer: Option<&str>) -> (StatusCode, String) {
    scrape_forwarded(node, peer, bearer, None).await
}

async fn scrape_forwarded(
    node: &common::TestNode,
    peer: Option<&str>,
    bearer: Option<&str>,
    forwarded_for: Option<&str>,
) -> (StatusCode, String) {
    let mut request = Request::get("/metrics");
    if let Some(f) = forwarded_for {
        request = request.header("x-forwarded-for", f);
    }
    if let Some(b) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    let mut request = request.body(Body::empty()).unwrap();
    if let Some(p) = peer {
        request.extensions_mut().insert(ConnectInfo(p.parse::<SocketAddr>().unwrap()));
    }
    let response = node.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    (status, String::from_utf8(body_bytes(response).await.to_vec()).unwrap())
}

fn value(text: &str, series: &str) -> f64 {
    text.lines()
        .find_map(|l| l.strip_prefix(series).and_then(|rest| rest.strip_prefix(' ')))
        .map(|v| v.parse().unwrap())
        .unwrap_or(0.0)
}

#[tokio::test]
async fn metrics_are_off_by_default() {
    let node = test_node("t.local").await;
    let (st, body) = scrape(&node, Some("127.0.0.1:5000"), None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{body}");
    assert!(!body.contains("tavrn_"));
}

#[tokio::test]
async fn token_protects_the_endpoint() {
    let node = test_node_with("t.local", |c| {
        c.metrics = tavrn_node::config::Switch::On;
        c.metrics_token = Some(TOKEN.into());
    })
    .await;
    assert_eq!(scrape(&node, Some("127.0.0.1:5000"), None).await.0, StatusCode::NOT_FOUND, "loopback needs it too");
    assert_eq!(scrape(&node, None, Some("wrong-token-0123456789")).await.0, StatusCode::NOT_FOUND);
    let (st, body) = scrape(&node, Some("198.51.100.7:443"), Some(TOKEN)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        body.contains(&format!("tavrn_build_info{{version=\"{}\"}} 1", tavrn_node::app::SOFTWARE_VERSION)),
        "{body}"
    );
}

#[tokio::test]
async fn without_a_token_only_loopback_and_trusted_proxies() {
    let node = test_node_with("t.local", |c| {
        c.metrics = tavrn_node::config::Switch::On;
        c.trusted_proxies = "10.0.0.0/8".into();
    })
    .await;
    assert_eq!(scrape(&node, Some("127.0.0.1:5000"), None).await.0, StatusCode::OK);
    assert_eq!(scrape(&node, Some("[::1]:5000"), None).await.0, StatusCode::OK);
    assert_eq!(scrape(&node, Some("10.1.2.3:5000"), None).await.0, StatusCode::OK, "trusted proxy");
    assert_eq!(scrape(&node, Some("198.51.100.7:5000"), None).await.0, StatusCode::NOT_FOUND, "public peer");
    assert_eq!(scrape(&node, None, None).await.0, StatusCode::NOT_FOUND, "no peer address");
    assert_eq!(scrape(&node, Some("198.51.100.7:5000"), Some(TOKEN)).await.0, StatusCode::NOT_FOUND, "no token set");
    // A public request through a reverse proxy on the same host is refused; an internal scraper behind it is not.
    let forwarded = |f: &'static str| scrape_forwarded(&node, Some("127.0.0.1:5000"), None, Some(f));
    assert_eq!(forwarded("198.51.100.7").await.0, StatusCode::NOT_FOUND, "public client via the proxy");
    assert_eq!(forwarded("10.9.8.7").await.0, StatusCode::OK, "internal scraper via the proxy");
    assert_eq!(forwarded("10.9.8.7, 198.51.100.7").await.0, StatusCode::NOT_FOUND, "any public hop refuses");
    assert_eq!(forwarded("not-an-address").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn counters_move() {
    let node = test_node_with("t.local", |c| c.metrics = tavrn_node::config::Switch::On).await;
    let (_, before) = scrape(&node, Some("127.0.0.1:1"), None).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = common::TestNode::text_channel(&room);
    let (st, _) = node.send(&alice.token, room_id, &channel, "hello").await;
    assert_eq!(st, StatusCode::CREATED);
    let (st, _) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(st, StatusCode::OK);
    node.get("/api/v1/does-not-exist").await;
    let _ws = node.state.hub.connect(&alice.user_id);
    let (st, after) = scrape(&node, Some("127.0.0.1:1"), None).await;
    assert_eq!(st, StatusCode::OK);
    let plain = r#"tavrn_messages_total{encrypted="false"}"#;
    assert_eq!(value(&after, plain) - value(&before, plain), 1.0, "{after}");
    let room_get = r#"tavrn_http_requests_total{method="GET",route="/api/v1/rooms/{room_id}",status="200"}"#;
    assert_eq!(value(&after, room_get), 1.0, "route templates, never ids: {after}");
    assert!(!after.contains(room_id), "no ids in labels");
    assert!(
        value(&after, r#"tavrn_http_requests_total{method="POST",route="/api/v1/auth/register",status="201"}"#) >= 1.0
    );
    assert!(after.contains(r#"route="unmatched""#) || after.contains("status=\"404\""), "unknown paths are bounded");
    assert_eq!(value(&after, "tavrn_websocket_connections"), 1.0);
    assert!(after.contains("tavrn_http_request_duration_seconds_bucket"));
    assert!(after.contains("tavrn_db_pool_connections"));
    assert!(after.contains("tavrn_housekeeping_last_run_timestamp_seconds 0"));
    assert!(after.contains("tavrn_push_sent_total 0"));
    assert!(!after.contains("tavrn_cache_up"), "standalone: no cache gauge");
    // The scrape itself is not secret-bearing: no tokens or addresses.
    assert!(!after.contains(&alice.token));
}

/// `TAVRN_LOG_SLOW_REQUEST_MS`: a request at or above the threshold leaves a `slow request` line with the method, the
/// route template, the status and the duration; off (the default) nothing is logged.
#[tokio::test]
async fn slow_requests_are_logged_when_enabled() {
    let _capture = common::logs::CAPTURE.lock().await;
    let off = test_node("t.local").await;
    let quiet = off.register("quiet").await;
    let on = test_node_with("t.local", |c| c.log_slow_request_ms = 1).await;

    let (capture, guard) = common::logs::start();
    assert_eq!(off.get_auth("/api/v1/users/me", &quiet.token).await.0, StatusCode::OK);
    drop(guard);
    assert!(!capture.text().contains("slow request"), "off by default:\n{}", capture.text());

    // A registration hashes a password (Argon2, 64 MiB): above 1 ms on any machine.
    let (capture, guard) = common::logs::start();
    on.register("alice").await;
    drop(guard);
    let text = capture.text();
    let line = text
        .lines()
        .find(|l| l.contains("slow request") && l.contains("route=/api/v1/auth/register") && l.contains("method=POST"))
        .unwrap_or_else(|| panic!("no slow request line:\n{text}"));
    assert!(line.contains("duration_ms="), "{line}");
    assert!(line.contains("status=201") || line.contains("status=200"), "{line}");
}
