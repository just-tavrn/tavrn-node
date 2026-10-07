// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! Request logs never contain a webhook secret (APPLICATIONS.md §6.1, §9.4): the HTTP trace layer logs the path
//! as `/api/v1/webhooks/<id>/***`, for successful, refused and mistyped requests alike. A thread-local subscriber
//! captures the requests' events; tracing's callsite interest cache and max level are process-wide and every
//! integration test shares this process, so the captures run one at a time and rebuild that cache first.

use crate::common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use axum::http::{Method, StatusCode};
use common::{TestNode, test_node};
use serde_json::json;

/// One log capture at a time (see the module comment).
static CAPTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Collects everything the subscriber writes.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn webhook_secrets_never_reach_the_request_log() {
    let _capture = CAPTURE.lock().await;
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Logs").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels/{channel}/webhooks"), &alice.token, json!({ "name": "CI" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let url = j["url"].as_str().unwrap();
    let path = url[url.find("/api/v1/").unwrap()..].to_string();
    let id = j["webhook"]["id"].as_str().unwrap().to_string();
    let secret = path.rsplit('/').next().unwrap().to_string();

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // Interest computed on other threads (without this subscriber) must not hide this thread's events.
    tracing::callsite::rebuild_interest_cache();
    let body = json!({ "content": { "type": "text", "body": "deployed" } });
    let (s, j) = node.req(Method::POST, &path, None, Some(body.clone())).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, _) = node.req(Method::POST, &format!("{path}?wait=true&x={secret}"), None, Some(body.clone())).await;
    assert_eq!(s, StatusCode::OK);
    let wrong = format!("/api/v1/webhooks/{id}/{secret}x");
    assert_eq!(node.req(Method::POST, &wrong, None, Some(body.clone())).await.0, StatusCode::NOT_FOUND);
    let mistyped = format!("/api/v1//webhooks/{id}/{secret}");
    assert_eq!(node.req(Method::POST, &mistyped, None, Some(body)).await.0, StatusCode::NOT_FOUND);
    drop(guard);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains(&format!("/api/v1/webhooks/{id}/***")), "the redacted path is logged:\n{logs}");
    assert!(!logs.contains(&secret), "the secret leaked into the logs:\n{logs}");
}

/// Node-sealed posts into encrypted channels (APPLICATIONS.md §6.1a): neither the text, the per-message username nor
/// the embed of a plaintext body reaches any log line, accepted or refused.
#[tokio::test]
async fn node_sealed_payloads_never_reach_the_logs() {
    let _capture = CAPTURE.lock().await;
    use common::e2ee::{DOMAIN, b64, qualified};
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Sealed logs").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    node.create_group(&mut alice, &channel).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/webhooks"),
            alice.token(),
            json!({ "name": "Alerts", "sealing": "node" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let url = j["url"].as_str().unwrap();
    let path = url[url.find("/api/v1/").unwrap()..].to_string();
    let (pk, sig) = alice.client.inbox_key(&qualified(&channel), 0).unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/conversations/{channel}/inbox-key"),
            alice.token(),
            json!({ "epoch": 0, "public_key": b64(&pk), "signature": b64(&sig) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    // Interest computed on other threads (without this subscriber) must not hide this thread's events.
    tracing::callsite::rebuild_interest_cache();
    let body = json!({
        "content": { "type": "text", "body": "PLAINTEXT-BODY-7f3a", "embeds": [{ "title": "EMBED-TITLE-7f3a" }] },
        "username": "USERNAME-7f3a",
    });
    let (s, m) = node.req(Method::POST, &format!("{path}?wait=true"), None, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["encrypted"], true);
    // Refused payloads (bad username, bad type, bad mention) are not logged either.
    for bad in [
        json!({ "content": { "type": "text", "body": "PLAINTEXT-BODY-7f3a" }, "username": "USERNAME-7f3a@x" }),
        json!({ "content": { "type": "PLAINTEXT-BODY-7f3a" } }),
        json!({ "content": { "type": "text", "body": "a" }, "mentions": ["USERNAME-7f3a mention"] }),
        json!({ "content": "PLAINTEXT-BODY-7f3a" }),
    ] {
        let (s, j) = node.req(Method::POST, &path, None, Some(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
        assert!(!j.to_string().contains("7f3a"), "the answer quotes the payload: {j}");
    }
    drop(guard);

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("webhook executed"), "the execution is logged:\n{logs}");
    for needle in ["PLAINTEXT-BODY", "EMBED-TITLE", "USERNAME-7f3a", "7f3a"] {
        assert!(!logs.contains(needle), "{needle} leaked into the logs:\n{logs}");
    }
}
