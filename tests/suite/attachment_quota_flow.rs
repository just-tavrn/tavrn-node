// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The storage quota of a room holds for uploads that stream at the same time: each one reserves its share before
//! its body arrives, so parallel slow uploads cannot all count on the same free space.
use crate::common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{TestNode, body_bytes, test_node_with};
use serde_json::Value;
use futures::channel::mpsc;
use tower::ServiceExt;

type Chunk = Result<Vec<u8>, std::io::Error>;

/// Starts a streaming upload; the body is fed through the returned sender and ends when it is dropped.
fn start(
    node: &TestNode,
    token: &str,
    room: &str,
    channel: &str,
) -> (mpsc::UnboundedSender<Chunk>, tokio::task::JoinHandle<(StatusCode, Value)>) {
    let (tx, rx) = mpsc::unbounded::<Chunk>();
    let body = Body::from_stream(rx);
    let req = Request::post(format!("/api/v1/rooms/{room}/channels/{channel}/uploads"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "image/png")
        .header("tavrn-file-name", "x.png")
        .body(body)
        .unwrap();
    let router = node.router.clone();
    let task = tokio::spawn(async move {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    });
    (tx, task)
}

#[tokio::test]
async fn parallel_streaming_uploads_cannot_overrun_the_room_quota() {
    let node = test_node_with("t.local", |c| {
        c.upload_max_bytes = 16;
        c.storage_quota_per_room_bytes = 20;
    })
    .await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let png = |n: usize| {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.resize(n, 0);
        v
    };
    let (a_tx, a) = start(&node, &alice.token, &room_id, &channel);
    a_tx.unbounded_send(Ok(png(12))).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (b_tx, b) = start(&node, &alice.token, &room_id, &channel);
    b_tx.unbounded_send(Ok(png(12))).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(b_tx);
    drop(a_tx);
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    let created = [&a, &b].iter().filter(|(s, _)| *s == StatusCode::CREATED).count();
    assert_eq!(created, 1, "{a:?} {b:?}");
    let refused = if a.0 == StatusCode::CREATED { &b } else { &a };
    assert_eq!((refused.0, refused.1["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("upload.quota_exceeded")));
    let used: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) FROM blobs WHERE room_id = $1")
        .bind(&room_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert!(used <= 20, "{used} bytes stored");
    // The reservation of a finished upload is released: the remaining space is usable.
    let (tx, c) = start(&node, &alice.token, &room_id, &channel);
    tx.unbounded_send(Ok(png(8))).unwrap();
    drop(tx);
    let (s, j) = c.await.unwrap();
    assert_eq!(s, StatusCode::CREATED, "{j}");
}
