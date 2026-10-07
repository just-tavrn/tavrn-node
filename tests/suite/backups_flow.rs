// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! History backups (ENCRYPTION.md §7).
use crate::common;

use axum::http::{Method, StatusCode};
use common::test_node;
use tavrn_crypto::{Client, Device, MasterSecret};

const CONV: &str = "01J9ZK3G5M8Q2W4E6R8T0Y2V00";

#[tokio::test]
async fn put_get_list_with_etags() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let path = format!("/api/v1/users/me/backups/other.example/{CONV}");

    // A real backup blob from the crypto core.
    let master = MasterSecret::generate().unwrap();
    let mut client = Client::new(Device::generate("alice@t.local", &alice.device_id).unwrap());
    let conversation = format!("other.example/{CONV}");
    client.create_group(&conversation).unwrap();
    let blob = client.export_backup(&conversation, &master.backup_key()).unwrap();

    let (s, _, _) = node.raw(Method::GET, &path, &alice.token, &[], vec![]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // If-Match on a backup that does not exist yet.
    let (s, _, _) = node.raw(Method::PUT, &path, &alice.token, &[("if-match", "\"x\"")], blob.clone()).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);

    let (s, h, body) =
        node.raw(Method::PUT, &path, &alice.token, &[("content-type", "application/octet-stream")], blob.clone()).await;
    assert_eq!(s, StatusCode::OK, "{body:?}");
    let etag = h["etag"].to_str().unwrap().to_string();
    let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(info["conversation"], conversation.as_str());
    assert_eq!(info["etag"], etag.as_str());
    assert_eq!(info["size"], blob.len());

    let (s, h, body) = node.raw(Method::GET, &path, &alice.token, &[], vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["etag"].to_str().unwrap(), etag);
    assert_eq!(h["content-type"], "application/octet-stream");
    assert_eq!(body.to_vec(), blob);
    let n = client.import_backup(&conversation, &master.backup_key(), &body).unwrap();
    assert!(n <= 1);

    // Overwrite needs the current ETag.
    let (s, _, _) = node.raw(Method::PUT, &path, &alice.token, &[], blob.clone()).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "without If-Match");
    let (s, _, body) = node.raw(Method::PUT, &path, &alice.token, &[("if-match", "\"stale\"")], blob.clone()).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "backup.etag_mismatch");
    let mut newer = blob.clone();
    newer.push(0);
    let (s, h, _) = node.raw(Method::PUT, &path, &alice.token, &[("if-match", &etag)], newer.clone()).await;
    assert_eq!(s, StatusCode::OK);
    assert_ne!(h["etag"].to_str().unwrap(), etag);
    let (s, _, _) = node.raw(Method::PUT, &path, &alice.token, &[("if-match", &etag)], blob.clone()).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "the old ETag no longer applies");

    // Owner only: Bob's /me is his own (empty) space.
    let (s, _, _) = node.raw(Method::GET, &path, &bob.token, &[], vec![]).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, list) = node.get_auth("/api/v1/users/me/backups", &bob.token).await;
    assert_eq!(list["items"], serde_json::json!([]));
    let (s, list) = node.get_auth("/api/v1/users/me/backups", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["items"][0]["conversation"], conversation.as_str());
    assert_eq!(list["items"][0]["size"], newer.len());
    let (s, _, _) = node.raw(Method::GET, &path, "no-token", &[], vec![]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn limits_and_validation() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let ok = format!("/api/v1/users/me/backups/t.local/{CONV}");
    for path in [
        format!("/api/v1/users/me/backups/T.LOCAL/{CONV}"),
        "/api/v1/users/me/backups/t.local/not-a-ulid".to_string(),
        format!("/api/v1/users/me/backups/..%2Fetc/{CONV}"),
    ] {
        let (s, _, body) = node.raw(Method::PUT, &path, &alice.token, &[], vec![1u8; 64]).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{path}: {body:?}");
    }
    let (s, _, body) = node.raw(Method::PUT, &ok, &alice.token, &[], vec![]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body:?}");
    let (s, _, body) = node.raw(Method::PUT, &ok, &alice.token, &[], vec![2u8; 64]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown version: {body:?}");
    let (s, _, body) = node.raw(Method::PUT, &ok, &alice.token, &[], vec![1u8; 1024 * 1024 + 1]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{body:?}");
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "backup.too_large");
    let (s, _, _) = node.raw(Method::PUT, &ok, &alice.token, &[], vec![1u8; 1024 * 1024]).await;
    assert_eq!(s, StatusCode::OK, "exactly 1 MiB is allowed");

    for _ in 0..10_000 {
        if node.state.backup_limiter.check(&format!("backup:{}", alice.user_id)).is_err() {
            break;
        }
    }
    let (s, _, _) = node.raw(Method::PUT, &ok, &alice.token, &[], vec![1u8; 64]).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}
