// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Attachment retention: housekeeping deletes the files of attachments older than the
//! retention of their conversation, keeps the rows as `expired`, skips pinned messages and keeps everything
//! with retention 0; downloads of expired files answer `410 attachment.expired`; rooms can only shorten.
use crate::common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use common::{Session, TestNode, body_bytes, test_node_with};
use serde_json::{Value, json};
use tavrn_node::{housekeeping, util};
use tower::ServiceExt;

struct Room {
    node: TestNode,
    admin: Session,
    owner: Session,
    member: Session,
    room_id: String,
    channel: String,
}

async fn setup(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Room {
    let node = test_node_with("t.local", tweak).await;
    let admin = node.register("admin").await;
    let owner = node.register("owner").await;
    let member = node.register("member").await;
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({})).await;
    Room { node, admin, owner, member, room_id, channel }
}

impl Room {
    /// Uploads a file, sends it in a message and returns (message id, blob id).
    async fn send_file(&self, body: &str) -> (String, String) {
        let req = Request::post(format!("/api/v1/rooms/{}/channels/{}/uploads", self.room_id, self.channel))
            .header(header::AUTHORIZATION, format!("Bearer {}", self.owner.token))
            .header(header::CONTENT_TYPE, "text/plain")
            .header("tavrn-file-name", "note.txt")
            .body(Body::from(body.as_bytes().to_vec()))
            .unwrap();
        let resp = self.node.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let blob: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let blob_id = blob["id"].as_str().unwrap().to_string();
        let (s, msg) = self
            .node
            .post(
                &self.messages_path(),
                &self.owner.token,
                json!({ "content": { "type": "text", "body": body }, "attachments": [blob_id] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{msg}");
        (msg["id"].as_str().unwrap().to_string(), blob_id)
    }

    fn messages_path(&self) -> String {
        format!("/api/v1/rooms/{}/channels/{}/messages", self.room_id, self.channel)
    }

    async fn download(&self, blob_id: &str) -> (StatusCode, Value) {
        self.node.get_auth(&format!("/api/v1/blobs/{blob_id}"), &self.member.token).await
    }

    async fn message_attachment(&self, message_id: &str) -> Value {
        let (_, list) = self.node.get_auth(&self.messages_path(), &self.member.token).await;
        list.as_array().unwrap().iter().find(|m| m["id"] == message_id).unwrap()["attachments"][0].clone()
    }

    fn file_exists(&self, blob_id: &str) -> bool {
        self.node.state.storage.path_of(blob_id).unwrap().exists()
    }

    async fn expire(&self) -> housekeeping::RetentionReport {
        housekeeping::expire_attachments(&self.node.state, Utc::now(), Duration::from_secs(60)).await.unwrap()
    }
}

async fn age(node: &TestNode, blob_id: &str, days: i64) {
    let at = util::format_time(Utc::now() - chrono::Duration::days(days));
    sqlx::query("UPDATE blobs SET created_at = $1 WHERE id = $2")
        .bind(at)
        .bind(blob_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn node_retention_expires_old_attachments_but_not_pinned_or_young_ones() {
    let r = setup(|c| c.attachment_retention_days = 30).await;
    let (old_msg, old_blob) = r.send_file("old").await;
    let (pinned_msg, pinned_blob) = r.send_file("pinned").await;
    let (_young_msg, young_blob) = r.send_file("new").await;
    age(&r.node, &old_blob, 40).await;
    age(&r.node, &pinned_blob, 40).await;
    age(&r.node, &young_blob, 10).await;
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/channels/{}/pins/{pinned_msg}", r.room_id, r.channel),
            &r.owner.token,
            json!({}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let usage_before = tavrn_node::store::blobs::room_usage(&r.node.state.db, &r.room_id).await.unwrap();

    // A DM attachment (rows written directly: DMs are end-to-end encrypted) follows the node value too.
    let (s, dm) = r
        .node
        .post("/api/v1/conversations", &r.owner.token, json!({ "kind": "dm", "members": ["member@t.local"] }))
        .await;
    assert!(s.is_success(), "{dm}");
    let dm_id = dm["id"].as_str().unwrap();
    let (dm_msg, dm_blob) = (util::ulid(), util::ulid());
    let old = util::format_time(Utc::now() - chrono::Duration::days(31));
    sqlx::query("INSERT INTO messages (id, conversation_id, author_id, encrypted, content, content_size, created_at) VALUES ($1, $2, $3, 1, 'x', 1, $4)")
        .bind(&dm_msg).bind(dm_id).bind(&r.owner.user_id).bind(&old).execute(&r.node.state.db).await.unwrap();
    sqlx::query("INSERT INTO blobs (id, uploader_id, conversation_id, message_id, name, mime, size, sha256, created_at) VALUES ($1, $2, $3, $4, '', 'application/octet-stream', 3, 'x', $5)")
        .bind(&dm_blob).bind(&r.owner.user_id).bind(dm_id).bind(&dm_msg).bind(&old).execute(&r.node.state.db).await.unwrap();
    r.node.state.storage.write(&dm_blob, b"abc").await.unwrap();

    let report = r.expire().await;
    assert_eq!(report, housekeeping::RetentionReport { expired: 2, incomplete: false });
    assert!(!r.file_exists(&old_blob) && !r.file_exists(&dm_blob), "files deleted");
    assert!(r.file_exists(&pinned_blob) && r.file_exists(&young_blob), "pinned and young kept");
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob_keys WHERE storage_id = $1")
        .bind(&old_blob)
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(keys, 0, "the wrapped file key is gone with the file");

    let (s, j) = r.download(&old_blob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::GONE, Some("attachment.expired")), "{j}");
    let (s, _) = r.download(&pinned_blob).await;
    assert_eq!(s, StatusCode::OK);
    let a = r.message_attachment(&old_msg).await;
    assert_eq!((a["id"].as_str(), a["expired"].as_bool()), (Some(old_blob.as_str()), Some(true)), "{a}");
    assert_eq!(r.message_attachment(&pinned_msg).await["expired"], false);
    let usage_after = tavrn_node::store::blobs::room_usage(&r.node.state.db, &r.room_id).await.unwrap();
    assert_eq!(usage_after, usage_before - 3, "expired files no longer count against the quota");

    // A second run finds nothing; the rows stay.
    assert_eq!(r.expire().await, housekeeping::RetentionReport::default());
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE expired_at IS NOT NULL")
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(rows, 2);
}

#[tokio::test]
async fn retention_zero_keeps_everything_and_rooms_can_only_shorten() {
    let r = setup(|_| {}).await;
    let (_, old_blob) = r.send_file("old").await;
    age(&r.node, &old_blob, 4000).await;
    assert_eq!(r.expire().await, housekeeping::RetentionReport::default(), "0 = keep forever");
    assert!(r.file_exists(&old_blob));

    // The room setting: owner or manage_room only, 0–36500.
    let room = format!("/api/v1/rooms/{}", r.room_id);
    let (s, _) = r.node.patch(&room, &r.member.token, json!({ "attachment_retention_days": 7 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = r.node.patch(&room, &r.owner.token, json!({ "attachment_retention_days": 40_000 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.range")));
    let (s, j) = r.node.patch(&room, &r.owner.token, json!({ "attachment_retention_days": 7 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["attachment_retention_days"], 7, "{j}");
    let (_, me) = r.node.get_auth(&format!("/api/v1/users/me/entitlements?room={}", r.room_id), &r.member.token).await;
    assert_eq!(me["values"]["attachments.retention_days"], 7);
    assert_eq!(me["retention_bound_days"], 0, "no node bound");

    let (_, young_blob) = r.send_file("new").await;
    age(&r.node, &young_blob, 3).await;
    assert_eq!(r.expire().await.expired, 1);
    assert!(!r.file_exists(&old_blob) && r.file_exists(&young_blob));

    // 0 resets to the node value.
    let (_, j) = r.node.patch(&room, &r.owner.token, json!({ "attachment_retention_days": 0 })).await;
    assert_eq!(j["attachment_retention_days"], Value::Null);
    let log = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", r.room_id), &r.owner.token).await.1;
    assert!(log.to_string().contains("attachment_retention_days"), "{log}");

    // A room grant shortens as well; it can never extend the node value.
    let (s, j) = r
        .node
        .post(
            "/api/v1/admin/entitlements/grants",
            &r.admin.token,
            json!({ "subject": format!("room:{}", r.room_id), "overrides": { "attachments.retention_days": 2 } }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(r.expire().await.expired, 1);
    assert!(!r.file_exists(&young_blob));
}

#[tokio::test]
async fn room_cannot_extend_the_node_retention_and_budget_is_respected() {
    let r = setup(|c| c.attachment_retention_days = 30).await;
    let (_, blob) = r.send_file("old").await;
    age(&r.node, &blob, 40).await;
    let (_, j) = r
        .node
        .patch(&format!("/api/v1/rooms/{}", r.room_id), &r.owner.token, json!({ "attachment_retention_days": 365 }))
        .await;
    assert_eq!(j["attachment_retention_days"], 365);
    let (_, me) = r.node.get_auth(&format!("/api/v1/users/me/entitlements?room={}", r.room_id), &r.owner.token).await;
    assert_eq!(me["values"]["attachments.retention_days"], 30, "{me}");
    assert_eq!(me["retention_bound_days"], 30);

    // No time left: nothing happens, the next round does it.
    let report = housekeeping::expire_attachments(&r.node.state, Utc::now(), Duration::ZERO).await.unwrap();
    assert_eq!(report, housekeeping::RetentionReport { expired: 0, incomplete: true });
    assert!(r.file_exists(&blob));
    assert_eq!(r.expire().await.expired, 1);
    assert!(!r.file_exists(&blob));
}
