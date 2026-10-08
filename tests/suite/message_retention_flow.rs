// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Message retention (`TAVRN_RETENTION_DAYS`): the hourly housekeeping deletes messages older than the retention of
//! their conversation; rooms may only shorten it (`message_retention_days`); pinned messages and the welcome channel
//! are exempt; the files of deleted messages go with them; one audit entry per run that deleted something.
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
    owner: Session,
    member: Session,
    room_id: String,
    channel: String,
}

async fn setup(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Room {
    let node = test_node_with("t.local", tweak).await;
    let owner = node.register("owner").await;
    let member = node.register("member").await;
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({})).await;
    Room { node, owner, member, room_id, channel }
}

impl Room {
    async fn send(&self, body: &str) -> String {
        let (s, msg) = self.node.send(&self.owner.token, &self.room_id, &self.channel, body).await;
        assert_eq!(s, StatusCode::CREATED, "{msg}");
        msg["id"].as_str().unwrap().to_string()
    }

    /// Sends a message with a file; returns (message id, blob id).
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
                &format!("/api/v1/rooms/{}/channels/{}/messages", self.room_id, self.channel),
                &self.owner.token,
                json!({ "content": { "type": "text", "body": body }, "attachments": [blob_id] }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{msg}");
        (msg["id"].as_str().unwrap().to_string(), blob_id)
    }

    async fn exists(&self, message_id: &str) -> bool {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = $1")
            .bind(message_id)
            .fetch_one(&self.node.state.db)
            .await
            .unwrap();
        n == 1
    }

    async fn expire(&self) -> housekeeping::MessageRetentionReport {
        housekeeping::expire_messages(&self.node.state, Utc::now(), Duration::from_secs(60)).await.unwrap()
    }

    async fn audit_entries(&self) -> Vec<Value> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'retention.messages' ORDER BY id")
                .fetch_all(&self.node.state.db)
                .await
                .unwrap();
        rows.iter().map(|m| serde_json::from_str(m).unwrap()).collect()
    }
}

/// Moves every message of the conversation `id` (or only the message `id`) `days` into the past.
async fn age(node: &TestNode, id: &str, days: i64) {
    let at = util::format_time(Utc::now() - chrono::Duration::days(days));
    sqlx::query("UPDATE messages SET created_at = $1 WHERE id = $2 OR conversation_id = $2")
        .bind(at)
        .bind(id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn node_retention_deletes_old_messages_but_not_pinned_welcome_or_young_ones() {
    let r = setup(|c| c.retention_days = 30).await;
    let old = r.send("old").await;
    let pinned = r.send("pinned").await;
    let young = r.send("young").await;
    let (with_file, blob) = r.send_file("file").await;
    for id in [&old, &pinned, &with_file] {
        age(&r.node, id, 40).await;
    }
    age(&r.node, &young, 10).await;
    let (s, j) = r
        .node
        .put(&format!("/api/v1/rooms/{}/channels/{}/pins/{pinned}", r.room_id, r.channel), &r.owner.token, json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The welcome channel's entries (the member's join) are the room's security log: never deleted.
    let welcome: String = sqlx::query_scalar(
        "SELECT c.id FROM channels c JOIN conversations v ON v.id = c.id WHERE v.room_id = $1 AND c.kind = 'system'",
    )
    .bind(&r.room_id)
    .fetch_one(&r.node.state.db)
    .await
    .unwrap();
    age(&r.node, &welcome, 400).await;
    let welcome_entries = |db| {
        let welcome = welcome.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
                .bind(welcome)
                .fetch_one(db)
                .await
                .unwrap()
        }
    };
    let before = welcome_entries(&r.node.state.db).await;
    assert!(before > 0, "the join wrote an entry");

    // A DM message (rows written directly: DMs are end-to-end encrypted) follows the node value too.
    let (s, dm) = r
        .node
        .post("/api/v1/conversations", &r.owner.token, json!({ "kind": "dm", "members": ["member@t.local"] }))
        .await;
    assert!(s.is_success(), "{dm}");
    let dm_msg = util::ulid();
    sqlx::query("INSERT INTO messages (id, conversation_id, author_id, encrypted, content, content_size, created_at) VALUES ($1, $2, $3, 1, 'x', 1, $4)")
        .bind(&dm_msg).bind(dm["id"].as_str().unwrap()).bind(&r.owner.user_id)
        .bind(util::format_time(Utc::now() - chrono::Duration::days(31)))
        .execute(&r.node.state.db).await.unwrap();

    assert_eq!(r.expire().await, housekeeping::MessageRetentionReport { deleted: 3, incomplete: false });
    assert!(!r.exists(&old).await && !r.exists(&with_file).await && !r.exists(&dm_msg).await);
    assert!(r.exists(&pinned).await && r.exists(&young).await, "pinned and young messages are kept");
    assert_eq!(welcome_entries(&r.node.state.db).await, before, "welcome channel exempt");
    // The attachment went with its message: row and file.
    assert!(!r.node.state.storage.path_of(&blob).unwrap().exists(), "file deleted");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE id = $1")
        .bind(&blob)
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let (_, list) = r
        .node
        .get_auth(&format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.channel), &r.member.token)
        .await;
    let ids: Vec<&str> = list.as_array().unwrap().iter().filter_map(|m| m["id"].as_str()).collect();
    assert!(ids.contains(&pinned.as_str()) && !ids.contains(&old.as_str()), "{list}");

    let audit = r.audit_entries().await;
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!((audit[0]["deleted"].as_i64(), audit[0]["node_days"].as_i64()), (Some(3), Some(30)), "{audit:?}");

    // The account's data summary names the retention (LEGAL.md §2).
    let (_, summary) = r.node.get_auth("/api/v1/users/me/data", &r.member.token).await;
    assert_eq!(summary["retention"]["message_retention_days"], 30, "{summary}");

    // A second run finds nothing and writes no audit entry.
    assert_eq!(r.expire().await, housekeeping::MessageRetentionReport::default());
    assert_eq!(r.audit_entries().await.len(), 1);
}

#[tokio::test]
async fn retention_zero_keeps_everything_and_rooms_can_only_shorten() {
    let r = setup(|_| {}).await;
    let ancient = r.send("ancient").await;
    age(&r.node, &ancient, 4000).await;
    assert_eq!(r.expire().await, housekeeping::MessageRetentionReport::default(), "0 = keep forever");
    assert!(r.exists(&ancient).await);

    // The room setting: owner or manage_room only, 0–36500.
    let room = format!("/api/v1/rooms/{}", r.room_id);
    let (s, _) = r.node.patch(&room, &r.member.token, json!({ "message_retention_days": 7 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = r.node.patch(&room, &r.owner.token, json!({ "message_retention_days": 40_000 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.range")), "{j}");
    let (s, j) = r.node.patch(&room, &r.owner.token, json!({ "message_retention_days": 7 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["message_retention_days"], 7, "{j}");
    let (_, detail) = r.node.get_auth(&room, &r.member.token).await;
    assert_eq!(detail["message_retention_days"], 7, "members see the room's retention");
    let log = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", r.room_id), &r.owner.token).await.1;
    assert!(log.to_string().contains("message_retention_days"), "{log}");

    let young = r.send("young").await;
    age(&r.node, &young, 3).await;
    assert_eq!(r.expire().await.deleted, 1);
    assert!(!r.exists(&ancient).await && r.exists(&young).await);
    let audit = r.audit_entries().await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["rooms"], 1, "{audit:?}");

    // 0 resets to the node value.
    let (_, j) = r.node.patch(&room, &r.owner.token, json!({ "message_retention_days": 0 })).await;
    assert_eq!(j["message_retention_days"], Value::Null);
}

#[tokio::test]
async fn room_cannot_extend_the_node_retention_and_budget_is_respected() {
    let r = setup(|c| c.retention_days = 30).await;
    let old = r.send("old").await;
    let mid = r.send("mid").await;
    age(&r.node, &old, 40).await;
    age(&r.node, &mid, 20).await;
    let room = format!("/api/v1/rooms/{}", r.room_id);
    let (_, j) = r.node.patch(&room, &r.owner.token, json!({ "message_retention_days": 365 })).await;
    assert_eq!(j["message_retention_days"], 365, "{j}");

    // No time left: nothing happens, the next round does it.
    let report = housekeeping::expire_messages(&r.node.state, Utc::now(), Duration::ZERO).await.unwrap();
    assert_eq!(report, housekeeping::MessageRetentionReport { deleted: 0, incomplete: true });
    assert!(r.exists(&old).await);
    assert_eq!(r.expire().await.deleted, 1, "365 days in the room do not extend the node's 30");
    assert!(!r.exists(&old).await && r.exists(&mid).await);

    // A shorter room value applies on top of the node value.
    r.node.patch(&room, &r.owner.token, json!({ "message_retention_days": 14 })).await;
    assert_eq!(r.expire().await.deleted, 1);
    assert!(!r.exists(&mid).await);
}

#[tokio::test]
async fn deleting_thread_messages_recounts_the_thread() {
    let r = setup(|c| c.retention_days = 30).await;
    let root = r.send("root").await;
    let (s, thread) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/threads", r.room_id, r.channel),
            &r.owner.token,
            json!({ "root_message_id": root, "title": "T" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{thread}");
    let thread_id = thread["id"].as_str().unwrap().to_string();
    let path = format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.channel);
    for body in ["one", "two"] {
        let (s, m) = r
            .node
            .post(&path, &r.owner.token, json!({ "content": { "type": "text", "body": body }, "thread_id": thread_id }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{m}");
        if body == "one" {
            age(&r.node, m["id"].as_str().unwrap(), 40).await;
        }
    }
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT message_count FROM threads WHERE id = $1")
            .bind(&thread_id)
            .fetch_one(&r.node.state.db)
            .await
            .unwrap()
    };
    assert_eq!(count().await, 2);
    assert_eq!(r.expire().await.deleted, 1);
    assert_eq!(count().await, 1, "the thread counts its messages again");
}
