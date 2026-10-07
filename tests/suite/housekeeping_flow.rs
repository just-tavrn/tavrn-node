// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Periodic housekeeping of the node: pruning of the MLS handshake log and of old Welcomes
//! (ENCRYPTION.md §4.4), and of remote users nothing ties to the node any more (FEDERATION.md §2.6).
use crate::common;

use chrono::{Duration, Utc};
use common::test_node;
use serde_json::json;
use tavrn_node::{housekeeping, util};

async fn insert_commits(
    db: &tavrn_node::db::Pool,
    conversation_id: &str,
    epochs: std::ops::RangeInclusive<i64>,
    at: &str,
) {
    for epoch in epochs {
        sqlx::query("INSERT INTO mls_commits (conversation_id, epoch, message, committer_device_id, created_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(conversation_id)
            .bind(epoch)
            .bind(vec![1u8, 2, 3])
            .bind("dev")
            .bind(at)
            .execute(db)
            .await
            .unwrap();
    }
}

async fn epochs(db: &tavrn_node::db::Pool, conversation_id: &str) -> (i64, i64, i64) {
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT CAST(COUNT(*) AS BIGINT), CAST(MIN(epoch) AS BIGINT), CAST(MAX(epoch) AS BIGINT) FROM mls_commits WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(db)
    .await
    .unwrap();
    row
}

#[tokio::test]
async fn prunes_old_epochs_beyond_1000_and_old_welcomes() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    node.befriend(&alice, &carol).await;
    let busy = node.create_dm(&alice, &bob).await;
    let young = node.create_dm(&alice, &carol).await;
    let db = &node.state.db;
    let old = util::format_time(Utc::now() - Duration::days(100));
    let recent = util::now();

    // 1005 epochs: 1..=1003 are 100 days old, the last two are new. Epochs 1..=5 are beyond the
    // newest 1000 and older than 90 days: they go.
    insert_commits(db, &busy, 1..=1003, &old).await;
    insert_commits(db, &busy, 1004..=1005, &recent).await;
    // Few epochs, all old: kept (at least the last 1000 epochs stay).
    insert_commits(db, &young, 1..=10, &old).await;

    for (id, at) in [("01J9ZK3G5M8Q2W4E6R8T0Y2V01", &old), ("01J9ZK3G5M8Q2W4E6R8T0Y2V02", &recent)] {
        sqlx::query("INSERT INTO mls_welcomes (id, conversation_id, device_id, epoch, welcome, created_at) VALUES ($1, $2, $3, 1, $4, $5)")
            .bind(id)
            .bind(&busy)
            .bind(&bob.device_id)
            .bind(vec![9u8])
            .bind(at.as_str())
            .execute(db)
            .await
            .unwrap();
    }

    let report = housekeeping::prune_handshake_log(db, Utc::now()).await.unwrap();
    assert_eq!(report.commits, 5);
    assert_eq!(report.welcomes, 1);
    assert_eq!(epochs(db, &busy).await, (1000, 6, 1005));
    assert_eq!(epochs(db, &young).await, (10, 1, 10));
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM mls_welcomes").fetch_all(db).await.unwrap();
    assert_eq!(left, vec!["01J9ZK3G5M8Q2W4E6R8T0Y2V02".to_string()]);

    // Idempotent; recent commits beyond 1000 epochs stay until they are 90 days old.
    insert_commits(db, &busy, 1006..=1010, &recent).await;
    let report = housekeeping::prune_handshake_log(db, Utc::now()).await.unwrap();
    assert_eq!((report.commits, report.welcomes), (5, 0), "epochs 6..=10 are old and now beyond the newest 1000");
    let report = housekeeping::prune_handshake_log(db, Utc::now()).await.unwrap();
    assert_eq!((report.commits, report.welcomes), (0, 0));
    assert_eq!(epochs(db, &busy).await, (1000, 11, 1010));
}

// ---------------------------------------------------------------- remote users (FEDERATION.md §2.6)

async fn remote_user(node: &common::federation::FedNode, address: &str) -> Option<String> {
    let (name, domain) = address.split_once('@').unwrap();
    sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND domain = $2")
        .bind(name)
        .bind(domain)
        .fetch_optional(&node.state.db)
        .await
        .unwrap()
}

async fn count(node: &common::federation::FedNode, sql: &str, user_id: &str) -> i64 {
    sqlx::query_scalar(sql).bind(user_id).fetch_one(&node.state.db).await.unwrap()
}

#[tokio::test]
async fn remote_users_nothing_ties_to_the_node_are_deleted_after_the_retention() {
    let (a, b) = common::federation::two_nodes().await;
    let carol = b.register("carol").await;
    let (_, room) = b.post("/api/v1/rooms", &carol.token, json!({ "name": "Hangout", "join_mode": "public" })).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    // alice signs in on B, joins and leaves again; bob stays a member; dave has a friend request of
    // carol; erin was the stub of a friend request carol withdrew.
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    a.register("dave").await;
    a.register("erin").await;
    let ra = b.sign_in_from(&a, &alice).await;
    assert!(b.post(&format!("/api/v1/rooms/{room_id}/join"), &ra.token, json!({})).await.0.is_success());
    assert!(b.post(&format!("/api/v1/rooms/{room_id}/leave"), &ra.token, json!({})).await.0.is_success());
    let rb = b.sign_in_from(&a, &bob).await;
    assert!(b.post(&format!("/api/v1/rooms/{room_id}/join"), &rb.token, json!({})).await.0.is_success());
    let (st, j) = b.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "dave@a.test" })).await;
    assert!(st.is_success(), "{j}");
    let (st, j) = b.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "erin@a.test" })).await;
    assert!(st.is_success(), "{j}");
    let request = j["request_id"].as_str().unwrap().to_string();
    let (st, j) = b.delete(&format!("/api/v1/users/me/friends/requests/{request}"), &carol.token).await;
    assert!(st.is_success(), "{j}");
    let alice_id = remote_user(&b, "alice@a.test").await.unwrap();
    assert_eq!(count(&b, "SELECT CAST(COUNT(*) AS BIGINT) FROM devices WHERE user_id = $1", &alice_id).await, 1);

    // Within the retention nothing goes.
    let state = &b.state;
    assert_eq!(housekeeping::prune_remote_users(state, Utc::now()).await.unwrap(), 0);
    assert_eq!(housekeeping::prune_remote_users(state, Utc::now() + Duration::days(89)).await.unwrap(), 0);
    // After 90 days without a federated login: alice (no ties left) and the stub of erin.
    assert_eq!(housekeeping::prune_remote_users(state, Utc::now() + Duration::days(91)).await.unwrap(), 2);
    assert!(remote_user(&b, "alice@a.test").await.is_none());
    assert!(remote_user(&b, "erin@a.test").await.is_none());
    assert!(remote_user(&b, "bob@a.test").await.is_some(), "a member stays");
    assert!(remote_user(&b, "dave@a.test").await.is_some(), "a pending friend request keeps the row");
    assert!(remote_user(&b, "carol@b.test").await.is_some(), "local users are never touched");
    for table in ["devices", "sessions", "remote_users"] {
        let sql = format!("SELECT CAST(COUNT(*) AS BIGINT) FROM {table} WHERE user_id = $1");
        assert_eq!(count(&b, &sql, &alice_id).await, 0, "{table}");
    }
    // A later federated login simply creates the user again.
    let again = b.sign_in_from(&a, &alice).await;
    let (st, me) = b.get_auth("/api/v1/users/me", &again.token).await;
    assert_eq!((st.as_u16(), me["address"].as_str()), (200, Some("alice@a.test")));
}

#[tokio::test]
async fn remote_user_cleanup_follows_its_setting() {
    let (a, b) = common::federation::two_nodes_with(|_| {}, |c| c.federation_remote_user_retention_days = 0).await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    assert_eq!(housekeeping::prune_remote_users(&b.state, Utc::now() + Duration::days(3650)).await.unwrap(), 0);
    assert!(remote_user(&b, "alice@a.test").await.is_some(), "0 keeps remote users forever");

    let (a, b) = common::federation::two_nodes_with(|_| {}, |c| c.federation_remote_user_retention_days = 10).await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    assert_eq!(housekeeping::prune_remote_users(&b.state, Utc::now() + Duration::days(9)).await.unwrap(), 0);
    assert_eq!(housekeeping::prune_remote_users(&b.state, Utc::now() + Duration::days(11)).await.unwrap(), 1);
}
