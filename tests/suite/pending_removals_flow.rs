// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Pending MLS removals (ENCRYPTION.md §4.7): recorded with `mls.remove_needed` and by housekeeping, listed for
//! members, cleared by the commit that removes the leaf, by the roster and after 90 days.
use crate::common;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::{
    TestNode,
    e2ee::{DOMAIN, Dev, qualified, unb64},
    test_node,
};
use serde_json::Value;
use tavrn_node::{device_cleanup, util};

/// A DM of alice and bob where bob has a second device (`bob2`) in the group.
async fn dm_with_second_device(node: &TestNode) -> (Dev, Dev, Dev, String) {
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    node.add_user(&mut alice, &dm, "bob").await;
    assert_eq!(node.accept_welcomes(&mut bob).await, 1);
    let mut bob2 = node.second_device(&bob).await;
    let (_, gi) = node.get_auth(&format!("/api/v1/conversations/{dm}/mls/group-info"), bob.token()).await;
    let join = bob2.client.join_by_external_commit(&qualified(&dm), &unb64(&gi["group_info"])).unwrap();
    let (s, j) = node.post_commit(bob2.token(), &dm, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    bob2.client.merge_pending_commit(&qualified(&dm)).unwrap();
    node.catch_up(&mut alice, &dm).await;
    node.catch_up(&mut bob, &dm).await;
    (alice, bob, bob2, dm)
}

async fn pending(node: &TestNode, token: &str, dm: &str) -> Value {
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{dm}/mls/pending-removals"), token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j["items"].clone()
}

#[tokio::test]
async fn deleted_devices_stay_pending_until_a_member_removes_the_leaf() {
    let node = test_node(DOMAIN).await;
    let (mut alice, bob, bob2, dm) = dm_with_second_device(&node).await;
    assert_eq!(pending(&node, alice.token(), &dm).await, serde_json::json!([]));

    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", bob2.session.device_id), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let items = pending(&node, alice.token(), &dm).await;
    assert_eq!(items.as_array().unwrap().len(), 1, "{items}");
    assert_eq!(items[0]["identity"], bob2.identity().as_str());
    assert_eq!(items[0]["reason"], "deleted");
    assert_eq!(items[0]["conversation_id"], dm.as_str());
    // bob sees his own pending leaves across conversations.
    let (_, own) = node.get_auth("/api/v1/mls/pending-removals", bob.token()).await;
    assert_eq!(own["items"][0]["identity"], bob2.identity().as_str());
    let (_, none) = node.get_auth("/api/v1/mls/pending-removals", alice.token()).await;
    assert_eq!(none["items"], serde_json::json!([]), "only the caller's own leaves");
    // A non-member learns nothing.
    let carol = node.register("carol").await;
    let (s, _) = node.get_auth(&format!("/api/v1/conversations/{dm}/mls/pending-removals"), &carol.token).await;
    assert!(s == StatusCode::NOT_FOUND || s == StatusCode::FORBIDDEN, "{s}");

    // Any member may remove a deleted device (§4.5 rule 4); the commit clears the row.
    let rm = alice.client.remove_members(&qualified(&dm), &[bob2.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    alice.client.merge_pending_commit(&qualified(&dm)).unwrap();
    assert_eq!(pending(&node, bob.token(), &dm).await, serde_json::json!([]));
}

#[tokio::test]
async fn the_own_user_removes_its_deleted_device() {
    let node = test_node(DOMAIN).await;
    let (_alice, mut bob, bob2, dm) = dm_with_second_device(&node).await;
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", bob2.session.device_id), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rm = bob.client.remove_members(&qualified(&dm), &[bob2.identity()]).unwrap();
    let (s, j) = node.post_commit(bob.token(), &dm, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(pending(&node, bob.token(), &dm).await, serde_json::json!([]));
}

#[tokio::test]
async fn housekeeping_finds_leaves_of_missing_devices_and_expires_old_rows() {
    let node = test_node(DOMAIN).await;
    let (alice, _bob, bob2, dm) = dm_with_second_device(&node).await;
    let db = &node.state.db;
    // A device row that disappeared without `mls.remove_needed` (deleted by an older version).
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(&bob2.session.device_id).execute(db).await.unwrap();
    let found = device_cleanup::detect_ghost_leaves(&node.state).await.unwrap();
    assert_eq!(found, 1);
    let items = pending(&node, alice.token(), &dm).await;
    assert_eq!(items[0]["identity"], bob2.identity().as_str());
    assert_eq!(items[0]["reason"], "deleted");
    assert_eq!(device_cleanup::detect_ghost_leaves(&node.state).await.unwrap(), 0, "recorded once");

    // After 90 days the row goes (clients still detect the ghost themselves).
    sqlx::query("UPDATE mls_pending_removals SET created_at = $1")
        .bind(util::format_time(Utc::now() - Duration::days(91)))
        .execute(db)
        .await
        .unwrap();
    let report = device_cleanup::run(&node.state, Utc::now()).await.unwrap();
    assert_eq!(report.expired, 1);
    // The scan of this round found the leaf again (it is still in the group): a fresh row.
    assert_eq!(report.ghosts, 1);
}

#[tokio::test]
async fn rows_of_leaves_no_longer_in_the_group_are_dropped() {
    let node = test_node(DOMAIN).await;
    let (alice, _bob, _bob2, dm) = dm_with_second_device(&node).await;
    tavrn_node::store::pending_removals::insert(
        &node.state.db,
        &dm,
        &["ghost@t.local/01J9ZK3G5M8Q2W4E6R8T0Y2V4X".into()],
        "deleted",
    )
    .await
    .unwrap();
    assert_eq!(pending(&node, alice.token(), &dm).await, serde_json::json!([]), "not in the roster");
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mls_pending_removals").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(left, 0);
}
