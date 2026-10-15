// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Federation policy and budgets (FEDERATION.md §1.5, §5.2; ENCRYPTION.md §3.2): outbound traffic honours node bans
//! and peer blocks, the KeyPackage claim budget of a sending node cannot be sidestepped through requesters of other
//! nodes, and inbound friend requests are bounded per sending node and recipient.


use axum::http::StatusCode;
use common::federation::{A, two_nodes};
use serde_json::json;

// ---------------------------------------------------------------- outbound policy

#[tokio::test]
async fn a_blocked_peer_receives_nothing_from_the_outbox() {
    let (a, b) = two_nodes().await;
    let bob = b.register("bob").await;
    a.sign_in_from(&b, &bob).await; // a.test is now one of bob's federation targets
    tavrn_node::store::federation::set_peer_status(&b.state.db, A, "blocked").await.unwrap();
    let bob_row = tavrn_node::store::users::by_id(&b.state.db, &bob.user_id).await.unwrap().unwrap();
    tavrn_node::federation::remote::devices_changed(&b.state, &bob_row).await.unwrap();
    let report = b.deliver().await;
    assert_eq!(report.delivered, 0, "nothing reaches a blocked peer: {report:?}");
    assert!(b.outbox().await.is_empty(), "entries for a blocked peer are dropped");
}

#[tokio::test]
async fn a_node_ban_of_a_domain_stops_its_outbox_entries() {
    let (a, b) = two_nodes().await;
    let admin = b.register("admin").await; // the first user of a dev node is node admin
    let bob = b.register("bob").await;
    a.sign_in_from(&b, &bob).await;
    let bob_row = tavrn_node::store::users::by_id(&b.state.db, &bob.user_id).await.unwrap().unwrap();
    // Queued before the ban, and after it.
    tavrn_node::federation::remote::devices_changed(&b.state, &bob_row).await.unwrap();
    let (st, j) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": A })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    tavrn_node::federation::remote::devices_changed(&b.state, &bob_row).await.unwrap();
    let report = b.deliver().await;
    assert_eq!(report.delivered, 0, "{report:?}");
    assert!(b.outbox().await.is_empty());
}

#[tokio::test]
async fn profiles_and_app_documents_are_not_fetched_from_a_blocked_peer() {
    let (a, b) = two_nodes().await;
    a.register("alice").await;
    // Control: the profile is fetched while the peer is fine.
    assert!(tavrn_node::federation::profiles::fetch(&b.state, "alice", A).await.is_ok());
    tavrn_node::store::federation::set_peer_status(&b.state.db, A, "key_conflict").await.unwrap();
    let e = tavrn_node::federation::profiles::fetch(&b.state, "alice", A).await.unwrap_err();
    assert_eq!(e.code(), "federation.peer_blocked");
    let e = tavrn_node::installations::fetch_document(&b.state, A, &tavrn_node::util::ulid()).await.unwrap_err();
    assert_eq!(e.code(), "federation.peer_blocked");
}
