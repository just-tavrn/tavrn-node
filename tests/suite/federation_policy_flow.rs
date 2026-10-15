// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Federation policy and budgets (FEDERATION.md §1.5, §5.2; ENCRYPTION.md §3.2): outbound traffic honours node bans
//! and peer blocks, the KeyPackage claim budget of a sending node cannot be sidestepped through requesters of other
//! nodes, and inbound friend requests are bounded per sending node and recipient.


use axum::http::StatusCode;
use common::federation::{A, FedNode, two_nodes};
use serde_json::{Value, json};

/// A node token request to `path` on `to_node`, signed by `from_node`.
async fn s2s(from_node: &FedNode, to_node: &FedNode, path: &str, body: Value) -> (StatusCode, String) {
    let body = body.to_string().into_bytes();
    let n = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": from_node.domain(), "sub": from_node.domain(), "aud": to_node.domain(), "iat": n, "exp": n + 300,
        "jti": tavrn_node::util::ulid(), "typ": "s2s", "htm": "POST", "htu": path,
        "body_sha256": tavrn_node::federation::tokens::body_sha256(&body),
    });
    let token = from_node.sign(&claims);
    let (st, _, raw) =
        to_node.raw(axum::http::Method::POST, path, &token, &[("content-type", "application/json")], body).await;
    let code = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v["code"].as_str().map(String::from));
    (st, code.unwrap_or_default())
}

const CLAIM: &str = "/api/v1/federation/key-packages/claim";

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

// ---------------------------------------------------------------- claim budget

#[tokio::test]
async fn claims_in_the_name_of_a_third_node_user_count_against_the_sending_node() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    while b.state.claim_target_limiter.check(&format!("a.test|{}", carol.user_id)).await.is_ok() {}
    let (st, _) = s2s(&a, &b, CLAIM, json!({ "user": "carol@b.test", "requester": "x1@a.test" })).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "a.test's own budget is exhausted");
    // dave@c.test is carol's friend here, but a.test cannot speak for him.
    let dave =
        tavrn_node::store::federation::create_remote_user(&b.state.db, "dave", "c.test", "dave", "user", None)
            .await
            .unwrap();
    tavrn_node::store::social::add_friendship(&b.state.db, &carol.user_id, &dave.id).await.unwrap();
    let (st, code) = s2s(&a, &b, CLAIM, json!({ "user": "carol@b.test", "requester": "dave@c.test" })).await;
    assert_eq!((st, code.as_str()), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    // A related requester of the sending node itself keeps the exemption.
    let erin = tavrn_node::store::federation::create_remote_user(&b.state.db, "erin", A, "erin", "user", None)
        .await
        .unwrap();
    tavrn_node::store::social::add_friendship(&b.state.db, &carol.user_id, &erin.id).await.unwrap();
    let (st, code) = s2s(&a, &b, CLAIM, json!({ "user": "carol@b.test", "requester": "erin@a.test" })).await;
    assert_eq!(st, StatusCode::OK, "{code}");
}
