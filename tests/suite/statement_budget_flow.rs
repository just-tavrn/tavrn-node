// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Statement budgets of the hot routes: the database statements one request runs, counted by the per-request
//! statement counter of telemetry.rs (the one behind `queries=` of the `slow request` line). The budgets pin that
//! list routes cost a constant number of statements, independent of the page size, and that the high-frequency
//! routes stay cheap.
use crate::common::{self, Session, TestNode, logs, test_node};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use serde_json::{Value, json};
use tower::ServiceExt;
use tracing::Instrument;

/// Runs one request inside a span of the node's request target and returns its response and the database statements
/// it ran (the per-request statement counter of telemetry.rs, which the test log subscriber carries). The span is the
/// test's own, so neither timing nor other tests running at the same time affect the count.
async fn measure(
    node: &TestNode,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, u64) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let request = match body {
        Some(b) => builder.header(header::CONTENT_TYPE, "application/json").body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let span = tracing::trace_span!(target: tavrn_node::telemetry::REQUEST_SPAN, "request");
    let response = node.router.clone().oneshot(request).instrument(span.clone()).await.unwrap();
    let status = response.status();
    let bytes = common::body_bytes(response).instrument(span.clone()).await;
    let json = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    let statements = tavrn_node::telemetry::statements(&span).expect("the test subscriber counts statements");
    (status, json, statements)
}

/// Installs the test log subscriber (with the statement counter) before the first measurement.
async fn counting() {
    let _c = logs::CAPTURE.lock().await;
    drop(logs::start());
}

/// Records a missed budget (all budgets are checked, then reported together).
fn budget(over: &mut Vec<String>, ok: bool, what: String) {
    if !ok {
        over.push(what);
    }
}

async fn befriend(node: &TestNode, a: &Session, b: &Session) {
    node.post("/api/v1/users/me/friends/requests", &a.token, json!({ "user": b.username })).await;
    let (_, j) = node.post("/api/v1/users/me/friends/requests", &b.token, json!({ "user": a.username })).await;
    assert_eq!(j["status"], "accepted", "{j}");
}

async fn dm(node: &TestNode, a: &Session, b: &Session) -> String {
    let (s, j) = node
        .post(
            "/api/v1/conversations",
            &a.token,
            json!({ "kind": "dm", "members": [format!("{}@t.local", b.username)] }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    j["id"].as_str().unwrap().to_string()
}

/// A public room of `owner` with `n` joined members (returns the room, its text channel and the members).
async fn room_with(node: &TestNode, owner: &Session, n: usize, prefix: &str) -> (String, String, Vec<Session>) {
    let room = node.plaintext_room(&owner.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{id}"), &owner.token, json!({ "join_mode": "public", "discoverable": true }))
        .await;
    assert!(s.is_success(), "{j}");
    let mut members = Vec::new();
    for i in 0..n {
        let u = node.register(&format!("{prefix}{i}")).await;
        let (s, j) = node.post(&format!("/api/v1/rooms/{id}/join"), &u.token, json!({})).await;
        assert!(s.is_success(), "{j}");
        members.push(u);
    }
    (id, channel, members)
}

#[tokio::test]
async fn hot_routes_stay_within_their_statement_budgets() {
    counting().await;
    let node = test_node("t.local").await;
    let mut over = Vec::new();
    let alice = node.register("alice").await;
    let (room, channel, members) = room_with(&node, &alice, 30, "member").await;

    // GET /rooms/{id}/members: constant in the page size.
    let path = format!("/api/v1/rooms/{room}/members");
    let (s, small, few) = measure(&node, Method::GET, &format!("{path}?limit=3"), Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{small}");
    let (s, page, many) = measure(&node, Method::GET, &path, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(page.as_array().unwrap().len(), 31, "{page}");
    println!("BUDGET GET members: 3 per page {few}, 31 per page {many}");
    budget(&mut over, few == many, format!("GET members: {few} for 3, {many} for 31"));
    budget(&mut over, many <= 8, format!("GET members: {many} statements"));

    // POST …/ephemeral (a cursor packet, 10 per second per drawing user).
    let eph = format!("/api/v1/conversations/{channel}/ephemeral");
    let cursor = json!({ "type": "cursor", "content": { "x": 1, "y": 2 } });
    // The first packet may load the shared snapshot; the budget is for the steady state.
    let (s, j) = node.post(&eph, &alice.token, cursor.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j, n) = measure(&node, Method::POST, &eph, Some(&alice.token), Some(cursor.clone())).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET POST ephemeral (channel): {n}");
    budget(&mut over, n <= 3, format!("POST ephemeral: {n} statements"));

    // POST a channel message.
    let send = format!("/api/v1/rooms/{room}/channels/{channel}/messages");
    let (s, j, n) = measure(
        &node,
        Method::POST,
        &send,
        Some(&alice.token),
        Some(json!({ "content": { "type": "text", "body": "hello" } })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let last = j["id"].as_str().unwrap().to_string();
    println!("BUDGET POST message: {n}");

    // A message mentioning a role, and the room as a member opens it (both read the room's roles once now).
    let (s, role) = node.post(&format!("/api/v1/rooms/{room}/roles"), &alice.token, json!({ "name": "Crew" })).await;
    assert!(s.is_success(), "{role}");
    let mention = json!({ "content": { "type": "text", "body": "crew" }, "mentions": [format!("role:{}", role["id"].as_str().unwrap())] });
    let (s, j, n) = measure(&node, Method::POST, &send, Some(&alice.token), Some(mention)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    println!("BUDGET POST message with a role mention: {n}");
    let (s, j, n) = measure(&node, Method::GET, &format!("/api/v1/rooms/{room}"), Some(&members[1].token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET room: {n}");

    // PUT …/read.
    let (s, j, n) = measure(
        &node,
        Method::PUT,
        &format!("/api/v1/conversations/{channel}/read"),
        Some(&members[0].token),
        Some(json!({ "last_read_message_id": last })),
    )
    .await;
    assert!(s.is_success(), "{j}");
    println!("BUDGET PUT read: {n}");

    // GET /conversations: constant in the number of DMs.
    let list_route = "/api/v1/conversations";
    for m in members.iter().take(2) {
        befriend(&node, &alice, m).await;
        dm(&node, &alice, m).await;
    }
    let (s, j, two) = measure(&node, Method::GET, list_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let friends_route = "/api/v1/users/me/friends";
    let (s, j, two_friends) = measure(&node, Method::GET, friends_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for m in members.iter().skip(2).take(6) {
        befriend(&node, &alice, m).await;
        let id = dm(&node, &alice, m).await;
        node.post(
            &format!("/api/v1/conversations/{id}/messages"),
            &alice.token,
            json!({ "content": { "type": "text", "body": "hi" } }),
        )
        .await;
    }
    let (s, j, eight) = measure(&node, Method::GET, list_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j, eight_friends) = measure(&node, Method::GET, friends_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET friends: 2 friends {two_friends}, 8 friends {eight_friends}");
    budget(&mut over, two_friends == eight_friends, format!("GET friends: {two_friends} for 2, {eight_friends} for 8"));
    println!("BUDGET GET conversations: 2 DMs {two}, 8 DMs {eight}");
    budget(&mut over, two == eight, format!("GET conversations: {two} for 2, {eight} for 8"));
    budget(&mut over, eight <= 10, format!("GET conversations: {eight} statements"));

    // GET /conversations/requests: message requests from strangers (not friends).
    let req_route = "/api/v1/conversations/requests";
    let bob = &members[10];
    for m in members.iter().skip(11).take(4) {
        dm(&node, m, bob).await;
    }
    let (s, j, n) = measure(&node, Method::GET, req_route, Some(&bob.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET conversations/requests (4): {n}");
    budget(&mut over, n <= 12, format!("GET conversations/requests: {n} statements"));

    // GET /presence: constant in the number of online users.
    let presence = "/api/v1/presence";
    let mut online =
        vec![tavrn_node::presence::Registry::connect(&node.state, &members[0].user_id, &members[0].device_id)];
    let (s, j, one) = measure(&node, Method::GET, presence, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for m in members.iter().skip(1) {
        online.push(tavrn_node::presence::Registry::connect(&node.state, &m.user_id, &m.device_id));
    }
    let (s, j, all) = measure(&node, Method::GET, presence, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j.as_array().unwrap().len(), 30, "{j}");
    drop(online);
    println!("BUDGET GET presence: 1 online {one}, 30 online {all}");
    budget(&mut over, one == all, format!("GET presence: {one} for 1, {all} for 30"));

    // GET /rooms/discover (anonymous): constant in the number of public rooms.
    let discover = "/api/v1/rooms/discover";
    let (s, j, one) = measure(&node, Method::GET, discover, None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for i in 0..4 {
        let r = node.create_room(&alice.token, &format!("Public {i}")).await;
        let (s, j) = node
            .patch(
                &format!("/api/v1/rooms/{}", r["id"].as_str().unwrap()),
                &alice.token,
                json!({ "join_mode": "public", "discoverable": true }),
            )
            .await;
        assert!(s.is_success(), "{j}");
    }
    let (s, j, five) = measure(&node, Method::GET, discover, None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET discover: 1 room {one}, 5 rooms {five}");
    budget(&mut over, one == five, format!("GET discover: {one} for 1, {five} for 5"));
    assert!(over.is_empty(), "over budget:\n{}", over.join("\n"));
}

/// Encrypted cursor packets (the default: channels are end-to-end encrypted) check the epoch and the sending
/// device's attestation; both are cached briefly, so the steady state stays as cheap as plaintext.
#[tokio::test]
async fn encrypted_cursor_packets_stay_within_their_budget() {
    counting().await;
    let node = test_node("t.local").await;
    let mut alice = node.crypto_user("alice").await;
    let created = node.create_room(alice.token(), "Encrypted").await;
    let channel = TestNode::text_channel(&created);
    node.create_group(&mut alice, &channel).await;
    let content = alice
        .client
        .encrypt_content(&crate::common::e2ee::qualified(&channel), r#"{"type":"cursor","x":1,"y":2}"#)
        .unwrap();
    let eph = format!("/api/v1/conversations/{channel}/ephemeral");
    let body = json!({ "type": "cursor", "content": content });
    let (s, j) = node.post(&eph, alice.token(), body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j, n) = measure(&node, Method::POST, &eph, Some(alice.token()), Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET POST ephemeral (encrypted channel): {n}");
    assert!(n <= 3, "POST ephemeral (encrypted): {n} statements");
}

/// The entitlement check of the devices an MLS commit adds or removes runs once for all their users, with the same
/// number of statements for 3 and for 20 users.
#[tokio::test]
async fn mls_entitlement_checks_cost_the_same_for_many_users() {
    counting().await;
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (_room, channel, members) = room_with(&node, &alice, 20, "member").await;
    let db = &node.state.db;
    let owner = tavrn_node::store::users::by_id(db, &alice.user_id).await.unwrap().unwrap();
    let conv = tavrn_node::access::conversation(&node.state, &channel, &owner).await.unwrap();
    let ids: Vec<String> = members.iter().map(|m| m.user_id.clone()).collect();
    let users = tavrn_node::store::users::by_ids(db, &ids).await.unwrap();
    let mut counts = Vec::new();
    for n in [3, 20] {
        let refs: Vec<&tavrn_node::models::UserRow> = users.iter().take(n).collect();
        let span = tracing::trace_span!(target: tavrn_node::telemetry::REQUEST_SPAN, "request");
        let entitled =
            tavrn_node::access::entitled_users(&node.state, &conv, &refs).instrument(span.clone()).await.unwrap();
        assert_eq!(entitled.len(), n, "every member views the channel");
        counts.push(tavrn_node::telemetry::statements(&span).unwrap());
    }
    println!("BUDGET MLS entitlement: 3 users {}, 20 users {}", counts[0], counts[1]);
    assert_eq!(counts[0], counts[1]);
    assert!(counts[1] <= 4, "{counts:?}");
}
