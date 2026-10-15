// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Statement budgets of the hot routes: the database statements one request runs, read from the `queries=` field of
//! the `slow request` line (`TAVRN_LOG_SLOW_REQUEST_MS`, the per-request statement counter of telemetry.rs). The
//! budgets pin that list routes cost a constant number of statements, independent of the page size, and that the
//! high-frequency routes stay cheap.
use crate::common::{Session, TestNode, logs, test_node_with};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

/// The statement count of the last `slow request` line of `method route` in `text`.
fn statements(text: &str, method: &str, route: &str) -> u64 {
    let route = format!("route={route} ");
    let method = format!("method={method} ");
    text.lines()
        .filter(|l| l.contains("slow request") && l.contains(&method) && l.contains(&route))
        .filter_map(|l| l.split("queries=").nth(1)?.split_whitespace().next()?.parse().ok())
        .next_back()
        .unwrap_or_else(|| panic!("no slow request line with a statement count for {method}{route}:\n{text}"))
}

/// Runs `req` while capturing and returns its response and statement count.
async fn measure(
    node: &TestNode,
    method: Method,
    path: &str,
    route: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, u64) {
    let (capture, guard) = logs::start();
    let (status, json) = node.req(method.clone(), path, token, body).await;
    drop(guard);
    (status, json, statements(&capture.text(), method.as_str(), route))
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
    let (s, j) =
        node.post("/api/v1/conversations", &a.token, json!({ "kind": "dm", "members": [format!("{}@t.local", b.username)] })).await;
    assert!(s.is_success(), "{j}");
    j["id"].as_str().unwrap().to_string()
}

/// A public room of `owner` with `n` joined members (returns the room, its text channel and the members).
async fn room_with(node: &TestNode, owner: &Session, n: usize, prefix: &str) -> (String, String, Vec<Session>) {
    let room = node.plaintext_room(&owner.token, "Room").await;
    let id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{id}"), &owner.token, json!({ "join_mode": "public", "discoverable": true })).await;
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
    let _c = logs::CAPTURE.lock().await;
    let node = test_node_with("t.local", |c| c.log_slow_request_ms = 1).await;
    let mut over = Vec::new();
    let alice = node.register("alice").await;
    let (room, channel, members) = room_with(&node, &alice, 30, "member").await;

    // GET /rooms/{id}/members: constant in the page size.
    let members_route = "/api/v1/rooms/{room_id}/members";
    let path = format!("/api/v1/rooms/{room}/members");
    let (s, small, few) =
        measure(&node, Method::GET, &format!("{path}?limit=3"), members_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{small}");
    let (s, page, many) = measure(&node, Method::GET, &path, members_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert_eq!(page.as_array().map_or(page["items"].as_array().unwrap().len(), Vec::len), 31, "{page}");
    println!("BUDGET GET members: 3 per page {few}, 31 per page {many}");
    budget(&mut over, few == many, format!("GET members: {few} for 3, {many} for 31"));
    budget(&mut over, many <= 8, format!("GET members: {many} statements"));

    // POST …/ephemeral (a cursor packet, 10 per second per drawing user).
    let eph = format!("/api/v1/conversations/{channel}/ephemeral");
    let cursor = json!({ "type": "cursor", "content": { "x": 1, "y": 2 } });
    // The first packet may load the shared snapshot; the budget is for the steady state.
    let (s, j) = node.post(&eph, &alice.token, cursor.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j, n) = measure(
        &node,
        Method::POST,
        &eph,
        "/api/v1/conversations/{conversation_id}/ephemeral",
        Some(&alice.token),
        Some(cursor.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET POST ephemeral (channel): {n}");
    budget(&mut over, n <= 3, format!("POST ephemeral: {n} statements"));

    // POST a channel message.
    let send = format!("/api/v1/rooms/{room}/channels/{channel}/messages");
    let (s, j, n) = measure(
        &node,
        Method::POST,
        &send,
        "/api/v1/rooms/{room_id}/channels/{channel_id}/messages",
        Some(&alice.token),
        Some(json!({ "content": { "type": "text", "body": "hello" } })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let last = j["id"].as_str().unwrap().to_string();
    println!("BUDGET POST message: {n}");

    // PUT …/read.
    let (s, j, n) = measure(
        &node,
        Method::PUT,
        &format!("/api/v1/conversations/{channel}/read"),
        "/api/v1/conversations/{conversation_id}/read",
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
    let (s, j, two) = measure(&node, Method::GET, list_route, list_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for m in members.iter().skip(2).take(6) {
        befriend(&node, &alice, m).await;
        let id = dm(&node, &alice, m).await;
        node.post(&format!("/api/v1/conversations/{id}/messages"), &alice.token, json!({ "content": { "type": "text", "body": "hi" } }))
            .await;
    }
    let (s, j, eight) = measure(&node, Method::GET, list_route, list_route, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET conversations: 2 DMs {two}, 8 DMs {eight}");
    budget(&mut over, two == eight, format!("GET conversations: {two} for 2, {eight} for 8"));
    budget(&mut over, eight <= 10, format!("GET conversations: {eight} statements"));

    // GET /conversations/requests: message requests from strangers (not friends).
    let req_route = "/api/v1/conversations/requests";
    let bob = &members[10];
    for m in members.iter().skip(11).take(4) {
        dm(&node, m, bob).await;
    }
    let (s, j, n) = measure(&node, Method::GET, req_route, req_route, Some(&bob.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET conversations/requests (4): {n}");
    budget(&mut over, n <= 12, format!("GET conversations/requests: {n} statements"));

    // GET /presence: constant in the number of online users.
    let presence = "/api/v1/presence";
    let mut online = vec![tavrn_node::presence::Registry::connect(&node.state, &members[0].user_id, &members[0].device_id)];
    let (s, j, one) = measure(&node, Method::GET, presence, presence, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for m in members.iter().skip(1) {
        online.push(tavrn_node::presence::Registry::connect(&node.state, &m.user_id, &m.device_id));
    }
    let (s, j, all) = measure(&node, Method::GET, presence, presence, Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j.as_array().unwrap().len(), 30, "{j}");
    drop(online);
    println!("BUDGET GET presence: 1 online {one}, 30 online {all}");
    budget(&mut over, one == all, format!("GET presence: {one} for 1, {all} for 30"));

    // GET /rooms/discover (anonymous): constant in the number of public rooms.
    let discover = "/api/v1/rooms/discover";
    let (s, j, one) = measure(&node, Method::GET, discover, discover, None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for i in 0..4 {
        let r = node.create_room(&alice.token, &format!("Public {i}")).await;
        let (s, j) = node
            .patch(&format!("/api/v1/rooms/{}", r["id"].as_str().unwrap()), &alice.token, json!({ "join_mode": "public", "discoverable": true }))
            .await;
        assert!(s.is_success(), "{j}");
    }
    let (s, j, five) = measure(&node, Method::GET, discover, discover, None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    println!("BUDGET GET discover: 1 room {one}, 5 rooms {five}");
    budget(&mut over, one == five, format!("GET discover: {one} for 1, {five} for 5"));
    assert!(over.is_empty(), "over budget:\n{}", over.join("\n"));
}
