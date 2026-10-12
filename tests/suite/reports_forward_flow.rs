// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Reports v2 (protocol MODERATION.md §1.6, FEDERATION.md §5.2 `report.forward`): node admins forward a report about
//! a user of another node to that user's home node, which stores it in its admins' inbox with the origin. Two real
//! nodes: forwarding, receiving, deduplication, the capability check, local users, authorization and the limits.
use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{
    Session, TestNode,
    federation::{A, B, FedNode, two_nodes, two_nodes_with},
};
use serde_json::{Value, json};
use tavrn_node::util;

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

/// A on A.test: the admin `admina` and the room owner `alice` with a plaintext room; on B: the admin `adminb` and
/// `carol`, who joins alice's room with a federated session and posts there.
struct World {
    a: FedNode,
    b: FedNode,
    admin_a: Session,
    alice: Session,
    admin_b: Session,
    carol: Session,
    room_id: String,
    channel: String,
    message_id: String,
}

async fn world_with(tweak_b: impl FnOnce(&mut tavrn_node::config::Config)) -> World {
    let (a, b) = two_nodes_with(|_| {}, tweak_b).await;
    world_on(a, b).await
}

async fn world_on(a: FedNode, b: FedNode) -> World {
    let admin_a = a.register("admina").await;
    let alice = a.register("alice").await;
    let admin_b = b.register("adminb").await;
    let carol = b.register("carol").await;
    let room = a.plaintext_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = a.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let remote = a.sign_in_from(&b, &carol).await;
    let (s, j) =
        a.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote.token, json!({})).await;
    assert!(s.is_success(), "{j}");
    let (s, m) = a.send(&remote.token, &room_id, &channel, "Buy followers at spam.example").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let message_id = m["id"].as_str().unwrap().to_string();
    World { a, b, admin_a, alice, admin_b, carol, room_id, channel, message_id }
}

/// alice reports carol's message on A; returns the report id.
async fn report_carol(w: &World) -> String {
    let (s, r) =
        w.a.post(
            "/api/v1/reports",
            &w.alice.token,
            json!({ "kind": "message", "conversation_id": w.channel, "message_id": w.message_id,
                    "category": "spam", "detail": "Selling followers in every channel" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    r["id"].as_str().unwrap().to_string()
}

async fn forward(node: &FedNode, token: &str, id: &str) -> (StatusCode, Value) {
    node.post(&format!("/api/v1/reports/{id}/forward"), token, json!({})).await
}

/// Forwarded reports in the outbox of `node`.
async fn queued(node: &FedNode) -> Vec<tavrn_node::store::federation::OutboxRow> {
    node.outbox().await.into_iter().filter(|r| r.kind == "report.forward").collect()
}

/// Posts an inbox message signed by `from_node` to `to_node`; returns status and problem code.
async fn inbox(from_node: &FedNode, to_node: &FedNode, from: &str, to: &str, payload: Value) -> (StatusCode, String) {
    let body = json!({ "id": util::ulid(), "type": "report.forward", "from": from, "to": to, "at": util::now(),
                       "payload": payload })
    .to_string()
    .into_bytes();
    let n = chrono::Utc::now().timestamp();
    let token = from_node.sign(&json!({
        "iss": from_node.domain(), "sub": from_node.domain(), "aud": to_node.domain(), "iat": n, "exp": n + 300,
        "jti": util::ulid(), "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox",
        "body_sha256": tavrn_node::federation::tokens::body_sha256(&body),
    }));
    let (st, _, raw) = to_node
        .raw(Method::POST, "/api/v1/federation/inbox", &token, &[("content-type", "application/json")], body)
        .await;
    let code = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v["code"].as_str().map(String::from));
    (st, code.unwrap_or_default())
}

fn payload(report_id: &str) -> Value {
    json!({ "report_id": report_id, "kind": "user", "category": "harassment", "detail": "Keeps insulting people",
            "created_at": util::now(), "reporter": "anon-reporter-1" })
}

async fn admin_inbox(node: &FedNode, admin: &Session) -> Vec<Value> {
    let (s, list) = node.get_auth("/api/v1/admin/reports", &admin.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list["reports"].as_array().unwrap().clone()
}

#[tokio::test]
async fn a_report_about_a_remote_user_reaches_the_admins_of_its_home_node() {
    let w = world_with(|_| {}).await;
    let id = report_carol(&w).await;
    let mut events = w.b.state.hub.subscribe();

    // Only node admins forward.
    let (s, j) = forward(&w.a, &w.alice.token, &id).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "auth.node_admin_required"), "{j}");
    let (s, j) = forward(&w.a, &w.admin_a.token, &util::ulid()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "report.not_found"), "{j}");
    assert!(queued(&w.a).await.is_empty());

    let (s, r) = forward(&w.a, &w.admin_a.token, &id).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["forwarded"]["node"], B);
    assert_eq!(r["forwarded"]["by"], format!("admina@{A}"));
    assert_eq!(r["status"], "open", "forwarding changes nothing else");
    // Idempotent: a second forward answers the same and sends nothing again.
    let (s, again) = forward(&w.a, &w.admin_a.token, &id).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["forwarded"], r["forwarded"]);
    let out = queued(&w.a).await;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].target, B);
    // The reporter stays pseudonymous to the home node.
    let body: Value = serde_json::from_str(&out[0].body).unwrap();
    assert_eq!(body["from"], A);
    assert_eq!(body["to"], format!("carol@{B}"));
    let reporter = body["payload"]["reporter"].as_str().unwrap().to_string();
    assert!(reporter.starts_with("anon-"), "{reporter}");
    assert!(!out[0].body.contains("alice"), "no address or name of the reporter: {}", out[0].body);
    assert!(!out[0].body.contains(&w.room_id), "no room id: {}", out[0].body);
    let (_, list) = w.a.get_auth("/api/v1/admin/reports", &w.admin_a.token).await;
    assert_eq!(list["reports"][0]["forwarded"]["node"], B, "the list shows it too");

    let report = w.a.deliver().await;
    assert_eq!(report.delivered, 1, "{report:?}");

    // B: the admins' inbox has it with its origin.
    let reports = admin_inbox(&w.b, &w.admin_b).await;
    assert_eq!(reports.len(), 1, "{reports:?}");
    let f = &reports[0];
    assert_eq!(
        (f["source"].as_str(), f["scope"].as_str(), f["kind"].as_str()),
        (Some("forward"), Some("node"), Some("message"))
    );
    assert_eq!(f["origin"]["node"], A);
    assert_eq!(f["origin"]["report_id"], id.as_str());
    assert_eq!(f["origin"]["reporter"], reporter.as_str());
    assert!(f["origin"]["reported_at"].is_string(), "{f}");
    assert_eq!(f["reporter"], Value::Null);
    assert_eq!(f["node"], A, "the content lives on the origin");
    assert_eq!(f["target"]["id"], w.carol.user_id.as_str());
    assert_eq!(f["target_address"], format!("carol@{B}"));
    assert_eq!(
        (f["category"].as_str(), f["detail"].as_str()),
        (Some("spam"), Some("Selling followers in every channel"))
    );
    assert_eq!(f["snapshot"]["text"], "Buy followers at spam.example");
    assert_eq!(f["snapshot"]["author"], format!("carol@{B}"));
    assert_eq!(f["message_id"], w.message_id.as_str());
    assert_eq!(f["forwarded"], Value::Null);
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, events.recv()).await.expect("report.create on B").unwrap();
        if ev.kind == "report.create" {
            assert_eq!(ev.data["report"]["source"], "forward");
            assert!(
                matches!(&ev.scope, tavrn_node::hub::Scope::Users(u) if u.contains(&w.admin_b.user_id) && !u.contains(&w.carol.user_id)),
                "{:?}",
                ev.scope
            );
            break;
        }
    }
    // The home node acts on the account, not on content it does not hold.
    let fid = f["id"].as_str().unwrap();
    let (s, j) =
        w.b.post(&format!("/api/v1/reports/{fid}/actions"), &w.admin_b.token, json!({ "action": "delete_message" }))
            .await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "report.target_remote"), "{j}");
    let (s, j) =
        w.b.post(&format!("/api/v1/reports/{fid}/actions"), &w.admin_b.token, json!({ "action": "purge" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["purge"]["dry_run"], true);
    // Forwarded reports are not forwarded again; carol is not told anything.
    let (s, j) = forward(&w.b, &w.admin_b.token, fid).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "report.forward_invalid"), "{j}");
    let (s, j) = w.b.get_auth(&format!("/api/v1/reports/{fid}"), &w.carol.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "report.not_found"), "{j}");

    // A replay of the same original report is accepted and changes nothing.
    let mut replay = payload(&id);
    replay["kind"] = json!("user");
    let (s, c) = inbox(&w.a, &w.b, A, &format!("carol@{B}"), replay).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{c}");
    assert_eq!(admin_inbox(&w.b, &w.admin_b).await.len(), 1);
}

#[tokio::test]
async fn only_reports_about_users_of_other_nodes_are_forwarded() {
    let w = world_with(|_| {}).await;
    let _bob = w.a.register("bob").await;
    // A local user: the admins here act themselves.
    let (s, r) =
        w.a.post(
            "/api/v1/reports",
            &w.alice.token,
            json!({ "kind": "user", "user": format!("bob@{A}"), "category": "spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let (s, j) = forward(&w.a, &w.admin_a.token, r["id"].as_str().unwrap()).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "report.target_local"), "{j}");
    // A room report names no user.
    let (s, r) = w
        .a
        .post("/api/v1/reports", &w.alice.token, json!({ "kind": "room", "room_id": w.room_id, "category": "other" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let (s, j) = forward(&w.a, &w.admin_a.token, r["id"].as_str().unwrap()).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "report.forward_invalid"), "{j}");
    // A user report about carol (remote) with the room as context is forwarded.
    let (s, r) =
        w.a.post(
            "/api/v1/reports",
            &w.alice.token,
            json!({ "kind": "user", "user": format!("carol@{B}"), "room_id": w.room_id, "category": "harassment" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let (s, j) = forward(&w.a, &w.admin_a.token, r["id"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(queued(&w.a).await.len() == 1);
    assert!(queued(&w.b).await.is_empty());
}

/// The home node must announce `reports.v2`; a node without it would ignore the type.
#[tokio::test]
async fn forwarding_needs_the_capability_of_the_home_node() {
    let w = world_with(|_| {}).await;
    let id = report_carol(&w).await;
    // A knows B's document (the federated login fetched it); B "drops" reports.v2.
    let doc: String = sqlx::query_scalar("SELECT document FROM federation_peers WHERE domain = $1")
        .bind(B)
        .fetch_one(&w.a.state.db)
        .await
        .unwrap();
    let mut doc: Value = serde_json::from_str(&doc).unwrap();
    let caps: Vec<Value> =
        doc["capabilities"].as_array().unwrap().iter().filter(|c| *c != "reports.v2").cloned().collect();
    assert!(doc["capabilities"].as_array().unwrap().iter().any(|c| c == "reports.v2"), "B announces it: {doc}");
    doc["capabilities"] = json!(caps);
    sqlx::query("UPDATE federation_peers SET document = $1 WHERE domain = $2")
        .bind(doc.to_string())
        .bind(B)
        .execute(&w.a.state.db)
        .await
        .unwrap();
    let (s, j) = forward(&w.a, &w.admin_a.token, &id).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "report.forward_unsupported"), "{j}");
    assert!(queued(&w.a).await.is_empty());
    let (_, r) = w.a.get_auth(&format!("/api/v1/reports/{id}"), &w.admin_a.token).await;
    assert_eq!(r["forwarded"], Value::Null, "{r}");
}

#[tokio::test]
async fn forwarded_reports_are_checked_deduplicated_and_limited() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.reports_inbound_per_hour = 2).await;
    let admin_b = b.register("adminb").await;
    let carol = b.register("carol").await;
    let to = format!("carol@{B}");
    assert_eq!(carol.username, "carol");
    // Unsigned: refused before anything else.
    let (s, _, _) = b
        .raw(Method::POST, "/api/v1/federation/inbox", "nope", &[("content-type", "application/json")], b"{}".to_vec())
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The reported user must be a user of this node.
    for recipient in [format!("ghost@{B}"), format!("dave@{A}")] {
        let (s, c) = inbox(&a, &b, A, &recipient, payload(&util::ulid())).await;
        assert_eq!((s, c.as_str()), (StatusCode::NOT_FOUND, "federation.recipient_unknown"), "{recipient}");
    }
    // Malformed payloads.
    let bad = |f: &dyn Fn(&mut Value)| {
        let mut p = payload(&util::ulid());
        f(&mut p);
        p
    };
    let entry = |id: &str, author: &str| json!({ "message_id": id, "author": author, "created_at": util::now(), "text": "x", "attachments": [] });
    let reported = util::ulid();
    for (what, p) in [
        ("category", bad(&|p| p["category"] = json!("rude"))),
        ("kind", bad(&|p| p["kind"] = json!("room"))),
        ("report id", bad(&|p| p["report_id"] = json!("x"))),
        ("reporter", bad(&|p| p["reporter"] = json!("alice@a.test"))),
        ("detail", bad(&|p| p["detail"] = json!("x".repeat(2001)))),
        ("message without id", bad(&|p| p["kind"] = json!("message"))),
        (
            "evidence without the reported message",
            bad(&|p| {
                p["kind"] = json!("message");
                p["message_id"] = json!(reported);
                p["evidence"] = json!([entry(&util::ulid(), &to)]);
            }),
        ),
        (
            "an author that is neither an address nor a pseudonym",
            bad(&|p| {
                p["kind"] = json!("message");
                p["message_id"] = json!(reported);
                p["evidence"] = json!([entry(&reported, "not an author!")]);
            }),
        ),
    ] {
        let (s, c) = inbox(&a, &b, A, &to, p).await;
        assert_eq!((s, c.as_str()), (StatusCode::BAD_REQUEST, "federation.envelope_invalid"), "{what}");
    }
    assert!(admin_inbox(&b, &admin_b).await.is_empty());

    // A valid message report with released evidence (a pseudonymous context author) is stored once.
    let original = util::ulid();
    let mut p = payload(&original);
    p["kind"] = json!("message");
    p["message_id"] = json!(reported);
    p["evidence"] = json!([entry(&util::ulid(), "anon-reporter-1"), entry(&reported, &to)]);
    let (s, c) = inbox(&a, &b, A, &to, p.clone()).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{c}");
    let (s, c) = inbox(&a, &b, A, &to, p).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{c}");
    let reports = admin_inbox(&b, &admin_b).await;
    assert_eq!(reports.len(), 1, "deduplicated by origin and report id: {reports:?}");
    assert_eq!(reports[0]["evidence_count"], 2);
    let (_, full) =
        b.get_auth(&format!("/api/v1/reports/{}", reports[0]["id"].as_str().unwrap()), &admin_b.token).await;
    assert_eq!(full["evidence"][0]["author"], "anon-reporter-1");
    assert_eq!(full["evidence_source"], "reporter");
    // The budget per sending domain (2 per hour here) counts every attempt.
    let (s, c) = inbox(&a, &b, A, &to, payload(&util::ulid())).await;
    assert_eq!((s, c.as_str()), (StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    // Spoofed senders come last (each one counts as a violation of the sending node).
    let (s, c) = inbox(&a, &b, &format!("alice@{A}"), &to, payload(&util::ulid())).await;
    assert_eq!((s, c.as_str()), (StatusCode::FORBIDDEN, "federation.type_forbidden"));
}

/// The pseudonym is stable per reporter and receiving node, and differs between receiving nodes.
#[tokio::test]
async fn pseudonyms_are_stable_per_receiving_node() {
    let (a, _b) = two_nodes().await;
    let p = |domain: &str, address: &str| tavrn_node::reports::forward::pseudonym(&a.state, domain, address);
    assert_eq!(p(B, "alice@a.test"), p(B, "alice@a.test"));
    assert_ne!(p(B, "alice@a.test"), p("c.test", "alice@a.test"));
    assert_ne!(p(B, "alice@a.test"), p(B, "bob@a.test"));
    let x = p(B, "alice@a.test");
    assert!(x.len() <= 64 && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "{x}");
}
