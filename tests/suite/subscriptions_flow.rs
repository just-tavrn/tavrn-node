// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 5 step 4 (protocol/APPLICATIONS.md §6.2, §6.3): event subscriptions of applications, the outbox with its
//! retry schedule (injected clock), hook tokens, URL verification and the SSRF rules for application URLs.

use crate::common;

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use chrono::Utc;
use common::{Session, TestNode, test_node, test_node_with};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tavrn_node::{
    federation::client::Lookup,
    hooks::{HookClaims, HookClient},
    jwt, store, subscriptions,
};

const D: &str = "t.local";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

/// One request the receiver got.
#[derive(Debug, Clone)]
struct Received {
    headers: HeaderMap,
    body: Value,
    raw: Vec<u8>,
}

/// How the receiver answers events (pings are always answered correctly unless `bad_ping`).
#[derive(Default)]
struct Behaviour {
    status: Option<u16>,
    retry_after: Option<u64>,
    delay_ms: u64,
    bad_ping: bool,
    redirect_to: Option<String>,
}

#[derive(Clone, Default)]
struct Receiver {
    got: Arc<Mutex<Vec<Received>>>,
    behaviour: Arc<Mutex<Behaviour>>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
}

impl Receiver {
    fn events(&self) -> Vec<Received> {
        self.got.lock().unwrap().iter().filter(|r| r.body["type"] != "ping").cloned().collect()
    }
    fn pings(&self) -> Vec<Received> {
        self.got.lock().unwrap().iter().filter(|r| r.body["type"] == "ping").cloned().collect()
    }
    fn set(&self, f: impl FnOnce(&mut Behaviour)) {
        f(&mut self.behaviour.lock().unwrap());
    }
}

async fn receive(State(r): State<Receiver>, headers: HeaderMap, body: Bytes) -> axum::response::Response {
    let now = r.active.fetch_add(1, Ordering::SeqCst) + 1;
    r.max_active.fetch_max(now, Ordering::SeqCst);
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    r.got.lock().unwrap().push(Received { headers, body: parsed.clone(), raw: body.to_vec() });
    let (status, retry_after, delay, bad_ping, redirect) = {
        let b = r.behaviour.lock().unwrap();
        (b.status, b.retry_after, b.delay_ms, b.bad_ping, b.redirect_to.clone())
    };
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    r.active.fetch_sub(1, Ordering::SeqCst);
    if let Some(to) = redirect {
        return (StatusCode::FOUND, [(header::LOCATION, to)]).into_response();
    }
    if parsed["type"] == "ping" {
        let challenge = if bad_ping { json!("wrong") } else { parsed["challenge"].clone() };
        return axum::Json(json!({ "challenge": challenge })).into_response();
    }
    let status = StatusCode::from_u16(status.unwrap_or(200)).unwrap();
    match retry_after {
        Some(secs) => (status, [(header::RETRY_AFTER, secs.to_string())]).into_response(),
        None => status.into_response(),
    }
}

/// A receiver on `127.0.0.1:<port>/hook`; returns it and its URL.
async fn receiver() -> (Receiver, String) {
    let r = Receiver::default();
    let app = Router::new().route("/hook", post(receive)).with_state(r.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (r, format!("http://127.0.0.1:{port}/hook"))
}

struct Bot {
    app_id: String,
    user_id: String,
}

/// Alice owns a plaintext room and an application whose bot (with `scopes`) is a member of it.
async fn setup(node: &TestNode, scopes: Value) -> (Session, Session, Value, Bot) {
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Events").await;
    let room_id = room["id"].as_str().unwrap();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let (s, app) =
        node.post("/api/v1/applications", &alice.token, json!({ "name": "Watcher", "scopes": scopes })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (s, t) =
        node.post(&format!("/api/v1/applications/{app_id}/tokens"), &alice.token, json!({ "name": "t" })).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    // Bots enter rooms only through an installation (APPLICATIONS.md §4.2).
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &alice.token,
            json!({ "application": format!("{D}/{app_id}"), "permissions": "0", "create_role": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let _ = t["secret"].as_str().unwrap();
    let user_id = app["bot"]["id"].as_str().unwrap().to_string();
    (alice, bob, room, Bot { app_id, user_id })
}

async fn subscribe(node: &TestNode, owner: &Session, bot: &Bot, url: &str, events: &[&str]) -> (StatusCode, Value) {
    node.put(
        &format!("/api/v1/applications/{}/subscriptions", bot.app_id),
        &owner.token,
        json!({ "url": url, "events": events }),
    )
    .await
}

async fn outbox(node: &TestNode, bot: &Bot) -> Vec<store::subscriptions::OutboxRow> {
    store::subscriptions::outbox_of(&node.state.db, &bot.app_id).await.unwrap()
}

async fn deliver_at(node: &TestNode, secs: i64) -> subscriptions::DeliveryReport {
    subscriptions::deliver_due(&node.state, Utc::now() + chrono::Duration::seconds(secs)).await.unwrap()
}

/// Verifies a hook token like an application does (with the node's key).
fn check_signature(node: &TestNode, app_id: &str, url: &str, got: &Received) -> HookClaims {
    let token = got.headers.get("tavrn-signature").unwrap().to_str().unwrap();
    let kid = jwt::peek_kid(token).unwrap();
    let key = node.state.keys.iter().find(|k| k.kid == kid).unwrap();
    let expected = jwt::Expected { iss: D.into(), aud: format!("app:{app_id}"), typ: "hook" };
    let (std, claims): (_, HookClaims) = jwt::verify(token, &key.verifying(), &expected).unwrap();
    assert_eq!(std.sub, D);
    assert!(std.exp - std.iat <= 300);
    assert_eq!(claims.htu, url);
    assert_eq!(claims.body_sha256, tavrn_node::federation::tokens::body_sha256(&got.raw));
    let ua = got.headers.get("user-agent").unwrap().to_str().unwrap();
    assert!(ua.starts_with("tavrn-node/") && ua.contains(&format!("+https://{D}")), "{ua}");
    claims
}

#[tokio::test]
async fn a_verified_subscription_receives_signed_events() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read", "members:read"])).await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (r, url) = receiver().await;

    let (s, sub) = subscribe(&node, &alice, &bot, &url, &["message.create", "message.delete", "member.join"]).await;
    assert_eq!(s, StatusCode::OK, "{sub}");
    assert_eq!(sub["state"], "active");
    assert_eq!(sub["events"], json!(["member.join", "message.create", "message.delete"]));
    assert_eq!((sub["queued"].clone(), sub["dropped"].clone()), (json!(0), json!(0)));
    // The URL was verified with a signed ping.
    let pings = r.pings();
    assert_eq!(pings.len(), 1);
    assert_eq!(pings[0].headers.get("tavrn-event-type").unwrap(), "ping");
    check_signature(&node, &bot.app_id, &url, &pings[0]);

    // A message is queued in the request that created it and delivered by the worker.
    let (s, m) = node.send(&bob.token, room_id, &channel, "hello bots").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let queued = outbox(&node, &bot).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].event_type, "message.create");
    let report = deliver_at(&node, 0).await;
    assert_eq!(report.delivered, 1, "{report:?}");
    let events = r.events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.body["type"], "message.create");
    assert_eq!(e.body["application_id"], bot.app_id);
    assert_eq!(e.body["room_id"], room_id);
    assert_eq!(e.body["data"]["content"]["body"], "hello bots");
    assert_eq!(e.headers.get("tavrn-event-type").unwrap(), "message.create");
    assert_eq!(e.headers.get("tavrn-event-id").unwrap().to_str().unwrap(), e.body["id"].as_str().unwrap());
    let first_jti = {
        let token = e.headers.get("tavrn-signature").unwrap().to_str().unwrap();
        check_signature(&node, &bot.app_id, &url, e);
        token.to_string()
    };
    assert!(outbox(&node, &bot).await.is_empty());
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert!(sub["last_success_at"].is_string(), "{sub}");

    // Webhook messages and deletions too; unsubscribed types are not queued.
    let (_, hook) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels/{channel}/webhooks"), &alice.token, json!({ "name": "CI" }))
        .await;
    let hook_url = hook["url"].as_str().unwrap();
    let (s, _) = node
        .req(
            axum::http::Method::POST,
            &hook_url[hook_url.find("/api/v1/").unwrap()..],
            None,
            Some(json!({ "content": { "type": "text", "body": "from ci" } })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/messages/{}", m["id"].as_str().unwrap()),
            &bob.token,
            json!({ "content": { "type": "text", "body": "edited" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node
        .delete(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/messages/{}", m["id"].as_str().unwrap()),
            &bob.token,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let types: Vec<String> = outbox(&node, &bot).await.iter().map(|o| o.event_type.clone()).collect();
    assert_eq!(types, vec!["message.create", "message.delete"], "message.update is not subscribed");
    deliver_at(&node, 0).await;
    let events = r.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[1].body["data"]["webhook"]["name"], "CI");
    assert_eq!(events[1].body["data"]["author_kind"], "webhook");
    // Every attempt has its own token.
    assert!(events.iter().skip(1).all(|e| e.headers.get("tavrn-signature").unwrap() != first_jti.as_str()));

    // A new member is announced (members:read).
    let carol = node.register("carol").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    deliver_at(&node, 0).await;
    let last = r.events().pop().unwrap();
    assert_eq!(last.body["type"], "member.join");
    assert_eq!(last.body["data"]["user"]["username"], "carol");

    // Deleting the subscription stops everything.
    let (s, _) = node.delete(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    node.send(&bob.token, room_id, &channel, "nobody listens").await;
    assert!(outbox(&node, &bot).await.is_empty());
    let (s, j) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "subscription.not_found"));
}

#[tokio::test]
async fn encrypted_content_is_never_queued() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read", "members:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, url) = receiver().await;
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create", "message.update", "message.delete"]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, encrypted) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "name": "secret", "kind": "text" }))
        .await;
    let enc = encrypted["id"].as_str().unwrap();
    assert_eq!(encrypted["encrypted"], true);
    // Message events of an encrypted channel (as every route publishes them) and of DMs: nothing is queued.
    let cipher = json!({ "id": tavrn_node::util::ulid(), "conversation_id": enc, "encrypted": true, "content": "Y2lwaGVydGV4dA" });
    subscriptions::record(&node.state, &room_id, "message.create", "e1", &cipher).await;
    subscriptions::record(&node.state, &room_id, "message.update", "e2", &cipher).await;
    subscriptions::record(
        &node.state,
        &room_id,
        "message.delete",
        "e3",
        &json!({ "room_id": room_id, "conversation_id": enc, "id": "m" }),
    )
    .await;
    // A plaintext envelope that names an encrypted channel is refused as well (the channel decides).
    let lying = json!({ "conversation_id": enc, "encrypted": false, "content": { "type": "text", "body": "x" } });
    subscriptions::record(&node.state, &room_id, "message.create", "e4", &lying).await;
    // Event types that are never subscribable.
    for kind in ["typing", "mls.commit", "ephemeral", "presence.update"] {
        subscriptions::record(&node.state, &room_id, kind, "e5", &json!({ "conversation_id": channel })).await;
    }
    assert!(outbox(&node, &bot).await.is_empty());

    // A plaintext message is queued; once the channel is encrypted, its later edits and deletions are not.
    let (_, m) = node.send(&bob.token, &room_id, &channel, "plain").await;
    assert_eq!(outbox(&node, &bot).await.len(), 1);
    let (s, _) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), &alice.token, json!({ "encrypted": true }))
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node
        .delete(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/messages/{}", m["id"].as_str().unwrap()),
            &bob.token,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rows = outbox(&node, &bot).await;
    assert_eq!(rows.len(), 1);
    assert!(rows.iter().all(|r| !r.body.contains("Y2lwaGVydGV4dA")));
}

#[tokio::test]
async fn only_what_the_bot_may_see_is_queued() {
    let node = test_node(D).await;
    // Without messages:read the application gets no message events at all.
    let (alice, bob, room, bot) = setup(&node, json!(["members:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, url) = receiver().await;
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create", "member.update"]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    node.send(&bob.token, &room_id, &channel, "invisible").await;
    assert!(outbox(&node, &bot).await.is_empty());

    // With messages:read: not from a "no bots" channel or a channel the bot cannot view.
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), &alice.token, json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::OK);
    node.send(&bob.token, &room_id, &channel, "no bots here").await;
    assert!(outbox(&node, &bot).await.is_empty());
    let (_, hidden) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "staff", "kind": "text", "encrypted": false }),
        )
        .await;
    let hidden_id = hidden["id"].as_str().unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": hidden_id, "subject_type": "member", "subject_id": bot.user_id,
                    "allow": "0", "deny": tavrn_node::permissions::VIEW_CHANNEL.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    node.send(&bob.token, &room_id, hidden_id, "staff only").await;
    assert!(outbox(&node, &bot).await.is_empty());
    let (_, open) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "open", "kind": "text", "encrypted": false }),
        )
        .await;
    node.send(&bob.token, &room_id, open["id"].as_str().unwrap(), "visible").await;
    assert_eq!(outbox(&node, &bot).await.len(), 1);
}

#[tokio::test]
async fn retries_follow_the_schedule_and_three_days_disable() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (r, url) = receiver().await;
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    r.set(|b| b.status = Some(503));
    node.send(&bob.token, &room_id, &channel, "retry me").await;
    let start = Utc::now();
    // 1 min, 5 min, 30 min, 2 h, 12 h, 12 h … (±10 %).
    let mut at = 0i64;
    for expected in [60, 300, 1800, 7200, 43_200, 43_200] {
        let report = deliver_at(&node, at).await;
        assert_eq!(report.retried, 1, "at +{at}s: {report:?}");
        let row = outbox(&node, &bot).await.pop().unwrap();
        let next = tavrn_node::util::parse_time(&row.next_at).unwrap();
        let delay = (next - (start + chrono::Duration::seconds(at))).num_seconds();
        let tolerance = expected / 10 + 2;
        assert!((delay - expected).abs() <= tolerance, "after +{at}s expected {expected}s, got {delay}s");
        assert_eq!(row.last_error.as_deref(), Some("status 503"));
        // Nothing is due before the next attempt.
        assert_eq!(deliver_at(&node, at + delay - (expected / 10) - 3).await, subscriptions::DeliveryReport::default());
        at += delay + 1;
    }
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!(sub["state"], "active", "{sub}");
    assert_eq!(sub["last_error"], "status 503");
    assert_eq!(sub["queued"], 1);

    // After 3 days the event is given up; without any success the subscription is disabled and the owner told.
    let mut events = node.state.hub.subscribe();
    let report = deliver_at(&node, 3 * 24 * 3600 + 60).await;
    assert_eq!((report.given_up, report.disabled), (1, 1), "{report:?}");
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!(sub["state"], "disabled", "{sub}");
    let mut told = false;
    while let Ok(e) = events.try_recv() {
        if e.kind == "application.subscription_disabled" {
            assert_eq!(e.data["application_id"], bot.app_id);
            assert!(matches!(&e.scope, tavrn_node::hub::Scope::Users(u) if u == &vec![alice.user_id.clone()]));
            told = true;
        }
    }
    assert!(told);
    // Disabled: nothing is queued any more.
    node.send(&bob.token, &room_id, &channel, "into the void").await;
    assert!(outbox(&node, &bot).await.is_empty());

    // Re-enabling verifies again.
    r.set(|b| b.bad_ping = true);
    let enable = format!("/api/v1/applications/{}/subscriptions/enable", bot.app_id);
    let (s, j) = node.post(&enable, &alice.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_verification_failed"));
    r.set(|b| {
        b.bad_ping = false;
        b.status = None;
    });
    let (s, j) = node.post(&enable, &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["state"], "active");
    node.send(&bob.token, &room_id, &channel, "back").await;
    assert_eq!(deliver_at(&node, 0).await.delivered, 1);
}

#[tokio::test]
async fn final_errors_and_retry_after() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (r, url) = receiver().await;
    subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    // Retry-After is honoured when it is longer than the schedule.
    r.set(|b| {
        b.status = Some(429);
        b.retry_after = Some(3600);
    });
    node.send(&bob.token, &room_id, &channel, "later").await;
    deliver_at(&node, 0).await;
    let row = outbox(&node, &bot).await.pop().unwrap();
    let delay = (tavrn_node::util::parse_time(&row.next_at).unwrap() - Utc::now()).num_seconds();
    assert!((3590..=3610).contains(&delay), "{delay}");
    // A 4xx other than 408/429 is final: the event is given up, the subscription is failing.
    r.set(|b| {
        b.status = Some(410);
        b.retry_after = None;
    });
    let report = deliver_at(&node, 3601).await;
    assert_eq!(report.given_up, 1, "{report:?}");
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!((sub["state"].as_str(), sub["last_error"].as_str()), (Some("failing"), Some("status 410")));
    // A success makes it active again.
    r.set(|b| b.status = None);
    node.send(&bob.token, &room_id, &channel, "ok").await;
    assert_eq!(deliver_at(&node, 0).await.delivered, 1);
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!(sub["state"], "active");
}

#[tokio::test]
async fn at_most_four_requests_per_application_and_a_bounded_queue() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read"])).await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (r, url) = receiver().await;
    subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    r.set(|b| b.delay_ms = 200);
    for i in 0..9 {
        // Bob is not rate-limited in development mode.
        let (s, j) = node.send(&bob.token, &room_id, &channel, &format!("m{i}")).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    let report = deliver_at(&node, 0).await;
    assert_eq!(report.delivered, 9, "{report:?}");
    let max = r.max_active.load(Ordering::SeqCst);
    assert!((2..=4).contains(&max), "concurrency {max}");

    // The queue keeps at most `cap` events; the oldest are dropped and counted.
    for i in 0..5 {
        let hook = store::subscriptions::NewHook {
            application_id: &bot.app_id,
            event_id: &format!("e{i}"),
            event_type: "message.create",
            body: "{}",
            next_at: "9999-01-01T00:00:00.000Z",
            expires_at: "9999-01-02T00:00:00.000Z",
        };
        store::subscriptions::enqueue(&node.state.db, hook, 3).await.unwrap();
    }
    let rows = outbox(&node, &bot).await;
    assert_eq!(rows.iter().map(|r| r.event_id.as_str()).collect::<Vec<_>>(), vec!["e2", "e3", "e4"]);
    let (_, sub) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &alice.token).await;
    assert_eq!((sub["queued"].clone(), sub["dropped"].clone()), (json!(3), json!(2)));
    assert_eq!(subscriptions::MAX_QUEUE, 10_000);
}

/// Resolves every name to one address (a DNS rebinding pattern: a public-looking name with a private address).
struct FakeDns(HashMap<String, Vec<IpAddr>>);

impl Lookup for FakeDns {
    fn lookup(&self, host: String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> {
        let r = self.0.get(&host).cloned().ok_or_else(|| std::io::Error::other("NXDOMAIN"));
        Box::pin(async move { r })
    }
}

#[tokio::test]
async fn private_targets_redirects_and_bad_urls_are_refused() {
    let mut node = test_node_with(D, |c| c.app_allow_private_urls = false).await;
    let mut state = node.state.clone();
    let dns = HashMap::from([
        ("rebind.example".to_string(), vec!["10.0.0.7".parse().unwrap()]),
        ("mixed.example".to_string(), vec!["93.184.216.34".parse().unwrap(), "127.0.0.1".parse().unwrap()]),
    ]);
    state.hooks = Arc::new(HookClient::new(&state.config, Arc::new(FakeDns(dns))).unwrap());
    node.router = tavrn_node::app::router(state.clone());
    node.state = state;
    let (alice, _, _, bot) = setup(&node, json!(["messages:read"])).await;
    let (r, url) = receiver().await;
    let port = url.split(':').nth(2).unwrap().split('/').next().unwrap().to_string();
    for target in [
        url.clone(),
        format!("http://localhost:{port}/hook"),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        format!("http://[::1]:{port}/hook"),
        format!("http://[::ffff:127.0.0.1]:{port}/hook"),
        format!("http://rebind.example:{port}/hook"),
        format!("http://mixed.example:{port}/hook"),
        "https://10.1.2.3/hook".to_string(),
    ] {
        let (s, j) = subscribe(&node, &alice, &bot, &target, &["message.create"]).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_verification_failed"), "{target}: {j}");
    }
    assert!(r.pings().is_empty(), "no request reached the private receiver");
    for target in
        ["ftp://bot.example/hook", "https://user:pw@bot.example/hook", "https://bot.example/hook#frag", "not a url"]
    {
        let (s, j) = subscribe(&node, &alice, &bot, target, &["message.create"]).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_invalid"), "{target}");
    }
    let (s, j) = subscribe(&node, &alice, &bot, "https://bot.example/hook", &["mls.commit"]).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "subscription.event_invalid"));
}

#[tokio::test]
async fn a_transfer_drops_the_previous_owners_subscription() {
    let node = test_node(D).await;
    let (alice, bob, room, bot) = setup(&node, json!(["messages:read"])).await;
    let (_, url) = receiver().await;
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    node.send(&bob.token, room["id"].as_str().unwrap(), &TestNode::text_channel(&room), "queued").await;
    assert_eq!(outbox(&node, &bot).await.len(), 1);
    let (s, j) =
        node.post(&format!("/api/v1/applications/{}/transfer", bot.app_id), &alice.token, json!({ "to": "bob" })).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
    let (s, j) =
        node.post(&format!("/api/v1/applications/{}/transfer/accept", bot.app_id), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/applications/{}/subscriptions", bot.app_id), &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "subscription.not_found"));
    assert!(outbox(&node, &bot).await.is_empty());
}

#[tokio::test]
async fn redirects_and_wrong_challenges_fail_verification() {
    let node = test_node(D).await;
    let (alice, _, _, bot) = setup(&node, json!(["messages:read"])).await;
    let (target, target_url) = receiver().await;
    let (r, url) = receiver().await;
    // A redirect (here even to another local receiver) is never followed.
    r.set(|b| b.redirect_to = Some(target_url.clone()));
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_verification_failed"));
    assert_eq!(r.got.lock().unwrap().len(), 1);
    assert!(target.got.lock().unwrap().is_empty(), "the redirect target was contacted");
    // A URL that does not echo the challenge (a third party's server) is refused.
    r.set(|b| {
        b.redirect_to = None;
        b.bad_ping = true;
    });
    let (s, j) = subscribe(&node, &alice, &bot, &url, &["message.create"]).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_verification_failed"));
    // Only the owner configures it.
    let eve = node.register("eve").await;
    let (s, j) = subscribe(&node, &eve, &bot, &url, &["message.create"]).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
}
