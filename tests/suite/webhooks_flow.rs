// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 5 step 4 (protocol/APPLICATIONS.md §6.1, §6.4): incoming webhooks, their pseudo users, the envelope field
//! `webhook`, embeds, sealing modes across the encryption switch, limits, moderation and permissions (the sealed
//! posts themselves: `sealed_webhooks_flow.rs`).

use crate::common;

use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, federation, perms, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const D: &str = "t.local";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

struct Room {
    id: String,
    channel: String,
}

/// Alice owns a room whose text channel is unencrypted; Bob is a plain member.
async fn setup(node: &TestNode) -> (Session, Session, Room) {
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Hooks").await;
    let id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    (alice, bob, Room { id, channel })
}

/// Creates a webhook; returns (webhook, execution path without the origin).
async fn create(node: &TestNode, token: &str, room: &Room, body: Value) -> (Value, String) {
    let (s, j) = node.post(&format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel), token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let url = j["url"].as_str().unwrap();
    let path = url[url.find("/api/v1/").unwrap()..].to_string();
    (j["webhook"].clone(), path)
}

/// Posts a payload to an execution path (no authentication).
async fn exec(node: &TestNode, path: &str, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, path, None, Some(body)).await
}

async fn exec_raw(node: &TestNode, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
    let request = axum::http::Request::post(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = tower::ServiceExt::oneshot(node.router.clone(), request).await.unwrap();
    let status = resp.status();
    let bytes = common::body_bytes(resp).await;
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn text(body: &str) -> Value {
    json!({ "content": { "type": "text", "body": body } })
}

async fn messages(node: &TestNode, token: &str, room: &Room) -> Vec<Value> {
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{}/channels/{}/messages", room.id, room.channel), token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j.as_array().unwrap().clone()
}

async fn audit_actions(node: &TestNode, token: &str, room_id: &str) -> Vec<Value> {
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j.as_array().unwrap().clone()
}

#[tokio::test]
async fn a_webhook_posts_plaintext_messages_with_its_envelope() {
    let node = test_node(D).await;
    let (alice, bob, room) = setup(&node).await;
    let (webhook, path) = create(&node, &alice.token, &room, json!({ "name": "Deploys" })).await;
    let id = webhook["id"].as_str().unwrap();
    assert_eq!(webhook["name"], "Deploys");
    assert_eq!(webhook["suspended"], false);
    assert_eq!(webhook["user"]["kind"], "webhook");
    assert_eq!(webhook["user"]["username"], format!("wh.{}", id.to_lowercase()));
    assert_eq!(webhook["user"]["owner"], format!("alice@{D}"));
    assert_eq!(webhook["created_by"], format!("alice@{D}"));
    assert!(path.starts_with(&format!("/api/v1/webhooks/{id}/")), "{path}");
    let secret = path.rsplit('/').next().unwrap();
    assert_eq!(secret.len(), 43, "32 bytes base64url");
    // The secret is never shown again.
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{}/webhooks", room.id), &alice.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(secret));

    // Without `wait`: 204; with `wait=true`: the message with the webhook envelope.
    let (s, j) = exec(&node, &path, text("plain")).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let embed = json!({ "title": "Build #128", "description": "All **42** tests passed", "url": "https://ci.example/b/128",
        "color": 3066993, "fields": [ { "name": "Branch", "value": "main", "inline": true } ],
        "footer": "ci.example", "timestamp": "2026-10-05T12:00:00Z" });
    let (s, m) = exec(
        &node,
        &format!("{path}?wait=true"),
        json!({ "content": { "type": "text", "body": "", "embeds": [embed] }, "username": "CI" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["author_kind"], "webhook");
    assert_eq!(m["author"], format!("wh.{}@{D}", id.to_lowercase()));
    assert_eq!(m["webhook"], json!({ "id": id, "name": "CI" }));
    assert_eq!(m["device_id"], Value::Null);
    assert_eq!(m["signature"], Value::Null);
    assert_eq!(m["encrypted"], false);
    assert_eq!(m["content"]["embeds"][0]["fields"][0]["name"], "Branch");
    // Every member reads them; ordinary messages carry no `webhook` field.
    node.send(&bob.token, &room.id, &room.channel, "human").await;
    let list = messages(&node, &bob.token, &room).await;
    let plain = list.iter().find(|m| m["content"]["body"] == "plain").unwrap();
    assert_eq!(plain["webhook"], json!({ "id": id, "name": "Deploys" }));
    let human = list.iter().find(|m| m["content"]["body"] == "human").unwrap();
    assert!(human.get("webhook").is_none(), "{human}");
    // The node announces the capability.
    let (_, info) = node.get_auth("/api/v1/node", &alice.token).await;
    assert!(info["capabilities"].as_array().unwrap().iter().any(|c| c == "webhooks.v1"), "{info}");
    // Audited without the secret.
    let log = audit_actions(&node, &alice.token, &room.id).await;
    let entry = log.iter().find(|e| e["action"] == "webhook.create").unwrap();
    assert_eq!(entry["meta"]["webhook_id"], id);
    assert_eq!(entry["meta"]["channel_id"], room.channel);
    assert!(!log.iter().any(|e| e.to_string().contains(secret)));
}

#[tokio::test]
async fn unknown_ids_and_wrong_secrets_look_the_same() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let (webhook, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let id = webhook["id"].as_str().unwrap();
    let (good_secret, unknown) = (path.rsplit('/').next().unwrap().to_string(), util_ulid());
    let cases = [
        format!("/api/v1/webhooks/{id}/{}", "A".repeat(43)),
        format!("/api/v1/webhooks/{id}/{}", &good_secret[..42]),
        format!("/api/v1/webhooks/{unknown}/{good_secret}"),
        format!("/api/v1/webhooks/not-an-id/{good_secret}"),
        format!("/api/v1/webhooks/{}/{good_secret}", id.to_lowercase()),
    ];
    let mut answers = Vec::new();
    for c in &cases {
        let (s, j) = exec(&node, c, text("x")).await;
        assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "webhook.not_found"), "{c}");
        answers.push((j["detail"].clone(), j["title"].clone()));
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "identical answers: {answers:?}");
    // Same timing class: an existing id with a wrong secret and an unknown id do the same work.
    let median = |mut v: Vec<Duration>| {
        v.sort();
        v[v.len() / 2]
    };
    let mut wrong = Vec::new();
    let mut missing = Vec::new();
    for _ in 0..15 {
        let t = Instant::now();
        exec(&node, &cases[0], text("x")).await;
        wrong.push(t.elapsed());
        let t = Instant::now();
        exec(&node, &cases[2], text("x")).await;
        missing.push(t.elapsed());
    }
    let (a, b) = (median(wrong), median(missing));
    assert!(a.abs_diff(b) < Duration::from_millis(25), "wrong secret {a:?} vs unknown id {b:?}");

    // Reset: the old URL stops working at once, the new one works.
    let (s, j) = node.post(&format!("/api/v1/rooms/{}/webhooks/{id}/reset", room.id), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let new_url = j["url"].as_str().unwrap();
    let new_path = &new_url[new_url.find("/api/v1/").unwrap()..];
    assert_ne!(new_path, path);
    assert_eq!(exec(&node, &path, text("old")).await.0, StatusCode::NOT_FOUND);
    assert_eq!(exec(&node, new_path, text("new")).await.0, StatusCode::NO_CONTENT);
    assert!(audit_actions(&node, &alice.token, &room.id).await.iter().any(|e| e["action"] == "webhook.reset"));
}

fn util_ulid() -> String {
    tavrn_node::util::ulid()
}

#[tokio::test]
async fn webhooks_in_encrypted_channels_are_sealed_and_survive_the_switch() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    // A new channel is encrypted by default: webhooks there are sealed, by the sender unless asked otherwise.
    let (s, enc) = node
        .post(&format!("/api/v1/rooms/{}/channels", room.id), &alice.token, json!({ "name": "secret", "kind": "text" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{enc}");
    assert_eq!((enc["encrypted"].clone(), enc["has_webhooks"].clone()), (json!(true), json!(false)));
    let enc_hooks = format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, enc["id"].as_str().unwrap());
    let (s, j) = node.post(&enc_hooks, &alice.token, json!({ "name": "Sealed" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!((j["webhook"]["sealing"].clone(), j["webhook"]["pending_key"].clone()), (json!("sender"), json!(true)));
    let (s, j) = node.post(&enc_hooks, &alice.token, json!({ "name": "Node", "sealing": "node" })).await;
    assert_eq!((s, j["webhook"]["sealing"].clone()), (StatusCode::CREATED, json!("node")), "{j}");
    let (s, j) = node.post(&enc_hooks, &alice.token, json!({ "name": "Bad", "sealing": "nobody" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "webhook.sealing_invalid"));
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{}", room.id), &alice.token).await;
    let ch = detail["channels"].as_array().unwrap().iter().find(|c| c["id"] == enc["id"]).unwrap().clone();
    assert_eq!(ch["has_webhooks"], true);
    // Plaintext channels know no sealing.
    let plain_hooks = format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel);
    let (s, j) = node.post(&plain_hooks, &alice.token, json!({ "name": "Bad", "sealing": "sender" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "webhook.sealing_invalid"));

    let (webhook, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    assert_eq!((webhook["sealing"].clone(), webhook["pending_key"].clone()), (Value::Null, json!(false)));
    let id = webhook["id"].as_str().unwrap();
    let channel_path = format!("/api/v1/rooms/{}/channels/{}", room.id, room.channel);
    let (s, j) = node.patch(&channel_path, &alice.token, json!({ "encrypted": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The switch keeps the webhook: sealed by the sender and waiting until a member publishes the inbox key.
    let mine = |list: &Value| list.as_array().unwrap().iter().find(|w| w["id"] == id).unwrap().clone();
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{}/webhooks", room.id), &alice.token).await;
    let w = mine(&list);
    assert_eq!(
        (w["sealing"].clone(), w["pending_key"].clone(), w["suspended"].clone()),
        (json!("sender"), json!(true), json!(false))
    );
    let (s, j) = exec(&node, &path, text("while encrypted")).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "webhook.pending_key"));
    let log = audit_actions(&node, &alice.token, &room.id).await;
    let entry = log.iter().find(|e| e["action"] == "webhook.update" && e["meta"]["webhook_id"] == id).unwrap();
    assert_eq!(
        (entry["meta"]["sealing"].clone(), entry["meta"]["changed"].clone()),
        (json!("sender"), json!(["sealing"]))
    );
    // The mode can be changed while the channel is encrypted.
    let hook = format!("/api/v1/rooms/{}/webhooks/{id}", room.id);
    let (s, j) = node.patch(&hook, &alice.token, json!({ "sealing": "node" })).await;
    assert_eq!((s, j["sealing"].clone()), (StatusCode::OK, json!("node")), "{j}");

    // Switched back: plaintext again.
    let (s, _) = node.patch(&channel_path, &alice.token, json!({ "encrypted": false })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{}/webhooks", room.id), &alice.token).await;
    assert_eq!((mine(&list)["sealing"].clone(), mine(&list)["pending_key"].clone()), (Value::Null, json!(false)));
    assert_eq!(exec(&node, &path, text("back")).await.0, StatusCode::NO_CONTENT);
    let (s, j) = node.patch(&hook, &alice.token, json!({ "sealing": "node" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "webhook.sealing_invalid"));

    // Moving it into the encrypted channel seals it; a voice channel is refused; deleting its channel deletes it.
    let (s, j) = node.patch(&hook, &alice.token, json!({ "channel_id": enc["id"] })).await;
    assert_eq!((s, j["sealing"].clone()), (StatusCode::OK, json!("sender")), "{j}");
    let (s, j) = node.patch(&hook, &alice.token, json!({ "channel_id": room.channel })).await;
    assert_eq!((s, j["sealing"].clone()), (StatusCode::OK, Value::Null), "{j}");
    let (_, voice) = node
        .post(&format!("/api/v1/rooms/{}/channels", room.id), &alice.token, json!({ "name": "talk", "kind": "voice" }))
        .await;
    let (s, j) = node.patch(&hook, &alice.token, json!({ "channel_id": voice["id"] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "channel.no_text"));
    let (s, plain) = node
        .post(
            &format!("/api/v1/rooms/{}/channels", room.id),
            &alice.token,
            json!({ "name": "news", "kind": "text", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{plain}");
    let (s, j) = node.patch(&hook, &alice.token, json!({ "channel_id": plain["id"], "name": "Builds" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["channel_id"].clone(), j["name"].clone()), (plain["id"].clone(), json!("Builds")));
    assert_eq!(j["user"]["display_name"], "Builds");
    let (s, _) = node
        .delete(&format!("/api/v1/rooms/{}/channels/{}", room.id, plain["id"].as_str().unwrap()), &alice.token)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{}/webhooks", room.id), &alice.token).await;
    assert!(list.as_array().unwrap().iter().all(|w| w["id"] != id), "{list}");
    assert_eq!(exec(&node, &path, text("gone")).await.0, StatusCode::NOT_FOUND);
}

/// A node whose webhook rate limits do not get in the way of tests that send many payloads.
async fn unthrottled() -> TestNode {
    let mut node = test_node(D).await;
    let mut state = node.state.clone();
    let cluster = state.cluster.clone();
    let many = || {
        std::sync::Arc::new(tavrn_node::cache::limiter::SharedLimiter::new(
            "test",
            10_000,
            Duration::from_secs(60),
            &cluster,
        ))
    };
    state.webhook_burst_limiter = many();
    state.webhook_minute_limiter = many();
    node.router = tavrn_node::app::router(state.clone());
    node.state = state;
    node
}

#[tokio::test]
async fn payloads_are_checked() {
    let node = unthrottled().await;
    let (alice, bob, room) = setup(&node).await;
    let (_, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    // 32 KiB at most.
    let big = json!({ "content": { "type": "text", "body": "x".repeat(33 * 1024) } }).to_string().into_bytes();
    let (s, j) = exec_raw(&node, &path, big).await;
    assert_eq!((s, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, "webhook.too_large"));
    for (body, expected) in [
        (b"{not json".to_vec(), "webhook.payload_invalid"),
        (b"[]".to_vec(), "webhook.payload_invalid"),
        (json!({ "content": { "type": "text", "body": "x" }, "attachments": ["01J"] }).to_string().into_bytes(), "webhook.payload_invalid"),
        (json!({ "content": { "type": "action", "body": "x" } }).to_string().into_bytes(), "webhook.payload_invalid"),
        (json!({ "content": "Y2lwaGVy" }).to_string().into_bytes(), "webhook.payload_invalid"),
        (json!({ "content": { "type": "text", "body": "" } }).to_string().into_bytes(), "message.body_length"),
        (json!({ "content": { "type": "text", "body": "a".repeat(4001) } }).to_string().into_bytes(), "message.body_length"),
        (
            json!({ "content": { "type": "text", "body": "x", "embeds": [{ "title": "x", "url": "http://insecure.example" }] } })
                .to_string()
                .into_bytes(),
            "message.embeds_invalid",
        ),
        (
            json!({ "content": { "type": "text", "body": "x", "embeds": vec![json!({ "title": "t" }); 11] } }).to_string().into_bytes(),
            "message.embeds_invalid",
        ),
    ] {
        let (s, j) = exec_raw(&node, &path, body.clone()).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, expected), "{}", String::from_utf8_lossy(&body));
    }
    for username in ["", "a@b", "#ops", "x:y", "everyone", "HERE", &"n".repeat(33)] {
        let (s, j) =
            exec(&node, &path, json!({ "content": { "type": "text", "body": "x" }, "username": username })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "webhook.username_invalid"), "{username:?}");
    }
    // Mentions: members stay, everybody else is dropped.
    let carol = node.register("carol").await;
    let (s, m) = exec(
        &node,
        &format!("{path}?wait=true"),
        json!({ "content": { "type": "text", "body": "hi" }, "mentions": [format!("BOB@{D}"), format!("carol@{D}"), "ghost@far.example", format!("role:{}", util_ulid())] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["mentions"], json!([format!("bob@{D}")]));
    let _ = (bob, carol);
    // A reply needs a message of the same channel.
    let (s, j) =
        exec(&node, &path, json!({ "content": { "type": "text", "body": "x" }, "reply_to": util_ulid() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.reply_target_missing"));
    let (s, j) = exec(
        &node,
        &format!("{path}?wait=true"),
        json!({ "content": { "type": "text", "body": "re" }, "reply_to": m["id"] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["reply_to_id"], m["id"]);
}

#[tokio::test]
async fn everyone_mentions_need_the_flag_and_the_flag_needs_the_right() {
    let node = test_node(D).await;
    let (alice, bob, room) = setup(&node).await;
    // Bob may manage webhooks but not mention @everyone.
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{}/roles", room.id),
            &alice.token,
            json!({ "name": "Hooks", "permissions": perms(&[p::MANAGE_WEBHOOKS]), "position": 1 }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", room.id, bob.user_id),
            &alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel),
            &bob.token,
            json!({ "name": "Loud", "allow_mentions_everyone": true }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.mention_everyone_forbidden"));
    let (quiet, quiet_path) = create(&node, &bob.token, &room, json!({ "name": "Quiet" })).await;
    let everyone = json!({ "content": { "type": "text", "body": "@everyone" }, "mentions_everyone": true });
    let (s, j) = exec(&node, &quiet_path, everyone.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.mention_everyone_forbidden"));
    let hook = format!("/api/v1/rooms/{}/webhooks/{}", room.id, quiet["id"].as_str().unwrap());
    let (s, j) = node.patch(&hook, &bob.token, json!({ "allow_mentions_everyone": true })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.mention_everyone_forbidden"));
    // The owner may allow it.
    let (s, j) = node.patch(&hook, &alice.token, json!({ "allow_mentions_everyone": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, m) = exec(&node, &format!("{quiet_path}?wait=true"), everyone).await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(m["mentions_everyone"], true);
}

#[tokio::test]
async fn executions_are_rate_limited_per_webhook() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let (_, a) = create(&node, &alice.token, &room, json!({ "name": "A" })).await;
    let (_, b) = create(&node, &alice.token, &room, json!({ "name": "B" })).await;
    for i in 0..5 {
        assert_eq!(exec(&node, &a, text(&format!("{i}"))).await.0, StatusCode::NO_CONTENT, "{i}");
    }
    let (s, _) = exec(&node, &a, text("6th")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(exec(&node, &b, text("other webhook")).await.0, StatusCode::NO_CONTENT);
    // Wrong secrets never use up the webhook's budget.
    let (_, c) = create(&node, &alice.token, &room, json!({ "name": "C" })).await;
    let wrong = format!("{}/{}", c.rsplit_once('/').unwrap().0, "B".repeat(43));
    for _ in 0..10 {
        assert_eq!(exec(&node, &wrong, text("x")).await.0, StatusCode::NOT_FOUND);
    }
    assert_eq!(exec(&node, &c, text("still fine")).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_pseudo_user_is_in_no_member_list_and_receives_nothing() {
    let node = test_node(D).await;
    let (alice, bob, room) = setup(&node).await;
    let (webhook, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let username = webhook["user"]["username"].as_str().unwrap().to_string();
    let address = format!("{username}@{D}");
    assert_eq!(exec(&node, &path, text("hello")).await.0, StatusCode::NO_CONTENT);
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{}/members", room.id), &bob.token).await;
    assert!(!members.to_string().contains(&username), "{members}");
    assert_eq!(members.as_array().unwrap().len(), 2);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{}", room.id), &bob.token).await;
    assert!(!detail.to_string().contains(&username));
    let (_, presence) = node.get_auth("/api/v1/presence", &bob.token).await;
    assert!(!presence.to_string().contains(&username), "{presence}");
    // Admin user search (alice is the first account and thus node admin) and statistics skip it.
    let (s, users) = node.get_auth("/api/v1/admin/users?q=wh.", &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{users}");
    assert!(!users.to_string().contains(&username), "{users}");
    // Nobody can DM, befriend, block or invite it, nor register its name space.
    let (s, j) = node.post("/api/v1/conversations", &bob.token, json!({ "kind": "dm", "members": [address] })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "user.not_found"), "{j}");
    let (s, j) = node.post("/api/v1/users/me/friends/requests", &bob.token, json!({ "user": address })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{}/invites/direct", room.id), &alice.token, json!({ "user": address })).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    let (s, j) = node
        .req(
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({ "username": "wh.mine", "password": "password-123456" })),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "auth.username_taken"));
    let (s, j) =
        node.post("/api/v1/applications", &alice.token, json!({ "name": "Imposter", "username": "wh.bot" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.username_taken"));
    // It cannot sign in.
    let (s, _) = node
        .req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({ "username": username, "password": "irrelevant-123" })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Its public profile (name and avatar of message authors) shows the kind.
    let (s, profile) = node.get_auth(&format!("/api/v1/users/{address}/profile"), &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{profile}");
    assert_eq!(profile["kind"], "webhook");
}

#[tokio::test]
async fn webhook_messages_are_moderated_like_any_message() {
    let node = test_node(D).await;
    let (alice, bob, room) = setup(&node).await;
    let (webhook, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let author_id = webhook["user"]["id"].as_str().unwrap().to_string();
    let mut ids = Vec::new();
    for i in 0..4 {
        let (s, m) = exec(&node, &format!("{path}?wait=true"), text(&format!("m{i}"))).await;
        assert_eq!(s, StatusCode::OK, "{m}");
        ids.push(m["id"].as_str().unwrap().to_string());
    }
    let one = |id: &str| format!("/api/v1/rooms/{}/channels/{}/messages/{id}", room.id, room.channel);
    // Members without manage_messages cannot delete them; moderators can.
    let (s, j) = node.delete(&one(&ids[0]), &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.delete_forbidden"));
    let (s, _) = node.delete(&one(&ids[0]), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Nobody can edit them (not even the creator).
    let (s, _) = node.patch(&one(&ids[1]), &alice.token, json!({ "content": { "type": "text", "body": "x" } })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Purge by author.
    let purge = format!("/api/v1/rooms/{}/moderation/purge", room.id);
    let (s, preview) = node.post(&purge, &alice.token, json!({ "author_id": author_id })).await;
    assert_eq!(s, StatusCode::OK, "{preview}");
    assert_eq!(preview["messages"], 3, "{preview}");
    let (s, done) = node
        .post(&purge, &alice.token, json!({ "author_id": author_id, "confirm_token": preview["confirm_token"] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert!(messages(&node, &alice.token, &room).await.iter().all(|m| m["author_kind"] != "webhook"));
    // A deleted webhook leaves its messages (author: the disabled pseudo user).
    let (s, m) = exec(&node, &format!("{path}?wait=true"), text("last words")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = node
        .delete(&format!("/api/v1/rooms/{}/webhooks/{}", room.id, webhook["id"].as_str().unwrap()), &alice.token)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(exec(&node, &path, text("after")).await.0, StatusCode::NOT_FOUND);
    let list = messages(&node, &bob.token, &room).await;
    let kept = list.iter().find(|x| x["id"] == m["id"]).unwrap();
    assert_eq!(kept["webhook"]["name"], "CI");
    assert!(audit_actions(&node, &alice.token, &room.id).await.iter().any(|e| e["action"] == "webhook.delete"));
}

#[tokio::test]
async fn management_needs_manage_webhooks() {
    let node = test_node(D).await;
    let (alice, bob, room) = setup(&node).await;
    let (webhook, _) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let id = webhook["id"].as_str().unwrap();
    let base = format!("/api/v1/rooms/{}", room.id);
    let forbidden =
        |s: StatusCode, j: &Value| assert_eq!((s, code(j)), (StatusCode::FORBIDDEN, "webhook.manage_forbidden"), "{j}");
    let (s, j) = node.get_auth(&format!("{base}/channels/{}/webhooks", room.channel), &bob.token).await;
    forbidden(s, &j);
    let (s, j) =
        node.post(&format!("{base}/channels/{}/webhooks", room.channel), &bob.token, json!({ "name": "x" })).await;
    forbidden(s, &j);
    let (s, j) = node.get_auth(&format!("{base}/webhooks"), &bob.token).await;
    forbidden(s, &j);
    let (s, j) = node.patch(&format!("{base}/webhooks/{id}"), &bob.token, json!({ "name": "y" })).await;
    forbidden(s, &j);
    let (s, j) = node.post(&format!("{base}/webhooks/{id}/reset"), &bob.token, json!({})).await;
    forbidden(s, &j);
    let (s, j) = node.delete(&format!("{base}/webhooks/{id}/avatar"), &bob.token).await;
    forbidden(s, &j);
    let (s, j) = node.delete(&format!("{base}/webhooks/{id}"), &bob.token).await;
    forbidden(s, &j);
    // Non-members see nothing at all; a webhook of another room is not found.
    let eve = node.register("eve").await;
    let (s, _) = node.get_auth(&format!("{base}/webhooks"), &eve.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let other = node.plaintext_room(&eve.token, "Other").await;
    let (s, j) =
        node.delete(&format!("/api/v1/rooms/{}/webhooks/{id}", other["id"].as_str().unwrap()), &eve.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "webhook.not_found"));
    // A channel override can grant it for one channel.
    let (s, j) = node
        .put(
            &format!("{base}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": room.channel, "subject_type": "member", "subject_id": bob.user_id,
                    "allow": perms(&[p::MANAGE_WEBHOOKS]), "deny": "0" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) =
        node.post(&format!("{base}/channels/{}/webhooks", room.channel), &bob.token, json!({ "name": "Bob's" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.get_auth(&format!("{base}/webhooks"), &bob.token).await;
    forbidden(s, &j);
}

#[tokio::test]
async fn bot_tokens_need_the_scope_and_the_permission() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let mut bots = Vec::new();
    for (name, scopes) in [("NoScope", json!(["messages:read"])), ("WithScope", json!(["webhooks:manage"]))] {
        let (s, app) = node.post("/api/v1/applications", &alice.token, json!({ "name": name })).await;
        assert_eq!(s, StatusCode::CREATED, "{app}");
        let app_id = app["id"].as_str().unwrap();
        let (s, t) = node
            .post(
                &format!("/api/v1/applications/{app_id}/tokens"),
                &alice.token,
                json!({ "name": "t", "scopes": scopes }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{t}");
        let secret = t["secret"].as_str().unwrap().to_string();
        // Bots enter rooms only through an installation (APPLICATIONS.md §4.2).
        let (s, j) = node
            .post(
                &format!("/api/v1/rooms/{}/applications", room.id),
                &alice.token,
                json!({ "application": format!("{D}/{app_id}"), "permissions": "0", "create_role": false }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        bots.push((secret, app["bot"]["id"].as_str().unwrap().to_string()));
    }
    let create_path = format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel);
    let (s, j) = node.post(&create_path, &bots[0].0, json!({ "name": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    assert_eq!(j["meta"]["scope"], "webhooks:manage");
    // The scope alone is not enough: the room must grant manage_webhooks.
    let (s, j) = node.post(&create_path, &bots[1].0, json!({ "name": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "webhook.manage_forbidden"));
    let (_, role) = node
        .post(
            &format!("/api/v1/rooms/{}/roles", room.id),
            &alice.token,
            json!({ "name": "Hooks", "permissions": perms(&[p::VIEW_CHANNEL, p::MANAGE_WEBHOOKS]), "position": 1 }),
        )
        .await;
    for (_, bot_id) in &bots {
        let (s, j) = node
            .patch(
                &format!("/api/v1/rooms/{}/members/{bot_id}", room.id),
                &alice.token,
                json!({ "roles": [role["id"]] }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    let (s, j) = node.post(&create_path, &bots[0].0, json!({ "name": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let (s, j) = node.post(&create_path, &bots[1].0, json!({ "name": "Bot hook" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // Bots never reach the subscription routes of their application.
    let (_, apps) = node.get_auth("/api/v1/applications", &alice.token).await;
    let app_id = apps[0]["id"].as_str().unwrap();
    let (s, j) = node.get_auth(&format!("/api/v1/applications/{app_id}/subscriptions"), &bots[1].0).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
}

#[tokio::test]
async fn remote_users_need_the_permission_too() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Remote").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let remote = b.sign_in_from(&a, &alice).await;
    let (_, invite) = b.post(&format!("/api/v1/rooms/{room_id}/invites"), &carol.token, json!({})).await;
    let (s, j) =
        b.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel}/webhooks");
    let (s, j) = b.post(&path, &remote.token, json!({ "name": "x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "webhook.manage_forbidden"));
    let (s, j) = b.get_auth(&format!("/api/v1/rooms/{room_id}/webhooks"), &remote.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "webhook.manage_forbidden"));
    // Subscriptions are owner routes of the home node.
    let (s, j) = b.get_auth(&format!("/api/v1/applications/{}/subscriptions", util_ulid()), &remote.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"));
}

#[tokio::test]
async fn limits_per_channel_and_room() {
    let node = test_node_with(D, |c| c.webhooks_per_channel = 2).await;
    let (alice, _, room) = setup(&node).await;
    create(&node, &alice.token, &room, json!({ "name": "1" })).await;
    create(&node, &alice.token, &room, json!({ "name": "2" })).await;
    let path = format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel);
    let (s, j) = node.post(&path, &alice.token, json!({ "name": "3" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "webhook.limit"));
    assert_eq!(j["meta"]["max"], 2);
    for name in ["", "   ", &"n".repeat(33)] {
        let (s, j) = node.post(&path, &alice.token, json!({ "name": name })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{name:?}: {j}");
    }

    // 50 per room, whatever the channels.
    let node = test_node_with(D, |c| c.webhooks_per_channel = 50).await;
    let (alice, _, room) = setup(&node).await;
    for i in 0..50 {
        create(&node, &alice.token, &room, json!({ "name": format!("h{i}") })).await;
    }
    let (_, other) = node
        .post(
            &format!("/api/v1/rooms/{}/channels", room.id),
            &alice.token,
            json!({ "name": "more", "kind": "text", "encrypted": false }),
        )
        .await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, other["id"].as_str().unwrap()),
            &alice.token,
            json!({ "name": "51" }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "webhook.limit"));
    assert_eq!(j["meta"]["max"], 50);
}

#[tokio::test]
async fn switched_off_webhooks_refuse_everything() {
    let on = test_node(D).await;
    let (alice, _, room) = setup(&on).await;
    let (_, path) = create(&on, &alice.token, &room, json!({ "name": "CI" })).await;
    let off = test_node_with(D, |c| c.webhooks_enabled = false).await;
    let (alice, _, room) = setup(&off).await;
    let (s, j) = off
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/webhooks", room.id, room.channel),
            &alice.token,
            json!({ "name": "x" }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "webhook.disabled"));
    let (s, j) = exec(&off, &path, text("x")).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "webhook.disabled"));
    let (_, info) = off.get_auth("/api/v1/node", &alice.token).await;
    assert!(!info["capabilities"].as_array().unwrap().iter().any(|c| c == "webhooks.v1"));
}

#[tokio::test]
async fn no_bots_zones_do_not_block_webhooks() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let (_, path) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", room.id, room.channel),
            &alice.token,
            json!({ "no_bots": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(exec(&node, &path, text("still here")).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn embeds_from_users_and_bots_follow_the_same_rules() {
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let send = |content: Value| {
        let node = &node;
        let (token, room) = (alice.token.clone(), &room);
        async move {
            node.post(
                &format!("/api/v1/rooms/{}/channels/{}/messages", room.id, room.channel),
                &token,
                json!({ "content": content }),
            )
            .await
        }
    };
    let (s, m) = send(json!({ "type": "text", "body": "", "embeds": [{ "title": "Card", "color": 255 }] })).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["content"]["embeds"][0]["title"], "Card");
    let (s, j) =
        send(json!({ "type": "text", "body": "x", "embeds": [{ "title": "x", "description": "d".repeat(4097) }] }))
            .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.embeds_invalid"));
    let (s, j) =
        send(json!({ "type": "text", "body": "x", "embeds": [{ "title": "x", "url": "https://u:p@evil.example" }] }))
            .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.embeds_invalid"));
}

#[tokio::test]
async fn avatars_go_through_the_media_pipeline() {
    let Some(png) = png() else {
        eprintln!("ffmpeg not installed: skipped");
        return;
    };
    let node = test_node(D).await;
    let (alice, _, room) = setup(&node).await;
    let (webhook, _) = create(&node, &alice.token, &room, json!({ "name": "CI" })).await;
    let path = format!("/api/v1/rooms/{}/webhooks/{}/avatar", room.id, webhook["id"].as_str().unwrap());
    let (s, _, body) =
        node.raw(Method::PUT, &path, &alice.token, &[("content-type", "application/octet-stream")], png).await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["avatar_still"].as_str().unwrap().starts_with("/api/v1/media/"), "{j}");
    assert_eq!(j["user"]["avatar_still"], j["avatar_still"]);
    let (s, j) = node.delete(&path, &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["avatar"], Value::Null);
}

fn png() -> Option<Vec<u8>> {
    let path = std::env::var_os("PATH")?;
    let ffmpeg = std::env::split_paths(&path).map(|d| d.join("ffmpeg")).find(|p| p.is_file())?;
    let dir = tempfile::tempdir().ok()?;
    let out = dir.path().join("a.png");
    let ok = std::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x64:rate=1"])
        .args(["-frames:v", "1", "-f", "image2", "-c:v", "png"])
        .arg(&out)
        .status()
        .ok()?
        .success();
    if ok { std::fs::read(out).ok() } else { None }
}
