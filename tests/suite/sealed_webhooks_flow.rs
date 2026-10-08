// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Write-only webhooks in encrypted channels (APPLICATIONS.md §6.1a, ENCRYPTION.md §5b): publishing inbox keys,
//! sender- and node-sealed posts, pending keys, the epoch window, the encryption switch and moderation. The native
//! `tavrn_crypto` client plays the members.

use crate::common;

use axum::http::{Method, StatusCode};
use common::e2ee::{DOMAIN, Dev, b64, qualified, unb64};
use common::{Session, TestNode, federation, test_node};

use serde_json::{Value, json};
use tavrn_node::permissions as p;

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

struct Setup {
    node: TestNode,
    alice: Dev,
    room_id: String,
    channel: String,
}

/// A node whose webhook rate limits do not get in the way of tests that send many payloads.
async fn unthrottled() -> TestNode {
    let mut node = test_node(DOMAIN).await;
    let mut state = node.state.clone();
    let cluster = state.cluster.clone();
    let many = || {
        std::sync::Arc::new(tavrn_node::cache::limiter::SharedLimiter::new(
            "test",
            10_000,
            std::time::Duration::from_secs(60),
            &cluster,
        ))
    };
    state.webhook_burst_limiter = many();
    state.webhook_minute_limiter = many();
    node.router = tavrn_node::app::router(state.clone());
    node.state = state;
    node
}

/// Alice owns a room whose encrypted text channel has an MLS group (epoch 0).
async fn setup() -> Setup {
    let node = unthrottled().await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Sealed").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    node.create_group(&mut alice, &channel).await;
    Setup { node, alice, room_id, channel }
}

impl Setup {
    /// Creates a webhook in the encrypted channel; returns it and its execution path.
    async fn webhook(&self, body: Value) -> (Value, String) {
        let (s, j) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/channels/{}/webhooks", self.room_id, self.channel),
                self.alice.token(),
                body,
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        let url = j["url"].as_str().unwrap();
        (j["webhook"].clone(), url[url.find("/api/v1/").unwrap()..].to_string())
    }

    async fn join(&self, member: &Session) {
        let (_, invite) =
            self.node.post(&format!("/api/v1/rooms/{}/invites", self.room_id), self.alice.token(), json!({})).await;
        let (s, j) = self
            .node
            .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({}))
            .await;
        assert!(s.is_success(), "{j}");
    }

    async fn webhooks(&self) -> Vec<Value> {
        let (_, j) = self.node.get_auth(&format!("/api/v1/rooms/{}/webhooks", self.room_id), self.alice.token()).await;
        j.as_array().unwrap().clone()
    }
}

fn inbox_body(dev: &Dev, channel: &str, epoch: u64) -> Value {
    let (pk, sig) = dev.client.inbox_key(&qualified(channel), epoch).unwrap();
    json!({ "epoch": epoch, "public_key": b64(&pk), "signature": b64(&sig) })
}

async fn publish(node: &TestNode, token: &str, channel: &str, body: Value) -> (StatusCode, Value) {
    node.put(&format!("/api/v1/conversations/{channel}/inbox-key"), token, body).await
}

async fn exec(node: &TestNode, path: &str, body: Value) -> (StatusCode, Value) {
    node.req(Method::POST, &format!("{path}?wait=true"), None, Some(body)).await
}

/// Opens a sealed webhook message with a member's client: the inner JSON payload.
fn open(dev: &Dev, channel: &str, m: &Value) -> Value {
    assert_eq!(m["content"]["type"], "webhook.sealed", "{m}");
    assert_eq!(m["content"]["epoch"], m["epoch"]);
    let epoch = m["epoch"].as_u64().unwrap();
    let plain = dev.client.open_sealed(&qualified(channel), epoch, &unb64(&m["content"]["sealed"])).unwrap();
    serde_json::from_slice(&plain).unwrap()
}

#[tokio::test]
async fn inbox_keys_are_published_by_attested_members_for_newer_epochs_only() {
    let mut s = setup().await;
    let body = inbox_body(&s.alice, &s.channel, 0);
    // Channels without webhooks pay nothing: the node refuses keys for them.
    let (st, j) = publish(&s.node, s.alice.token(), &s.channel, body.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "inbox_key.no_webhooks"));
    let (webhook, _) = s.webhook(json!({ "name": "CI" })).await;
    assert_eq!(webhook["pending_key"], true);

    // Malformed keys, foreign signatures and future epochs are refused.
    let mut wrong = body.clone();
    wrong["epoch"] = json!(1);
    let (st, j) = publish(&s.node, s.alice.token(), &s.channel, wrong).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "inbox_key.invalid"), "the group is at epoch 0");
    let mut wrong = body.clone();
    wrong["public_key"] = json!(b64(&[1u8; 31]));
    assert_eq!(code(&publish(&s.node, s.alice.token(), &s.channel, wrong).await.1), "inbox_key.invalid");
    let mut wrong = body.clone();
    wrong["public_key"] = json!(b64(&tavrn_crypto::sealed::inbox_public_key(&[9u8; 32])));
    let (st, j) = publish(&s.node, s.alice.token(), &s.channel, wrong).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "inbox_key.bad_signature"));
    let mut wrong = body.clone();
    wrong["extra"] = json!(1);
    assert_eq!(publish(&s.node, s.alice.token(), &s.channel, wrong).await.0, StatusCode::BAD_REQUEST);

    // Members without an attested device, non-members and members who cannot see the channel are refused.
    let bob = s.node.register("bob").await;
    s.join(&bob).await;
    let (st, j) = publish(&s.node, &bob.token, &s.channel, body.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, "e2ee.device_not_attested"));
    let carol = s.node.crypto_user("carol").await;
    let (st, _) = publish(&s.node, carol.token(), &s.channel, body.clone()).await;
    assert!(st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND, "non-member: {st}");
    let mut dave = s.node.crypto_user("dave").await;
    s.join(&dave.session).await;
    let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), s.alice.token()).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let role = format!("/api/v1/rooms/{}/roles/{}", s.room_id, everyone.as_str().unwrap());
    let (st, j) = s
        .node
        .patch(&role, s.alice.token(), json!({ "permissions": (p::DEFAULT_EVERYONE & !p::VIEW_CHANNEL).to_string() }))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, _) = publish(&s.node, dave.token(), &s.channel, body.clone()).await;
    assert!(st == StatusCode::FORBIDDEN || st == StatusCode::NOT_FOUND, "no view_channel: {st}");
    let (st, _) = s.node.patch(&role, s.alice.token(), json!({ "permissions": p::DEFAULT_EVERYONE.to_string() })).await;
    assert_eq!(st, StatusCode::OK);
    // A signature of another device does not count for the session's device.
    let (st, j) = publish(&s.node, dave.token(), &s.channel, body.clone()).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "inbox_key.bad_signature"));

    // Alice publishes epoch 0: the webhook is ready; the same key again is fine.
    let (st, j) = publish(&s.node, s.alice.token(), &s.channel, body.clone()).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!((j["epoch"].clone(), j["algorithm"].clone()), (json!(0), json!("x25519-xsalsa20poly1305-sealedbox")));
    assert_eq!(publish(&s.node, s.alice.token(), &s.channel, body.clone()).await.0, StatusCode::OK);
    assert_eq!(s.webhooks().await[0]["pending_key"], false);

    // Dave joins the group (epoch 1) and publishes the new key; older epochs cannot replace it.
    s.node.add_user(&mut s.alice, &s.channel, "dave").await;
    assert_eq!(s.node.accept_welcomes(&mut dave).await, 1);
    let (st, j) = publish(&s.node, dave.token(), &s.channel, inbox_body(&dave, &s.channel, 1)).await;
    assert_eq!((st, j["epoch"].clone()), (StatusCode::OK, json!(1)), "{j}");
    let (st, j) = publish(&s.node, s.alice.token(), &s.channel, body).await;
    assert_eq!((st, code(&j), j["meta"]["epoch"].clone()), (StatusCode::CONFLICT, "inbox_key.stale", json!(1)));
    assert_eq!(
        publish(&s.node, s.alice.token(), &s.channel, inbox_body(&s.alice, &s.channel, 1)).await.0,
        StatusCode::OK
    );

    // Plaintext channels have no inbox key.
    let (_, plain) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", s.room_id),
            s.alice.token(),
            json!({ "name": "open", "kind": "text", "encrypted": false }),
        )
        .await;
    let plain = plain["id"].as_str().unwrap();
    let (st, j) = publish(&s.node, s.alice.token(), plain, inbox_body(&s.alice, &s.channel, 1)).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "inbox_key.not_encrypted"));
}

#[tokio::test]
async fn remote_users_publish_only_where_they_are_entitled() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let carol = b.register("carol").await;
    let room = b.create_room(&carol.token, "Remote").await;
    let channel = TestNode::text_channel(&room);
    let remote = b.sign_in_from(&a, &alice).await;
    let body = json!({ "epoch": 0, "public_key": b64(&[1u8; 32]), "signature": b64(&[2u8; 64]) });
    let (s, _) = b.put(&format!("/api/v1/conversations/{channel}/inbox-key"), &remote.token, body).await;
    assert!(s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND, "remote non-member: {s}");
}

#[tokio::test]
async fn sender_sealed_webhooks_accept_only_sealed_bodies() {
    let s = setup().await;
    let (webhook, path) = s.webhook(json!({ "name": "CI" })).await;
    assert_eq!(webhook["sealing"], "sender");
    let key_path = format!("{path}/inbox-key");
    // Nothing to seal to before a member published.
    let (st, j) = s.node.req(Method::GET, &key_path, None, None).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "webhook.pending_key"));
    let (st, j) = exec(&s.node, &path, json!({ "sealed": "AAAA", "epoch": 0 })).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "webhook.pending_key"));
    // The key route is guarded by the secret like the execution route.
    let wrong = format!("{}/inbox-key", path.replace(path.rsplit('/').next().unwrap(), &"A".repeat(43)));
    let (st, j) = s.node.req(Method::GET, &wrong, None, None).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, "webhook.not_found"));

    assert_eq!(
        publish(&s.node, s.alice.token(), &s.channel, inbox_body(&s.alice, &s.channel, 0)).await.0,
        StatusCode::OK
    );
    let (st, key) = s.node.req(Method::GET, &key_path, None, None).await;
    assert_eq!(st, StatusCode::OK, "{key}");
    assert_eq!(key["epoch"], 0);
    let pk: [u8; 32] = unb64(&key["public_key"]).try_into().unwrap();

    // Plaintext, unknown fields, future epochs and broken boxes are refused.
    let (st, j) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "plain" } })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.sealed_required"));
    let inner = json!({ "content": { "type": "text", "body": "Deployed **v2**" }, "username": "CI Bot" }).to_string();
    let sealed = b64(&tavrn_crypto::sealed::seal(&pk, inner.as_bytes()).unwrap());
    let (st, j) = exec(&s.node, &path, json!({ "sealed": sealed, "epoch": 0, "username": "x" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.sealed_required"));
    let (st, j) = exec(&s.node, &path, json!({ "sealed": sealed, "epoch": 1 })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.epoch_invalid"));
    let (st, j) = exec(&s.node, &path, json!({ "sealed": "not base64!", "epoch": 0 })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.payload_invalid"));
    let (st, j) = exec(&s.node, &path, json!({ "sealed": b64(&[0u8; 48]), "epoch": 0 })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.payload_invalid"));

    let (st, m) = exec(&s.node, &path, json!({ "sealed": sealed, "epoch": 0 })).await;
    assert_eq!(st, StatusCode::OK, "{m}");
    assert_eq!(
        (m["encrypted"].clone(), m["epoch"].clone(), m["device_id"].clone()),
        (json!(true), json!(0), Value::Null)
    );
    assert_eq!((m["author_kind"].clone(), m["webhook"]["name"].clone()), (json!("webhook"), json!("CI")));
    assert_eq!(m["content"]["sealed_by"], "sender");
    assert_eq!(open(&s.alice, &s.channel, &m), serde_json::from_str::<Value>(&inner).unwrap());
    // Members read it from the message list like any message.
    let (_, list) = s.node.get_auth(&format!("/api/v1/conversations/{}/messages", s.channel), s.alice.token()).await;
    let listed = list.as_array().unwrap().iter().find(|x| x["id"] == m["id"]).unwrap().clone();
    assert_eq!(listed["content"], m["content"]);
}

#[tokio::test]
async fn node_sealed_webhooks_store_only_the_sealed_box() {
    let mut s = setup().await;
    let bob = s.node.crypto_user("bob").await;
    s.join(&bob.session).await;
    let (webhook, path) = s.webhook(json!({ "name": "Alerts", "sealing": "node" })).await;
    let (st, j) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "x" } })).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "webhook.pending_key"));
    assert_eq!(
        publish(&s.node, s.alice.token(), &s.channel, inbox_body(&s.alice, &s.channel, 0)).await.0,
        StatusCode::OK
    );

    let embed = json!({ "title": "Disk", "description": "92 % full" });
    let payload = json!({
        "content": { "type": "text", "body": "TOPSECRET-disk-alert", "embeds": [embed] },
        "username": "Monitor-Unique-Name",
        "mentions": ["bob@t.local"],
    });
    let (st, m) = exec(&s.node, &path, payload).await;
    assert_eq!(st, StatusCode::OK, "{m}");
    assert_eq!(
        (m["encrypted"].clone(), m["epoch"].clone(), m["content"]["sealed_by"].clone()),
        (json!(true), json!(0), json!("node"))
    );
    // The username travels inside the box; the envelope names the webhook. Mentions stay metadata.
    assert_eq!(m["webhook"]["name"], "Alerts");
    assert_eq!(m["mentions"], json!(["bob@t.local"]));
    let inner = open(&s.alice, &s.channel, &m);
    assert_eq!(inner["content"]["body"], "TOPSECRET-disk-alert");
    assert_eq!(inner["content"]["embeds"][0], embed);
    assert_eq!(inner["username"], "Monitor-Unique-Name");
    // Nothing readable is stored.
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT content, webhook_name FROM messages WHERE id = $1")
            .bind(m["id"].as_str().unwrap())
            .fetch_all(&s.node.state.db)
            .await
            .unwrap();
    let stored = format!("{rows:?}");
    assert!(
        !stored.contains("TOPSECRET") && !stored.contains("Monitor-Unique-Name") && !stored.contains("92 %"),
        "{stored}"
    );
    let audit = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), s.alice.token()).await.1.to_string();
    assert!(!audit.contains("TOPSECRET"));

    // Refused payloads do not echo what they carried.
    let (st, j) = exec(
        &s.node,
        &path,
        json!({ "content": { "type": "text", "body": "TOPSECRET" }, "mentions_everyone": "TOPSECRET" }),
    )
    .await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.payload_invalid"));
    assert!(!j.to_string().contains("TOPSECRET"), "{j}");
    let (st, j) =
        exec(&s.node, &path, json!({ "content": { "type": "text", "body": "a" }, "mentions": ["TOPSECRET mention"] }))
            .await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "message.mention_invalid"));
    assert!(!j.to_string().contains("TOPSECRET"), "{j}");
    let (st, j) =
        exec(&s.node, &path, json!({ "content": { "type": "text", "body": "a" }, "username": "TOPSECRET@x" })).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, "webhook.username_invalid"));
    assert!(!j.to_string().contains("TOPSECRET"), "{j}");

    // Epoch window: after a commit the node seals with the newest key it has (the message says which epoch) until a
    // member publishes the next one.
    let mut bob = bob;
    s.node.add_user(&mut s.alice, &s.channel, "bob").await;
    s.node.accept_welcomes(&mut bob).await;
    let (_, m) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "window" } })).await;
    assert_eq!(m["epoch"], 0);
    assert_eq!(open(&s.alice, &s.channel, &m)["content"]["body"], "window");
    assert!(
        bob.client.open_sealed(&qualified(&s.channel), 0, &unb64(&m["content"]["sealed"])).is_err(),
        "bob joined at 1"
    );
    assert_eq!(publish(&s.node, bob.token(), &s.channel, inbox_body(&bob, &s.channel, 1)).await.0, StatusCode::OK);
    let (_, m) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "fresh" } })).await;
    assert_eq!(m["epoch"], 1);
    assert_eq!(open(&bob, &s.channel, &m)["content"]["body"], "fresh");
    assert_eq!(open(&s.alice, &s.channel, &m)["content"]["body"], "fresh");
    let _ = webhook;
}

#[tokio::test]
async fn the_encryption_switch_resets_the_key_and_sealed_messages_are_moderated() {
    let s = setup().await;
    let bob = s.node.register("bob").await;
    s.join(&bob).await;
    let (webhook, path) = s.webhook(json!({ "name": "CI", "sealing": "node" })).await;
    assert_eq!(
        publish(&s.node, s.alice.token(), &s.channel, inbox_body(&s.alice, &s.channel, 0)).await.0,
        StatusCode::OK
    );
    let mut ids = Vec::new();
    for i in 0..3 {
        let (st, m) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": format!("m{i}") } })).await;
        assert_eq!(st, StatusCode::OK, "{m}");
        ids.push(m["id"].as_str().unwrap().to_string());
    }
    let one = |id: &str| format!("/api/v1/rooms/{}/channels/{}/messages/{id}", s.room_id, s.channel);
    let (st, j) = s.node.delete(&one(&ids[0]), &bob.token).await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, "message.delete_forbidden"));
    assert_eq!(s.node.delete(&one(&ids[0]), s.alice.token()).await.0, StatusCode::NO_CONTENT);
    let purge = format!("/api/v1/rooms/{}/moderation/purge", s.room_id);
    let author_id = webhook["user"]["id"].clone();
    let (st, preview) = s.node.post(&purge, s.alice.token(), json!({ "author_id": author_id })).await;
    assert_eq!((st, preview["messages"].clone()), (StatusCode::OK, json!(2)), "{preview}");

    // To plaintext: plaintext posts again, the key is gone; back to encrypted: pending until a member publishes.
    let channel_path = format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel);
    assert_eq!(s.node.patch(&channel_path, s.alice.token(), json!({ "encrypted": false })).await.0, StatusCode::OK);
    let w = s.webhooks().await[0].clone();
    assert_eq!((w["sealing"].clone(), w["pending_key"].clone()), (Value::Null, json!(false)));
    let (st, m) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "plain" } })).await;
    assert_eq!((st, m["encrypted"].clone()), (StatusCode::OK, json!(false)), "{m}");
    let (st, j) = s.node.req(Method::GET, &format!("{path}/inbox-key"), None, None).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "webhook.not_sealed"));
    assert_eq!(s.node.patch(&channel_path, s.alice.token(), json!({ "encrypted": true })).await.0, StatusCode::OK);
    let w = s.webhooks().await[0].clone();
    assert_eq!((w["sealing"].clone(), w["pending_key"].clone()), (json!("sender"), json!(true)));
    let (st, j) = exec(&s.node, &path, json!({ "content": { "type": "text", "body": "x" } })).await;
    assert_eq!((st, code(&j)), (StatusCode::CONFLICT, "webhook.pending_key"));
}

/// A sealed post names its thread outside the box (`thread_id`, routing metadata like `epoch`; tavrn-node #8).
#[tokio::test]
async fn sealed_posts_go_into_threads() {
    let s = setup().await;
    let (_, path) = s.webhook(json!({ "name": "CI" })).await;
    assert_eq!(
        publish(&s.node, s.alice.token(), &s.channel, inbox_body(&s.alice, &s.channel, 0)).await.0,
        StatusCode::OK
    );
    // A thread of the channel (its encrypted title does not matter here).
    let thread_id = tavrn_node::util::ulid();
    let inserted = tavrn_node::store::threads::insert(
        &s.node.state.db,
        tavrn_node::store::threads::NewThread {
            id: &thread_id,
            channel_id: &s.channel,
            root_message_id: None,
            title: tavrn_node::store::threads::Title {
                text: "AAAA",
                epoch: Some(0),
                author_id: &s.alice.session.user_id,
                device_id: None,
            },
            tags: &[],
            created_by: &s.alice.session.user_id,
        },
    )
    .await
    .unwrap();
    assert!(inserted);
    let (_, key) = s.node.req(Method::GET, &format!("{path}/inbox-key"), None, None).await;
    let pk: [u8; 32] = unb64(&key["public_key"]).try_into().unwrap();
    let inner = json!({ "content": { "type": "text", "body": "threaded" } }).to_string();
    let sealed = b64(&tavrn_crypto::sealed::seal(&pk, inner.as_bytes()).unwrap());
    let (st, m) = exec(&s.node, &path, json!({ "sealed": sealed, "epoch": 0, "thread_id": thread_id })).await;
    assert_eq!((st, m["thread_id"].as_str()), (StatusCode::OK, Some(thread_id.as_str())), "{m}");
    let (st, j) =
        exec(&s.node, &path, json!({ "sealed": sealed, "epoch": 0, "thread_id": tavrn_node::util::ulid() })).await;
    assert_eq!((st, code(&j)), (StatusCode::NOT_FOUND, "thread.not_found"));
}
