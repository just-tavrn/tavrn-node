// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Web push (PROTOCOL.md §6d): subscriptions (validation, takeover, the cascade with devices and sign-out), which
//! events push (notification rules, only without a connection), what an encrypted conversation's payload contains,
//! coalescing, the handling of push service answers, forwarded hints and the test push. A fake push service (an
//! axum listener) records the requests and decrypts them with the test subscription's keys, as a browser would.
use crate::common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Session, TestNode, test_node};
use p256::{
    SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use serde_json::{Value, json};
use tavrn_node::{federation::social::Incoming, push::crypto, store};

const DOMAIN: &str = "t.local";
const SUBS: &str = "/api/v1/users/me/push-subscriptions";

#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

/// A push service on 127.0.0.1: `/gone/…` answers 410, `/busy/…` 429 with `Retry-After: 120`, the rest 201.
#[derive(Clone, Default)]
struct FakePushService {
    received: Arc<Mutex<Vec<Received>>>,
    base: String,
}

async fn receive(
    State(fake): State<FakePushService>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    fake.received.lock().unwrap().push(Received { path: path.clone(), headers, body });
    if path.starts_with("gone/") {
        StatusCode::GONE.into_response()
    } else if path.starts_with("busy/") {
        (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "120")]).into_response()
    } else {
        StatusCode::CREATED.into_response()
    }
}

impl FakePushService {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fake = Self { received: Arc::default(), base };
        let app = Router::new().route("/{*path}", post(receive)).with_state(fake.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        fake
    }

    fn for_path(&self, path: &str) -> Vec<Received> {
        self.received.lock().unwrap().iter().filter(|r| r.path == path).cloned().collect()
    }

    /// Waits until `path` received `n` pushes (the sender works in the background).
    async fn wait(&self, path: &str, n: usize) -> Vec<Received> {
        for _ in 0..common::rounds(100) {
            let got = self.for_path(path);
            if got.len() >= n {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{path}: expected {n} pushes, got {:?}", self.for_path(path).len());
    }

    /// Gives the sender time and asserts that `path` still has exactly `n` pushes.
    async fn settle(&self, path: &str, n: usize) {
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(self.for_path(path).len(), n, "{path}: pushes");
    }
}

/// The browser's side of one subscription.
struct Browser {
    secret: SecretKey,
    auth: [u8; 16],
    endpoint: String,
    path: String,
}

impl Browser {
    fn new(fake: &FakePushService, path: &str) -> Self {
        let mut auth = [0u8; 16];
        tavrn_node::util::fill_random(&mut auth);
        Self {
            secret: SecretKey::generate_from_rng(&mut tavrn_node::util::os_rng()),
            auth,
            endpoint: format!("{}/{path}", fake.base),
            path: path.to_string(),
        }
    }

    fn subscription(&self) -> Value {
        json!({
            "endpoint": self.endpoint,
            "keys": {
                "p256dh": URL_SAFE_NO_PAD.encode(self.secret.public_key().to_sec1_point(false).as_bytes()),
                "auth": URL_SAFE_NO_PAD.encode(self.auth),
            },
            "expirationTime": null,
        })
    }

    /// Decrypts a received push as the service worker gets it.
    fn open(&self, r: &Received) -> Value {
        assert_eq!(r.headers["content-encoding"], "aes128gcm");
        let plain =
            crypto::decrypt(&self.secret, &self.auth, &r.body).expect("the push decrypts with the browser's keys");
        serde_json::from_slice(&plain).unwrap()
    }
}

async fn subscribe(node: &TestNode, s: &Session, browser: &Browser) -> Value {
    let (st, j) = node.put(SUBS, &s.token, browser.subscription()).await;
    assert!(st == StatusCode::CREATED || st == StatusCode::OK, "{j}");
    j
}

struct Setup {
    node: TestNode,
    fake: FakePushService,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let fake = FakePushService::start().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Tavern").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    Setup { node, fake, alice, bob, room_id, channel }
}

/// A second unencrypted text channel of the room (a conversation of its own for the coalescing).
async fn plaintext_channel(s: &Setup, name: &str) -> String {
    let (st, c) = s
        .node
        .post(&format!("/api/v1/rooms/{}/channels", s.room_id), &s.alice.token, json!({ "name": name, "kind": "text" }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{c}");
    let id = c["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
        .bind(&id)
        .execute(&s.node.state.db)
        .await
        .unwrap();
    id
}

async fn send(s: &Setup, channel: &str, body: Value) -> Value {
    let (st, m) = s.node.post(&format!("/api/v1/conversations/{channel}/messages"), &s.alice.token, body).await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    m
}

fn text(body: &str) -> Value {
    json!({ "content": { "type": "text", "body": body } })
}

#[tokio::test]
async fn vapid_key_and_subscriptions_are_validated() {
    let s = setup().await;
    let (st, v) = s.node.req(axum::http::Method::GET, "/api/v1/push/vapid", None, None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["enabled"], true);
    assert_eq!(URL_SAFE_NO_PAD.decode(v["public_key"].as_str().unwrap()).unwrap().len(), 65);
    let (_, node) = s.node.get_auth("/api/v1/node", &s.bob.token).await;
    assert!(node["capabilities"].as_array().unwrap().contains(&json!("push.webpush")), "{node}");

    let browser = Browser::new(&s.fake, "ok/bob");
    let good = browser.subscription();
    let with = |f: &dyn Fn(&mut Value)| {
        let mut b = good.clone();
        f(&mut b);
        b
    };
    for (body, code) in [
        (with(&|b| b["endpoint"] = json!("ftp://push.example/x")), "push.endpoint_invalid"),
        (with(&|b| b["endpoint"] = json!("https://user:pw@push.example/x")), "push.endpoint_invalid"),
        (
            with(&|b| b["endpoint"] = json!(format!("https://push.example/{}", "a".repeat(2100)))),
            "push.endpoint_invalid",
        ),
        (with(&|b| b["keys"]["p256dh"] = json!("AAAA")), "push.keys_invalid"),
        (with(&|b| b["keys"]["auth"] = json!("c2hvcnQ")), "push.keys_invalid"),
        (with(&|b| b["device_id"] = json!("01JAAAAAAAAAAAAAAAAAAAAAAA")), "push.device_invalid"),
        (with(&|b| b["expirationTime"] = json!(1_000)), "push.expiration_invalid"),
    ] {
        let (st, j) = s.node.put(SUBS, &s.bob.token, body).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{j}");
    }
    let (st, created) = s.node.put(SUBS, &s.bob.token, with(&|b| b["device_id"] = json!(s.bob.device_id))).await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert_eq!(created["push_service"], s.fake.base.as_str());
    assert_eq!(created["current_device"], true);
    assert!(created.get("keys").is_none() && created.get("endpoint").is_none(), "keys and endpoint stay private");
    let (st, again) = s.node.put(SUBS, &s.bob.token, good.clone()).await;
    assert_eq!((st, &again["id"]), (StatusCode::OK, &created["id"]), "same endpoint: updated");
    // Another account cannot take over the endpoint of a live subscription (tavrn-node #9).
    let (st, j) = s.node.put(SUBS, &s.alice.token, good.clone()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("push.endpoint_taken")), "{j}");
    let (_, mine) = s.node.get_auth(SUBS, &s.bob.token).await;
    assert_eq!(mine.as_array().unwrap().len(), 1, "the owner keeps it: {mine}");
    // The same account moves it to another of its devices.
    let laptop = s.node.login("bob").await;
    let (st, moved) = s.node.put(SUBS, &laptop.token, good.clone()).await;
    assert_eq!(
        (st, &moved["id"], moved["device_id"].as_str()),
        (StatusCode::OK, &created["id"], Some(laptop.device_id.as_str()))
    );
    // Once the owner's device has no live session, the endpoint is stale and another account takes it over.
    sqlx::query("UPDATE sessions SET expires_at = '2000-01-01T00:00:00.000Z' WHERE device_id = $1")
        .bind(&laptop.device_id)
        .execute(&s.node.state.db)
        .await
        .unwrap();
    let (st, taken) = s.node.put(SUBS, &s.alice.token, good.clone()).await;
    assert_eq!((st, &taken["id"]), (StatusCode::OK, &created["id"]), "{taken}");
    let (_, mine) = s.node.get_auth(SUBS, &s.bob.token).await;
    assert_eq!(mine, json!([]));
    let (_, theirs) = s.node.get_auth(SUBS, &s.alice.token).await;
    assert_eq!(theirs.as_array().unwrap().len(), 1);
    let path = format!("{SUBS}/{}", created["id"].as_str().unwrap());
    let (st, _) = s.node.delete(&path, &s.bob.token).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "only the owner deletes");
    let (st, _) = s.node.delete(&path, &s.alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) = s.node.delete(&path, &s.alice.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("push.subscription_not_found")));
    let (st, _) = s.node.req(axum::http::Method::GET, SUBS, None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn subscriptions_go_with_sign_out_and_removed_devices() {
    let s = setup().await;
    subscribe(&s.node, &s.bob, &Browser::new(&s.fake, "ok/one")).await;
    let second = s.node.login("bob").await;
    subscribe(&s.node, &second, &Browser::new(&s.fake, "ok/two")).await;
    let third = s.node.login("bob").await;
    subscribe(&s.node, &third, &Browser::new(&s.fake, "ok/three")).await;
    let count = || async { store::push::list(&s.node.state.db, &s.bob.user_id).await.unwrap().len() };
    assert_eq!(count().await, 3);
    // Sign-out of a device.
    let (st, _) = s.node.post("/api/v1/auth/logout", &second.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(count().await, 2);
    // A device removed from another one.
    let (st, j) = s.node.delete(&format!("/api/v1/users/me/devices/{}", third.device_id), &s.bob.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(count().await, 1);
    // A device row that goes by any other path takes its subscriptions along (foreign key cascade).
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(&s.bob.device_id).execute(&s.node.state.db).await.unwrap();
    assert_eq!(count().await, 0);
}

#[tokio::test]
async fn messages_push_under_the_notification_rules_only_without_a_connection() {
    let s = setup().await;
    let browser = Browser::new(&s.fake, "ok/bob");
    subscribe(&s.node, &s.bob, &browser).await;

    // Offline, mode "all": a plain message pushes; no text without push_text.
    let m = send(&s, &s.channel, text("the dragon is awake")).await;
    let got = s.fake.wait(&browser.path, 1).await;
    let r = &got[0];
    let p = browser.open(r);
    assert_eq!(p["v"], 1);
    assert_eq!(p["type"], "message");
    assert_eq!(p["node"], DOMAIN);
    assert_eq!(p["local"], true);
    assert_eq!(p["conversation_id"], s.channel.as_str());
    assert_eq!(p["room_id"], s.room_id.as_str());
    assert_eq!(p["conversation_kind"], "channel");
    assert_eq!(p["room"], "Tavern");
    assert_eq!(p["sender"], "alice");
    assert_eq!(p["encrypted"], false);
    assert!(p.get("text").is_none(), "no preview unless the user asked for it: {p}");
    assert!(!serde_json::to_string(&p).unwrap().contains(m["id"].as_str().unwrap()), "no message id");
    // RFC 8030/8292 headers.
    let vapid = s.node.state.push.public_key().unwrap().to_string();
    let claims =
        crypto::verify_authorization(r.headers["authorization"].to_str().unwrap(), &vapid, &s.fake.base).unwrap();
    assert_eq!(claims["sub"], format!("http://{DOMAIN}:8080"), "default contact: the public URL");
    assert_eq!(r.headers["ttl"], "21600");
    assert_eq!(r.headers["urgency"], "normal");
    assert_eq!(r.headers["topic"].len(), 22);
    // The sender records the delivery after the push service answered: wait for it (tavrn-node #21).
    let mut used = None;
    for _ in 0..common::rounds(100) {
        used = store::push::list(&s.node.state.db, &s.bob.user_id).await.unwrap()[0].last_used_at.clone();
        if used.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(used.is_some(), "a delivered push sets last_used_at");

    // Coalescing: the next message of the same conversation within 30 seconds does not push.
    send(&s, &s.channel, text("again")).await;
    s.fake.settle(&browser.path, 1).await;

    // With push_text a preview of at most 120 characters is included.
    let settings = "/api/v1/users/me/notification-settings";
    s.node.put(settings, &s.bob.token, json!({ "global": { "mode": "all", "push_text": true } })).await;
    let preview = plaintext_channel(&s, "preview").await;
    send(&s, &preview, text(&format!("long  {}", "x".repeat(200)))).await;
    let got = s.fake.wait(&browser.path, 2).await;
    let p = browser.open(&got[1]);
    assert_eq!(p["conversation"], "preview");
    let t = p["text"].as_str().unwrap();
    assert!(t.starts_with("long x") && t.chars().count() == 120 && t.ends_with('…'), "{t}");

    // Connected: no push.
    let online = plaintext_channel(&s, "online").await;
    let guard = s.node.state.hub.connect(&s.bob.user_id);
    send(&s, &online, text("you are here")).await;
    s.fake.settle(&browser.path, 2).await;
    drop(guard);

    // Mentions only: a plain message does not push, a mention does (type mention, urgent).
    s.node.put(settings, &s.bob.token, json!({ "global": { "mode": "mentions" } })).await;
    let quiet = plaintext_channel(&s, "quiet").await;
    send(&s, &quiet, text("nothing for bob")).await;
    s.fake.settle(&browser.path, 2).await;
    send(
        &s,
        &quiet,
        json!({ "content": { "type": "text", "body": "@bob look" }, "mentions": [format!("bob@{DOMAIN}")] }),
    )
    .await;
    let got = s.fake.wait(&browser.path, 3).await;
    let p = browser.open(&got[2]);
    assert_eq!(p["type"], "mention");
    assert_eq!(got[2].headers["urgency"], "high");

    // A muted channel never pushes, not even mentions.
    let muted = plaintext_channel(&s, "muted").await;
    s.node
        .put(
            settings,
            &s.bob.token,
            json!({ "global": { "mode": "all" }, "channels": { muted.clone(): { "muted_until": "forever" } } }),
        )
        .await;
    send(&s, &muted, json!({ "content": { "type": "text", "body": "@bob" }, "mentions": [format!("bob@{DOMAIN}")] }))
        .await;
    s.fake.settle(&browser.path, 3).await;

    // Own messages never push the author.
    let alices = Browser::new(&s.fake, "ok/alice");
    subscribe(&s.node, &s.alice, &alices).await;
    send(&s, &plaintext_channel(&s, "own").await, text("mine")).await;
    s.fake.settle(&alices.path, 0).await;
}

#[tokio::test]
async fn encrypted_conversations_push_no_content() {
    let node = test_node(DOMAIN).await;
    let fake = FakePushService::start().await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    node.put(
        "/api/v1/users/me/notification-settings",
        bob.token(),
        json!({ "global": { "mode": "mentions", "push_text": true } }),
    )
    .await;
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob.session, &browser).await;
    let (st, m) = node.send_encrypted(&alice, &dm, "secret plans for the heist").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    let got = fake.wait(&browser.path, 1).await;
    let p = browser.open(&got[0]);
    assert_eq!(p["type"], "dm", "DMs push under mentions mode too: {p}");
    assert_eq!(p["conversation_kind"], "dm");
    assert_eq!(p["encrypted"], true);
    assert_eq!(p["sender"], "alice");
    let raw = serde_json::to_string(&p).unwrap();
    assert!(p.get("text").is_none(), "never a preview of an encrypted message: {raw}");
    assert!(!raw.contains("heist"), "{raw}");
    assert!(!raw.contains(m["content"].as_str().unwrap()), "never the ciphertext");
    let keys: Vec<&String> = p.as_object().unwrap().keys().collect();
    for k in &keys {
        assert!(
            ["v", "type", "node", "local", "conversation_id", "conversation_kind", "sender", "encrypted"]
                .contains(&k.as_str()),
            "unexpected field {k} in {raw}"
        );
    }
    assert_eq!(got[0].headers["urgency"], "high");
}

#[tokio::test]
async fn push_service_answers_remove_or_hold_back_subscriptions() {
    let s = setup().await;
    let gone = Browser::new(&s.fake, "gone/bob");
    subscribe(&s.node, &s.bob, &gone).await;
    let busy = Browser::new(&s.fake, "busy/bob");
    let second = s.node.login("bob").await;
    subscribe(&s.node, &second, &busy).await;
    send(&s, &s.channel, text("hello")).await;
    s.fake.wait(&gone.path, 1).await;
    s.fake.wait(&busy.path, 1).await;
    let rows = || async { store::push::list(&s.node.state.db, &s.bob.user_id).await.unwrap() };
    let mut left = rows().await;
    for _ in 0..common::rounds(50) {
        if left.len() == 1 && left[0].failures == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        left = rows().await;
    }
    assert_eq!(left.len(), 1, "410: the subscription is deleted");
    assert_eq!(left[0].failures, 1, "429: held back");
    let retry_at = tavrn_node::util::parse_time(left[0].retry_at.as_deref().unwrap()).unwrap();
    let wait = retry_at - chrono::Utc::now();
    assert!(
        wait > chrono::Duration::seconds(100) && wait <= chrono::Duration::seconds(121),
        "Retry-After honored: {wait}"
    );
    // Held back: the next push skips it.
    send(&s, &plaintext_channel(&s, "later").await, text("hello again")).await;
    s.fake.settle(&busy.path, 1).await;
}

/// FEDERATION.md §5.2: a ring hint naming a caller of a third node is pushed with `via` (the node that named the
/// caller), so the notification never presents the caller as verified.
#[tokio::test]
async fn a_ring_naming_a_third_node_caller_is_pushed_with_via() {
    let node = test_node_with_limit(2).await;
    let fake = FakePushService::start().await;
    let bob_session = node.register("bob").await;
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob_session, &browser).await;
    let bob = store::users::by_id(&node.state.db, &bob_session.user_id).await.unwrap().unwrap();
    store::federation::touch_target(&node.state.db, &bob.id, &bob_session.device_id, "b.test").await.unwrap();
    let ring = Incoming::Notify {
        conversation_id: tavrn_node::util::ulid(),
        room_id: None,
        mention: false,
        everyone: false,
        call: Some(tavrn_node::federation::social::CallHint::Ring {
            from: "carol@c.test".into(),
            started_at: tavrn_node::util::now(),
            group: false,
        }),
    };
    let r =
        tavrn_node::federation::social::handle(&node.state, "b.test", "b.test", &bob, &tavrn_node::util::now(), ring)
            .await
            .unwrap();
    assert_eq!(r, "handled");
    let got = fake.wait(&browser.path, 1).await;
    let p = browser.open(&got[0]);
    assert_eq!(
        (p["type"].as_str(), p["sender"].as_str(), p["via"].as_str()),
        (Some("call"), Some("carol@c.test"), Some("b.test"))
    );
}

#[tokio::test]
async fn forwarded_hints_and_call_rings_push_and_the_limit_per_minute_holds() {
    let node = test_node_with_limit(2).await;
    let fake = FakePushService::start().await;
    let bob_session = node.register("bob").await;
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob_session, &browser).await;
    let bob = store::users::by_id(&node.state.db, &bob_session.user_id).await.unwrap().unwrap();
    // Hints come only from nodes bob signed in on (FEDERATION.md §5.2).
    store::federation::touch_target(&node.state.db, &bob.id, &bob_session.device_id, "b.test").await.unwrap();
    let handle = |incoming: Incoming| {
        let (state, bob) = (node.state.clone(), bob.clone());
        async move {
            tavrn_node::federation::social::handle(&state, "b.test", "b.test", &bob, &tavrn_node::util::now(), incoming)
                .await
                .unwrap()
        }
    };
    let room = tavrn_node::util::ulid();
    let conv = tavrn_node::util::ulid();
    let hint = Incoming::Notify {
        conversation_id: conv.clone(),
        room_id: Some(room.clone()),
        mention: true,
        everyone: false,
        call: None,
    };
    assert_eq!(handle(hint).await, "stored");
    let got = fake.wait(&browser.path, 1).await;
    let p = browser.open(&got[0]);
    assert_eq!(
        p,
        json!({ "v": 1, "type": "mention", "node": "b.test", "local": false, "conversation_id": conv,
                "room_id": room, "conversation_kind": "channel", "encrypted": true })
    );
    // A ring of a call on another node.
    let ring = Incoming::Notify {
        conversation_id: tavrn_node::util::ulid(),
        room_id: None,
        mention: false,
        everyone: false,
        call: Some(tavrn_node::federation::social::CallHint::Ring {
            from: "carol@b.test".into(),
            started_at: tavrn_node::util::now(),
            group: false,
        }),
    };
    assert_eq!(handle(ring).await, "handled");
    let got = fake.wait(&browser.path, 2).await;
    let p = browser.open(&got[1]);
    assert_eq!((p["type"].as_str(), p["sender"].as_str()), (Some("call"), Some("carol@b.test")));
    assert_eq!(p["via"], Value::Null, "b.test vouches for its own user");
    assert_eq!(got[1].headers["ttl"], "45");
    // TAVRN_PUSH_MAX_PER_MINUTE=2: a third push of another conversation within the minute is dropped.
    let third = Incoming::Notify {
        conversation_id: tavrn_node::util::ulid(),
        room_id: None,
        mention: false,
        everyone: false,
        call: None,
    };
    assert_eq!(handle(third).await, "stored");
    fake.settle(&browser.path, 2).await;
}

async fn test_node_with_limit(max: u32) -> TestNode {
    common::test_node_with(DOMAIN, |c| c.push_max_per_minute = max).await
}

#[tokio::test]
async fn test_push_reaches_every_subscription_even_while_connected() {
    let s = setup().await;
    let browser = Browser::new(&s.fake, "ok/bob");
    subscribe(&s.node, &s.bob, &browser).await;
    let _guard = s.node.state.hub.connect(&s.bob.user_id);
    let (st, _) = s.node.post(&format!("{SUBS}/test"), &s.bob.token, json!({})).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let got = s.fake.wait(&browser.path, 1).await;
    assert_eq!(browser.open(&got[0])["type"], "test");
    for _ in 0..4 {
        s.node.post(&format!("{SUBS}/test"), &s.bob.token, json!({})).await;
    }
    let (st, _) = s.node.post(&format!("{SUBS}/test"), &s.bob.token, json!({})).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "5 test pushes per 10 minutes");
}

#[tokio::test]
async fn push_can_be_switched_off() {
    let node = common::test_node_with(DOMAIN, |c| c.push = tavrn_node::config::Switch::Off).await;
    let bob = node.register("bob").await;
    let (_, v) = node.req(axum::http::Method::GET, "/api/v1/push/vapid", None, None).await;
    assert_eq!(v, json!({ "enabled": false, "public_key": null }));
    let fake = FakePushService::start().await;
    let (st, j) = node.put(SUBS, &bob.token, Browser::new(&fake, "ok/bob").subscription()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("push.disabled")));
    let (_, info) = node.get_auth("/api/v1/node", &bob.token).await;
    assert!(!info["capabilities"].as_array().unwrap().contains(&json!("push.webpush")));
    assert!(!std::path::Path::new(&node.state.config.data_dir).join("keys/vapid.key").exists(), "no key while off");
}

#[tokio::test]
async fn a_call_in_a_local_dm_rings_by_push() {
    let node = test_node(DOMAIN).await;
    let fake = FakePushService::start().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    node.befriend(&alice, &bob).await;
    let dm = node.create_dm(&alice, &bob).await;
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob, &browser).await;
    let caller = store::users::by_id(&node.state.db, &alice.user_id).await.unwrap().unwrap();
    assert!(tavrn_node::calls::start(&node.state, &dm, &caller, false).await.unwrap());
    let got = fake.wait(&browser.path, 1).await;
    let p = browser.open(&got[0]);
    assert_eq!((p["type"].as_str(), p["conversation_kind"].as_str()), (Some("call"), Some("dm")), "{p}");
    assert_eq!((p["sender"].as_str(), p["local"].as_bool()), (Some("alice"), Some(true)));
    assert_eq!((got[0].headers["ttl"].to_str().unwrap(), got[0].headers["urgency"].to_str().unwrap()), ("45", "high"));
}

/// Call rings push even while the callee has a connection (PROTOCOL.md §6d): a phone keeps the WebSocket of a frozen
/// background tab open, so "connected" does not mean the ring can be heard. The service worker stays silent while a
/// page of the client is visible. Messages keep pushing only without a connection (the test above).
#[tokio::test]
async fn call_rings_push_even_while_the_callee_is_connected() {
    let node = test_node_with_limit(10).await;
    let fake = FakePushService::start().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    node.befriend(&alice, &bob).await;
    let dm = node.create_dm(&alice, &bob).await;
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob, &browser).await;
    let _guard = node.state.hub.connect(&bob.user_id);
    assert!(tavrn_node::presence::is_online(&node.state, &bob.user_id));
    let caller = store::users::by_id(&node.state.db, &alice.user_id).await.unwrap().unwrap();
    assert!(tavrn_node::calls::start(&node.state, &dm, &caller, false).await.unwrap());
    let got = fake.wait(&browser.path, 1).await;
    let p = browser.open(&got[0]);
    assert_eq!((p["type"].as_str(), p["conversation_id"].as_str()), (Some("call"), Some(dm.as_str())), "{p}");

    // A ring forwarded by another node (`notify` hint) pushes while connected, too.
    let bob_row = store::users::by_id(&node.state.db, &bob.user_id).await.unwrap().unwrap();
    store::federation::touch_target(&node.state.db, &bob_row.id, &bob.device_id, "b.test").await.unwrap();
    let ring = Incoming::Notify {
        conversation_id: tavrn_node::util::ulid(),
        room_id: None,
        mention: false,
        everyone: false,
        call: Some(tavrn_node::federation::social::CallHint::Ring {
            from: "carol@b.test".into(),
            started_at: tavrn_node::util::now(),
            group: false,
        }),
    };
    let r = tavrn_node::federation::social::handle(
        &node.state,
        "b.test",
        "b.test",
        &bob_row,
        &tavrn_node::util::now(),
        ring,
    )
    .await
    .unwrap();
    assert_eq!(r, "handled");
    let got = fake.wait(&browser.path, 2).await;
    assert_eq!(browser.open(&got[1])["type"], "call");
}

/// Thread messages (PROTOCOL.md §7e) push only to the thread's followers, plus anyone mentioned directly.
#[tokio::test]
async fn thread_messages_push_to_followers_and_direct_mentions_only() {
    let s = setup().await;
    let browser = Browser::new(&s.fake, "ok/bob");
    subscribe(&s.node, &s.bob, &browser).await;
    let threads = |channel: &str| format!("/api/v1/rooms/{}/channels/{channel}/threads", s.room_id);
    let in_thread =
        |body: &str, thread_id: &str| json!({ "content": { "type": "text", "body": body }, "thread_id": thread_id });

    // Alice's thread: Bob does not follow it, so its first message does not push (mode "all" would otherwise).
    let channel = plaintext_channel(&s, "threads").await;
    let root = send(&s, &channel, text("plan the raid")).await;
    let (st, thread) = s
        .node
        .post(
            &threads(&channel),
            &s.alice.token,
            json!({ "title": "raid", "root_message_id": root["id"], "message": text("who is in?") }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{thread}");
    let thread_id = thread["id"].as_str().unwrap().to_string();
    s.fake.settle(&browser.path, 1).await;

    // A direct mention inside the thread reaches him anyway (another conversation: no coalescing in the way).
    let mention = plaintext_channel(&s, "mention").await;
    let (st, t2) =
        s.node.post(&threads(&mention), &s.alice.token, json!({ "title": "loot", "message": text("rules") })).await;
    assert_eq!(st, StatusCode::CREATED, "{t2}");
    s.fake.settle(&browser.path, 1).await;
    let mut m = in_thread("<@bob> you too", t2["id"].as_str().unwrap());
    m["mentions"] = json!([format!("bob@{DOMAIN}")]);
    send(&s, &mention, m).await;
    let got = s.fake.wait(&browser.path, 2).await;
    let p = browser.open(&got[1]);
    assert_eq!(p["type"], "mention", "{p}");
    assert_eq!(p["conversation_id"], mention.as_str());

    // A thread Bob follows (he started it) pushes its plain messages.
    let own = plaintext_channel(&s, "own").await;
    let (st, t3) =
        s.node.post(&threads(&own), &s.bob.token, json!({ "title": "mine", "message": text("hello") })).await;
    assert_eq!(st, StatusCode::CREATED, "{t3}");
    send(&s, &own, in_thread("we start at nine", t3["id"].as_str().unwrap())).await;
    let got = s.fake.wait(&browser.path, 3).await;
    let p = browser.open(&got[2]);
    assert_eq!(p["type"], "message", "{p}");
    assert_eq!(p["conversation_id"], own.as_str());
    let _ = thread_id;
}

/// Web push of a private channel reaches only the members who may view it (roles and overrides at delivery time,
/// the same check as the WebSocket fan-out and the `notify` hints), thread follows and `@everyone` included.
#[tokio::test]
async fn private_channels_push_only_to_members_who_can_view_them() {
    let s = setup().await;
    let browser = Browser::new(&s.fake, "ok/bob");
    subscribe(&s.node, &s.bob, &browser).await;
    let secret = plaintext_channel(&s, "secret").await;
    // Bob follows a thread of the channel while he may still view it.
    let threads = format!("/api/v1/rooms/{}/channels/{secret}/threads", s.room_id);
    let (st, thread) = s.node.post(&threads, &s.bob.token, json!({ "title": "mine", "message": text("hi") })).await;
    assert_eq!(st, StatusCode::CREATED, "{thread}");
    let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let deny = |deny: u64| {
        json!({ "target_type": "channel", "target_id": secret, "subject_type": "role", "subject_id": everyone,
                "allow": "0", "deny": deny.to_string() })
    };
    let overrides = format!("/api/v1/rooms/{}/overrides", s.room_id);
    let (st, j) = s.node.put(&overrides, &s.alice.token, deny(tavrn_node::permissions::VIEW_CHANNEL)).await;
    assert_eq!(st, StatusCode::OK, "{j}");

    let everyone_msg = json!({ "content": { "type": "text", "body": "@everyone" }, "mentions_everyone": true });
    send(&s, &secret, everyone_msg.clone()).await;
    let mut followed = json!({ "content": { "type": "text", "body": "news" }, "thread_id": thread["id"] });
    followed["mentions"] = json!([format!("bob@{DOMAIN}")]);
    send(&s, &secret, followed).await;
    s.fake.settle(&browser.path, 0).await;
    // The open channel still pushes (the subscription works).
    send(&s, &s.channel, text("open")).await;
    s.fake.wait(&browser.path, 1).await;

    // The deny is lifted: the channel pushes again.
    let (st, j) = s.node.put(&overrides, &s.alice.token, deny(0)).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    send(&s, &secret, everyone_msg).await;
    let got = s.fake.wait(&browser.path, 2).await;
    assert_eq!(browser.open(&got[1])["conversation_id"], secret.as_str());
}

#[tokio::test]
async fn gated_channels_push_nothing_to_minors() {
    let node = test_node(DOMAIN).await;
    let fake = FakePushService::start().await;
    let alice = node.register("alice").await;
    let sixteen = chrono::Utc::now().date_naive().checked_sub_months(chrono::Months::new(16 * 12)).unwrap();
    let bob = node.register_born("bob", &sixteen.format("%Y-%m-%d").to_string()).await;
    let room = node.plaintext_room(&alice.token, "Tavern").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let open = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let (st, gated) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "late", "kind": "text", "encrypted": false, "age_gate": "adults_only" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{gated}");
    let browser = Browser::new(&fake, "ok/bob");
    subscribe(&node, &bob, &browser).await;
    let body = json!({ "content": { "type": "text", "body": "@everyone late", "mentions_everyone": true } });
    let gated = gated["id"].as_str().unwrap();
    let (st, m) = node.post(&format!("/api/v1/conversations/{gated}/messages"), &alice.token, body).await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    fake.settle(&browser.path, 0).await;
    let (st, m) = node.post(&format!("/api/v1/conversations/{open}/messages"), &alice.token, text("early")).await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    fake.wait(&browser.path, 1).await;
}

/// One message to a channel with 20 offline subscribed members: the recipients, their settings, blocks and
/// subscriptions are loaded in batches (not per member), the deliveries are recorded in one statement, and a
/// coalesced repeat costs no per-member work at all.
#[tokio::test]
async fn a_channel_message_loads_its_push_recipients_in_batches() {
    let s = setup().await;
    let (_, invite) = s.node.post(&format!("/api/v1/rooms/{}/invites", s.room_id), &s.alice.token, json!({})).await;
    let code = invite["code"].as_str().unwrap().to_string();
    let mut browsers = Vec::new();
    let mut members = Vec::new();
    for i in 0..20 {
        let m = s.node.register(&format!("member{i}")).await;
        members.push(m.user_id.clone());
        s.node.post(&format!("/api/v1/invites/{code}/join"), &m.token, json!({})).await;
        let b = Browser::new(&s.fake, &format!("ok/member{i}"));
        subscribe(&s.node, &m, &b).await;
        browsers.push(b);
    }
    // One member blocked the author: no push for them.
    store::social::block(&s.node.state.db, &members[0], &s.alice.user_id, "").await.unwrap();
    let m = send(&s, &s.channel, text("round for everyone")).await;
    for b in &browsers[1..] {
        s.fake.wait(&b.path, 1).await;
    }
    s.fake.settle(&browsers[0].path, 0).await;
    // The same message in a second channel nobody was pushed for yet, run directly and counted.
    let other = plaintext_channel(&s, "second").await;
    let mut message: tavrn_node::models::Message = serde_json::from_value(m).unwrap();
    message.conversation_id = other.clone();
    let job = || tavrn_node::push::Job::Message {
        message: Box::new(message.clone()),
        author_id: s.alice.user_id.clone(),
        priority: false,
    };
    let (r, first) = common::logs::statements(tavrn_node::push::run(&s.node.state, job())).await;
    r.unwrap();
    for b in &browsers[1..] {
        s.fake.wait(&b.path, 2).await;
    }
    // conversation, candidates, author, the recipients with settings, blocks and subscriptions, the deliveries
    // (and the room's visibility snapshot when it was dropped since).
    println!("push job statements for 20 recipients: {first}");
    assert!(first <= 6 + 7, "statements for 20 recipients: {first}");
    let (r, coalesced) = common::logs::statements(tavrn_node::push::run(&s.node.state, job())).await;
    r.unwrap();
    println!("push job statements when coalesced: {coalesced}");
    assert!(coalesced <= 4, "a coalesced repeat: {coalesced}");
    for b in &browsers[1..] {
        s.fake.settle(&b.path, 2).await;
    }
}
