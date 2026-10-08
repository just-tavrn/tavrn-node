// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Web push for new reports (MODERATION.md §1.5, PROTOCOL.md §6d): the room's moderators and the node admins without
//! a connection get a push of type `report` that names the report's kind and room only, coalesced per room, unless
//! they turned the notification setting `global.reports` off. A fake push service decrypts what a browser would get.
use crate::common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, body::Bytes, extract::Path, extract::State, http::StatusCode, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Session, TestNode, test_node};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use serde_json::{Value, json};
use tavrn_node::push::crypto;

/// A push service on 127.0.0.1 that records (path, body) and answers 201.
#[derive(Clone, Default)]
struct Fake {
    received: Arc<Mutex<Vec<(String, Bytes)>>>,
    base: String,
}

impl Fake {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake = Self { received: Arc::default(), base: format!("http://{}", listener.local_addr().unwrap()) };
        let app = Router::new()
            .route(
                "/{*path}",
                post(|State(f): State<Fake>, Path(p): Path<String>, body: Bytes| async move {
                    f.received.lock().unwrap().push((p, body));
                    StatusCode::CREATED
                }),
            )
            .with_state(fake.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        fake
    }

    fn count(&self, path: &str) -> usize {
        self.received.lock().unwrap().iter().filter(|(p, _)| p == path).count()
    }

    async fn wait(&self, path: &str, n: usize) {
        for _ in 0..100 {
            if self.count(path) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{path}: expected {n} pushes, got {}", self.count(path));
    }
}

/// One browser subscription of a user.
struct Browser {
    secret: SecretKey,
    auth: [u8; 16],
    path: String,
}

impl Browser {
    async fn subscribe(node: &TestNode, fake: &Fake, s: &Session) -> Self {
        let mut auth = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut auth);
        let b = Self { secret: SecretKey::random(&mut rand::rngs::OsRng), auth, path: s.username.clone() };
        let body = json!({ "endpoint": format!("{}/{}", fake.base, b.path), "keys": {
            "p256dh": URL_SAFE_NO_PAD.encode(b.secret.public_key().to_encoded_point(false).as_bytes()),
            "auth": URL_SAFE_NO_PAD.encode(b.auth) } });
        let (st, j) = node.put("/api/v1/users/me/push-subscriptions", &s.token, body).await;
        assert_eq!(st, StatusCode::CREATED, "{j}");
        b
    }

    fn last(&self, fake: &Fake) -> Value {
        let got = fake.received.lock().unwrap();
        let (_, body) = got.iter().rev().find(|(p, _)| *p == self.path).unwrap();
        serde_json::from_slice(&crypto::decrypt(&self.secret, &self.auth, body).unwrap()).unwrap()
    }
}

#[tokio::test]
async fn new_reports_push_to_offline_moderators_and_admins_with_kind_and_room_only() {
    let fake = Fake::start().await;
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let moder = node.register("moder").await;
    let quiet = node.register("quiet").await;
    let bob = node.register("bob").await;
    let carl = node.register("carl").await;
    let room = node.plaintext_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let perms = common::perms(&[1 << 0, 1 << 1, 1 << 13]);
    let (_, role) =
        node.post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Mods", "permissions": perms })).await;
    for who in [&moder, &quiet, &bob, &carl] {
        let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    }
    for m in [&moder, &quiet] {
        let (s, j) = node
            .patch(&format!("/api/v1/rooms/{room_id}/members/{}", m.user_id), &alice.token, json!({ "roles": [role["id"]] }))
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    // `reports` is on by default and left out of the document while on.
    let (_, settings) = node.get_auth("/api/v1/users/me/notification-settings", &quiet.token).await;
    assert!(settings["global"].get("reports").is_none(), "{settings}");
    let (s, j) = node
        .put("/api/v1/users/me/notification-settings", &quiet.token, json!({ "global": { "mode": "all", "reports": false } }))
        .await;
    assert_eq!((s, j["global"]["reports"].as_bool()), (StatusCode::OK, Some(false)), "{j}");

    // The reported message is sent before anyone subscribes (it would push to the room's members itself).
    let (_, msg) = node.send(&carl.token, &room_id, &channel, "coins for free").await;
    let browsers = [
        Browser::subscribe(&node, &fake, &admin).await,
        Browser::subscribe(&node, &fake, &alice).await,
        Browser::subscribe(&node, &fake, &moder).await,
        Browser::subscribe(&node, &fake, &quiet).await,
        Browser::subscribe(&node, &fake, &bob).await,
    ];
    let report = |kind: &str| match kind {
        "message" => json!({ "kind": "message", "conversation_id": channel, "message_id": msg["id"], "category": "spam",
            "detail": "secret detail" }),
        _ => json!({ "kind": "user", "user": "alice@t.local", "category": "harassment", "detail": "secret detail" }),
    };
    let (s, j) = node.post("/api/v1/reports", &bob.token, report("message")).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    for b in &browsers[..3] {
        fake.wait(&b.path, 1).await;
        let p = b.last(&fake);
        assert_eq!(
            p,
            json!({ "v": 1, "type": "report", "node": "t.local", "local": true, "room_id": room_id, "room": "Guild",
                "report_kind": "message", "encrypted": false }),
            "{}: nothing but the kind and the room",
            b.path
        );
    }
    // A second report in the same room within the coalescing window pushes no one again.
    let (s, _) = node
        .post("/api/v1/reports", &bob.token, json!({ "kind": "user", "user": "moder@t.local", "room_id": room_id, "category": "spam" }))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!((fake.count("admin"), fake.count("moder")), (1, 1));
    // Never the reporter, never someone who turned reports off.
    assert_eq!((fake.count("bob"), fake.count("quiet")), (0, 0));

    // A report for the node admins only (a user without room context): no room in the payload.
    let (s, j) = node.post("/api/v1/reports", &bob.token, report("user")).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    fake.wait("admin", 2).await;
    assert_eq!(browsers[0].last(&fake), json!({ "v": 1, "type": "report", "node": "t.local", "local": true,
        "report_kind": "user", "encrypted": false }));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.count("alice"), 1, "node reports go to the node admins only");
}
