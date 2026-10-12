// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Screen publishers (protocol/VOICE.md §4b): a device's second LiveKit participant that only publishes its screen
//! share (the Android app). The join with `role: "screen"` and its publish-only token, the checks (the device must be
//! there, `stream`, one per device), the listing under the owner with `screen_of`, that it counts as its owner, and
//! that it ends with the owner's participation; the same in calls.
use crate::common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, perms, test_node_with};
use livekit_api::access_token::AccessToken;
use serde_json::{Value, json};
use tavrn_node::{config::Config, permissions as p, voice};
use tower::ServiceExt;

const DOMAIN: &str = "t.local";

struct Voice {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    voice_id: String,
}

async fn setup_with(tweak: impl FnOnce(&mut Config)) -> Voice {
    let node = test_node_with(DOMAIN, tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let voice_id = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    Voice { node, alice, bob, room_id, voice_id }
}

async fn setup() -> Voice {
    setup_with(|_| {}).await
}

fn screen() -> Value {
    json!({ "role": "screen" })
}

impl Voice {
    fn path(&self, rest: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{}/voice/{rest}", self.room_id, self.voice_id)
    }

    async fn join(&self, s: &Session) -> (StatusCode, Value) {
        self.node.post(&self.path("join"), &s.token, json!({})).await
    }

    async fn join_screen(&self, s: &Session) -> (StatusCode, Value) {
        self.node.post(&self.path("join"), &s.token, screen()).await
    }

    fn identity(&self, s: &Session) -> String {
        format!("{}@{DOMAIN}/{}", s.username, s.device_id)
    }

    fn screen_identity(&self, s: &Session) -> String {
        format!("{}#screen", self.identity(s))
    }

    fn room_name(&self) -> String {
        format!("{}:{}", self.room_id, self.voice_id)
    }

    async fn webhook(&self, event: Value) {
        assert_eq!(webhook(&self.node, event).await, StatusCode::OK);
    }

    /// LiveKit reports `identity` as connected.
    async fn connected(&self, identity: &str) {
        self.webhook(json!({ "event": "participant_joined", "room": { "name": self.room_name() }, "participant": { "identity": identity, "state": "ACTIVE" } })).await;
    }

    async fn participants(&self, s: &Session) -> Vec<Value> {
        let (st, j) = self.node.get_auth(&format!("/api/v1/rooms/{}/voice", self.room_id), &s.token).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        j["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["channel_id"] == self.voice_id.as_str())
            .map(|c| c["participants"].as_array().unwrap().clone())
            .unwrap_or_default()
    }

    async fn identities(&self, s: &Session) -> Vec<String> {
        self.participants(s).await.iter().map(|p| p["identity"].as_str().unwrap().to_string()).collect()
    }

    async fn override_everyone(&self, allow: &[u64], deny: &[u64]) {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &self.alice.token).await;
        let everyone = room["roles"][0]["id"].as_str().unwrap().to_string();
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": self.voice_id, "subject_type": "role", "subject_id": everyone, "allow": perms(allow), "deny": perms(deny) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
}

/// A LiveKit webhook signed like LiveKit does.
async fn webhook(node: &TestNode, event: Value) -> StatusCode {
    use base64::Engine;
    use sha2::Digest;
    let body = event.to_string();
    let key = node.state.voice.api_key().unwrap();
    let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body.as_bytes()));
    let jwt = AccessToken::with_api_key(&key.key, &key.secret).with_sha256(&hash).to_jwt().unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/voice/webhook")
        .header(header::CONTENT_TYPE, "application/webhook+json")
        .header(header::AUTHORIZATION, jwt)
        .body(Body::from(body))
        .unwrap();
    node.router.clone().oneshot(req).await.unwrap().status()
}

/// A POST without any body (as the web client sends `voice/join` and `voice/leave`).
async fn post_empty(node: &TestNode, path: &str, token: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, serde_json::from_slice(&body_bytes(resp).await).unwrap_or(Value::Null))
}

fn claims(node: &TestNode, token: &str) -> livekit_api::access_token::Claims {
    node.state.voice.verify(token).expect("token signed by the node")
}

#[tokio::test]
async fn the_screen_join_returns_a_publish_only_token_for_the_screen_identity() {
    let v = setup().await;
    // Without a body (the web client) and with an explicit device role, the join is the device's as before.
    let (s, j) = post_empty(&v.node, &v.path("join"), &v.alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["identity"], v.identity(&v.alice));
    let (s, j) = v.node.post(&v.path("join"), &v.alice.token, json!({ "role": "device" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["identity"], v.identity(&v.alice));
    let device = j;

    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["identity"], v.screen_identity(&v.alice));
    assert_eq!(j["room"], v.room_name());
    assert_eq!(j["url"], device["url"]);
    assert_eq!(j["limits"], device["limits"], "the owner's limits");
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.sub, v.screen_identity(&v.alice));
    assert_eq!(c.video.room, v.room_name());
    assert!(c.video.room_join);
    assert_eq!(c.video.can_subscribe, Some(false), "a screen publisher never receives anything");
    assert_eq!(c.video.can_publish, Some(true));
    assert_eq!(c.video.can_publish_sources, vec!["screen_share", "screen_share_audio"]);
    assert_eq!(c.video.can_publish_data, Some(false));
    assert_eq!(c.video.can_update_own_metadata, Some(false));
    assert!(!c.video.room_admin && !c.video.room_create && !c.video.room_list && !c.video.hidden && !c.video.recorder);
    assert!((590..=610).contains(&(c.exp - c.nbf)), "ten minutes");

    // Garbage is refused.
    for body in [json!({ "role": "camera" }), json!({ "role": "screen", "extra": 1 }), json!({ "role": 3 })] {
        let (s, j) = v.node.post(&v.path("join"), &v.bob.token, body.clone()).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("request.invalid_json")), "{body}: {j}");
    }
    // The `/rtc` proxy takes the screen token like the device's (LiveKit is not running here).
    let token = j["token"].as_str().unwrap().to_string();
    let (s, j) = v.node.req(Method::GET, &format!("/rtc/validate?access_token={token}"), None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("voice.unavailable")), "{j}");
}

#[tokio::test]
async fn the_screen_join_needs_the_device_in_the_channel_and_the_stream_permission() {
    let v = setup().await;
    // No screen publisher without its device.
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
    // Another device of the same user does not count: the screen belongs to the device that is there.
    v.join(&v.bob).await;
    let phone = v.node.login("bob").await;
    let (s, j) = v.join_screen(&phone).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
    // Without `stream` in the channel: refused like a screen share.
    v.override_everyone(&[], &[p::STREAM]).await;
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.stream_forbidden")), "{j}");
    v.override_everyone(&[], &[]).await;
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The other checks of the join hold first: a member without `connect` gets nothing.
    v.override_everyone(&[], &[p::CONNECT]).await;
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");

    // The node's screen share policy.
    let v = setup_with(|c| c.screenshare_enabled = false).await;
    v.join(&v.alice).await;
    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.stream_forbidden")), "{j}");
}

#[tokio::test]
async fn a_device_has_one_screen_publisher_until_it_leaves() {
    let v = setup().await;
    v.join(&v.alice).await;
    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Refused twice: reserved, then connected.
    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.screen_active")), "{j}");
    v.connected(&v.identity(&v.alice)).await;
    v.connected(&v.screen_identity(&v.alice)).await;
    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.screen_active")), "{j}");
    // The screen's own leave ends it alone; then a new one may start.
    let (s, _) = v.node.post(&v.path("leave"), &v.alice.token, screen()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(v.identities(&v.bob).await, vec![v.identity(&v.alice)], "the device stays");
    let (s, j) = v.join_screen(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // A rejoin of the device (a new token) keeps its screen publisher.
    v.connected(&v.screen_identity(&v.alice)).await;
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(v.identities(&v.bob).await, vec![v.identity(&v.alice), v.screen_identity(&v.alice)]);
}

#[tokio::test]
async fn the_screen_publisher_is_listed_under_its_owner_and_counts_as_the_owner() {
    let v = setup().await;
    // A channel for two: alice with her screen publisher and bob fit.
    let (s, j) = v
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", v.room_id, v.voice_id),
            &v.alice.token,
            json!({ "user_limit": 2 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let carol = v.node.register("carol").await;
    let (_, invite) = v.node.post(&format!("/api/v1/rooms/{}/invites", v.room_id), &v.alice.token, json!({})).await;
    v.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    // alice owns the room (`move_members` may exceed the user limit), so bob and carol fill it.
    v.join(&v.bob).await;
    v.connected(&v.identity(&v.bob)).await;
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut rx = v.node.state.hub.subscribe();
    v.connected(&v.screen_identity(&v.bob)).await;
    let state = next_state(&mut rx).await;
    let ps = state["participants"].as_array().unwrap();
    assert_eq!(ps.len(), 2, "{state}");
    assert_eq!(ps[1]["identity"], v.screen_identity(&v.bob));
    assert_eq!(ps[1]["screen_of"], v.identity(&v.bob));
    assert_eq!(ps[1]["user"], "bob@t.local");
    assert_eq!(ps[1]["user_id"], v.bob.user_id.as_str());
    assert_eq!(ps[1]["device_id"], v.bob.device_id.as_str());
    assert_eq!((ps[1]["muted"].as_bool(), ps[1]["camera"].as_bool()), (Some(true), Some(false)));
    assert!(ps[0].get("screen_of").is_none(), "devices carry no screen_of: {state}");
    // The second seat is free: the screen publisher takes none.
    let (s, j) = v.join(&carol).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&v.identity(&carol)).await;
    // Listed right after its owner, also when somebody connected in between.
    let ids = v.identities(&v.alice).await;
    assert_eq!(ids, vec![v.identity(&v.bob), v.screen_identity(&v.bob), v.identity(&carol)]);

    // Its screen track makes it and its owner stream.
    let track = |event: &str| json!({ "event": event, "room": { "name": v.room_name() }, "participant": { "identity": v.screen_identity(&v.bob) }, "track": { "sid": "TR_S", "source": "SCREEN_SHARE" } });
    v.webhook(track("track_published")).await;
    let ps = v.participants(&v.alice).await;
    assert_eq!((ps[0]["streaming"].as_bool(), ps[1]["streaming"].as_bool()), (Some(true), Some(true)), "{ps:?}");
    v.webhook(track("track_unpublished")).await;
    let ps = v.participants(&v.alice).await;
    assert_eq!((ps[0]["streaming"].as_bool(), ps[1]["streaming"].as_bool()), (Some(false), Some(false)), "{ps:?}");

    // A screen identity whose device is not in the channel is never listed.
    v.connected(&v.screen_identity(&v.alice)).await;
    assert!(!v.identities(&v.bob).await.contains(&v.screen_identity(&v.alice)));
    // The join answer lists it too.
    let (_, j) = v.join(&v.alice).await;
    let listed: Vec<&str> =
        j["participants"].as_array().unwrap().iter().map(|p| p["identity"].as_str().unwrap()).collect();
    assert!(listed.contains(&v.screen_identity(&v.bob).as_str()), "{j}");
}

#[tokio::test]
async fn the_screen_publisher_ends_with_its_owner() {
    let v = setup_with(|c| c.voice_reconnect_grace_secs = 1).await;
    let both = |v: &Voice| vec![v.identity(&v.bob), v.screen_identity(&v.bob)];

    // The owner's leave.
    connect_both(&v).await;
    assert_eq!(v.identities(&v.alice).await, both(&v));
    let (s, _) = post_empty(&v.node, &v.path("leave"), &v.bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(v.identities(&v.alice).await.is_empty(), "the screen publisher left with its owner");

    // A dropped owner keeps it while reconnecting; the end of the grace period removes both.
    connect_both(&v).await;
    v.webhook(json!({ "event": "participant_left", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.bob), "disconnectReason": "SIGNAL_CLOSE" } })).await;
    voice::expire_once(&v.node.state).await;
    assert_eq!(v.identities(&v.alice).await, both(&v), "kept while the owner reconnects");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    voice::expire_once(&v.node.state).await;
    assert!(v.identities(&v.alice).await.is_empty(), "gone with the owner after the grace period");

    // A moderator's disconnect.
    connect_both(&v).await;
    let (s, j) = v
        .node
        .post(&v.path(&format!("members/{}@{DOMAIN}/disconnect", v.bob.username)), &v.alice.token, json!({}))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    assert!(v.identities(&v.alice).await.is_empty());

    // Another device of the user taking over.
    connect_both(&v).await;
    let phone = v.node.login("bob").await;
    let (s, j) = v.join(&phone).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&v.identity(&phone)).await;
    assert_eq!(v.identities(&v.alice).await, vec![v.identity(&phone)]);

    // Leaving the room (a kick).
    connect_both(&v).await;
    v.node.delete(&format!("/api/v1/rooms/{}/members/{}", v.room_id, v.bob.user_id), &v.alice.token).await;
    let gone = common::within(Duration::from_secs(5), "the kicked member's voice removal", async {
        loop {
            if v.identities(&v.alice).await.iter().all(|i| !i.starts_with("bob@")) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(gone);
}

/// bob (this session's device, or the latest login) in voice with a connected screen publisher.
async fn connect_both(v: &Voice) {
    let (s, j) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&v.identity(&v.bob)).await;
    let (s, j) = v.join_screen(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&v.screen_identity(&v.bob)).await;
}

async fn next_state(rx: &mut tokio::sync::broadcast::Receiver<std::sync::Arc<tavrn_node::hub::Event>>) -> Value {
    common::within(Duration::from_secs(10), "a voice.state event on the hub", async {
        loop {
            let ev = rx.recv().await.unwrap();
            if ev.kind == "voice.state" {
                return ev.data.clone();
            }
        }
    })
    .await
}

// ---------------------------------------------------------------- calls

async fn dm(node: &TestNode, a: &Session, b: &Session) -> String {
    node.befriend(a, b).await;
    let (s, j) = node
        .post(
            "/api/v1/conversations",
            &a.token,
            json!({ "kind": "dm", "members": [format!("{}@{DOMAIN}", b.username)] }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    j["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn calls_take_a_screen_publisher_of_a_device_in_the_call() {
    let node = test_node_with(DOMAIN, |_| {}).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let id = dm(&node, &alice, &bob).await;
    let call = |rest: &str| format!("/api/v1/conversations/{id}/call/{rest}");
    let identity = |s: &Session| format!("{}@{DOMAIN}/{}", s.username, s.device_id);
    let connected = |who: String| {
        let room = format!("call:{id}");
        let node = &node;
        async move {
            assert_eq!(
                webhook(node, json!({ "event": "participant_joined", "room": { "name": room }, "participant": { "identity": who, "state": "ACTIVE" } })).await,
                StatusCode::OK
            );
        }
    };

    let (s, j) = node.post(&call("start"), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // bob is not in the call yet: no screen publisher for him.
    let (s, j) = node.post(&call("join"), &bob.token, screen()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
    assert_eq!(
        node.get_auth(&format!("/api/v1/conversations/{id}/call"), &bob.token).await.1["ringing"],
        json!(["bob@t.local"])
    );
    // alice is: a publish-only token for her screen, no ringing again, nobody answered by it.
    let (s, j) = node.post(&call("join"), &alice.token, screen()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["identity"], format!("{}#screen", identity(&alice)));
    let c = claims(&node, j["token"].as_str().unwrap());
    assert_eq!(c.video.room, format!("call:{id}"));
    assert_eq!(c.video.can_subscribe, Some(false));
    assert_eq!(c.video.can_publish_sources, vec!["screen_share", "screen_share_audio"]);
    assert_eq!(j["call"]["ringing"], json!(["bob@t.local"]), "the screen join is no answer");
    let (s, j) = node.post(&call("join"), &alice.token, screen()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.screen_active")), "{j}");

    connected(identity(&alice)).await;
    connected(format!("{}#screen", identity(&alice))).await;
    let (s, j) = node.post(&call("join"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    connected(identity(&bob)).await;
    let (_, state) = node.get_auth(&format!("/api/v1/conversations/{id}/call"), &bob.token).await;
    let ps = state["participants"].as_array().unwrap();
    assert_eq!(ps.len(), 3, "{state}");
    assert_eq!(ps[1]["screen_of"], identity(&alice));
    assert!(node.state.calls.is_active(&id));

    // The screen's own leave keeps the call and its owner.
    let (s, _) = node.post(&call("leave"), &alice.token, screen()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, state) = node.get_auth(&format!("/api/v1/conversations/{id}/call"), &bob.token).await;
    assert_eq!(state["participants"].as_array().unwrap().len(), 2, "{state}");
    assert!(node.state.calls.is_active(&id));
    // The owner's leave takes it along (and ends the DM call).
    node.post(&call("join"), &alice.token, screen()).await;
    connected(format!("{}#screen", identity(&alice))).await;
    let (s, _) = post_empty(&node, &call("leave"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!node.state.calls.is_active(&id), "a DM call ends when one of the two hangs up");
    let (_, state) = node.get_auth(&format!("/api/v1/conversations/{id}/call"), &bob.token).await;
    assert!(state["participants"].as_array().unwrap().is_empty(), "{state}");
}
