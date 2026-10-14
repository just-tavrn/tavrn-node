// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Voice (protocol/VOICE.md): join tokens, permissions and node policies, user limit, self state,
//! moderator actions, LiveKit webhooks → `voice.state`, the `/rtc` proxy, reconciliation, soundboard.
//!
//! Tests marked "LiveKit" start a real `livekit-server` child through the node's supervisor. Without the
//! binary they are skipped with a message (`just livekit-install`); with `TAVRN_TEST_REQUIRE_LIVEKIT=1`
//! (CI) a missing binary fails them instead.
use crate::common;

use std::{
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, perms, test_node_with};
use futures::{SinkExt, StreamExt};
use livekit_api::access_token::AccessToken;
use serde_json::{Value, json};
use tavrn_node::{
    config::Config,
    permissions as p,
    voice::{self, livekit::Supervisor},
};
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

// ---------------------------------------------------------------- helpers

struct Voice {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    voice_id: String,
    text_id: String,
}

async fn setup_with(tweak: impl FnOnce(&mut Config)) -> Voice {
    let node = test_node_with("t.local", tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let voice_id = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let text_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    Voice { node, alice, bob, room_id, voice_id, text_id }
}

async fn setup() -> Voice {
    setup_with(|_| {}).await
}

impl Voice {
    fn path(&self, rest: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{}/voice/{rest}", self.room_id, self.voice_id)
    }

    async fn join(&self, s: &Session) -> (StatusCode, Value) {
        self.node.post(&self.path("join"), &s.token, json!({})).await
    }

    fn identity(&self, s: &Session) -> String {
        format!("{}@t.local/{}", s.username, s.device_id)
    }

    fn room_name(&self) -> String {
        format!("{}:{}", self.room_id, self.voice_id)
    }

    /// Sends a LiveKit webhook signed like LiveKit does (`Authorization: <jwt with sha256 of the body>`).
    async fn webhook(&self, event: Value) -> (StatusCode, Value) {
        let body = event.to_string();
        let auth = sign_webhook(&self.node, &body);
        webhook_raw(&self.node, &body, Some(&auth)).await
    }

    /// LiveKit reports `s` as connected.
    async fn connected(&self, s: &Session) {
        let ev = json!({ "event": "participant_joined", "room": { "name": self.room_name() }, "participant": { "identity": self.identity(s), "state": "ACTIVE" } });
        let (st, j) = self.webhook(ev).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }

    async fn voice_states(&self, s: &Session) -> Value {
        let (st, j) = self.node.get_auth(&format!("/api/v1/rooms/{}/voice", self.room_id), &s.token).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        j
    }

    async fn participants(&self, s: &Session) -> Vec<Value> {
        let states = self.voice_states(s).await;
        states["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["channel_id"] == self.voice_id.as_str())
            .map(|c| c["participants"].as_array().unwrap().clone())
            .unwrap_or_default()
    }

    async fn override_everyone(&self, channel: &str, allow: &[u64], deny: &[u64]) {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &self.alice.token).await;
        let everyone = room["roles"][0]["id"].as_str().unwrap().to_string();
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": channel, "subject_type": "role", "subject_id": everyone, "allow": perms(allow), "deny": perms(deny) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
}

fn sign_webhook(node: &TestNode, body: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let key = node.state.voice.api_key().unwrap();
    let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body.as_bytes()));
    AccessToken::with_api_key(&key.key, &key.secret).with_sha256(&hash).to_jwt().unwrap()
}

async fn webhook_raw(node: &TestNode, body: &str, auth: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/voice/webhook")
        .header(header::CONTENT_TYPE, "application/webhook+json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    let resp = node.router.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Grants of a LiveKit token, verified with the node's secret.
fn claims(node: &TestNode, token: &str) -> livekit_api::access_token::Claims {
    node.state.voice.verify(token).expect("token signed by the node")
}

/// Waits for the next event of `kind` on an in-process hub subscription.
async fn next_event(
    rx: &mut tokio::sync::broadcast::Receiver<std::sync::Arc<tavrn_node::hub::Event>>,
    kind: &str,
) -> Value {
    common::within(Duration::from_secs(10), &format!("a {kind} event on the hub"), async {
        loop {
            let ev = rx.recv().await.unwrap();
            if ev.kind == kind {
                return ev.data.clone();
            }
        }
    })
    .await
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A client WebSocket on `addr` signed in with `token`, once the node answered `ready`: only then is the
/// connection subscribed to the node's events (`ws.rs`), so nothing published afterwards can pass it by.
async fn client_socket(addr: std::net::SocketAddr, token: &str) -> Socket {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/v1/ws")).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    let ready = common::within(Duration::from_secs(5), "the WebSocket's ready", ws.next()).await.unwrap().unwrap();
    assert!(ready.to_text().unwrap().contains("\"ready\""), "{ready:?}");
    ws
}

/// The next `voice.state` event on a client WebSocket.
async fn next(ws: &mut Socket) -> Value {
    common::within(Duration::from_secs(10), "a voice.state event on the WebSocket", async {
        loop {
            if let Message::Text(t) = ws.next().await.unwrap().unwrap() {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "voice.state" {
                    return v["data"].clone();
                }
            }
        }
    })
    .await
}

fn livekit_available() -> bool {
    if voice::livekit::find_binary("livekit-server").is_some() {
        return true;
    }
    if std::env::var_os("TAVRN_TEST_REQUIRE_LIVEKIT").is_some() {
        panic!("livekit-server is not installed but TAVRN_TEST_REQUIRE_LIVEKIT is set");
    }
    eprintln!("SKIPPED: livekit-server is not installed (`just livekit-install` puts it into ~/.local/bin)");
    false
}

/// A free local TCP port and a UDP range of 20 ports for one LiveKit instance.
fn livekit_ports() -> (u16, String) {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let base = 52000 + (std::process::id() % 40) as u16 * 200 + NEXT.fetch_add(20, Ordering::SeqCst);
    (tcp, format!("{base}-{}", base + 19))
}

/// A node with voice whose LiveKit runs on free ports, served on a real TCP port (webhooks, `/rtc`).
async fn livekit_setup() -> (Voice, u16) {
    livekit_setup_with(|_| {}).await
}

async fn livekit_setup_with(tweak: impl FnOnce(&mut Config)) -> (Voice, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (lk_port, udp) = livekit_ports();
    let v = setup_with(|c| {
        c.listen = format!("127.0.0.1:{port}");
        c.livekit_port = lk_port;
        c.rtc_udp_port_range = udp;
        tweak(c);
    })
    .await;
    let router = v.node.router.clone();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap()
    });
    (v, port)
}

async fn wait_reachable(port: u16) {
    common::wait_until(Duration::from_secs(10), &format!("LiveKit answers on port {port}"), || {
        voice::livekit::reachable(port)
    })
    .await;
}

// ---------------------------------------------------------------- join and grants

#[tokio::test]
async fn join_returns_a_token_with_exactly_the_allowed_grants() {
    let v = setup().await;
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["url"], "ws://t.local:8080", "LiveKit SDKs append /rtc themselves");
    assert_eq!(j["room"], v.room_name());
    assert_eq!(j["identity"], v.identity(&v.alice));
    assert!(j["participants"].as_array().unwrap().is_empty());
    assert!(j["epoch"].is_null(), "no MLS group yet");
    assert_eq!(j["reconnect_grace_secs"], 45);
    assert_eq!(j["limits"]["audio_bitrate_kbps"], 64);
    assert_eq!(j["limits"]["audio_fec"], true, "Opus in-band FEC is announced");
    assert_eq!(j["limits"]["screenshare"], json!({ "enabled": true, "max_resolution": "1080p", "max_fps": 30 }));
    assert_eq!(j["limits"]["camera"], json!({ "enabled": true, "max_resolution": "720p", "max_fps": 30 }));
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.sub, v.identity(&v.alice));
    assert_eq!(c.video.room, v.room_name());
    assert!(c.video.room_join && !c.video.room_admin && !c.video.room_create && !c.video.room_list);
    assert_eq!(c.video.can_publish, Some(true));
    assert_eq!(c.video.can_publish_sources, vec!["microphone", "camera", "screen_share", "screen_share_audio"]);
    assert_eq!(c.video.can_subscribe, Some(true));
    // The owner has every bit: the soundboard signal (data) and the priority attribute (VOICE.md §7a, §8).
    assert_eq!(c.video.can_publish_data, Some(true));
    assert_eq!(c.video.can_update_own_metadata, Some(true));
    assert!((590..=610).contains(&(c.exp - c.nbf)), "ten minutes");
    assert!(j["expires_at"].is_string());

    // Bob may not stream or use the camera in this channel; listening only without `speak`.
    v.override_everyone(&v.voice_id, &[], &[p::STREAM, p::USE_CAMERA]).await;
    let (s, j) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(claims(&v.node, j["token"].as_str().unwrap()).video.can_publish_sources, vec!["microphone"]);
    assert_eq!(j["limits"]["screenshare"]["enabled"], false);
    assert_eq!(j["limits"]["camera"]["enabled"], false);
    v.override_everyone(&v.voice_id, &[], &[p::STREAM, p::USE_CAMERA, p::SPEAK]).await;
    let (_, j) = v.join(&v.bob).await;
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.video.can_publish, Some(false), "no source at all: no publishing");
    assert!(c.video.can_publish_sources.is_empty());
}

#[tokio::test]
async fn attribute_updates_need_priority_speaker_and_data_needs_the_soundboard() {
    let v = setup().await;
    // `priority_speaker` is off for @everyone by default: no own attribute updates.
    let (s, j) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.video.can_update_own_metadata, Some(false), "a client without the bit cannot set `priority`");
    assert_eq!(c.video.can_publish_data, Some(true), "use_soundboard is on for @everyone");
    // Granted in the channel: the token allows the `priority` attribute; without the soundboard no data.
    v.override_everyone(&v.voice_id, &[p::PRIORITY_SPEAKER], &[p::USE_SOUNDBOARD]).await;
    let (_, j) = v.join(&v.bob).await;
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.video.can_update_own_metadata, Some(true));
    assert_eq!(c.video.can_publish_data, Some(false));
    assert!(!c.video.room_admin && !c.video.hidden, "nothing else widens");
}

#[tokio::test]
async fn join_checks_channel_kind_membership_permissions_and_timeouts() {
    let v = setup().await;
    let carol = v.node.register("carol").await;
    let (s, j) = v.join(&carol).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.not_member")), "{j}");
    let text = format!("/api/v1/rooms/{}/channels/{}/voice/join", v.room_id, v.text_id);
    let (s, j) = v.node.post(&text, &v.alice.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("voice.not_voice_channel")), "{j}");
    let missing = format!("/api/v1/rooms/{}/channels/01J9ZZZZZZZZZZZZZZZZZZZZZZ/voice/join", v.room_id);
    let (s, j) = v.node.post(&missing, &v.alice.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("channel.not_found")), "{j}");
    let (s, _) = v.node.req(Method::POST, &v.path("join"), None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    v.override_everyone(&v.voice_id, &[], &[p::CONNECT]).await;
    let (s, j) = v.join(&v.bob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
    v.override_everyone(&v.voice_id, &[], &[]).await;
    let (s, _) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK);

    let (s, j) = v
        .node
        .put(
            &format!("/api/v1/rooms/{}/members/{}/timeout", v.room_id, v.bob.user_id),
            &v.alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = v.join(&v.bob).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
}

#[tokio::test]
async fn node_policies_remove_sources_and_are_announced() {
    let v = setup_with(|c| {
        c.screenshare_enabled = false;
        c.camera_enabled = false;
        c.voice_max_bitrate_kbps = 48;
    })
    .await;
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.video.can_publish_sources, vec!["microphone"], "screen share and camera are off on this node");
    assert_eq!(j["limits"]["screenshare"]["enabled"], false);
    assert_eq!(j["limits"]["camera"]["enabled"], false);
    assert_eq!(j["limits"]["audio_bitrate_kbps"], 48, "the default channel bitrate is capped by the node");

    let wk = common::body_json(v.node.get("/.well-known/tavrn").await).await;
    assert_eq!(wk["policies"]["voice_max_bitrate_kbps"], 48);
    assert_eq!(wk["policies"]["screenshare"]["enabled"], false);
    assert_eq!(wk["policies"]["camera"], json!({ "enabled": false, "max_resolution": "720p", "max_fps": 30 }));
    let caps: Vec<&str> = wk["capabilities"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert!(caps.contains(&"voice") && caps.contains(&"soundboard") && !caps.contains(&"screenshare"), "{caps:?}");
    let node = common::body_json(v.node.get("/api/v1/node").await).await;
    assert_eq!(node["voice"]["enabled"], true);
    assert_eq!(node["voice"]["max_bitrate_kbps"], 48);
    assert_eq!(node["voice"]["camera"]["enabled"], false);

    // A new voice channel without explicit bitrate gets the node maximum; more is refused.
    let path = format!("/api/v1/rooms/{}/channels", v.room_id);
    let (s, j) = v.node.post(&path, &v.alice.token, json!({ "kind": "voice", "name": "Quiet" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["bitrate_kbps"], 48);
    let (s, j) =
        v.node.post(&path, &v.alice.token, json!({ "kind": "voice", "name": "Loud", "bitrate_kbps": 64 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.bitrate_too_high")), "{j}");
}

#[tokio::test]
async fn the_default_cap_allows_the_music_preset_and_refuses_more() {
    // Default node: TAVRN_VOICE_MAX_BITRATE_KBPS = 192, so every client preset up to "Music" (stereo,
    // 192 kbps) is reachable; new channels still start at 64 kbps.
    let v = setup().await;
    let node = common::body_json(v.node.get("/api/v1/node").await).await;
    assert_eq!(node["voice"]["max_bitrate_kbps"], 192);
    let wk = common::body_json(v.node.get("/.well-known/tavrn").await).await;
    assert_eq!(wk["policies"]["voice_max_bitrate_kbps"], 192);
    let path = format!("/api/v1/rooms/{}/channels", v.room_id);
    let (s, j) = v.node.post(&path, &v.alice.token, json!({ "kind": "voice", "name": "New" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["bitrate_kbps"], 64, "the default of a new channel stays 64 kbps");

    let channel = format!("{path}/{}", v.voice_id);
    for kbps in [8, 32, 64, 128, 192] {
        let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "bitrate_kbps": kbps })).await;
        assert_eq!(s, StatusCode::OK, "{kbps}: {j}");
        assert_eq!(j["bitrate_kbps"], kbps);
    }
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["limits"]["audio_bitrate_kbps"], 192);
    assert_eq!(j["limits"]["audio_fec"], true);
    let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "bitrate_kbps": 193 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.bitrate_too_high")), "{j}");
    let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "bitrate_kbps": 7 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "below the Opus minimum of the protocol: {j}");
    // Members without `manage_channels` cannot change the quality.
    let (s, j) = v.node.patch(&channel, &v.bob.token, json!({ "bitrate_kbps": 8 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

#[tokio::test]
async fn a_lowered_cap_limits_existing_channels_at_join() {
    // A channel set to the music preset keeps its setting when the operator lowers the cap later; the join
    // hands out the node's maximum.
    let v = setup_with(|c| c.voice_max_bitrate_kbps = 128).await;
    sqlx::query("UPDATE channels SET bitrate_kbps = 192 WHERE id = $1")
        .bind(&v.voice_id)
        .execute(&v.node.state.db)
        .await
        .unwrap();
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["limits"]["audio_bitrate_kbps"], 128);
    // Other settings of such a channel stay editable; only a new bitrate above the cap is refused.
    let channel = format!("/api/v1/rooms/{}/channels/{}", v.room_id, v.voice_id);
    let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "user_limit": 5 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["user_limit"].as_i64(), j["bitrate_kbps"].as_i64()), (Some(5), Some(192)));
    let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "bitrate_kbps": 192 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.bitrate_too_high")), "{j}");
    let (s, j) = v.node.patch(&channel, &v.alice.token, json!({ "bitrate_kbps": 128 })).await;
    assert_eq!((s, j["bitrate_kbps"].as_i64()), (StatusCode::OK, Some(128)), "{j}");
    // Calls stay at the default channel bitrate below the cap, and follow a cap below it.
    let low = setup_with(|c| c.voice_max_bitrate_kbps = 48).await;
    assert_eq!(low.node.state.config.call_audio_bitrate_kbps(), 48);
    assert_eq!(v.node.state.config.call_audio_bitrate_kbps(), 64);
}

#[tokio::test]
async fn voice_disabled_by_the_node_is_503() {
    let v = setup_with(|c| c.voice_enabled = false).await;
    let (s, j) = v.join(&v.alice).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("voice.disabled")), "{j}");
    let (s, j) = webhook_raw(&v.node, r#"{"event":"room_started"}"#, Some("x")).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("voice.disabled")), "{j}");
    let (s, j) = v.node.get_auth("/rtc/validate?access_token=x", &v.alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("voice.disabled")), "{j}");
    assert!(v.node.state.voice.api_key().is_none(), "no LiveKit key is created");
    let health = common::body_json(v.node.get("/healthz").await).await;
    assert_eq!(health, json!({ "status": "ok", "voice": "disabled" }));
    let ready = v.node.get("/readyz").await;
    assert_eq!(ready.status(), StatusCode::OK, "LiveKit is not required without voice");
    let wk = common::body_json(v.node.get("/.well-known/tavrn").await).await;
    assert!(!wk["capabilities"].as_array().unwrap().iter().any(|c| c == "voice"));
    assert_eq!(wk["policies"]["voice_enabled"], false);
}

#[tokio::test]
async fn health_reports_voice_and_readiness_needs_livekit() {
    let v = setup().await;
    let health = common::body_json(v.node.get("/healthz").await).await;
    assert_eq!(health, json!({ "status": "ok", "voice": "stopped" }), "not supervised in library use");
    let ready = v.node.get("/readyz").await;
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let j = common::body_json(ready).await;
    assert_eq!((j["database"].as_bool(), j["livekit"].as_bool()), (Some(true), Some(false)), "{j}");
}

// ---------------------------------------------------------------- user limit, leave, self state

#[tokio::test]
async fn user_limit_counts_reserved_and_connected_participants() {
    let v = setup().await;
    let (s, j) = v
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", v.room_id, v.voice_id),
            &v.alice.token,
            json!({ "user_limit": 1 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let carol = v.node.register("carol").await;
    let (_, invite) = v.node.post(&format!("/api/v1/rooms/{}/invites", v.room_id), &v.alice.token, json!({})).await;
    v.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;

    let (s, _) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "joining again with the same device does not count twice");
    let (s, j) = v.join(&carol).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.channel_full")), "{j}");
    assert_eq!(j["meta"]["user_limit"], 1);
    let (s, _) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "members with move_members may exceed the user limit");

    let (s, _) = v.node.post(&v.path("leave"), &v.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
    // Alice (moderator) does not count against the limit of the others either? She does: limit is full.
    v.node.post(&v.path("leave"), &v.alice.token, json!({})).await;
    let (s, j) = v.join(&carol).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn self_state_changes_are_checked_and_published() {
    let v = setup_with(|c| c.camera_enabled = false).await;
    v.override_everyone(&v.voice_id, &[], &[p::STREAM]).await;
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
    v.join(&v.bob).await;
    let mut rx = v.node.state.hub.subscribe();
    v.connected(&v.bob).await;
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["room_id"], v.room_id.as_str());
    assert_eq!(ev["participants"][0]["identity"], v.identity(&v.bob));

    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": true, "deafened": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["participants"][0]["muted"], true);
    assert_eq!(j["participants"][0]["deafened"], true);
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["participants"][0]["deafened"], true);
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "streaming": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.stream_forbidden")), "{j}");
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "camera": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.camera_forbidden")), "{j}");
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": "yes" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
}

// ---------------------------------------------------------------- webhooks

#[tokio::test]
async fn livekit_webhooks_become_voice_state_events_over_the_websocket() {
    let v = setup().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = v.node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut ws = client_socket(addr, &v.bob.token).await;

    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&v.alice).await;
    let state = next(&mut ws).await;
    assert_eq!(state["channel_id"], v.voice_id.as_str());
    let p0 = &state["participants"][0];
    assert_eq!(p0["user"], "alice@t.local");
    assert_eq!(p0["device_id"], v.alice.device_id.as_str());
    assert_eq!(p0["user_id"], v.alice.user_id.as_str());
    assert_eq!(
        (p0["muted"].as_bool(), p0["streaming"].as_bool(), p0["camera"].as_bool()),
        (Some(false), Some(false), Some(false))
    );

    let track = |event: &str, source: &str| json!({ "event": event, "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice) }, "track": { "sid": "TR_1", "source": source } });
    v.webhook(track("track_published", "SCREEN_SHARE")).await;
    assert_eq!(next(&mut ws).await["participants"][0]["streaming"], true);
    v.webhook(track("track_published", "CAMERA")).await;
    assert_eq!(next(&mut ws).await["participants"][0]["camera"], true);
    v.webhook(track("track_unpublished", "SCREEN_SHARE")).await;
    assert_eq!(next(&mut ws).await["participants"][0]["streaming"], false);
    let (s, _) = v.webhook(track("track_published", "MICROPHONE")).await;
    assert_eq!(s, StatusCode::OK, "microphone tracks change nothing visible");

    // A lost connection keeps the participant as reconnecting (grace period), a rejoin continues the entry.
    assert_eq!(p0["connection"], "connected");
    let left = json!({ "event": "participant_left", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice), "disconnectReason": "SIGNAL_CLOSE" } });
    v.webhook(left).await;
    let state = next(&mut ws).await;
    assert_eq!(state["participants"].as_array().unwrap().len(), 1);
    assert_eq!(state["participants"][0]["connection"], "reconnecting");
    assert_eq!(state["participants"][0]["camera"], true, "the state is kept while reconnecting");
    v.connected(&v.alice).await;
    let state = next(&mut ws).await;
    assert_eq!(state["participants"].as_array().unwrap().len(), 1, "never twice");
    assert_eq!(state["participants"][0]["connection"], "connected");
    // A second connection of the same identity pushes the first out: nothing changes.
    let dup = json!({ "event": "participant_left", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice), "disconnectReason": "DUPLICATE_IDENTITY" } });
    v.webhook(dup).await;
    assert_eq!(v.participants(&v.bob).await[0]["connection"], "connected");
    // Hanging up removes the participant at once.
    let left = json!({ "event": "participant_left", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice), "disconnectReason": "CLIENT_INITIATED" } });
    v.webhook(left).await;
    assert_eq!(next(&mut ws).await["participants"], json!([]));

    // Rooms that are no voice channels and unknown events are ignored.
    let (s, _) = v.webhook(json!({ "event": "room_started", "room": { "name": "something-else" } })).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = v.webhook(json!({ "event": "egress_started" })).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn dropped_participants_leave_after_the_grace_period() {
    let v = setup_with(|c| c.voice_reconnect_grace_secs = 1).await;
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    let mut rx = v.node.state.hub.subscribe();
    let aborted = json!({ "event": "participant_connection_aborted", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.bob) } });
    v.webhook(aborted).await;
    assert_eq!(next_event(&mut rx, "voice.state").await["participants"][0]["connection"], "reconnecting");
    // Still within the grace period: nothing happens.
    voice::expire_once(&v.node.state).await;
    assert_eq!(v.participants(&v.alice).await.len(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    voice::expire_once(&v.node.state).await;
    assert_eq!(next_event(&mut rx, "voice.state").await["participants"], json!([]), "announced as left");
    assert!(v.participants(&v.alice).await.is_empty());
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
}

/// VOICE.md §5 "Session start": `session_started_at` is set with the first connected participant, kept while
/// anybody is connected or reconnecting (whoever that is), cleared with the last one, and carried by every voice
/// state (the room's list, `/users/me/voice`, the join answer, the `voice.state` event).
#[tokio::test]
async fn the_voice_state_carries_the_session_start() {
    let v = setup_with(|c| c.voice_reconnect_grace_secs = 1).await;
    let states = v.voice_states(&v.alice).await;
    assert_eq!(states["items"].as_array().unwrap().len(), 0, "nothing before anybody joins");
    let mut rx = v.node.state.hub.subscribe();
    let (s, j) = v.join(&v.alice).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["session_started_at"].is_null(), "reserved, not connected: {j}");
    v.connected(&v.alice).await;
    let ev = next_event(&mut rx, "voice.state").await;
    let started = ev["session_started_at"].as_str().expect("set with the first participant").to_string();
    assert!(started.ends_with('Z'), "RFC 3339: {started}");
    let item = &v.voice_states(&v.bob).await["items"][0];
    assert_eq!(item["session_started_at"], started.as_str());
    let (s, mine) = v.node.get_auth("/api/v1/users/me/voice", &v.bob.token).await;
    assert_eq!(s, StatusCode::OK, "{mine}");
    assert_eq!(mine["rooms"][0]["channels"][0]["session_started_at"], started.as_str());

    // Bob joins later: the join answer tells him when the session began; Alice leaving changes nothing.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let (s, j) = v.join(&v.bob).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["session_started_at"], started.as_str(), "the late joiner sees the channel's start");
    v.connected(&v.bob).await;
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(
        (ev["participants"].as_array().unwrap().len(), ev["session_started_at"].as_str()),
        (2, Some(started.as_str()))
    );
    let left = json!({ "event": "participant_left", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice), "disconnectReason": "CLIENT_INITIATED" } });
    v.webhook(left).await;
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["participants"].as_array().unwrap().len(), 1);
    assert_eq!(ev["session_started_at"], started.as_str(), "the session is the channel's, not the first joiner's");
    assert_eq!(v.voice_states(&v.alice).await["items"][0]["session_started_at"], started.as_str());

    // A dropped connection keeps it through the grace period; the expiry of the last participant clears it.
    let aborted = json!({ "event": "participant_connection_aborted", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.bob) } });
    v.webhook(aborted).await;
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(
        (ev["participants"][0]["connection"].as_str(), ev["session_started_at"].as_str()),
        (Some("reconnecting"), Some(started.as_str()))
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    voice::expire_once(&v.node.state).await;
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!((ev["participants"].as_array().unwrap().len(), ev["session_started_at"].is_null()), (0, true), "{ev}");
    assert!(v.voice_states(&v.alice).await["items"].as_array().unwrap().is_empty());

    // The next session starts anew.
    v.join(&v.alice).await;
    v.connected(&v.alice).await;
    let ev = next_event(&mut rx, "voice.state").await;
    let again = ev["session_started_at"].as_str().unwrap();
    assert!(again > started.as_str(), "a new session: {again} after {started}");
}

#[tokio::test]
async fn a_second_device_of_the_same_user_replaces_the_first() {
    let v = setup().await;
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    let phone = v.node.login("bob").await;
    let (s, j) = v.join(&phone).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    v.connected(&phone).await;
    let ps = v.participants(&v.alice).await;
    assert_eq!(ps.len(), 1, "one voice session per user: {ps:?}");
    assert_eq!(ps[0]["identity"], v.identity(&phone));
    // The old device can no longer report state for this channel.
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("voice.not_connected")), "{j}");
}

#[tokio::test]
async fn webhooks_must_be_signed_by_livekit() {
    let v = setup().await;
    let body = json!({ "event": "participant_joined", "room": { "name": v.room_name() }, "participant": { "identity": v.identity(&v.alice) } }).to_string();
    let (s, j) = webhook_raw(&v.node, &body, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("voice.webhook_invalid")), "{j}");
    let (s, _) = webhook_raw(&v.node, &body, Some("garbage")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Valid signature for another body: the sha256 claim does not match.
    let other = sign_webhook(&v.node, "{}");
    let (s, _) = webhook_raw(&v.node, &body, Some(&other)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // A token signed with a different secret.
    let forged = AccessToken::with_api_key(
        &v.node.state.voice.api_key().unwrap().key,
        "an-attacker-secret-an-attacker-secret-xx",
    )
    .with_sha256("x")
    .to_jwt()
    .unwrap();
    let (s, _) = webhook_raw(&v.node, &body, Some(&forged)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(v.participants(&v.alice).await.is_empty(), "nothing was applied");
    // A bearer prefix is accepted too.
    let auth = format!("Bearer {}", sign_webhook(&v.node, &body));
    let (s, _) = webhook_raw(&v.node, &body, Some(&auth)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.participants(&v.alice).await.len(), 1);
    // Identities of unknown users are not shown.
    let ghost = json!({ "event": "participant_joined", "room": { "name": v.room_name() }, "participant": { "identity": "mallory@t.local/01J9ZZZZZZZZZZZZZZZZZZZZZZ" } });
    v.webhook(ghost).await;
    assert_eq!(v.participants(&v.alice).await.len(), 1);
}

// ---------------------------------------------------------------- moderation

#[tokio::test]
async fn moderators_mute_disconnect_and_move_members() {
    let v = setup().await;
    let carol = v.node.register("carol").await;
    let (_, invite) = v.node.post(&format!("/api/v1/rooms/{}/invites", v.room_id), &v.alice.token, json!({})).await;
    v.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    let member = |who: &str, action: &str| v.path(&format!("members/{who}@t.local/{action}"));

    // Without mute_members/move_members.
    let (s, j) = v.node.post(&member("bob", "mute"), &carol.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.mute_forbidden")), "{j}");
    let (s, j) = v.node.post(&member("bob", "disconnect"), &carol.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.move_forbidden")), "{j}");
    // Members cannot moderate the owner.
    let (s, j) = v.node.post(&member("nobody", "mute"), &v.alice.token, json!({ "muted": true })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("member.not_found")), "{j}");

    let mut rx = v.node.state.hub.subscribe();
    let (s, j) = v.node.post(&member("bob", "mute"), &v.alice.token, json!({ "muted": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(
        (ev["participants"][0]["muted"].as_bool(), ev["participants"][0]["server_muted"].as_bool()),
        (Some(true), Some(true))
    );
    let (s, j) = v.node.patch(&v.path("state"), &v.bob.token, json!({ "muted": false })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.server_muted")), "{j}");
    let (_, j) = v.join(&v.bob).await;
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert!(
        !c.video.can_publish_sources.contains(&"microphone".to_string()),
        "a server-muted member gets no microphone"
    );
    assert!(c.video.can_publish_sources.contains(&"camera".to_string()));
    let (s, _) = v.node.post(&member("bob", "mute"), &v.alice.token, json!({ "muted": false })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, j) = v.join(&v.bob).await;
    assert!(
        claims(&v.node, j["token"].as_str().unwrap()).video.can_publish_sources.contains(&"microphone".to_string())
    );

    // Move to another voice channel: the member is disconnected here and told where to join.
    let (s, other) = v
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", v.room_id),
            &v.alice.token,
            json!({ "kind": "voice", "name": "Two" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    let other_id = other["id"].as_str().unwrap();
    let (s, j) = v.node.post(&member("bob", "move"), &v.alice.token, json!({ "channel_id": v.text_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("voice.not_voice_channel")), "{j}");
    let (s, j) = v.node.post(&member("bob", "move"), &v.alice.token, json!({ "channel_id": other_id })).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let ev = next_event(&mut rx, "voice.move").await;
    assert_eq!(
        ev,
        json!({ "room_id": v.room_id, "from_channel_id": v.voice_id, "channel_id": other_id, "user_id": v.bob.user_id })
    );
    assert!(v.participants(&v.alice).await.is_empty());

    // Disconnect.
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    let (s, j) = v.node.post(&member("bob", "disconnect"), &v.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    assert!(v.participants(&v.alice).await.is_empty());
    let (s, j) = v.node.post(&member("bob", "disconnect"), &v.alice.token, json!({})).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("voice.not_connected")), "{j}");

    let (_, log) = v.node.get_auth(&format!("/api/v1/rooms/{}/audit-log?limit=200", v.room_id), &v.alice.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    for a in ["voice.mute", "voice.unmute", "voice.move", "voice.disconnect"] {
        assert!(actions.contains(&a), "{a} in {actions:?}");
    }
}

#[tokio::test]
async fn kicked_members_leave_voice_and_others_see_it() {
    let v = setup().await;
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    assert_eq!(v.participants(&v.alice).await.len(), 1);
    let mut rx = v.node.state.hub.subscribe();
    let (s, j) = v.node.delete(&format!("/api/v1/rooms/{}/members/{}", v.room_id, v.bob.user_id), &v.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["participants"], json!([]));
    assert!(v.participants(&v.alice).await.is_empty());
}

// ---------------------------------------------------------------- /rtc proxy

#[tokio::test]
async fn rtc_proxy_refuses_requests_without_a_valid_token() {
    let v = setup().await;
    for path in ["/rtc/validate", "/rtc/validate?access_token=garbage", "/rtc/v1/validate?access_token=x.y.z"] {
        let (s, j) = v.node.req(Method::GET, path, None, None).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("voice.token_invalid")), "{path}: {j}");
    }
    let (_, j) = v.join(&v.bob).await;
    let token = j["token"].as_str().unwrap().to_string();
    // Unknown sub-paths are not forwarded.
    let (s, _) = v.node.req(Method::GET, &format!("/rtc/admin?access_token={token}"), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A valid token while LiveKit is not running.
    let (s, j) = v.node.req(Method::GET, &format!("/rtc/validate?access_token={token}"), None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("voice.unavailable")), "{j}");
    // The token of a member who was kicked afterwards is refused before it reaches LiveKit.
    v.node.delete(&format!("/api/v1/rooms/{}/members/{}", v.room_id, v.bob.user_id), &v.alice.token).await;
    let (s, j) = v.node.req(Method::GET, &format!("/rtc/validate?access_token={token}"), None, None).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
    // A token in the Authorization header works the same way.
    let (s, j) = v.node.get_auth("/rtc/validate", &token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
}

// ---------------------------------------------------------------- soundboard

#[tokio::test]
async fn soundboard_clips_are_managed_with_manage_emojis_and_limited() {
    let v = setup().await;
    let base = format!("/api/v1/rooms/{}/soundboard", v.room_id);
    let upload = |token: String, name: &str, mime: &str, duration: &str, body: Vec<u8>| {
        let (base, node) = (base.clone(), &v.node);
        let headers = [
            ("tavrn-sound-name", name.to_string()),
            ("content-type", mime.to_string()),
            ("tavrn-sound-duration-ms", duration.to_string()),
        ];
        async move {
            let h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let (s, _, b) = node.raw(Method::POST, &base, &token, &h, body).await;
            (s, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null))
        }
    };
    let clip = vec![7u8; 2048];
    let (s, j) = upload(v.bob.token.clone(), "Fanfare", "audio/ogg", "1200", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("soundboard.manage_forbidden")), "{j}");
    let (s, sound) = upload(v.alice.token.clone(), "Fanfare%20%F0%9F%8E%BA", "audio/ogg", "1200", clip.clone()).await;
    assert_eq!(s, StatusCode::CREATED, "{sound}");
    assert_eq!(
        (sound["name"].as_str(), sound["duration_ms"].as_i64(), sound["size"].as_i64()),
        (Some("Fanfare 🎺"), Some(1200), Some(2048))
    );
    let (s, j) = upload(v.alice.token.clone(), "Fanfare%20%F0%9F%8E%BA", "audio/ogg", "1200", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("soundboard.name_taken")), "{j}");
    let (s, j) = upload(v.alice.token.clone(), "", "audio/ogg", "1200", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("soundboard.name_invalid")), "{j}");
    let (s, j) = upload(v.alice.token.clone(), &"x".repeat(33), "audio/ogg", "1200", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("soundboard.name_invalid")), "{j}");
    let (s, j) = upload(v.alice.token.clone(), "Image", "image/png", "1200", clip.clone()).await;
    assert_eq!(
        (s, j["code"].as_str()),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("soundboard.type_not_allowed")),
        "{j}"
    );
    let (s, j) = upload(v.alice.token.clone(), "Lang", "audio/ogg", "5001", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("soundboard.too_long")), "{j}");
    let (s, j) = upload(v.alice.token.clone(), "Without", "audio/ogg", "abc", clip.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("soundboard.too_long")), "{j}");
    let (s, j) = upload(v.alice.token.clone(), "Gross", "audio/ogg", "1000", vec![0u8; 1024 * 1024 + 1]).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("soundboard.too_large")), "{j}");

    let (s, list) = v.node.get_auth(&base, &v.bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let id = sound["id"].as_str().unwrap();
    let resp = v.node.get_with(&format!("{base}/{id}/audio"), &v.bob.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "audio/ogg");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert_eq!(body_bytes(resp).await.to_vec(), clip);
    let carol = v.node.register("carol").await;
    let (s, _) = v.node.get_auth(&base, &carol.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "members only");

    // At most 50 clips per room.
    for i in 1..50 {
        let (s, j) = upload(v.alice.token.clone(), &format!("s{i}"), "audio/mpeg", "100", vec![1u8; 16]).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    let (s, j) = upload(v.alice.token.clone(), "too much", "audio/mpeg", "100", vec![1u8; 16]).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("soundboard.limit")), "{j}");

    let (s, _) = v.node.delete(&format!("{base}/{id}"), &v.bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = v.node.delete(&format!("{base}/{id}"), &v.alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = v.node.delete(&format!("{base}/{id}"), &v.alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("soundboard.not_found")), "{j}");
    let resp = v.node.get_with(&format!("{base}/{id}/audio"), &v.bob.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let (_, log) = v.node.get_auth(&format!("/api/v1/rooms/{}/audit-log?limit=200", v.room_id), &v.alice.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"soundboard.create") && actions.contains(&"soundboard.delete"), "{actions:?}");
}

// ---------------------------------------------------------------- with a real LiveKit

#[tokio::test]
async fn livekit_is_supervised_and_reconciliation_removes_ghosts() {
    if !livekit_available() {
        return;
    }
    let (v, _) = livekit_setup().await;
    let supervisor = Supervisor::start(&v.node.state).unwrap();
    wait_reachable(v.node.state.config.livekit_port).await;
    let health = common::body_json(v.node.get("/healthz").await).await;
    assert_eq!(health, json!({ "status": "ok", "voice": "running" }));
    let ready = v.node.get("/readyz").await;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(common::body_json(ready).await["livekit"], true);
    let yaml =
        std::fs::read_to_string(std::path::Path::new(&v.node.state.config.data_dir).join("livekit.yaml")).unwrap();
    assert!(
        yaml.contains("bind_addresses: [\"127.0.0.1\"]")
            && !yaml.contains(v.node.state.voice.api_key().unwrap().secret.as_str())
    );

    // A participant LiveKit does not know (lost webhook, crash) becomes reconnecting in the reconciliation
    // and is gone once its grace period ran out: no ghosts.
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    assert_eq!(v.participants(&v.alice).await.len(), 1);
    let mut rx = v.node.state.hub.subscribe();
    voice::reconcile_once(&v.node.state).await.unwrap();
    assert_eq!(next_event(&mut rx, "voice.state").await["participants"][0]["connection"], "reconnecting");
    let after_grace = std::time::Instant::now() + Duration::from_secs(v.node.state.config.voice_reconnect_grace_secs);
    assert_eq!(v.node.state.voice.participants().expire(after_grace).len(), 1);
    assert!(v.participants(&v.alice).await.is_empty());

    // Moderator actions talk to LiveKit; a participant it does not know is no error.
    v.join(&v.bob).await;
    v.connected(&v.bob).await;
    let (s, j) = v.node.post(&v.path("members/bob@t.local/mute"), &v.alice.token, json!({ "muted": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = v.node.post(&v.path("members/bob@t.local/disconnect"), &v.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    supervisor.stop().await;
    assert_eq!(common::body_json(v.node.get("/healthz").await).await["voice"], "stopped");
    assert!(!voice::livekit::reachable(v.node.state.config.livekit_port).await, "LiveKit was stopped");
}

#[tokio::test]
async fn a_missing_livekit_binary_is_a_clear_startup_error() {
    let v = setup_with(|c| c.livekit_binary = "/nonexistent/livekit-server".into()).await;
    let err = Supervisor::start(&v.node.state).err().expect("start fails").to_string();
    assert!(err.contains("livekit-server not found") && err.contains("just livekit-install"), "{err}");
}

#[tokio::test]
async fn rtc_signaling_is_proxied_to_livekit_and_webhooks_arrive() {
    if !livekit_available() {
        return;
    }
    let (v, port) = livekit_setup().await;
    let supervisor = Supervisor::start(&v.node.state).unwrap();
    wait_reachable(v.node.state.config.livekit_port).await;
    let mut rx = v.node.state.hub.subscribe();
    let (_, j) = v.join(&v.bob).await;
    let token = j["token"].as_str().unwrap().to_string();

    // HTTP validation goes through the node to LiveKit.
    let resp = reqwest::get(format!("http://127.0.0.1:{port}/rtc/validate?access_token={token}")).await.unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // The signaling WebSocket: LiveKit answers with its JoinResponse (binary protobuf).
    let url =
        format!("ws://127.0.0.1:{port}/rtc?access_token={token}&protocol=16&sdk=rust&version=0.0.1&auto_subscribe=1");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.expect("proxied WebSocket");
    let first = common::within(Duration::from_secs(10), "LiveKit's JoinResponse", ws.next()).await.unwrap().unwrap();
    assert!(matches!(first, Message::Binary(ref b) if !b.is_empty()), "{first:?}");
    let rooms = v.node.state.voice.rooms().unwrap();
    let present = rooms.list_participants(&v.room_name()).await.unwrap();
    assert!(present.iter().any(|p| p.identity == v.identity(&v.bob)), "LiveKit knows the participant");

    // LiveKit sends `participant_joined` only once media flows (ICE), which this test has no WebRTC stack
    // for; the reconciliation sees the signaling participant and shows it.
    voice::reconcile_once(&v.node.state).await.unwrap();
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["participants"][0]["identity"], v.identity(&v.bob));

    // The connection breaks: LiveKit's own (signed) `participant_left` webhook reaches the node, which keeps
    // the participant as reconnecting for the grace period.
    ws.close(None).await.unwrap();
    drop(ws);
    let ev = next_event(&mut rx, "voice.state").await;
    assert_eq!(ev["participants"][0]["connection"], "reconnecting", "kept by LiveKit's webhook: {ev}");

    // A moderator disconnect closes the signaling connection.
    let (_, j) = v.join(&v.bob).await;
    let token = j["token"].as_str().unwrap().to_string();
    let url =
        format!("ws://127.0.0.1:{port}/rtc?access_token={token}&protocol=16&sdk=rust&version=0.0.1&auto_subscribe=1");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.expect("proxied WebSocket");
    common::within(Duration::from_secs(10), "LiveKit's JoinResponse", ws.next()).await.unwrap().unwrap();
    voice::reconcile_once(&v.node.state).await.unwrap();
    assert_eq!(next_event(&mut rx, "voice.state").await["participants"].as_array().unwrap().len(), 1);
    let (s, j) = v.node.post(&v.path("members/bob@t.local/disconnect"), &v.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    common::within(Duration::from_secs(10), "the proxied connection ends after the disconnect", async {
        while let Some(Ok(m)) = ws.next().await {
            if m.is_close() {
                break;
            }
        }
    })
    .await;

    let (_, j) = v.join(&v.bob).await;
    let token = j["token"].as_str().unwrap().to_string();
    // LiveKit's Rust SDK (the desktop app's native voice engine) sends the token as `Authorization: Bearer`: the node
    // checks it and hands it on to LiveKit, over HTTP and on the WebSocket.
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/rtc/validate"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut req = format!("ws://127.0.0.1:{port}/rtc?protocol=16&sdk=rust&version=0.0.1&auto_subscribe=1")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let (mut ws, _) = tokio_tungstenite::connect_async(req).await.expect("proxied WebSocket with a bearer token");
        let first =
            common::within(Duration::from_secs(10), "LiveKit's JoinResponse", ws.next()).await.unwrap().unwrap();
        assert!(matches!(first, Message::Binary(ref b) if !b.is_empty()), "{first:?}");
        ws.close(None).await.unwrap();
    }
    supervisor.stop().await;
}

// ---------------------------------------------------------------- mass move

/// A user who joined the room and connected to `channel`.
async fn in_voice(v: &Voice, name: &str, channel: &str) -> Session {
    let s = v.node.register(name).await;
    let (_, invite) = v.node.post(&format!("/api/v1/rooms/{}/invites", v.room_id), &v.alice.token, json!({})).await;
    v.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &s.token, json!({})).await;
    connect_to(v, &s, channel).await;
    s
}

async fn connect_to(v: &Voice, s: &Session, channel: &str) {
    let (st, j) =
        v.node.post(&format!("/api/v1/rooms/{}/channels/{channel}/voice/join", v.room_id), &s.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let ev = json!({ "event": "participant_joined", "room": { "name": format!("{}:{channel}", v.room_id) }, "participant": { "identity": v.identity(s), "state": "ACTIVE" } });
    assert_eq!(v.webhook(ev).await.0, StatusCode::OK);
}

async fn voice_channel(v: &Voice, name: &str) -> String {
    let (s, j) = v
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", v.room_id),
            &v.alice.token,
            json!({ "kind": "voice", "name": name }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn mass_move_respects_permissions_ranks_and_the_user_limit() {
    let v = setup().await;
    let lounge = voice_channel(&v, "Lounge").await;
    let target = voice_channel(&v, "Raid").await;
    let (s, _) = v
        .node
        .patch(&format!("/api/v1/rooms/{}/channels/{target}", v.room_id), &v.alice.token, json!({ "user_limit": 2 }))
        .await;
    assert_eq!(s, StatusCode::OK);
    connect_to(&v, &v.bob, &v.voice_id).await;
    let carol = in_voice(&v, "carol", &v.voice_id).await;
    let dave = in_voice(&v, "dave", &lounge).await;
    let url = format!("/api/v1/rooms/{}/voice/move-all", v.room_id);

    // Without move_members; invalid targets.
    let (s, j) = v.node.post(&url, &v.bob.token, json!({ "to_channel_id": target })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.move_forbidden")), "{j}");
    let (s, j) = v.node.post(&url, &v.alice.token, json!({ "to_channel_id": v.text_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("voice.not_voice_channel")), "{j}");
    let (s, j) = v.node.post(&url, &v.alice.token, json!({ "from_channel_id": target, "to_channel_id": target })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("voice.same_channel")), "{j}");

    // Only the main channel: bob and carol fit (limit 2).
    let mut rx = v.node.state.hub.subscribe();
    let (s, j) =
        v.node.post(&url, &v.alice.token, json!({ "from_channel_id": v.voice_id, "to_channel_id": target })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut moved: Vec<&str> = j["moved"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
    moved.sort_unstable();
    assert_eq!(moved, vec!["bob@t.local", "carol@t.local"]);
    assert_eq!(j["skipped"], json!([]));
    let ev = next_event(&mut rx, "voice.move").await;
    assert_eq!(ev["channel_id"], target.as_str());
    assert!(v.participants(&v.alice).await.is_empty(), "the main channel is empty");
    // They rejoin the target (as the client does after voice.move).
    connect_to(&v, &v.bob, &target).await;
    connect_to(&v, &carol, &target).await;

    // Everybody into the full channel: dave stays, reported as channel_full (partial result).
    let (s, j) = v.node.post(&url, &v.alice.token, json!({ "to_channel_id": target })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["moved"], json!([]));
    assert_eq!(j["skipped"], json!([{ "user": "dave@t.local", "reason": "channel_full" }]));
    // Everybody back into the main channel (no limit), the owner included without a rank check.
    connect_to(&v, &v.alice, &lounge).await;
    let (s, j) = v.node.post(&url, &v.alice.token, json!({ "to_channel_id": v.voice_id })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut moved: Vec<&str> = j["moved"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
    moved.sort_unstable();
    assert_eq!(moved, vec!["alice@t.local", "bob@t.local", "carol@t.local", "dave@t.local"]);
    // A moderator may not move the owner (rank): reported as outranked.
    // (`move_members` can no longer be granted to @everyone: a "Mover" role for dave.)
    let (s, role) = v
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", v.room_id),
            &v.alice.token,
            json!({ "name": "Mover", "permissions": perms(&[p::MOVE_MEMBERS]), "position": 1 }),
        )
        .await;
    assert!(s.is_success(), "{role}");
    let (s, j) = v
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", v.room_id, dave.user_id),
            &v.alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    connect_to(&v, &v.alice, &lounge).await;
    let (s, j) = v.node.post(&url, &dave.token, json!({ "from_channel_id": lounge, "to_channel_id": target })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["skipped"], json!([{ "user": "alice@t.local", "reason": "outranked" }]));
    let (_, log) = v.node.get_auth(&format!("/api/v1/rooms/{}/audit-log?limit=200", v.room_id), &v.alice.token).await;
    let entries: Vec<&Value> = log.as_array().unwrap().iter().filter(|e| e["action"] == "voice.move_all").collect();
    assert_eq!(entries.len(), 4, "every mass move is audited");
}

// ---------------------------------------------------------------- media hostnames (VOICE.md §10.2)

/// A/AAAA answers for every host; `None`: the lookup fails.
struct FixedLookup(Option<Vec<std::net::IpAddr>>);

impl voice::advertise::HostLookup for FixedLookup {
    fn lookup(
        &self,
        _host: String,
    ) -> futures::future::BoxFuture<'static, std::io::Result<voice::advertise::HostAnswer>> {
        let answer = self.0.clone();
        Box::pin(async move { answer.map(|ips| (ips, None)).ok_or_else(|| std::io::Error::other("NXDOMAIN")) })
    }
}

#[tokio::test]
async fn media_hostnames_are_resolved_and_an_unresolvable_one_is_reported() {
    let v = setup_with(|c| {
        c.rtc_external_ip = Some("media.example.org".into());
        c.rtc_advertise_ips = "lan.example.org".into();
    })
    .await;
    // Nothing resolves: voice keeps running (STUN in production, the interfaces in development), /healthz
    // names the problem.
    let task = voice::advertise::start_with(&v.node.state, std::sync::Arc::new(FixedLookup(None))).await.unwrap();
    task.abort();
    let health = common::body_json(v.node.get("/healthz").await).await;
    assert_eq!(health["voice"], "stopped");
    let problem = health["voice_problem"].as_str().unwrap();
    assert!(problem.contains("media.example.org, lan.example.org"), "{problem}");
    let (_, j) = v.node.post("/api/v1/voice/test", &v.bob.token, json!({})).await;
    assert_eq!(j["rtc"]["mode"], "local");

    // Resolved: the addresses are announced (development nodes keep private ones, production only with
    // TAVRN_RTC_ADVERTISE_PRIVATE), the problem is gone.
    let ips = vec!["8.8.8.8".parse().unwrap(), "10.0.0.5".parse().unwrap(), "2a00:1450::1".parse().unwrap()];
    let task = voice::advertise::start_with(&v.node.state, std::sync::Arc::new(FixedLookup(Some(ips)))).await.unwrap();
    task.abort();
    let health = common::body_json(v.node.get("/healthz").await).await;
    assert_eq!(health, json!({ "status": "ok", "voice": "stopped" }));
    let (s, j) = v.node.post("/api/v1/voice/test", &v.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["rtc"]["mode"], "explicit");
    assert_eq!(j["rtc"]["addresses"], json!(["8.8.8.8", "2a00:1450::1"]));
    assert_eq!(j["rtc"]["ice_aliases"], json!(["10.0.0.5"]), "both names resolve to the same addresses");

    // Literal addresses only: nothing to resolve.
    let plain = setup_with(|c| c.rtc_external_ip = Some("203.0.113.7".into())).await;
    assert!(voice::advertise::start_with(&plain.node.state, std::sync::Arc::new(FixedLookup(None))).await.is_none());
}

// ---------------------------------------------------------------- connection test (VOICE.md §10.4)

#[tokio::test]
async fn connection_test_tokens_join_only_their_empty_hidden_room() {
    let v = setup_with(|c| {
        c.rtc_external_ip = Some("203.0.113.7".into());
        c.rtc_advertise_ips = "2001:db8::7,192.168.0.23".into();
        c.rtc_tcp_port = 7881;
    })
    .await;
    let (s, j) = v.node.post("/api/v1/voice/test", &v.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["rtc"]["mode"], "explicit");
    assert_eq!(j["rtc"]["addresses"], json!(["203.0.113.7", "2001:db8::7"]));
    assert_eq!(j["rtc"]["ice_aliases"], json!(["192.168.0.23"]));
    assert_eq!((j["rtc"]["tcp_port"].as_u64(), j["rtc"]["turn_udp"].as_bool()), (Some(7881), Some(false)));
    let room = j["room"].as_str().unwrap();
    assert!(room.starts_with("test:") && room.len() == 31, "{room}");
    let c = claims(&v.node, j["token"].as_str().unwrap());
    assert_eq!(c.video.room, room);
    assert!(c.video.hidden && c.video.room_join);
    assert_eq!((c.video.can_publish, c.video.can_publish_data), (Some(false), Some(false)));
    assert!(c.exp - c.nbf <= 70, "a minute");
    assert!(c.sub.starts_with("bob@t.local/"));
    // The voice join tells clients the extra addresses too.
    let (_, join) = v.join(&v.bob).await;
    assert_eq!(join["ice_aliases"], json!(["192.168.0.23"]));
    // `/rtc` lets the test token through (502: LiveKit is not running in this test) …
    let check = |token: String| {
        let router = v.node.router.clone();
        async move {
            let req =
                Request::builder().uri(format!("/rtc/validate?access_token={token}")).body(Body::empty()).unwrap();
            router.oneshot(req).await.unwrap().status()
        }
    };
    assert_eq!(check(j["token"].as_str().unwrap().to_string()).await, StatusCode::BAD_GATEWAY);
    // … webhooks of test rooms change nothing.
    let ev = json!({ "event": "participant_joined", "room": { "name": room }, "participant": { "identity": c.sub, "state": "ACTIVE" } });
    assert_eq!(v.webhook(ev).await.0, StatusCode::OK);
    assert!(v.voice_states(&v.alice).await["items"].as_array().unwrap().is_empty());
    let off = test_node_with("off.local", |c| c.voice_enabled = false).await;
    let s = off.register("alice").await;
    let (st, j) = off.post("/api/v1/voice/test", &s.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("voice.disabled")));
}

/// A free TCP port on the loopback interface.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A free UDP port.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn generated_livekit_configs_are_accepted_by_livekit_in_every_connectivity_mode() {
    if !livekit_available() {
        return;
    }
    // Explicit addresses (public IPv4 + global IPv6 + a LAN alias), ICE/TCP and TURN over UDP and TLS.
    let tcp = free_tcp_port();
    let turn_tls = free_tcp_port();
    let turn_udp = free_udp_port();
    let (v, _) = livekit_setup_with(|c| {
        c.rtc_external_ip = Some("203.0.113.7".into());
        c.rtc_advertise_ips = "2001:db8::7,192.168.0.23".into();
        c.rtc_tcp_port = tcp;
        c.rtc_turn_enabled = true;
        c.rtc_turn_udp_port = turn_udp;
        c.rtc_turn_tls_port = turn_tls;
        c.rtc_turn_relay_port_range = "39000-39099".into();
    })
    .await;
    let supervisor = Supervisor::start(&v.node.state).unwrap();
    wait_reachable(v.node.state.config.livekit_port).await;
    let yaml =
        std::fs::read_to_string(std::path::Path::new(&v.node.state.config.data_dir).join("livekit.yaml")).unwrap();
    for expected in [
        format!("  tcp_port: {tcp}\n  allow_tcp_fallback: true\n"),
        "  use_external_ip: false\n  node_ip: \"203.0.113.7,2001:db8::7\"\n".to_string(),
        "  advertise_internal_ip: true\n  enable_loopback_candidate: true\n".to_string(),
        format!(
            "turn:\n  enabled: true\n  domain: \"turn.t.local\"\n  tls_port: {turn_tls}\n  external_tls: true\n  udp_port: {turn_udp}\n"
        ),
    ] {
        assert!(yaml.contains(&expected), "missing {expected:?} in\n{yaml}");
    }
    assert!(!yaml.contains("192.168.0.23"), "aliases are handed to the clients, LiveKit takes one address per family");
    // LiveKit listens on the ICE/TCP and the TURN/TLS port (the proxy's plain TCP backend).
    for port in [tcp, turn_tls] {
        common::wait_until(Duration::from_secs(5), &format!("LiveKit listens on TCP {port}"), || async move {
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        })
        .await;
    }
    supervisor.stop().await;

    // Development: local addresses, no TCP, no TURN — still accepted.
    let (v, _) = livekit_setup_with(|_| {}).await;
    let supervisor = Supervisor::start(&v.node.state).unwrap();
    wait_reachable(v.node.state.config.livekit_port).await;
    let yaml =
        std::fs::read_to_string(std::path::Path::new(&v.node.state.config.data_dir).join("livekit.yaml")).unwrap();
    assert!(yaml.contains("  tcp_port: 0\n  allow_tcp_fallback: false\n  use_external_ip: false\n"), "{yaml}");
    assert!(yaml.contains("turn:\n  enabled: false\n") && !yaml.contains("node_ip"), "{yaml}");
    supervisor.stop().await;
}

/// Authorization audit (2026-10-09): a mass move without `from_channel_id` walks every active voice channel; who sits
/// in one the mover cannot view stays hidden (as in `GET /rooms/{id}/voice`), it is not reported as `move_forbidden`.
#[tokio::test]
async fn authz_mass_move_does_not_reveal_hidden_voice_channels() {
    let v = setup().await;
    let staff = voice_channel(&v, "Staff").await;
    let target = voice_channel(&v, "Raid").await;
    v.override_everyone(&staff, &[], &[p::VIEW_CHANNEL]).await;
    connect_to(&v, &v.alice, &staff).await;
    let dave = in_voice(&v, "dave", &v.voice_id).await;
    let (s, role) = v
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", v.room_id),
            &v.alice.token,
            json!({ "name": "Mover", "permissions": perms(&[p::MOVE_MEMBERS]), "position": 1 }),
        )
        .await;
    assert!(s.is_success(), "{role}");
    let (s, j) = v
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", v.room_id, dave.user_id),
            &v.alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = v
        .node
        .post(&format!("/api/v1/rooms/{}/voice/move-all", v.room_id), &dave.token, json!({ "to_channel_id": target }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(!j.to_string().contains("alice@t.local"), "the hidden channel's participant leaks: {j}");
}

/// Authorization audit (2026-10-09): losing `view_channel` or `connect` through a role or override change ends a
/// running voice session within the next visibility refresh (the event that changed it), announced as `voice.state`.
#[tokio::test]
async fn authz_losing_access_ends_the_voice_session() {
    let v = setup().await;
    assert_eq!(v.join(&v.bob).await.0, StatusCode::OK);
    v.connected(&v.bob).await;
    assert_eq!(v.participants(&v.alice).await.len(), 1);
    let mut rx = v.node.state.hub.subscribe();
    v.override_everyone(&v.voice_id, &[], &[p::VIEW_CHANNEL]).await;
    assert_eq!(next_event(&mut rx, "voice.state").await["participants"], json!([]), "announced as left");
    assert!(v.participants(&v.alice).await.is_empty(), "bob still sits in the channel he cannot see");
}

#[tokio::test]
async fn authz_losing_connect_ends_the_voice_session() {
    let v = setup().await;
    assert_eq!(v.join(&v.bob).await.0, StatusCode::OK);
    v.connected(&v.bob).await;
    assert_eq!(v.join(&v.alice).await.0, StatusCode::OK);
    v.connected(&v.alice).await;
    v.override_everyone(&v.voice_id, &[], &[p::CONNECT]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let left: Vec<Value> = v.participants(&v.alice).await;
    assert_eq!(left.len(), 1, "the owner stays: {left:?}");
    assert_eq!(left[0]["identity"], v.identity(&v.alice));
}

// ---------------------------------------------------------------- GET /users/me/voice

/// `(channel id, [user addresses])` of one channel.
type ChannelUsers = (String, Vec<String>);

/// The rooms of `GET /users/me/voice` as `room id → [(channel id, [user addresses])]`, sorted.
async fn my_voice(v: &Voice, s: &Session) -> Vec<(String, Vec<ChannelUsers>)> {
    let (st, j) = v.node.get_auth("/api/v1/users/me/voice", &s.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let mut rooms: Vec<(String, Vec<ChannelUsers>)> = j["rooms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let mut channels: Vec<ChannelUsers> = r["channels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    assert_eq!(c["room_id"], r["room_id"], "{j}");
                    let users = c["participants"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|p| p["user"].as_str().unwrap().to_string())
                        .collect();
                    (c["channel_id"].as_str().unwrap().to_string(), users)
                })
                .collect();
            channels.sort();
            (r["room_id"].as_str().unwrap().to_string(), channels)
        })
        .collect();
    rooms.sort();
    rooms
}

/// `GET /users/me/voice` (VOICE.md §5): the voice state of every room the requester is a member of, with only the
/// channels they can view, like `GET /rooms/{id}/voice` per room; nothing of rooms they are not in.
#[tokio::test]
async fn my_voice_lists_the_viewable_channels_of_all_member_rooms() {
    let v = setup().await;
    let staff = voice_channel(&v, "Staff").await;
    v.override_everyone(&staff, &[], &[p::VIEW_CHANNEL]).await;
    connect_to(&v, &v.alice, &staff).await;
    connect_to(&v, &v.bob, &v.voice_id).await;
    // A second room of alice's that bob is not in, with dave in its voice channel.
    let other = v.node.create_room(&v.alice.token, "Other").await;
    let other_id = other["id"].as_str().unwrap().to_string();
    let other_voice = other["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let dave = v.node.register("dave").await;
    let (_, invite) = v.node.post(&format!("/api/v1/rooms/{other_id}/invites"), &v.alice.token, json!({})).await;
    v.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &dave.token, json!({})).await;
    let (st, j) = v
        .node
        .post(&format!("/api/v1/rooms/{other_id}/channels/{other_voice}/voice/join"), &dave.token, json!({}))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let ev = json!({ "event": "participant_joined", "room": { "name": format!("{other_id}:{other_voice}") }, "participant": { "identity": v.identity(&dave), "state": "ACTIVE" } });
    assert_eq!(v.webhook(ev).await.0, StatusCode::OK);

    // Bob: his room only, without the hidden staff channel.
    assert_eq!(
        my_voice(&v, &v.bob).await,
        vec![(v.room_id.clone(), vec![(v.voice_id.clone(), vec!["bob@t.local".to_string()])])]
    );
    // Alice (owner of both): both rooms, the staff channel too.
    let mut room_channels =
        vec![(v.voice_id.clone(), vec!["bob@t.local".to_string()]), (staff.clone(), vec!["alice@t.local".to_string()])];
    room_channels.sort();
    let mut expected = vec![
        (v.room_id.clone(), room_channels),
        (other_id.clone(), vec![(other_voice.clone(), vec!["dave@t.local".to_string()])]),
    ];
    expected.sort();
    assert_eq!(my_voice(&v, &v.alice).await, expected);
    // Dave: the other room only. Somebody in no room: nothing.
    assert_eq!(
        my_voice(&v, &dave).await,
        vec![(other_id.clone(), vec![(other_voice.clone(), vec!["dave@t.local".to_string()])])]
    );
    let eve = v.node.register("eve").await;
    assert!(my_voice(&v, &eve).await.is_empty());
    // A room the user left disappears.
    let (st, _) = v.node.post(&format!("/api/v1/rooms/{other_id}/leave"), &dave.token, json!({})).await;
    assert!(st.is_success());
    assert!(my_voice(&v, &dave).await.is_empty());
    // Without a session: 401.
    let (st, _) = v.node.get_auth("/api/v1/users/me/voice", "nope").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn my_voice_is_empty_when_voice_is_disabled() {
    let v = setup_with(|c| c.voice_enabled = false).await;
    let (st, j) = v.node.get_auth("/api/v1/users/me/voice", &v.alice.token).await;
    assert_eq!((st, j), (StatusCode::OK, json!({ "rooms": [] })));
}

// ---------------------------------------------------------------- revocations

/// A disabled or node-banned account leaves every voice channel at once; a logout removes only that device.
#[tokio::test]
async fn ended_sessions_leave_voice() {
    for how in ["disable", "ban", "logout", "logout_other"] {
        let v = setup().await;
        let phone = v.node.login("bob").await;
        v.join(&v.bob).await;
        v.connected(&v.bob).await;
        assert_eq!(v.participants(&v.alice).await.len(), 1);
        let mut rx = v.node.state.hub.subscribe();
        let (s, j) = match how {
            "disable" => {
                v.node
                    .patch(
                        &format!("/api/v1/admin/users/{}", v.bob.user_id),
                        &v.alice.token,
                        json!({ "disabled": true }),
                    )
                    .await
            }
            "ban" => v.node.post("/api/v1/admin/bans", &v.alice.token, json!({ "subject": "bob@t.local" })).await,
            "logout" => v.node.post("/api/v1/auth/logout", &v.bob.token, json!({})).await,
            _ => v.node.post("/api/v1/auth/logout", &phone.token, json!({})).await,
        };
        assert!(s.is_success(), "{how}: {s} {j}");
        if how == "logout_other" {
            // Another device of bob signs out: his voice device stays.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(v.participants(&v.alice).await.len(), 1, "{how}");
            continue;
        }
        let ev = next_event(&mut rx, "voice.state").await;
        assert_eq!(ev["participants"], json!([]), "{how}");
        assert!(v.participants(&v.alice).await.is_empty(), "{how}");
    }
}

/// A leave answers without waiting for LiveKit's room service; a rejoin of the same device waits until that removal is
/// done, so the late removal can never disconnect the new connection.
#[tokio::test]
async fn a_leave_answers_at_once_and_a_rejoin_waits_for_the_livekit_removal() {
    use tokio::io::AsyncWriteExt;
    // A LiveKit room service that holds every request until released, then refuses it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release, released) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut released = released.clone();
            tokio::spawn(async move {
                let _ = released.wait_for(|r| *r).await;
                let _ =
                    socket.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
            });
        }
    });
    let v = setup_with(|c| c.livekit_port = port).await;
    let key = (v.room_id.clone(), v.voice_id.clone());
    let identity = v.identity(&v.bob);
    assert_eq!(v.join(&v.bob).await.0, StatusCode::OK);

    let (s, _) =
        common::within(Duration::from_secs(2), "the leave", v.node.post(&v.path("leave"), &v.bob.token, json!({})))
            .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(v.participants(&v.alice).await.is_empty(), "gone for the others at once");
    assert!(voice::removal_pending(&v.node.state, &key, &identity), "LiveKit still holds the removal");

    let rejoin = v.join(&v.bob);
    tokio::pin!(rejoin);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut rejoin).await.is_err(),
        "the rejoin waits for the pending removal"
    );
    release.send(true).unwrap();
    let (s, j) = common::within(Duration::from_secs(5), "the rejoin", rejoin).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(!voice::removal_pending(&v.node.state, &key, &identity));
}
