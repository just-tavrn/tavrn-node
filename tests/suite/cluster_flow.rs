// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Several instances of one node behind a load balancer (`TAVRN_CACHE_URL`, docs/SCALING.md): every scenario runs
//! twice, with an in-process cache shared by the instances and with the Valkey of `TAVRN_TEST_CACHE_URL`
//! (skipped with a message when unset; `docker run -d --name tavrn-test-valkey -p 56379:6379 valkey/valkey:8`).
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::{
    cluster::{self, Instance, domain, elect, in_process, instances, share_factors, wait_for},
    password,
};
use futures::{SinkExt, StreamExt, future::BoxFuture, stream::BoxStream};
use serde_json::{Value, json};
use tavrn_node::cache::{Cache, CacheError, CacheResult, memory::InProcess};
use tokio_tungstenite::tungstenite::Message as WsMessage;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const LEASE: Duration = Duration::from_millis(900);

/// Runs `$scenario(cache)` with a shared in-process cache and, if configured, with Valkey.
macro_rules! both {
    ($scenario:ident, $in_process:ident, $valkey:ident) => {
        #[tokio::test]
        async fn $in_process() {
            $scenario(in_process()).await;
        }

        #[tokio::test]
        async fn $valkey() {
            if let Some((cache, _valkey)) = cluster::valkey(stringify!($valkey)).await {
                $scenario(cache).await;
            }
        }
    };
}

async fn connect(url: &str, token: &str, last_event_id: Option<&str>) -> Socket {
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    let hello = json!({ "op": "hello", "token": token, "last_event_id": last_event_id });
    ws.send(WsMessage::Text(hello.to_string().into())).await.unwrap();
    assert_eq!(next(&mut ws, 5000).await.unwrap()["op"], "ready");
    ws
}

/// The next JSON frame within `ms` (pings answered and skipped).
async fn next(ws: &mut Socket, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["op"] == "ping" {
                    continue;
                }
                return Some(v);
            }
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

/// The next frame that is an event of `kind` (or, for `"resync"`, the resync hint) within `ms`.
async fn wait_event(ws: &mut Socket, kind: &str, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis() as u64;
        let frame = next(ws, left.max(1)).await?;
        if (kind == "resync" && frame["op"] == "resync") || frame["type"] == kind {
            return Some(frame);
        }
    }
}

/// A plaintext room of `owner` on instance `a` that `others` joined.
async fn room(inst: &Instance, owner: &common::Session, others: &[&common::Session]) -> (String, String) {
    let node = &inst.node;
    let room = node.plaintext_room(&owner.token, "Raid").await;
    let id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &owner.token, json!({})).await;
    for o in others {
        let (st, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &o.token, json!({})).await;
        assert!(st.is_success(), "{j}");
    }
    (id, common::TestNode::text_channel(&room))
}

async fn mine(n: &Instance, token: &str) -> Value {
    n.node.get_auth("/api/v1/users/me/presence", token).await.1
}

async fn attempt(n: &Instance) -> (StatusCode, Value) {
    let body = json!({ "username": "alice", "password": "wrong-password-1", "device_name": "x" });
    n.node.req(Method::POST, "/api/v1/auth/login", None, Some(body)).await
}

async fn login(inst: &Instance, proof: Value) -> Value {
    let body = json!({ "username": "alice", "password": password("alice"), "device_name": "B", "device": proof });
    let (s, pre) = inst.node.req(Method::POST, "/api/v1/auth/login", None, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{pre}");
    inst.node.verify_second_factor("alice", pre["preauth_token"].as_str().unwrap()).await
}

async fn exchange(inst: &Instance, code: &str, verifier: &str) -> (StatusCode, Value) {
    let (s, _, body) = inst
        .node
        .raw(
            Method::POST,
            "/api/v1/auth/connect/token",
            "",
            &[("origin", "https://visit.example"), ("content-type", "application/json")],
            json!({ "code": code, "code_verifier": verifier }).to_string().into_bytes(),
        )
        .await;
    (s, serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null))
}

// ---------------------------------------------------------------- hub fan-out

async fn events_reach_websockets_on_every_instance(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let bob = a.node.register("bob").await;
    let (room_id, channel) = room(a, &alice, &[&bob]).await;
    let mut ws_alice = connect(&a.ws_url(), &alice.token, None).await;
    let mut ws_bob = connect(&b.ws_url(), &bob.token, None).await;

    // Bob writes through instance B: Alice's WebSocket on A gets it, and Bob's on B.
    let (st, sent) = b.node.send(&bob.token, &room_id, &channel, "hello from B").await;
    assert_eq!(st, StatusCode::CREATED, "{sent}");
    let ev = wait_event(&mut ws_alice, "message.create", 5000).await.expect("event on A");
    assert_eq!(ev["data"]["id"], sent["id"]);
    assert_eq!(ev["data"]["content"]["body"], "hello from B");
    let own = wait_event(&mut ws_bob, "message.create", 5000).await.expect("event on B");
    assert_eq!(own["id"], ev["id"], "one event, one id on every instance");
    // And the other way round, exactly once each.
    let (st, _) = a.node.send(&alice.token, &room_id, &channel, "hello from A").await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(
        wait_event(&mut ws_bob, "message.create", 5000).await.unwrap()["data"]["content"]["body"],
        "hello from A"
    );
    assert!(wait_event(&mut ws_bob, "message.create", 400).await.is_none(), "no duplicate");
    assert!(wait_event(&mut ws_alice, "message.create", 5000).await.is_some());
    assert!(wait_event(&mut ws_alice, "message.create", 400).await.is_none(), "no duplicate");
}
both!(events_reach_websockets_on_every_instance, fanout_in_process, fanout_valkey);

async fn a_reconnect_with_another_instances_event_id_resyncs(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let (room_id, channel) = room(a, &alice, &[]).await;
    let mut ws = connect(&a.ws_url(), &alice.token, None).await;
    a.node.send(&alice.token, &room_id, &channel, "x").await;
    let last = wait_event(&mut ws, "message.create", 5000).await.unwrap()["id"].as_str().unwrap().to_string();
    drop(ws);
    // The load balancer sends the reconnect to B: B cannot replay A's events, the client reloads.
    let mut ws = connect(&b.ws_url(), &alice.token, Some(&last)).await;
    assert_eq!(next(&mut ws, 3000).await.unwrap(), json!({ "op": "resync" }));
}
both!(a_reconnect_with_another_instances_event_id_resyncs, last_event_id_in_process, last_event_id_valkey);

// ---------------------------------------------------------------- presence

async fn presence_counts_connections_on_every_instance(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let bob = a.node.register("bob").await;
    room(a, &alice, &[&bob]).await;
    let mut ws_bob = connect(&a.ws_url(), &bob.token, None).await;
    assert_eq!(mine(a, &alice.token).await["effective"], "offline");

    // Alice connects to B: A counts her as online, Bob (on A) gets her presence.
    let ws_alice = connect(&b.ws_url(), &alice.token, None).await;
    let update = loop {
        // Bob's own presence comes first (his connection on A).
        let ev = wait_event(&mut ws_bob, "presence.update", 5000).await.expect("presence via the bus");
        if ev["data"]["user_id"] == alice.user_id.as_str() {
            break ev;
        }
    };
    assert_eq!(update["data"]["status"], "online");
    wait_for(Duration::from_secs(5), || tavrn_node::presence::is_online(&a.node.state, &alice.user_id)).await;
    assert_eq!(mine(a, &alice.token).await["effective"], "online");
    let (_, list) = a.node.get_auth("/api/v1/presence", &bob.token).await;
    assert!(list.as_array().unwrap().iter().any(|p| p["user_id"] == alice.user_id.as_str()), "{list}");

    // Her device goes idle through A (the REST call and the WebSocket on different instances): both agree.
    let (st, j) = a.node.put("/api/v1/users/me/presence", &alice.token, json!({ "status": "idle" })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while mine(b, &alice.token).await["effective"] != "idle" {
        assert!(tokio::time::Instant::now() < deadline, "idle not replicated to B");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(mine(a, &alice.token).await["effective"], "idle");

    // She disconnects from B: A sees her offline, Bob gets the update.
    drop(ws_alice);
    wait_for(Duration::from_secs(5), || !tavrn_node::presence::is_online(&a.node.state, &alice.user_id)).await;
    let offline = loop {
        let ev = wait_event(&mut ws_bob, "presence.update", 5000).await.expect("offline update");
        if ev["data"]["status"] == "offline" {
            break ev;
        }
    };
    assert_eq!(offline["data"]["user_id"], alice.user_id.as_str());
}
both!(presence_counts_connections_on_every_instance, presence_in_process, presence_valkey);

// ---------------------------------------------------------------- shared rate limits and single-use values

async fn a_login_limit_filled_on_one_instance_blocks_on_the_other(cache: Arc<dyn Cache>) {
    // Production values (development nodes allow 1000 per minute).
    let nodes = cluster::instances_with(&domain(), cache, 2, |state| {
        state.login_limiter = Arc::new(tavrn_node::cache::limiter::SharedLimiter::new(
            "login",
            3,
            Duration::from_secs(60),
            &state.cluster,
        ));
    })
    .await;
    let (a, b) = (&nodes[0], &nodes[1]);
    a.node.register("alice").await;
    for _ in 0..3 {
        assert_eq!(attempt(a).await.0, StatusCode::UNAUTHORIZED);
    }
    let (st, j) = attempt(b).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "{j}");
    // Even the right password waits on B now.
    let body = json!({ "username": "alice", "password": password("alice"), "device_name": "x" });
    assert_eq!(b.node.req(Method::POST, "/api/v1/auth/login", None, Some(body)).await.0, StatusCode::TOO_MANY_REQUESTS);
}
both!(a_login_limit_filled_on_one_instance_blocks_on_the_other, login_limit_in_process, login_limit_valkey);

async fn a_device_nonce_of_one_instance_is_spent_on_another(cache: Arc<dyn Cache>) {
    use common::e2ee::b64;
    // The crypto helpers attest devices of `…@t.local`.
    let nodes = instances(common::e2ee::DOMAIN, cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.crypto_user("alice").await;
    share_factors(&a.node, &b.node);
    let device = alice.client.device();
    let (_, n) = a.node.req(Method::POST, "/api/v1/auth/device-nonce", None, None).await;
    let nonce = n["nonce"].as_str().unwrap().to_string();
    let proof = json!({ "id": device.device_id(), "nonce": nonce, "proof": b64(&device.sign_login(&nonce).unwrap()) });
    // Issued by A, accepted by B (shared node key and spend table): the session continues the device.
    let session = login(b, proof.clone()).await;
    assert_eq!(session["device_id"], alice.session.device_id.as_str());
    // A replay on A is refused (single use across instances): a new device.
    let replay = login(a, proof).await;
    assert_ne!(replay["device_id"], alice.session.device_id.as_str());
}
both!(a_device_nonce_of_one_instance_is_spent_on_another, device_nonce_in_process, device_nonce_valkey);

async fn connect_codes_are_exchanged_on_another_instance(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = tavrn_node::routes::connect::s256(verifier);
    let (st, j) = a
        .node
        .post(
            "/api/v1/auth/connect/code",
            &alice.token,
            json!({ "origin": "https://visit.example", "code_challenge": challenge }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let code = j["code"].as_str().unwrap().to_string();
    let (st, session) = exchange(b, &code, verifier).await;
    assert_eq!(st, StatusCode::OK, "{session}");
    assert!(session["access_token"].is_string());
    let (st, j) = exchange(a, &code, verifier).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("connect.code_invalid")), "single use");
}
both!(connect_codes_are_exchanged_on_another_instance, connect_code_in_process, connect_code_valkey);

// ---------------------------------------------------------------- leader election and relayed state

async fn exactly_one_instance_leads_and_another_takes_over(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0].node.state, &nodes[1].node.state);
    assert!(!a.cluster.is_leader() && !b.cluster.is_leader(), "nobody leads before the lease");
    let ta = tavrn_node::cache::leader::spawn(a, LEASE).unwrap();
    wait_for(Duration::from_secs(3), || a.cluster.is_leader()).await;
    let tb = tavrn_node::cache::leader::spawn(b, LEASE).unwrap();
    // B competes for a while and never leads while A renews: the singleton jobs run on A only.
    for _ in 0..10 {
        tokio::time::sleep(LEASE / 5).await;
        assert!(a.cluster.is_leader() ^ b.cluster.is_leader(), "exactly one leader");
        assert!(a.cluster.is_leader());
    }
    assert_eq!(b.cluster.leader_id().as_deref(), Some("i0"));
    // A stops (crash: no release): its leadership lapses with the lease and B takes over.
    ta.abort();
    wait_for(LEASE * 4, || b.cluster.is_leader()).await;
    assert!(!a.cluster.is_leader());
    // A graceful stop hands over at once.
    let ta = tavrn_node::cache::leader::spawn(a, LEASE).unwrap();
    tb.abort();
    tavrn_node::cache::leader::step_down(&b.cluster).await;
    wait_for(LEASE * 2, || a.cluster.is_leader()).await;
    ta.abort();
}
both!(exactly_one_instance_leads_and_another_takes_over, leader_in_process, leader_valkey);

async fn whiteboard_requests_are_relayed_to_the_leader(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    elect(&nodes, 0, Duration::from_secs(30)).await;
    let alice = a.node.register("alice").await;
    let bob = a.node.register("bob").await;
    let (_, channel) = room(a, &alice, &[&bob]).await;
    let mut ws_bob = connect(&a.ws_url(), &bob.token, None).await;
    // Alice opens a whiteboard through B (not the leader): the session lives on A.
    let open = json!({ "type": "whiteboard.open", "content": { "type": "whiteboard.open" } });
    let (st, j) = b.node.post(&format!("/api/v1/conversations/{channel}/ephemeral"), &alice.token, open).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["session"]["owner_id"], alice.user_id.as_str());
    let session_path = format!("/api/v1/conversations/{channel}/whiteboard");
    for inst in [a, b] {
        let (_, s) = inst.node.get_auth(&session_path, &bob.token).await;
        assert_eq!(s["session"]["owner_id"], alice.user_id.as_str(), "same session through every instance");
    }
    assert!(b.node.state.whiteboards.get(&channel, std::time::Instant::now()).is_none(), "nothing kept on B");
    assert!(wait_event(&mut ws_bob, "whiteboard.session", 5000).await.is_some());
    // The ephemeral limiter of the leader counts the relayed events (30 per second and sender).
    let cursor = json!({ "type": "cursor", "content": { "x": 1 } });
    let mut limited = false;
    for _ in 0..40 {
        let (st, _) =
            b.node.post(&format!("/api/v1/conversations/{channel}/ephemeral"), &alice.token, cursor.clone()).await;
        limited |= st == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "one limit for the node");
}
both!(whiteboard_requests_are_relayed_to_the_leader, relay_in_process, relay_valkey);

async fn voice_effects_and_wakeups_reach_the_leader(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0].node.state, &nodes[1].node.state);
    elect(&nodes, 0, Duration::from_secs(30)).await;
    // A wakeup of a leader-only worker from B reaches A.
    let woken = a.outbox_wakeup.clone();
    let wait =
        tokio::spawn(async move { tokio::time::timeout(Duration::from_secs(5), woken.notified()).await.is_ok() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    tavrn_node::cache::wake(b, tavrn_node::cache::Job::Outbox);
    assert!(wait.await.unwrap(), "the leader's outbox worker was woken");
    // A voice side effect on B is handed to the leader instead of touching B's (empty) state.
    let mut rx = a.hub.subscribe();
    tavrn_node::voice::disconnect_user(b, "01J9AAAAAAAAAAAAAAAAAAAAAA", "01J9BBBBBBBBBBBBBBBBBBBBBB").await;
    // Nothing to publish (nobody is in voice), but the message must arrive and be handled without errors.
    assert!(tokio::time::timeout(Duration::from_millis(300), rx.recv()).await.is_err());
}
both!(voice_effects_and_wakeups_reach_the_leader, effects_in_process, effects_valkey);

/// A member moved into a voice channel they may not view (VOICE.md §7) sees it through every instance: the leader's
/// announcement reaches the other instances' hubs, so their REST routes and WebSockets follow it.
async fn a_moved_member_views_the_channel_on_every_instance(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    elect(&nodes, 0, Duration::from_secs(30)).await;
    let alice = a.node.register("alice").await;
    let bob = a.node.register("bob").await;
    let (room_id, _) = room(a, &alice, &[&bob]).await;
    let (_, detail) = a.node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let lobby = detail["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let everyone = detail["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (st, stage) = a
        .node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "voice", "name": "Stage" }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{stage}");
    let stage = stage["id"].as_str().unwrap().to_string();
    let deny = (tavrn_node::permissions::VIEW_CHANNEL | tavrn_node::permissions::CONNECT).to_string();
    let (st, j) = a
        .node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": stage, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": deny }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let listed = |detail: &Value| detail["channels"].as_array().unwrap().iter().any(|c| c["id"] == stage.as_str());
    let mut ws_bob = connect(&b.ws_url(), &bob.token, None).await;

    // Bob joins the lobby and Alice moves him to the stage, both through B (relayed to the leader A).
    let voice = |channel: &str, rest: &str| format!("/api/v1/rooms/{room_id}/channels/{channel}/voice/{rest}");
    let (st, j) = b.node.post(&voice(&lobby, "join"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let domain = a.node.state.config.domain.clone();
    let (st, j) = b
        .node
        .post(&voice(&lobby, &format!("members/bob@{domain}/move")), &alice.token, json!({ "channel_id": stage }))
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let created = wait_event(&mut ws_bob, "channel.create", 5000).await.expect("channel.create on B");
    assert_eq!(created["data"]["id"], stage.as_str());
    assert!(wait_event(&mut ws_bob, "voice.move", 5000).await.is_some());
    let (_, detail) = b.node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert!(listed(&detail), "B's room detail lists the stage for the moved member");
    let (st, j) = b.node.post(&voice(&stage, "join"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");

    // Leaving through B ends it on B too.
    let (st, _) = b.node.post(&voice(&stage, "leave"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let hidden = wait_event(&mut ws_bob, "channel.delete", 5000).await.expect("channel.delete on B");
    assert_eq!(hidden["data"]["hidden"], true);
    let (_, detail) = b.node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert!(!listed(&detail));
}
both!(a_moved_member_views_the_channel_on_every_instance, moved_in_process, moved_valkey);

// ---------------------------------------------------------------- command interactions (APPLICATIONS.md §5.6)

/// A request on an instance's router in its own task (an invocation waits for the bot's answer).
fn spawn_post(inst: &Instance, path: String, token: &str, body: Value) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    use tower::ServiceExt;
    let router = inst.node.router.clone();
    let token = token.to_string();
    tokio::spawn(async move {
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = common::body_bytes(resp).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    })
}

async fn interactions_reach_a_bot_connected_to_another_instance(cache: Arc<dyn Cache>) {
    let nodes = instances(&domain(), cache, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let _admin = a.node.register("admin").await;
    let alice = a.node.register("alice").await;
    let bob = a.node.register("bob").await;
    let (room_id, channel) = room(a, &alice, &[&bob]).await;
    let (st, app) = a.node.post("/api/v1/applications", &alice.token, json!({ "name": "Relay", "public": true })).await;
    assert_eq!(st, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap();
    let bot_id = app["bot"]["id"].as_str().unwrap();
    let (st, t) =
        a.node.post(&format!("/api/v1/applications/{app_id}/tokens"), &alice.token, json!({ "name": "main" })).await;
    assert_eq!(st, StatusCode::CREATED, "{t}");
    let secret = t["secret"].as_str().unwrap();
    let commands = json!({ "commands": [{ "name": "ping", "description": "Pong" }] });
    let (st, set) = a.node.put(&format!("/api/v1/applications/{app_id}/commands"), &alice.token, commands).await;
    assert_eq!(st, StatusCode::OK, "{set}");
    let reference = format!("{}/{app_id}", a.node.state.config.domain);
    let command = format!("{reference}/{}", set["commands"][0]["id"].as_str().unwrap());
    let (st, j) = a
        .node
        .post(&format!("/api/v1/rooms/{room_id}/applications"), &alice.token, json!({ "application": reference }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");

    // The bot is connected to B only; A learns that through the cache.
    let mut ws_bot = connect(&b.ws_url(), secret, None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a.node.state.interactions.remote_receiver(bot_id).await.is_none() {
        assert!(tokio::time::Instant::now() < deadline, "B's receiver not registered");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(a.node.state.interactions.receivers(bot_id), 0);

    // Bob invokes through A; B delivers to the bot; the bot answers through B, which relays to A.
    let path = format!("/api/v1/conversations/{channel}/interactions");
    let invocation = spawn_post(a, path.clone(), &bob.token, json!({ "command": command, "args": {} }));
    let invoke = wait_event(&mut ws_bot, "command.invoke", 5000).await.expect("invocation on B");
    let id = invoke["data"]["interaction_id"].as_str().unwrap().to_string();
    assert_eq!(invoke["data"]["user"], format!("bob@{}", a.node.state.config.domain));
    let (st, j) = b
        .node
        .post(
            &format!("/api/v1/interactions/{id}/callback"),
            secret,
            json!({ "type": "reply", "content": { "type": "text", "body": "pong" } }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, answer) = invocation.await.unwrap();
    assert_eq!(st, StatusCode::OK, "{answer}");
    assert_eq!(
        (answer["outcome"].as_str(), answer["message"]["content"]["body"].as_str()),
        (Some("reply"), Some("pong"))
    );
    // Follow-ups and a second answer through B reach the owner as well.
    let (st, j) = b
        .node
        .post(
            &format!("/api/v1/interactions/{id}/messages"),
            secret,
            json!({ "content": { "type": "text", "body": "more" }, "ephemeral": false }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (st, j) = b.node.post(&format!("/api/v1/interactions/{id}/callback"), secret, json!({ "type": "defer" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("interaction.already_acked")));
    // Unknown interactions are not relayed anywhere.
    let unknown = tavrn_node::util::ulid();
    let (st, j) =
        b.node.post(&format!("/api/v1/interactions/{unknown}/callback"), secret, json!({ "type": "defer" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("interaction.not_found")));

    // The bot leaves B: A answers `503 interaction.app_offline` once nobody holds a connection.
    drop(ws_bot);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a.node.state.interactions.remote_receiver(bot_id).await.is_some() {
        assert!(tokio::time::Instant::now() < deadline, "B's receiver not removed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (st, j) = spawn_post(a, path, &bob.token, json!({ "command": command, "args": {} })).await.unwrap();
    assert_eq!((st, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("interaction.app_offline")));
}
both!(interactions_reach_a_bot_connected_to_another_instance, interactions_in_process, interactions_valkey);

// ---------------------------------------------------------------- failure modes

#[tokio::test]
async fn an_unreachable_cache_stops_the_start_with_a_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_string_lossy().to_string();
    let mut config = common::dev_config("x.test", &dir, "sqlite::memory:");
    // Nothing listens on port 1.
    config.cache_url = Some("redis://:secret@127.0.0.1:1".into());
    let err = tavrn_node::app::AppState::init(config).await.err().expect("must not start");
    let cache = err.downcast_ref::<tavrn_node::cache::CacheUnreachable>().expect("a cache error");
    assert_eq!(cache.target, "127.0.0.1:1");
    let text = err.to_string();
    assert!(text.contains("TAVRN_CACHE_URL") && text.contains("127.0.0.1:1"), "{text}");
    assert!(!text.contains("secret"), "no password in the message");

    // The binary exits with code 3 and says why.
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_tavrn-node"))
        .args(["--dev", "serve"])
        .env("TAVRN_DOMAIN", "x.test")
        .env("TAVRN_DATA_DIR", &dir)
        .env("TAVRN_DATABASE_URL", format!("sqlite://{dir}/t.db?mode=rwc"))
        .env("TAVRN_LISTEN", "127.0.0.1:0")
        .env("TAVRN_VOICE_ENABLED", "false")
        .env("TAVRN_MEDIA_FFMPEG", "off")
        .env("TAVRN_CACHE_URL", "redis://127.0.0.1:1")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(tavrn_node::cache::EXIT_CACHE_UNREACHABLE), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("TAVRN_CACHE_URL: Valkey/Redis at 127.0.0.1:1"), "{out:?}");
}

/// A cache whose bus can fail on demand (in-process otherwise).
struct Flaky {
    inner: InProcess,
    publish_fails: std::sync::atomic::AtomicBool,
}

impl Cache for Flaky {
    fn ping(&self) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.ping()
    }
    fn hit(&self, key: &str, window: Duration) -> BoxFuture<'_, CacheResult<(u64, Duration)>> {
        self.inner.hit(key, window)
    }
    fn put(&self, key: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.put(key, value, ttl)
    }
    fn get(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        self.inner.get(key)
    }
    fn take(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        self.inner.take(key)
    }
    fn delete(&self, key: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.delete(key)
    }
    fn lease(&self, key: &str, holder: &str, ttl: Duration) -> BoxFuture<'_, CacheResult<bool>> {
        self.inner.lease(key, holder, ttl)
    }
    fn release(&self, key: &str, holder: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.release(key, holder)
    }
    fn hash_put(&self, key: &str, field: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.hash_put(key, field, value, ttl)
    }
    fn hash_remove(&self, key: &str, field: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.inner.hash_remove(key, field)
    }
    fn hash_all(&self, key: &str) -> BoxFuture<'_, CacheResult<std::collections::HashMap<String, String>>> {
        self.inner.hash_all(key)
    }
    fn publish(&self, channel: &str, payload: String) -> BoxFuture<'_, CacheResult<()>> {
        if self.publish_fails.load(std::sync::atomic::Ordering::Relaxed) {
            return Box::pin(std::future::ready(Err(CacheError("connection refused".into()))));
        }
        self.inner.publish(channel, payload)
    }
    fn subscribe(&self, channel: &str) -> BoxFuture<'_, CacheResult<BoxStream<'static, String>>> {
        self.inner.subscribe(channel)
    }
}

#[tokio::test]
async fn lost_events_make_the_other_instances_clients_resync() {
    let flaky = Arc::new(Flaky { inner: InProcess::default(), publish_fails: false.into() });
    let nodes = instances(&domain(), flaky.clone(), 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let (room_id, channel) = room(a, &alice, &[]).await;
    let mut ws = connect(&a.ws_url(), &alice.token, None).await;
    // The cache refuses publishing: B's event cannot reach A (logged, counted as lost).
    flaky.publish_fails.store(true, std::sync::atomic::Ordering::Relaxed);
    let (st, _) = b.node.send(&alice.token, &room_id, &channel, "lost").await;
    assert_eq!(st, StatusCode::CREATED, "the request itself succeeds");
    assert!(wait_event(&mut ws, "message.create", 500).await.is_none());
    // Back: B's next publish is preceded by a resync, so A's client reloads instead of missing the event.
    flaky.publish_fails.store(false, std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    b.node.send(&alice.token, &room_id, &channel, "after").await;
    assert_eq!(next(&mut ws, 5000).await.unwrap(), json!({ "op": "resync" }));
    assert_eq!(wait_event(&mut ws, "message.create", 5000).await.unwrap()["data"]["content"]["body"], "after");
}

#[tokio::test]
async fn a_broken_subscription_is_renewed_and_clients_resync() {
    let cache = Arc::new(InProcess::default());
    let nodes = instances(&domain(), cache.clone(), 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let alice = a.node.register("alice").await;
    let (room_id, channel) = room(a, &alice, &[]).await;
    let mut ws = connect(&a.ws_url(), &alice.token, None).await;
    // The connection to the cache breaks: every instance subscribes again and its clients reload.
    cache.interrupt();
    assert_eq!(wait_event(&mut ws, "resync", 5000).await.unwrap(), json!({ "op": "resync" }));
    // Afterwards events flow again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.node.send(&alice.token, &room_id, &channel, "again").await;
    assert_eq!(wait_event(&mut ws, "message.create", 5000).await.unwrap()["data"]["content"]["body"], "again");
    let (_, ready) = a.node.req(Method::GET, "/readyz", None, None).await;
    assert_eq!(ready["cache"], true, "{ready}");
}

#[tokio::test]
async fn a_standalone_node_reports_no_cache_and_leads() {
    let node = common::test_node("solo.test").await;
    let (_, ready) = node.req(Method::GET, "/readyz", None, None).await;
    assert_eq!(ready["cache"], Value::Null, "{ready}");
    assert!(node.state.cluster.is_leader() && !node.state.cluster.is_shared());
    assert!(tavrn_node::cache::leader::spawn(&node.state, LEASE).is_none(), "nothing to elect");
}
