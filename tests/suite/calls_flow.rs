// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Calls in DMs and group DMs (protocol/VOICE.md §11): start rings the other members,
//! join/answer, decline, missed after the ring time, the end with a duration, permissions, the `/rtc`
//! check of call tokens, and the ring across nodes through the callee's home node.
use crate::common;

use std::time::Duration;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{
    Session, TestNode, body_bytes,
    crossnode::{event, no_event, ws},
    federation::{A, B, two_nodes_with},
    test_node, test_node_with,
};
use livekit_api::access_token::AccessToken;
use serde_json::{Value, json};
use tavrn_node::{calls, config::DmPolicy, hub::Scope};
use tower::ServiceExt;

const DOMAIN: &str = "t.local";

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

fn path(id: &str, rest: &str) -> String {
    if rest.is_empty() {
        format!("/api/v1/conversations/{id}/call")
    } else {
        format!("/api/v1/conversations/{id}/call/{rest}")
    }
}

fn identity(s: &Session) -> String {
    format!("{}@{DOMAIN}/{}", s.username, s.device_id)
}

/// A LiveKit webhook signed like LiveKit does.
async fn webhook(node: &TestNode, event: Value) {
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
    let resp = node.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn connected(node: &TestNode, id: &str, s: &Session) {
    webhook(node, json!({ "event": "participant_joined", "room": { "name": format!("call:{id}") }, "participant": { "identity": identity(s), "state": "ACTIVE" } }))
        .await;
}

type Rx = tokio::sync::broadcast::Receiver<std::sync::Arc<tavrn_node::hub::Event>>;

/// The next hub event of `kind` (data and the users it goes to).
async fn next(rx: &mut Rx, kind: &str) -> (Value, Vec<String>) {
    tokio::time::timeout(common::timeout(Duration::from_secs(5)), async {
        loop {
            let ev = rx.recv().await.unwrap();
            if ev.kind == kind {
                let users = match &ev.scope {
                    Scope::Users(u) => u.clone(),
                    _ => Vec::new(),
                };
                return (ev.data.clone(), users);
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} event"))
}

async fn system_messages(node: &TestNode, s: &Session, id: &str) -> Vec<Value> {
    let (st, j) = node.get_auth(&format!("/api/v1/conversations/{id}/messages"), &s.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    j.as_array()
        .unwrap()
        .iter()
        .filter(|m| m["content"]["type"].as_str().is_some_and(|t| t.starts_with("system.call.")))
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_dm_call_rings_is_answered_and_ends_with_its_duration() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let id = dm(&node, &alice, &bob).await;
    let (st, j) = node.get_auth(&path(&id, ""), &bob.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["active"], false);
    let mut rx = node.state.hub.subscribe();

    let (st, start) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{start}");
    assert_eq!(start["room"], format!("call:{id}"));
    assert_eq!(start["identity"], identity(&alice));
    assert_eq!(start["call"]["ringing"], json!(["bob@t.local"]));
    assert_eq!(start["call"]["group"], false);
    assert!(start["ice_aliases"].as_array().unwrap().is_empty());
    // Calls are speech: the bitrate of a new voice channel (64), not the node's cap (192, room for the music
    // preset), with Opus in-band FEC announced (VOICE.md §3).
    assert_eq!(start["limits"]["audio_bitrate_kbps"], 64, "{start}");
    assert_eq!(start["limits"]["audio_fec"], true);
    let claims = node.state.voice.verify(start["token"].as_str().unwrap()).unwrap();
    assert_eq!(claims.video.room, format!("call:{id}"));
    assert_eq!(claims.video.can_publish_data, Some(false));
    let (ring, to) = next(&mut rx, "call.ring").await;
    assert_eq!(to, vec![bob.user_id.clone()], "only the callee rings");
    assert_eq!(ring["from"], "alice@t.local");
    assert_eq!(ring["conversation_id"], id.as_str());
    assert_eq!(ring["node"], DOMAIN);
    // Starting again (another device, a double click) joins the running call instead of ringing twice.
    let (st, again) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["call"]["started_at"], start["call"]["started_at"]);

    // bob answers: no longer ringing; LiveKit reports both.
    let (st, joined) = node.post(&path(&id, "join"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{joined}");
    assert_eq!(joined["call"]["ringing"], json!([]));
    connected(&node, &id, &alice).await;
    connected(&node, &id, &bob).await;
    let (_, state) = node.get_auth(&path(&id, ""), &alice.token).await;
    assert_eq!(state["participants"].as_array().unwrap().len(), 2, "{state}");
    // Own state (mute) is shown to the others.
    let (st, j) = node.patch(&path(&id, "state"), &bob.token, json!({ "muted": true })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let muted = |update: &Value| {
        update["call"]["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["user"] == "bob@t.local" && p["muted"] == true)
    };
    loop {
        let (update, to) = next(&mut rx, "call.update").await;
        assert!(to.contains(&alice.user_id) && to.contains(&bob.user_id));
        if muted(&update) {
            break;
        }
    }

    // A dropped connection keeps the call (reconnecting for the grace period) …
    webhook(&node, json!({ "event": "participant_left", "room": { "name": format!("call:{id}") }, "participant": { "identity": identity(&alice), "disconnectReason": "SIGNAL_CLOSE" } })).await;
    assert!(node.state.calls.is_active(&id), "a reconnecting participant is no hang-up");
    connected(&node, &id, &alice).await;
    // … a hang-up in a DM ends it for both, with a duration message (plaintext, written by the node).
    let (st, _) = node.post(&path(&id, "leave"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (end, _) = next(&mut rx, "call.end").await;
    assert_eq!(end["reason"], "ended");
    assert!(!node.state.calls.is_active(&id));
    let messages = system_messages(&node, &bob, &id).await;
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0]["content"]["type"], "system.call.ended");
    assert_eq!(messages[0]["content"]["by"], "alice@t.local");
    assert!(messages[0]["content"]["duration_secs"].is_u64());
    assert_eq!(messages[0]["encrypted"], false);
    let (st, j) = node.post(&path(&id, "join"), &bob.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("call.not_active")));
}

#[tokio::test]
async fn declined_and_unanswered_calls_end_as_missed() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let id = dm(&node, &alice, &bob).await;
    let mut rx = node.state.hub.subscribe();

    // The callee declines a DM call: it ends at once, as missed.
    node.post(&path(&id, "start"), &alice.token, json!({})).await;
    let (st, _) = node.post(&path(&id, "decline"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (end, to) = next(&mut rx, "call.end").await;
    assert_eq!(
        (end["reason"].as_str(), to),
        (Some("declined"), vec![bob.user_id.clone()]),
        "bob's other devices stop ringing"
    );
    let (end, _) = next(&mut rx, "call.end").await;
    assert_eq!(end["reason"], "missed");
    assert!(!node.state.calls.is_active(&id));
    let (st, j) = node.post(&path(&id, "decline"), &bob.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("call.not_active")));

    // Nobody answers within the ring time.
    node.post(&path(&id, "start"), &alice.token, json!({})).await;
    connected(&node, &id, &alice).await;
    calls::ring_timeout_now(&node.state, &id).await;
    assert!(!node.state.calls.is_active(&id));
    // The caller hangs up before anybody answered.
    node.post(&path(&id, "start"), &alice.token, json!({})).await;
    node.post(&path(&id, "leave"), &alice.token, json!({})).await;
    assert!(!node.state.calls.is_active(&id));
    let kinds: Vec<String> = system_messages(&node, &bob, &id)
        .await
        .iter()
        .map(|m| m["content"]["type"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, vec!["system.call.missed"; 3]);
}

#[tokio::test]
async fn group_calls_ring_everybody_and_survive_single_declines() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    node.befriend(&alice, &carol).await;
    let (_, group) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["bob", "carol"] })).await;
    let id = group["id"].as_str().unwrap().to_string();
    let mut rx = node.state.hub.subscribe();
    let (_, start) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(start["call"]["group"], true);
    let (ring, to) = next(&mut rx, "call.ring").await;
    assert_eq!(ring["group"], true);
    assert!(to.contains(&bob.user_id) && to.contains(&carol.user_id) && !to.contains(&alice.user_id));
    // carol declines: the call goes on for bob.
    node.post(&path(&id, "decline"), &carol.token, json!({})).await;
    assert!(node.state.calls.is_active(&id));
    let (_, state) = node.get_auth(&path(&id, ""), &bob.token).await;
    assert_eq!(state["ringing"], json!(["bob@t.local"]));
    node.post(&path(&id, "join"), &bob.token, json!({})).await;
    connected(&node, &id, &alice).await;
    connected(&node, &id, &bob).await;
    // The ring time ends; the answered call stays.
    calls::ring_timeout_now(&node.state, &id).await;
    assert!(node.state.calls.is_active(&id));
    // carol joins later; group calls show who is in.
    node.post(&path(&id, "join"), &carol.token, json!({})).await;
    connected(&node, &id, &carol).await;
    let (_, state) = node.get_auth(&path(&id, ""), &carol.token).await;
    let users: Vec<&str> =
        state["participants"].as_array().unwrap().iter().map(|p| p["user"].as_str().unwrap()).collect();
    assert_eq!(users, vec!["alice@t.local", "bob@t.local", "carol@t.local"]);
    // A dropped connection keeps the seat for the grace period; then the last one gone ends the call.
    for s in [&alice, &bob, &carol] {
        webhook(&node, json!({ "event": "participant_left", "room": { "name": format!("call:{id}") }, "participant": { "identity": identity(s), "disconnectReason": "CLIENT_INITIATED" } })).await;
    }
    assert!(!node.state.calls.is_active(&id));
}

#[tokio::test]
async fn calls_need_an_accepted_dm_and_rtc_checks_call_tokens() {
    let node = test_node_with(DOMAIN, |c| c.dm_policy = DmPolicy::Everyone).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let eve = node.register("eve").await;
    let room = node.create_room(&alice.token, "Room").await;
    let text = TestNode::text_channel(&room);
    let id = dm(&node, &alice, &bob).await;
    for (who, p, status, code) in [
        (&eve, path(&id, "start"), StatusCode::NOT_FOUND, "conversation.not_found"),
        (&alice, path(&text, "start"), StatusCode::BAD_REQUEST, "call.not_direct"),
        (&bob, path(&id, "join"), StatusCode::CONFLICT, "call.not_active"),
        (&alice, path("01J9ZZZZZZZZZZZZZZZZZZZZZZ", "start"), StatusCode::NOT_FOUND, "conversation.not_found"),
    ] {
        let (st, j) = node.post(&p, &who.token, json!({})).await;
        assert_eq!((st, j["code"].as_str()), (status, Some(code)), "{p}: {j}");
    }
    // A message request (no friendship): the recipient cannot be rung and cannot call before accepting.
    node.patch("/api/v1/users/me", &alice.token, json!({ "dm_policy": "everyone" })).await;
    let (st, req) = node.post("/api/v1/conversations", &eve.token, json!({ "kind": "dm", "members": ["alice"] })).await;
    assert!(st.is_success(), "{req}");
    let req_id = req["id"].as_str().unwrap();
    let (st, j) = node.post(&path(req_id, "start"), &alice.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("call.request_pending")));
    let (st, start) = node.post(&path(req_id, "start"), &eve.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{start}");
    assert_eq!(start["call"]["ringing"], json!([]), "requested members are not rung");
    node.post(&path(req_id, "leave"), &eve.token, json!({})).await;

    // `/rtc` lets call tokens through only while the call runs (502: authorized, LiveKit not running).
    let (_, start) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    let token = start["token"].as_str().unwrap().to_string();
    let validate = |token: String| {
        let router = node.router.clone();
        async move {
            let req =
                Request::builder().uri(format!("/rtc/validate?access_token={token}")).body(Body::empty()).unwrap();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap_or(Value::Null);
            (status, body)
        }
    };
    let (st, j) = validate(token.clone()).await;
    assert_eq!(st, StatusCode::BAD_GATEWAY, "{j}");
    node.post(&path(&id, "leave"), &alice.token, json!({})).await;
    let (st, j) = validate(token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
    let voice_off = test_node_with("off.local", |c| c.voice_enabled = false).await;
    let a = voice_off.register("alice").await;
    let (st, j) = voice_off.post(&path(&id, "start"), &a.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("voice.disabled")));
}

#[tokio::test]
async fn remote_members_ring_through_their_home_node() {
    let (a, b) = two_nodes_with(|c| c.dm_policy = DmPolicy::Everyone, |c| c.dm_policy = DmPolicy::Everyone).await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    b.patch("/api/v1/users/me", &bob.token, json!({ "dm_policy": "everyone" })).await;
    a.deliver().await;
    let (st, dm) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": [format!("bob@{B}")] })).await;
    assert!(st.is_success(), "{dm}");
    let id = dm["id"].as_str().unwrap().to_string();
    a.deliver().await;
    let remote = a.sign_in_from(&b, &bob).await;
    let (st, j) = a.post(&format!("/api/v1/conversations/{id}/accept"), &remote.token, json!({})).await;
    assert!(st.is_success(), "{j}");
    let mut bob_home = ws(&b, &bob.token).await;

    // bob has no connection on A: the ring goes to B as a content-free `notify` with a call hint.
    let (st, start) = a.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{start}");
    let hint = a.outbox().await.into_iter().find(|e| e.kind == "notify").expect("ring hint queued");
    let body: Value = serde_json::from_str(&hint.body).unwrap();
    assert_eq!(body["to"], format!("bob@{B}"));
    assert_eq!(body["payload"]["call"]["state"], "ring");
    assert_eq!(body["payload"]["call"]["from"], format!("alice@{A}"));
    a.deliver().await;
    let ring = event(&mut bob_home, "call.ring").await;
    assert_eq!(ring["conversation_id"], id.as_str());
    assert_eq!(ring["node"], A, "the client answers on the hosting node");
    assert_eq!(ring["from"], format!("alice@{A}"));

    // bob declines through his federated session on A: the call ends, B stops ringing.
    let (st, _) = a.post(&path(&id, "decline"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert!(!a.state.calls.is_active(&id));
    a.deliver().await;
    let end = event(&mut bob_home, "call.end").await;
    assert_eq!(end["conversation_id"], id.as_str());
    assert!(no_event(&mut bob_home, "call.ring", 200).await);
}

#[tokio::test]
async fn members_who_blocked_the_caller_are_not_rung() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    node.befriend(&alice, &carol).await;
    let (_, group) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["bob", "carol"] })).await;
    let id = group["id"].as_str().unwrap().to_string();
    let (st, j) = node.post("/api/v1/users/me/blocks", &carol.token, json!({ "user": "alice" })).await;
    assert!(st.is_success(), "{j}");
    let (_, start) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(start["call"]["ringing"], json!(["bob@t.local"]));
}

/// Authorization audit: a member removed from a group DM (or leaving it) is dropped from its running call at once,
/// the call goes on for the others.
#[tokio::test]
async fn a_removed_group_member_is_dropped_from_the_call() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    node.befriend(&alice, &carol).await;
    let (_, group) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["bob", "carol"] })).await;
    let id = group["id"].as_str().unwrap().to_string();
    node.post(&path(&id, "start"), &alice.token, json!({})).await;
    for s in [&bob, &carol] {
        let (st, j) = node.post(&path(&id, "join"), &s.token, json!({})).await;
        assert!(st.is_success(), "{j}");
    }
    for s in [&alice, &bob, &carol] {
        connected(&node, &id, s).await;
    }
    let mut rx = node.state.hub.subscribe();
    let (st, j) = node.delete(&format!("/api/v1/conversations/{id}/members/bob"), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let (update, _) = next(&mut rx, "call.update").await;
    let users: Vec<&str> =
        update["call"]["participants"].as_array().unwrap().iter().map(|p| p["user"].as_str().unwrap()).collect();
    assert_eq!(users, vec!["alice@t.local", "carol@t.local"], "{update}");
    assert!(node.state.calls.is_active(&id));
    // Leaving by oneself drops the seat as well.
    let (st, j) = node.delete(&format!("/api/v1/conversations/{id}/members/carol"), &carol.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let (_, state) = node.get_auth(&path(&id, ""), &alice.token).await;
    let users: Vec<&str> =
        state["participants"].as_array().unwrap().iter().map(|p| p["user"].as_str().unwrap()).collect();
    assert_eq!(users, vec!["alice@t.local"], "{state}");
}

/// A disabled account leaves its running DM call at once (a DM call then ends).
#[tokio::test]
async fn a_disabled_account_leaves_its_calls() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let id = dm(&node, &alice, &bob).await;
    let mut rx = node.state.hub.subscribe();
    let (st, start) = node.post(&path(&id, "start"), &alice.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{start}");
    let (st, joined) = node.post(&path(&id, "join"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{joined}");
    connected(&node, &id, &alice).await;
    connected(&node, &id, &bob).await;
    let (st, j) =
        node.patch(&format!("/api/v1/admin/users/{}", bob.user_id), &alice.token, json!({ "disabled": true })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (end, _) = next(&mut rx, "call.end").await;
    assert_eq!(end["conversation_id"], id.as_str(), "{end}");
    assert!(!node.state.calls.is_active(&id));
}
