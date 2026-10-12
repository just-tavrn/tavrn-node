// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Moving members into voice channels they may neither view nor connect to (protocol/VOICE.md §7 "Moved
//! participations"): the move needs only the mover's permissions, the moved member's join is entitled by a
//! single-use move grant, the participation is marked `moved`, grants a temporary view of the channel (WebSocket
//! `channel.create` / `channel.delete { hidden: true }`, the room detail, the channel's MLS group) and ends with the
//! participation; the member cannot rejoin by themselves.
use crate::common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    Session, TestNode,
    e2ee::{b64, qualified, unb64},
    perms, test_node,
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_node::{permissions as p, voice};
use tokio_tungstenite::tungstenite::Message;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Alice's room with Bob (and Carol) and a second voice channel `stage` that @everyone may neither view nor
/// connect to. `lobby` is the room's default voice channel.
struct Room {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    lobby: String,
    stage: String,
}

async fn join_room(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

impl Room {
    async fn new() -> Self {
        let node = test_node("t.local").await;
        let alice = node.register("alice").await;
        let bob = node.register("bob").await;
        Self::with(node, alice, bob).await
    }

    async fn with(node: TestNode, alice: Session, bob: Session) -> Self {
        let room = node.create_room(&alice.token, "Room").await;
        let room_id = room["id"].as_str().unwrap().to_string();
        let lobby = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        join_room(&node, &alice, &room_id, &bob).await;
        let (s, ch) = node
            .post(
                &format!("/api/v1/rooms/{room_id}/channels"),
                &alice.token,
                json!({ "kind": "voice", "name": "Stage" }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{ch}");
        let stage = ch["id"].as_str().unwrap().to_string();
        let r = Self { node, alice, bob, room_id, lobby, stage };
        r.deny_everyone(&r.stage, &[p::VIEW_CHANNEL, p::CONNECT]).await;
        r
    }

    async fn deny_everyone(&self, channel: &str, deny: &[u64]) {
        let (_, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &self.alice.token).await;
        let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let (s, j) = self
            .node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": "channel", "target_id": channel, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": perms(deny) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }

    fn voice(&self, channel: &str, rest: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{channel}/voice/{rest}", self.room_id)
    }

    async fn join(&self, s: &Session, channel: &str) -> (StatusCode, Value) {
        self.node.post(&self.voice(channel, "join"), &s.token, json!({})).await
    }

    fn identity(&self, s: &Session) -> String {
        format!("{}@t.local/{}", s.username, s.device_id)
    }

    /// Sends a LiveKit webhook signed with the node's secret.
    async fn webhook(&self, event: Value) {
        use base64::Engine;
        use sha2::Digest;
        let body = event.to_string();
        let key = self.node.state.voice.api_key().unwrap();
        let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body.as_bytes()));
        let token = livekit_api::access_token::AccessToken::with_api_key(&key.key, &key.secret)
            .with_sha256(&hash)
            .to_jwt()
            .unwrap();
        let resp = tower::ServiceExt::oneshot(
            self.node.router.clone(),
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/voice/webhook")
                .header("content-type", "application/webhook+json")
                .header("authorization", token)
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// LiveKit reports `s` as connected to `channel`.
    async fn connected(&self, s: &Session, channel: &str) {
        let ev = json!({ "event": "participant_joined", "room": { "name": format!("{}:{channel}", self.room_id) }, "participant": { "identity": self.identity(s), "state": "ACTIVE" } });
        self.webhook(ev).await;
    }

    async fn join_and_connect(&self, s: &Session, channel: &str) {
        let (st, j) = self.join(s, channel).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        self.connected(s, channel).await;
    }

    async fn move_member(&self, mover: &Session, who: &Session, from: &str, to: &str) -> (StatusCode, Value) {
        let path = self.voice(from, &format!("members/{}@t.local/move", who.username));
        self.node.post(&path, &mover.token, json!({ "channel_id": to })).await
    }

    /// Ids of the channels `GET /rooms/{id}` lists to `s`.
    async fn listed(&self, s: &Session) -> Vec<String> {
        let (st, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &s.token).await;
        assert_eq!(st, StatusCode::OK, "{room}");
        room["channels"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect()
    }

    /// The participants of `channel` as `GET /rooms/{id}/voice` shows them to `s`.
    async fn participants(&self, s: &Session, channel: &str) -> Vec<Value> {
        let (st, j) = self.node.get_auth(&format!("/api/v1/rooms/{}/voice", self.room_id), &s.token).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        j["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["channel_id"] == channel)
            .map(|c| c["participants"].as_array().unwrap().clone())
            .unwrap_or_default()
    }
}

async fn serve(node: &TestNode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{addr}/api/v1/ws")
}

async fn hello(url: &str, token: &str) -> Socket {
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    ws.send(Message::Text(json!({ "op": "hello", "token": token }).to_string().into())).await.unwrap();
    let ready = next_frame(&mut ws).await;
    assert_eq!(ready["op"], "ready", "{ready}");
    ws
}

/// The next frame, skipping presence updates.
async fn next_frame(ws: &mut Socket) -> Value {
    loop {
        let msg = common::within(Duration::from_secs(5), "the next frame", ws.next()).await.unwrap().unwrap();
        if let Message::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] != "presence.update" {
                return v;
            }
        }
    }
}

/// The frames up to and including the first one of `kind`.
async fn frames_until(ws: &mut Socket, kind: &str) -> Vec<Value> {
    let mut seen = Vec::new();
    loop {
        let ev = next_frame(ws).await;
        let done = ev["type"] == kind;
        seen.push(ev);
        if done {
            return seen;
        }
    }
}

fn kinds(frames: &[Value]) -> Vec<String> {
    frames.iter().map(|f| f["type"].as_str().unwrap_or("").to_string()).collect()
}

#[tokio::test]
async fn a_member_is_moved_into_a_channel_they_may_neither_view_nor_connect_to() {
    let r = Room::new().await;
    let url = serve(&r.node).await;
    r.join_and_connect(&r.bob, &r.lobby).await;
    let mut bob_ws = hello(&url, &r.bob.token).await;

    // Bob neither sees the stage nor may join it himself.
    assert!(!r.listed(&r.bob).await.contains(&r.stage));
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");

    // Alice moves him there: no permission of his is needed. His client learns the channel before the move.
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let frames = frames_until(&mut bob_ws, "voice.move").await;
    let created: Vec<&Value> =
        frames.iter().filter(|f| f["type"] == "channel.create" && f["data"]["id"] == r.stage.as_str()).collect();
    assert_eq!(created.len(), 1, "channel.create for the stage before voice.move: {:?}", kinds(&frames));
    assert_eq!(created[0]["data"]["kind"], "voice");
    assert_eq!(frames.last().unwrap()["data"]["channel_id"], r.stage.as_str());
    assert!(r.listed(&r.bob).await.contains(&r.stage), "the room detail lists the stage while he is moved");

    // His join is entitled by the move grant (a token for the stage, listening at least).
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["room"], format!("{}:{}", r.room_id, r.stage));
    let claims = r.node.state.voice.verify(j["token"].as_str().unwrap()).unwrap();
    assert!(claims.video.room_join && claims.video.can_subscribe == Some(true));
    r.connected(&r.bob, &r.stage).await;
    let ps = r.participants(&r.alice, &r.stage).await;
    assert_eq!(ps.len(), 1, "{ps:?}");
    assert_eq!((ps[0]["user"].as_str(), ps[0]["moved"].as_bool()), (Some("bob@t.local"), Some(true)));
    assert_eq!(r.participants(&r.bob, &r.stage).await.len(), 1, "he sees the stage's state too");
    let ev = frames_until(&mut bob_ws, "voice.state").await;
    assert_eq!(ev.last().unwrap()["data"]["channel_id"], r.stage.as_str(), "voice.state reaches him");

    // The access watcher keeps him: a moved participation needs no view_channel or connect.
    voice::check_access(&r.node.state, &r.room_id).await;
    assert_eq!(r.participants(&r.alice, &r.stage).await.len(), 1, "still there after the access check");
    // A dropped connection and a rejoin within the grace period keep the participation and its mark.
    let aborted = json!({ "event": "participant_connection_aborted", "room": { "name": format!("{}:{}", r.room_id, r.stage) }, "participant": { "identity": r.identity(&r.bob) } });
    r.webhook(aborted).await;
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!(s, StatusCode::OK, "rejoin within the grace period: {j}");
    r.connected(&r.bob, &r.stage).await;
    assert_eq!(r.participants(&r.alice, &r.stage).await[0]["moved"], true);
    // Other participants are not marked.
    r.join_and_connect(&r.alice, &r.stage).await;
    let ps = r.participants(&r.alice, &r.stage).await;
    let alice = ps.iter().find(|p| p["user"] == "alice@t.local").unwrap();
    assert_eq!(alice["moved"], false);

    // Leaving ends everything: the stage disappears for him and he cannot come back by himself.
    let (s, _) = r.node.post(&r.voice(&r.stage, "leave"), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let frames = frames_until(&mut bob_ws, "channel.delete").await;
    assert_eq!(
        frames.last().unwrap()["data"],
        json!({ "room_id": r.room_id, "id": r.stage, "hidden": true }),
        "{:?}",
        kinds(&frames)
    );
    assert!(!r.listed(&r.bob).await.contains(&r.stage));
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");

    let (_, log) = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log?limit=50", r.room_id), &r.alice.token).await;
    assert!(log.as_array().unwrap().iter().any(|e| e["action"] == "voice.move"), "the move is audited");
}

#[tokio::test]
async fn a_moved_member_reads_the_channel_only_while_moved() {
    let r = Room::new().await;
    let messages = format!("/api/v1/rooms/{}/channels/{}/messages", r.room_id, r.stage);
    let (s, j) = r.node.get_auth(&messages, &r.bob.token).await;
    assert_eq!(
        (s, j["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("channel.view_forbidden")),
        "before the move: {j}"
    );

    r.join_and_connect(&r.bob, &r.lobby).await;
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    r.join_and_connect(&r.bob, &r.stage).await;
    let (s, j) = r.node.get_auth(&messages, &r.bob.token).await;
    assert_eq!(s, StatusCode::OK, "while moved: {j}");

    let (s, _) = r.node.post(&r.voice(&r.stage, "leave"), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = r.node.get_auth(&messages, &r.bob.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.view_forbidden")), "after leaving: {j}");
}

#[tokio::test]
async fn the_move_grant_is_used_once_and_bound_to_its_channel() {
    let r = Room::new().await;
    let (s, ch) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", r.room_id),
            &r.alice.token,
            json!({ "kind": "voice", "name": "Back" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let backstage = ch["id"].as_str().unwrap().to_string();
    r.deny_everyone(&backstage, &[p::VIEW_CHANNEL, p::CONNECT]).await;
    r.join_and_connect(&r.bob, &r.lobby).await;
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    // The grant is for the stage only.
    let (s, j) = r.join(&r.bob, &backstage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
    // Joining another channel he may join (the lobby) drops the grant.
    r.join_and_connect(&r.bob, &r.lobby).await;
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");
    assert!(!r.listed(&r.bob).await.contains(&r.stage), "and with it the view");

    // Moved again: the first join consumes it, a join after leaving is refused.
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    r.join_and_connect(&r.bob, &r.stage).await;
    let (s, _) = r.node.post(&r.voice(&r.stage, "leave"), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = r.join(&r.bob, &r.stage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.connect_forbidden")), "{j}");

    // Moving from the stage onwards into the backstage works the same way.
    r.join_and_connect(&r.bob, &r.lobby).await;
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    r.join_and_connect(&r.bob, &r.stage).await;
    r.join_and_connect(&r.alice, &r.stage).await;
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.stage, &backstage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let listed = r.listed(&r.bob).await;
    assert!(listed.contains(&backstage) && !listed.contains(&r.stage), "{listed:?}");
    r.join_and_connect(&r.bob, &backstage).await;
    assert_eq!(r.participants(&r.alice, &backstage).await[0]["moved"], true);
}

#[tokio::test]
async fn a_timeout_or_a_kick_ends_a_moved_participation() {
    let r = Room::new().await;
    r.join_and_connect(&r.bob, &r.lobby).await;
    r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    r.join_and_connect(&r.bob, &r.stage).await;
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/members/{}/timeout", r.room_id, r.bob.user_id),
            &r.alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    voice::check_access(&r.node.state, &r.room_id).await;
    let mut gone = false;
    for _ in 0..common::rounds(50) {
        if r.participants(&r.alice, &r.stage).await.is_empty() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "a member in timeout leaves the stage");
    assert!(!r.listed(&r.bob).await.contains(&r.stage));
}

#[tokio::test]
async fn mass_moves_bring_everybody_into_a_channel_they_may_not_view() {
    let r = Room::new().await;
    let carol = r.node.register("carol").await;
    join_room(&r.node, &r.alice, &r.room_id, &carol).await;
    r.join_and_connect(&r.bob, &r.lobby).await;
    r.join_and_connect(&carol, &r.lobby).await;
    let (s, j) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/voice/move-all", r.room_id),
            &r.alice.token,
            json!({ "to_channel_id": r.stage }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut moved: Vec<&str> = j["moved"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
    moved.sort_unstable();
    assert_eq!(moved, vec!["bob@t.local", "carol@t.local"]);
    assert_eq!(j["skipped"], json!([]));
    for s in [&r.bob, &carol] {
        assert!(r.listed(s).await.contains(&r.stage));
        r.join_and_connect(s, &r.stage).await;
    }
    assert!(r.participants(&r.alice, &r.stage).await.iter().all(|p| p["moved"] == true));
}

#[tokio::test]
async fn members_below_the_age_gate_are_not_moved_into_it() {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let young = chrono::Utc::now().date_naive().checked_sub_months(chrono::Months::new(12 * 16)).unwrap();
    let bob = node.register_born("bob", &young.format("%Y-%m-%d").to_string()).await;
    let r = Room::with(node, alice, bob).await;
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.stage),
            &r.alice.token,
            json!({ "age_gate": "adults_only" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    r.join_and_connect(&r.bob, &r.lobby).await;
    let (s, j) = r.move_member(&r.alice, &r.bob, &r.lobby, &r.stage).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("voice.target_forbidden")), "{j}");
    assert_eq!(r.participants(&r.alice, &r.lobby).await.len(), 1, "he stays where he is");
}

#[tokio::test]
async fn a_moved_member_joins_the_voice_channel_s_mls_group_and_is_removed_afterwards() {
    let node = test_node("t.local").await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let (alice_admin, bob_admin) = (node.login("alice").await, node.login("bob").await);
    let r = Room::with(node, alice_admin, bob_admin).await;
    let base = format!("/api/v1/conversations/{}/mls", r.stage);
    let gi = alice.client.create_group(&qualified(&r.stage)).unwrap();
    let (s, j) = r.node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = r.node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "not entitled before the move: {j}");

    r.join_and_connect(&bob.session, &r.lobby).await;
    let (s, j) = r.move_member(&alice.session, &bob.session, &r.lobby, &r.stage).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (s, j) = r.join(&bob.session, &r.stage).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    r.connected(&bob.session, &r.stage).await;
    // Entitled while moved: he joins the group by external commit.
    let (s, j) = r.node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let join = bob.client.join_by_external_commit(&qualified(&r.stage), &unb64(&j["group_info"])).unwrap();
    let (s, j) = r.node.post_commit(bob.token(), &r.stage, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    bob.client.merge_pending_commit(&qualified(&r.stage)).unwrap();
    r.node.catch_up(&mut alice, &r.stage).await;

    // Leaving ends the entitlement: the remaining members are asked to remove his leaf.
    let mut rx = r.node.state.hub.subscribe();
    let (s, _) = r.node.post(&r.voice(&r.stage, "leave"), bob.token(), json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let needed = tokio::time::timeout(common::timeout(Duration::from_secs(5)), async {
        loop {
            let ev = rx.recv().await.unwrap();
            if ev.kind == "mls.remove_needed" {
                return ev.data.clone();
            }
        }
    })
    .await
    .expect("mls.remove_needed");
    assert_eq!(needed, json!({ "conversation_id": r.stage, "identities": [bob.identity()] }));
    let (s, j) = r.node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let rm = alice.client.remove_members(&qualified(&r.stage), &[bob.identity()]).unwrap();
    let (s, j) = r.node.post_commit(alice.token(), &r.stage, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}
