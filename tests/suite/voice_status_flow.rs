// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The status line of voice channels (protocol VOICE.md §2a, permissions.md bit 38): set through the channel update
//! route by members with `voice_status` alone, validated, audited, announced with `channel.update`; refused on other
//! kinds and without the bit; the startup fixup grants the bit to roles that manage channels.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    voice_id: String,
    text_id: String,
}

async fn setup() -> Setup {
    let node = test_node("t.local").await;
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
    Setup { node, alice, bob, room_id, voice_id, text_id }
}

impl Setup {
    fn channel(&self, id: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{id}", self.room_id)
    }

    async fn give(&self, user_id: &str, name: &str, bits: &[u64]) -> String {
        let (s, role) = self
            .node
            .post(
                &format!("/api/v1/rooms/{}/roles", self.room_id),
                &self.alice.token,
                json!({ "name": name, "permissions": perms(bits), "position": 1 }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{role}");
        let role_id = role["id"].as_str().unwrap().to_string();
        let (s, j) = self
            .node
            .patch(
                &format!("/api/v1/rooms/{}/members/{user_id}", self.room_id),
                &self.alice.token,
                json!({ "roles": [role_id] }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
        role_id
    }

    async fn audit(&self, action: &str) -> Vec<Value> {
        let (s, log) =
            self.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", self.room_id), &self.alice.token).await;
        assert_eq!(s, StatusCode::OK, "{log}");
        log.as_array().unwrap().iter().filter(|e| e["action"] == action).cloned().collect()
    }
}

#[tokio::test]
async fn the_status_needs_voice_status_alone_and_is_validated_audited_and_announced() {
    let t = setup().await;
    let (_, room) = t.node.get_auth(&format!("/api/v1/rooms/{}", t.room_id), &t.bob.token).await;
    let voice = room["channels"].as_array().unwrap().iter().find(|c| c["id"] == t.voice_id.as_str()).unwrap();
    assert_eq!(voice["status"], "", "every channel object carries the field, empty at first");

    // Bob holds neither manage_channels nor voice_status.
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "Raid night" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.status_forbidden")), "{j}");

    // With the bit alone the status goes through (no manage_channels needed), announced with channel.update.
    let role = t.give(&t.bob.user_id, "Host", &[p::VOICE_STATUS]).await;
    let mut rx = t.node.state.hub.subscribe();
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "  Raid night  " })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["status"], "Raid night", "trimmed");
    let ev = common::within(std::time::Duration::from_secs(5), "channel.update", async {
        loop {
            let ev = rx.recv().await.unwrap();
            if ev.kind == "channel.update" {
                return ev.data.clone();
            }
        }
    })
    .await;
    assert_eq!((ev["id"].as_str(), ev["status"].as_str()), (Some(t.voice_id.as_str()), Some("Raid night")));
    let entries = t.audit("channel.voice_status").await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["meta"]["status"], "Raid night");
    assert_eq!(entries[0]["target"], t.voice_id.as_str());
    assert_eq!(entries[0]["actor_id"], t.bob.user_id.as_str());

    // The same text again is no change: no second audit entry.
    let (s, _) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "Raid night" })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(t.audit("channel.voice_status").await.len(), 1);

    // The bit does not open the other fields.
    let (s, j) = t
        .node
        .patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "Planning", "user_limit": 5 }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.manage_forbidden")), "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "name": "loud" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.manage_forbidden")), "{j}");

    // Limits: 128 characters after trimming, one line, no control characters.
    let long = "x".repeat(129);
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": long })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")), "{j}");
    let exact = "y".repeat(128);
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": format!(" {exact} ") })).await;
    assert_eq!((s, j["status"].as_str()), (StatusCode::OK, Some(exact.as_str())), "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "two\nlines" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.multiline")), "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "bell\u{7}" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.control_chars")), "{j}");

    // Only voice channels carry a status, whoever asks.
    let (s, j) = t.node.patch(&t.channel(&t.text_id), &t.alice.token, json!({ "status": "nope" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.status_not_voice")), "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.text_id), &t.alice.token, json!({ "topic": "fine" })).await;
    assert_eq!((s, j["topic"].as_str()), (StatusCode::OK, Some("fine")), "topic is untouched: {j}");

    // Clearing: an empty string; the owner (all bits) may, and the channel keeps its topic field apart.
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.alice.token, json!({ "status": "" })).await;
    assert_eq!((s, j["status"].as_str()), (StatusCode::OK, Some("")), "{j}");
    assert_eq!(t.audit("channel.voice_status").await.len(), 3);

    // A channel override can take the bit away again (channel-scoped) and give it to @everyone.
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", t.room_id),
            &t.alice.token,
            json!({ "target_type": "channel", "target_id": t.voice_id, "subject_type": "role", "subject_id": role, "allow": "0", "deny": perms(&[p::VOICE_STATUS]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "denied" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.status_forbidden")), "{j}");
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", t.room_id),
            &t.alice.token,
            json!({ "target_type": "channel", "target_id": t.voice_id, "subject_type": "role", "subject_id": everyone, "allow": perms(&[p::VOICE_STATUS]), "deny": "0" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "voice_status is not restricted for @everyone: {j}");

    // A member in timeout keeps reading only.
    let (s, j) = t
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", t.room_id, t.bob.user_id),
            &t.alice.token,
            json!({ "roles": [] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "via everyone" })).await;
    assert_eq!((s, j["status"].as_str()), (StatusCode::OK, Some("via everyone")), "{j}");
    let (s, j) = t
        .node
        .put(
            &format!("/api/v1/rooms/{}/members/{}/timeout", t.room_id, t.bob.user_id),
            &t.alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = t.node.patch(&t.channel(&t.voice_id), &t.bob.token, json!({ "status": "muted" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.status_forbidden")), "{j}");

    // Non-members get nothing.
    let carol = t.node.register("carol").await;
    let (s, _) = t.node.patch(&t.channel(&t.voice_id), &carol.token, json!({ "status": "hi" })).await;
    assert!(s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND, "{s}");
}

#[tokio::test]
async fn the_startup_fixup_grants_voice_status_to_roles_that_manage_channels_once() {
    let t = setup().await;
    let (s, role) = t
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", t.room_id),
            &t.alice.token,
            json!({ "name": "Builders", "permissions": perms(&[p::MANAGE_CHANNELS]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let (s, other) = t
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", t.room_id),
            &t.alice.token,
            json!({ "name": "Mods", "permissions": perms(&[p::MANAGE_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::VOICE_STATUS_MARKER)
        .execute(&t.node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&t.node.state.db).await.unwrap();
    assert!(report.voice_status_roles >= 1, "{report:?}");
    let bits = |id: &str| {
        let id = id.to_string();
        let db = t.node.state.db.clone();
        async move {
            let perms: i64 =
                sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1").bind(id).fetch_one(&db).await.unwrap();
            perms as u64
        }
    };
    assert_eq!(bits(role["id"].as_str().unwrap()).await & p::VOICE_STATUS, p::VOICE_STATUS);
    assert_eq!(bits(other["id"].as_str().unwrap()).await & p::VOICE_STATUS, 0, "only roles that manage channels");
    let report = tavrn_node::fixups::run(&t.node.state.db).await.unwrap();
    assert_eq!(report.voice_status_roles, 0, "runs once");
}
