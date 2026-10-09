// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Layered permission overrides (protocol permissions.md "Evaluation", "Channel-scoped bits"): the role base,
//! then the category's overrides, then the channel's own on top; overrides carry channel-scoped bits only; the
//! start-up strip of other bits from existing overrides; `sync_with_category` is gone.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    everyone: String,
}

async fn setup() -> Setup {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Layers").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    Setup { node, alice, bob, room_id, everyone }
}

impl Setup {
    async fn category(&self, name: &str) -> String {
        let (s, j) = self
            .node
            .post(&format!("/api/v1/rooms/{}/categories", self.room_id), &self.alice.token, json!({ "name": name }))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        j["id"].as_str().unwrap().to_string()
    }

    async fn channel(&self, kind: &str, name: &str, category: &str) -> String {
        let mut body = json!({ "kind": kind, "name": name, "category_id": category });
        if kind == "text" {
            body["encrypted"] = json!(false);
        }
        let (s, j) = self.node.post(&format!("/api/v1/rooms/{}/channels", self.room_id), &self.alice.token, body).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        j["id"].as_str().unwrap().to_string()
    }

    async fn set_override(
        &self,
        target_type: &str,
        target_id: &str,
        subject: (&str, &str),
        allow: u64,
        deny: u64,
    ) -> (StatusCode, Value) {
        self.node
            .put(
                &format!("/api/v1/rooms/{}/overrides", self.room_id),
                &self.alice.token,
                json!({ "target_type": target_type, "target_id": target_id, "subject_type": subject.0, "subject_id": subject.1,
                        "allow": allow.to_string(), "deny": deny.to_string() }),
            )
            .await
    }

    async fn ok_override(&self, target_type: &str, target_id: &str, subject: (&str, &str), allow: u64, deny: u64) {
        let (s, j) = self.set_override(target_type, target_id, subject, allow, deny).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }

    async fn room_of(&self, who: &Session) -> Value {
        let (s, room) = self.node.get_auth(&format!("/api/v1/rooms/{}", self.room_id), &who.token).await;
        assert_eq!(s, StatusCode::OK, "{room}");
        room
    }

    async fn everyone_without_view(&self) {
        let (s, j) = self
            .node
            .patch(
                &format!("/api/v1/rooms/{}/roles/{}", self.room_id, self.everyone),
                &self.alice.token,
                json!({ "permissions": (p::DEFAULT_EVERYONE & !p::VIEW_CHANNEL).to_string() }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }

    fn messages(&self, channel: &str) -> String {
        format!("/api/v1/rooms/{}/channels/{channel}/messages", self.room_id)
    }
}

fn ids(list: &Value) -> Vec<String> {
    list.as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn the_owners_example_through_real_routes() {
    let s = setup().await;
    let team = s.category("Team").await;
    let open = s.channel("text", "open", &team).await;
    let secret = s.channel("text", "secret", &team).await;
    let talk = s.channel("voice", "talk", &team).await;
    let other = s.category("Other").await;
    let shown = s.channel("text", "shown", &other).await;
    let hidden = s.channel("text", "hidden", &other).await;
    let staff = s.category("Staff").await;
    let staff_only = s.channel("text", "staff-only", &staff).await;

    // `@everyone` loses view_channel on the role; the Team category stays neutral; two of its channels allow it.
    s.everyone_without_view().await;
    s.ok_override("channel", &open, ("role", &s.everyone), p::VIEW_CHANNEL, 0).await;
    s.ok_override("channel", &talk, ("role", &s.everyone), p::VIEW_CHANNEL, 0).await;
    // Category allow + channel deny: the category's other channel follows the category, this one is hidden.
    s.ok_override("category", &other, ("role", &s.everyone), p::VIEW_CHANNEL, 0).await;
    s.ok_override("channel", &hidden, ("role", &s.everyone), 0, p::VIEW_CHANNEL).await;

    // Channel listing: Bob sees exactly the visible channels (and the welcome channel), and only the
    // categories that contain one of them.
    let room = s.room_of(&s.bob).await;
    let mut visible = ids(&room["channels"]);
    let welcome = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    visible.retain(|c| *c != welcome);
    visible.sort();
    let mut expected = vec![open.clone(), talk.clone(), shown.clone()];
    expected.sort();
    assert_eq!(visible, expected, "{room}");
    let mut cats = ids(&room["categories"]);
    cats.sort();
    let mut expected_cats = vec![team.clone(), other.clone()];
    expected_cats.sort();
    assert_eq!(cats, expected_cats, "a category without a visible channel is not listed: {room}");
    assert!(room["channels"].as_array().unwrap().iter().all(|c| c.get("sync_with_category").is_none()), "{room}");
    // The owner still sees every channel and category.
    let all = s.room_of(&s.alice).await;
    for id in [&secret, &hidden, &staff_only] {
        assert!(ids(&all["channels"]).contains(id));
    }
    assert!(ids(&all["categories"]).contains(&staff));

    // Message read and send.
    let (st, j) = s.node.get_auth(&s.messages(&open), &s.bob.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = s.node.send(&s.bob.token, &s.room_id, &open, "hello").await;
    assert!(st.is_success(), "{j}");
    let (st, j) = s.node.get_auth(&s.messages(&shown), &s.bob.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    for channel in [&secret, &hidden, &staff_only] {
        let (st, j) = s.node.get_auth(&s.messages(channel), &s.bob.token).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.view_forbidden")), "{j}");
        let (st, _) = s.node.send(&s.bob.token, &s.room_id, channel, "nope").await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    // Voice join: allowed in the visible voice channel, refused in the room's default one (no override).
    let voice = |c: &str| format!("/api/v1/rooms/{}/channels/{c}/voice/join", s.room_id);
    let (st, j) = s.node.post(&voice(&talk), &s.bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let default_voice =
        all["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice" && c["id"] != talk.as_str()).unwrap()
            ["id"]
            .as_str()
            .unwrap()
            .to_string();
    let (st, j) = s.node.post(&voice(&default_voice), &s.bob.token, json!({})).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{j}");
}

#[tokio::test]
async fn a_channel_with_own_overrides_inherits_its_category_and_members_come_last() {
    let s = setup().await;
    let cat = s.category("Talk").await;
    let chan = s.channel("text", "chat", &cat).await;
    // The category takes sending away from everybody; the channel's own override is about something else.
    s.ok_override("category", &cat, ("role", &s.everyone), 0, p::SEND_MESSAGES).await;
    s.ok_override("channel", &chan, ("role", &s.everyone), p::ADD_REACTIONS, 0).await;
    let (st, _) = s.node.send(&s.bob.token, &s.room_id, &chan, "blocked").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "the category's deny is inherited underneath the channel's overrides");
    // A member override on the channel wins over everything below it.
    s.ok_override("channel", &chan, ("member", &s.bob.user_id), p::SEND_MESSAGES, 0).await;
    let (st, j) = s.node.send(&s.bob.token, &s.room_id, &chan, "now").await;
    assert!(st.is_success(), "{j}");
    // A channel role deny beats a category member allow (the later layer wins).
    let (st, role) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Quiet", "permissions": "0", "position": 1 }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{role}");
    let quiet = role["id"].as_str().unwrap().to_string();
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, s.bob.user_id),
            &s.alice.token,
            json!({ "roles": [quiet] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    s.ok_override("channel", &chan, ("member", &s.bob.user_id), 0, 0).await;
    s.ok_override("category", &cat, ("member", &s.bob.user_id), p::SEND_MESSAGES, 0).await;
    let (st, j) = s.node.send(&s.bob.token, &s.room_id, &chan, "category member allow").await;
    assert!(st.is_success(), "a category member allow beats the category's @everyone deny: {j}");
    s.ok_override("channel", &chan, ("role", &quiet), 0, p::SEND_MESSAGES).await;
    let (st, _) = s.node.send(&s.bob.token, &s.room_id, &chan, "channel role deny").await;
    assert_eq!(st, StatusCode::FORBIDDEN, "the channel layer wins over the category's member override");
}

#[tokio::test]
async fn overrides_refuse_bits_that_are_not_channel_scoped() {
    let s = setup().await;
    let cat = s.category("Cat").await;
    let chan = s.channel("text", "chan", &cat).await;
    let (st, role) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Mods", "permissions": "0", "position": 1 }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{role}");
    let mods = role["id"].as_str().unwrap().to_string();
    for (target_type, target) in [("channel", &chan), ("category", &cat)] {
        for (allow, deny) in [
            (p::KICK_MEMBERS, 0),
            (0, p::MANAGE_ROOM),
            (p::SEND_MESSAGES | p::ADMINISTRATOR, 0),
            (0, p::CHANGE_NICKNAME),
        ] {
            let (st, j) = s.set_override(target_type, target, ("role", &mods), allow, deny).await;
            assert_eq!(
                (st, j["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some("permissions.not_channel_scoped")),
                "{j}"
            );
            assert!(j["meta"]["names"].as_array().is_some_and(|n| !n.is_empty()), "{j}");
        }
        // Also for @everyone: the scope check comes first.
        let (st, j) = s.set_override(target_type, target, ("role", &s.everyone), p::PURGE, 0).await;
        assert_eq!(j["code"].as_str(), Some("permissions.not_channel_scoped"), "{st} {j}");
        // Every channel-scoped bit is accepted for a role (management ones included).
        s.ok_override(target_type, target, ("role", &mods), p::CHANNEL_SCOPED & !p::VIEW_CHANNEL, p::VIEW_CHANNEL)
            .await;
    }
    let (st, j) = s.set_override("channel", &chan, ("role", &mods), 0, p::KICK_MEMBERS).await;
    assert_eq!(j["meta"]["names"], json!(["kick_members"]), "{st} {j}");
}

#[tokio::test]
async fn patch_ignores_sync_with_category() {
    let s = setup().await;
    let cat = s.category("Cat").await;
    let chan = s.channel("text", "chan", &cat).await;
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{chan}", s.room_id),
            &s.alice.token,
            json!({ "sync_with_category": false, "topic": "t" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert!(j.get("sync_with_category").is_none(), "{j}");
    assert_eq!(j["topic"], "t");
    // The welcome channel refuses changes, but the ignored field alone is no change.
    let room = s.room_of(&s.alice).await;
    let welcome = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{welcome}", s.room_id),
            &s.alice.token,
            json!({ "sync_with_category": true }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn startup_strip_removes_bits_that_are_not_channel_scoped_and_audits() {
    let s = setup().await;
    let cat = s.category("Cat").await;
    let chan = s.channel("text", "chan", &cat).await;
    let insert = |target_type: &'static str,
                  target: String,
                  subject_type: &'static str,
                  subject: String,
                  allow: u64,
                  deny: u64| {
        let db = s.node.state.db.clone();
        let room_id = s.room_id.clone();
        async move {
            sqlx::query("INSERT INTO permission_overrides (id, room_id, target_type, target_id, subject_type, subject_id, allow, deny) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
                .bind(tavrn_node::util::ulid())
                .bind(room_id)
                .bind(target_type)
                .bind(target)
                .bind(subject_type)
                .bind(subject)
                .bind(allow as i64)
                .bind(deny as i64)
                .execute(&db)
                .await
                .unwrap();
        }
    };
    // Data from before the rule: a role override mixing scoped and room-level bits, a member override with
    // room-level bits only, and a clean one.
    insert(
        "channel",
        chan.clone(),
        "member",
        s.alice.user_id.clone(),
        p::SEND_MESSAGES | p::KICK_MEMBERS,
        p::ATTACH_FILES | p::PURGE,
    )
    .await;
    insert("category", cat.clone(), "member", s.bob.user_id.clone(), p::MANAGE_ROOM, p::CHANGE_NICKNAME).await;
    insert("channel", chan.clone(), "role", s.everyone.clone(), p::ADD_REACTIONS, 0).await;
    let report = tavrn_node::fixups::run(&s.node.state.db).await.unwrap();
    assert_eq!(report.override_restricted, 2, "{report:?}");
    let room = s.room_of(&s.alice).await;
    let overrides = room["overrides"].as_array().unwrap();
    let mixed = overrides.iter().find(|o| o["subject_id"] == s.alice.user_id.as_str()).unwrap();
    assert_eq!(
        (&mixed["allow"], &mixed["deny"]),
        (&json!(p::SEND_MESSAGES.to_string()), &json!(p::ATTACH_FILES.to_string()))
    );
    assert!(
        overrides.iter().all(|o| o["subject_id"] != s.bob.user_id.as_str()),
        "an override left with nothing is deleted: {room}"
    );
    assert!(overrides.iter().any(|o| o["subject_id"] == s.everyone.as_str()), "clean overrides stay");
    let (_, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), &s.alice.token).await;
    let entries: Vec<&Value> =
        log.as_array().unwrap().iter().filter(|e| e["action"] == "role.override_restricted").collect();
    assert_eq!(entries.len(), 2, "{log}");
    let first = entries.iter().find(|e| e["target"] == chan.as_str()).unwrap();
    assert_eq!(first["meta"]["names"], json!(["kick_members", "purge"]), "{log}");
    assert_eq!(first["meta"]["target_type"], "channel");
    assert_eq!(first["meta"]["subject_type"], "member");
    assert_eq!(first["meta"]["removed"], (p::KICK_MEMBERS | p::PURGE).to_string());
    // Idempotent.
    assert_eq!(tavrn_node::fixups::run(&s.node.state.db).await.unwrap(), Default::default());
}

#[tokio::test]
async fn overrides_still_grant_only_bits_the_actor_holds() {
    let s = setup().await;
    let cat = s.category("Cat").await;
    let mut ids = Vec::new();
    for (name, bits, position) in [("Manager", p::MANAGE_ROLES, 5), ("Helper", 0, 1)] {
        let (st, role) = s
            .node
            .post(
                &format!("/api/v1/rooms/{}/roles", s.room_id),
                &s.alice.token,
                json!({ "name": name, "permissions": bits.to_string(), "position": position }),
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "{role}");
        ids.push(role["id"].as_str().unwrap().to_string());
    }
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, s.bob.user_id),
            &s.alice.token,
            json!({ "roles": [ids[0]] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let path = format!("/api/v1/rooms/{}/overrides", s.room_id);
    let body = |allow: u64| {
        json!({ "target_type": "category", "target_id": cat, "subject_type": "role", "subject_id": ids[1],
                "allow": allow.to_string(), "deny": "0" })
    };
    let (st, j) = s.node.put(&path, &s.bob.token, body(p::MANAGE_MESSAGES)).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("override.escalation")), "{j}");
    let (st, j) = s.node.put(&path, &s.bob.token, body(p::SEND_MESSAGES)).await;
    assert_eq!(st, StatusCode::OK, "{j}");
}
