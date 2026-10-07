// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 4E: @everyone safety (`role.everyone_restricted` on roles and overrides, the audited
//! startup fixup for old rooms), hoisted roles, and the whiteboard permissions `use_whiteboard` and
//! `manage_whiteboard`.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const DOMAIN: &str = "t.local";

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
    everyone: String,
}

async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert!(s.is_success(), "{j}");
    Setup { node, alice, bob, room_id, channel, everyone }
}

fn code(j: &Value) -> Option<&str> {
    j["code"].as_str()
}

#[tokio::test]
async fn management_permissions_can_never_go_to_everyone() {
    let s = setup().await;
    let path = format!("/api/v1/rooms/{}/roles/{}", s.room_id, s.everyone);
    for bit in [p::ADMINISTRATOR, p::MANAGE_ROOM, p::KICK_MEMBERS, p::BAN_MEMBERS, p::MANAGE_WHITEBOARD, p::PURGE] {
        let (st, j) =
            s.node.patch(&path, &s.alice.token, json!({ "permissions": perms(&[p::VIEW_CHANNEL, bit]) })).await;
        assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("role.everyone_restricted")), "{bit}: {j}");
    }
    // Ordinary permissions are fine; the new defaults contain use_whiteboard.
    let (st, role) = s
        .node
        .patch(
            &path,
            &s.alice.token,
            json!({ "permissions": perms(&[p::VIEW_CHANNEL, p::SEND_MESSAGES, p::USE_WHITEBOARD]) }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{role}");
    // Channel overrides may not allow them to @everyone either (denying is fine).
    let override_path = format!("/api/v1/rooms/{}/overrides", s.room_id);
    let body = |allow: u64, deny: u64| {
        json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "role", "subject_id": s.everyone,
                "allow": allow.to_string(), "deny": deny.to_string() })
    };
    let (st, j) = s.node.put(&override_path, &s.alice.token, body(p::MANAGE_MESSAGES, 0)).await;
    assert_eq!((st, code(&j)), (StatusCode::BAD_REQUEST, Some("role.everyone_restricted")), "{j}");
    let (st, j) = s.node.put(&override_path, &s.alice.token, body(0, p::MANAGE_MESSAGES | p::SEND_MESSAGES)).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    // Other roles can hold them.
    let (st, role) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Mods", "permissions": perms(&[p::KICK_MEMBERS, p::MANAGE_WHITEBOARD]), "hoist": true }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{role}");
    assert_eq!(role["hoist"], true);
    let (st, j) = s
        .node
        .put(
            &override_path,
            &s.alice.token,
            json!({ "target_type": "channel", "target_id": s.channel,
        "subject_type": "role", "subject_id": role["id"], "allow": p::MANAGE_MESSAGES.to_string(), "deny": "0" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, updated) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{}", s.room_id, role["id"].as_str().unwrap()),
            &s.alice.token,
            json!({ "hoist": false }),
        )
        .await;
    assert_eq!((st, &updated["hoist"]), (StatusCode::OK, &json!(false)), "{updated}");
}

#[tokio::test]
async fn startup_fixup_strips_restricted_bits_from_old_rooms_and_audits() {
    let s = setup().await;
    // An old room whose @everyone had management permissions before the rule existed.
    let bad = (p::DEFAULT_EVERYONE | p::KICK_MEMBERS | p::ADMINISTRATOR) as i64;
    sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
        .bind(bad)
        .bind(&s.everyone)
        .execute(&s.node.state.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO permission_overrides (id, room_id, target_type, target_id, subject_type, subject_id, allow, deny) VALUES ($1, $2, 'channel', $3, 'role', $4, $5, 0)",
    )
    .bind(tavrn_node::util::ulid())
    .bind(&s.room_id)
    .bind(&s.channel)
    .bind(&s.everyone)
    .bind((p::PURGE | p::SEND_MESSAGES) as i64)
    .execute(&s.node.state.db)
    .await
    .unwrap();
    let report = tavrn_node::fixups::run(&s.node.state.db).await.unwrap();
    assert_eq!((report.everyone_roles, report.everyone_overrides), (1, 1));
    let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), &s.alice.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap();
    assert_eq!(everyone["permissions"], p::DEFAULT_EVERYONE.to_string());
    let o = room["overrides"].as_array().unwrap().iter().find(|o| o["subject_id"] == s.everyone.as_str()).unwrap();
    assert_eq!(o["allow"], p::SEND_MESSAGES.to_string());
    let (_, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), &s.alice.token).await;
    let entries: Vec<&Value> =
        log.as_array().unwrap().iter().filter(|e| e["action"] == "role.everyone_restricted").collect();
    assert_eq!(entries.len(), 2, "{log}");
    assert!(entries.iter().any(|e| e["meta"]["names"] == json!(["kick_members", "administrator"])), "{log}");
    // Idempotent.
    assert_eq!(tavrn_node::fixups::run(&s.node.state.db).await.unwrap(), Default::default());
}

async fn eph(node: &TestNode, token: &str, conversation: &str, kind: &str) -> (StatusCode, Value) {
    let body = json!({ "type": kind, "content": { "type": kind }, "session": { "open_for_all": false, "grants": [] } });
    node.post(&format!("/api/v1/conversations/{conversation}/ephemeral"), token, body).await
}

#[tokio::test]
async fn whiteboards_need_use_whiteboard_and_manage_whiteboard_moderates() {
    let s = setup().await;
    let carol = s.node.register("carol").await;
    let (_, invite) = s.node.post(&format!("/api/v1/rooms/{}/invites", s.room_id), &s.alice.token, json!({})).await;
    s.node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    // @everyone without use_whiteboard: bob cannot open a board, even though he may write.
    let everyone = format!("/api/v1/rooms/{}/roles/{}", s.room_id, s.everyone);
    let (st, j) = s
        .node
        .patch(&everyone, &s.alice.token, json!({ "permissions": perms(&[p::VIEW_CHANNEL, p::SEND_MESSAGES]) }))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = eph(&s.node, &s.bob.token, &s.channel, "whiteboard.open").await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.open_forbidden")), "{j}");
    // With it, bob opens; carol cannot close or regrant his board without manage_whiteboard …
    s.node
        .patch(
            &everyone,
            &s.alice.token,
            json!({ "permissions": perms(&[p::VIEW_CHANNEL, p::SEND_MESSAGES, p::USE_WHITEBOARD]) }),
        )
        .await;
    let (st, j) = eph(&s.node, &s.bob.token, &s.channel, "whiteboard.open").await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = eph(&s.node, &carol.token, &s.channel, "whiteboard.grant").await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.not_owner")), "{j}");
    let (st, j) = eph(&s.node, &carol.token, &s.channel, "whiteboard.close").await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.close_forbidden")), "{j}");
    // … manage_channels alone is no longer enough …
    let (_, mods) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Mods", "permissions": perms(&[p::MANAGE_CHANNELS]) }),
        )
        .await;
    let mods_id = mods["id"].as_str().unwrap().to_string();
    let (st, j) = s
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, carol.user_id),
            &s.alice.token,
            json!({ "roles": [mods_id] }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = eph(&s.node, &carol.token, &s.channel, "whiteboard.close").await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.close_forbidden")), "{j}");
    // … with manage_whiteboard she may change the grants and close it.
    s.node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{mods_id}", s.room_id),
            &s.alice.token,
            json!({ "permissions": perms(&[p::MANAGE_WHITEBOARD]) }),
        )
        .await;
    let (st, j) = eph(&s.node, &carol.token, &s.channel, "whiteboard.grant").await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["session"]["owner"], "bob@t.local");
    let (st, j) = eph(&s.node, &carol.token, &s.channel, "whiteboard.close").await;
    assert_eq!(st, StatusCode::OK, "{j}");
    // A channel override can take use_whiteboard away again.
    s.node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            &s.alice.token,
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "member", "subject_id": s.bob.user_id,
                    "allow": "0", "deny": p::USE_WHITEBOARD.to_string() }),
        )
        .await;
    let (st, j) = eph(&s.node, &s.bob.token, &s.channel, "whiteboard.open").await;
    assert_eq!((st, code(&j)), (StatusCode::FORBIDDEN, Some("whiteboard.open_forbidden")), "{j}");
}
