// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Notification settings: storage and validation, how they change unread and mention
//! counts, role mentions, and that unwanted `notify` hints are dropped by the home node.
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::{federation::social::Incoming, permissions as p, store};

const DOMAIN: &str = "t.local";

struct Setup {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    Setup { node, alice, bob, room_id, channel }
}

async fn read_state(s: &Setup, token: &str) -> Value {
    let (_, room) = s.node.get_auth(&format!("/api/v1/rooms/{}", s.room_id), token).await;
    room["read_states"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["conversation_id"] == s.channel.as_str())
        .cloned()
        .unwrap()
}

fn counts(state: &Value) -> (i64, i64, bool) {
    (
        state["unread_count"].as_i64().unwrap(),
        state["mention_count"].as_i64().unwrap(),
        state["muted"].as_bool().unwrap(),
    )
}

async fn send(s: &Setup, token: &str, mentions: Value, everyone: bool) -> (StatusCode, Value) {
    s.node
        .post(
            &format!("/api/v1/conversations/{}/messages", s.channel),
            token,
            json!({ "content": { "type": "text", "body": "hey" }, "mentions": mentions, "mentions_everyone": everyone }),
        )
        .await
}

#[tokio::test]
async fn settings_are_stored_validated_and_returned_with_me() {
    let s = setup().await;
    let path = "/api/v1/users/me/notification-settings";
    let (st, j) = s.node.get_auth(path, &s.bob.token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(j, json!({ "global": { "mode": "all", "sound": true, "browser": false }, "rooms": {}, "channels": {} }));
    let body = json!({
        "global": { "mode": "mentions", "sound": false, "browser": true },
        "rooms": { s.room_id.clone(): { "suppress_everyone": true } },
        "channels": { s.channel.clone(): { "muted_until": "forever" } }
    });
    let (st, saved) = s.node.put(path, &s.bob.token, body).await;
    assert_eq!(st, StatusCode::OK, "{saved}");
    let (_, me) = s.node.get_auth("/api/v1/users/me", &s.bob.token).await;
    assert_eq!(me["notification_settings"], saved);
    assert_eq!(me["notification_settings"]["channels"][&s.channel]["muted_until"], "forever");
    for bad in [
        json!({ "global": { "mode": "loud" } }),
        json!({ "rooms": { "not-an-id": { "mode": "all" } } }),
        json!({ "channels": { s.channel.clone(): { "muted_until": "tomorrow" } } }),
        json!({ "unknown": true }),
    ] {
        let (st, j) = s.node.put(path, &s.bob.token, bad.clone()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}: {j}");
    }
    let many: serde_json::Map<String, Value> =
        (0..501).map(|_| (tavrn_node::util::ulid(), json!({ "mode": "all" }))).collect();
    let (st, j) = s.node.put(path, &s.bob.token, json!({ "rooms": many })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("notifications.invalid")), "{j}");
}

#[tokio::test]
async fn role_mentions_count_and_settings_change_the_counts() {
    let s = setup().await;
    let (_, role) = s
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", s.room_id),
            &s.alice.token,
            json!({ "name": "Raiders", "mentionable": false }),
        )
        .await;
    let role_id = role["id"].as_str().unwrap().to_string();
    s.node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", s.room_id, s.bob.user_id),
            &s.alice.token,
            json!({ "roles": [role_id] }),
        )
        .await;

    // A role mention counts for its members.
    let (st, m) = send(&s, &s.alice.token, json!([format!("role:{}", role_id.to_lowercase())]), false).await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    assert_eq!(m["mentions"], json!([format!("role:{role_id}")]), "stored canonical");
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (1, 1, false));
    // Members without mention_everyone cannot ping roles that are not mentionable; unknown roles fail.
    let (st, j) = send(&s, &s.bob.token, json!([format!("role:{role_id}")]), false).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("message.mention_role_forbidden")), "{j}");
    let (st, j) = send(&s, &s.bob.token, json!([format!("role:{}", tavrn_node::util::ulid())]), false).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("message.mention_invalid")), "{j}");

    // @everyone counts unless the room suppresses it.
    let (st, j) = send(&s, &s.alice.token, json!([]), true).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (2, 2, false));
    let path = "/api/v1/users/me/notification-settings";
    s.node.put(path, &s.bob.token, json!({ "rooms": { s.room_id.clone(): { "suppress_everyone": true } } })).await;
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (2, 1, false));
    // Mode `nothing`: unread still shows, mentions do not.
    s.node.put(path, &s.bob.token, json!({ "channels": { s.channel.clone(): { "mode": "nothing" } } })).await;
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (2, 0, false));
    // Muted (here: the room until later): nothing counts.
    let until = tavrn_node::util::in_seconds(3600);
    s.node.put(path, &s.bob.token, json!({ "rooms": { s.room_id.clone(): { "muted_until": until } } })).await;
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (0, 0, true));
    // An expired mute is no mute.
    let past = tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::minutes(1));
    s.node.put(path, &s.bob.token, json!({ "rooms": { s.room_id.clone(): { "muted_until": past } } })).await;
    assert_eq!(counts(&read_state(&s, &s.bob.token).await), (2, 2, false));
    // The read route answers with the same rules.
    let (_, list) = s.node.get_auth(&format!("/api/v1/conversations/{}/messages", s.channel), &s.bob.token).await;
    let newest = list[0]["id"].as_str().unwrap().to_string();
    s.node.put(path, &s.bob.token, json!({ "channels": { s.channel.clone(): { "muted_until": "forever" } } })).await;
    let (st, rs) = s
        .node
        .put(
            &format!("/api/v1/conversations/{}/read", s.channel),
            &s.bob.token,
            json!({ "last_read_message_id": newest }),
        )
        .await;
    assert_eq!((st, rs["muted"].as_bool()), (StatusCode::OK, Some(true)), "{rs}");
    let _ = perms(&[p::VIEW_CHANNEL]);
}

#[tokio::test]
async fn home_node_drops_hints_the_user_does_not_want() {
    let s = setup().await;
    let bob = store::users::by_id(&s.node.state.db, &s.bob.user_id).await.unwrap().unwrap();
    // Hints come only from nodes bob signed in on (FEDERATION.md §5.2).
    store::federation::touch_target(&s.node.state.db, &bob.id, &s.bob.device_id, "b.test").await.unwrap();
    let room = tavrn_node::util::ulid();
    let conv = tavrn_node::util::ulid();
    let hint = |mention: bool, everyone: bool| Incoming::Notify {
        conversation_id: conv.clone(),
        room_id: Some(room.clone()),
        mention,
        everyone,
        call: None,
    };
    let handle = |incoming: Incoming| {
        let (state, bob) = (s.node.state.clone(), bob.clone());
        async move {
            tavrn_node::federation::social::handle(&state, "b.test", "b.test", &bob, &tavrn_node::util::now(), incoming)
                .await
                .unwrap()
        }
    };
    assert_eq!(handle(hint(false, false)).await, "stored");
    let path = "/api/v1/users/me/notification-settings";
    // Mentions only: plain messages are dropped, @everyone too when suppressed.
    s.node
        .put(
            path,
            &s.bob.token,
            json!({ "rooms": { room.clone(): { "mode": "mentions", "suppress_everyone": true } } }),
        )
        .await;
    assert_eq!(handle(hint(false, false)).await, "muted");
    assert_eq!(handle(hint(true, true)).await, "muted");
    assert_eq!(handle(hint(true, false)).await, "stored");
    // A muted conversation gets nothing.
    s.node.put(path, &s.bob.token, json!({ "channels": { conv.clone(): { "muted_until": "forever" } } })).await;
    assert_eq!(handle(hint(true, false)).await, "muted");
    assert_eq!(store::invites::hint_count(&s.node.state.db, &bob.id).await.unwrap(), 2);
}
