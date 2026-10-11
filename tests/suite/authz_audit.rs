// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Authorization audit (2026-10-09): one regression test per gap found, so that each stays closed. Gaps that need a
//! design decision are `#[ignore]`d with the reason.
use crate::common;

use axum::http::{Method, StatusCode};
use common::e2ee::DOMAIN;
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};

/// Owner `alice`, member `bob`, a plaintext room; returns the room id and its text channel.
async fn room_with(node: &TestNode, owner: &Session, members: &[&Session]) -> (String, String) {
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    for m in members {
        let (s, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &m.token, json!({})).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    (room_id, channel_id)
}

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

// ---------------------------------------------------------------- DMs: message requests and blocks

/// PROTOCOL.md §8a: a requested member "may read the conversation (the preview) but … cannot write
/// (`403 conversation.request_pending`)". Reactions, pins and uploads are writes too.
#[tokio::test]
async fn requested_dm_member_cannot_react_pin_or_upload() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    room_with(&node, &alice.session, &[&bob.session]).await;
    let (s, c) = node.post("/api/v1/conversations", alice.token(), json!({ "kind": "dm", "members": ["bob"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!(c["pending"], json!(["bob@t.local"]));
    let dm = c["id"].as_str().unwrap().to_string();
    node.create_group(&mut alice, &dm).await;
    let (s, m) = node.send_encrypted(&alice, &dm, "hello").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let base = format!("/api/v1/conversations/{dm}");
    let mid = m["id"].as_str().unwrap();

    let (s, j) = node.put(&format!("{base}/messages/{mid}/reactions/%F0%9F%91%8D"), bob.token(), json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "conversation.request_pending"), "reaction: {j}");
    let (s, j) = node.put(&format!("{base}/pins/{mid}"), bob.token(), json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "conversation.request_pending"), "pin: {j}");
    let (s, _, body) = node
        .raw(
            Method::POST,
            &format!("{base}/uploads"),
            bob.token(),
            &[("tavrn-upload-category", "images")],
            vec![7u8; 10],
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "upload: {}", String::from_utf8_lossy(&body));
    // Reading the preview stays possible.
    let (s, _) = node.get_auth(&format!("{base}/messages"), bob.token()).await;
    assert_eq!(s, StatusCode::OK);
}

/// PROTOCOL.md §8a: a requested member of a group DM has not joined it yet: renaming the group or adding members
/// is writing.
#[tokio::test]
async fn requested_group_member_cannot_rename_or_add_members() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let dave = node.register("dave").await;
    room_with(&node, &alice, &[&bob, &carol, &dave]).await;
    let (s, c) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["bob", "carol"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert!(c["pending"].as_array().unwrap().iter().any(|p| p == "bob@t.local"), "{c}");
    let id = c["id"].as_str().unwrap();
    let (s, j) = node.patch(&format!("/api/v1/conversations/{id}"), &bob.token, json!({ "name": "Mine" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "conversation.request_pending"), "rename: {j}");
    let (s, j) = node.post(&format!("/api/v1/conversations/{id}/members"), &bob.token, json!({ "user": "dave" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "conversation.request_pending"), "add: {j}");
    // The creator still can.
    let (s, j) = node.patch(&format!("/api/v1/conversations/{id}"), &alice.token, json!({ "name": "Ours" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// PROTOCOL.md §8a: "a blocked user cannot … write in an existing DM with the blocking user". Reactions and pins
/// are writes as well.
#[tokio::test]
async fn blocked_user_cannot_react_or_pin_in_the_dm() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    node.add_user(&mut alice, &dm, "bob").await;
    node.accept_welcomes(&mut bob).await;
    let (s, m) = node.send_encrypted(&alice, &dm, "hello").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let mid = m["id"].as_str().unwrap();
    let (s, j) = node.post("/api/v1/users/me/blocks", alice.token(), json!({ "user": "bob" })).await;
    assert!(s.is_success(), "{j}");
    let base = format!("/api/v1/conversations/{dm}");
    let (s, j) = node.put(&format!("{base}/messages/{mid}/reactions/%F0%9F%91%8D"), bob.token(), json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "dm.blocked"), "reaction: {j}");
    let (s, j) = node.put(&format!("{base}/pins/{mid}"), bob.token(), json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "dm.blocked"), "pin: {j}");
}

// ---------------------------------------------------------------- Threads

/// permissions.md step 5: "Members in timeout keep only `view_channel` and `read_history` (a timeout limits writing,
/// not reading)". Renaming, locking or archiving one's own thread is writing.
#[tokio::test]
async fn timed_out_thread_creator_cannot_change_the_thread() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel_id) = room_with(&node, &alice, &[&bob]).await;
    let (s, t) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/threads"), &bob.token, json!({ "title": "Mine" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let tid = t["id"].as_str().unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/members/{}/timeout", bob.user_id),
            &alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.patch(&format!("/api/v1/threads/{tid}"), &bob.token, json!({ "title": "Renamed" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.patch(&format!("/api/v1/threads/{tid}"), &bob.token, json!({ "locked": true })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

/// permissions.md step 5: a timeout limits writing. Cursors and whiteboard strokes are writing too: a member in
/// timeout sends no ephemeral events in the room (`403 member.timed_out`), and opens no whiteboard.
#[tokio::test]
async fn timed_out_member_sends_no_ephemeral_events() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel_id) = room_with(&node, &alice, &[&bob]).await;
    let path = format!("/api/v1/conversations/{channel_id}/ephemeral");
    let cursor = json!({ "type": "cursor", "content": { "x": 1, "y": 2 } });
    let (s, j) = node.post(&path, &bob.token, cursor.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/members/{}/timeout", bob.user_id),
            &alice.token,
            json!({ "minutes": 10 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for body in [
        cursor,
        json!({ "type": "whiteboard.stroke", "content": { "points": [] } }),
        json!({ "type": "whiteboard.open", "content": {} }),
    ] {
        let (s, j) = node.post(&path, &bob.token, body).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.timed_out"), "{j}");
    }
    let (s, j) = node.post(&path, &alice.token, json!({ "type": "cursor", "content": {} })).await;
    assert_eq!(s, StatusCode::OK, "the owner is never timed out: {j}");
    // Typing is writing too: bob's notice reaches nobody.
    let mut rx = node.state.hub.subscribe();
    let ws = crate::suite::ws_flow::serve(&node).await;
    let mut bob_ws = crate::suite::ws_flow::hello(&ws, &bob.token).await;
    use futures::SinkExt;
    bob_ws
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({ "op": "typing", "room_id": room_id, "channel_id": channel_id }).to_string().into(),
        ))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    while let Ok(ev) = rx.try_recv() {
        assert_ne!(ev.kind, "typing", "a timed-out member's typing went out");
    }
}

// ---------------------------------------------------------------- Roles, hierarchy and moderation

async fn role(node: &TestNode, owner: &str, room_id: &str, name: &str, bits: &[u64], position: i64) -> String {
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            owner,
            json!({ "name": name, "permissions": common::perms(bits), "position": position }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    role["id"].as_str().unwrap().to_string()
}

async fn assign(node: &TestNode, actor: &str, room_id: &str, user_id: &str, roles: &[&str]) -> (StatusCode, Value) {
    node.patch(&format!("/api/v1/rooms/{room_id}/members/{user_id}"), actor, json!({ "roles": roles })).await
}

/// permissions.md "Hierarchy": members "only kick, ban or time out members whose highest role is lower" and "only
/// manage or assign roles below their own highest position". `PATCH …/members/{id} { roles }` replaces the
/// member's roles: a manager must not strip (or touch) the roles of a member who ranks at or above them.
#[tokio::test]
async fn role_manager_cannot_change_roles_of_a_higher_member() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob, &carol]).await;
    let low = role(&node, &alice.token, &room_id, "Helper", &[p::VIEW_CHANNEL], 1).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_ROLES], 2).await;
    let admin = role(&node, &alice.token, &room_id, "Admin", &[p::MANAGE_ROLES, p::KICK_MEMBERS], 3).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    assert_eq!(assign(&node, &alice.token, &room_id, &carol.user_id, &[&admin]).await.0, StatusCode::OK);

    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[]).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[&low]).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    let c = members.as_array().unwrap().iter().find(|m| m["user"]["id"] == carol.user_id.as_str()).unwrap().clone();
    assert_eq!(c["roles"], json!([admin]), "carol keeps her role: {c}");
}

/// The same for a lower member who holds a role at or above the manager: replacing the list would drop it.
#[tokio::test]
async fn role_manager_cannot_drop_a_role_above_their_own() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob, &carol]).await;
    let low = role(&node, &alice.token, &room_id, "Helper", &[p::VIEW_CHANNEL], 1).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_ROLES], 2).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    // Carol holds the same rank as bob: bob may not touch her.
    assert_eq!(assign(&node, &alice.token, &room_id, &carol.user_id, &[&mods]).await.0, StatusCode::OK);
    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[&low]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    // Bob may still manage himself below his rank... but not drop his own top role through the list? He may.
    let (s, j) = assign(&node, &bob.token, &room_id, &bob.user_id, &[&mods, &low]).await;
    assert_eq!(s, StatusCode::OK, "own roles below the own top position: {j}");
}

/// permissions.md step 4: without `view_channel` "no other permission applies in the channel". A purge over "all
/// channels" must leave the channels the moderator cannot view alone, and naming one is refused.
#[tokio::test]
async fn purge_skips_channels_the_moderator_cannot_view() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, general) = room_with(&node, &alice, &[&bob]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::PURGE], 1).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let secret = ch["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
        .bind(&secret)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": secret, "subject_type": "role", "subject_id": mods, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.send(&alice.token, &room_id, &secret, "staff only").await.0, StatusCode::CREATED);
    assert_eq!(node.send(&alice.token, &room_id, &general, "hello all").await.0, StatusCode::CREATED);

    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");
    let (s, j) = node.post(&path, &bob.token, json!({ "author_id": alice.user_id })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["messages"], 1, "only the visible channel counts: {j}");
    let (s, j) = node.post(&path, &bob.token, json!({ "channel_ids": [secret] })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

/// A purge must never leave its room: with no purgeable channel (here the room kept only its welcome channel) the
/// filter had no conversation clause and reached every message of the node, DMs and other rooms included.
#[tokio::test]
async fn purge_never_reaches_beyond_the_room() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (other_room, other_channel) = room_with(&node, &bob, &[]).await;
    let (s, kept) = node.send(&bob.token, &other_room, &other_channel, "not yours").await;
    assert_eq!(s, StatusCode::CREATED, "{kept}");
    let room = node.create_room(&alice.token, "Empty").await;
    let room_id = room["id"].as_str().unwrap();
    for c in room["channels"].as_array().unwrap().iter().filter(|c| c["kind"] != "system") {
        let (s, j) =
            node.delete(&format!("/api/v1/rooms/{room_id}/channels/{}", c["id"].as_str().unwrap()), &alice.token).await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    }
    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");
    let (s, j) = node.post(&path, &alice.token, json!({ "from": "2000-01-01T00:00:00Z" })).await;
    if s == StatusCode::OK {
        assert_eq!(j["messages"], 0, "the preview counts messages of other rooms: {j}");
        let (_, done) = node
            .post(&path, &alice.token, json!({ "from": "2000-01-01T00:00:00Z", "confirm_token": j["confirm_token"] }))
            .await;
        assert_eq!(done["messages"], 0, "{done}");
    } else {
        assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    }
    let (_, msgs) =
        node.get_auth(&format!("/api/v1/rooms/{other_room}/channels/{other_channel}/messages"), &bob.token).await;
    assert_eq!(msgs.as_array().unwrap().len(), 1, "bob's message survives: {msgs}");
}

/// permissions.md: `manage_roles` covers overrides "only below your own highest role". A member override is a role
/// of one: it must not be set on a member who ranks at or above the actor.
#[tokio::test]
async fn member_override_on_a_higher_member_is_refused() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, channel) = room_with(&node, &alice, &[&bob, &carol]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::VIEW_CHANNEL, p::MANAGE_ROLES], 1).await;
    let admin = role(&node, &alice.token, &room_id, "Admin", &[p::MANAGE_ROLES], 2).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    assert_eq!(assign(&node, &alice.token, &room_id, &carol.user_id, &[&admin]).await.0, StatusCode::OK);
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &bob.token,
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member", "subject_id": carol.user_id, "allow": "0", "deny": common::perms(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
}

/// permissions.md: overrides grant "only permissions you hold". What the actor holds is decided in the channel, not
/// in the room: a manager who cannot view a private channel must not open it to themselves (or anyone).
#[tokio::test]
async fn override_cannot_open_a_channel_the_actor_cannot_view() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_ROLES], 1).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = detail["roles"].as_array().unwrap().iter().find(|r| r["name"] == "@everyone").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let staff = ch["id"].as_str().unwrap().to_string();
    let deny_view = json!({ "target_type": "channel", "target_id": staff, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) });
    assert_eq!(
        node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, deny_view).await.0,
        StatusCode::OK
    );
    let path = format!("/api/v1/rooms/{room_id}/channels/{staff}/messages");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN);

    let own = json!({ "target_type": "channel", "target_id": staff, "subject_type": "member", "subject_id": bob.user_id, "allow": common::perms(&[p::VIEW_CHANNEL]), "deny": "0" });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &bob.token, own).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "self-grant: {j}");
    let clear = json!({ "target_type": "channel", "target_id": staff, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": "0" });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &bob.token, clear).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "removing the deny: {j}");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "still private");
}

/// permissions.md step 4: without `view_channel` no other permission applies in the channel, `manage_channels`
/// included: a channel manager cannot rename or delete a channel hidden from them.
#[tokio::test]
async fn channel_manager_cannot_change_a_channel_they_cannot_view() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_CHANNELS], 1).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let (_, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    let staff = ch["id"].as_str().unwrap().to_string();
    let deny = json!({ "target_type": "channel", "target_id": staff, "subject_type": "role", "subject_id": mods, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) });
    assert_eq!(node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, deny).await.0, StatusCode::OK);
    let path = format!("/api/v1/rooms/{room_id}/channels/{staff}");
    let (s, j) = node.patch(&path, &bob.token, json!({ "name": "renamed" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.delete(&path, &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

/// permissions.md "Hierarchy": a domain ban removes every member of that domain, so it must not remove one who
/// outranks the actor.
#[tokio::test]
async fn domain_ban_respects_the_hierarchy() {
    use tavrn_node::{permissions as p, store};
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::BAN_MEMBERS], 1).await;
    let admin = role(&node, &alice.token, &room_id, "Admin", &[p::BAN_MEMBERS], 2).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let remote = store::federation::create_remote_user(&node.state.db, "dana", "far.example", "Dana", "user", None)
        .await
        .unwrap();
    store::rooms::add_member(&node.state.db, &room_id, &remote.id, true).await.unwrap();
    store::rooms::set_member_roles(&node.state.db, &room_id, &remote.id, std::slice::from_ref(&admin)).await.unwrap();
    let (s, j) =
        node.post(&format!("/api/v1/rooms/{room_id}/bans"), &bob.token, json!({ "subject": "far.example" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "member.hierarchy"), "{j}");
    assert!(store::rooms::member(&node.state.db, &room_id, &remote.id).await.unwrap().is_some(), "dana stays");
}

/// `@everyone` is reserved on create; renaming a role to it spoofs the base role in every client.
#[tokio::test]
async fn role_cannot_be_renamed_to_everyone() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let (room_id, _) = room_with(&node, &alice, &[]).await;
    let r = role(&node, &alice.token, &room_id, "Fake", &[], 1).await;
    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}/roles/{r}"), &alice.token, json!({ "name": "@everyone" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "role.name_reserved"), "{j}");
}

// ---------------------------------------------------------------- Keys and calls

/// FEDERATION.md §3.5: a home node "refuses with `403 federation.claim_refused` if `user` blocked `requester`". The
/// same must hold for claims on the user's own node, or the block is bypassed by asking locally.
#[tokio::test]
async fn blocked_user_cannot_claim_key_packages_locally() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let bob = node.register("bob").await;
    let (s, j) = node.post("/api/v1/users/me/blocks", alice.token(), json!({ "user": "bob" })).await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.claim_refused"), "{j}");
}

/// PROTOCOL.md §8a: blocks always win. A call from a blocked person would ring nowhere but still end as a missed
/// call message in the DM, so starting one is refused.
#[tokio::test]
async fn blocked_user_cannot_start_a_call() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    node.befriend(&alice, &bob).await;
    let (s, c) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["bob"] })).await;
    assert!(s.is_success(), "{c}");
    let id = c["id"].as_str().unwrap();
    let (s, j) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "bob" })).await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post(&format!("/api/v1/conversations/{id}/call/start"), &bob.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "dm.blocked"), "{j}");
}

// ---------------------------------------------------------------- Bots and "no bots"

/// APPLICATIONS.md §3.5: "Bots can never change these settings or the no_bots flags … whatever their roles and
/// scopes", and no_bots channels are invisible to them. Moving a channel out of a "no bots" category, or deleting
/// the category, lifts the flag as well.
#[tokio::test]
async fn bot_cannot_lift_no_bots_through_the_category() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let body =
        json!({ "name": "Janitor", "public": true, "requested_permissions": common::perms(&[p::MANAGE_CHANNELS]) });
    let (s, app) = node.post("/api/v1/applications", &alice.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap();
    let (s, t) =
        node.post(&format!("/api/v1/applications/{app_id}/tokens"), &alice.token, json!({ "name": "t" })).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let bot = t["secret"].as_str().unwrap().to_string();
    let (room_id, _) = room_with(&node, &carol, &[]).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": format!("{DOMAIN}/{app_id}"), "permissions": common::perms(&[p::MANAGE_CHANNELS]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, cat) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &carol.token, json!({ "name": "staff" })).await;
    assert_eq!(s, StatusCode::CREATED, "{cat}");
    let cat = cat["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/categories/{cat}"), &carol.token, json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &carol.token,
            json!({ "kind": "text", "name": "secrets", "encrypted": false, "category_id": cat }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let secrets = ch["id"].as_str().unwrap().to_string();
    assert_eq!(ch["no_bots_effective"], true, "{ch}");

    let (s, j) =
        node.patch(&format!("/api/v1/rooms/{room_id}/channels/{secrets}"), &bot, json!({ "category_id": null })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "move out of the category: {j}");
    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}/categories/{cat}"), &bot).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "delete the category: {j}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &carol.token).await;
    let c = detail["channels"].as_array().unwrap().iter().find(|c| c["id"] == secrets.as_str()).unwrap().clone();
    assert_eq!(c["no_bots_effective"], true, "{c}");
}

// ---------------------------------------------------------------- Open: need a design decision

/// `GET /rooms/{id}` sent every channel (name, topic) to every member; only bots got the channels they can view.
/// Since the layered permissions it lists only the channels the requester can view (permissions.md "Evaluation").
#[tokio::test]
async fn room_detail_hides_channels_the_member_cannot_view() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob]).await;
    let (_, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    let staff = ch["id"].as_str().unwrap().to_string();
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = detail["roles"][0]["id"].as_str().unwrap().to_string();
    let deny = json!({ "target_type": "channel", "target_id": staff, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) });
    assert_eq!(node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, deny).await.0, StatusCode::OK);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert!(!detail["channels"].as_array().unwrap().iter().any(|c| c["id"] == staff.as_str()), "{detail}");
}

/// A room with a category `staff` that hides its channels from `@everyone` and a channel `plans` in it; returns
/// (room, category, channel, @everyone role).
async fn private_category(node: &TestNode, owner: &Session, members: &[&Session]) -> (String, String, String, String) {
    use tavrn_node::permissions as p;
    let (room_id, _) = room_with(node, owner, members).await;
    let (_, cat) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &owner.token, json!({ "name": "staff" })).await;
    let cat = cat["id"].as_str().unwrap().to_string();
    let (_, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &owner.token,
            json!({ "kind": "text", "name": "plans", "encrypted": false, "category_id": cat }),
        )
        .await;
    let plans = ch["id"].as_str().unwrap().to_string();
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &owner.token).await;
    let everyone = detail["roles"][0]["id"].as_str().unwrap().to_string();
    let deny = json!({ "target_type": "category", "target_id": cat, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) });
    assert_eq!(node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &owner.token, deny).await.0, StatusCode::OK);
    (room_id, cat, plans, everyone)
}

/// Deleting a category (`manage_channels` only) left its channels without a category: their category overrides
/// stopped applying and a private channel became public. The category's overrides are now copied into each of its
/// channels first (permissions.md "Moving channels"), audited.
#[tokio::test]
async fn deleting_a_category_keeps_its_channels_private() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, cat, plans, _) = private_category(&node, &alice, &[&bob]).await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{plans}/messages");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN);
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/categories/{cat}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "the channel became public");
    assert_eq!(node.get_auth(&path, &alice.token).await.0, StatusCode::OK);
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &alice.token).await;
    assert!(log.to_string().contains("channel.overrides_copied"), "{log}");
}

/// The same for moving a channel out of its category, to no category or into another one.
#[tokio::test]
async fn moving_a_channel_out_of_a_private_category_keeps_it_private() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, _, plans, _) = private_category(&node, &alice, &[&bob]).await;
    let (_, other) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &alice.token, json!({ "name": "open" })).await;
    let other = other["id"].as_str().unwrap().to_string();
    let channel = format!("/api/v1/rooms/{room_id}/channels/{plans}");
    let path = format!("{channel}/messages");
    let (s, j) = node.patch(&channel, &alice.token, json!({ "category_id": other })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "moved into another category");
    let (s, j) = node.patch(&channel, &alice.token, json!({ "category_id": null })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "moved out of every category");
}

/// Copying is not enough when the channel's own overrides decide the same bits for other subjects: the category
/// lets one role view, the channel hides itself from another role (the channel layer wins for members of both). In
/// one layer the allow would win; the member who would gain gets a deny of their own.
#[tokio::test]
async fn moving_a_channel_never_grants_what_the_layers_denied() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, cat, plans, _) = private_category(&node, &alice, &[&bob, &carol]).await;
    let helpers = role(&node, &alice.token, &room_id, "Helpers", &[], 1).await;
    let muted = role(&node, &alice.token, &room_id, "Muted", &[], 2).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&helpers, &muted]).await.0, StatusCode::OK);
    assert_eq!(assign(&node, &alice.token, &room_id, &carol.user_id, &[&helpers]).await.0, StatusCode::OK);
    let overrides = format!("/api/v1/rooms/{room_id}/overrides");
    let allow = json!({ "target_type": "category", "target_id": cat, "subject_type": "role", "subject_id": helpers, "allow": common::perms(&[p::VIEW_CHANNEL]), "deny": "0" });
    assert_eq!(node.put(&overrides, &alice.token, allow).await.0, StatusCode::OK);
    let deny = json!({ "target_type": "channel", "target_id": plans, "subject_type": "role", "subject_id": muted, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) });
    assert_eq!(node.put(&overrides, &alice.token, deny).await.0, StatusCode::OK);
    let path = format!("/api/v1/rooms/{room_id}/channels/{plans}/messages");
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "the channel layer wins");
    assert_eq!(node.get_auth(&path, &carol.token).await.0, StatusCode::OK, "carol keeps it");
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/categories/{cat}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(node.get_auth(&path, &bob.token).await.0, StatusCode::FORBIDDEN, "bob gained the channel");
    assert_eq!(node.get_auth(&path, &carol.token).await.0, StatusCode::OK, "carol keeps it");
}

/// Moving a channel into a category whose overrides grant more needs `manage_roles` (in that category), like
/// setting those overrides would.
#[tokio::test]
async fn moving_a_channel_into_a_granting_category_needs_manage_roles() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob, &carol]).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_CHANNELS], 2).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let helpers = role(&node, &alice.token, &room_id, "Helpers", &[], 1).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &carol.user_id, &[&helpers]).await.0, StatusCode::OK);
    let (_, cat) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &alice.token, json!({ "name": "helpers" })).await;
    let cat = cat["id"].as_str().unwrap().to_string();
    let (_, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "text", "name": "quiet", "encrypted": false }),
        )
        .await;
    let quiet = ch["id"].as_str().unwrap().to_string();
    // The category lets its helpers manage messages.
    let grant = json!({ "target_type": "category", "target_id": cat, "subject_type": "role", "subject_id": helpers, "allow": common::perms(&[p::MANAGE_MESSAGES]), "deny": "0" });
    assert_eq!(node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, grant).await.0, StatusCode::OK);
    let channel = format!("/api/v1/rooms/{room_id}/channels/{quiet}");
    let (s, j) = node.patch(&channel, &bob.token, json!({ "category_id": cat })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "role.manage_forbidden"), "{j}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let moved = detail["channels"].as_array().unwrap().iter().find(|c| c["id"] == quiet.as_str()).unwrap().clone();
    assert_eq!(moved["category_id"], Value::Null, "{moved}");
    // A category that grants nothing new: a move with manage_channels alone.
    let (_, plain) =
        node.post(&format!("/api/v1/rooms/{room_id}/categories"), &alice.token, json!({ "name": "plain" })).await;
    let (s, j) = node.patch(&channel, &bob.token, json!({ "category_id": plain["id"] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The owner may move it into the granting one.
    let (s, j) = node.patch(&channel, &alice.token, json!({ "category_id": null })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.patch(&channel, &alice.token, json!({ "category_id": cat })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// permissions.md "Hierarchy": members "only grant permissions they hold themselves". Assigning a role is granting
/// its bits: a manager below the role's position still cannot hand out (to others or to themselves) a role that
/// carries bits they lack. The owner can.
#[tokio::test]
async fn role_assignment_grants_only_bits_the_actor_holds() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let (room_id, _) = room_with(&node, &alice, &[&bob, &carol]).await;
    let bans = role(&node, &alice.token, &room_id, "Bans", &[p::BAN_MEMBERS], 2).await;
    let helper = role(&node, &alice.token, &room_id, "Helper", &[p::VIEW_CHANNEL], 1).await;
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_ROLES], 5).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);

    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[&bans]).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "role.escalation"), "to another member: {j}");
    let (s, j) = assign(&node, &bob.token, &room_id, &bob.user_id, &[&mods, &bans]).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "role.escalation"), "to themselves: {j}");
    // Bits the manager holds stay assignable.
    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[&helper]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The owner may hand out any role.
    let (s, j) = assign(&node, &alice.token, &room_id, &carol.user_id, &[&bans]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // A role the member already holds may stay in the list of a manager who lacks its bits (it is not granted anew).
    let (s, j) = assign(&node, &bob.token, &room_id, &carol.user_id, &[&bans, &helper]).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// A limited invite admits exactly as many people as it allows, also when they redeem it at the same moment (the
/// use is claimed before the join, not counted after it).
#[tokio::test]
async fn a_single_use_invite_admits_one_member_under_concurrent_joins() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, invite) =
        node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({ "max_uses": 1 })).await;
    assert_eq!(s, StatusCode::CREATED, "{invite}");
    let join = format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap());
    let mut users = Vec::new();
    for i in 0..8 {
        users.push(node.register(&format!("joiner{i}")).await);
    }
    let results = futures::future::join_all(users.iter().map(|u| node.post(&join, &u.token, json!({})))).await;
    let ok = results.iter().filter(|(s, _)| *s == StatusCode::OK).count();
    assert_eq!(ok, 1, "{results:?}");
    for (s, j) in results.iter().filter(|(s, _)| *s != StatusCode::OK) {
        assert_eq!((*s, code(j)), (StatusCode::NOT_FOUND, "invite.invalid"), "{j}");
    }
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    assert_eq!(members.as_array().unwrap().len(), 2, "the owner and one joiner: {members}");
}

/// Sends a DM `typing` op over a WebSocket of `token` and returns the users the hub delivered it to (empty: it went
/// nowhere).
async fn dm_typing_reaches(node: &TestNode, token: &str, conversation_id: &str) -> Vec<String> {
    use futures::SinkExt;
    let mut rx = node.state.hub.subscribe();
    let ws = crate::suite::ws_flow::serve(node).await;
    let mut sock = crate::suite::ws_flow::hello(&ws, token).await;
    sock.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({ "op": "typing", "conversation_id": conversation_id }).to_string().into(),
    ))
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut to = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if ev.kind == "typing"
            && let tavrn_node::hub::Scope::Users(users) = &ev.scope
        {
            to.extend(users.iter().cloned());
        }
    }
    to
}

/// PROTOCOL.md §8a: blocks always win and a requested member has not joined yet. Typing in a DM is writing: a
/// blocked person's typing reaches nobody, a requested member's typing is not sent, and the members' typing does
/// not reach the requested member either.
#[tokio::test]
async fn dm_typing_respects_blocks_and_message_requests() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    node.befriend(&alice, &bob).await;
    let (s, c) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["bob"] })).await;
    assert!(s.is_success(), "{c}");
    let dm = c["id"].as_str().unwrap().to_string();
    assert!(dm_typing_reaches(&node, &bob.token, &dm).await.contains(&alice.user_id), "typing works between friends");
    let (s, j) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "bob" })).await;
    assert!(s.is_success(), "{j}");
    assert_eq!(dm_typing_reaches(&node, &bob.token, &dm).await, Vec::<String>::new(), "blocked: nobody");

    // A message request: carol writes to alice, who has not accepted.
    room_with(&node, &carol, &[&alice]).await;
    let (s, c) = node.post("/api/v1/conversations", &carol.token, json!({ "kind": "dm", "members": ["alice"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!(c["pending"], json!(["alice@t.local"]), "{c}");
    let req = c["id"].as_str().unwrap().to_string();
    assert_eq!(dm_typing_reaches(&node, &alice.token, &req).await, Vec::<String>::new(), "requested member");
    let to = dm_typing_reaches(&node, &carol.token, &req).await;
    assert!(!to.contains(&alice.user_id), "the requester's typing does not reach the requested member: {to:?}");
}

/// PROTOCOL.md §8a: blocks always win, also for calls. Blocking ends a running call of the DM, and a blocked person
/// cannot (re)join a call.
#[tokio::test]
async fn blocking_ends_the_dm_call_and_blocked_users_cannot_join() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    node.befriend(&alice, &bob).await;
    let (s, c) = node.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["bob"] })).await;
    assert!(s.is_success(), "{c}");
    let id = c["id"].as_str().unwrap().to_string();
    let (s, j) = node.post(&format!("/api/v1/conversations/{id}/call/start"), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(node.state.calls.is_active(&id));
    let (s, j) = node.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "bob" })).await;
    assert!(s.is_success(), "{j}");
    assert!(!node.state.calls.is_active(&id), "the block ended the call");
    let (s, j) = node.post(&format!("/api/v1/conversations/{id}/call/join"), &bob.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "dm.blocked"), "{j}");
}

/// permissions.md "Hierarchy" and bit 8: overrides set "only permissions you hold". Taking a permission away from
/// others (a deny bit) and the upload categories of an override count too: a manager cannot deny what they do not
/// hold, nor allow (or deny) upload categories they cannot use there.
#[tokio::test]
async fn overrides_deny_and_upload_categories_stay_within_the_actor_s_own() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
            &alice.token,
            json!({ "allowed_upload_categories": ["images"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mods = role(&node, &alice.token, &room_id, "Mod", &[p::MANAGE_ROLES], 5).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&mods]).await.0, StatusCode::OK);
    let path = format!("/api/v1/rooms/{room_id}/overrides");
    let body = |subject_type: &str, subject: &str, deny: u64, extra: Value| {
        let mut b = json!({ "target_type": "channel", "target_id": channel_id, "subject_type": subject_type,
                            "subject_id": subject, "allow": "0", "deny": deny.to_string() });
        b.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        b
    };

    let (s, j) = node.put(&path, &bob.token, body("role", &everyone, p::MANAGE_MESSAGES, json!({}))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "override.escalation"), "deny of a bit bob lacks: {j}");
    let (s, j) =
        node.put(&path, &bob.token, body("member", &bob.user_id, 0, json!({ "upload_allow": ["archives"] }))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "override.escalation"), "upload category bob lacks: {j}");
    let (s, j) = node.put(&path, &bob.token, body("role", &everyone, 0, json!({ "upload_deny": ["video"] }))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "override.escalation"), "deny of a category bob lacks: {j}");
    // What bob holds stays possible; the owner may do anything.
    let (s, j) = node
        .put(&path, &bob.token, body("role", &everyone, p::SEND_MESSAGES, json!({ "upload_deny": ["images"] })))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .put(&path, &alice.token, body("role", &everyone, p::MANAGE_MESSAGES, json!({ "upload_allow": ["archives"] })))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// PROTOCOL.md §6 audiences: a purge over several channels must not name, to a member, the channels hidden from
/// them. Each channel's `message.purge` reaches that channel's viewers only.
#[tokio::test]
async fn purge_events_name_only_channels_the_member_can_view() {
    use futures::StreamExt;
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, general) = room_with(&node, &alice, &[&bob]).await;
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let secret = ch["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
        .bind(&secret)
        .execute(&node.state.db)
        .await
        .unwrap();
    let everyone = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await.1["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["is_everyone"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": secret, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.send(&alice.token, &room_id, &secret, "staff only").await.0, StatusCode::CREATED);
    assert_eq!(node.send(&alice.token, &room_id, &general, "hello all").await.0, StatusCode::CREATED);

    let ws = crate::suite::ws_flow::serve(&node).await;
    let mut bob_ws = crate::suite::ws_flow::hello(&ws, &bob.token).await;
    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");
    let (s, preview) = node.post(&path, &alice.token, json!({ "author_id": alice.user_id })).await;
    assert_eq!(s, StatusCode::OK, "{preview}");
    let (s, j) = node
        .post(&path, &alice.token, json!({ "author_id": alice.user_id, "confirm_token": preview["confirm_token"] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut named = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(800);
    while let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t)))) =
        tokio::time::timeout_at(deadline, bob_ws.next()).await
    {
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["type"] == "message.purge" {
            named.extend(v["data"]["conversation_ids"].as_array().unwrap().iter().cloned());
        }
    }
    assert!(named.contains(&json!(general)), "bob learns of the purge in the channel he sees: {named:?}");
    assert!(!named.contains(&json!(secret)), "but never of the hidden channel: {named:?}");
}

/// `manage_webhooks` is channel-scoped (permissions.md): the room-wide list shows a manager only the webhooks of the
/// channels they can view and manage, never those of a channel hidden from them.
#[tokio::test]
async fn the_room_webhook_list_leaves_out_hidden_channels() {
    use tavrn_node::permissions as p;
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, general) = room_with(&node, &alice, &[&bob]).await;
    let hooks = role(&node, &alice.token, &room_id, "Hooks", &[p::MANAGE_WEBHOOKS], 1).await;
    assert_eq!(assign(&node, &alice.token, &room_id, &bob.user_id, &[&hooks]).await.0, StatusCode::OK);
    let (s, ch) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), &alice.token, json!({ "kind": "text", "name": "staff" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    let secret = ch["id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE conversations SET encrypted = 0 WHERE id = $1")
        .bind(&secret)
        .execute(&node.state.db)
        .await
        .unwrap();
    for (channel, name) in [(&general, "public hook"), (&secret, "staff hook")] {
        let (s, j) = node
            .post(
                &format!("/api/v1/rooms/{room_id}/channels/{channel}/webhooks"),
                &alice.token,
                json!({ "name": name }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": secret, "subject_type": "role", "subject_id": hooks, "allow": "0", "deny": common::perms(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/webhooks"), &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let names: Vec<&str> = list.as_array().unwrap().iter().map(|w| w["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["public hook"], "{list}");
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/webhooks"), &alice.token).await;
    assert_eq!(list.as_array().unwrap().len(), 2, "the owner sees both: {list}");
}
