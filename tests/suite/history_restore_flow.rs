// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! History restore after a key reset (ENCRYPTION.md §7b "History after a key reset"): the reset sets
//! `key_reset_at` on the memberships, the message cut and the automatic shares start at the reset, and history from
//! before it comes back only through a request that a member with `restore_history` approves.
use crate::common;

use axum::http::StatusCode;
use common::e2ee::{DOMAIN, Dev, b64, qualified};
use common::{TestNode, test_node};
use serde_json::{Value, json};
use tavrn_crypto::MasterSecret;
use tavrn_node::{hub::Scope, permissions as p};

struct Setup {
    node: TestNode,
    alice: Dev,
    /// Bob after the reset: same session, new master secret, re-attested and back in the channel's group.
    bob: Dev,
    room_id: String,
    channel: String,
    welcome: String,
}

fn bob_address() -> String {
    format!("bob@{DOMAIN}")
}

async fn join(node: &TestNode, owner: &str, room_id: &str, token: &str) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

async fn external_join(node: &TestNode, dev: &mut Dev, channel: &str) {
    let (s, gi) = node.get_auth(&format!("/api/v1/conversations/{channel}/mls/group-info"), dev.token()).await;
    assert_eq!(s, StatusCode::OK, "{gi}");
    let gi = common::e2ee::unb64(&gi["group_info"]);
    let out = dev.client.join_by_external_commit(&qualified(channel), &gi).unwrap();
    let (s, j) = node.post_commit(dev.token(), channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    dev.client.merge_pending_commit(&qualified(channel)).unwrap();
}

async fn encrypted_count(node: &TestNode, token: &str, channel: &str) -> usize {
    let (s, list) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list.as_array().unwrap().iter().filter(|m| m["encrypted"] == true).count()
}

async fn sleep() {
    // Message ids and times have millisecond resolution.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

async fn reset(node: &TestNode, dev: Dev) -> Dev {
    let fresh = MasterSecret::generate().unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            dev.token(),
            json!({ "identity_public_key": b64(&fresh.identity_public_key()), "password": common::password(&dev.session.username) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    // The lost device is gone; the user signs in on a new one and attests it under the new key.
    let session = node.login(&dev.session.username).await;
    node.attest(session, fresh, 3).await
}

/// Alice owns a room whose encrypted channel (policy `all`) has a message from before Bob's join (epoch 0) and one
/// he could read (epoch 1). Bob resets his key, Alice writes once more (still epoch 1), and Bob's re-attested device
/// joins the group again (epoch 2).
async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Archive").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let welcome = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    node.create_group(&mut alice, &channel).await;
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}"),
            alice.token(),
            json!({ "history_for_new_members": "all" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.send_encrypted(&alice, &channel, "Before Bob").await.0, StatusCode::CREATED);
    sleep().await;
    let mut bob = node.crypto_user("bob").await;
    join(&node, alice.token(), &room_id, bob.token()).await;
    external_join(&node, &mut bob, &channel).await;
    node.catch_up(&mut alice, &channel).await;
    assert_eq!(node.send_encrypted(&alice, &channel, "Bob was there").await.0, StatusCode::CREATED);
    assert_eq!(encrypted_count(&node, bob.token(), &channel).await, 2, "policy all: Bob reads everything");
    sleep().await;
    let bob = reset(&node, bob).await;
    sleep().await;
    assert_eq!(node.send_encrypted(&alice, &channel, "After the reset").await.0, StatusCode::CREATED);
    Setup { node, alice, bob, room_id, channel, welcome }
}

/// Bob's device back in the group (the external commit replaces his old leaf).
async fn rejoin(s: &mut Setup) {
    external_join(&s.node, &mut s.bob, &s.channel).await;
    s.node.catch_up(&mut s.alice, &s.channel).await;
}

fn share_body(s: &Setup, to: &str, epoch_from: i64, epoch_to: i64) -> Value {
    let ciphertext = s
        .alice
        .client
        .encrypt_content(&qualified(&s.channel), &json!({ "type": "history_keys", "epochs": [] }).to_string())
        .unwrap();
    json!({ "to_user": to, "epoch_from": epoch_from, "epoch_to": epoch_to, "ciphertext": ciphertext })
}

async fn share(s: &Setup, token: &str, epoch_from: i64, epoch_to: i64) -> (StatusCode, Value) {
    s.node
        .post(
            &format!("/api/v1/conversations/{}/history-keys", s.channel),
            token,
            share_body(s, &bob_address(), epoch_from, epoch_to),
        )
        .await
}

fn requests(s: &Setup) -> String {
    format!("/api/v1/rooms/{}/history-requests", s.room_id)
}

async fn mine(s: &Setup) -> Value {
    let (st, j) = s.node.get_auth(&format!("{}/mine", requests(s)), s.bob.token()).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    j
}

async fn ask(s: &Setup, token: &str, message: &str) -> (StatusCode, Value) {
    s.node.post(&requests(s), token, json!({ "message": message })).await
}

async fn audit(s: &Setup, action: &str) -> Vec<Value> {
    let (st, log) = s.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", s.room_id), s.alice.token()).await;
    assert_eq!(st, StatusCode::OK, "{log}");
    log.as_array().unwrap().iter().filter(|e| e["action"] == action).cloned().collect()
}

/// Welcome channel entries of `kind`, oldest first.
async fn welcome_entries(s: &Setup, kind: &str) -> Vec<Value> {
    let (st, msgs) = s.node.get_auth(&format!("/api/v1/conversations/{}/messages", s.welcome), s.alice.token()).await;
    assert_eq!(st, StatusCode::OK, "{msgs}");
    let mut list: Vec<Value> =
        msgs.as_array().unwrap().iter().map(|m| m["content"].clone()).filter(|c| c["type"] == kind).collect();
    list.reverse();
    list
}

/// A member with an attested device in the room; `perms` adds a role with these bits.
async fn member(s: &Setup, name: &str, perms: Option<u64>) -> Dev {
    let dev = s.node.crypto_user(name).await;
    join(&s.node, s.alice.token(), &s.room_id, dev.token()).await;
    if let Some(bits) = perms {
        let (_, role) = s
            .node
            .post(
                &format!("/api/v1/rooms/{}/roles", s.room_id),
                s.alice.token(),
                json!({ "name": format!("Role {name}"), "permissions": bits.to_string(), "position": 1 }),
            )
            .await;
        let (st, j) = s
            .node
            .patch(
                &format!("/api/v1/rooms/{}/members/{}", s.room_id, dev.session.user_id),
                s.alice.token(),
                json!({ "roles": [role["id"]] }),
            )
            .await;
        assert!(st.is_success(), "{j}");
    }
    dev
}

#[tokio::test]
async fn a_reset_cuts_the_history_and_stops_automatic_shares_of_the_old_range() {
    let mut s = setup().await;
    // The reset is recorded on Bob's membership; nothing is restored or requested yet.
    let state = mine(&s).await;
    let reset_at = state["key_reset_at"].as_str().expect("key_reset_at").to_string();
    assert_eq!((state["restored_at"].clone(), state["request"].clone()), (Value::Null, Value::Null), "{state}");
    // The cut: only what was written after the reset; Alice still reads everything.
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 1);
    assert_eq!(encrypted_count(&s.node, s.alice.token(), &s.channel).await, 3);
    // The room route is cut the same way.
    let (_, list) =
        s.node.get_auth(&format!("/api/v1/rooms/{}/channels/{}/messages", s.room_id, s.channel), s.bob.token()).await;
    assert_eq!(list.as_array().unwrap().iter().filter(|m| m["encrypted"] == true).count(), 1, "{list}");

    // Bob's device rejoins: he is pending for the range since the reset only, once per reset.
    let mut rx = s.node.state.hub.subscribe();
    rejoin(&mut s).await;
    let pending = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "history.pending").expect("pending");
    assert_eq!(pending.data["user"], bob_address());
    assert_eq!(pending.data["since"], reset_at.as_str());
    assert_eq!(pending.data["key_reset_at"], reset_at.as_str());
    assert_eq!(pending.data["min_epoch"], 2, "the reset epoch is 1: {}", pending.data);
    let (_, j) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", s.channel), s.alice.token()).await;
    assert_eq!(j["items"][0]["user"], bob_address());
    assert_eq!(
        (j["items"][0]["key_reset_at"].as_str(), j["items"][0]["min_epoch"].as_i64()),
        (Some(reset_at.as_str()), Some(2))
    );

    // Ordinary shares of the pre-reset range are refused, the range since the reset is fine.
    for (from, to) in [(0, 1), (1, 2), (0, 2)] {
        let (st, j) = share(&s, s.alice.token(), from, to).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{from}..{to}: {j}");
    }
    let (st, j) = share(&s, s.alice.token(), 2, 2).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");

    // The pending list of a member without a reset carries null for both fields.
    let mut carol = member(&s, "carol", None).await;
    external_join(&s.node, &mut carol, &s.channel).await;
    let (_, j) =
        s.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", s.channel), s.alice.token()).await;
    let item = j["items"].as_array().unwrap().iter().find(|i| i["user"] == format!("carol@{DOMAIN}")).unwrap().clone();
    assert_eq!((item["key_reset_at"].clone(), item["min_epoch"].clone()), (Value::Null, Value::Null), "{item}");
}

#[tokio::test]
async fn a_rotation_is_no_reset_and_a_new_membership_starts_without_one() {
    let s = setup().await;
    let node = &s.node;
    let carol = node.crypto_user("carol").await;
    join(node, s.alice.token(), &s.room_id, carol.token()).await;
    let user = tavrn_node::store::users::by_id(&node.state.db, &carol.session.user_id).await.unwrap().unwrap();
    tavrn_node::welcome::key_changed(&node.state, &user, true).await;
    let (_, j) = node.get_auth(&format!("{}/mine", requests(&s)), carol.token()).await;
    assert_eq!(j["key_reset_at"], Value::Null, "a rotation keeps the history: {j}");
    tavrn_node::welcome::key_changed(&node.state, &user, false).await;
    let (_, j) = node.get_auth(&format!("{}/mine", requests(&s)), carol.token()).await;
    assert!(j["key_reset_at"].is_string(), "{j}");
    // Leave and come back: a fresh membership.
    let (st, _) = node.post(&format!("/api/v1/rooms/{}/leave", s.room_id), carol.token(), json!({})).await;
    assert!(st.is_success());
    join(node, s.alice.token(), &s.room_id, carol.token()).await;
    let (_, j) = node.get_auth(&format!("{}/mine", requests(&s)), carol.token()).await;
    assert_eq!(j["key_reset_at"], Value::Null, "{j}");
    let (st, j) = node.post(&requests(&s), carol.token(), json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("history.nothing_to_restore")), "{j}");
}

#[tokio::test]
async fn an_approved_request_lifts_the_cut_and_allows_restore_shares() {
    let mut s = setup().await;
    rejoin(&mut s).await;
    let carol = member(&s, "carol", None).await;
    let dave = member(&s, "dave", Some(p::RESTORE_HISTORY)).await;

    // Bob asks; the owner and Dave (restore_history) hear about it, Carol does not.
    let mut rx = s.node.state.hub.subscribe();
    let (st, req) = ask(&s, s.bob.token(), "It is me, call me").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    assert_eq!((req["status"].as_str(), req["user"].as_str()), (Some("open"), Some(bob_address().as_str())), "{req}");
    assert_eq!(req["message"], "It is me, call me");
    let id = req["id"].as_str().unwrap().to_string();
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "history.request").expect("event");
    let Scope::Users(users) = &ev.scope else { panic!("{:?}", ev.scope) };
    assert!(users.contains(&s.alice.session.user_id) && users.contains(&dave.session.user_id), "{users:?}");
    assert!(!users.contains(&carol.session.user_id) && !users.contains(&s.bob.session.user_id), "{users:?}");
    assert_eq!(ev.data["request"]["id"], id.as_str());
    assert_eq!(audit(&s, "history.restore_requested").await.len(), 1);
    // One open request per room.
    let (st, j) = ask(&s, s.bob.token(), "again").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("history.request_open")), "{j}");
    assert_eq!(mine(&s).await["request"]["id"], id.as_str());
    // A message is limited to 500 characters.
    let (st, _) = s.node.post(&requests(&s), carol.token(), json!({ "message": "x".repeat(501) })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Only members with restore_history list and decide.
    let (st, j) = s.node.get_auth(&requests(&s), carol.token()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    let (st, _) = s.node.post(&format!("{}/{id}/approve", requests(&s)), carol.token(), json!({})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, list) = s.node.get_auth(&requests(&s), dave.token()).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let item = &list["items"][0];
    assert_eq!(item["id"], id.as_str());
    assert!(item["joined_at"].is_string() && item["key_reset_at"].is_string(), "{item}");
    assert_eq!(
        item["channels"],
        json!([{ "channel_id": s.channel, "kind": "text", "window_start": null, "reset_epoch": 1 }]),
        "{item}"
    );

    // Before the approval nobody sends the old range.
    let (st, _) = share(&s, s.alice.token(), 0, 1).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    let mut rx = s.node.state.hub.subscribe();
    let (st, done) =
        s.node.post(&format!("{}/{id}/approve", requests(&s)), s.alice.token(), json!({ "partial": true })).await;
    assert_eq!(st, StatusCode::OK, "{done}");
    assert_eq!(
        (done["status"].as_str(), done["decided_by"].as_str()),
        (Some("approved"), Some(format!("alice@{DOMAIN}").as_str()))
    );
    assert_eq!(done["partial"], true);
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "history.request_decided").expect("event");
    let Scope::Users(users) = &ev.scope else { panic!("{:?}", ev.scope) };
    assert!(users.contains(&s.bob.session.user_id) && users.contains(&dave.session.user_id), "{users:?}");
    assert_eq!(ev.data["request"]["status"], "approved");
    let entry = audit(&s, "history.restore_approved").await;
    assert_eq!(entry[0]["meta"], json!({ "user": bob_address(), "by": format!("alice@{DOMAIN}") }));
    let restored = welcome_entries(&s, "system.history_restored").await;
    assert_eq!(restored.len(), 1);
    assert_eq!(
        (restored[0]["user"].as_str(), restored[0]["by"].as_str()),
        (Some(bob_address().as_str()), Some(format!("alice@{DOMAIN}").as_str()))
    );

    // The cut is lifted; Bob's state shows the restore.
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 3);
    let state = mine(&s).await;
    assert!(state["restored_at"].is_string(), "{state}");
    assert_eq!(state["request"]["status"], "approved");
    // Restore shares: from members with restore_history, not from others.
    let (st, j) = share(&s, s.alice.token(), 0, 1).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (st, j) = share(&s, dave.token(), 0, 1).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (st, j) = share(&s, carol.token(), 0, 1).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    // Decided requests stay decided; nothing more to restore.
    let (st, j) =
        s.node.post(&format!("{}/{id}/deny", requests(&s)), s.alice.token(), json!({ "reason": "late" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("history.request_decided")), "{j}");
    let (st, j) = ask(&s, s.bob.token(), "more").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("history.nothing_to_restore")), "{j}");
    let (_, j) = s.node.get_auth(&requests(&s), s.alice.token()).await;
    assert_eq!(j["items"], json!([]));

    // Restore shares are accepted for 30 days after the approval; the cut stays lifted.
    sqlx::query("UPDATE room_members SET history_restored_at = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::days(31)))
        .bind(&s.room_id)
        .bind(&s.bob.session.user_id)
        .execute(&s.node.state.db)
        .await
        .unwrap();
    let (st, _) = share(&s, s.alice.token(), 0, 1).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 3);

    // A further reset starts over.
    let bob = std::mem::replace(&mut s.bob, s.node.crypto_user("placeholder").await);
    s.bob = reset(&s.node, bob).await;
    let state = mine(&s).await;
    assert_eq!(state["restored_at"], Value::Null, "{state}");
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 0);
}

#[tokio::test]
async fn restore_shares_work_under_since_join_and_need_view_channel_only() {
    let mut s = setup().await;
    rejoin(&mut s).await;
    let path = format!("/api/v1/rooms/{}/channels/{}", s.room_id, s.channel);
    assert_eq!(
        s.node.patch(&path, s.alice.token(), json!({ "history_for_new_members": "since_join" })).await.0,
        StatusCode::OK
    );
    let (_, req) = ask(&s, s.bob.token(), "").await;
    let id = req["id"].as_str().unwrap();
    // The approver sees Bob's normal window: his join.
    let (_, list) = s.node.get_auth(&requests(&s), s.alice.token()).await;
    let joined = list["items"][0]["joined_at"].as_str().unwrap().to_string();
    assert_eq!(list["items"][0]["channels"][0]["window_start"], joined.as_str());
    let (st, j) = s.node.post(&format!("{}/{id}/approve", requests(&s)), s.alice.token(), json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["partial"], false);
    // since_join: restore shares are accepted.
    let (st, j) = share(&s, s.alice.token(), 0, 1).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    // Bob reads from his join again (since_join): the two messages since then.
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 2);
    // Without read_history the restore still reaches him (his own window from the join).
    let (st, _) = s
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", s.room_id),
            s.alice.token(),
            json!({ "target_type": "channel", "target_id": s.channel, "subject_type": "member", "subject_id": s.bob.session.user_id, "allow": "0", "deny": p::READ_HISTORY.to_string() }),
        )
        .await;
    assert!(st.is_success());
    let (st, j) = share(&s, s.alice.token(), 0, 1).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn deny_cancel_the_setting_self_approval_and_limits() {
    let s = setup().await;
    let (_, req) = ask(&s, s.bob.token(), "please").await;
    let id = req["id"].as_str().unwrap().to_string();
    // A reason is required.
    for body in [json!({}), json!({ "reason": "" }), json!({ "reason": "x".repeat(501) })] {
        let (st, _) = s.node.post(&format!("{}/{id}/deny", requests(&s)), s.alice.token(), body.clone()).await;
        assert!(st == StatusCode::BAD_REQUEST || st == StatusCode::UNPROCESSABLE_ENTITY, "{body}: {st}");
    }
    let mut rx = s.node.state.hub.subscribe();
    let (st, j) = s
        .node
        .post(&format!("{}/{id}/deny", requests(&s)), s.alice.token(), json!({ "reason": "Call me first" }))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!((j["status"].as_str(), j["reason"].as_str()), (Some("denied"), Some("Call me first")));
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "history.request_decided").expect("event");
    assert!(matches!(&ev.scope, Scope::Users(u) if u.contains(&s.bob.session.user_id)));
    let denied = welcome_entries(&s, "system.history_restore_denied").await;
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["by"], format!("alice@{DOMAIN}"));
    assert_eq!(denied[0].get("reason"), None, "the reason stays in the audit log: {}", denied[0]);
    let entry = audit(&s, "history.restore_denied").await;
    assert_eq!(entry[0]["meta"]["reason"], "Call me first");
    let state = mine(&s).await;
    assert_eq!(
        (state["request"]["status"].as_str(), state["request"]["reason"].as_str()),
        (Some("denied"), Some("Call me first"))
    );
    assert_eq!(encrypted_count(&s.node, s.bob.token(), &s.channel).await, 1, "still cut");

    // Cancel: only the requester, only open requests.
    let (st, req) = ask(&s, s.bob.token(), "").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    let id = req["id"].as_str().unwrap().to_string();
    let (st, j) = s.node.delete(&format!("{}/{id}", requests(&s)), s.alice.token()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("history.request_not_found")), "{j}");
    let (st, _) = s.node.delete(&format!("{}/{id}", requests(&s)), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(mine(&s).await["request"]["status"], "cancelled");
    let (st, _) = s.node.delete(&format!("{}/{id}", requests(&s)), s.bob.token()).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, j) = s.node.post(&format!("{}/{id}/approve", requests(&s)), s.alice.token(), json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("history.request_decided")), "{j}");
    let (st, j) =
        s.node.post(&format!("{}/01J9ZK3G5M8Q2W4E6R8T0Y2VA1/approve", requests(&s)), s.alice.token(), json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("history.request_not_found")), "{j}");

    // The room setting: manage_room changes it, `off` refuses requests and approvals.
    let room = format!("/api/v1/rooms/{}", s.room_id);
    let (_, detail) = s.node.get_auth(&room, s.alice.token()).await;
    assert_eq!(detail["history_restore"], "request", "{detail}");
    let (st, _) = s.node.patch(&room, s.alice.token(), json!({ "history_restore": "sometimes" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = s.node.patch(&room, s.bob.token(), json!({ "history_restore": "off" })).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (_, open) = ask(&s, s.bob.token(), "").await;
    let (st, j) = s.node.patch(&room, s.alice.token(), json!({ "history_restore": "off" })).await;
    assert_eq!((st, j["history_restore"].as_str()), (StatusCode::OK, Some("off")), "{j}");
    let update = audit(&s, "room.update").await;
    assert_eq!(update[0]["meta"]["history_restore"], "off");
    let (st, j) = s
        .node
        .post(&format!("{}/{}/approve", requests(&s), open["id"].as_str().unwrap()), s.alice.token(), json!({}))
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.restore_disabled")), "{j}");
    let (st, _) = s.node.delete(&format!("{}/{}", requests(&s), open["id"].as_str().unwrap()), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) = ask(&s, s.bob.token(), "").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.restore_disabled")), "{j}");
    assert_eq!(s.node.patch(&room, s.alice.token(), json!({ "history_restore": "request" })).await.0, StatusCode::OK);

    // Nobody approves their own request, administrators included.
    let (_, role) = s
        .node
        .post(
            &format!("{room}/roles"),
            s.alice.token(),
            json!({ "name": "Admin", "permissions": p::ADMINISTRATOR.to_string(), "position": 1 }),
        )
        .await;
    let (st, _) = s
        .node
        .patch(&format!("{room}/members/{}", s.bob.session.user_id), s.alice.token(), json!({ "roles": [role["id"]] }))
        .await;
    assert!(st.is_success());
    let (st, req) = ask(&s, s.bob.token(), "").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    let id = req["id"].as_str().unwrap().to_string();
    let (st, j) = s.node.post(&format!("{}/{id}/approve", requests(&s)), s.bob.token(), json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");

    // Five requests per member, room and day (this is the fifth).
    let (st, _) = s.node.delete(&format!("{}/{id}", requests(&s)), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, req) = ask(&s, s.bob.token(), "").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    let (st, _) = s.node.delete(&format!("{}/{}", requests(&s), req["id"].as_str().unwrap()), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _) = ask(&s, s.bob.token(), "").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    // Leaving ends open requests.
    sqlx::query("DELETE FROM history_requests WHERE user_id = $1")
        .bind(&s.bob.session.user_id)
        .execute(&s.node.state.db)
        .await
        .unwrap();
    let (st, req) = ask(&s, s.bob.token(), "").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    let (st, _) = s.node.post(&format!("{room}/leave"), s.bob.token(), json!({})).await;
    assert!(st.is_success());
    let status: String = sqlx::query_scalar("SELECT status FROM history_requests WHERE id = $1")
        .bind(req["id"].as_str().unwrap())
        .fetch_one(&s.node.state.db)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");
    // The capability is announced.
    let (_, info) = s.node.get_auth("/api/v1/node", s.alice.token()).await;
    assert!(info["capabilities"].as_array().unwrap().contains(&json!("history.restore")), "{info}");
}

#[tokio::test]
async fn housekeeping_drops_old_decided_requests() {
    let s = setup().await;
    let (_, req) = ask(&s, s.bob.token(), "").await;
    let (st, _) = s.node.delete(&format!("{}/{}", requests(&s), req["id"].as_str().unwrap()), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (_, open) = ask(&s, s.bob.token(), "").await;
    let fmt = tavrn_node::util::format_time;
    let later = fmt(chrono::Utc::now() + chrono::Duration::hours(1));
    // Open requests stay, decided ones go after 30 days.
    let report = tavrn_node::store::history::prune_requests(&s.node.state.db, &later).await.unwrap();
    assert_eq!(report, 1);
    let left: Vec<String> =
        sqlx::query_scalar("SELECT id FROM history_requests").fetch_all(&s.node.state.db).await.unwrap();
    assert_eq!(left, vec![open["id"].as_str().unwrap().to_string()]);
}

#[tokio::test]
async fn the_room_node_learns_the_reset_of_a_remote_member() {
    use common::federation::two_nodes;
    let (a, b) = two_nodes().await;
    let carol = b.crypto_user("carol", 1).await;
    let alice = a.crypto_user("alice", 1).await;
    let remote = b.sign_in_from(&a, &alice.session).await;
    let (st, room) = b.post("/api/v1/rooms", carol.token(), json!({ "name": "Room", "join_mode": "public" })).await;
    assert_eq!(st, StatusCode::CREATED, "{room}");
    let room_id = room["id"].as_str().unwrap().to_string();
    let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let mine = format!("/api/v1/rooms/{room_id}/history-requests/mine");
    let (st, j) = b.get_auth(&mine, &remote.token).await;
    assert_eq!((st, j["key_reset_at"].clone()), (StatusCode::OK, Value::Null), "{j}");

    // Alice resets on her home node; `identity.changed` reaches the room's node.
    let fresh = MasterSecret::generate().unwrap();
    let (st, j) = a
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&fresh.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    a.deliver().await;
    let (_, j) = b.get_auth(&mine, &remote.token).await;
    assert!(j["key_reset_at"].is_string(), "the hosting node enforces the reset window: {j}");
    // The request goes to the room's node with the federated session.
    let (st, req) = b.post(&format!("/api/v1/rooms/{room_id}/history-requests"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    assert_eq!(req["user"], "alice@a.test");
    let (st, list) = b.get_auth(&format!("/api/v1/rooms/{room_id}/history-requests"), carol.token()).await;
    assert_eq!((st, list["items"][0]["id"].clone()), (StatusCode::OK, req["id"].clone()), "{list}");
}

/// ENCRYPTION.md §7b "History after a key reset", end to end with policy `all` and real keys: Bob's re-attested device
/// is pending for the range since the reset only, asks, is approved, receives a restore share with the old epochs'
/// keys, reads every message with them, keeps them in his new backup (the reset dropped the old one) and acknowledges
/// the share, which clears his pending mark.
#[tokio::test]
async fn a_restore_after_a_reset_reaches_the_new_device_and_its_backup() {
    let mut s = setup().await;
    rejoin(&mut s).await;
    let conv = qualified(&s.channel);
    let alice_address = format!("alice@{DOMAIN}");
    let (_, backups) = s.node.get_auth("/api/v1/users/me/backups", s.bob.token()).await;
    assert_eq!(backups["items"], json!([]), "the reset leaves no backup: {backups}");
    let pending_path = format!("/api/v1/conversations/{}/history-pending", s.channel);
    let (_, j) = s.node.get_auth(&pending_path, s.alice.token()).await;
    assert_eq!(
        (j["items"][0]["user"].as_str(), j["items"][0]["min_epoch"].as_i64()),
        (Some(bob_address().as_str()), Some(2))
    );
    // Bob's new device holds no key of the old epochs.
    assert!(s.bob.client.export_epoch_key(&conv, 1).is_err());

    let (st, req) = ask(&s, s.bob.token(), "New phone, same Bob").await;
    assert_eq!(st, StatusCode::CREATED, "{req}");
    let (st, j) = s
        .node
        .post(&format!("{}/{}/approve", requests(&s), req["id"].as_str().unwrap()), s.alice.token(), json!({}))
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");

    // The approving device shares the pre-reset epochs as a real, signed payload under the current epoch.
    let epochs: Vec<Value> =
        (0..=1u64).map(|e| json!([e, b64(s.alice.client.export_epoch_key(&conv, e).unwrap().as_slice())])).collect();
    let payload =
        json!({ "type": "history_keys", "v": 1, "conversation": conv, "to": bob_address(), "epochs": epochs })
            .to_string();
    let ciphertext = s.alice.client.encrypt_content(&conv, &payload).unwrap();
    let base = format!("/api/v1/conversations/{}/history-keys", s.channel);
    let (st, j) = s
        .node
        .post(
            &base,
            s.alice.token(),
            json!({ "to_user": bob_address(), "epoch_from": 0, "epoch_to": 1, "ciphertext": ciphertext }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");

    // Bob receives it, checks it and imports the keys.
    let (_, j) = s.node.get_auth(&base, s.bob.token()).await;
    let item = j["items"][0].clone();
    assert_eq!((item["from_user"].as_str(), item["epoch_from"].as_i64()), (Some(alice_address.as_str()), Some(0)));
    let plain = s
        .bob
        .client
        .decrypt_content(&conv, &alice_address, &s.alice.session.device_id, item["ciphertext"].as_str().unwrap(), None)
        .unwrap();
    let share: Value = serde_json::from_str(&plain).unwrap();
    assert_eq!(
        (share["to"].as_str(), share["conversation"].as_str()),
        (Some(bob_address().as_str()), Some(conv.as_str()))
    );
    for pair in share["epochs"].as_array().unwrap() {
        let key: [u8; 32] = common::e2ee::unb64(&pair[1]).try_into().unwrap();
        s.bob.client.import_epoch_key(&conv, pair[0].as_u64().unwrap(), &key).unwrap();
    }
    // The whole history is served again and readable with the restored keys.
    let (_, list) = s.node.get_auth(&format!("/api/v1/conversations/{}/messages", s.channel), s.bob.token()).await;
    let mut bodies: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| m["encrypted"] == true)
        .map(|m| {
            let json = s
                .bob
                .client
                .decrypt_content(
                    &conv,
                    &alice_address,
                    &s.alice.session.device_id,
                    m["content"].as_str().unwrap(),
                    None,
                )
                .unwrap();
            serde_json::from_str::<Value>(&json).unwrap()["body"].as_str().unwrap().to_string()
        })
        .collect();
    bodies.sort();
    assert_eq!(bodies, ["After the reset", "Before Bob", "Bob was there"]);

    // The restored keys go into Bob's new backup (under his new backup key).
    let blob = s.bob.client.export_backup(&conv, &s.bob.master.backup_key()).unwrap();
    let path = format!("/api/v1/users/me/backups/{DOMAIN}/{}", s.channel);
    let (st, _, body) = s
        .node
        .raw(axum::http::Method::PUT, &path, s.bob.token(), &[("content-type", "application/octet-stream")], blob)
        .await;
    assert_eq!(st, StatusCode::OK, "{body:?}");
    let (st, _, stored) = s.node.raw(axum::http::Method::GET, &path, s.bob.token(), &[], vec![]).await;
    assert_eq!(st, StatusCode::OK);
    let mut fresh =
        tavrn_crypto::Client::new(tavrn_crypto::Device::generate(&bob_address(), &s.bob.session.device_id).unwrap());
    assert!(fresh.import_backup(&conv, &s.bob.master.backup_key(), &stored).unwrap() >= 3, "epochs 0, 1 and 2");

    // The acknowledgement clears the pending mark.
    let (st, _) = s.node.delete(&format!("{base}/{}", item["id"].as_str().unwrap()), s.bob.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (_, j) = s.node.get_auth(&pending_path, s.alice.token()).await;
    assert_eq!(j["items"], json!([]), "{j}");
}
