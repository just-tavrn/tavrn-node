// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! History for new members of encrypted channels (ENCRYPTION.md §7b): the node's
//! cut of `GET …/messages`, the channel policy, the `read_history` bit and the history key share routes.
use crate::common;

use axum::http::StatusCode;
use common::e2ee::{DOMAIN, Dev, qualified};
use common::{Session, TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::{hub::Scope, permissions as p};

struct Room {
    node: TestNode,
    alice: Dev,
    room_id: String,
    channel: String,
}

/// Alice owns a room whose encrypted text channel has an MLS group and one old encrypted message.
async fn room_with_history() -> Room {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Archive").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    node.create_group(&mut alice, &channel).await;
    let (s, j) = node.send_encrypted(&alice, &channel, "Before joining").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // Message ids have millisecond resolution: the join happens strictly later.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    Room { node, alice, room_id, channel }
}

async fn join(node: &TestNode, owner: &str, room_id: &str, member: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    let (s, j) = node
        .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({}))
        .await;
    assert!(s.is_success(), "{j}");
}

async fn set_policy(r: &Room, value: &str) -> (StatusCode, Value) {
    r.node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel),
            r.alice.token(),
            json!({ "history_for_new_members": value }),
        )
        .await
}

/// Bodies of the encrypted messages `token` can list (count of ciphertexts) and all ids.
async fn encrypted_count(node: &TestNode, token: &str, channel: &str) -> usize {
    let (s, list) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list.as_array().unwrap().iter().filter(|m| m["encrypted"] == true).count()
}

async fn set_joined_at(node: &TestNode, room_id: &str, user_id: &str, at: chrono::DateTime<chrono::Utc>) {
    sqlx::query("UPDATE room_members SET joined_at = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(tavrn_node::util::format_time(at))
        .bind(room_id)
        .bind(user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

async fn everyone_role(node: &TestNode, token: &str, room_id: &str) -> String {
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), token).await;
    room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn messages_are_cut_at_the_join_unless_the_policy_and_the_bit_allow_more() {
    let r = room_with_history().await;
    let bob = r.node.register("bob").await;
    join(&r.node, r.alice.token(), &r.room_id, &bob).await;
    let channel_path = format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel);

    // Default `since_join`: the owner reads everything, Bob nothing from before his join.
    let (_, ch) = r.node.get_auth(&format!("/api/v1/rooms/{}", r.room_id), r.alice.token()).await;
    let ch = ch["channels"].as_array().unwrap().iter().find(|c| c["id"] == r.channel.as_str()).unwrap().clone();
    assert_eq!(ch["history_for_new_members"], "since_join");
    assert_eq!(encrypted_count(&r.node, r.alice.token(), &r.channel).await, 1);
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 0);
    // The room route is cut the same way.
    let (_, list) = r.node.get_auth(&format!("{channel_path}/messages"), &bob.token).await;
    assert!(list.as_array().unwrap().iter().all(|m| m["encrypted"] == false), "{list}");

    // Only `manage_channels` changes the policy; invalid values are refused.
    let (s, j) = r.node.patch(&channel_path, &bob.token, json!({ "history_for_new_members": "all" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    for bad in ["days:0", "days:3651", "forever", "days:01"] {
        let (s, j) = set_policy(&r, bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert_eq!(j["code"], "channel.history_policy_invalid");
    }
    let mut rx = r.node.state.hub.subscribe();
    let (s, j) = set_policy(&r, "all").await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["history_for_new_members"], "all");
    assert!(std::iter::from_fn(|| rx.try_recv().ok()).any(|e| e.kind == "channel.update"));
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 1);
    let (_, log) = r.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", r.room_id), r.alice.token()).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "channel.history_policy").expect("audit");
    assert_eq!(entry["meta"], json!({ "from": "since_join", "to": "all" }));

    // `days:1`: a join half a day after the message still shows it, three days after it does not.
    assert_eq!(set_policy(&r, "days:1").await.0, StatusCode::OK);
    let now = chrono::Utc::now();
    set_joined_at(&r.node, &r.room_id, &bob.user_id, now + chrono::Duration::hours(12)).await;
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 1);
    set_joined_at(&r.node, &r.room_id, &bob.user_id, now + chrono::Duration::days(3)).await;
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 0);
    set_joined_at(&r.node, &r.room_id, &bob.user_id, now).await;

    // Without `read_history` the policy does not apply: the history starts at the join.
    assert_eq!(set_policy(&r, "all").await.0, StatusCode::OK);
    let everyone = everyone_role(&r.node, r.alice.token(), &r.room_id).await;
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{everyone}", r.room_id),
            r.alice.token(),
            json!({ "permissions": (p::DEFAULT_EVERYONE & !p::READ_HISTORY).to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 0);
    let (s, _) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/roles/{everyone}", r.room_id),
            r.alice.token(),
            json!({ "permissions": p::DEFAULT_EVERYONE.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 1);

    // A re-join starts over: with `since_join` again nothing from before the new join.
    assert_eq!(set_policy(&r, "since_join").await.0, StatusCode::OK);
    let (s, _) = r.node.post(&format!("/api/v1/rooms/{}/leave", r.room_id), &bob.token, json!({})).await;
    assert!(s.is_success());
    let (s, _) = r.node.send_encrypted(&r.alice, &r.channel, "Between memberships").await;
    assert_eq!(s, StatusCode::CREATED);
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    join(&r.node, r.alice.token(), &r.room_id, &bob).await;
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 0);
    assert_eq!(set_policy(&r, "all").await.0, StatusCode::OK);
    assert_eq!(encrypted_count(&r.node, &bob.token, &r.channel).await, 2);

    // The epoch filter (key checks of shares) lists only encrypted messages of that epoch.
    let (s, list) = r.node.get_auth(&format!("/api/v1/conversations/{}/messages?epoch=0", r.channel), &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 2);
    let (_, list) = r.node.get_auth(&format!("/api/v1/conversations/{}/messages?epoch=7", r.channel), &bob.token).await;
    assert_eq!(list, json!([]));
    let (s, _) = r.node.get_auth(&format!("/api/v1/conversations/{}/messages?epoch=-1", r.channel), &bob.token).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admins_follow_the_rule_and_plaintext_and_dms_are_not_cut() {
    let r = room_with_history().await;
    // An administrator who joined later is cut like everyone else (it is about keys, not trust).
    let carol = r.node.register("carol").await;
    join(&r.node, r.alice.token(), &r.room_id, &carol).await;
    let (_, role) = r
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", r.room_id),
            r.alice.token(),
            json!({ "name": "Admin", "permissions": p::ADMINISTRATOR.to_string(), "position": 1 }),
        )
        .await;
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", r.room_id, carol.user_id),
            r.alice.token(),
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    assert_eq!(encrypted_count(&r.node, &carol.token, &r.channel).await, 0);

    // Plaintext messages of a channel are always served.
    let plain = r.node.plaintext_room(r.alice.token(), "Open").await;
    let plain_room = plain["id"].as_str().unwrap();
    let plain_channel = TestNode::text_channel(&plain);
    let (s, _) = r.node.send(r.alice.token(), plain_room, &plain_channel, "Old plaintext").await;
    assert_eq!(s, StatusCode::CREATED);
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    join(&r.node, r.alice.token(), plain_room, &carol).await;
    let (_, list) = r.node.get_auth(&format!("/api/v1/conversations/{plain_channel}/messages"), &carol.token).await;
    assert!(list.as_array().unwrap().iter().any(|m| m["content"]["body"] == "Old plaintext"), "{list}");

    // DMs: both participants are members from the start, nothing is cut.
    let mut dave = r.node.crypto_user("dave").await;
    let erin = r.node.crypto_user("erin").await;
    r.node.befriend(&dave.session, &erin.session).await;
    let dm = r.node.create_dm(&dave.session, &erin.session).await;
    r.node.create_group(&mut dave, &dm).await;
    let (s, _) = r.node.send_encrypted(&dave, &dm, "DM").await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(encrypted_count(&r.node, erin.token(), &dm).await, 1);
}

#[tokio::test]
async fn group_dm_members_added_later_start_at_their_join() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    let carol = node.crypto_user("carol").await;
    node.befriend(&alice.session, &bob.session).await;
    node.befriend(&alice.session, &carol.session).await;
    let (s, g) =
        node.post("/api/v1/conversations", alice.token(), json!({ "kind": "group", "members": ["bob"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    let id = g["id"].as_str().unwrap().to_string();
    node.create_group(&mut alice, &id).await;
    assert_eq!(node.send_encrypted(&alice, &id, "Before").await.0, StatusCode::CREATED);
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let (s, j) =
        node.post(&format!("/api/v1/conversations/{id}/members"), alice.token(), json!({ "user": "carol" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(encrypted_count(&node, bob.token(), &id).await, 1);
    assert_eq!(encrypted_count(&node, carol.token(), &id).await, 0);
    // Shares are only for room channels.
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{id}/history-keys"),
            alice.token(),
            json!({ "to_user": format!("carol@{DOMAIN}"), "epoch_from": 0, "epoch_to": 0, "ciphertext": "x" }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "history.forbidden");
}

/// Bob (attested device) joins Alice's room with policy `all` and joins the channel's group by external commit.
async fn shared_setup() -> (Room, Dev) {
    let mut r = room_with_history().await;
    assert_eq!(set_policy(&r, "all").await.0, StatusCode::OK);
    let mut bob = r.node.crypto_user("bob").await;
    join(&r.node, r.alice.token(), &r.room_id, &bob.session).await;
    external_join(&r.node, &mut bob, &r.channel).await;
    r.node.catch_up(&mut r.alice, &r.channel).await;
    (r, bob)
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

fn share_body(r: &Room, to: &str, epoch_from: i64, epoch_to: i64) -> Value {
    let ciphertext = r
        .alice
        .client
        .encrypt_content(&qualified(&r.channel), &json!({ "type": "history_keys", "epochs": [] }).to_string())
        .unwrap();
    json!({ "to_user": to, "epoch_from": epoch_from, "epoch_to": epoch_to, "ciphertext": ciphertext })
}

#[tokio::test]
async fn new_members_are_marked_pending_and_receive_shares() {
    let mut r = room_with_history().await;
    assert_eq!(set_policy(&r, "all").await.0, StatusCode::OK);
    let mut bob = r.node.crypto_user("bob").await;
    join(&r.node, r.alice.token(), &r.room_id, &bob.session).await;
    let pending_path = format!("/api/v1/conversations/{}/history-pending", r.channel);
    let (_, j) = r.node.get_auth(&pending_path, r.alice.token()).await;
    assert_eq!(j["items"], json!([]), "pending only once a device of the member is in the group");

    let mut rx = r.node.state.hub.subscribe();
    external_join(&r.node, &mut bob, &r.channel).await;
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let pending = evs.iter().find(|e| e.kind == "history.pending").expect("history.pending");
    assert_eq!(pending.data["user"], format!("bob@{DOMAIN}"));
    assert!(matches!(&pending.scope, Scope::Room(id) if id == &r.room_id), "{:?}", pending.scope);
    let (s, j) = r.node.get_auth(&pending_path, r.alice.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["items"][0]["user"], format!("bob@{DOMAIN}"));
    // A second device of Bob joining does not mark him again.
    let mut phone = r.node.second_device(&bob).await;
    r.node.catch_up(&mut r.alice, &r.channel).await;
    let mut rx = r.node.state.hub.subscribe();
    external_join(&r.node, &mut phone, &r.channel).await;
    assert!(!std::iter::from_fn(|| rx.try_recv().ok()).any(|e| e.kind == "history.pending"));
    r.node.catch_up(&mut r.alice, &r.channel).await;

    // Alice shares; only Bob's sockets hear about it and only Bob sees it.
    let base = format!("/api/v1/conversations/{}/history-keys", r.channel);
    let mut rx = r.node.state.hub.subscribe();
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("bob@{DOMAIN}"), 0, 1)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let share_id = j["id"].as_str().unwrap().to_string();
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "history.keys_available").unwrap();
    assert!(matches!(&ev.scope, Scope::Users(u) if u == &vec![bob.session.user_id.clone()]), "{:?}", ev.scope);
    assert_eq!(ev.data, json!({ "conversation_id": r.channel }));
    let (_, j) = r.node.get_auth(&base, r.alice.token()).await;
    assert_eq!(j["items"], json!([]));
    let (_, j) = r.node.get_auth(&base, bob.token()).await;
    let item = &j["items"][0];
    assert_eq!(item["id"], share_id.as_str());
    assert_eq!(item["from_user"], format!("alice@{DOMAIN}"));
    assert_eq!(item["from_device"], r.alice.session.device_id.as_str());
    assert_eq!((item["epoch_from"].as_i64(), item["epoch_to"].as_i64()), (Some(0), Some(1)));
    // Bob decrypts it with the current epoch's key.
    r.node.catch_up(&mut bob, &r.channel).await;
    let plain = bob
        .client
        .decrypt_content(
            &qualified(&r.channel),
            &format!("alice@{DOMAIN}"),
            &r.alice.session.device_id,
            item["ciphertext"].as_str().unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&plain).unwrap()["type"], "history_keys");

    // Only the recipient acknowledges; afterwards the share is gone and Bob no longer pending.
    let (s, _) = r.node.delete(&format!("{base}/{share_id}"), r.alice.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = r.node.delete(&format!("{base}/{share_id}"), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = r.node.delete(&format!("{base}/{share_id}"), bob.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(j["code"], "history.share_not_found");
    let (_, j) = r.node.get_auth(&base, bob.token()).await;
    assert_eq!(j["items"], json!([]));
    let (_, j) = r.node.get_auth(&pending_path, r.alice.token()).await;
    assert_eq!(j["items"], json!([]));
    // The ciphertext is not kept after the acknowledgement.
    let left: String = sqlx::query_scalar("SELECT ciphertext FROM history_key_shares WHERE id = $1")
        .bind(&share_id)
        .fetch_one(&r.node.state.db)
        .await
        .unwrap();
    assert_eq!(left, "");
}

#[tokio::test]
async fn shares_are_refused_unless_sender_recipient_policy_and_limits_allow_them() {
    let (r, bob) = shared_setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", r.channel);
    let to_bob = format!("bob@{DOMAIN}");

    // Not a member: the conversation is closed to Carol.
    let carol = r.node.crypto_user("carol").await;
    let (s, j) = r.node.post(&base, carol.token(), share_body(&r, &to_bob, 0, 1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.not_member");
    let (s, _) = r.node.get_auth(&base, carol.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A recipient who is not a member, the sender itself, malformed addresses.
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("carol@{DOMAIN}"), 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("nobody@{DOMAIN}"), 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("alice@{DOMAIN}"), 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("history.self")), "{j}");
    let (s, _) = r.node.post(&base, r.alice.token(), share_body(&r, "no-address", 0, 1)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Epoch ranges: inside the known epochs, at most 1000.
    for (from, to) in [(-1, 0), (1, 0), (0, 99), (0, 1000)] {
        let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, from, to)).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("history.invalid")), "{from}..{to}: {j}");
    }
    // Ciphertext: format 1 content only, at most 64 KiB.
    let mut body = share_body(&r, &to_bob, 0, 1);
    body["ciphertext"] = json!("not encrypted");
    let (s, j) = r.node.post(&base, r.alice.token(), body.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("history.invalid")), "{j}");
    body["ciphertext"] = json!("A".repeat(64 * 1024 + 1));
    let (s, j) = r.node.post(&base, r.alice.token(), body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("history.too_large")), "{j}");
    // A member without an attested device cannot share.
    let dave = r.node.register("dave").await;
    join(&r.node, r.alice.token(), &r.room_id, &dave).await;
    let (s, j) = r.node.post(&base, &dave.token, share_body(&r, &to_bob, 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("e2ee.device_not_attested")), "{j}");

    // A recipient without `read_history` (member override) gets nothing, a hostile sender notwithstanding.
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            r.alice.token(),
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member", "subject_id": bob.session.user_id, "allow": "0", "deny": p::READ_HISTORY.to_string() }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    let (s, _) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            r.alice.token(),
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member", "subject_id": bob.session.user_id, "allow": "0", "deny": "0" }),
        )
        .await;
    assert!(s.is_success());

    // `since_join` forbids shares.
    assert_eq!(set_policy(&r, "since_join").await.0, StatusCode::OK);
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    assert_eq!(set_policy(&r, "days:7").await.0, StatusCode::OK);

    // 20 shares per recipient, conversation and day (acknowledged ones count too).
    for i in 0..20 {
        let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
        assert_eq!(s, StatusCode::CREATED, "{i}: {j}");
    }
    let (s, _) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (_, j) = r.node.get_auth(&base, bob.token()).await;
    assert_eq!(j["items"].as_array().unwrap().len(), 20);

    // Plaintext channel: no shares.
    let plain = r.node.plaintext_room(r.alice.token(), "Open").await;
    let plain_channel = TestNode::text_channel(&plain);
    let (s, j) = r
        .node
        .post(
            &format!("/api/v1/conversations/{plain_channel}/history-keys"),
            r.alice.token(),
            share_body(&r, &to_bob, 0, 0),
        )
        .await;
    assert!(s == StatusCode::BAD_REQUEST || s == StatusCode::FORBIDDEN, "{j}");
}

#[tokio::test]
async fn housekeeping_drops_acknowledged_and_old_shares() {
    let (r, bob) = shared_setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", r.channel);
    let to_bob = format!("bob@{DOMAIN}");
    let (_, a) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
    let (_, b) = r.node.post(&base, r.alice.token(), share_body(&r, &to_bob, 0, 1)).await;
    let (s, _) = r.node.delete(&format!("{base}/{}", a["id"].as_str().unwrap()), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let fmt = tavrn_node::util::format_time;
    let now = chrono::Utc::now();
    // Nothing is due yet.
    let report = tavrn_node::store::history::prune(
        &r.node.state.db,
        &fmt(now - chrono::Duration::hours(24)),
        &fmt(now - chrono::Duration::days(30)),
    )
    .await
    .unwrap();
    assert_eq!(report, Default::default());
    // A day later the acknowledged share goes; a month later every share and pending mark.
    let report = tavrn_node::store::history::prune(
        &r.node.state.db,
        &fmt(now + chrono::Duration::hours(1)),
        &fmt(now - chrono::Duration::days(30)),
    )
    .await
    .unwrap();
    assert_eq!(report.shares, 1);
    let (_, j) = r.node.get_auth(&base, bob.token()).await;
    assert_eq!(j["items"][0]["id"], b["id"]);
    let report = tavrn_node::store::history::prune(&r.node.state.db, &fmt(now), &fmt(now + chrono::Duration::hours(1)))
        .await
        .unwrap();
    assert_eq!((report.shares, report.pending), (1, 1));
    let (_, j) = r.node.get_auth(&base, bob.token()).await;
    assert_eq!(j["items"], json!([]));
}

#[tokio::test]
async fn read_history_is_granted_to_existing_everyone_roles_once() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Alt").await;
    let room_id = room["id"].as_str().unwrap();
    let everyone = everyone_role(&node, &alice.token, room_id).await;
    // A room from before bit 34, and a node that has not run the fixup yet.
    sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
        .bind((p::DEFAULT_EVERYONE & !p::READ_HISTORY) as i64)
        .bind(&everyone)
        .execute(&node.state.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::READ_HISTORY_MARKER)
        .execute(&node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.read_history_roles, 1);
    let (_, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let role = j["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap().clone();
    assert_eq!(role["permissions"], p::DEFAULT_EVERYONE.to_string());
    // Once: a room that removes the bit afterwards keeps it removed.
    sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
        .bind((p::DEFAULT_EVERYONE & !p::READ_HISTORY) as i64)
        .bind(&everyone)
        .execute(&node.state.db)
        .await
        .unwrap();
    assert_eq!(tavrn_node::fixups::run(&node.state.db).await.unwrap().read_history_roles, 0);
}
