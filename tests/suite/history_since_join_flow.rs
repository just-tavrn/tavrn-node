// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! History since the join (ENCRYPTION.md §7b): the window belongs to the room membership, so messages posted after
//! a member's room join but before its device first entered the channel's MLS group are part of its history under
//! every policy, `since_join` included. The node marks such members pending and accepts shares for them; it never
//! serves them anything from before their join.
use crate::common;

use axum::http::StatusCode;
use common::e2ee::{DOMAIN, Dev, qualified};
use common::{TestNode, test_node};
use serde_json::{Value, json};
use tavrn_node::{hub::Scope, permissions as p};

struct Room {
    node: TestNode,
    alice: Dev,
    room_id: String,
    channel: String,
}

/// Alice's room with an MLS group in its encrypted text channel (default policy `since_join`) and one encrypted
/// message from before anybody else joined.
async fn room() -> Room {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Gap").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    node.create_group(&mut alice, &channel).await;
    let (s, j) = node.send_encrypted(&alice, &channel, "Before anybody joined").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    tick().await;
    Room { node, alice, room_id, channel }
}

/// Message ids and times have millisecond resolution: the next step happens strictly later.
async fn tick() {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}

async fn join_room(r: &Room, member: &Dev) {
    let (_, invite) = r.node.post(&format!("/api/v1/rooms/{}/invites", r.room_id), r.alice.token(), json!({})).await;
    let (s, j) = r
        .node
        .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), member.token(), json!({}))
        .await;
    assert!(s.is_success(), "{j}");
    tick().await;
}

async fn set_policy(r: &Room, value: &str) {
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel),
            r.alice.token(),
            json!({ "history_for_new_members": value }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
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

/// `external_join` and the `history.pending` events it caused.
async fn join_group_events(r: &Room, dev: &mut Dev) -> Vec<Value> {
    let mut rx = r.node.state.hub.subscribe();
    external_join(&r.node, dev, &r.channel).await;
    std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|e| e.kind == "history.pending")
        .inspect(|e| assert!(matches!(&e.scope, Scope::Room(id) if id == &r.room_id), "{:?}", e.scope))
        .map(|e| e.data.clone())
        .collect()
}

async fn pending(r: &Room) -> Value {
    let (s, j) =
        r.node.get_auth(&format!("/api/v1/conversations/{}/history-pending", r.channel), r.alice.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j["items"].clone()
}

async fn joined_at(r: &Room, user_id: &str) -> String {
    sqlx::query_scalar("SELECT joined_at FROM room_members WHERE room_id = $1 AND user_id = $2")
        .bind(&r.room_id)
        .bind(user_id)
        .fetch_one(&r.node.state.db)
        .await
        .unwrap()
}

/// Bodies of the encrypted messages `token` is served (optionally of one epoch).
async fn encrypted_bodies(r: &Room, token: &str, query: &str) -> Vec<Value> {
    let (s, list) = r.node.get_auth(&format!("/api/v1/conversations/{}/messages{query}", r.channel), token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    list.as_array().unwrap().iter().filter(|m| m["encrypted"] == true).cloned().collect()
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
async fn since_join_marks_members_whose_device_joins_after_messages_since_their_join() {
    let mut r = room().await;
    let mut bob = r.node.crypto_user("bob").await;
    join_room(&r, &bob).await;
    let (s, j) = r.node.send_encrypted(&r.alice, &r.channel, "While Bob was away").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(pending(&r).await, json!([]), "pending only once a device of the member is in the group");

    // Bob opens the channel later: the message since his join waits for a key.
    let events = join_group_events(&r, &mut bob).await;
    let since = joined_at(&r, &bob.session.user_id).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["user"], format!("bob@{DOMAIN}"));
    assert_eq!(events[0]["since"], since.as_str());
    assert_eq!(events[0]["key_reset_at"], Value::Null);
    let items = pending(&r).await;
    assert_eq!(
        items,
        json!([{ "user": format!("bob@{DOMAIN}"), "since": since, "key_reset_at": null, "min_epoch": null }])
    );

    // The node still serves Bob nothing from before his join, also for key checks of an epoch spanning the join.
    let mine = encrypted_bodies(&r, bob.token(), "").await;
    assert_eq!(mine.len(), 1, "{mine:?}");
    let epoch0 = encrypted_bodies(&r, bob.token(), "?epoch=0").await;
    assert_eq!(epoch0.len(), 1, "{epoch0:?}");
    assert_eq!(epoch0[0]["id"], mine[0]["id"]);
    assert_eq!(encrypted_bodies(&r, r.alice.token(), "?epoch=0").await.len(), 2);

    // A second device of Bob does not mark him again.
    r.node.catch_up(&mut r.alice, &r.channel).await;
    let mut phone = r.node.second_device(&bob).await;
    assert!(join_group_events(&r, &mut phone).await.is_empty());
    r.node.catch_up(&mut r.alice, &r.channel).await;

    // Alice shares the epoch; Bob gets it and his acknowledgement clears the mark.
    let base = format!("/api/v1/conversations/{}/history-keys", r.channel);
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("bob@{DOMAIN}"), 0, 0)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, list) = r.node.get_auth(&base, bob.token()).await;
    let share_id = list["items"][0]["id"].as_str().unwrap().to_string();
    let (s, _) = r.node.delete(&format!("{base}/{share_id}"), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(pending(&r).await, json!([]));
}

#[tokio::test]
async fn since_join_marks_nobody_without_messages_since_the_join_or_without_read_history() {
    let mut r = room().await;
    // Only messages from before the join: nothing Bob could get.
    let mut bob = r.node.crypto_user("bob").await;
    join_room(&r, &bob).await;
    assert!(join_group_events(&r, &mut bob).await.is_empty());
    assert_eq!(pending(&r).await, json!([]));
    r.node.catch_up(&mut r.alice, &r.channel).await;

    // Carol without `read_history`: not marked and no shares for her, whatever was posted since her join.
    let mut carol = r.node.crypto_user("carol").await;
    join_room(&r, &carol).await;
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            r.alice.token(),
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member", "subject_id": carol.session.user_id, "allow": "0", "deny": p::READ_HISTORY.to_string() }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = r.node.send_encrypted(&r.alice, &r.channel, "After Carol joined").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert!(join_group_events(&r, &mut carol).await.is_empty());
    assert_eq!(pending(&r).await, json!([]));
    r.node.catch_up(&mut r.alice, &r.channel).await;
    let base = format!("/api/v1/conversations/{}/history-keys", r.channel);
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("carol@{DOMAIN}"), 0, 1)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("history.forbidden")), "{j}");
    // Bob (with the bit) may receive shares under `since_join`.
    let (s, j) = r.node.post(&base, r.alice.token(), share_body(&r, &format!("bob@{DOMAIN}"), 0, 1)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn the_gap_since_the_join_counts_under_every_policy() {
    for policy in ["all", "days:7"] {
        // Nothing from before Bob's join except Alice's very first message, which `days:7` and `all` cover too:
        // move it out of reach so only the gap can mark Bob.
        let mut r = room().await;
        set_policy(&r, policy).await;
        sqlx::query("DELETE FROM messages WHERE conversation_id = $1")
            .bind(&r.channel)
            .execute(&r.node.state.db)
            .await
            .unwrap();
        let mut bob = r.node.crypto_user("bob").await;
        join_room(&r, &bob).await;
        assert!(pending(&r).await.as_array().unwrap().is_empty());
        let (s, j) = r.node.send_encrypted(&r.alice, &r.channel, "In the gap").await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        let events = join_group_events(&r, &mut bob).await;
        assert_eq!(events.len(), 1, "{policy}: {events:?}");
        assert_eq!(pending(&r).await[0]["user"], format!("bob@{DOMAIN}"), "{policy}");
        r.node.catch_up(&mut r.alice, &r.channel).await;
    }
}

/// Pins and reactions serve and act on messages like a page of messages does: an encrypted message from before the
/// member's window is neither listed among the pins nor reachable through the reaction and pin routes.
#[tokio::test]
async fn pins_and_reactions_stay_inside_the_window() {
    let r = room().await;
    let (s, list) = r.node.get_auth(&format!("/api/v1/conversations/{}/messages", r.channel), r.alice.token()).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let old =
        list.as_array().unwrap().iter().find(|m| m["encrypted"] == true).unwrap()["id"].as_str().unwrap().to_string();
    let (s, j) =
        r.node.put(&format!("/api/v1/conversations/{}/pins/{old}", r.channel), r.alice.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let bob = r.node.crypto_user("bob").await;
    join_room(&r, &bob).await;
    // Bob may pin in this channel: only the window keeps him out.
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            r.alice.token(),
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member", "subject_id": bob.session.user_id, "allow": p::PIN_MESSAGES.to_string(), "deny": "0" }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = r.node.send_encrypted(&r.alice, &r.channel, "After Bob joined").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let new = j["id"].as_str().unwrap().to_string();
    let (s, j) =
        r.node.put(&format!("/api/v1/conversations/{}/pins/{new}", r.channel), r.alice.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    for path in [
        format!("/api/v1/conversations/{}/pins", r.channel),
        format!("/api/v1/rooms/{}/channels/{}/pins", r.room_id, r.channel),
    ] {
        let (s, pins) = r.node.get_auth(&path, bob.token()).await;
        assert_eq!(s, StatusCode::OK, "{pins}");
        let ids: Vec<&str> = pins["messages"].as_array().unwrap().iter().filter_map(|m| m["id"].as_str()).collect();
        assert_eq!(ids, vec![new.as_str()], "{path}: only the pin inside Bob's window");
        let (_, pins) = r.node.get_auth(&path, r.alice.token()).await;
        assert_eq!(pins["messages"].as_array().unwrap().len(), 2, "Alice's window has both");
    }
    let base = format!("/api/v1/conversations/{}", r.channel);
    for (method, path) in [
        ("PUT", format!("{base}/messages/{old}/reactions/%F0%9F%91%8D")),
        ("DELETE", format!("{base}/messages/{old}/reactions/%F0%9F%91%8D")),
        ("PUT", format!("{base}/pins/{old}")),
        ("DELETE", format!("{base}/pins/{old}")),
    ] {
        let (s, j) = match method {
            "PUT" => r.node.put(&path, bob.token(), json!({})).await,
            _ => r.node.delete(&path, bob.token()).await,
        };
        assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("message.not_found")), "{method} {path}: {j}");
    }
    // Inside the window everything works as before.
    let (s, j) = r.node.put(&format!("{base}/messages/{new}/reactions/%F0%9F%91%8D"), bob.token(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.delete(&format!("{base}/pins/{new}"), bob.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}
