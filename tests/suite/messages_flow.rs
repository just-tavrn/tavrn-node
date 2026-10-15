// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::StatusCode;
use common::{Session, TestNode, perms, test_node};
use serde_json::json;
use tavrn_node::{hub::Scope, permissions as p};

async fn setup() -> (TestNode, Session, Session, String, String) {
    let node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    (node, alice, bob, room_id, channel_id)
}

#[tokio::test]
async fn send_list_edit_delete() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let mut rx = node.state.hub.subscribe();

    let (s, m1) = node.send(&bob.token, &room_id, &channel_id, "Hello **world**").await;
    assert_eq!(s, StatusCode::CREATED, "{m1}");
    assert_eq!(m1["author"], "bob@t.local");
    assert_eq!(m1["encrypted"], false);
    assert_eq!(m1["content"]["body"], "Hello **world**");
    let ev = rx.recv().await.unwrap();
    assert_eq!(ev.kind, "message.create");
    assert!(matches!(&ev.scope, Scope::Room(r) if r == &room_id));

    let (s, m2) = node.post(&path, &alice.token, json!({ "content": { "type": "text", "body": "Reply" }, "reply_to_id": m1["id"], "mentions": ["bob@t.local", "bob@t.local"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{m2}");
    assert_eq!(m2["reply_to_id"], m1["id"]);
    assert_eq!(m2["mentions"], json!(["bob@t.local"]));

    let (s, list) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["id"], m2["id"], "newest first");
    let (_, older) = node.get_auth(&format!("{path}?before={}", m2["id"].as_str().unwrap()), &bob.token).await;
    assert_eq!(older.as_array().unwrap().len(), 1);
    assert_eq!(older[0]["id"], m1["id"]);
    let (_, newer) = node.get_auth(&format!("{path}?after={}", m1["id"].as_str().unwrap()), &bob.token).await;
    assert_eq!(newer[0]["id"], m2["id"]);

    let mid = m1["id"].as_str().unwrap();
    let (s, j) = node
        .patch(&format!("{path}/{mid}"), &alice.token, json!({ "content": { "type": "text", "body": "hijacked" } }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "message.not_author");
    let (s, j) = node
        .patch(
            &format!("{path}/{mid}"),
            &bob.token,
            json!({ "content": { "type": "text", "body": "Hello world, corrected" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j["edited_at"].is_string());

    let (s, j) = node.delete(&format!("{path}/{}", m2["id"].as_str().unwrap()), &bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "message.delete_forbidden");
    let (s, _) = node.delete(&format!("{path}/{mid}"), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "own message");
    let (s, _) = node.delete(&format!("{path}/{}", m2["id"].as_str().unwrap()), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "the owner has manage_messages");
    let (_, list) = node.get_auth(&path, &bob.token).await;
    assert!(list.as_array().unwrap().is_empty());
    let (s, _) = node.delete(&format!("{path}/{mid}"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn validation_mismatch_and_permissions() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (s, j) = node.post(&path, &bob.token, json!({ "content": "Y2lwaGVy" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.encryption_mismatch");
    let (s, j) = node
        .post(&path, &bob.token, json!({ "content": { "type": "text", "body": "x" }, "mentions_everyone": true }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "message.mention_everyone_forbidden");
    let (s, j) = node
        .post(
            &path,
            &bob.token,
            json!({ "content": { "type": "text", "body": "x" }, "reply_to_id": "01JNICHTDA0000000000000000" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.reply_target_missing");

    // Switch the channel to encrypted: plaintext is rejected, a system message is created.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}"), &alice.token, json!({ "encrypted": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["encrypted"], true);
    let (s, j) = node.send(&bob.token, &room_id, &channel_id, "plaintext").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.encryption_mismatch");
    // Ciphertext must follow ENCRYPTION.md §5 (header, epoch of an existing MLS group); see mls_flow.rs.
    let (s, j) = node.post(&path, &bob.token, json!({ "content": "Y2lwaGVydGV4dA", "epoch": 3 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.ciphertext_invalid");
    let (_, list) = node.get_auth(&path, &bob.token).await;
    let kinds: Vec<_> =
        list.as_array().unwrap().iter().map(|m| m["content"].get("type").cloned().unwrap_or(json!("cipher"))).collect();
    assert!(kinds.contains(&json!("system.encryption_changed")), "{kinds:?}");

    // Non-member and voice channel
    let carol = node.register("carol").await;
    let (s, j) = node.send(&carol.token, &room_id, &channel_id, "hi").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.not_member");
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let voice = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, j) = node.send(&bob.token, &room_id, &voice, "hi").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "channel.no_text");
}

#[tokio::test]
async fn slowmode_limits_members_not_moderators() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    node.patch(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}"), &alice.token, json!({ "slowmode_secs": 30 }))
        .await;
    let (s, _) = node.send(&bob.token, &room_id, &channel_id, "one").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, j) = node.send(&bob.token, &room_id, &channel_id, "two").await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert!(j["meta"]["retry_after_secs"].as_u64().unwrap() <= 30);
    let (s, _) = node.send(&alice.token, &room_id, &channel_id, "one").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = node.send(&alice.token, &room_id, &channel_id, "two").await;
    assert_eq!(s, StatusCode::CREATED, "the owner is exempt from slowmode");
}

#[tokio::test]
async fn automod_purges_burst_times_out_and_alerts_moderators() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    let mut rx = node.state.hub.subscribe();
    let limit = node.state.config.automod_burst_limit as usize;
    let mut last = (StatusCode::OK, json!(null));
    for i in 0..=limit + 1 {
        last = node.send(&bob.token, &room_id, &channel_id, &format!("spam {i}")).await;
        if last.0 != StatusCode::CREATED {
            break;
        }
    }
    assert_eq!(last.0, StatusCode::FORBIDDEN, "{}", last.1);
    assert_eq!(last.1["code"], "automod.spam");

    let (_, list) =
        node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), &alice.token).await;
    assert!(list.as_array().unwrap().is_empty(), "the outburst was deleted: {list}");
    let (s, j) = node.send(&bob.token, &room_id, &channel_id, "one more").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "timeout active: {j}");
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    let bob_member = members.as_array().unwrap().iter().find(|m| m["user"]["id"] == bob.user_id).unwrap();
    assert!(bob_member["timeout_until"].is_string());

    let mut kinds = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if ev.kind == "moderation.alert" {
            assert!(matches!(&ev.scope, Scope::Users(u) if u.contains(&alice.user_id) && !u.contains(&bob.user_id)));
            assert_eq!(ev.data["kind"], "spam");
        }
        kinds.push(ev.kind.clone());
    }
    assert!(kinds.contains(&"message.purge".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"moderation.alert".to_string()), "{kinds:?}");
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &alice.token).await;
    assert_eq!(log[0]["action"], "automod.spam");
    assert_eq!(log[0]["target"], "bob@t.local");
}

#[tokio::test]
async fn purge_requires_preview_and_confirmation() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    for i in 0..3 {
        node.send(&bob.token, &room_id, &channel_id, &format!("bob {i}")).await;
    }
    node.send(&alice.token, &room_id, &channel_id, "alice").await;
    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");

    let (s, j) = node.post(&path, &bob.token, json!({ "author_id": bob.user_id })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "moderation.purge_forbidden");
    let (s, j) = node.post(&path, &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "moderation.purge_unbounded");

    let (s, preview) = node.post(&path, &alice.token, json!({ "author_id": bob.user_id })).await;
    assert_eq!(s, StatusCode::OK, "{preview}");
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["messages"], 3);
    let token = preview["confirm_token"].as_str().unwrap().to_string();

    let (s, j) = node
        .post(
            &path,
            &alice.token,
            json!({ "author_id": bob.user_id, "channel_ids": [channel_id], "confirm_token": token }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "changed filter: {j}");
    assert_eq!(j["code"], "moderation.confirm_mismatch");
    let (s, j) = node.post(&path, &alice.token, json!({ "author_id": bob.user_id, "confirm_token": "broken" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "moderation.confirm_invalid");

    let (s, done) = node.post(&path, &alice.token, json!({ "author_id": bob.user_id, "confirm_token": token })).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert_eq!(done["dry_run"], false);
    assert_eq!(done["messages"], 3);
    let (_, list) =
        node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), &alice.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["author"], "alice@t.local");

    // Delete the whole channel history.
    let (_, preview) = node.post(&path, &alice.token, json!({ "channel_ids": [channel_id] })).await;
    assert_eq!(preview["messages"], 1);
    let (s, done) = node
        .post(&path, &alice.token, json!({ "channel_ids": [channel_id], "confirm_token": preview["confirm_token"] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{done}");
    let (_, list) =
        node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), &alice.token).await;
    assert!(list.as_array().unwrap().is_empty());
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &alice.token).await;
    assert_eq!(log[0]["action"], "moderation.purge");
    assert_eq!(log[0]["meta"]["deleted"], 1);
    let _ = perms(&[p::PURGE]);
}

/// Message ids in paths and bodies are ULIDs in any case: edit, read marker and delete address the message whatever
/// the case of its id, and act on the stored (canonical) id.
#[tokio::test]
async fn message_ids_are_accepted_in_any_case() {
    let (node, _alice, bob, room_id, channel_id) = setup().await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (s, m) = node.send(&bob.token, &room_id, &channel_id, "Hello").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let id = m["id"].as_str().unwrap().to_string();
    let lower = id.to_lowercase();
    let (s, j) = node
        .patch(&format!("{path}/{lower}"), &bob.token, json!({ "content": { "type": "text", "body": "Edited" } }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["id"].as_str(), j["content"]["body"].as_str()), (Some(id.as_str()), Some("Edited")));
    let (s, j) = node
        .put(&format!("/api/v1/conversations/{channel_id}/read"), &bob.token, json!({ "last_read_message_id": lower }))
        .await;
    assert!(s.is_success(), "{j}");
    assert_eq!(
        tavrn_node::store::messages::read_marker(&node.state.db, &channel_id, &bob.user_id).await.unwrap().as_deref(),
        Some(id.as_str()),
        "the marker holds the canonical id"
    );
    let (s, j) = node.delete(&format!("{path}/{lower}"), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, list) = node.get_auth(&path, &bob.token).await;
    assert!(list.as_array().unwrap().iter().all(|m| m["id"] != id.as_str()), "deleted: {list}");

/// A message is stored together with its attachments, spoilers and poll close time, or not at all: a database
/// failure halfway leaves no message behind that nobody was told about.
#[tokio::test]
async fn a_failed_message_write_leaves_nothing_behind() {
    let (node, alice, _bob, _room_id, channel_id) = setup().await;
    // The last step of the write (the poll's close time) fails.
    let statements: &[&str] = if std::env::var("TAVRN_TEST_DATABASE_URL").is_ok() {
        &[
            "CREATE FUNCTION fail_close_time() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$",
            "CREATE TRIGGER fail_close_time BEFORE UPDATE OF poll_closes_at ON messages FOR EACH ROW EXECUTE FUNCTION fail_close_time()",
        ]
    } else {
        &[
            "CREATE TRIGGER fail_close_time BEFORE UPDATE OF poll_closes_at ON messages BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
        ]
    };
    for sql in statements {
        sqlx::query(sql).execute(&node.state.db).await.unwrap();
    }
    let poll = json!({ "type": "poll", "kind": "choice", "question": "Lunch?", "options": [{ "id": "a", "label": "Pizza" }, { "id": "b", "label": "Salad" }], "max_choices": 1, "results_visible": "always", "votes_visible": "public" });
    let closes_at = tavrn_node::util::format_time(chrono::Utc::now() + chrono::Duration::hours(1));
    let path = format!("/api/v1/conversations/{channel_id}/messages");
    let (s, j) = node.post(&path, &alice.token, json!({ "content": poll, "poll_closes_at": closes_at })).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{j}");
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE conversation_id = $1")
        .bind(&channel_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(stored, 0, "no orphan message");
    // Everything else still writes.
    let (s, j) = node.post(&path, &alice.token, json!({ "content": { "type": "text", "body": "hi" } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

/// A purge confirmation token deletes once: repeating the request needs a new preview.
#[tokio::test]
async fn a_purge_confirmation_is_single_use() {
    let (node, alice, bob, room_id, channel_id) = setup().await;
    node.send(&bob.token, &room_id, &channel_id, "bob").await;
    let path = format!("/api/v1/rooms/{room_id}/moderation/purge");
    let (_, preview) = node.post(&path, &alice.token, json!({ "author_id": bob.user_id })).await;
    let confirm = json!({ "author_id": bob.user_id, "confirm_token": preview["confirm_token"] });
    let (s, done) = node.post(&path, &alice.token, confirm.clone()).await;
    assert_eq!((s, done["messages"].as_i64()), (StatusCode::OK, Some(1)), "{done}");
    node.send(&bob.token, &room_id, &channel_id, "posted after the preview").await;
    let (s, j) = node.post(&path, &alice.token, confirm).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("moderation.confirm_invalid")), "{j}");
    let (_, list) =
        node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"), &alice.token).await;
    assert!(list.as_array().unwrap().iter().any(|m| m["content"]["body"] == "posted after the preview"), "{list}");
}
