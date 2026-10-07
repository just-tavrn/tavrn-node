// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! "Deleted means gone" for files: deleting a message, an automod burst, a channel or a
//! room deletes the files right away (plaintext and encrypted uploads, whiteboard shares, which are
//! ordinary uploads, custom emojis, soundboard clips, per-room avatars), and the hourly sweep removes
//! orphans older than 24 hours.
use crate::common;

use axum::http::{Method, StatusCode};
use chrono::{Duration, Utc};
use common::{Session, TestNode, test_node_with};
use serde_json::{Value, json};
use tavrn_node::{housekeeping, store};

const DOMAIN: &str = "t.local";

/// A valid 1×1 PNG (emojis are converted by the media pipeline).
const PNG_1X1: &[u8] = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0d\x49\x44\x41\x54\x78\xda\x63\x64\xf8\xcf\x50\x0f\x00\x03\x86\x01\x80\x5a\x34\x7d\x6b\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

fn stored(node: &TestNode, id: &str) -> bool {
    std::path::Path::new(&node.state.config.data_dir).join("blobs").join(&id[..2]).join(id).is_file()
}

async fn node() -> TestNode {
    test_node_with(DOMAIN, |c| c.upload_allowed_types = "*/*".into()).await
}

async fn room(node: &TestNode, owner: &Session, member: &Session, plaintext: bool) -> (String, String) {
    let room = if plaintext {
        node.plaintext_room(&owner.token, "Room").await
    } else {
        node.create_room(&owner.token, "Room").await
    };
    let room_id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({})).await;
    (room_id, TestNode::text_channel(&room))
}

async fn upload(node: &TestNode, token: &str, conversation: &str, encrypted: bool) -> String {
    let mut headers = vec![("content-type", "text/plain"), ("tavrn-file-name", "notes.txt")];
    if encrypted {
        headers = vec![("content-type", "application/octet-stream"), ("tavrn-upload-category", "documents")];
    }
    let (s, _, body) = node
        .raw(
            Method::POST,
            &format!("/api/v1/conversations/{conversation}/uploads"),
            token,
            &headers,
            b"content of the file".to_vec(),
        )
        .await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let id = j["id"].as_str().unwrap().to_string();
    assert!(stored(node, &id));
    id
}

/// An encrypted message with an attachment, written directly (the node never reads the ciphertext).
async fn encrypted_message_with(node: &TestNode, author: &Session, conversation: &str, blob: &str) -> String {
    let id = tavrn_node::util::ulid();
    store::messages::insert(
        &node.state.db,
        store::messages::NewMessage {
            id: &id,
            conversation_id: conversation,
            author_id: &author.user_id,
            device_id: Some("dev"),
            encrypted: true,
            format: 1,
            epoch: Some(0),
            content: "Y2lwaGVy",
            reply_to_id: None,
            thread_id: None,
            mentions: &[],
            mentions_everyone: false,
            signature: None,
        },
    )
    .await
    .unwrap();
    let bound = store::blobs::bind_to_message(&node.state.db, &[blob.to_string()], &id, &author.user_id, conversation)
        .await
        .unwrap();
    assert_eq!(bound.len(), 1);
    id
}

#[tokio::test]
async fn deleting_messages_deletes_their_files_plaintext_and_encrypted() {
    let node = node().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (_, plain) = room(&node, &alice, &bob, true).await;
    let blob = upload(&node, &bob.token, &plain, false).await;
    let (s, msg) = node
        .post(
            &format!("/api/v1/conversations/{plain}/messages"),
            &bob.token,
            json!({ "content": { "type": "text", "body": "x" }, "attachments": [blob] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    // A moderator deletes it: the file is gone at once.
    let (s, _) = node
        .delete(&format!("/api/v1/conversations/{plain}/messages/{}", msg["id"].as_str().unwrap()), &alice.token)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!stored(&node, &blob));

    let (_, secret) = room(&node, &alice, &bob, false).await;
    let blob = upload(&node, &bob.token, &secret, true).await;
    let id = encrypted_message_with(&node, &bob, &secret, &blob).await;
    let (s, _) = node.delete(&format!("/api/v1/conversations/{secret}/messages/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!stored(&node, &blob), "encrypted uploads go the same way");
}

#[tokio::test]
async fn automod_bursts_take_their_files_along() {
    let node = test_node_with(DOMAIN, |c| {
        c.upload_allowed_types = "*/*".into();
        c.automod_burst_limit = 2;
    })
    .await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (_, channel) = room(&node, &alice, &bob, true).await;
    let blob = upload(&node, &bob.token, &channel, false).await;
    let path = format!("/api/v1/conversations/{channel}/messages");
    node.post(&path, &bob.token, json!({ "content": { "type": "text", "body": "1" }, "attachments": [blob] })).await;
    node.post(&path, &bob.token, json!({ "content": { "type": "text", "body": "2" } })).await;
    let (s, j) = node.post(&path, &bob.token, json!({ "content": { "type": "text", "body": "3" } })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.spam")), "{j}");
    assert!(!stored(&node, &blob));
}

#[tokio::test]
async fn deleting_channels_and_rooms_deletes_every_file_of_them() {
    let node = node().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel) = room(&node, &alice, &bob, true).await;
    // A second channel with an unsent and a sent upload.
    let (_, extra) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "kind": "text", "name": "extra", "encrypted": false }),
        )
        .await;
    let extra = extra["id"].as_str().unwrap().to_string();
    let unsent = upload(&node, &bob.token, &extra, false).await;
    let sent = upload(&node, &bob.token, &extra, false).await;
    node.post(
        &format!("/api/v1/conversations/{extra}/messages"),
        &bob.token,
        json!({ "content": { "type": "text", "body": "x" }, "attachments": [sent] }),
    )
    .await;
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/channels/{extra}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!stored(&node, &unsent) && !stored(&node, &sent), "channel files deleted with the channel");

    // The room: uploads, an emoji, a soundboard clip and a per-room avatar.
    let kept = upload(&node, &bob.token, &channel, false).await;
    let (s, _, emoji) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/emojis"),
            &alice.token,
            &[("content-type", "image/png"), ("tavrn-emoji-name", "pog")],
            PNG_1X1.to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let emoji = serde_json::from_slice::<Value>(&emoji).unwrap()["id"].as_str().unwrap().to_string();
    let (s, _, sound) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/soundboard"),
            &alice.token,
            &[("content-type", "audio/ogg"), ("tavrn-sound-name", "Fanfare"), ("tavrn-sound-duration-ms", "500")],
            vec![7u8; 256],
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&sound));
    let sound = serde_json::from_slice::<Value>(&sound).unwrap()["id"].as_str().unwrap().to_string();
    let avatar =
        tavrn_node::profile::store_media(&node.state, "room_avatar", &bob.user_id, b"RIFFwebp", "image/webp", None)
            .await
            .unwrap();
    store::rooms::set_member_avatar(&node.state.db, &room_id, &bob.user_id, Some(&avatar.id), false).await.unwrap();
    for id in [&kept, &emoji, &sound, &avatar.id] {
        assert!(stored(&node, id), "{id}");
    }
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    for id in [&kept, &emoji, &sound, &avatar.id] {
        assert!(!stored(&node, id), "{id} deleted with the room");
    }
    assert!(store::media::by_id(&node.state.db, &avatar.id).await.unwrap().is_none());
}

#[tokio::test]
async fn hourly_sweep_removes_orphans_older_than_a_day() {
    let node = node().await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (room_id, channel) = room(&node, &alice, &bob, true).await;
    let unsent = upload(&node, &bob.token, &channel, false).await;
    let sent = upload(&node, &bob.token, &channel, false).await;
    node.post(
        &format!("/api/v1/conversations/{channel}/messages"),
        &bob.token,
        json!({ "content": { "type": "text", "body": "x" }, "attachments": [sent] }),
    )
    .await;
    // A media row nobody points at, one that is a room avatar, and a file without any row.
    let orphan_media =
        tavrn_node::profile::store_media(&node.state, "avatar", &bob.user_id, b"still", "image/webp", Some(b"anim"))
            .await
            .unwrap();
    let orphan_animated: String = sqlx::query_scalar("SELECT animated_id FROM media WHERE id = $1")
        .bind(&orphan_media.id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    let used = tavrn_node::profile::store_media(&node.state, "room_avatar", &bob.user_id, b"still", "image/webp", None)
        .await
        .unwrap();
    store::rooms::set_member_avatar(&node.state.db, &room_id, &bob.user_id, Some(&used.id), false).await.unwrap();
    let stray = tavrn_node::util::ulid();
    node.state.storage.write(&stray, b"left behind").await.unwrap();

    // Within a day nothing goes.
    let report = housekeeping::sweep_orphans(&node.state, Utc::now()).await.unwrap();
    assert_eq!(report, housekeeping::OrphanReport::default());
    assert!(stored(&node, &unsent) && stored(&node, &stray));

    let report = housekeeping::sweep_orphans(&node.state, Utc::now() + Duration::hours(25)).await.unwrap();
    assert_eq!((report.uploads, report.media, report.files), (1, 1, 1), "{report:?}");
    assert!(!stored(&node, &unsent), "never sent: gone");
    assert!(store::blobs::by_id(&node.state.db, &unsent).await.unwrap().is_none());
    assert!(!stored(&node, &orphan_media.id) && !stored(&node, &orphan_animated), "unreferenced media: gone");
    assert!(!stored(&node, &stray), "file without a row: gone");
    assert!(stored(&node, &sent), "attachments of messages stay");
    assert!(stored(&node, &used.id), "referenced media stays");
    // Nothing left the second time.
    let report = housekeeping::sweep_orphans(&node.state, Utc::now() + Duration::hours(25)).await.unwrap();
    assert_eq!(report, housekeeping::OrphanReport::default());
}
