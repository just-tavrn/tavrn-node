// SPDX-License-Identifier: AGPL-3.0-only
//! Attachment safety and encryption at rest: files on disk are ciphertext for every kind of
//! stored file, downloads return the plaintext with its size and hash, `off` mode, the in-place encryption
//! of existing plaintext files, SVG as a download-only document, and the `auto_preview` setting.
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::http::{Method, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tavrn_node::{
    config::StorageEncryption,
    storage::{BlobStorage, MAGIC, load_keyring},
    store,
};

const DOMAIN: &str = "t.local";

async fn up(
    node: &TestNode,
    token: &str,
    conversation: &str,
    name: &str,
    mime: &str,
    data: &[u8],
) -> (StatusCode, Value) {
    let (s, _, body) = node
        .raw(
            Method::POST,
            &format!("/api/v1/conversations/{conversation}/uploads"),
            token,
            &[("content-type", mime), ("tavrn-file-name", name)],
            data.to_vec(),
        )
        .await;
    (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn on_disk(node: &TestNode, id: &str) -> Vec<u8> {
    std::fs::read(node.state.storage.path_of(id).unwrap()).unwrap()
}

/// Encrypted on disk: the magic, a key row, and none of the plaintext.
async fn assert_encrypted(node: &TestNode, id: &str, plain: &[u8]) {
    let disk = on_disk(node, id);
    assert!(disk.starts_with(&MAGIC), "{id}: encrypted format");
    assert!(store::blobs::blob_key(&node.state.db, id).await.unwrap().is_some(), "{id}: key row");
    let probe = &plain[..plain.len().min(12)];
    assert!(!disk.windows(probe.len()).any(|w| w == probe), "{id}: plaintext not on disk");
}

async fn download(node: &TestNode, token: &str, id: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = node.get_with(&format!("/api/v1/blobs/{id}"), token).await;
    let (status, headers) = (resp.status(), resp.headers().clone());
    (status, headers, body_bytes(resp).await.to_vec())
}

#[tokio::test]
async fn attachments_are_encrypted_on_disk_and_downloads_return_the_plaintext() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let channel = TestNode::text_channel(&room);
    let plain: Vec<u8> = b"\x89PNG\r\n\x1a\n".iter().copied().chain((0..200_000u32).map(|i| (i % 253) as u8)).collect();
    let (s, blob) = up(&node, &alice.token, &channel, "big.png", "image/png", &plain).await;
    assert_eq!(s, StatusCode::CREATED, "{blob}");
    let id = blob["id"].as_str().unwrap();
    // Size and hash describe the plaintext, as before.
    assert_eq!(blob["size"], plain.len());
    assert_eq!(blob["sha256"], URL_SAFE_NO_PAD.encode(Sha256::digest(&plain)));
    assert_encrypted(&node, id, &plain[8..]).await;
    assert!(on_disk(&node, id).len() > plain.len(), "ciphertext with tags");
    let (s, headers, body) = download(&node, &alice.token, id).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_LENGTH], plain.len().to_string().as_str());
    assert_eq!(body, plain, "decrypted while streaming");
}

#[tokio::test]
async fn encrypted_conversation_uploads_are_wrapped_a_second_time() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "E2EE").await;
    let channel = TestNode::text_channel(&room);
    let ciphertext = vec![0xA5u8; 4096];
    let (s, _, body) = node
        .raw(
            Method::POST,
            &format!("/api/v1/conversations/{channel}/uploads"),
            &alice.token,
            &[("content-type", "application/octet-stream"), ("tavrn-upload-category", "images")],
            ciphertext.clone(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let id = serde_json::from_slice::<Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
    assert_encrypted(&node, &id, &ciphertext).await;
    let (s, _, got) = download(&node, &alice.token, &id).await;
    assert_eq!((s, got), (StatusCode::OK, ciphertext), "the client gets its ciphertext back unchanged");
}

#[tokio::test]
async fn media_emojis_and_sounds_are_encrypted_too() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    // Avatars and room icons go through the same store (still and animated variant).
    let still = b"RIFF\x10\x00\x00\x00WEBPVP8 still avatar bytes".to_vec();
    let animated = b"RIFF\x10\x00\x00\x00WEBPVP8X animated avatar bytes".to_vec();
    let media =
        tavrn_node::profile::store_media(&node.state, "avatar", &alice.user_id, &still, "image/webp", Some(&animated))
            .await
            .unwrap();
    let animated_id: String = sqlx::query_scalar("SELECT animated_id FROM media WHERE id = $1")
        .bind(&media.id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_encrypted(&node, &media.id, &still[12..]).await;
    assert_encrypted(&node, &animated_id, &animated[12..]).await;
    let resp = node.get(&format!("/api/v1/media/{}", media.id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), still.as_slice());
    let resp = node.get(&format!("/api/v1/media/{}/animated", media.id)).await;
    assert_eq!(body_bytes(resp).await.as_ref(), animated.as_slice());
    let icon = tavrn_node::profile::store_media(&node.state, "room_icon", &alice.user_id, &still, "image/webp", None)
        .await
        .unwrap();
    assert_encrypted(&node, &icon.id, &still[12..]).await;

    // A valid 1×1 PNG: emojis are converted by the media pipeline.
    let emoji_png = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0d\x49\x44\x41\x54\x78\xda\x63\x64\xf8\xcf\x50\x0f\x00\x03\x86\x01\x80\x5a\x34\x7d\x6b\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82".to_vec();
    let (s, _, emoji) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/emojis"),
            &alice.token,
            &[("content-type", "image/png"), ("tavrn-emoji-name", "pog")],
            emoji_png.clone(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let emoji = serde_json::from_slice::<Value>(&emoji).unwrap()["id"].as_str().unwrap().to_string();
    let resp = node.get_with(&format!("/api/v1/rooms/{room_id}/emojis/{emoji}/image"), &alice.token).await;
    let served = body_bytes(resp).await.to_vec();
    assert!(!served.is_empty());
    assert_encrypted(&node, &emoji, &served[12..]).await;

    let clip: Vec<u8> = b"OggS".iter().copied().chain((0..500u16).map(|i| (i % 7) as u8 + 1)).collect();
    let (s, _, sound) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/soundboard"),
            &alice.token,
            &[("content-type", "audio/ogg"), ("tavrn-sound-name", "Fanfare"), ("tavrn-sound-duration-ms", "500")],
            clip.clone(),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&sound));
    let sound = serde_json::from_slice::<Value>(&sound).unwrap()["id"].as_str().unwrap().to_string();
    assert_encrypted(&node, &sound, &clip[4..]).await;
    assert_eq!(node.state.storage.read(&sound).await.unwrap().unwrap(), clip);
}

#[tokio::test]
async fn off_mode_writes_plaintext_and_housekeeping_encrypts_it_later() {
    let node = test_node_with(DOMAIN, |c| c.storage_encryption = StorageEncryption::Off).await;
    assert!(!node.state.storage.encrypts());
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let channel = TestNode::text_channel(&room);
    let plain = b"%PDF-1.7 a plaintext document".to_vec();
    let (s, blob) = up(&node, &alice.token, &channel, "doc.pdf", "application/pdf", &plain).await;
    assert_eq!(s, StatusCode::CREATED, "{blob}");
    let id = blob["id"].as_str().unwrap().to_string();
    assert_eq!(on_disk(&node, &id), plain, "off: stored as is");
    // Housekeeping does nothing while encryption is off.
    tavrn_node::housekeeping::encrypt_stored_files(&node.state).await;
    assert_eq!(on_disk(&node, &id), plain);

    // Switched on again (same data directory and database): the existing file is encrypted in place, the
    // download is unchanged.
    let data_dir = node.state.config.data_dir.clone();
    let keys = load_keyring(&std::path::Path::new(&data_dir).join("keys"), &node.state.db).await.unwrap();
    let on = BlobStorage::new(&data_dir, node.state.db.clone(), keys, true);
    let report = on.encrypt_plaintext(u64::MAX, u64::MAX).await.unwrap();
    assert_eq!((report.encrypted, report.bytes, report.failed), (1, plain.len() as u64, 0));
    assert_encrypted(&node, &id, &plain).await;
    // The node that runs with `off` still reads the now encrypted file.
    let (s, _, body) = download(&node, &alice.token, &id).await;
    assert_eq!((s, body), (StatusCode::OK, plain));
}

#[tokio::test]
async fn deleting_a_file_removes_its_key_and_orphan_keys_are_swept() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let channel = TestNode::text_channel(&room);
    let (_, blob) = up(&node, &alice.token, &channel, "a.txt", "text/plain", b"hello there").await;
    let id = blob["id"].as_str().unwrap().to_string();
    assert!(store::blobs::blob_key(&node.state.db, &id).await.unwrap().is_some());
    node.state.storage.delete(&id).await;
    assert!(store::blobs::blob_key(&node.state.db, &id).await.unwrap().is_none(), "the key goes with the file");
    // A key row whose file no row knows (a crash between the deletes) goes after a day.
    let stray = tavrn_node::util::ulid();
    node.state.storage.write(&stray, b"x").await.unwrap();
    std::fs::remove_file(node.state.storage.path_of(&stray).unwrap()).unwrap();
    let r = tavrn_node::housekeeping::sweep_orphans(&node.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(r.keys, 0, "not within a day");
    let r = tavrn_node::housekeeping::sweep_orphans(&node.state, chrono::Utc::now() + chrono::Duration::hours(25))
        .await
        .unwrap();
    assert!(r.keys >= 1, "{r:?}");
    assert!(store::blobs::blob_key(&node.state.db, &stray).await.unwrap().is_none());
}

#[tokio::test]
async fn svg_is_a_download_only_document() {
    let node = test_node_with(DOMAIN, |c| c.upload_allowed_types = "*/*".into()).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // Members who may upload images only cannot smuggle SVG in as an image.
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
            &alice.token,
            json!({ "allowed_upload_categories": ["images"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    for (name, mime) in [("x.svg", "image/svg+xml"), ("x.png", "image/png"), ("x.svg", "application/octet-stream")] {
        let (s, j) = up(&node, &bob.token, &channel, name, mime, svg).await;
        assert_eq!(
            (s, j["meta"]["category"].as_str()),
            (StatusCode::FORBIDDEN, Some("documents")),
            "{name} {mime}: {j}"
        );
    }
    let (s, _) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
            &alice.token,
            json!({ "allowed_upload_categories": ["images", "documents"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    // Declared as PNG: stored as what it is.
    let (s, blob) = up(&node, &bob.token, &channel, "x.png", "image/png", svg).await;
    assert_eq!(s, StatusCode::CREATED, "{blob}");
    assert_eq!(blob["mime"], "image/svg+xml");
    let (s, headers, body) = download(&node, &alice.token, blob["id"].as_str().unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert!(headers[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment"), "never inline");
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("sandbox"));
    assert_eq!(body, svg);
    // Avatars refuse SVG (the media pipeline only takes raster images).
    let (s, _, _) = node
        .raw(Method::PUT, "/api/v1/users/me/avatar", &alice.token, &[("content-type", "image/svg+xml")], svg.to_vec())
        .await;
    assert!(s.is_client_error(), "{s}");
}

#[tokio::test]
async fn auto_preview_setting_and_node_cap() {
    let node = test_node_with(DOMAIN, |c| c.preview_auto_max_bytes = 3 * 1024 * 1024).await;
    let alice = node.register("alice").await;
    let (s, me) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["auto_preview"], "friends_and_shared", "default");
    for value in ["never", "always", "friends_and_shared"] {
        let (s, me) = node.patch("/api/v1/users/me", &alice.token, json!({ "auto_preview": value })).await;
        assert_eq!((s, me["auto_preview"].as_str()), (StatusCode::OK, Some(value)), "{me}");
    }
    let (s, j) = node.patch("/api/v1/users/me", &alice.token, json!({ "auto_preview": "sometimes" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.enum")));
    let (_, me) = node.patch("/api/v1/users/me", &alice.token, json!({ "auto_preview": "never" })).await;
    assert_eq!(me["auto_preview"], "never");
    // Other fields leave it alone.
    let (_, me) = node.patch("/api/v1/users/me", &alice.token, json!({ "bio": "hi" })).await;
    assert_eq!(me["auto_preview"], "never");
    let (_, me) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!(me["auto_preview"], "never");

    let (s, info) = node.get_auth("/api/v1/node", &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(info["preview_auto_max_bytes"], 3 * 1024 * 1024);
    let resp = node.get("/.well-known/tavrn").await;
    let doc: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(doc["policies"]["preview_auto_max_bytes"], 3 * 1024 * 1024);
}
