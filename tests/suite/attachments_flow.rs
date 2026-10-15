// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
use crate::common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn setup(node: &TestNode) -> (Session, Session, String, String) {
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    (alice, bob, room_id, channel_id)
}

async fn upload(
    node: &TestNode,
    token: &str,
    room: &str,
    channel: &str,
    name: &str,
    mime: &str,
    data: &[u8],
) -> (StatusCode, Value) {
    let req = Request::post(format!("/api/v1/rooms/{room}/channels/{channel}/uploads"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, mime)
        .header("tavrn-file-name", name)
        .body(Body::from(data.to_vec()))
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

#[tokio::test]
async fn upload_send_download_and_delete_cleans_file() {
    let node = test_node("t.local").await;
    let (alice, bob, room_id, channel_id) = setup(&node).await;
    let (s, blob) =
        upload(&node, &bob.token, &room_id, &channel_id, "Image%20%C3%A4.png", "image/png", b"\x89PNGfake").await;
    assert_eq!(s, StatusCode::CREATED, "{blob}");
    assert_eq!(blob["name"], "Image ä.png");
    assert_eq!(blob["mime"], "image/png");
    assert_eq!(blob["size"], 8);
    let blob_id = blob["id"].as_str().unwrap().to_string();

    // The blob is not bound to any message yet, but members can load it.
    let req = Request::get(format!("/api/v1/blobs/{blob_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .body(Body::empty())
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/png");
    assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment;"));
    assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(body_bytes(resp).await.as_ref(), b"\x89PNGfake");

    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (s, msg) = node
        .post(&path, &bob.token, json!({ "content": { "type": "text", "body": "look" }, "attachments": [blob_id] }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    assert_eq!(msg["attachments"][0]["id"], blob_id);
    assert_eq!(msg["attachments"][0]["name"], "Image ä.png");
    let (s, j) = node
        .post(&path, &bob.token, json!({ "content": { "type": "text", "body": "again" }, "attachments": [blob_id] }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a blob may be bound only once: {j}");
    assert_eq!(j["code"], "message.attachment_invalid");

    let (_, list) = node.get_auth(&path, &alice.token).await;
    assert_eq!(list[0]["attachments"].as_array().unwrap().len(), 1);

    // Strangers without membership get nothing.
    let carol = node.register("carol").await;
    let req = Request::get(format!("/api/v1/blobs/{blob_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", carol.token))
        .body(Body::empty())
        .unwrap();
    assert_eq!(node.router.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Deleting the message removes the blob and the file.
    let (s, _) = node.delete(&format!("{path}/{}", msg["id"].as_str().unwrap()), &bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let req = Request::get(format!("/api/v1/blobs/{blob_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {}", alice.token))
        .body(Body::empty())
        .unwrap();
    assert_eq!(node.router.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);
    assert!(node.state.storage.read(&blob_id).await.unwrap().is_none(), "file was deleted");
}

#[tokio::test]
async fn upload_limits_and_permissions() {
    let node = test_node_with("t.local", |c| {
        c.upload_max_bytes = 16;
        c.upload_allowed_types = "image/*".into();
        c.storage_quota_per_room_bytes = 20;
    })
    .await;
    let (alice, bob, room_id, channel_id) = setup(&node).await;
    let (s, j) = upload(&node, &bob.token, &room_id, &channel_id, "x.png", "image/png", &[0u8; 17]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");
    assert_eq!(j["code"], "upload.too_large");
    assert_eq!(j["meta"]["max_bytes"], 16);
    let (s, j) = upload(&node, &bob.token, &room_id, &channel_id, "x.sh", "application/x-sh", b"echo").await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{j}");
    assert_eq!(j["code"], "upload.type_not_allowed");
    let (s, _) = upload(&node, &bob.token, &room_id, &channel_id, "a.png", "image/png", &[0u8; 12]).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, j) = upload(&node, &bob.token, &room_id, &channel_id, "b.png", "image/png", &[0u8; 12]).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");
    assert_eq!(j["code"], "upload.quota_exceeded");
    let (s, j) = upload(&node, &bob.token, &room_id, &channel_id, "empty.png", "image/png", b"").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    // Without the attach_files permission: an @everyone override revokes it.
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let everyone = room["roles"][0]["id"].as_str().unwrap();
    node.put(&format!("/api/v1/rooms/{room_id}/overrides"), &alice.token, json!({ "target_type": "channel", "target_id": channel_id, "subject_type": "role", "subject_id": everyone, "allow": "0", "deny": tavrn_node::permissions::ATTACH_FILES.to_string() })).await;
    let (s, j) = upload(&node, &bob.token, &room_id, &channel_id, "c.png", "image/png", &[0u8; 4]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "upload.forbidden");

    let disabled = test_node_with("t.local", |c| c.uploads_enabled = false).await;
    let (a, _, r, c) = setup(&disabled).await;
    let (s, j) = upload(&disabled, &a.token, &r, &c, "x.png", "image/png", b"x").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "upload.disabled");
}

#[tokio::test]
async fn reactions_and_pins() {
    let node = test_node("t.local").await;
    let (alice, bob, room_id, channel_id) = setup(&node).await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (_, msg) = node.send(&alice.token, &room_id, &channel_id, "hello").await;
    let mid = msg["id"].as_str().unwrap().to_string();
    let mut rx = node.state.hub.subscribe();

    let (s, j) = node.put(&format!("{path}/{mid}/reactions/%F0%9F%91%8D"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["reactions"], json!([{ "emoji": "👍", "count": 1, "me": true }]));
    let (_, j) = node.put(&format!("{path}/{mid}/reactions/%F0%9F%91%8D"), &alice.token, json!({})).await;
    assert_eq!(j["reactions"][0]["count"], 2);
    let (_, j) = node.put(&format!("{path}/{mid}/reactions/%F0%9F%91%8D"), &alice.token, json!({})).await;
    assert_eq!(j["reactions"][0]["count"], 2, "duplicates do not count");
    let (s, j) =
        node.req(Method::DELETE, &format!("{path}/{mid}/reactions/%F0%9F%91%8D"), Some(&bob.token), None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["reactions"][0]["count"], 1);
    assert_eq!(j["reactions"][0]["me"], false);
    let (s, j) = node.put(&format!("{path}/{mid}/reactions/{}", "x".repeat(20)), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(rx.recv().await.unwrap().kind, "message.update");

    let (s, j) =
        node.put(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{mid}"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "pin.forbidden");
    let (s, j) =
        node.put(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{mid}"), &alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["pinned"], true);
    let (s, pins) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins"), &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(pins["messages"][0]["id"], mid);
    let (_, list) = node.get_auth(&path, &bob.token).await;
    assert_eq!(list[0]["pinned"], true);
    let (s, j) = node
        .req(
            Method::DELETE,
            &format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{mid}"),
            Some(&alice.token),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["pinned"], false);
}

#[tokio::test]
async fn purge_removes_attachment_files() {
    let node = test_node("t.local").await;
    let (alice, bob, room_id, channel_id) = setup(&node).await;
    let (_, blob) = upload(&node, &bob.token, &room_id, &channel_id, "a.txt", "text/plain", b"content").await;
    let blob_id = blob["id"].as_str().unwrap().to_string();
    node.post(
        &format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages"),
        &bob.token,
        json!({ "content": { "type": "text", "body": "with file" }, "attachments": [blob_id] }),
    )
    .await;
    let (_, preview) = node
        .post(&format!("/api/v1/rooms/{room_id}/moderation/purge"), &alice.token, json!({ "author_id": bob.user_id }))
        .await;
    assert_eq!(preview["messages"], 1);
    let (s, done) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/moderation/purge"),
            &alice.token,
            json!({ "author_id": bob.user_id, "confirm_token": preview["confirm_token"] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert!(node.state.storage.read(&blob_id).await.unwrap().is_none());
}

/// The list endpoint enriches a whole page at once (attachments, reactions, pins). Every message must look
/// exactly as when it is loaded alone, and nothing may leak between messages or conversations.
#[tokio::test]
async fn page_enrichment_matches_single_messages() {
    let node = test_node("t.local").await;
    let (alice, bob, room_id, channel_id) = setup(&node).await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");

    let mut blobs = Vec::new();
    for name in ["a.txt", "b.txt", "c.txt"] {
        let token = if name == "c.txt" { &bob.token } else { &alice.token };
        let (s, blob) = upload(&node, token, &room_id, &channel_id, name, "text/plain", name.as_bytes()).await;
        assert_eq!(s, StatusCode::CREATED, "{blob}");
        blobs.push(blob["id"].as_str().unwrap().to_string());
    }
    let mut ids = Vec::new();
    for i in 0..6 {
        let (token, attachments) = match i {
            0 => (&alice.token, vec![blobs[0].clone(), blobs[1].clone()]),
            1 => (&bob.token, vec![blobs[2].clone()]),
            _ => (if i % 2 == 0 { &alice.token } else { &bob.token }, vec![]),
        };
        let body = json!({ "content": { "type": "text", "body": format!("m{i}") }, "attachments": attachments });
        let (s, m) = node.post(&path, token, body).await;
        assert_eq!(s, StatusCode::CREATED, "{m}");
        ids.push(m["id"].as_str().unwrap().to_string());
    }
    // A second channel with its own pin and reaction: they must not leak into the first.
    let (s, other) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &alice.token,
            json!({ "name": "two", "kind": "text", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    let other_id = other["id"].as_str().unwrap().to_string();
    let (s, foreign) = node.send(&alice.token, &room_id, &other_id, "elsewhere").await;
    assert_eq!(s, StatusCode::CREATED, "{foreign}");
    let foreign_id = foreign["id"].as_str().unwrap();
    let other_path = format!("/api/v1/rooms/{room_id}/channels/{other_id}/messages");
    let (s, j) = node.put(&format!("{other_path}/{foreign_id}/reactions/%F0%9F%91%8D"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node
        .put(&format!("/api/v1/rooms/{room_id}/channels/{other_id}/pins/{foreign_id}"), &alice.token, json!({}))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");

    for (msg, token, emoji) in [
        (0, &bob.token, "%F0%9F%91%8D"),
        (0, &alice.token, "%F0%9F%91%8D"),
        (0, &alice.token, "%F0%9F%8E%89"),
        (2, &alice.token, "%F0%9F%94%A5"),
        (5, &bob.token, "%F0%9F%94%A5"),
        (5, &bob.token, "%F0%9F%91%8D"),
    ] {
        // Reactions are ordered by their first timestamp (milliseconds).
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let (s, j) = node.put(&format!("{path}/{}/reactions/{emoji}", ids[msg]), token, json!({})).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    for msg in [1, 3] {
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        let pin = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins/{}", ids[msg]);
        let (s, j) = node.put(&pin, &alice.token, json!({})).await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }

    let (s, page) = node.get_auth(&path, &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let page = page.as_array().unwrap().clone();
    assert_eq!(page.len(), 6);
    // Newest first: message i is page[5 - i].
    let m = |i: usize| &page[5 - i];
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(&m(i)["id"], id);
    }
    let attachment_ids =
        |v: &Value| v["attachments"].as_array().unwrap().iter().map(|a| a["id"].clone()).collect::<Vec<_>>();
    assert_eq!(attachment_ids(m(0)), vec![json!(blobs[0]), json!(blobs[1])]);
    assert_eq!(m(0)["attachments"][0]["name"], "a.txt");
    assert_eq!(attachment_ids(m(1)), vec![json!(blobs[2])]);
    for i in 2..6 {
        assert_eq!(m(i)["attachments"], json!([]));
    }
    assert_eq!(
        m(0)["reactions"],
        json!([{ "emoji": "👍", "count": 2, "me": true }, { "emoji": "🎉", "count": 1, "me": false }])
    );
    assert_eq!(m(2)["reactions"], json!([{ "emoji": "🔥", "count": 1, "me": false }]));
    assert_eq!(
        m(5)["reactions"],
        json!([{ "emoji": "🔥", "count": 1, "me": true }, { "emoji": "👍", "count": 1, "me": true }])
    );
    for i in [1, 3, 4] {
        assert_eq!(m(i)["reactions"], json!([]));
    }
    let pinned: Vec<bool> = (0..6).map(|i| m(i)["pinned"].as_bool().unwrap()).collect();
    assert_eq!(pinned, vec![false, true, false, true, false, false]);

    // Each message loaded alone (a page of one) looks exactly the same.
    for (i, id) in ids.iter().enumerate() {
        let single_path =
            if i + 1 < ids.len() { format!("{path}?limit=1&before={}", ids[i + 1]) } else { format!("{path}?limit=1") };
        let (s, single) = node.get_auth(&single_path, &bob.token).await;
        assert_eq!(s, StatusCode::OK, "{single}");
        assert_eq!(single.as_array().unwrap().len(), 1);
        assert_eq!(&single[0]["id"], id);
        assert_eq!(&single[0], m(i), "message {i}");
    }

    // The pin list is enriched the same way (newest pin first).
    let (_, pins) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel_id}/pins"), &bob.token).await;
    let pins = pins["messages"].as_array().unwrap();
    assert_eq!(pins.len(), 2);
    assert_eq!(&pins[0], m(3));
    assert_eq!(&pins[1], m(1));
}

/// Files below `dir` whose name ends in `.part` (a blob being written).
fn part_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(part_files(&path));
        } else if path.extension().is_some_and(|e| e == "part") {
            out.push(path);
        }
    }
    out
}

/// Uploads stream into storage as the bytes arrive (memory stays bounded by the chunk size, not the file size), and
/// a body over the limit is cut off at the limit: the node stops reading and answers 413.
#[tokio::test]
async fn uploads_stream_to_storage_and_stop_at_the_limit() {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    const CHUNK: usize = 64 * 1024;
    let node = test_node_with("t.local", |c| c.upload_max_bytes = 1024 * 1024).await;
    let (_alice, bob, room_id, channel_id) = setup(&node).await;
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/uploads");
    let request = |body: Body| {
        Request::post(&path)
            .header(header::AUTHORIZATION, format!("Bearer {}", bob.token))
            .header(header::CONTENT_TYPE, "text/plain")
            .header("tavrn-file-name", "notes.txt")
            .body(body)
            .unwrap()
    };
    // 512 KiB, then the client pauses: the file is already being written before the body is complete.
    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let first =
        futures::stream::iter((0..8).map(|_| Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'a'; CHUNK]))));
    let rest = futures::stream::once(async move {
        let _ = wait.await;
        Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'b'; CHUNK]))
    });
    let router = node.router.clone();
    let upload = tokio::spawn(router.oneshot(request(Body::from_stream(futures::StreamExt::chain(first, rest)))));
    let data_dir = std::path::PathBuf::from(&node.state.config.data_dir);
    common::wait_until(std::time::Duration::from_secs(5), "the blob is written while the body arrives", || {
        let found = !part_files(&data_dir).is_empty();
        async move { found }
    })
    .await;
    release.send(()).unwrap();
    let resp = upload.await.unwrap().unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let blob = common::body_json(resp).await;
    assert_eq!(blob["size"], 9 * CHUNK);
    assert!(part_files(&data_dir).is_empty(), "the finished blob is renamed");
    let (st, _, bytes) = node
        .raw(Method::GET, &format!("/api/v1/blobs/{}", blob["id"].as_str().unwrap()), &bob.token, &[], vec![])
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(bytes.len(), 9 * CHUNK);
    assert_eq!((bytes[0], bytes[9 * CHUNK - 1]), (b'a', b'b'));

    // Endless body without a Content-Length: read up to the limit, then 413; nothing stays behind.
    let pulled = Arc::new(AtomicU64::new(0));
    let counter = pulled.clone();
    let endless = futures::stream::repeat_with(move || {
        counter.fetch_add(CHUNK as u64, Ordering::Relaxed);
        Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'x'; CHUNK]))
    });
    let resp = node.router.clone().oneshot(request(Body::from_stream(endless))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(common::body_json(resp).await["code"], "upload.too_large");
    let read = pulled.load(Ordering::Relaxed);
    assert!(read <= 1024 * 1024 + 2 * CHUNK as u64, "read {read} bytes of an endless body");
    assert!(part_files(&data_dir).is_empty(), "the cut upload leaves no file");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs").fetch_one(&node.state.db).await.unwrap();
    assert_eq!(count, 1, "no row for the cut upload");
}
