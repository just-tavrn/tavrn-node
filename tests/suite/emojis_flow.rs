// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Custom emojis per room (`manage_emojis`): limits, the media pipeline conversion (WebP, 128 px, ≤ 256 KiB,
//! animations ≤ 5 s / 60 frames, still variant), decompression bomb limits and the public image
//! route. Image fixtures are made by ffmpeg; conversion tests skip without it (CI installs it).
use crate::common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tower::ServiceExt;

fn ffmpeg() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join("ffmpeg")).find(|p| p.is_file())
}

/// A fixture made by `ffmpeg -f lavfi`, `None` without ffmpeg.
fn fixture(source: &str, out: &[&str]) -> Option<Vec<u8>> {
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("f");
    let ok = std::process::Command::new(ffmpeg()?)
        .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", source])
        .args(out)
        .arg(&path)
        .status()
        .ok()?
        .success();
    if ok { std::fs::read(path).ok() } else { None }
}

macro_rules! need {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => {
                eprintln!("ffmpeg not installed: skipped");
                return;
            }
        }
    };
}

fn still_png() -> Option<Vec<u8>> {
    fixture("testsrc=size=320x240:rate=1", &["-frames:v", "1", "-f", "image2", "-c:v", "png"])
}

fn animated_gif(secs: u32, size: &str) -> Option<Vec<u8>> {
    fixture(&format!("testsrc=size={size}:rate=10:duration={secs}"), &["-f", "gif"])
}

/// Width, height and the animation frames of a WebP (VP8X canvas; ANMF chunks with their durations).
fn webp_info(data: &[u8]) -> (u32, u32, Vec<u32>) {
    assert_eq!(&data[0..4], b"RIFF");
    assert_eq!(&data[8..12], b"WEBP");
    let le24 = |b: &[u8]| u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16);
    let mut frames = Vec::new();
    let mut pos = 12;
    let (mut w, mut h) = (0, 0);
    while pos + 8 <= data.len() {
        let kind = &data[pos..pos + 4];
        let len = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let body = &data[pos + 8..(pos + 8 + len).min(data.len())];
        match kind {
            b"VP8X" => (w, h) = (le24(&body[4..7]) + 1, le24(&body[7..10]) + 1),
            b"VP8L" if w == 0 => {
                let bits = u32::from_le_bytes([body[1], body[2], body[3], body[4]]);
                (w, h) = ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1);
            }
            b"VP8 " if w == 0 => {
                (w, h) = (
                    u32::from(u16::from_le_bytes([body[6], body[7]]) & 0x3FFF),
                    u32::from(u16::from_le_bytes([body[8], body[9]]) & 0x3FFF),
                );
            }
            b"ANMF" => frames.push(le24(&body[12..15])),
            _ => {}
        }
        pos += 8 + len + (len & 1);
    }
    (w, h, frames)
}

async fn upload_emoji(
    node: &TestNode,
    token: &str,
    path: &str,
    name: &str,
    mime: &str,
    data: &[u8],
) -> (StatusCode, Value) {
    let req = Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, mime)
        .header("tavrn-emoji-name", name)
        .body(Body::from(data.to_vec()))
        .unwrap();
    let resp = node.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = body_bytes(resp).await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

/// GET without a token: status, headers and bytes.
async fn public(node: &TestNode, path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = node.get(path).await;
    let (status, headers) = (resp.status(), resp.headers().clone());
    (status, headers, body_bytes(resp).await.to_vec())
}

#[tokio::test]
async fn custom_emojis_lifecycle_conversion_and_limits() {
    let png = need!(still_png());
    let gif = need!(animated_gif(2, "64x64"));
    let node = test_node_with("t.local", |c| {
        c.emoji_max_per_room = 2;
        c.emoji_max_bytes = 200_000;
    })
    .await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let base = format!("/api/v1/rooms/{room_id}/emojis");
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;

    let (s, j) = upload_emoji(&node, &bob.token, &base, "pog", "image/png", &png).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("emoji.manage_forbidden")), "{j}");
    let (s, j) = upload_emoji(&node, &alice.token, &base, "Pog Champ", "image/png", &png).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("emoji.name_invalid")), "{j}");
    let (s, j) = upload_emoji(&node, &alice.token, &base, "pog", "image/svg+xml", b"<svg/>").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("emoji.type_not_allowed")), "{j}");
    // The declared type is only a first filter: the content decides (SVG/HTML posing as PNG is refused).
    let (s, j) = upload_emoji(&node, &alice.token, &base, "pog", "image/png", b"<svg onload=alert(1)>").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("media.type_not_allowed")), "{j}");
    let (s, j) = upload_emoji(&node, &alice.token, &base, "pog", "image/png", &[0u8; 200_001]).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("emoji.too_large")), "{j}");

    let (s, e1) = upload_emoji(&node, &alice.token, &base, "pog", "image/png", &png).await;
    assert_eq!(s, StatusCode::CREATED, "{e1}");
    assert_eq!(
        (e1["name"].as_str(), e1["animated"].as_bool(), e1["mime"].as_str()),
        (Some("pog"), Some(false), Some("image/webp"))
    );
    let (s, j) = upload_emoji(&node, &alice.token, &base, "pog", "image/png", &png).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("emoji.name_taken")), "{j}");
    let (s, e2) = upload_emoji(&node, &alice.token, &base, "gg", "image/gif", &gif).await;
    assert_eq!(s, StatusCode::CREATED, "{e2}");
    assert_eq!(e2["animated"], true);
    let (s, j) = upload_emoji(&node, &alice.token, &base, "third", "image/png", &png).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("emoji.limit")), "{j}");

    let (s, list) = node.get_auth(&base, &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);

    // Converted: a WebP of at most 128 px.
    let id = e1["id"].as_str().unwrap();
    let resp = node.get_with(&format!("{base}/{id}/image"), &bob.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/webp");
    let still = body_bytes(resp).await.to_vec();
    let (w, h, frames) = webp_info(&still);
    assert!(w == 128 && h == 96 && frames.is_empty(), "{w}x{h} {frames:?}");
    let carol = node.register("carol").await;
    let resp = node.get_with(&format!("{base}/{id}/image"), &carol.token).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "the room route stays members only");

    // Public route: no token, strict headers, cacheable; animated plus `?still=1`.
    let (s, h, data) = public(&node, &format!("/api/v1/emojis/{id}/image")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(data, still);
    assert_eq!(h[header::CONTENT_TYPE], "image/webp");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["content-security-policy"], "default-src 'none'; sandbox");
    assert_eq!(h[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
    let gid = e2["id"].as_str().unwrap();
    let (_, _, anim) = public(&node, &format!("/api/v1/emojis/{gid}/image")).await;
    let (w, h, frames) = webp_info(&anim);
    assert!(w == 64 && h == 64 && frames.len() > 1, "{w}x{h} {frames:?}");
    let (_, _, first) = public(&node, &format!("/api/v1/emojis/{gid}/image?still=1")).await;
    assert!(webp_info(&first).2.is_empty(), "the still variant has no animation");
    assert!(first.len() < anim.len());
    let (s, _, _) = public(&node, "/api/v1/emojis/01J9ZK8Q4V6X3M2N1P0R5S7T8W/image").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = public(&node, "/api/v1/emojis/..%2F..%2Fetc/image").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Deleting removes both files.
    let still_id: Option<String> = sqlx::query_scalar("SELECT still_id FROM emojis WHERE id = $1")
        .bind(gid)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    let still_id = still_id.expect("animated emojis have a still variant");
    let (s, _) = node.delete(&format!("{base}/{gid}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(node.state.storage.read(gid).await.unwrap().is_none());
    assert!(node.state.storage.read(&still_id).await.unwrap().is_none());
    let (s, _, _) = public(&node, &format!("/api/v1/emojis/{gid}/image")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = node.delete(&format!("{base}/{gid}"), &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn animated_emojis_are_cut_and_bombs_refused_before_decoding() {
    let long = need!(animated_gif(8, "64x64"));
    // A huge canvas compresses to a few KB: the dimensions are checked before anything decodes it.
    let huge = need!(fixture("color=c=red:size=2048x2048:rate=2:duration=1", &["-f", "gif"]));
    let video = need!(fixture("testsrc=size=64x64:rate=10:duration=1", &["-f", "mp4", "-pix_fmt", "yuv420p"]));
    let node = test_node_with("t.local", |c| c.emoji_max_bytes = 1024 * 1024).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Room").await;
    let base = format!("/api/v1/rooms/{}/emojis", room["id"].as_str().unwrap());

    let (s, e) = upload_emoji(&node, &alice.token, &base, "long", "image/gif", &long).await;
    assert_eq!(s, StatusCode::CREATED, "{e}");
    let (_, _, anim) = public(&node, &format!("/api/v1/emojis/{}/image", e["id"].as_str().unwrap())).await;
    assert!(anim.len() <= 256 * 1024);
    let (_, _, frames) = webp_info(&anim);
    let total: u32 = frames.iter().sum();
    assert!(frames.len() <= 60 && total <= 5100, "{} frames, {total} ms", frames.len());

    let (s, j) = upload_emoji(&node, &alice.token, &base, "huge", "image/gif", &huge).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("media.dimensions")), "{j}");
    let (s, j) = upload_emoji(&node, &alice.token, &base, "video", "image/gif", &video).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("media.type_not_allowed")), "{j}");
    // A GIF with thousands of (tiny) frames is refused by counting, not by decoding.
    let many = need!(fixture("color=c=blue:size=8x8:rate=100:duration=12", &["-f", "gif"]));
    let (s, j) = upload_emoji(&node, &alice.token, &base, "many", "image/gif", &many).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("media.too_long")), "{j}");
}

#[tokio::test]
async fn gif_search_is_proxied_and_gif_messages_validated() {
    use axum::{Json, Router, extract::Query, routing::get};
    #[derive(serde::Deserialize)]
    struct Q {
        q: Option<String>,
    }
    let fake = Router::new().route("/v1/gifs/search", get(|Query(q): Query<Q>| async move { Json(json!({ "data": [{ "id": "g1", "title": q.q, "images": { "original": { "url": "https://media.giphy.com/g1.gif", "width": "1", "height": "1" }, "fixed_height_small": { "url": "https://media.giphy.com/g1s.gif" } } }] })) }))
        .route("/v1/gifs/trending", get(|| async { Json(json!({ "data": [] })) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });

    let mut node = test_node("t.local").await;
    let alice = node.register("alice").await;
    let (s, j) = node.get_auth("/api/v1/gifs?q=dog", &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "without a provider: {j}");
    assert_eq!(j["code"], "gif.disabled");

    node.state.gifs = Some(tavrn_node::gifs::GifClient::new(
        tavrn_node::config::GifProvider::Giphy,
        "k".into(),
        &format!("http://{addr}"),
    ));
    node.router = tavrn_node::app::router(node.state.clone());
    let (s, j) = node.get_auth("/api/v1/gifs?q=dog", &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["provider"], "giphy");
    assert_eq!(j["results"][0]["title"], "dog");
    let (s, j) = node.get_auth("/api/v1/gifs", &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["results"].as_array().unwrap().len(), 0);
    let (s, _) = node.req(Method::GET, "/api/v1/gifs?q=x", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel_id = TestNode::text_channel(&room);
    let path = format!("/api/v1/rooms/{room_id}/channels/{channel_id}/messages");
    let (s, j) = node.post(&path, &alice.token, json!({ "content": { "type": "text", "body": "", "gif": { "url": "https://media.giphy.com/g1.gif", "preview_url": "https://media.giphy.com/g1s.gif", "width": 1, "height": 1 } } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["content"]["gif"]["url"], "https://media.giphy.com/g1.gif");
    let (s, j) = node
        .post(
            &path,
            &alice.token,
            json!({ "content": { "type": "text", "body": "", "gif": { "url": "https://evil.example/x.gif" } } }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.gif_invalid");
}

/// An unreachable GIF provider answers `503 gif.unavailable`; the log line names the failure and the request (route,
/// request id), never the provider URL with the node's API key and the user's search term.
#[tokio::test]
async fn an_unreachable_gif_provider_is_logged_without_the_key() {
    let mut node = test_node("t.local").await;
    let alice = node.register("alice").await;
    // A port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    node.state.gifs = Some(tavrn_node::gifs::GifClient::new(
        tavrn_node::config::GifProvider::Giphy,
        "GifKeyDoNotLog".into(),
        &format!("http://127.0.0.1:{port}"),
    ));
    node.router = tavrn_node::app::router(node.state.clone());
    let _capture = common::logs::CAPTURE.lock().await;
    let (capture, guard) = common::logs::start();
    let (s, headers, body) =
        node.raw(Method::GET, "/api/v1/gifs?q=SecretSearchTerm", &alice.token, &[], Vec::new()).await;
    drop(guard);
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((s, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("gif.unavailable")), "{j}");
    let log = capture.text();
    let line = log.lines().find(|l| l.contains("GIF provider unreachable"));
    assert!(line.is_some(), "no log line: {log}");
    let line = line.unwrap();
    assert!(!log.contains("GifKeyDoNotLog") && !log.contains("SecretSearchTerm"), "{log}");
    assert!(line.contains("/api/v1/gifs"), "the route: {line}");
    assert!(line.contains(headers["x-request-id"].to_str().unwrap()), "the request id: {line}");
}
