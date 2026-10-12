// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Profiles: image uploads through the media pipeline, bio and linked accounts, public
//! profiles and images, room icons, and the profile mirror on other nodes. Image fixtures are made by
//! ffmpeg; the tests that need conversions skip when it is not installed (CI installs it).
use crate::common;

use axum::http::{Method, StatusCode};
use common::federation::{A, two_nodes};
use common::{TestNode, test_node};
use serde_json::{Value, json};

const DOMAIN: &str = "t.local";

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

fn still_png() -> Option<Vec<u8>> {
    fixture("testsrc=size=320x240:rate=1", &["-frames:v", "1", "-f", "image2", "-c:v", "png"])
}

fn animated_gif() -> Option<Vec<u8>> {
    fixture("testsrc=size=64x64:rate=10:duration=1", &["-f", "gif"])
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

async fn upload(node: &TestNode, path: &str, token: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
    let (status, _, body) =
        node.raw(Method::PUT, path, token, &[("content-type", "application/octet-stream")], bytes).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// GET of a public image: status, content type, cache control and the bytes.
async fn image(node: &TestNode, path: &str) -> (StatusCode, String, String, Vec<u8>) {
    let resp = node.get(path).await;
    let h = |name: &str| resp.headers().get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
    let (status, ctype, cache) = (resp.status(), h("content-type"), h("cache-control"));
    if status == StatusCode::OK {
        assert_eq!(h("x-content-type-options"), "nosniff");
        assert_eq!(h("content-security-policy"), "default-src 'none'; sandbox");
    }
    (status, ctype, cache, common::body_bytes(resp).await.to_vec())
}

/// Dimensions and animation flag of a WebP (VP8X header, or the simple formats).
fn webp_size(data: &[u8]) -> (u32, u32, bool) {
    assert_eq!(&data[0..4], b"RIFF");
    assert_eq!(&data[8..12], b"WEBP");
    let le24 = |b: &[u8]| u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16);
    match &data[12..16] {
        b"VP8X" => (le24(&data[24..27]) + 1, le24(&data[27..30]) + 1, data[20] & 0x02 != 0),
        b"VP8L" => {
            let bits = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
            ((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1, false)
        }
        _ => {
            let w = u16::from_le_bytes([data[26], data[27]]) & 0x3FFF;
            let h = u16::from_le_bytes([data[28], data[29]]) & 0x3FFF;
            (u32::from(w), u32::from(h), false)
        }
    }
}

#[tokio::test]
async fn avatars_are_converted_served_and_replaced() {
    let png = need!(still_png());
    let gif = need!(animated_gif());
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let (_, before) = node.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(before["avatar"], Value::Null);
    let v0 = before["profile_version"].as_i64().unwrap();

    // A still: WebP 256 × 256, no animated variant, the version grows.
    let (st, p) = upload(&node, "/api/v1/users/me/avatar", &alice.token, png).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["avatar_animated"], false);
    assert_eq!(p["avatar"], p["avatar_still"]);
    assert!(p["profile_version"].as_i64().unwrap() > v0);
    let still = p["avatar_still"].as_str().unwrap().to_string();
    let (st, ctype, cache, bytes) = image(&node, &still).await;
    assert_eq!((st, ctype.as_str()), (StatusCode::OK, "image/webp"));
    assert_eq!(cache, "public, max-age=31536000, immutable", "keyed by id, cached long");
    assert_eq!(webp_size(&bytes), (256, 256, false));
    assert_eq!(image(&node, &format!("{still}/animated")).await.0, StatusCode::NOT_FOUND);

    // An animated GIF: still first frame plus animated WebP; the old images are gone.
    let (st, p) = upload(&node, "/api/v1/users/me/avatar", &alice.token, gif).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["avatar_animated"], true);
    let (still2, animated) = (p["avatar_still"].as_str().unwrap(), p["avatar"].as_str().unwrap());
    assert_eq!(animated, format!("{still2}/animated"));
    assert_eq!(webp_size(&image(&node, still2).await.3), (256, 256, false));
    assert_eq!(webp_size(&image(&node, animated).await.3), (256, 256, true));
    assert_eq!(image(&node, &still).await.0, StatusCode::NOT_FOUND, "the replaced avatar was deleted");
    // Member lists, messages and friends carry the paths in the user object.
    let (_, me) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!(me["avatar"], animated);
    assert_eq!(me["avatar_still"], still2);
    // The legacy route serves the still (older nodes mirror from it).
    assert_eq!(node.get("/api/v1/users/alice/avatar").await.status(), StatusCode::OK);

    let (st, p) = node.delete("/api/v1/users/me/avatar", &alice.token).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["avatar"], Value::Null);
    assert_eq!(image(&node, still2).await.0, StatusCode::NOT_FOUND);
    assert_eq!(image(&node, "/api/v1/media/not-an-id").await.0, StatusCode::NOT_FOUND);
    assert_eq!(image(&node, "/api/v1/media/01J9ZZZZZZZZZZZZZZZZZZZZZZ").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uploads_are_checked_before_conversion() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    // SVG (scripts!) and HTML are refused whatever the content type says.
    let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".to_vec();
    let (st, _, body) =
        node.raw(Method::PUT, "/api/v1/users/me/avatar", &alice.token, &[("content-type", "image/png")], svg).await;
    let j: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((st, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("media.type_not_allowed")));
    let (st, j) = upload(&node, "/api/v1/users/me/header", &alice.token, b"<!DOCTYPE html><p>x</p>".to_vec()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("media.type_not_allowed")));
    let (st, j) = upload(&node, "/api/v1/users/me/avatar", &alice.token, Vec::new()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("media.invalid")));
    // More than 20 MB: refused while reading (no conversion starts).
    let big = vec![0x89u8; 20 * 1024 * 1024 + 1];
    let (st, j) = upload(&node, "/api/v1/users/me/avatar", &alice.token, big).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("media.too_large")));
    // Unauthenticated uploads are refused.
    let (st, _) = node.req(Method::PUT, "/api/v1/users/me/avatar", None, Some(json!({}))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let long = need!(fixture("testsrc=size=32x32:rate=1:duration=40", &["-f", "gif"]));
    let (st, j) = upload(&node, "/api/v1/users/me/avatar", &alice.token, long).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("media.too_long")), "{j}");
}

#[tokio::test]
async fn without_ffmpeg_animations_are_refused_with_a_clear_code() {
    let gif = need!(animated_gif());
    let png = need!(still_png());
    let node = common::test_node_with(DOMAIN, |c| c.media_ffmpeg = "off".into()).await;
    let alice = node.register("alice").await;
    let (st, j) = upload(&node, "/api/v1/users/me/avatar", &alice.token, gif).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::UNSUPPORTED_MEDIA_TYPE, Some("media.animation_unavailable")));
    let (st, p) = upload(&node, "/api/v1/users/me/avatar", &alice.token, png).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    let (_, ctype, _, _) = image(&node, p["avatar"].as_str().unwrap()).await;
    assert_eq!(ctype, "image/png", "stored as uploaded, metadata removed");
}

#[tokio::test]
async fn headers_and_backgrounds() {
    let png = need!(still_png());
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let (st, p) = upload(&node, "/api/v1/users/me/header", &alice.token, png.clone()).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["header_animated"], false);
    assert_eq!(webp_size(&image(&node, p["header"].as_str().unwrap()).await.3), (1200, 400, false));

    // Backgrounds are private: only through /users/me/background with the owner's session.
    let (st, bg) = upload(&node, "/api/v1/users/me/background", &alice.token, png).await;
    assert_eq!(st, StatusCode::OK, "{bg}");
    assert_eq!(bg["still"], "/api/v1/users/me/background/still");
    assert_eq!(bg["animated"], Value::Null);
    let resp = node.get_with("/api/v1/users/me/background/still", &alice.token).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(webp_size(&common::body_bytes(resp).await), (320, 240, false), "fit into 1280, never upscaled");
    let resp = node.get_with("/api/v1/users/me/background/still", &bob.token).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "bob has none, and cannot name alice's");
    let id: String = sqlx::query_scalar("SELECT background_blob_id FROM users WHERE username = 'alice'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(image(&node, &format!("/api/v1/media/{id}")).await.0, StatusCode::NOT_FOUND, "never public");
    let (st, bg) = node.delete("/api/v1/users/me/background", &alice.token).await;
    assert_eq!((st, &bg["still"]), (StatusCode::OK, &Value::Null));
}

#[tokio::test]
async fn bio_links_and_settings() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let (_, before) = node.req(Method::GET, "/api/v1/users/alice@t.local/profile", None, None).await;
    let v0 = before["profile_version"].as_i64().unwrap();
    assert_eq!(before["dm_policy"], "everyone_shared");
    let links = json!([
        { "service": "steam", "value": "https://steamcommunity.com/id/alice_gg" },
        { "service": "battlenet", "value": "Alice#1234" },
        { "service": "twitch", "value": "AliceStreams", "url": "https://evil.example/phish" },
        { "service": "website", "value": "https://alice.example/" },
    ]);
    let (st, j) = node
        .patch(
            "/api/v1/users/me",
            &alice.token,
            json!({ "bio": " **GG** \nwp ", "links": links, "dm_policy": "friends" }),
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (_, p) = node.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(p["bio"], "**GG** \nwp");
    assert_eq!(p["dm_policy"], "friends");
    assert!(p["profile_version"].as_i64().unwrap() > v0);
    assert_eq!(
        p["links"],
        json!([
            { "service": "steam", "value": "alice_gg", "url": "https://steamcommunity.com/id/alice_gg" },
            { "service": "battlenet", "value": "Alice#1234", "url": null },
            { "service": "twitch", "value": "alicestreams", "url": "https://www.twitch.tv/alicestreams" },
            { "service": "website", "value": "alice.example", "url": "https://alice.example/" },
        ]),
        "URLs are derived by the node, never taken from the client"
    );

    for (body, code) in [
        (json!({ "bio": "x".repeat(513) }), "profile.bio_too_long"),
        (json!({ "links": [{ "service": "website", "value": "javascript:alert(1)" }] }), "profile.link_invalid"),
        (json!({ "links": [{ "service": "website", "value": "https://192.168.1.1/" }] }), "profile.link_invalid"),
        (json!({ "links": [{ "service": "myspace", "value": "x" }] }), "profile.link_service"),
        (json!({ "links": vec![json!({ "service": "x", "value": "a" }); 11] }), "profile.links_too_many"),
        (json!({ "dm_policy": "nobody" }), "validation.enum"),
        (json!({ "display_name": "" }), "validation.length"),
    ] {
        let (st, j) = node.patch("/api/v1/users/me", &alice.token, body.clone()).await;
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}");
    }
    // Clearing the bio and the links.
    let (st, _) = node.patch("/api/v1/users/me", &alice.token, json!({ "bio": "", "links": [] })).await;
    assert_eq!(st, StatusCode::OK);
    let (_, p) = node.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!((p["bio"].as_str(), p["links"].as_array().map(Vec::len)), (Some(""), Some(0)));
    // Unknown users and malformed addresses.
    for path in
        ["/api/v1/users/nobody/profile", "/api/v1/users/x@unknown.example/profile", "/api/v1/users/a%20b/profile"]
    {
        assert_eq!(node.req(Method::GET, path, None, None).await.0, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn room_icons_need_manage_room_and_are_audited() {
    let node = test_node(DOMAIN).await;
    let owner = node.register("owner").await;
    let member = node.register("member").await;
    let outsider = node.register("outsider").await;
    let room = node.create_room(&owner.token, "Guild").await;
    let id = room["id"].as_str().unwrap();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &owner.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({})).await;
    let path = format!("/api/v1/rooms/{id}/icon");
    // Permissions are checked before the body is read.
    let (st, j) = upload(&node, &path, &member.token, b"whatever".to_vec()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.manage_forbidden")));
    let (st, _) = upload(&node, &path, &outsider.token, b"whatever".to_vec()).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let (st, _) = node.delete(&path, &member.token).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    let gif = need!(animated_gif());
    let mut rx = node.state.hub.subscribe();
    let (st, r) = upload(&node, &path, &owner.token, gif).await;
    assert_eq!(st, StatusCode::OK, "{r}");
    assert_eq!(r["icon_animated"], true);
    assert!(r["icon"].as_str().unwrap().ends_with("/animated"));
    let ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "room.update").unwrap();
    assert_eq!(ev.data["icon"], r["icon"]);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{id}"), &member.token).await;
    assert_eq!(detail["icon_still"], r["icon_still"]);
    let (_, rooms) = node.get_auth("/api/v1/rooms", &member.token).await;
    assert_eq!(rooms[0]["icon"], r["icon"]);
    let (_, preview) =
        node.req(Method::GET, &format!("/api/v1/invites/{}", invite["code"].as_str().unwrap()), None, None).await;
    assert_eq!(preview["room"]["icon_still"], r["icon_still"], "invite previews show the icon");
    assert_eq!(image(&node, r["icon"].as_str().unwrap()).await.0, StatusCode::OK);

    let (st, r2) = node.delete(&path, &owner.token).await;
    assert_eq!((st, &r2["icon"]), (StatusCode::OK, &Value::Null));
    assert_eq!(image(&node, r["icon_still"].as_str().unwrap()).await.0, StatusCode::NOT_FOUND);
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{id}/audit-log"), &owner.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"room.icon") && actions.contains(&"room.icon_remove"), "{actions:?}");
}

#[tokio::test]
async fn the_profile_mirror_copies_images_bio_and_links() {
    let png = need!(still_png());
    let gif = need!(animated_gif());
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    upload(&a, "/api/v1/users/me/avatar", &alice.token, gif).await;
    upload(&a, "/api/v1/users/me/header", &alice.token, png).await;
    a.patch(
        "/api/v1/users/me",
        &alice.token,
        json!({ "bio": "Raid lead", "links": [{ "service": "x", "value": "@alice" }], "dm_policy": "everyone" }),
    )
    .await;
    b.sign_in_from(&a, &alice).await;

    let (st, p) = b.req(Method::GET, "/api/v1/users/alice@a.test/profile", None, None).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    assert_eq!(p["bio"], "Raid lead");
    assert_eq!(p["links"][0]["url"], "https://x.com/alice");
    assert_eq!(p["dm_policy"], "everyone");
    assert_eq!(p["avatar_animated"], true);
    let (_, home) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_ne!(p["avatar"], home["avatar"], "B serves its own copy");
    for (key, sha) in
        [("avatar_still", "avatar_sha256"), ("avatar", "avatar_animated_sha256"), ("header", "header_sha256")]
    {
        let (st, _, _, bytes) = image(&b, p[key].as_str().unwrap()).await;
        assert_eq!(st, StatusCode::OK, "{key}");
        assert_eq!(tavrn_node::federation::tokens::body_sha256(&bytes), home[sha].as_str().unwrap(), "{key}");
    }

    // A change on A reaches B with the next login (newer profile version), the old copies go.
    let old = p["avatar_still"].as_str().unwrap().to_string();
    a.delete("/api/v1/users/me/avatar", &alice.token).await;
    a.patch("/api/v1/users/me", &alice.token, json!({ "bio": "Retired" })).await;
    b.sign_in_from(&a, &alice).await;
    let (_, p) = b.req(Method::GET, "/api/v1/users/alice@a.test/profile", None, None).await;
    assert_eq!((p["bio"].as_str(), &p["avatar"]), (Some("Retired"), &Value::Null));
    assert_eq!(image(&b, &old).await.0, StatusCode::NOT_FOUND);
    let _ = A;
}

/// The `profile.changed` entries of a node's outbox: (target, payload).
async fn profile_changes(node: &common::federation::FedNode) -> Vec<(String, Value)> {
    node.outbox()
        .await
        .into_iter()
        .filter(|e| e.kind == "profile.changed")
        .map(|e| (e.target, serde_json::from_str::<Value>(&e.body).unwrap()["payload"].clone()))
        .collect()
}

/// Waits (up to 10 s) until B's mirror of alice@a.test satisfies `done`.
async fn mirror_until(b: &common::federation::FedNode, done: impl Fn(&Value) -> bool) -> Value {
    let mut p = Value::Null;
    for _ in 0..100 {
        p = b.req(Method::GET, "/api/v1/users/alice@a.test/profile", None, None).await.1;
        if done(&p) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(done(&p), "the mirror on B was not refreshed: {p}");
    p
}

/// FEDERATION.md §2.7 (d), §5.2: a profile change on A reaches B's mirror through `profile.changed`, without a new
/// federation token; a burst of edits leaves as one message with the latest version; the private background never
/// leaves the node.
#[tokio::test]
async fn a_profile_change_reaches_the_mirror_without_a_new_token() {
    let png = need!(still_png());
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    b.sign_in_from(&a, &alice).await;
    let (_, p) = b.req(Method::GET, "/api/v1/users/alice@a.test/profile", None, None).await;
    assert_eq!(p["avatar_sha256"], Value::Null);
    assert!(profile_changes(&a).await.is_empty());

    // A burst: avatar, name and bio within the coalescing window give one queued message per target.
    let (st, r) = upload(&a, "/api/v1/users/me/avatar", &alice.token, png.clone()).await;
    assert_eq!(st, StatusCode::OK, "{r}");
    a.patch("/api/v1/users/me", &alice.token, json!({ "display_name": "Alice Avatar" })).await;
    a.patch("/api/v1/users/me", &alice.token, json!({ "bio": "New look" })).await;
    let (_, home) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    let changes = profile_changes(&a).await;
    assert_eq!(changes, vec![("b.test".to_string(), json!({ "profile_version": home["profile_version"] }))]);
    assert_eq!(a.deliver().await.delivered, 0, "held back a few seconds to coalesce the burst");

    let mut rx = b.state.hub.subscribe();
    assert_eq!(a.deliver_at(6).await.delivered, 1);
    let p = mirror_until(&b, |p| p["avatar_sha256"] == home["avatar_sha256"]).await;
    assert_eq!((p["display_name"].as_str(), p["bio"].as_str()), (Some("Alice Avatar"), Some("New look")));
    assert_eq!(p["profile_version"], home["profile_version"]);
    assert_ne!(p["avatar_still"], home["avatar_still"], "B serves its own copy");
    let (st, _, _, bytes) = image(&b, p["avatar_still"].as_str().unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(tavrn_node::federation::tokens::body_sha256(&bytes), home["avatar_sha256"].as_str().unwrap());
    let alice_on_b = p["id"].clone();
    let mut announced = false;
    for _ in 0..50 {
        if std::iter::from_fn(|| rx.try_recv().ok())
            .any(|e| e.kind == "user.update" && e.data["user"]["id"] == alice_on_b)
        {
            announced = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(announced, "clients on B hear about the refreshed mirror");
    let _ = bob;

    // A second change: the old copy on B goes, the new one is served (still no new token).
    let old = p["avatar_still"].as_str().unwrap().to_string();
    a.delete("/api/v1/users/me/avatar", &alice.token).await;
    assert_eq!(profile_changes(&a).await.len(), 1);
    a.deliver_at(6).await;
    mirror_until(&b, |p| p["avatar"].is_null()).await;
    assert_eq!(image(&b, &old).await.0, StatusCode::NOT_FOUND);

    // The DM setting is public too; the private background and unchanged names are not announced.
    a.patch("/api/v1/users/me", &alice.token, json!({ "dm_policy": "everyone" })).await;
    let (_, home) = a.req(Method::GET, "/api/v1/users/alice/profile", None, None).await;
    assert_eq!(
        profile_changes(&a).await,
        vec![("b.test".to_string(), json!({ "profile_version": home["profile_version"] }))]
    );
    a.deliver_at(6).await;
    mirror_until(&b, |p| p["dm_policy"] == "everyone").await;
    let (st, _) = upload(&a, "/api/v1/users/me/background", &alice.token, png).await;
    assert_eq!(st, StatusCode::OK);
    a.patch("/api/v1/users/me", &alice.token, json!({ "hide_activity": true })).await;
    assert!(profile_changes(&a).await.is_empty(), "no notification for private settings");
}
