// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Per-room profiles: nickname, bio and avatar per membership, moderation with
//! `manage_nicknames`, the author profile on messages, and that the profile ends with the membership.
//! The avatar test needs ffmpeg for its fixture and skips without it.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, perms, test_node};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const DOMAIN: &str = "t.local";

fn png() -> Option<Vec<u8>> {
    let path = std::env::var_os("PATH")?;
    let ffmpeg = std::env::split_paths(&path).map(|d| d.join("ffmpeg")).find(|p| p.is_file())?;
    let dir = tempfile::tempdir().ok()?;
    let out = dir.path().join("a.png");
    let ok = std::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x64:rate=1"])
        .args(["-frames:v", "1", "-f", "image2", "-c:v", "png"])
        .arg(&out)
        .status()
        .ok()?
        .success();
    if ok { std::fs::read(out).ok() } else { None }
}

pub fn stored(node: &TestNode, id: &str) -> bool {
    std::path::Path::new(&node.state.config.data_dir).join("blobs").join(&id[..2]).join(id).is_file()
}

async fn setup() -> (TestNode, Session, Session, String, String) {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    (node, alice, bob, room_id, channel)
}

async fn member(node: &TestNode, token: &str, room_id: &str, user_id: &str) -> Value {
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), token).await;
    list.as_array().unwrap().iter().find(|m| m["user"]["id"] == user_id).cloned().unwrap()
}

#[tokio::test]
async fn own_room_profile_is_set_shown_and_reset() {
    let (node, alice, bob, room_id, channel) = setup().await;
    let path = format!("/api/v1/rooms/{room_id}/members/me/profile");
    let (s, m) = node.put(&path, &bob.token, json!({ "nickname": "Bobby", "bio": "**Healer** main" })).await;
    assert_eq!(s, StatusCode::OK, "{m}");
    assert_eq!(
        (m["nick"].as_str(), m["nickname"].as_str(), m["room_bio"].as_str()),
        (Some("Bobby"), Some("Bobby"), Some("**Healer** main"))
    );
    assert_eq!(m["room_avatar"], Value::Null);
    let seen = member(&node, &alice.token, &room_id, &bob.user_id).await;
    assert_eq!(seen["nick"], "Bobby");

    // Messages in this room carry the author's room profile.
    let (s, msg) = node.send(&bob.token, &room_id, &channel, "hello").await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    assert_eq!(msg["author_room_profile"]["nick"], "Bobby");
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), &alice.token).await;
    assert_eq!(list[0]["author_room_profile"]["nick"], "Bobby");
    let (_, own) = node.send(&alice.token, &room_id, &channel, "hi").await;
    assert_eq!(own["author_room_profile"], Value::Null, "no profile, no object");

    // Validation and permission.
    let (s, j) = node.put(&path, &bob.token, json!({ "nickname": "x".repeat(33) })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")), "{j}");
    let (s, j) = node.put(&path, &bob.token, json!({ "bio": "x".repeat(513) })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("profile.bio_too_long")), "{j}");
    let everyone = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await.1["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["is_everyone"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    node.patch(
        &format!("/api/v1/rooms/{room_id}/roles/{everyone}"),
        &alice.token,
        json!({ "permissions": perms(&[p::VIEW_CHANNEL, p::SEND_MESSAGES]) }),
    )
    .await;
    let (s, j) = node.put(&path, &bob.token, json!({ "nickname": "Nope" })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("member.nickname_forbidden")), "{j}");

    // Reset by the member, and non-members have none.
    let (s, m) = node.delete(&path, &bob.token).await;
    assert_eq!((s, &m["nick"], &m["room_bio"]), (StatusCode::OK, &Value::Null, &Value::Null), "{m}");
    let carol = node.register("carol").await;
    let (s, _) = node.put(&path, &carol.token, json!({ "nickname": "x" })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn moderators_change_profiles_below_them_and_are_audited() {
    let (node, alice, bob, room_id, _) = setup().await;
    let carol = node.register("carol").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &alice.token, json!({})).await;
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &carol.token, json!({})).await;
    node.put(
        &format!("/api/v1/rooms/{room_id}/members/me/profile"),
        &carol.token,
        json!({ "nickname": "BadWord", "bio": "rude" }),
    )
    .await;
    let path = format!("/api/v1/rooms/{room_id}/members/{}/profile", carol.user_id);
    let (s, j) = node.patch(&path, &bob.token, json!({ "nickname": null })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("member.nickname_forbidden")), "{j}");
    let (_, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &alice.token,
            json!({ "name": "Mods", "permissions": perms(&[p::MANAGE_NICKNAMES]), "position": 2 }),
        )
        .await;
    node.patch(
        &format!("/api/v1/rooms/{room_id}/members/{}", bob.user_id),
        &alice.token,
        json!({ "roles": [role["id"]] }),
    )
    .await;
    let (s, m) = node.patch(&path, &bob.token, json!({ "nickname": null, "bio": "", "reset_avatar": true })).await;
    assert_eq!((s, &m["nick"], &m["room_bio"]), (StatusCode::OK, &Value::Null, &Value::Null), "{m}");
    // Not on the owner (the owner resets their own via /me), not upwards.
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}/profile", alice.user_id),
            &bob.token,
            json!({ "nickname": "x" }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("member.is_owner")), "{j}");
    let (s, _) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}/profile", bob.user_id),
            &alice.token,
            json!({ "nickname": "Mod" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the owner may change everybody's");
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &alice.token).await;
    let n = log.as_array().unwrap().iter().filter(|e| e["action"] == "member.profile").count();
    assert_eq!(n, 2, "{log}");
}

#[tokio::test]
async fn room_avatar_uses_the_media_pipeline_and_goes_with_the_membership() {
    let Some(png) = png() else {
        eprintln!("ffmpeg not installed: skipped");
        return;
    };
    let (node, alice, bob, room_id, _) = setup().await;
    let path = format!("/api/v1/rooms/{room_id}/members/me/avatar");
    let (s, _, body) = node.raw(Method::PUT, &path, &bob.token, &[("content-type", "image/png")], png.clone()).await;
    let m: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(s, StatusCode::OK, "{m}");
    let still = m["room_avatar_still"].as_str().unwrap().to_string();
    assert!(still.starts_with("/api/v1/media/"), "{m}");
    let id = still.trim_start_matches("/api/v1/media/").to_string();
    assert!(stored(&node, &id));
    let resp = node.get(&still).await;
    assert_eq!(resp.status(), StatusCode::OK, "public like user avatars");
    // Replacing deletes the old file right away.
    let (s, _, body) = node.raw(Method::PUT, &path, &bob.token, &[("content-type", "image/png")], png.clone()).await;
    assert_eq!(s, StatusCode::OK);
    let m: Value = serde_json::from_slice(&body).unwrap();
    let id2 = m["room_avatar_still"].as_str().unwrap().trim_start_matches("/api/v1/media/").to_string();
    assert_ne!(id, id2);
    assert!(!stored(&node, &id) && stored(&node, &id2));
    let (s, _, _) = node.raw(Method::PUT, &path, &bob.token, &[], b"<svg/>".to_vec()).await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "SVG is refused like for user avatars");
    // Leaving ends the profile and deletes the avatar.
    let (s, _) = node.post(&format!("/api/v1/rooms/{room_id}/leave"), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!stored(&node, &id2), "room avatar deleted on leave");
    let _ = alice;
}
