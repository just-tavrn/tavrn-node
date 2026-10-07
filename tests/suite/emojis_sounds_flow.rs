// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Feature round 3: personal emojis and clips on the home node, public emoji and
//! clip bytes, external use gated by `use_external_emojis` / `use_external_sounds` (messages, reactions,
//! soundboard play), clip emojis, attachment spoilers, deleted reply originals and the one-time fixup that
//! grants the new bits to `@everyone` of old rooms.
use crate::common;

use axum::http::{Method, StatusCode, header};
use common::{Session, TestNode, body_bytes, perms, test_node_with};
use serde_json::{Value, json};
use tavrn_node::{config::Config, permissions as p};

const DOMAIN: &str = "t.local";
const FOREIGN_ID: &str = "01J9ZK8Q4V6X3M2N1P0R5S7T8W";

fn ffmpeg() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join("ffmpeg")).find(|p| p.is_file())
}

fn png() -> Option<Vec<u8>> {
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("f.png");
    let ok = std::process::Command::new(ffmpeg()?)
        .args(["-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "testsrc=size=64x64:rate=1"])
        .args(["-frames:v", "1", "-f", "image2", "-c:v", "png"])
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

fn code(j: &Value) -> Option<&str> {
    j["code"].as_str()
}

async fn upload(
    node: &TestNode,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let (s, _, b) = node.raw(Method::POST, path, token, headers, body).await;
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

async fn emoji(node: &TestNode, path: &str, token: &str, name: &str, data: &[u8]) -> (StatusCode, Value) {
    upload(node, path, token, &[("content-type", "image/png"), ("tavrn-emoji-name", name)], data.to_vec()).await
}

async fn clip(node: &TestNode, path: &str, token: &str, name: &str, emoji: Option<&str>) -> (StatusCode, Value) {
    let mut h = vec![("content-type", "audio/ogg"), ("tavrn-sound-name", name), ("tavrn-sound-duration-ms", "900")];
    if let Some(e) = emoji {
        h.push(("tavrn-sound-emoji", e));
    }
    upload(node, path, token, &h, vec![9u8; 512]).await
}

struct Rooms {
    node: TestNode,
    alice: Session,
    bob: Session,
    /// Alice's room with emoji `:own:`.
    home: String,
    /// The second room (bob is a member of both), plaintext text channel `text`, with emoji `:local:`.
    other: String,
    text: String,
    voice: String,
    everyone: String,
    own_id: String,
    local_id: String,
}

async fn join(node: &TestNode, owner: &Session, room: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

async fn rooms(tweak: impl FnOnce(&mut Config)) -> Option<Rooms> {
    let image = png()?;
    let node = test_node_with(DOMAIN, tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let home = node.create_room(&alice.token, "Home").await["id"].as_str().unwrap().to_string();
    let other_room = node.plaintext_room(&alice.token, "Other").await;
    let other = other_room["id"].as_str().unwrap().to_string();
    let text = TestNode::text_channel(&other_room);
    let voice = other_room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "voice").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let everyone = other_room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    join(&node, &alice, &home, &bob).await;
    join(&node, &alice, &other, &bob).await;
    let (s, own) = emoji(&node, &format!("/api/v1/rooms/{home}/emojis"), &alice.token, "own", &image).await;
    assert_eq!(s, StatusCode::CREATED, "{own}");
    let (s, local) = emoji(&node, &format!("/api/v1/rooms/{other}/emojis"), &alice.token, "local", &image).await;
    assert_eq!(s, StatusCode::CREATED, "{local}");
    Some(Rooms {
        own_id: own["id"].as_str().unwrap().into(),
        local_id: local["id"].as_str().unwrap().into(),
        node,
        alice,
        bob,
        home,
        other,
        text,
        voice,
        everyone,
    })
}

impl Rooms {
    fn messages(&self) -> String {
        format!("/api/v1/rooms/{}/channels/{}/messages", self.other, self.text)
    }

    /// Removes the external bits from `@everyone` of the second room.
    async fn deny_external(&self) {
        let bits = p::DEFAULT_EVERYONE & !(p::USE_EXTERNAL_EMOJIS | p::USE_EXTERNAL_SOUNDS);
        let (s, j) = self
            .node
            .patch(
                &format!("/api/v1/rooms/{}/roles/{}", self.other, self.everyone),
                &self.alice.token,
                json!({ "permissions": perms(&[bits]) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{j}");
    }
}

#[tokio::test]
async fn personal_emojis_live_on_the_home_node_with_limits() {
    let image = need!(png());
    let node = test_node_with(DOMAIN, |c| c.emoji_max_personal = 2).await;
    // The first account is a node admin, unlimited by entitlements: limits are checked on a normal user.
    node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let base = "/api/v1/users/me/emojis";
    let (s, list) = node.get_auth(base, &alice.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!((list["max_personal"].as_u64(), list["items"].as_array().map(Vec::len)), (Some(2), Some(0)));

    let (s, e1) = emoji(&node, base, &alice.token, "wave", &image).await;
    assert_eq!(s, StatusCode::CREATED, "{e1}");
    assert_eq!((e1["name"].as_str(), e1["animated"].as_bool()), (Some("wave"), Some(false)));
    let (s, j) = emoji(&node, base, &alice.token, "wave", &image).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, Some("emoji.name_taken")), "{j}");
    let (s, j) = emoji(&node, base, &alice.token, "x", &image).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("emoji.name_invalid")), "{j}");
    let (s, e2) = emoji(&node, base, &alice.token, "nod", &image).await;
    assert_eq!(s, StatusCode::CREATED, "{e2}");
    let (s, j) = emoji(&node, base, &alice.token, "third", &image).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("emoji.limit")), "{j}");
    // Bob's list is his own; another user's emoji cannot be renamed or deleted.
    let (_, list) = node.get_auth(base, &bob.token).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
    let id = e1["id"].as_str().unwrap();
    let (s, _) = node.patch(&format!("{base}/{id}"), &bob.token, json!({ "name": "mine" })).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = node.delete(&format!("{base}/{id}"), &bob.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "name": "nod" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, Some("emoji.name_taken")), "{j}");
    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "name": "Hello world" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("emoji.name_invalid")), "{j}");
    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "name": "hello" })).await;
    assert_eq!((s, j["name"].as_str()), (StatusCode::OK, Some("hello")), "{j}");

    // Public bytes, no token.
    let resp = node.get(&format!("/api/v1/emojis/{id}/image")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/webp");
    assert_eq!(resp.headers()["cross-origin-resource-policy"], "cross-origin");

    let (s, _) = node.delete(&format!("{base}/{id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(node.state.storage.read(id).await.unwrap().is_none());
    assert_eq!(node.get(&format!("/api/v1/emojis/{id}/image")).await.status(), StatusCode::NOT_FOUND);
    let (s, _) = node.req(Method::GET, base, None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn personal_sounds_with_emojis_limits_and_public_audio() {
    let node = test_node_with(DOMAIN, |c| c.sounds_max_personal = 1).await;
    // The first account is a node admin, unlimited by entitlements: limits are checked on a normal user.
    node.register("admin").await;
    let alice = node.register("alice").await;
    let base = "/api/v1/users/me/sounds";
    let (s, list) = node.get_auth(base, &alice.token).await;
    assert_eq!(
        (s, list["max_personal"].as_u64(), list["max_duration_ms"].as_i64()),
        (StatusCode::OK, Some(1), Some(5000))
    );
    let (s, j) = clip(&node, base, &alice.token, "Fanfare", Some("<script>")).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("soundboard.emoji_invalid")), "{j}");
    let (s, sound) = clip(&node, base, &alice.token, "Fanfare", Some("%F0%9F%8E%BA")).await;
    assert_eq!(s, StatusCode::CREATED, "{sound}");
    assert_eq!((sound["name"].as_str(), sound["emoji"].as_str()), (Some("Fanfare"), Some("🎺")));
    let (s, j) = clip(&node, base, &alice.token, "Second", None).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("soundboard.limit")), "{j}");

    let id = sound["id"].as_str().unwrap();
    let token = format!("<:pog:{FOREIGN_ID}@b.example>");
    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "emoji": token })).await;
    assert_eq!((s, j["emoji"].as_str()), (StatusCode::OK, Some(token.as_str())), "{j}");
    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "name": "Fanfare" })).await;
    assert_eq!(
        (s, j["name"].as_str(), j["emoji"].as_str()),
        (StatusCode::OK, Some("Fanfare"), Some(token.as_str())),
        "{j}"
    );
    let (s, j) = node.patch(&format!("{base}/{id}"), &alice.token, json!({ "emoji": null })).await;
    assert_eq!((s, j["emoji"].clone()), (StatusCode::OK, Value::Null), "{j}");

    let resp = node.get(&format!("/api/v1/sounds/{id}/audio")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "audio/ogg");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
    assert_eq!(body_bytes(resp).await.to_vec(), vec![9u8; 512]);
    let (s, _) = node.delete(&format!("{base}/{id}"), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(node.get(&format!("/api/v1/sounds/{id}/audio")).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn room_clips_carry_an_emoji() {
    let Some(r) = rooms(|_| {}).await else { return };
    let base = format!("/api/v1/rooms/{}/soundboard", r.other);
    let (s, sound) = clip(&r.node, &base, &r.alice.token, "Horn", Some("%F0%9F%93%A3")).await;
    assert_eq!((s, sound["emoji"].as_str()), (StatusCode::CREATED, Some("📣")), "{sound}");
    let id = sound["id"].as_str().unwrap();
    let local = format!("<:local:{}>", r.local_id);
    let (s, j) = r.node.patch(&format!("{base}/{id}"), &r.bob.token, json!({ "emoji": local })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("soundboard.manage_forbidden")), "{j}");
    let (s, j) = r.node.patch(&format!("{base}/{id}"), &r.alice.token, json!({ "emoji": local })).await;
    assert_eq!((s, j["emoji"].as_str()), (StatusCode::OK, Some(local.as_str())), "{j}");
    let (s, j) = r.node.patch(&format!("{base}/{id}"), &r.alice.token, json!({ "emoji": ":local:" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("soundboard.emoji_invalid")), "{j}");
    let (_, list) = r.node.get_auth(&base, &r.bob.token).await;
    assert_eq!(list[0]["emoji"].as_str(), Some(local.as_str()));
    // The public route serves room clips too.
    assert_eq!(r.node.get(&format!("/api/v1/sounds/{id}/audio")).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn external_emojis_need_the_permission_in_room_channels() {
    let Some(r) = rooms(|_| {}).await else { return };
    let image = png().unwrap();
    let (s, personal) = emoji(&r.node, "/api/v1/users/me/emojis", &r.bob.token, "mine", &image).await;
    assert_eq!(s, StatusCode::CREATED, "{personal}");
    let path = r.messages();
    let text = |body: String| json!({ "content": { "type": "text", "body": body } });
    let foreign_room = format!("hi <:own:{}>", r.own_id);
    let personal_token = format!("<:mine:{}>", personal["id"].as_str().unwrap());
    let remote = format!("<:far:{FOREIGN_ID}@b.example>");
    let own_room = format!("<:local:{}> and <:local:{}@{DOMAIN}>", r.local_id, r.local_id);

    // Granted by default (DEFAULT_EVERYONE).
    for body in [&foreign_room, &personal_token, &remote] {
        let (s, j) = r.node.post(&path, &r.bob.token, text(body.clone())).await;
        assert_eq!(s, StatusCode::CREATED, "{body}: {j}");
    }
    r.deny_external().await;
    for body in [&foreign_room, &personal_token, &remote] {
        let (s, j) = r.node.post(&path, &r.bob.token, text(body.clone())).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("emoji.external_forbidden")), "{body}: {j}");
    }
    // The room's own emojis, by token or by name, and malformed tokens (plain text) stay fine.
    for body in [own_room.clone(), ":own: :local:".into(), format!("<:own:{}@evil.example/x>", r.own_id)] {
        let (s, j) = r.node.post(&path, &r.bob.token, text(body.clone())).await;
        assert_eq!(s, StatusCode::CREATED, "{body}: {j}");
    }
    // The owner holds every permission.
    let (s, j) = r.node.post(&path, &r.alice.token, text(foreign_room.clone())).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Edits are checked like new messages.
    let (_, msg) = r.node.post(&path, &r.bob.token, text("plain".into())).await;
    let mid = msg["id"].as_str().unwrap();
    let (s, j) = r
        .node
        .patch(&format!("{path}/{mid}"), &r.bob.token, json!({ "content": { "type": "text", "body": remote } }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("emoji.external_forbidden")), "{j}");

    // Reactions: tokens are validated by structure and checked like bodies.
    let react = |emoji: &str| format!("{path}/{mid}/reactions/{}", urlencoding(emoji));
    let (s, j) = r.node.put(&react(&remote), &r.bob.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("emoji.external_forbidden")), "{j}");
    let (s, j) = r.node.put(&react(&format!("<:local:{}>", r.local_id)), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.put(&react("👍🏽"), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.put(&react(":a_custom_emoji_with_a_long_name:"), &r.bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.node.put(&react("<:x:nope@b.example>"), &r.bob.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("reaction.invalid")), "{j}");
    let (s, j) = r.node.put(&react(&remote), &r.alice.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "owner: {j}");
    let emojis: Vec<&str> = j["reactions"].as_array().unwrap().iter().map(|x| x["emoji"].as_str().unwrap()).collect();
    assert!(emojis.contains(&remote.as_str()), "{emojis:?}");
}

/// Percent-encodes a path segment.
fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[tokio::test]
async fn playing_external_clips_needs_use_external_sounds() {
    let Some(r) = rooms(|_| {}).await else { return };
    let own =
        clip(&r.node, &format!("/api/v1/rooms/{}/soundboard", r.other), &r.alice.token, "Horn", Some("%F0%9F%93%A3"))
            .await
            .1;
    let foreign = clip(&r.node, &format!("/api/v1/rooms/{}/soundboard", r.home), &r.alice.token, "Alien", None).await.1;
    let personal = clip(&r.node, "/api/v1/users/me/sounds", &r.bob.token, "Mine", Some("%F0%9F%8E%BA")).await.1;
    let play = format!("/api/v1/rooms/{}/channels/{}/soundboard/play", r.other, r.voice);
    let id = |v: &Value| v["id"].as_str().unwrap().to_string();

    let (s, j) = r.node.post(&play, &r.bob.token, json!({ "sound_id": id(&own) })).await;
    assert_eq!((s, j["external"].as_bool(), j["emoji"].as_str()), (StatusCode::OK, Some(false), Some("📣")), "{j}");
    let (s, j) = r.node.post(&play, &r.bob.token, json!({ "sound_id": id(&personal) })).await;
    assert_eq!((s, j["external"].as_bool(), j["emoji"].as_str()), (StatusCode::OK, Some(true), Some("🎺")), "{j}");

    r.deny_external().await;
    let (s, j) = r.node.post(&play, &r.bob.token, json!({ "sound_id": id(&own) })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    for body in [
        json!({ "sound_id": id(&foreign) }),
        json!({ "sound_id": id(&personal) }),
        json!({ "sound_id": FOREIGN_ID, "host": "b.example" }),
        json!({ "sound_id": id(&own), "host": "b.example" }),
    ] {
        let (s, j) = r.node.post(&play, &r.bob.token, body.clone()).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, Some("soundboard.external_forbidden")), "{body}: {j}");
    }
    let (s, j) = r.node.post(&play, &r.bob.token, json!({ "sound_id": id(&own), "host": "evil/x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("soundboard.host_invalid")), "{j}");
    let (s, j) = r.node.post(&play, &r.bob.token, json!({ "sound_id": id(&own), "host": DOMAIN })).await;
    assert_eq!(s, StatusCode::OK, "own domain = local: {j}");
    let text_play = format!("/api/v1/rooms/{}/channels/{}/soundboard/play", r.other, r.text);
    let (s, j) = r.node.post(&text_play, &r.bob.token, json!({ "sound_id": id(&own) })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("voice.not_voice_channel")), "{j}");
}

#[tokio::test]
async fn plaintext_attachment_spoilers_and_deleted_reply_originals() {
    let Some(r) = rooms(|_| {}).await else { return };
    let uploads = format!("/api/v1/rooms/{}/channels/{}/uploads", r.other, r.text);
    let mut ids = Vec::new();
    for name in ["a.txt", "b.txt"] {
        let (s, j) = upload(
            &r.node,
            &uploads,
            &r.bob.token,
            &[("content-type", "text/plain"), ("tavrn-file-name", name)],
            b"hello".to_vec(),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        ids.push(j["id"].as_str().unwrap().to_string());
    }
    let path = r.messages();
    let (s, j) = r
        .node
        .post(
            &path,
            &r.bob.token,
            json!({ "content": { "type": "text", "body": "x" }, "attachments": [ids[0]], "spoilers": [ids[1]] }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, Some("message.spoiler_invalid")), "{j}");
    let (s, msg) = r
        .node
        .post(
            &path,
            &r.bob.token,
            json!({ "content": { "type": "text", "body": "x" }, "attachments": ids, "spoilers": [ids[1]] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let flags: Vec<(String, bool)> = msg["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["id"].as_str().unwrap().to_string(), a["spoiler"].as_bool().unwrap_or(false)))
        .collect();
    assert!(flags.contains(&(ids[0].clone(), false)) && flags.contains(&(ids[1].clone(), true)), "{flags:?}");

    // Replies keep the reference; a deleted original is marked, never copied.
    let original = msg["id"].as_str().unwrap();
    let (s, reply) = r
        .node
        .post(&path, &r.alice.token, json!({ "content": { "type": "text", "body": "re" }, "reply_to_id": original }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{reply}");
    assert!(reply.get("reply_deleted").is_none(), "{reply}");
    let (s, _) = r.node.delete(&format!("{path}/{original}"), &r.bob.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = r.node.get_auth(&path, &r.alice.token).await;
    let found = list.as_array().unwrap().iter().find(|m| m["id"] == reply["id"]).unwrap().clone();
    assert_eq!(
        (found["reply_to_id"].as_str(), found["reply_deleted"].as_bool()),
        (Some(original), Some(true)),
        "{found}"
    );
    assert!(!found.to_string().contains("\"x\""), "no copy of the original: {found}");
}

#[tokio::test]
async fn old_rooms_get_the_external_bits_once() {
    let node = test_node_with(DOMAIN, |_| {}).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Alt").await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bits = (p::USE_EXTERNAL_EMOJIS | p::USE_EXTERNAL_SOUNDS) as i64;
    let read = || async {
        sqlx::query_scalar::<_, i64>("SELECT permissions FROM roles WHERE id = $1")
            .bind(&everyone)
            .fetch_one(&node.state.db)
            .await
            .unwrap()
    };
    // A room from before the bits existed: they are missing and the marker is not set yet.
    let before = read().await;
    sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
        .bind(before & !bits)
        .bind(&everyone)
        .execute(&node.state.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::EXTERNAL_EMOJI_MARKER)
        .execute(&node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.external_emoji_roles, 1);
    assert_eq!(read().await & bits, bits);
    // An owner who removes them later keeps that choice across restarts.
    sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
        .bind(before & !bits)
        .bind(&everyone)
        .execute(&node.state.db)
        .await
        .unwrap();
    assert_eq!(tavrn_node::fixups::run(&node.state.db).await.unwrap(), Default::default());
    assert_eq!(read().await & bits, 0);
}

#[tokio::test]
async fn the_orphan_sweep_keeps_personal_emojis_clips_and_still_variants() {
    let Some(r) = rooms(|_| {}).await else { return };
    let image = png().unwrap();
    let (_, personal) = emoji(&r.node, "/api/v1/users/me/emojis", &r.bob.token, "mine", &image).await;
    let (_, sound) = clip(&r.node, "/api/v1/users/me/sounds", &r.bob.token, "Mine", None).await;
    // An animated room emoji has a second file (the still variant) that no `id` column names.
    sqlx::query("UPDATE emojis SET still_id = $1, animated = 1 WHERE id = $2")
        .bind(&r.own_id)
        .bind(&r.local_id)
        .execute(&r.node.state.db)
        .await
        .unwrap();
    let later = chrono::Utc::now() + chrono::Duration::hours(25);
    let report = tavrn_node::housekeeping::sweep_orphans(&r.node.state, later).await.unwrap();
    assert_eq!(report.files, 0, "{report:?}");
    for id in [personal["id"].as_str().unwrap(), sound["id"].as_str().unwrap(), &r.own_id, &r.local_id] {
        assert!(r.node.state.storage.read(id).await.unwrap().is_some(), "{id}");
    }
}
