// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Files channels for bots (protocol/FILES.md §3 "Bots", APPLICATIONS.md §2.4–§2.5): reads under `messages:read`,
//! writes under `messages:write` with the channel's `attach_files`, others' entries only with `manage_files`
//! (`rooms:manage`), the storage backend closed whatever the scopes, "no bots" zones, the events and the rate limits,
//! and an encrypted files channel the bot writes to as a member of its MLS group.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{
    Session, TestNode,
    e2ee::{Dev, qualified, unb64},
    test_node, test_node_with,
};
use futures::StreamExt;
use serde_json::{Value, json};
use tavrn_crypto::MasterSecret;
use tavrn_node::permissions as p;

const D: &str = "t.local";

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

/// A bot with one token of the given scopes.
struct Bot {
    app_id: String,
    user_id: String,
    username: String,
    secret: String,
    device_id: String,
}

impl Bot {
    fn reference(&self) -> String {
        format!("{D}/{}", self.app_id)
    }
    fn session(&self) -> Session {
        Session {
            token: self.secret.clone(),
            refresh: String::new(),
            user_id: self.user_id.clone(),
            username: self.username.clone(),
            device_id: self.device_id.clone(),
            totp_secret: Vec::new(),
            recovery_codes: Vec::new(),
        }
    }
}

/// A public application that may ask for `attach_files`, `manage_files` and `manage_channels`, and a token of `scopes`.
async fn bot(node: &TestNode, owner: &Session, name: &str, scopes: &[&str]) -> Bot {
    let requested = mask(&[p::SEND_MESSAGES, p::ATTACH_FILES, p::MANAGE_FILES, p::MANAGE_CHANNELS]);
    let (s, app) = node
        .post(
            "/api/v1/applications",
            &owner.token,
            json!({ "name": name, "public": true, "requested_permissions": requested }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (s, t) = node
        .post(
            &format!("/api/v1/applications/{app_id}/tokens"),
            &owner.token,
            json!({ "name": "main", "scopes": scopes }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
        device_id: t["token"]["device_id"].as_str().unwrap().into(),
    }
}

/// Installs the bot with a managed role of `perms` (empty: no role, the bot has `@everyone`'s permissions).
async fn install(node: &TestNode, installer: &str, room_id: &str, b: &Bot, perms: &[u64]) {
    let body = if perms.is_empty() {
        json!({ "application": b.reference() })
    } else {
        json!({ "application": b.reference(), "permissions": mask(perms) })
    };
    let (s, j) = node.post(&format!("/api/v1/rooms/{room_id}/applications"), installer, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

async fn join(node: &TestNode, owner: &str, room_id: &str, token: &str) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

/// A room of Alice with an unencrypted files channel and Bob as a member.
struct Room {
    node: TestNode,
    alice: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

impl Room {
    fn base(&self) -> String {
        base(&self.room_id, &self.channel)
    }

    async fn up(&self, token: &str, name: &str, parent: Option<&str>, data: &[u8]) -> (StatusCode, Value) {
        upload(&self.node, &self.base(), token, name, parent, data).await
    }

    async fn folder(&self, token: &str, parent: Option<&str>, name: &str) -> (StatusCode, Value) {
        self.node.post(&format!("{}/folders", self.base()), token, json!({ "parent_id": parent, "name": name })).await
    }
}

fn base(room_id: &str, channel: &str) -> String {
    format!("/api/v1/rooms/{room_id}/channels/{channel}/files")
}

async fn upload(
    node: &TestNode,
    base: &str,
    token: &str,
    name: &str,
    parent: Option<&str>,
    data: &[u8],
) -> (StatusCode, Value) {
    let encoded = tavrn_node::files::sigv4::uri_encode(name, false);
    let mut headers = vec![("content-type", "text/plain"), ("tavrn-file-name", encoded.as_str())];
    if let Some(p) = parent {
        headers.push(("tavrn-parent", p));
    }
    let (s, _, body) = node.raw(Method::POST, &format!("{base}/upload"), token, &headers, data.to_vec()).await;
    (s, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn download(node: &TestNode, base: &str, token: &str, entry: &str) -> (StatusCode, Vec<u8>) {
    let (s, _, b) = node.raw(Method::GET, &format!("{base}/{entry}/download"), token, &[], Vec::new()).await;
    (s, b.to_vec())
}

async fn files_channel(node: &TestNode, token: &str, room_id: &str, name: &str, encrypted: bool) -> String {
    let (s, ch) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            token,
            json!({ "kind": "files", "name": name, "encrypted": encrypted }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{ch}");
    id(&ch)
}

async fn room_with(tweak: impl FnOnce(&mut tavrn_node::config::Config)) -> Room {
    let node = test_node_with(D, tweak).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Room").await;
    let room_id = id(&room);
    let channel = files_channel(&node, &alice.token, &room_id, "Shared", false).await;
    join(&node, &alice.token, &room_id, &bob.token).await;
    Room { node, alice, bob, room_id, channel }
}

async fn room() -> Room {
    room_with(|_| {}).await
}

// ---------------------------------------------------------------- scopes

#[tokio::test]
async fn bots_read_with_messages_read_and_write_their_own_entries_with_messages_write() {
    let r = room().await;
    let (s, docs) = r.folder(&r.alice.token, None, "Docs").await;
    assert_eq!(s, StatusCode::CREATED, "{docs}");
    let (s, notes) = r.up(&r.alice.token, "notes.txt", Some(&id(&docs)), b"alice's notes").await;
    assert_eq!(s, StatusCode::CREATED, "{notes}");

    let reader = bot(&r.node, &r.alice, "Reader", &["messages:read"]).await;
    let writer = bot(&r.node, &r.alice, "Writer", &["messages:read", "messages:write"]).await;
    let blind = bot(&r.node, &r.alice, "Blind", &["messages:write"]).await;
    for b in [&reader, &writer, &blind] {
        install(&r.node, &r.alice.token, &r.room_id, b, &[]).await;
    }
    let base = r.base();

    // messages:read: listing, entry, download, usage, mine.
    let (s, top) = r.node.get_auth(&base, &reader.secret).await;
    assert_eq!(s, StatusCode::OK, "{top}");
    assert_eq!(top["entries"][0]["name"], "Docs");
    let (s, inside) = r.node.get_auth(&format!("{base}?parent={}", id(&docs)), &reader.secret).await;
    assert_eq!((s, inside["entries"][0]["name"].as_str()), (StatusCode::OK, Some("notes.txt")), "{inside}");
    let (s, found) = r.node.get_auth(&format!("{base}?q=notes"), &reader.secret).await;
    assert_eq!((s, found["entries"].as_array().map(Vec::len)), (StatusCode::OK, Some(1)), "{found}");
    let (s, entry) = r.node.get_auth(&format!("{base}/{}", id(&notes)), &reader.secret).await;
    assert_eq!((s, entry["path"].as_array().map(Vec::len)), (StatusCode::OK, Some(2)), "{entry}");
    assert_eq!(
        download(&r.node, &base, &reader.secret, &id(&notes)).await,
        (StatusCode::OK, b"alice's notes".to_vec())
    );
    let (s, usage) = r.node.get_auth(&format!("{base}/usage"), &reader.secret).await;
    assert_eq!(
        (s, usage["files"].as_i64(), usage["can_upload"].as_bool()),
        (StatusCode::OK, Some(1), Some(false)),
        "{usage}"
    );
    let (s, mine) = r.node.get_auth(&format!("{base}/mine"), &reader.secret).await;
    assert_eq!((s, mine["files"].as_i64()), (StatusCode::OK, Some(0)), "{mine}");
    // Thumbnails and records exist only in encrypted channels: the route answers, the channel refuses.
    let (s, j) = r.node.get_auth(&format!("{base}/records"), &reader.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "files.not_encrypted"));
    let (s, j) = r.node.get_auth(&format!("{base}/{}/thumbnail", id(&notes)), &reader.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "files.not_encrypted"));

    // Without messages:write nothing changes.
    let (s, j) = r.up(&reader.secret, "x.txt", None, b"x").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");
    assert_eq!(j["meta"]["scope"], "messages:write");
    let (s, j) = r.folder(&reader.secret, None, "Bot").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");
    let (s, j) = r.node.patch(&format!("{base}/{}", id(&notes)), &reader.secret, json!({ "name": "y.txt" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&notes)), &reader.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{j}");
    let (s, _, b) =
        r.node.raw(Method::PUT, &format!("{base}/{}/thumbnail", id(&notes)), &reader.secret, &[], b"t".to_vec()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{}", String::from_utf8_lossy(&b));
    // Without messages:read nothing is listed.
    for path in [
        base.clone(),
        format!("{base}/{}", id(&notes)),
        format!("{base}/{}/download", id(&notes)),
        format!("{base}/usage"),
        format!("{base}/mine"),
    ] {
        let (s, j) = r.node.get_auth(&path, &blind.secret).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{path}: {j}");
        assert_eq!(j["meta"]["scope"], "messages:read");
    }

    // messages:write: folders and uploads of its own, renamed, moved and deleted.
    let (s, reports) = r.folder(&writer.secret, None, "Reports").await;
    assert_eq!(s, StatusCode::CREATED, "{reports}");
    let (s, build) = r.up(&writer.secret, "build-128.txt", Some(&id(&reports)), b"42 tests passed").await;
    assert_eq!(s, StatusCode::CREATED, "{build}");
    assert_eq!(build["created_by"], writer.user_id.as_str());
    assert_eq!(download(&r.node, &base, &r.bob.token, &id(&build)).await.1, b"42 tests passed");
    let (s, j) =
        r.node.patch(&format!("{base}/{}", id(&build)), &writer.secret, json!({ "name": "build-129.txt" })).await;
    assert_eq!((s, j["name"].as_str()), (StatusCode::OK, Some("build-129.txt")), "{j}");
    let (s, j) = r.node.patch(&format!("{base}/{}", id(&build)), &writer.secret, json!({ "parent_id": null })).await;
    assert_eq!((s, &j["parent_id"]), (StatusCode::OK, &Value::Null), "{j}");
    let (s, j) = r.node.get_auth(&format!("{base}/mine"), &writer.secret).await;
    assert_eq!((s, j["files"].as_i64(), j["folders"].as_i64()), (StatusCode::OK, Some(1), Some(1)), "{j}");
    let (s, j) = r.node.get_auth(&format!("{base}/usage"), &writer.secret).await;
    assert_eq!((j["can_upload"].as_bool(), j["can_manage"].as_bool()), (Some(true), Some(false)), "{s} {j}");

    // Others' entries need manage_files: no rename, move or delete, also not of a folder holding them.
    let (s, j) = r.node.patch(&format!("{base}/{}", id(&notes)), &writer.secret, json!({ "name": "mine.txt" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.manage_forbidden"), "{j}");
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&notes)), &writer.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.manage_forbidden"), "{j}");
    let (_, j) =
        r.node.patch(&format!("{base}/{}", id(&notes)), &r.alice.token, json!({ "parent_id": id(&reports) })).await;
    assert_eq!(j["parent_id"], id(&reports).as_str(), "{j}");
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&reports)), &writer.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.manage_forbidden"), "{j}");
    // Its own file goes.
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&build)), &writer.secret).await;
    assert_eq!((s, j["files"].as_u64()), (StatusCode::OK, Some(1)), "{j}");

    // The channel's attach_files decides as for members.
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            &r.alice.token,
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member",
                    "subject_id": writer.user_id, "allow": "0", "deny": p::ATTACH_FILES.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = r.up(&writer.secret, "late.txt", None, b"late").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.upload_forbidden"), "{j}");
    let (s, j) = r.folder(&writer.secret, None, "Late").await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.upload_forbidden"), "{j}");
}

#[tokio::test]
async fn others_entries_need_manage_files_and_the_backend_stays_closed() {
    let r = room().await;
    let (_, docs) = r.folder(&r.alice.token, None, "Docs").await;
    let (_, notes) = r.up(&r.bob.token, "notes.txt", Some(&id(&docs)), b"bob's notes").await;
    // Every scope and a role with manage_files and manage_channels.
    let admin = bot(&r.node, &r.alice, "Janitor", &["messages:read", "messages:write", "rooms:manage"]).await;
    install(
        &r.node,
        &r.alice.token,
        &r.room_id,
        &admin,
        &[p::SEND_MESSAGES, p::ATTACH_FILES, p::MANAGE_FILES, p::MANAGE_CHANNELS],
    )
    .await;
    // The same role without rooms:manage: manage_files is masked away.
    let plain = bot(&r.node, &r.alice, "Helper", &["messages:read", "messages:write"]).await;
    install(
        &r.node,
        &r.alice.token,
        &r.room_id,
        &plain,
        &[p::SEND_MESSAGES, p::ATTACH_FILES, p::MANAGE_FILES, p::MANAGE_CHANNELS],
    )
    .await;
    let base = r.base();

    let (s, j) = r.node.delete(&format!("{base}/{}", id(&notes)), &plain.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "files.manage_forbidden"), "{j}");
    let (_, usage) = r.node.get_auth(&format!("{base}/usage"), &plain.secret).await;
    assert_eq!(usage["can_manage"], false, "{usage}");

    // The store's configuration and credentials stay out of reach whatever the scopes and roles.
    let (_, usage) = r.node.get_auth(&format!("{base}/usage"), &admin.secret).await;
    assert_eq!(
        (
            usage["can_manage"].as_bool(),
            usage["can_configure"].as_bool(),
            &usage["backend_host"],
            &usage["backend_prefix"]
        ),
        (Some(true), Some(false), &Value::Null, &Value::Null),
        "{usage}"
    );
    let (_, theirs) = r.node.get_auth(&format!("{base}/usage"), &r.alice.token).await;
    assert_eq!(
        (theirs["can_configure"].as_bool(), theirs["backend_host"].as_str()),
        (Some(true), Some("")),
        "{theirs}"
    );
    let (s, j) = r.node.get_auth(&format!("{base}/backend"), &admin.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{j}");
    let (s, j) = r.node.put(&format!("{base}/backend"), &admin.secret, json!({ "kind": "internal" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{j}");
    let (s, j) = r.node.post(&format!("{base}/backend/test"), &admin.secret, json!({ "kind": "internal" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{j}");

    // rooms:manage with manage_files: others' entries, the folder that holds them too.
    let (s, j) =
        r.node.patch(&format!("{base}/{}", id(&notes)), &admin.secret, json!({ "name": "archived.txt" })).await;
    assert_eq!((s, j["name"].as_str()), (StatusCode::OK, Some("archived.txt")), "{j}");
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&docs)), &admin.secret).await;
    assert_eq!((s, j["files"].as_u64(), j["folders"].as_u64()), (StatusCode::OK, Some(1), Some(1)), "{j}");
    let actor: String =
        sqlx::query_scalar("SELECT actor_id FROM audit_log WHERE action = 'files.delete' AND target = $1")
            .bind(id(&docs))
            .fetch_one(&r.node.state.db)
            .await
            .unwrap();
    assert_eq!(actor, admin.user_id, "the deletion is audited with the bot as actor");
}

// ---------------------------------------------------------------- "no bots"

#[tokio::test]
async fn no_bots_zones_and_closed_encrypted_channels_refuse_bots() {
    let r = room().await;
    let (_, notes) = r.up(&r.alice.token, "notes.txt", None, b"notes").await;
    let b = bot(&r.node, &r.alice, "Reader", &["messages:read", "messages:write"]).await;
    install(&r.node, &r.alice.token, &r.room_id, &b, &[]).await;
    let base = r.base();
    assert_eq!(r.node.get_auth(&base, &b.secret).await.0, StatusCode::OK);

    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{}", r.room_id, r.channel),
            &r.alice.token,
            json!({ "no_bots": true }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let refused = |s: StatusCode, j: &Value| (s, code(j).to_string());
    let view = (StatusCode::FORBIDDEN, "channel.view_forbidden".to_string());
    let (s, j) = r.node.get_auth(&base, &b.secret).await;
    assert_eq!(refused(s, &j), view, "{j}");
    let (s, j) = r.node.get_auth(&format!("{base}/{}/download", id(&notes)), &b.secret).await;
    assert_eq!(refused(s, &j), view, "{j}");
    let (s, j) = r.up(&b.secret, "x.txt", None, b"x").await;
    assert_eq!(refused(s, &j), view, "{j}");
    let (s, j) = r.folder(&b.secret, None, "X").await;
    assert_eq!(refused(s, &j), view, "{j}");
    let (s, j) = r.node.delete(&format!("{base}/{}", id(&notes)), &b.secret).await;
    assert_eq!(refused(s, &j), view, "{j}");
    // Members are not affected.
    assert_eq!(r.node.get_auth(&base, &r.bob.token).await.0, StatusCode::OK);

    // An encrypted files channel of a per_channel room is closed to bots until it allows them.
    let vault = files_channel(&r.node, &r.alice.token, &r.room_id, "Vault", true).await;
    let (s, j) = r.node.get_auth(&base_of(&r, &vault), &b.secret).await;
    assert_eq!(refused(s, &j), view, "{j}");
    let (s, j) = r
        .node
        .patch(
            &format!("/api/v1/rooms/{}/channels/{vault}", r.room_id),
            &r.alice.token,
            json!({ "bots_allowed": true }),
        )
        .await;
    assert_eq!((s, j["no_bots_effective"].as_bool()), (StatusCode::OK, Some(false)), "{j}");
    let (s, j) = r.node.get_auth(&base_of(&r, &vault), &b.secret).await;
    assert_eq!((s, j["entries"].as_array().map(Vec::len)), (StatusCode::OK, Some(0)), "{j}");
}

fn base_of(r: &Room, channel: &str) -> String {
    base(&r.room_id, channel)
}

// ---------------------------------------------------------------- events

async fn hello(url: &str, token: &str) -> Socket {
    crate::suite::ws_flow::hello(url, token).await
}

/// The data of the next event of `kind` within `ms`, skipping everything else.
async fn next_event(ws: &mut Socket, kind: &str, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + common::timeout(Duration::from_millis(ms));
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let Ok(text) = msg.to_text() else { continue };
                let Ok(v) = serde_json::from_str::<Value>(text) else { continue };
                if v["op"] == "event" && v["type"] == kind {
                    return Some(v["data"].clone());
                }
            }
            _ => return None,
        }
    }
}

#[tokio::test]
async fn files_events_reach_bots_with_messages_read_in_channels_they_may_view() {
    let r = room().await;
    let reader = bot(&r.node, &r.alice, "Reader", &["messages:read"]).await;
    let quiet = bot(&r.node, &r.alice, "Quiet", &["members:read", "messages:write"]).await;
    let shut = bot(&r.node, &r.alice, "Shut", &["messages:read"]).await;
    for b in [&reader, &quiet, &shut] {
        install(&r.node, &r.alice.token, &r.room_id, b, &[]).await;
    }
    // One bot may not view the files channel (a member override).
    let (s, j) = r
        .node
        .put(
            &format!("/api/v1/rooms/{}/overrides", r.room_id),
            &r.alice.token,
            json!({ "target_type": "channel", "target_id": r.channel, "subject_type": "member",
                    "subject_id": shut.user_id, "allow": "0", "deny": p::VIEW_CHANNEL.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let url = crate::suite::ws_flow::serve(&r.node).await;
    let mut ws_reader = hello(&url, &reader.secret).await;
    let mut ws_quiet = hello(&url, &quiet.secret).await;
    let mut ws_shut = hello(&url, &shut.secret).await;

    let (s, j) = r.folder(&r.alice.token, None, "Docs").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let ev = next_event(&mut ws_reader, "files.update", 5000).await.expect("files.update for the reader");
    assert_eq!((ev["channel_id"].as_str(), &ev["parent_id"]), (Some(r.channel.as_str()), &Value::Null), "{ev}");
    assert!(next_event(&mut ws_quiet, "files.update", 300).await.is_none(), "no messages:read, no files events");
    assert!(next_event(&mut ws_shut, "files.update", 300).await.is_none(), "cannot view the channel, no files events");

    let (s, j) = r.node.put(&format!("{}/backend", r.base()), &r.alice.token, json!({ "kind": "internal" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let ev = next_event(&mut ws_reader, "files.backend", 5000).await.expect("files.backend for the reader");
    assert_eq!(
        (ev["channel_id"].as_str(), ev["backend"].as_str()),
        (Some(r.channel.as_str()), Some("internal")),
        "{ev}"
    );
    assert!(ev.get("url").is_none() && ev.get("username").is_none(), "no store details: {ev}");
    assert!(next_event(&mut ws_quiet, "files.backend", 300).await.is_none());
}

// ---------------------------------------------------------------- limits

#[tokio::test]
async fn bot_rate_and_upload_limits_apply() {
    let r = room_with(|c| {
        c.app_rate_requests = 15;
        c.upload_max_bytes = 1024;
    })
    .await;
    let b = bot(&r.node, &r.alice, "Busy", &["messages:read", "messages:write"]).await;
    install(&r.node, &r.alice.token, &r.room_id, &b, &[]).await;
    // The bot account's upload size (upload.max_bytes) as for members.
    let (s, j) = r.up(&b.secret, "big.bin", None, &vec![7u8; 2048]).await;
    assert_eq!((s, code(&j)), (StatusCode::PAYLOAD_TOO_LARGE, "upload.too_large"), "{j}");
    let (s, j) = r.up(&b.secret, "small.txt", None, b"fits").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // The application's request budget (TAVRN_APP_RATE_REQUESTS) covers the files routes.
    let mut limited = None;
    for _ in 0..20 {
        let (s, j) = r.node.get_auth(&r.base(), &b.secret).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(j);
            break;
        }
        assert_eq!(s, StatusCode::OK, "{j}");
    }
    assert!(limited.is_some(), "the application's request budget runs out");
    // Members are not affected.
    assert_eq!(r.node.get_auth(&r.base(), &r.bob.token).await.0, StatusCode::OK);
}

// ---------------------------------------------------------------- encrypted channels

/// The bot's external join of a channel's group.
async fn external_join(node: &TestNode, dev: &mut Dev, channel: &str) {
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{channel}/mls/group-info"), dev.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let out = dev.client.join_by_external_commit(&qualified(channel), &unb64(&j["group_info"])).unwrap();
    let (s, j) = node.post_commit(dev.token(), channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    dev.client.merge_pending_commit(&qualified(channel)).unwrap();
}

#[tokio::test]
async fn a_bot_writes_and_reads_an_encrypted_files_channel_as_a_group_member() {
    let node = test_node(D).await;
    let mut carol = node.crypto_user("carol").await;
    let room = node.create_room(carol.token(), "Room").await;
    let room_id = id(&room);
    let channel = files_channel(&node, carol.token(), &room_id, "Vault", true).await;
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), carol.token(), json!({ "bots_allowed": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    node.create_group(&mut carol, &channel).await;
    let b = bot(&node, &carol.session, "Archiver", &["messages:read", "messages:write"]).await;
    install(&node, carol.token(), &room_id, &b, &[]).await;
    let master = MasterSecret::generate().unwrap();
    node.put_identity(&b.session(), &master).await;
    let mut dev = node.attest(b.session(), master, 3).await;
    external_join(&node, &mut dev, &channel).await;
    let q = qualified(&channel);
    let files = base(&room_id, &channel);

    // A folder and a file with records under the bot's current epoch; the body is ciphertext the node keeps as it is.
    let folder_id = tavrn_node::util::ulid();
    let record = json!({ "type": "files.entry", "v": 1, "entry": folder_id, "kind": "folder", "name": "Builds" });
    let epoch = dev.client.current_epoch(&q).unwrap() as i64;
    let sealed = dev.client.encrypt_content(&q, &record.to_string()).unwrap();
    let (s, folder) = node
        .post(
            &format!("{files}/folders"),
            dev.token(),
            json!({ "parent_id": null, "id": folder_id, "record": sealed, "record_epoch": epoch }),
        )
        .await;
    assert_eq!((s, folder["name"].as_str()), (StatusCode::CREATED, Some("")), "{folder}");
    // Names are refused in encrypted channels, for bots as for members.
    let (s, j) = node.post(&format!("{files}/folders"), dev.token(), json!({ "name": "Plain" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "files.encrypted"), "{j}");

    let file_id = tavrn_node::util::ulid();
    let record = json!({ "type": "files.entry", "v": 1, "entry": file_id, "kind": "file", "name": "build-128.log",
                         "mime": "text/plain", "size": 3, "key": "k" });
    let sealed = dev.client.encrypt_content(&q, &record.to_string()).unwrap();
    let epoch_s = epoch.to_string();
    let ciphertext = vec![0xA5u8; 19];
    let headers = [
        ("tavrn-entry-id", file_id.as_str()),
        ("tavrn-record", sealed.as_str()),
        ("tavrn-record-epoch", epoch_s.as_str()),
        ("tavrn-parent", folder_id.as_str()),
        ("tavrn-upload-category", "documents"),
    ];
    let (s, _, body) =
        node.raw(Method::POST, &format!("{files}/upload"), dev.token(), &headers, ciphertext.clone()).await;
    assert_eq!(s, StatusCode::CREATED, "{}", String::from_utf8_lossy(&body));
    let (s, _, body) =
        node.raw(Method::PUT, &format!("{files}/{file_id}/thumbnail"), dev.token(), &[], vec![1u8; 32]).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{}", String::from_utf8_lossy(&body));

    // Carol reads the bot's records: the node stored no name.
    node.catch_up(&mut carol, &channel).await;
    let (s, list) = node.get_auth(&format!("{files}?parent={folder_id}"), carol.token()).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let entry = &list["entries"][0];
    assert_eq!((entry["id"].as_str(), entry["name"].as_str()), (Some(file_id.as_str()), Some("")), "{entry}");
    assert_eq!(entry["record_author"], format!("{}@{D}", b.username));
    let bot_key = dev.client.device().public_key();
    let plain = carol
        .client
        .decrypt_content(
            &q,
            entry["record_author"].as_str().unwrap(),
            entry["record_device_id"].as_str().unwrap(),
            entry["record"].as_str().unwrap(),
            Some(&bot_key),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&plain).unwrap()["name"], "build-128.log");
    let names: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_entries WHERE channel_id = $1 AND name <> ''")
        .bind(&channel)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(names, 0, "no plaintext name in the database");

    // The bot reads back: records, ciphertext, thumbnail.
    let (s, records) = node.get_auth(&format!("{files}/records"), dev.token()).await;
    assert_eq!((s, records["entries"].as_array().map(Vec::len)), (StatusCode::OK, Some(2)), "{records}");
    assert_eq!(download(&node, &files, dev.token(), &file_id).await, (StatusCode::OK, ciphertext));
    let (s, _, thumb) =
        node.raw(Method::GET, &format!("{files}/{file_id}/thumbnail"), dev.token(), &[], Vec::new()).await;
    assert_eq!((s, thumb.len()), (StatusCode::OK, 32));
}
