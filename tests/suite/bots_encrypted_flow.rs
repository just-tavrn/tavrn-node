// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Bots, permissions and end-to-end encryption (decided 2026-10-06): the `manage_applications` bit
//! (install, uninstall, command settings, the startup fixup), the room setting `bots_in_encrypted_channels` with the
//! channel setting `bots_allowed` (evaluation, MLS entitlement, `mls.remove_needed`, events, audit), and the
//! security log entries `system.bot_added` / `system.bot_removed`.

use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use common::{
    Session, TestNode,
    e2ee::{Dev, qualified, unb64},
    test_node,
};
use serde_json::{Value, json};
use tavrn_crypto::MasterSecret;
use tavrn_node::{hub::Event, permissions as p};
use tokio::sync::broadcast;

const D: &str = "t.local";

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

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
    fn address(&self) -> String {
        format!("{}@{D}", self.username)
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

async fn token(node: &TestNode, owner: &Session, app_id: &str, scopes: Option<&[&str]>) -> (String, String) {
    let body = match scopes {
        Some(s) => json!({ "name": format!("t{}", tavrn_node::util::ulid()), "scopes": s }),
        None => json!({ "name": format!("t{}", tavrn_node::util::ulid()) }),
    };
    let (s, t) = node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    (t["secret"].as_str().unwrap().into(), t["token"]["device_id"].as_str().unwrap().into())
}

async fn bot(node: &TestNode, owner: &Session, name: &str) -> Bot {
    let body = json!({ "name": name, "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) });
    let (s, app) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (secret, device_id) = token(node, owner, &app_id, None).await;
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret,
        device_id,
    }
}

async fn member(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn give_role(node: &TestNode, owner: &Session, room_id: &str, user_id: &str, name: &str, perms: &[u64]) {
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &owner.token,
            json!({ "name": name, "permissions": mask(perms) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{user_id}"), &owner.token, json!({ "roles": [role["id"]] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn install(node: &TestNode, token: &str, room_id: &str, body: Value) -> (StatusCode, Value) {
    node.post(&format!("/api/v1/rooms/{room_id}/applications"), token, body).await
}

fn installation_path(room_id: &str, b: &Bot) -> String {
    format!("/api/v1/rooms/{room_id}/applications/{}", b.reference().replace('/', "%2F"))
}

async fn my_permissions(node: &TestNode, token: &str, room_id: &str) -> u64 {
    let (s, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), token).await;
    assert_eq!(s, StatusCode::OK, "{room}");
    room["my_permissions"].as_str().unwrap().parse().unwrap()
}

// ---------------------------------------------------------------- manage_applications

#[tokio::test]
async fn manage_applications_replaces_manage_room_for_applications() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let dave = node.register("dave").await;
    let eve = node.register("eve").await;
    let b = bot(&node, &alice, "Helper").await;
    let commands = json!({ "commands": [{ "name": "ping", "description": "Pong" }] });
    let (s, j) = node.put(&format!("/api/v1/applications/{}/commands", b.app_id), &alice.token, commands).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let room = node.plaintext_room(&carol.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    for u in [&bob, &dave, &eve] {
        member(&node, &carol, room_id, u).await;
    }
    give_role(&node, &carol, room_id, &bob.user_id, "Apps", &[p::MANAGE_APPLICATIONS]).await;
    give_role(&node, &carol, room_id, &dave.user_id, "Rooms", &[p::MANAGE_ROOM, p::MANAGE_ROLES]).await;
    let body = |create_role: bool| json!({ "application": b.reference(), "permissions": mask(&[p::SEND_MESSAGES]), "create_role": create_role });
    let list = format!("/api/v1/rooms/{room_id}/applications");
    let settings = format!("/api/v1/rooms/{room_id}/commands");

    // manage_room alone no longer installs (403 with the new code); it still reads the lists.
    let (s, j) = install(&node, &dave.token, room_id, body(false)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    assert_eq!(node.get_auth(&list, &dave.token).await.0, StatusCode::OK);
    assert_eq!(node.get_auth(&settings, &dave.token).await.0, StatusCode::OK);
    // Neither bit: nothing at all.
    for path in [&list, &settings] {
        let (s, j) = node.get_auth(path, &eve.token).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"), "{path}");
    }
    // manage_applications without manage_roles: no managed role, but the installation itself.
    let (s, j) = install(&node, &bob.token, room_id, body(true)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "role.manage_forbidden"));
    let (s, j) = install(&node, &bob.token, room_id, body(false)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["role_id"], Value::Null);
    let (s, j) = node.get_auth(&list, &bob.token).await;
    assert_eq!((s, j.as_array().unwrap().len()), (StatusCode::OK, 1));

    // Command settings: PUT/DELETE need the bit, GET is readable with either.
    let (s, rc) = node.get_auth(&settings, &bob.token).await;
    assert_eq!(s, StatusCode::OK, "{rc}");
    let one = format!("{settings}/{}", rc[0]["commands"][0]["ref"].as_str().unwrap().replace('/', "%2F"));
    let (s, j) = node.put(&one, &dave.token, json!({ "enabled": false })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    let (s, j) = node.delete(&one, &dave.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    let (s, j) = node.put(&one, &bob.token, json!({ "enabled": false })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(node.delete(&one, &bob.token).await.0, StatusCode::NO_CONTENT);

    // Bot tokens: rooms:manage carries the bit into the bot's permissions, but the routes stay closed to bots.
    give_role(&node, &carol, room_id, &b.user_id, "Bot managers", &[p::MANAGE_APPLICATIONS, p::MANAGE_ROOM]).await;
    assert!(p::has(my_permissions(&node, &b.secret, room_id).await, p::MANAGE_APPLICATIONS));
    let (narrow, _) = token(&node, &alice, &b.app_id, Some(&["messages:read", "commands"])).await;
    assert!(!p::has(my_permissions(&node, &narrow, room_id).await, p::MANAGE_APPLICATIONS), "scope cap");
    let other = bot(&node, &alice, "Other").await;
    let (s, j) = install(&node, &b.secret, room_id, json!({ "application": other.reference() })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "bots never install bots");
    for token in [b.secret.as_str(), narrow.as_str()] {
        assert_eq!(node.delete(&installation_path(room_id, &b), token).await.0, StatusCode::FORBIDDEN);
        assert_eq!(node.put(&one, token, json!({ "enabled": false })).await.0, StatusCode::FORBIDDEN);
    }

    // Never on @everyone (management class).
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &carol.token).await;
    let everyone = detail["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{}", everyone.as_str().unwrap()),
            &carol.token,
            json!({ "permissions": mask(&[p::VIEW_CHANNEL, p::MANAGE_APPLICATIONS]) }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "role.everyone_restricted"));

    // manage_room alone cannot uninstall; manage_applications can; the owner always can.
    let (s, j) = node.delete(&installation_path(room_id, &b), &dave.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    assert_eq!(node.delete(&installation_path(room_id, &b), &bob.token).await.0, StatusCode::NO_CONTENT);
    let (s, j) = install(&node, &carol.token, room_id, json!({ "application": other.reference() })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn fixups_grant_manage_applications_and_keep_existing_rooms_allowed_once() {
    let node = test_node(D).await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let dave = node.register("dave").await;
    let room = node.create_room(&carol.token, "Old room").await;
    let room_id = room["id"].as_str().unwrap();
    member(&node, &carol, room_id, &bob).await;
    member(&node, &carol, room_id, &dave).await;
    give_role(&node, &carol, room_id, &bob.user_id, "Managers", &[p::MANAGE_ROOM]).await;
    give_role(&node, &carol, room_id, &dave.user_id, "Mods", &[p::KICK_MEMBERS]).await;
    // A node from before the bit and the setting: the markers are missing, the room has the column default.
    for marker in [tavrn_node::fixups::MANAGE_APPLICATIONS_MARKER, tavrn_node::fixups::BOTS_IN_ENCRYPTED_MARKER] {
        sqlx::query("DELETE FROM node_settings WHERE key = $1").bind(marker).execute(&node.state.db).await.unwrap();
    }
    sqlx::query("UPDATE rooms SET bots_in_encrypted_channels = 'allowed' WHERE id = $1")
        .bind(room_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    assert!(!p::has(my_permissions(&node, &bob.token, room_id).await, p::MANAGE_APPLICATIONS));

    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.manage_applications_roles, 1, "only the role holding manage_room");
    assert_eq!(report.bots_encrypted_rooms, 1);
    assert!(p::has(my_permissions(&node, &bob.token, room_id).await, p::MANAGE_APPLICATIONS));
    assert!(!p::has(my_permissions(&node, &dave.token, room_id).await, p::MANAGE_APPLICATIONS));
    let audits: Vec<String> = sqlx::query_scalar(
        "SELECT meta FROM audit_log WHERE room_id = $1 AND action = 'room.bots_in_encrypted_channels'",
    )
    .bind(room_id)
    .fetch_all(&node.state.db)
    .await
    .unwrap();
    assert_eq!(audits.len(), 1);
    assert!(audits[0].contains("existing_room"), "{audits:?}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &carol.token).await;
    assert_eq!(detail["bots_in_encrypted_channels"], "allowed");
    assert_eq!(detail["channels"].as_array().unwrap().iter().filter(|c| c["no_bots_effective"] == true).count(), 0);

    // Idempotent: a room that narrows the bit afterwards keeps it narrowed.
    sqlx::query("UPDATE roles SET permissions = $1 WHERE name = 'Managers'")
        .bind(p::MANAGE_ROOM as i64)
        .execute(&node.state.db)
        .await
        .unwrap();
    let again = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!((again.manage_applications_roles, again.bots_encrypted_rooms), (0, 0));
    assert!(!p::has(my_permissions(&node, &bob.token, room_id).await, p::MANAGE_APPLICATIONS));
}

// ---------------------------------------------------------------- bots in encrypted channels

/// The room's channel `id` as `user` sees it (None if invisible).
async fn channel_of(node: &TestNode, token: &str, room_id: &str, id: &str) -> Option<Value> {
    let (s, room) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), token).await;
    assert_eq!(s, StatusCode::OK, "{room}");
    room["channels"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned()
}

async fn patch_channel(node: &TestNode, token: &str, room_id: &str, id: &str, body: Value) -> (StatusCode, Value) {
    node.patch(&format!("/api/v1/rooms/{room_id}/channels/{id}"), token, body).await
}

/// The contents of the welcome channel's entries of `kind`, oldest first.
async fn log(node: &TestNode, token: &str, welcome: &str, kind: &str) -> Vec<Value> {
    let (s, msgs) = node.get_auth(&format!("/api/v1/conversations/{welcome}/messages"), token).await;
    assert_eq!(s, StatusCode::OK, "{msgs}");
    let mut list: Vec<Value> =
        msgs.as_array().unwrap().iter().map(|m| m["content"].clone()).filter(|c| c["type"] == kind).collect();
    list.reverse();
    list
}

async fn next_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str, matches: impl Fn(&Value) -> bool) -> Value {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind && matches(&ev.data) {
            return ev.data.clone();
        }
    }
}

/// The bot's external join (`Err` = the node's refusal).
async fn external_join(node: &TestNode, dev: &mut Dev, channel: &str) -> Result<(), (StatusCode, Value)> {
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{channel}/mls/group-info"), dev.token()).await;
    if s != StatusCode::OK {
        return Err((s, j));
    }
    let out = dev.client.join_by_external_commit(&qualified(channel), &unb64(&j["group_info"])).unwrap();
    let (s, j) = node.post_commit(dev.token(), channel, &out).await;
    if s != StatusCode::CREATED {
        dev.client.delete_group(&qualified(channel)).unwrap();
        return Err((s, j));
    }
    dev.client.merge_pending_commit(&qualified(channel)).unwrap();
    Ok(())
}

/// `owner` removes the bot's leaf after a `mls.remove_needed`.
async fn remove_leaf(node: &TestNode, owner: &mut Dev, channel: &str, identity: &str) {
    node.catch_up(owner, channel).await;
    let out = owner.client.remove_members(&qualified(channel), &[identity.to_string()]).unwrap();
    let (s, j) = node.post_commit(owner.token(), channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    owner.client.merge_pending_commit(&qualified(channel)).unwrap();
}

#[tokio::test]
async fn encrypted_channels_of_new_rooms_are_closed_to_bots_until_allowed() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let mut carol = node.crypto_user("carol").await;
    let b = bot(&node, &alice, "Reader").await;
    let room = node.create_room(carol.token(), "Secret room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let welcome = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, second) = node
        .post(&format!("/api/v1/rooms/{room_id}/channels"), carol.token(), json!({ "kind": "text", "name": "council" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{second}");
    let council = second["id"].as_str().unwrap().to_string();
    let (s, plain) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            carol.token(),
            json!({ "kind": "text", "name": "lobby", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{plain}");
    let lobby = plain["id"].as_str().unwrap().to_string();

    // New rooms: per_channel; every encrypted channel is closed to bots, plaintext ones are not.
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), carol.token()).await;
    assert_eq!(detail["bots_in_encrypted_channels"], "per_channel");
    let general = channel_of(&node, carol.token(), &room_id, &channel).await.unwrap();
    assert_eq!((general["no_bots_effective"].as_bool(), general["bots_allowed"].as_bool()), (Some(true), Some(false)));
    assert_eq!(channel_of(&node, carol.token(), &room_id, &lobby).await.unwrap()["no_bots_effective"], false);

    let (s, j) =
        install(&node, carol.token(), &room_id, json!({ "application": b.reference(), "permissions": "0" })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let master = MasterSecret::generate().unwrap();
    node.put_identity(&b.session(), &master).await;
    let mut bot_dev = node.attest(b.session(), master, 3).await;
    let bot_identity = bot_dev.identity();
    // The bot sees only the plaintext channel (and the welcome channel), and reads nothing in the others.
    for c in [&channel, &council] {
        assert!(channel_of(&node, &b.secret, &room_id, c).await.is_none(), "{c} hidden from the bot");
    }
    assert!(channel_of(&node, &b.secret, &room_id, &lobby).await.is_some());
    let (s, j) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), &b.secret).await;
    assert!(s.is_client_error(), "{s} {j}");
    // Install-time joins: neither an external join nor an Add by a member gets the bot in.
    node.create_group(&mut carol, &channel).await;
    node.create_group(&mut carol, &council).await;
    let (s, j) = external_join(&node, &mut bot_dev, &channel).await.unwrap_err();
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"));
    let kps = node.claim(carol.token(), &b.username).await;
    let out = carol.client.add_members(&qualified(&channel), &kps).unwrap();
    let (s, j) = node.post_commit(carol.token(), &channel, &out).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"));
    carol.client.discard_pending_commit(&qualified(&channel)).unwrap();
    node.upload_kps(&bot_dev, 2).await;

    // Attackers: bad values, the welcome channel, a bot holding every management bit of its scopes.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}"), carol.token(), json!({ "bots_in_encrypted_channels": "always" }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.bots_in_encrypted_channels"));
    let (s, j) = patch_channel(&node, carol.token(), &room_id, &welcome, json!({ "bots_allowed": true })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "channel.system_protected"));
    give_role(&node, &carol.session, &room_id, &b.user_id, "Ops", &[p::MANAGE_ROOM, p::MANAGE_CHANNELS]).await;
    let (s, j) = patch_channel(&node, &b.secret, &room_id, &lobby, json!({ "bots_allowed": true })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    let (s, j) = patch_channel(&node, &b.secret, &room_id, &lobby, json!({ "no_bots": false })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    for body in [json!({ "bots_in_encrypted_channels": "allowed" }), json!({ "no_bots": false })] {
        let (s, j) = node.patch(&format!("/api/v1/rooms/{room_id}"), &b.secret, body).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    }

    // The channel setting opens exactly this channel: `channel.update`, audit, the bot joins, the security log.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = patch_channel(&node, carol.token(), &room_id, &channel, json!({ "bots_allowed": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["bots_allowed"].as_bool(), j["no_bots_effective"].as_bool()), (Some(true), Some(false)));
    let update = next_event(&mut rx, "channel.update", |d| d["id"] == channel.as_str()).await;
    assert_eq!(update["no_bots_effective"], false);
    assert!(channel_of(&node, &b.secret, &room_id, &channel).await.is_some());
    assert!(channel_of(&node, &b.secret, &room_id, &council).await.is_none(), "only the allowed channel");
    external_join(&node, &mut bot_dev, &channel).await.unwrap();
    let (s, j) = external_join(&node, &mut bot_dev, &council).await.unwrap_err();
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "mls.forbidden"));
    let added = log(&node, carol.token(), &welcome, "system.bot_added").await;
    assert_eq!(added.len(), 1);
    assert_eq!(
        (&added[0]["bot"], &added[0]["channel"], &added[0]["by"], &added[0]["channel_name"]),
        (&json!(b.address()), &json!(channel), &json!(b.address()), &general["name"])
    );
    assert_eq!(added[0]["channel_system_name"], general["system_name"], "default channels are localized by clients");
    let audit: Vec<String> =
        sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'channel.bots_allowed' AND target = $1")
            .bind(&channel)
            .fetch_all(&node.state.db)
            .await
            .unwrap();
    assert_eq!(audit.len(), 1);

    // Off again: `mls.remove_needed` for the bot's leaf; a member removes it; `system.bot_removed`.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = patch_channel(&node, carol.token(), &room_id, &channel, json!({ "bots_allowed": false })).await;
    assert_eq!((s, j["no_bots_effective"].as_bool()), (StatusCode::OK, Some(true)));
    let needed = next_event(&mut rx, "mls.remove_needed", |d| d["conversation_id"] == channel.as_str()).await;
    assert_eq!(needed["identities"], json!([bot_identity]));
    remove_leaf(&node, &mut carol, &channel, &bot_identity).await;
    let removed = log(&node, carol.token(), &welcome, "system.bot_removed").await;
    assert_eq!((removed.len(), &removed[0]["reason"]), (1, &json!("bots_not_allowed")));
    assert_eq!(removed[0]["bot"], b.address());

    // Allowed again and added by a member (Welcome path: `by` = the member); the explicit flag still wins.
    patch_channel(&node, carol.token(), &room_id, &channel, json!({ "bots_allowed": true })).await;
    bot_dev.client.delete_group(&qualified(&channel)).unwrap();
    node.add_user(&mut carol, &channel, &b.username).await;
    assert_eq!(node.accept_welcomes(&mut bot_dev).await, 1);
    let added = log(&node, carol.token(), &welcome, "system.bot_added").await;
    assert_eq!((added.len(), &added[1]["by"]), (2, &json!(format!("carol@{D}"))));
    let (s, j) = patch_channel(&node, carol.token(), &room_id, &channel, json!({ "no_bots": true })).await;
    assert_eq!(
        (s, j["no_bots_effective"].as_bool(), j["bots_allowed"].as_bool()),
        (StatusCode::OK, Some(true), Some(true))
    );
    remove_leaf(&node, &mut carol, &channel, &bot_identity).await;
    let removed = log(&node, carol.token(), &welcome, "system.bot_removed").await;
    assert_eq!(removed[1]["reason"], "no_bots");
    patch_channel(&node, carol.token(), &room_id, &channel, json!({ "no_bots": false })).await;

    // The room setting: `allowed` opens every encrypted channel, `per_channel` closes those without the setting.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}"), carol.token(), json!({ "bots_in_encrypted_channels": "allowed" }))
        .await;
    assert_eq!((s, &j["bots_in_encrypted_channels"]), (StatusCode::OK, &json!("allowed")), "{j}");
    let update = next_event(&mut rx, "channel.update", |d| d["id"] == council.as_str()).await;
    assert_eq!(update["no_bots_effective"], false);
    external_join(&node, &mut bot_dev, &council).await.unwrap();
    let mut rx = node.state.hub.subscribe();
    node.patch(
        &format!("/api/v1/rooms/{room_id}"),
        carol.token(),
        json!({ "bots_in_encrypted_channels": "per_channel" }),
    )
    .await;
    let needed = next_event(&mut rx, "mls.remove_needed", |d| d["conversation_id"] == council.as_str()).await;
    assert_eq!(needed["identities"], json!([bot_identity]));
    assert_eq!(channel_of(&node, carol.token(), &room_id, &channel).await.unwrap()["no_bots_effective"], false, "kept");
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT meta FROM audit_log WHERE action = 'room.bots_in_encrypted_channels' AND room_id = $1 ORDER BY id",
    )
    .bind(&room_id)
    .fetch_all(&node.state.db)
    .await
    .unwrap();
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert!(audit[1].contains("\"to\":\"per_channel\""), "{audit:?}");

    // Switching a plaintext channel to encrypted closes it in a per_channel room.
    let (s, j) = patch_channel(&node, carol.token(), &room_id, &lobby, json!({ "encrypted": true })).await;
    assert_eq!((s, j["no_bots_effective"].as_bool()), (StatusCode::OK, Some(true)));

    // Uninstalling removes the bot from the room; the security log names the reason.
    patch_channel(&node, carol.token(), &room_id, &channel, json!({ "bots_allowed": true })).await;
    bot_dev.client.delete_group(&qualified(&channel)).unwrap();
    external_join(&node, &mut bot_dev, &channel).await.unwrap();
    assert_eq!(node.delete(&installation_path(&room_id, &b), carol.token()).await.0, StatusCode::NO_CONTENT);
    remove_leaf(&node, &mut carol, &channel, &bot_identity).await;
    let removed = log(&node, carol.token(), &welcome, "system.bot_removed").await;
    assert_eq!(removed.last().unwrap()["reason"], "uninstalled");
    // Users are never logged: carol's own commits added and removed nobody but the bot.
    assert!(log(&node, carol.token(), &welcome, "system.bot_added").await.iter().all(|e| e["bot"] == b.address()));
}

// ---------------------------------------------------------------- command approval state (admin UI)

#[tokio::test]
async fn command_approval_state_is_for_local_node_admins_only() {
    let (a, b) = common::federation::two_nodes_with(|_| {}, |c| c.app_commands_require_approval = true).await;
    let alice = a.register("alice").await;
    let admin = b.register("admin").await;
    let carol = b.register("carol").await;
    let path = "/api/v1/admin/applications/commands/approval";
    let (s, j) = b.get_auth(path, &admin.token).await;
    assert_eq!((s, j["required"].as_bool()), (StatusCode::OK, Some(true)), "{j}");
    let (s, j) = a.get_auth(path, &alice.token).await;
    assert_eq!((s, j["required"].as_bool()), (StatusCode::OK, Some(false)), "{j}");
    let (s, _) = b.get_auth(path, &carol.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "members are not admins");
    // An admin of another node is no admin here.
    let remote = b.sign_in_from(&a, &alice).await;
    let (s, j) = b.get_auth(path, &remote.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"));
}
