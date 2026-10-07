// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The welcome channel as the room's security log: always visible (no override can hide
//! it), read-only, never encrypted, full history for new members, and `system.key_changed` entries when a
//! member's identity key changes.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    Session, TestNode,
    e2ee::{Dev, b64},
    test_node,
};
use serde_json::{Value, json};
use tavrn_crypto::{IdentityKey, MasterSecret, sign_continuity, wrap_identity_key};

const DOMAIN: &str = "t.local";

fn welcome(room: &Value) -> Value {
    room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").cloned().unwrap_or(Value::Null)
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

/// Contents of the channel's messages, oldest first.
async fn entries(node: &TestNode, token: &str, channel: &str) -> Vec<Value> {
    let (s, msgs) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), token).await;
    assert_eq!(s, StatusCode::OK, "{msgs}");
    let mut list: Vec<Value> = msgs.as_array().unwrap().iter().map(|m| m["content"].clone()).collect();
    list.reverse();
    list
}

fn key_entries(list: &[Value]) -> Vec<(String, bool)> {
    list.iter()
        .filter(|e| e["type"] == "system.key_changed")
        .map(|e| (e["user"].as_str().unwrap().to_string(), e["rotated"].as_bool().unwrap()))
        .collect()
}

/// A valid rotation of `dev`'s account (single device) from the derived key to a fresh one.
fn rotation(dev: &Dev) -> (IdentityKey, Value) {
    let address = format!("{}@{DOMAIN}", dev.session.username);
    let old = IdentityKey::from_master(&dev.master);
    let new = IdentityKey::generate().unwrap();
    let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let statement = sign_continuity(&old, &new, &at).unwrap();
    let att = new.attest_device(&address, &dev.session.device_id, &dev.client.device().public_key()).unwrap();
    let body = json!({
        "new_identity_public_key": b64(&new.public_key()),
        "continuity": statement,
        "identity_blob": b64(&wrap_identity_key(&dev.master, &new, &address).unwrap()),
        "attestations": [{ "device_id": dev.session.device_id, "identity_signature": b64(&att.signature) }],
    });
    (new, body)
}

#[tokio::test]
async fn key_changes_are_logged_in_every_room_of_the_member() {
    let node = test_node(DOMAIN).await;
    let owner = node.register("owner").await;
    let alice = node.crypto_user("alice").await;
    let first = node.create_room(&owner.token, "Guild").await;
    let second = node.create_room(&owner.token, "Tavern").await;
    let other = node.create_room(&owner.token, "Without Alice").await;
    for room in [&first, &second] {
        join(&node, &owner, room["id"].as_str().unwrap(), &alice.session).await;
    }
    let wid = |room: &Value| welcome(room)["id"].as_str().unwrap().to_string();

    // A rotation with continuity: "rotated".
    let (_, body) = rotation(&alice);
    let (s, j) = node.post("/api/v1/users/me/identity/rotate", alice.token(), body).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // An identity reset: a plain key change.
    let new_master = MasterSecret::generate().unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&new_master.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    for room in [&first, &second] {
        let list = entries(&node, &owner.token, &wid(room)).await;
        assert_eq!(
            key_entries(&list),
            vec![("alice@t.local".to_string(), true), ("alice@t.local".to_string(), false)],
            "{list:?}"
        );
        let entry = list.iter().find(|e| e["type"] == "system.key_changed").unwrap();
        assert!(entry["at"].as_str().is_some_and(|a| a.ends_with('Z')), "{entry}");
        assert_eq!(entry["display_name"], "alice");
        // Informational only: no keys, no reasons, no actor.
        for field in ["identity_public_key", "reason", "by", "moderator"] {
            assert!(entry.get(field).is_none(), "{field} in {entry}");
        }
    }
    assert!(key_entries(&entries(&node, &owner.token, &wid(&other)).await).is_empty(), "rooms without alice");
}

#[tokio::test]
async fn nobody_can_hide_the_welcome_channel_and_it_stays_read_only_and_plaintext() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let wid = welcome(&room)["id"].as_str().unwrap().to_string();
    join(&node, &alice, &room_id, &bob).await;

    // The former room setting is gone: ignored on update, absent from the room.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}"), &alice.token, json!({ "welcome_channel_enabled": false }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert!(j.get("welcome_channel_enabled").is_none(), "{j}");
    assert_eq!(welcome(&j)["id"], wid.as_str());

    // Deny view_channel (and read_history) on the channel for @everyone and for bob himself: still visible.
    let everyone = j["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    for (subject_type, subject_id) in [("role", everyone), ("member", json!(bob.user_id))] {
        let (s, o) = node
            .put(
                &format!("/api/v1/rooms/{room_id}/overrides"),
                &alice.token,
                json!({ "target_type": "channel", "target_id": wid, "subject_type": subject_type, "subject_id": subject_id,
                        "allow": "0", "deny": common::perms(&[1, 1 << 34]) }),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{o}");
    }
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &bob.token).await;
    assert_eq!(welcome(&detail)["id"], wid.as_str(), "listed: {detail}");
    assert!(
        detail["read_states"].as_array().unwrap().iter().any(|r| r["conversation_id"] == wid.as_str()),
        "counted as visible: {detail}"
    );
    assert_eq!(entries(&node, &bob.token, &wid).await.len(), 2, "alice and bob joined");

    // An override allowing to send changes nothing: system entries only.
    let (s, _) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            &alice.token,
            json!({ "target_type": "channel", "target_id": wid, "subject_type": "member", "subject_id": bob.user_id,
                    "allow": common::perms(&[2, 8]), "deny": "0" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{wid}/messages"),
            &bob.token,
            json!({ "content": { "type": "text", "body": "hi" } }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("channel.read_only")), "{j}");

    // Never encrypted.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{wid}"), &alice.token, json!({ "encrypted": true }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("channel.system_protected")), "{j}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(welcome(&detail)["encrypted"], false);
}

#[tokio::test]
async fn new_members_read_the_whole_log_even_without_read_history() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.crypto_user("bob").await;
    let carol = node.register("carol").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let wid = welcome(&room)["id"].as_str().unwrap().to_string();
    join(&node, &alice, &room_id, &bob.session).await;
    let (_, body) = rotation(&bob);
    let (s, j) = node.post("/api/v1/users/me/identity/rotate", bob.token(), body).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _) = node.post(&format!("/api/v1/rooms/{room_id}/leave"), &bob.session.token, json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // @everyone loses read_history (bit 34): the cut of encrypted history does not touch the log.
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap().clone();
    let perms = everyone["permissions"].as_str().unwrap().parse::<u64>().unwrap() & !(1u64 << 34);
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/roles/{}", everyone["id"].as_str().unwrap()),
            &alice.token,
            json!({ "permissions": perms.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    join(&node, &alice, &room_id, &carol).await;
    let list = entries(&node, &carol.token, &wid).await;
    let types: Vec<&str> = list.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(types, vec!["system.join", "system.join", "system.key_changed", "system.leave", "system.join"]);
    assert_eq!(key_entries(&list), vec![("bob@t.local".to_string(), true)]);
}

#[tokio::test]
async fn the_fixup_shows_switched_off_welcome_channels_again() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Alt").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let wid = welcome(&room)["id"].as_str().unwrap().to_string();
    // A room that had switched it off under the old setting, and one whose channel is missing altogether.
    sqlx::query("UPDATE rooms SET welcome_channel_enabled = 0 WHERE id = $1")
        .bind(&room_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    let older = node.create_room(&alice.token, "Older").await;
    let older_wid = welcome(&older)["id"].as_str().unwrap().to_string();
    sqlx::query("DELETE FROM conversations WHERE id = $1").bind(&older_wid).execute(&node.state.db).await.unwrap();
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.welcome_channels, 2);
    let enabled: i64 = sqlx::query_scalar("SELECT welcome_channel_enabled FROM rooms WHERE id = $1")
        .bind(&room_id)
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(enabled, 1);
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(welcome(&detail)["id"], wid.as_str());
    let (s, _) =
        node.req(Method::GET, &format!("/api/v1/conversations/{wid}/messages"), Some(&alice.token), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(tavrn_node::fixups::run(&node.state.db).await.unwrap().welcome_channels, 0, "idempotent");
}
