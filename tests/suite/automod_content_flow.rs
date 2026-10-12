// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Content-based auto-moderation of unencrypted conversations (protocol MODERATION.md §2): room rules with word
//! lists and link filters, their actions, exemptions, alerts, the node's own lists, and never ciphertext.
use crate::common;

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_node::hub::Event;
use tokio::sync::broadcast;
use tower::ServiceExt;

const DOMAIN: &str = "t.local";

struct World {
    node: TestNode,
    alice: Session,
    moder: Session,
    bob: Session,
    room_id: String,
    channel: String,
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

async fn world_on(node: TestNode) -> World {
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let moder = node.register("moder").await;
    let bob = node.register("bob").await;
    let room = node.plaintext_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    join(&node, &alice, &room_id, &moder).await;
    join(&node, &alice, &room_id, &bob).await;
    let perms = common::perms(&[1 << 0, 1 << 1, 1 << 13]);
    let (_, role) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Mods", "permissions": perms }))
        .await;
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", moder.user_id),
            &alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    World { node, alice, moder, bob, room_id, channel }
}

async fn world() -> World {
    world_on(test_node(DOMAIN).await).await
}

impl World {
    fn path(&self) -> String {
        format!("/api/v1/rooms/{}/automod", self.room_id)
    }
    async fn set_rules(&self, rules: Value) -> Value {
        let (s, j) = self.node.put(&self.path(), &self.alice.token, json!({ "rules": rules })).await;
        assert_eq!(s, StatusCode::OK, "{j}");
        j
    }
    async fn send(&self, token: &str, body: &str) -> (StatusCode, Value) {
        self.node.send(token, &self.room_id, &self.channel, body).await
    }
    async fn bodies(&self) -> Vec<String> {
        let (_, list) =
            self.node.get_auth(&format!("/api/v1/conversations/{}/messages", self.channel), &self.alice.token).await;
        list.as_array().unwrap().iter().filter_map(|m| m["content"]["body"].as_str().map(String::from)).collect()
    }
}

fn rule(name: &str, extra: Value) -> Value {
    let mut r = json!({ "name": name, "terms": [], "whole_word": false, "links": "off", "domains": [], "exempt_roles": [], "exempt_channels": [], "action": "block" });
    for (k, v) in extra.as_object().unwrap() {
        r[k] = v.clone();
    }
    r
}

async fn hub_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str) -> Arc<Event> {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind {
            return ev;
        }
    }
}

#[tokio::test]
async fn rules_are_managed_with_manage_room_and_validated() {
    let w = world().await;
    let (s, settings) = w.node.get_auth(&w.path(), &w.moder.token).await;
    assert_eq!(s, StatusCode::OK, "moderators read the rules: {settings}");
    assert_eq!(settings["rules"], json!([]));
    assert_eq!(settings["burst"]["limit"], 10);
    assert_eq!(settings["burst"]["window_secs"], 5);
    assert_eq!(settings["node"]["words"], false);
    let (s, j) = w.node.get_auth(&w.path(), &w.bob.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.forbidden")), "{j}");
    let (s, j) = w.node.put(&w.path(), &w.moder.token, json!({ "rules": [] })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.manage_forbidden")), "{j}");

    let invalid = [
        json!([rule("empty", json!({}))]),
        json!([rule("", json!({ "terms": ["x"] }))]),
        json!([rule("a", json!({ "terms": ["x"] })), rule("a", json!({ "terms": ["y"] }))]),
        json!([rule("long", json!({ "terms": ["x".repeat(101)] }))]),
        json!([rule("many", json!({ "terms": (0..501).map(|i| format!("t{i}")).collect::<Vec<_>>() }))]),
        json!([rule("stars", json!({ "terms": ["a*b*c*d*e*f*g"] }))]),
        json!([rule("only stars", json!({ "terms": ["**"] }))]),
        json!([rule("action", json!({ "terms": ["x"], "action": "nuke" }))]),
        json!([rule("timeout", json!({ "terms": ["x"], "action": "timeout" }))]),
        json!([rule("links", json!({ "links": "maybe" }))]),
        json!([rule("domain", json!({ "links": "block_list", "domains": ["not a domain"] }))]),
        json!([rule("role", json!({ "terms": ["x"], "exempt_roles": ["01J00000000000000000000000"] }))]),
        json!([rule("chan", json!({ "terms": ["x"], "exempt_channels": ["01J00000000000000000000000"] }))]),
        json!((0..21).map(|i| rule(&format!("r{i}"), json!({ "terms": ["x"] }))).collect::<Vec<_>>()),
    ];
    for rules in invalid {
        let (s, j) = w.node.put(&w.path(), &w.alice.token, json!({ "rules": rules })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("automod.rules_invalid")), "{rules}: {j}");
    }
    let saved = w.set_rules(json!([rule("Slurs", json!({ "terms": ["Badword", "spam*"] }))])).await;
    let id = saved["rules"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(saved["rules"][0]["enabled"], true);
    assert_eq!(saved["rules"][0]["terms"], json!(["badword", "spam*"]), "terms are stored normalized");
    // Ids are kept when a rule comes back with it.
    let mut again = saved["rules"].clone();
    again[0]["name"] = json!("Renamed");
    let saved = w.set_rules(again).await;
    assert_eq!(saved["rules"][0]["id"], id.as_str());
    let (_, log) = w.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", w.room_id), &w.alice.token).await;
    assert!(log.as_array().unwrap().iter().any(|e| e["action"] == "automod.rules"), "{log}");
}

#[tokio::test]
async fn block_refuses_the_message_names_the_rule_and_alerts_without_the_text() {
    let w = world().await;
    w.set_rules(json!([rule("Slurs", json!({ "terms": ["badword", "spam*"], "whole_word": true }))])).await;
    let mut rx = w.node.state.hub.subscribe();
    let (s, j) = w.send(&w.bob.token, "you are a BadWord, really").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
    assert_eq!((j["meta"]["rule"].as_str(), j["meta"]["scope"].as_str()), (Some("Slurs"), Some("room")));
    assert!(w.bodies().await.is_empty(), "nothing stored");

    let ev = hub_event(&mut rx, "moderation.alert").await;
    assert_eq!((ev.data["kind"].as_str(), ev.data["rule"].as_str()), (Some("content"), Some("Slurs")));
    assert_eq!((ev.data["matched"].as_str(), ev.data["action"].as_str()), (Some("badword"), Some("block")));
    let (_, log) = w.node.get_auth(&format!("/api/v1/rooms/{}/audit-log", w.room_id), &w.alice.token).await;
    let e = log.as_array().unwrap().iter().find(|e| e["action"] == "automod.content").expect("audit entry");
    assert_eq!(e["target"], "bob@t.local");
    assert_eq!(e["meta"]["matched"], "badword");
    assert!(!e.to_string().contains("really"), "the message text never reaches the audit log: {e}");
    // The inbox gets one automod entry per author while it is open.
    let (s, j) = w.send(&w.bob.token, "spammity").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "wildcards: {j}");
    let (_, list) = w.node.get_auth(&format!("/api/v1/rooms/{}/reports", w.room_id), &w.moder.token).await;
    assert_eq!(list["reports"].as_array().unwrap().len(), 1, "{list}");
    let r = &list["reports"][0];
    assert_eq!((r["source"].as_str(), r["kind"].as_str()), (Some("automod"), Some("user")));
    assert!(r["reporter"].is_null());
    assert_eq!(r["target"]["address"], "bob@t.local");

    // Whole words only: "badwordy" and "nospam" pass.
    let (s, j) = w.send(&w.bob.token, "badwordy nospam").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // Edits are checked as well.
    let (s, j) = w
        .node
        .patch(
            &format!("/api/v1/conversations/{}/messages/{}", w.channel, j["id"].as_str().unwrap()),
            &w.bob.token,
            json!({ "content": { "type": "text", "body": "badword" } }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
    assert_eq!(w.bodies().await, vec!["badwordy nospam".to_string()]);
}

#[tokio::test]
async fn delete_accepts_but_hides_and_timeout_mutes_the_author() {
    let w = world().await;
    w.set_rules(json!([
        rule("Soft", json!({ "terms": ["meh"], "action": "delete" })),
        rule("Hard", json!({ "terms": ["grr"], "action": "timeout", "timeout_minutes": 30 })),
    ]))
    .await;
    let mut rx = w.node.state.hub.subscribe();
    let (s, msg) = w.send(&w.bob.token, "meh whatever").await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let ev = hub_event(&mut rx, "message.delete").await;
    assert_eq!(ev.data["id"], msg["id"]);
    assert!(w.bodies().await.is_empty());
    let mut creates = 0;
    while let Ok(ev) = rx.try_recv() {
        if ev.kind == "message.create" {
            creates += 1;
        }
    }
    assert_eq!(creates, 0, "the message never reaches the others");

    let (s, _) = w.send(&w.bob.token, "grr").await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(w.bodies().await.is_empty());
    let (_, members) = w.node.get_auth(&format!("/api/v1/rooms/{}/members", w.room_id), &w.alice.token).await;
    let bob = members.as_array().unwrap().iter().find(|m| m["user"]["address"] == "bob@t.local").unwrap();
    assert!(bob["timeout_until"].is_string(), "{bob}");
    let (s, _) = w.send(&w.bob.token, "hello").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "timed out");
}

#[tokio::test]
async fn link_filters_and_exemptions() {
    let w = world().await;
    let (_, role) = w
        .node
        .post(
            &format!("/api/v1/rooms/{}/roles", w.room_id),
            &w.alice.token,
            json!({ "name": "Trusted", "permissions": common::perms(&[1, 2]) }),
        )
        .await;
    let (s, other) = w
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels", w.room_id),
            &w.alice.token,
            json!({ "name": "links", "kind": "text", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    let other_id = other["id"].as_str().unwrap().to_string();
    w.set_rules(json!([
        rule("Allowed sites", json!({ "links": "allow_list", "domains": ["example.org"], "exempt_roles": [role["id"]], "exempt_channels": [other_id] })),
        rule("Bad sites", json!({ "links": "block_list", "domains": ["evil.test"] })),
    ]))
    .await;
    let (s, _) = w.send(&w.bob.token, "see https://docs.example.org/page").await;
    assert_eq!(s, StatusCode::CREATED, "subdomains of allowed domains pass");
    let (s, j) = w.send(&w.bob.token, "see https://elsewhere.test/x").await;
    assert_eq!((s, j["meta"]["rule"].as_str()), (StatusCode::FORBIDDEN, Some("Allowed sites")), "{j}");
    let (s, j) = w.send(&w.bob.token, "go to www.elsewhere.test now").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "www hosts are links: {j}");
    let (s, j) = w.send(&w.bob.token, "plain evil.test mention").await;
    assert_eq!(
        (s, j["meta"]["rule"].as_str()),
        (StatusCode::FORBIDDEN, Some("Bad sites")),
        "block lists catch bare domains: {j}"
    );
    // The owner is exempt, so are exempt channels and roles (for that rule only).
    let (s, _) = w.send(&w.alice.token, "https://elsewhere.test").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = w.node.send(&w.bob.token, &w.room_id, &other_id, "https://elsewhere.test").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = w
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", w.room_id, w.bob.user_id),
            &w.alice.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = w.send(&w.bob.token, "https://elsewhere.test").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = w.send(&w.bob.token, "https://evil.test").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "the other rule still applies");
    // Disabled rules do nothing.
    let (_, current) = w.node.get_auth(&w.path(), &w.alice.token).await;
    let mut rules = current["rules"].clone();
    rules[1]["enabled"] = json!(false);
    w.set_rules(rules).await;
    let (s, _) = w.send(&w.bob.token, "https://evil.test").await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn attachment_names_are_checked() {
    let w = world().await;
    w.set_rules(json!([rule("Names", json!({ "terms": ["secret*"] }))])).await;
    let req = Request::post(format!("/api/v1/rooms/{}/channels/{}/uploads", w.room_id, w.channel))
        .header(header::AUTHORIZATION, format!("Bearer {}", w.bob.token))
        .header(header::CONTENT_TYPE, "text/plain")
        .header("tavrn-file-name", "secretplans.txt")
        .body(Body::from(b"plans".to_vec()))
        .unwrap();
    let resp = w.node.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success());
    let blob: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let (s, j) = w
        .node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/messages", w.room_id, w.channel),
            &w.bob.token,
            json!({ "content": { "type": "text", "body": "files" }, "attachments": [blob["id"]] }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
}

#[tokio::test]
async fn encrypted_channels_are_never_filtered() {
    let node = test_node(DOMAIN).await;
    let _admin = node.register("admin").await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let room = node.create_room(alice.token(), "Secret").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    join(&node, &alice.session, &room_id, &bob.session).await;
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/automod"),
            alice.token(),
            json!({ "rules": [rule("All", json!({ "terms": ["anything"] }))] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    node.create_group(&mut alice, &channel).await;
    node.add_user(&mut alice, &channel, "bob").await;
    assert_eq!(node.accept_welcomes(&mut bob).await, 1);
    let (s, j) = node.send_encrypted(&bob, &channel, "anything").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let n: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM audit_log WHERE action = 'automod.content'")
        .fetch_one(&node.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn node_lists_block_everywhere_without_exemptions() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    std::fs::write(&words, "# operator list\n\nforbidden phrase\nscam*\n").unwrap();
    let links = dir.path().join("links.txt");
    std::fs::write(&links, "malware.test\n").unwrap();
    let (w_path, l_path) = (words.to_string_lossy().to_string(), links.to_string_lossy().to_string());
    let node = test_node_with(DOMAIN, move |c| {
        c.automod_words_file = Some(w_path);
        c.automod_links = l_path;
    })
    .await;
    let w = world_on(node).await;
    let (_, settings) = w.node.get_auth(&w.path(), &w.alice.token).await;
    assert_eq!((settings["node"]["words"].as_bool(), settings["node"]["links"].as_bool()), (Some(true), Some(true)));
    for body in ["a FORBIDDEN   phrase here", "scammer", "visit http://cdn.malware.test/x"] {
        let (s, j) = w.send(&w.alice.token, body).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{body}: {j}");
        assert_eq!((j["meta"]["rule"].as_str(), j["meta"]["scope"].as_str()), (Some("node"), Some("node")));
    }
    let (s, _) = w.send(&w.alice.token, "forbidden phrases are whole words only? no: phrase").await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = w.send(&w.alice.token, "a phrase that is forbidden").await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn node_lists_reload_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    std::fs::write(&words, "forbidden\n").unwrap();
    let w_path = words.to_string_lossy().to_string();
    let node = test_node_with(DOMAIN, move |c| c.automod_words_file = Some(w_path)).await;
    let w = world_on(node).await;
    let (s, _) = w.send(&w.alice.token, "a newword here").await;
    assert_eq!(s, StatusCode::CREATED);

    // The operator edits the list; the hourly housekeeping (or SIGHUP) reads it again.
    std::fs::write(&words, "newword\n").unwrap();
    let changes = tavrn_node::automod::reload_node_lists(&w.node.state).await.unwrap();
    assert_eq!((changes.words_added, changes.words_removed), (1, 1));
    let (s, j) = w.send(&w.alice.token, "a newword here").await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
    let (s, _) = w.send(&w.alice.token, "forbidden is fine now").await;
    assert_eq!(s, StatusCode::CREATED);

    // An invalid file keeps the lists in force.
    std::fs::write(&words, "x*x*x*x*x*x*x\n").unwrap();
    assert!(tavrn_node::automod::reload_node_lists(&w.node.state).await.is_err());
    let (s, _) = w.send(&w.alice.token, "a newword here").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[test]
fn unreadable_node_lists_are_configuration_errors() {
    let mut c = common::dev_config(DOMAIN, "/tmp", "sqlite::memory:");
    c.automod_words_file = Some("/nonexistent/words.txt".into());
    c.automod_links = "/nonexistent/links.txt".into();
    let err = c.validate().unwrap_err().to_string();
    assert!(err.contains("TAVRN_AUTOMOD_WORDS_FILE") && err.contains("TAVRN_AUTOMOD_LINKS"), "{err}");
}
