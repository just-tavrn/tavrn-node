// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Moderation bots read the room's report inbox (protocol MODERATION.md §1.4a, APPLICATIONS.md §2.4–§2.6): the scope
//! `moderation` plus `moderate_members` in the room, room reports only, the reduced `AppReport` shape (no detail,
//! snapshot, evidence, note, assignee or actions; the reporter as a pseudonym), the events of the room, and nothing
//! that writes.
use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, crossnode, federation::FedNode};
use serde_json::{Value, json};
use tavrn_node::permissions as p;

const DOMAIN: &str = "t.local";

/// A bot with one token.
struct Bot {
    user_id: String,
    username: String,
    secret: String,
}

/// A served node with an admin, a room owned by alice with a plaintext channel and a "Mods" role
/// (`moderate_members`), the members bob and carol, and three installed bots: `watcher` (`moderation`, Mods role),
/// `plain` (`moderation`, no role) and `blind` (`messages:read` only, Mods role).
struct World {
    node: FedNode,
    admin: Session,
    alice: Session,
    bob: Session,
    carol: Session,
    room_id: String,
    channel: String,
    role_id: String,
    watcher: Bot,
    plain: Bot,
    blind: Bot,
}

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

/// A public application with a token of `scopes`, installed in the room by its owner.
async fn bot(node: &TestNode, owner: &Session, room_id: &str, name: &str, scopes: &[&str]) -> Bot {
    let (s, app) = node.post("/api/v1/applications", &owner.token, json!({ "name": name, "public": true })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap();
    let (s, t) = node
        .post(
            &format!("/api/v1/applications/{app_id}/tokens"),
            &owner.token,
            json!({ "name": "main", "scopes": scopes }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &owner.token,
            json!({ "application": format!("{DOMAIN}/{app_id}") }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    Bot {
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
    }
}

async fn give_role(node: &TestNode, owner: &Session, room_id: &str, user_id: &str, role_id: &str) {
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{user_id}"), &owner.token, json!({ "roles": [role_id] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn world() -> World {
    let node = FedNode::serve_one(DOMAIN).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.plaintext_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    for who in [&bob, &carol] {
        join(&node, &alice, &room_id, who).await;
    }
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &alice.token,
            json!({ "name": "Mods", "permissions": common::perms(&[p::MODERATE_MEMBERS]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap().to_string();
    let watcher = bot(&node, &alice, &room_id, "Watcher", &["moderation"]).await;
    let plain = bot(&node, &alice, &room_id, "Plain", &["moderation"]).await;
    let blind = bot(&node, &alice, &room_id, "Blind", &["messages:read"]).await;
    for b in [&watcher, &blind] {
        give_role(&node, &alice, &room_id, &b.user_id, &role_id).await;
    }
    World { node, admin, alice, bob, carol, room_id, channel, role_id, watcher, plain, blind }
}

async fn report(node: &TestNode, token: &str, body: Value) -> String {
    let (s, j) = node.post("/api/v1/reports", token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    j["id"].as_str().unwrap().to_string()
}

/// A report of carol's message by `reporter` with a reason.
async fn report_message(w: &World, reporter: &Session, text: &str) -> (String, String) {
    let (s, msg) = w.node.send(&w.carol.token, &w.room_id, &w.channel, text).await;
    assert_eq!(s, StatusCode::CREATED, "{msg}");
    let mid = msg["id"].as_str().unwrap().to_string();
    let id = report(
        &w.node,
        &reporter.token,
        json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "spam",
            "detail": "the private reason of the reporter" }),
    )
    .await;
    (id, mid)
}

fn ids(list: &Value) -> Vec<String> {
    list["reports"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
}

/// The fields an app token never gets.
const HIDDEN: &[&str] = &["detail", "snapshot", "evidence", "note", "assignee", "actions", "forwarded", "origin"];

fn assert_reduced(r: &Value) {
    for field in HIDDEN {
        assert!(r.get(*field).is_none(), "{field} must be absent for app tokens: {r}");
    }
    let reporter = r["reporter"].as_str().unwrap_or_else(|| panic!("a pseudonym: {r}"));
    assert!(reporter.starts_with("anon-") && !reporter.contains('@'), "{reporter}");
    let text = r.to_string();
    for leak in ["bob@", "the private reason", "carol said", "released text"] {
        assert!(!text.contains(leak), "{leak} leaked: {text}");
    }
}

#[tokio::test]
async fn a_moderation_bot_reads_the_room_inbox_metadata_only() {
    let w = world().await;
    let (first, mid) = report_message(&w, &w.bob, "carol said buy coins").await;
    let second = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "harassment",
            "detail": "the private reason again" }),
    )
    .await;
    let by_alice = report(
        &w.node,
        &w.alice.token,
        json!({ "kind": "user", "user": "carol@t.local", "room_id": w.room_id, "category": "other" }),
    )
    .await;
    // A report with released evidence (inserted directly: the encrypted path is covered in reports_flow).
    let evidence_id = tavrn_node::util::ulid();
    let evidence = json!([{ "message_id": mid, "author": "carol@t.local", "device_id": "dev", "created_at": "2026-10-01T10:00:00Z",
        "text": "released text", "attachments": ["photo.png"] }])
    .to_string();
    let now = tavrn_node::util::now();
    tavrn_node::store::reports::insert(
        &w.node.state.db,
        &tavrn_node::store::reports::NewReport {
            id: &evidence_id,
            source: "user",
            scope: "room",
            kind: "message",
            reporter_id: Some(&w.bob.user_id),
            room_id: Some(&w.room_id),
            conversation_id: Some(&w.channel),
            node: None,
            message_id: Some(&mid),
            target_user_id: Some(&w.carol.user_id),
            target_address: "carol@t.local",
            category: "illegal",
            detail: "the private reason with evidence",
            snapshot: None,
            evidence: Some(&evidence),
            created_at: &now,
        },
    )
    .await
    .unwrap();
    // A moderator's note and an action stay with the people as well.
    let (s, j) =
        w.node.patch(&format!("/api/v1/reports/{first}"), &w.alice.token, json!({ "note": "the private note" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let path = format!("/api/v1/rooms/{}/reports", w.room_id);
    let (s, list) = w.node.get_auth(&path, &w.watcher.secret).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(ids(&list), vec![evidence_id.clone(), by_alice.clone(), second.clone(), first.clone()]);
    assert_eq!(list["open"], 4);
    assert!(!list.to_string().contains("the private note"), "{list}");
    let reports = list["reports"].as_array().unwrap();
    for r in reports {
        assert_reduced(r);
        assert_eq!((r["scope"].as_str(), r["status"].as_str()), (Some("room"), Some("open")), "{r}");
        assert_eq!(r["target"]["address"], "carol@t.local");
        assert_eq!(r["target_address"], "carol@t.local");
        assert_eq!(r["room_name"], "Guild");
    }
    let by_id = |id: &str| reports.iter().find(|r| r["id"] == id).unwrap().clone();
    let (r_first, r_second, r_alice, r_evidence) =
        (by_id(&first), by_id(&second), by_id(&by_alice), by_id(&evidence_id));
    assert_eq!(
        (r_first["kind"].as_str(), r_first["category"].as_str(), r_first["message_id"].as_str()),
        (Some("message"), Some("spam"), Some(mid.as_str()))
    );
    assert_eq!(r_first["message_exists"], true);
    assert_eq!(r_first["conversation_id"], w.channel.as_str());
    assert_eq!(r_first["conversation_kind"], "channel");
    assert_eq!(r_evidence["evidence_count"], 1, "counts, never the evidence");
    assert_eq!(r_first["evidence_count"], 0);
    // The pseudonym is stable per reporter (bob twice), differs between reporters (alice).
    assert_eq!(r_first["reporter"], r_second["reporter"]);
    assert_eq!(r_first["reporter"], r_evidence["reporter"]);
    assert_ne!(r_first["reporter"], r_alice["reporter"]);

    // The detail route: the same reduced shape, and also for the report with evidence.
    for (id, listed) in [(&first, &r_first), (&evidence_id, &r_evidence)] {
        let (s, one) = w.node.get_auth(&format!("/api/v1/reports/{id}"), &w.watcher.secret).await;
        assert_eq!(s, StatusCode::OK, "{one}");
        assert_reduced(&one);
        assert_eq!(&one, listed, "list and detail agree");
    }
    // Moderators keep the full report.
    let (_, full) = w.node.get_auth(&format!("/api/v1/reports/{evidence_id}"), &w.alice.token).await;
    assert_eq!(full["evidence"][0]["text"], "released text");
    assert_eq!(full["reporter"]["address"], "bob@t.local");

    // Another bot of the room sees another pseudonym for the same reporter (unlinkable between bots).
    let second_watcher = bot(&w.node, &w.alice, &w.room_id, "Second", &["moderation"]).await;
    give_role(&w.node, &w.alice, &w.room_id, &second_watcher.user_id, &w.role_id).await;
    let (s, other) = w.node.get_auth(&format!("/api/v1/reports/{first}"), &second_watcher.secret).await;
    assert_eq!(s, StatusCode::OK, "{other}");
    assert_reduced(&other);
    assert_ne!(other["reporter"], r_first["reporter"]);

    // Filters and paging as for moderators.
    let (_, page) = w.node.get_auth(&format!("{path}?limit=1&before={by_alice}"), &w.watcher.secret).await;
    assert_eq!(ids(&page), vec![second.clone()]);
    let (s, j) =
        w.node.patch(&format!("/api/v1/reports/{second}"), &w.alice.token, json!({ "status": "resolved" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, open) = w.node.get_auth(&format!("{path}?status=open"), &w.watcher.secret).await;
    assert_eq!((open["reports"].as_array().unwrap().len(), open["open"].as_i64()), (3, Some(3)));
    let (_, done) = w.node.get_auth(&format!("{path}?status=resolved"), &w.watcher.secret).await;
    assert_eq!(ids(&done), vec![second.clone()]);
    assert!(done["reports"][0]["resolved_at"].is_string());
    let (s, j) = w.node.get_auth(&format!("{path}?status=closed"), &w.watcher.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "report.status_invalid"), "{j}");
}

#[tokio::test]
async fn without_moderate_members_or_the_scope_bots_see_nothing() {
    let w = world().await;
    let (id, _) = report_message(&w, &w.bob, "carol said spam").await;
    let path = format!("/api/v1/rooms/{}/reports", w.room_id);
    // `moderation` without `moderate_members` in the room.
    let (s, j) = w.node.get_auth(&path, &w.plain.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "report.view_forbidden"), "{j}");
    let (s, j) = w.node.get_auth(&format!("/api/v1/reports/{id}"), &w.plain.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "report.not_found"), "{j}");
    // `moderate_members` without the scope `moderation`: the route table refuses.
    for p in [path.clone(), format!("/api/v1/reports/{id}")] {
        let (s, j) = w.node.get_auth(&p, &w.blind.secret).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{p}: {j}");
    }
    // A bot that is not in the room.
    let (s, outsider) = w.node.post("/api/v1/applications", &w.bob.token, json!({ "name": "Outsider" })).await;
    assert_eq!(s, StatusCode::CREATED, "{outsider}");
    let (_, t) = w
        .node
        .post(
            &format!("/api/v1/applications/{}/tokens", outsider["id"].as_str().unwrap()),
            &w.bob.token,
            json!({ "name": "main", "scopes": ["moderation"] }),
        )
        .await;
    let secret = t["secret"].as_str().unwrap();
    let (s, j) = w.node.get_auth(&path, secret).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, _) = w.node.get_auth(&format!("/api/v1/reports/{id}"), secret).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Losing the role closes the inbox again.
    let (s, j) = w
        .node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", w.room_id, w.watcher.user_id),
            &w.alice.token,
            json!({ "roles": [] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = w.node.get_auth(&path, &w.watcher.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "report.view_forbidden"), "{j}");
}

#[tokio::test]
async fn node_reports_and_reports_about_the_bot_stay_hidden() {
    let w = world().await;
    let room_report =
        report(&w.node, &w.bob.token, json!({ "kind": "room", "room_id": w.room_id, "category": "other" })).await;
    let about_owner = report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "alice@t.local", "room_id": w.room_id, "category": "other" }),
    )
    .await;
    let about_bot = report(
        &w.node,
        &w.carol.token,
        json!({ "kind": "user", "user": format!("{}@{DOMAIN}", w.watcher.username), "room_id": w.room_id,
            "category": "spam" }),
    )
    .await;
    let dm_less =
        report(&w.node, &w.carol.token, json!({ "kind": "user", "user": "bob@t.local", "category": "spam" })).await;
    let visible = report(
        &w.node,
        &w.carol.token,
        json!({ "kind": "user", "user": "bob@t.local", "room_id": w.room_id, "category": "spam" }),
    )
    .await;
    let (s, list) = w.node.get_auth(&format!("/api/v1/rooms/{}/reports", w.room_id), &w.watcher.secret).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(ids(&list), vec![visible.clone()], "room reports not about the bot only");
    assert_eq!(list["open"], 1);
    for id in [&room_report, &about_owner, &about_bot, &dm_less] {
        let (s, j) = w.node.get_auth(&format!("/api/v1/reports/{id}"), &w.watcher.secret).await;
        assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "report.not_found"), "{id}: {j}");
    }
    let (s, j) = w.node.get_auth("/api/v1/admin/reports", &w.watcher.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{j}");
    // The node admin still sees everything (the about-the-bot report too).
    let (_, all) = w.node.get_auth("/api/v1/admin/reports", &w.admin.token).await;
    assert_eq!(all["reports"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn bots_still_cannot_create_triage_act_forward_or_delete() {
    let w = world().await;
    let (id, mid) = report_message(&w, &w.bob, "carol said spam").await;
    let cases: Vec<(Method, String, Value)> = vec![
        (
            Method::POST,
            "/api/v1/reports".into(),
            json!({ "kind": "user", "user": "carol@t.local", "category": "spam" }),
        ),
        (
            Method::POST,
            "/api/v1/reports".into(),
            json!({ "kind": "message", "conversation_id": w.channel, "message_id": mid, "category": "spam" }),
        ),
        (Method::PATCH, format!("/api/v1/reports/{id}"), json!({ "status": "dismissed" })),
        (Method::DELETE, format!("/api/v1/reports/{id}"), Value::Null),
        (Method::POST, format!("/api/v1/reports/{id}/actions"), json!({ "action": "kick" })),
        (Method::POST, format!("/api/v1/reports/{id}/forward"), json!({})),
    ];
    for (m, path, body) in cases {
        let body = (!body.is_null()).then_some(body);
        let (s, j) = w.node.req(m.clone(), &path, Some(&w.watcher.secret), body).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{m} {path}: {j}");
    }
    // Nothing changed: still open, carol still a member, no action recorded.
    let (_, full) = w.node.get_auth(&format!("/api/v1/reports/{id}"), &w.alice.token).await;
    assert_eq!((full["status"].as_str(), full["actions"].as_array().map(Vec::len)), (Some("open"), Some(0)), "{full}");
    let (_, list) = w.node.get_auth("/api/v1/admin/reports", &w.admin.token).await;
    assert_eq!(list["reports"].as_array().unwrap().len(), 1, "no report by the bot");
}

#[tokio::test]
async fn report_events_reach_moderation_bots_in_the_reduced_shape() {
    let w = world().await;
    let mut watcher = crossnode::ws(&w.node, &w.watcher.secret).await;
    let mut plain = crossnode::ws(&w.node, &w.plain.secret).await;
    let mut blind = crossnode::ws(&w.node, &w.blind.secret).await;
    let (id, _) = report_message(&w, &w.bob, "carol said spam").await;
    let created = crossnode::event(&mut watcher, "report.create").await;
    assert_eq!(created["report"]["id"], id.as_str());
    assert_eq!(
        (created["report"]["scope"].as_str(), created["report"]["room_id"].as_str()),
        (Some("room"), Some(w.room_id.as_str()))
    );
    for field in ["detail", "evidence", "snapshot", "reporter", "reporter_id"] {
        assert!(created["report"].get(field).is_none(), "{field}: {created}");
    }
    assert!(!created.to_string().contains("bob@"), "{created}");
    let (s, j) = w.node.patch(&format!("/api/v1/reports/{id}"), &w.alice.token, json!({ "status": "resolved" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let updated = crossnode::event(&mut watcher, "report.update").await;
    assert_eq!((updated["id"].as_str(), updated["status"].as_str()), (Some(id.as_str()), Some("resolved")));
    assert!(updated.get("note").is_none() && updated.get("detail").is_none(), "{updated}");
    // Without `moderate_members` (plain) or without the scope (blind): nothing.
    assert!(crossnode::no_event(&mut plain, "report.create", 300).await);
    assert!(crossnode::no_event(&mut blind, "report.create", 300).await);
    assert!(crossnode::no_event(&mut blind, "report.update", 100).await);

    // Node reports and reports about the bot itself never reach it.
    report(
        &w.node,
        &w.bob.token,
        json!({ "kind": "user", "user": "alice@t.local", "room_id": w.room_id, "category": "other" }),
    )
    .await;
    report(
        &w.node,
        &w.carol.token,
        json!({ "kind": "user", "user": format!("{}@{DOMAIN}", w.watcher.username), "room_id": w.room_id,
            "category": "spam" }),
    )
    .await;
    assert!(crossnode::no_event(&mut watcher, "report.create", 300).await);
}
