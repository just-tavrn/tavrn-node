// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Message components (protocol/APPLICATIONS.md §5.10): components on bots' messages only, component interactions
//! with every check of §5.10.2 in order, the `update` and `modal` responses, modal submits, ephemeral replies under
//! the message, encrypted conversations (ciphertext passthrough), removed applications, expired messages, the
//! permission `use_components` and its fixup.

use crate::common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Method, Request, StatusCode, header},
    routing::post,
};
use common::{Session, TestNode, body_bytes, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_crypto::MasterSecret;
use tavrn_node::{
    hub::{Event, Scope},
    interactions::{ManualClock, ReceiverGuard},
    permissions as p, util,
};
use tokio::sync::broadcast;
use tower::ServiceExt;

const D: &str = common::e2ee::DOMAIN;

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn path_of(j: &Value) -> &str {
    j["meta"]["path"].as_str().unwrap_or("")
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

async fn bot(node: &TestNode, owner: &Session, name: &str) -> Bot {
    let body = json!({ "name": name, "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) });
    let (s, app) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (s, t) =
        node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, json!({ "name": "main" })).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let (_, commands) = node
        .put(
            &format!("/api/v1/applications/{app_id}/commands"),
            &owner.token,
            json!({ "commands": [ { "name": "note", "description": "Leave a note" } ] }),
        )
        .await;
    assert!(commands["commands"].is_array(), "{commands}");
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
        device_id: t["token"]["device_id"].as_str().unwrap().into(),
    }
}

async fn member(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn install(node: &TestNode, token: &str, room_id: &str, b: &Bot) {
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            token,
            json!({ "application": b.reference(), "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

/// A plaintext room of carol with alice's bot installed and bob as a member.
struct World {
    node: TestNode,
    alice: Session,
    carol: Session,
    bob: Session,
    bot: Bot,
    room_id: String,
    channel: String,
    /// The `@everyone` role of the room.
    everyone: Value,
}

async fn world_with(node: TestNode) -> World {
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let b = bot(&node, &alice, "Raid").await;
    let room = node.plaintext_room(&carol.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap().clone();
    member(&node, &carol, &room_id, &bob).await;
    install(&node, &carol.token, &room_id, &b).await;
    World { node, alice, carol, bob, bot: b, room_id, channel, everyone }
}

async fn world() -> World {
    world_with(test_node(D).await).await
}

/// The raid card: Sign up / Decline / a disabled button / a link, and a class select (1–2 of 3).
fn card() -> Value {
    json!({ "type": "text", "body": "Raid on Friday", "components": [
        { "type": "row", "components": [
            { "type": "button", "style": "success", "label": "Sign up", "emoji": "✅", "custom_id": "signup" },
            { "type": "button", "style": "danger", "label": "Decline", "custom_id": "decline" },
            { "type": "button", "style": "secondary", "label": "Closed", "custom_id": "closed", "disabled": true },
            { "type": "button", "style": "link", "label": "Guide", "url": "https://guide.example/raid" } ] },
        { "type": "row", "components": [
            { "type": "select", "custom_id": "class", "placeholder": "Your class", "min": 1, "max": 2, "options": [
                { "label": "Tank", "value": "tank" }, { "label": "Healer", "value": "healer" },
                { "label": "Damage", "value": "dps" } ] } ] } ] })
}

async fn post_as(node: &TestNode, token: &str, conversation: &str, content: Value) -> (StatusCode, Value) {
    node.post(&format!("/api/v1/conversations/{conversation}/messages"), token, json!({ "content": content })).await
}

/// The bot posts the card; returns the message id.
async fn bot_card(w: &World) -> String {
    let (s, m) = post_as(&w.node, &w.bot.secret, &w.channel, card()).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    m["id"].as_str().unwrap().to_string()
}

fn invoke_path(conversation: &str, message: &str) -> String {
    format!("/api/v1/conversations/{conversation}/messages/{message}/interactions")
}

fn spawn_post(node: &TestNode, path: String, token: &str, body: Value) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let router: Router = node.router.clone();
    let token = token.to_string();
    tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_LANGUAGE, "de")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    })
}

/// A receiving connection of the bot, listening on the hub.
struct Receiver {
    guard: ReceiverGuard,
    rx: broadcast::Receiver<Arc<Event>>,
}

fn receiver(node: &TestNode, b: &Bot) -> Receiver {
    let rx = node.state.hub.subscribe();
    let guard = node.state.interactions.register(&b.user_id, &b.device_id);
    Receiver { guard, rx }
}

impl Receiver {
    async fn event(&mut self, kind: &str) -> Value {
        let id = self.guard.id;
        let deadline = common::deadline(Duration::from_secs(5));
        loop {
            let ev = tokio::time::timeout_at(deadline, self.rx.recv()).await.expect("no event").unwrap();
            if ev.kind == kind && matches!(ev.scope, Scope::Connection(c) if c == id) {
                return ev.data.clone();
            }
        }
    }
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

fn callback(id: &str) -> String {
    format!("/api/v1/interactions/{id}/callback")
}

fn submit(id: &str) -> String {
    format!("/api/v1/interactions/{id}/submit")
}

fn note_modal() -> Value {
    json!({ "custom_id": "raid:note", "title": "A note for the lead", "inputs": [
        { "custom_id": "note", "label": "Note", "style": "paragraph", "max_length": 50, "required": false },
        { "custom_id": "name", "label": "Character", "style": "short", "min_length": 2 } ] })
}

fn spec_modal() -> Value {
    json!({ "custom_id": "raid:spec", "title": "Your specialization", "inputs": [
        { "custom_id": "spec", "label": "Specialization", "style": "select", "value": "protection", "options": [
            { "label": "Protection", "value": "protection", "description": "Tank", "emoji": "🛡️" },
            { "label": "Holy", "value": "holy" } ] },
        { "custom_id": "backup", "label": "Backup", "style": "select", "required": false,
          "options": [{ "label": "Holy", "value": "holy" }] } ] })
}

#[tokio::test]
async fn modal_selects_validate_choices_and_keep_invoker_and_once_only_guards() {
    let w = world().await;
    let node = &w.node;
    let (_, info) = node.get_auth("/api/v1/node", &w.bob.token).await;
    assert!(info["capabilities"].as_array().unwrap().iter().any(|c| c == "components.modal_select.v1"));
    let message = bot_card(&w).await;
    let mut r = receiver(node, &w.bot);
    let task = spawn_post(
        node,
        invoke_path(&w.channel, &message),
        &w.bob.token,
        json!({ "custom_id": "class", "values": ["tank"] }),
    );
    let parent = r.event("component.invoke").await["interaction_id"].as_str().unwrap().to_string();
    let mut bad = spec_modal();
    bad["inputs"][0]["options"][0]["default"] = json!(true);
    let (s, j) = node.post(&callback(&parent), &w.bot.secret, json!({ "type": "modal", "modal": bad })).await;
    assert_eq!(
        (s, code(&j), path_of(&j)),
        (StatusCode::BAD_REQUEST, "interaction.modal_invalid", "inputs[0].options[0].default")
    );
    let (s, j) = node.post(&callback(&parent), &w.bot.secret, json!({ "type": "modal", "modal": spec_modal() })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, response) = task.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{response}");
    assert_eq!(response["modal"], spec_modal());
    let (s, j) = node.post(&submit(&parent), &w.carol.token, json!({ "values": { "spec": "holy" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "interaction.not_invoker"));
    for (values, field) in [
        (json!({}), "values.spec"),
        (json!({ "spec": "" }), "values.spec"),
        (json!({ "spec": "other-class" }), "values.spec"),
        (json!({ "spec": ["holy"] }), "values.spec"),
        (json!({ "spec": "holy", "backup": "protection" }), "values.backup"),
        (json!({ "spec": "holy", "unknown": "holy" }), "values.unknown"),
    ] {
        let (s, j) = node.post(&submit(&parent), &w.bob.token, json!({ "values": values })).await;
        assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "interaction.values_invalid", field), "{j}");
    }
    let task = spawn_post(node, submit(&parent), &w.bob.token, json!({ "values": { "spec": "holy", "backup": "" } }));
    let data = r.event("modal.submit").await;
    assert_eq!(data["values"], json!({ "spec": "holy", "backup": "" }));
    assert_eq!(data["modal_custom_id"], "raid:spec");
    let id = data["interaction_id"].as_str().unwrap();
    let (s, j) = node.post(&callback(id), &w.bot.secret,
        json!({ "type": "reply", "ephemeral": true, "content": { "type": "text", "body": "Specialization saved" } })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(task.await.unwrap().1["ephemeral"]["content"]["body"], "Specialization saved");
    let (s, j) = node.post(&submit(&parent), &w.bob.token, json!({ "values": { "spec": "holy" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "interaction.already_submitted"));
}

// ---------------------------------------------------------------- content (§5.10.1)

#[tokio::test]
async fn components_travel_on_bots_messages_only() {
    let w = world().await;
    let (node, bob) = (&w.node, &w.bob);
    // A person cannot plant buttons that look like an application's.
    let (s, j) = post_as(node, &bob.token, &w.channel, card()).await;
    assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "message.components_invalid", "components"));
    let (s, j) = post_as(node, &bob.token, &w.channel, json!({ "type": "text", "body": "x", "components": [] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.components_invalid"), "an empty array too");
    let (s, _) =
        post_as(node, &bob.token, &w.channel, json!({ "type": "text", "body": "x", "components": null })).await;
    assert_eq!(s, StatusCode::CREATED, "null is absent");
    // The bot may; the body may be empty with components.
    let (s, m) = post_as(node, &w.bot.secret, &w.channel, card()).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["content"]["components"][1]["components"][0]["custom_id"], "class");
    assert_eq!(m["author_kind"], "bot");
    let only = json!({ "type": "text", "body": "", "components": card()["components"] });
    let (s, j) = post_as(node, &w.bot.secret, &w.channel, only).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // Invalid components name the first offending field, for bots too; only `text` carries them.
    let mut bad = card();
    bad["components"][1]["components"][0]["options"][2]["value"] = json!("tank");
    let (s, j) = post_as(node, &w.bot.secret, &w.channel, bad).await;
    assert_eq!(
        (s, code(&j), path_of(&j)),
        (StatusCode::BAD_REQUEST, "message.components_invalid", "components[1].components[0].options[2].value")
    );
    let action = json!({ "type": "action", "body": "waves", "components": card()["components"] });
    let (s, j) = post_as(node, &w.bot.secret, &w.channel, action).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.components_invalid"));
    // Values content objects never travel as messages.
    for t in ["component.values", "modal.values"] {
        let (s, j) = post_as(node, &bob.token, &w.channel, json!({ "type": t, "body": "x" })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.type_reserved"), "{t}");
    }
    // Edits: a person cannot add components; the bot can change them.
    let (_, mine) = node.send(&bob.token, &w.room_id, &w.channel, "plain").await;
    let edit = format!("/api/v1/conversations/{}/messages/{}", w.channel, mine["id"].as_str().unwrap());
    let (s, j) = node.patch(&edit, &bob.token, json!({ "content": card() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "message.components_invalid"));
    let edit = format!("/api/v1/conversations/{}/messages/{}", w.channel, m["id"].as_str().unwrap());
    let mut changed = card();
    changed["components"][0]["components"][0]["disabled"] = json!(true);
    let (s, j) = node.patch(&edit, &w.bot.secret, json!({ "content": changed })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["content"]["components"][0]["components"][0]["disabled"], true);
    // Webhooks never carry components.
    let (s, hook) = node
        .post(
            &format!("/api/v1/rooms/{}/channels/{}/webhooks", w.room_id, w.channel),
            &w.carol.token,
            json!({ "name": "CI" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{hook}");
    let url = hook["url"].as_str().unwrap();
    let exec = url[url.find("/api/v1/").unwrap()..].to_string();
    let (s, j) = node.req(Method::POST, &exec, None, Some(json!({ "content": card() }))).await;
    assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "message.components_invalid", "components"));
}

// ---------------------------------------------------------------- happy paths (§5.10.2–§5.10.4)

#[tokio::test]
async fn buttons_selects_updates_and_modals() {
    let w = world().await;
    let (node, bob) = (&w.node, &w.bob);
    let message = bot_card(&w).await;
    let path = invoke_path(&w.channel, &message);
    let mut r = receiver(node, &w.bot);

    // A button → a stored reply with the envelope field `interaction` of kind component.
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "custom_id": "signup" }));
    let data = r.event("component.invoke").await;
    assert_eq!(
        (data["message_id"].as_str(), data["custom_id"].as_str(), data["values"].clone()),
        (Some(message.as_str()), Some("signup"), Value::Null)
    );
    assert_eq!(
        (data["user"].as_str(), data["device_id"].as_str()),
        (Some(format!("bob@{D}").as_str()), Some(bob.device_id.as_str()))
    );
    assert_eq!((data["encrypted"].as_bool(), data["locale"].as_str()), (Some(false), Some("de")));
    assert_eq!(
        (data["channel_id"].as_str(), data["application_id"].as_str()),
        (Some(w.channel.as_str()), Some(w.bot.app_id.as_str()))
    );
    assert!(data["permissions"].as_str().unwrap().parse::<u64>().unwrap() & p::USE_COMPONENTS != 0);
    let id = data["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &callback(&id),
            &w.bot.secret,
            json!({ "type": "reply", "content": { "type": "text", "body": "Signed up" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, res) = task.await.unwrap();
    assert_eq!((s, res["outcome"].as_str()), (StatusCode::OK, Some("reply")), "{res}");
    assert_eq!(res["modal"], Value::Null);
    let interaction = &res["message"]["interaction"];
    assert_eq!(interaction["kind"], "component");
    assert_eq!(interaction["command"], Value::Null);
    assert_eq!(interaction["message_id"], message.as_str());
    assert_eq!(interaction["user"], format!("bob@{D}"));

    // A select → an ephemeral reply under the message, also to bob's other connections.
    let mut events = node.state.hub.subscribe();
    let task =
        spawn_post(node, path.clone(), &bob.token, json!({ "custom_id": "class", "values": ["healer", "tank"] }));
    let data = r.event("component.invoke").await;
    assert_eq!(data["values"], json!(["healer", "tank"]));
    let id = data["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &callback(&id),
            &w.bot.secret,
            json!({ "type": "reply", "ephemeral": true, "content": { "type": "text", "body": "Healer and tank" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["ephemeral"]["message_id"], message.as_str());
    let ev = hub_event(&mut events, "interaction.reply").await;
    assert_eq!(ev.data["message_id"], message.as_str());
    // A follow-up of a component interaction is ephemeral under the message as well.
    let (s, j) = node
        .post(
            &format!("/api/v1/interactions/{id}/messages"),
            &w.bot.secret,
            json!({ "ephemeral": true, "content": { "type": "text", "body": "Also noted" } }),
        )
        .await;
    assert_eq!((s, j["ephemeral"]["message_id"].as_str()), (StatusCode::CREATED, Some(message.as_str())), "{j}");

    // A button → `update` edits the card through the normal edit path.
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "custom_id": "decline" }));
    let id = r.event("component.invoke").await["interaction_id"].as_str().unwrap().to_string();
    let mut updated = card();
    updated["body"] = json!("Raid on Friday: 1 declined");
    updated["components"][0]["components"][1]["disabled"] = json!(true);
    let (s, j) = node.post(&callback(&id), &w.bot.secret, json!({ "type": "update", "content": updated })).await;
    assert_eq!((s, j["outcome"].as_str()), (StatusCode::OK, Some("update")), "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["outcome"], "update");
    assert_eq!(res["message"]["id"], message.as_str());
    assert!(res["message"]["edited_at"].is_string());
    assert_eq!(hub_event(&mut events, "message.update").await.data["id"], message.as_str());
    // The node checks the current content: the button is disabled now.
    let (s, j) = node.post(&path, &bob.token, json!({ "custom_id": "decline" })).await;
    assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "component.values_invalid", "custom_id"));

    // A button → a modal for bob's device → submit → a reply.
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "custom_id": "signup" }));
    let parent = r.event("component.invoke").await["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node.post(&callback(&parent), &w.bot.secret, json!({ "type": "modal", "modal": note_modal() })).await;
    assert_eq!((s, j["outcome"].as_str()), (StatusCode::OK, Some("modal")), "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!((res["outcome"].as_str(), res["modal"]["custom_id"].as_str()), (Some("modal"), Some("raid:note")));
    // Only the invoker submits, with values that fit the definition the node kept.
    let (s, j) = node.post(&submit(&parent), &w.carol.token, json!({ "values": { "name": "Thrall" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "interaction.not_invoker"));
    let (s, j) = node.post(&submit(&parent), &w.bot.secret, json!({ "values": { "name": "Thrall" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    for (values, field) in [
        (json!({}), "values.name"),
        (json!({ "name": "T" }), "values.name"),
        (json!({ "name": "Thrall", "level": "60" }), "values.level"),
        (json!({ "name": "Thrall", "note": "x".repeat(51) }), "values.note"),
        (json!("Thrall"), "values"),
    ] {
        let (s, j) = node.post(&submit(&parent), &bob.token, json!({ "values": values })).await;
        assert_eq!(
            (s, code(&j), path_of(&j)),
            (StatusCode::BAD_REQUEST, "interaction.values_invalid", field),
            "{values}"
        );
    }
    let (s, j) = node
        .post(
            &submit(&parent),
            &bob.token,
            json!({ "values": { "name": "Thrall" }, "values_ciphertext": "AAAA", "epoch": 1 }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let task = spawn_post(node, submit(&parent), &bob.token, json!({ "values": { "name": "Thrall", "note": "late" } }));
    let data = r.event("modal.submit").await;
    assert_eq!(data["parent_interaction_id"], parent.as_str());
    assert_eq!(data["modal_custom_id"], "raid:note");
    assert_eq!((data["message_id"].as_str(), data["custom_id"].as_str()), (Some(message.as_str()), Some("signup")));
    assert_eq!(data["command"], Value::Null);
    assert_eq!(data["values"], json!({ "name": "Thrall", "note": "late" }));
    let id = data["interaction_id"].as_str().unwrap().to_string();
    assert_ne!(id, parent, "a new interaction");
    // A modal cannot answer a modal; a reply can.
    let (s, j) = node.post(&callback(&id), &w.bot.secret, json!({ "type": "modal", "modal": note_modal() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.modal_nested"));
    let (s, j) = node
        .post(
            &callback(&id),
            &w.bot.secret,
            json!({ "type": "reply", "content": { "type": "text", "body": "Noted, Thrall" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["message"]["interaction"]["kind"], "modal");
    assert_eq!(res["message"]["interaction"]["message_id"], message.as_str());
    // Each modal is submitted once.
    let (s, j) = node.post(&submit(&parent), &bob.token, json!({ "values": { "name": "Thrall" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "interaction.already_submitted"));
    // An interaction that did not answer with a modal has nothing to submit.
    let (s, j) = node.post(&submit(&id), &bob.token, json!({ "values": {} })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "interaction.not_found"));
    let (s, j) = node.post(&submit(&util::ulid()), &bob.token, json!({ "values": {} })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "interaction.not_found"));
}

#[tokio::test]
async fn commands_answer_with_modals_but_cannot_update() {
    let w = world().await;
    let (node, bob) = (&w.node, &w.bob);
    let (_, set) = node.get_auth(&format!("/api/v1/applications/{}/commands", w.bot.app_id), &w.alice.token).await;
    let command = format!("{}/{}", w.bot.reference(), set["commands"][0]["id"].as_str().unwrap());
    let mut r = receiver(node, &w.bot);
    let invoke = format!("/api/v1/conversations/{}/interactions", w.channel);

    let task = spawn_post(node, invoke.clone(), &bob.token, json!({ "command": command }));
    let id = r.event("command.invoke").await["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(&callback(&id), &w.bot.secret, json!({ "type": "update", "content": { "type": "text", "body": "x" } }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.update_unsupported"));
    // An invalid modal names the field; nothing was answered, so a valid one follows.
    let mut bad = note_modal();
    bad["inputs"][1]["style"] = json!("long");
    let (s, j) = node.post(&callback(&id), &w.bot.secret, json!({ "type": "modal", "modal": bad })).await;
    assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "interaction.modal_invalid", "inputs[1].style"));
    let (s, j) = node.post(&callback(&id), &w.bot.secret, json!({ "type": "modal" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.modal_invalid"));
    let (s, _) = node.post(&callback(&id), &w.bot.secret, json!({ "type": "modal", "modal": note_modal() })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(task.await.unwrap().1["outcome"], "modal");
    let task = spawn_post(node, submit(&id), &bob.token, json!({ "values": { "name": "Jaina" } }));
    let data = r.event("modal.submit").await;
    assert_eq!(data["command"]["name"], "note");
    assert_eq!((data["message_id"].clone(), data["custom_id"].clone()), (Value::Null, Value::Null));
    let sub = data["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(&callback(&sub), &w.bot.secret, json!({ "type": "update", "content": { "type": "text", "body": "x" } }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.update_unsupported"), "no message to update");
    let (s, _) = node
        .post(
            &callback(&sub),
            &w.bot.secret,
            json!({ "type": "reply", "ephemeral": true, "content": { "type": "text", "body": "Saved" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, res) = task.await.unwrap();
    assert_eq!((res["outcome"].as_str(), res["ephemeral"]["message_id"].clone()), (Some("reply"), Value::Null));
}

// ---------------------------------------------------------------- refusals (§5.10.2)

#[tokio::test]
async fn invocation_checks_run_in_order() {
    let w = world().await;
    let (node, bob, carol) = (&w.node, &w.bob, &w.carol);
    let message = bot_card(&w).await;
    let path = invoke_path(&w.channel, &message);
    let ok = json!({ "custom_id": "signup" });

    // Bots never click; strangers do not see the conversation.
    let (s, j) = node.post(&path, &w.bot.secret, ok.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    let stranger = node.register("stranger").await;
    let (s, _) = node.post(&path, &stranger.token, ok.clone()).await;
    assert!(s == StatusCode::NOT_FOUND || s == StatusCode::FORBIDDEN, "{s}");

    // 1. use_components, deniable per channel.
    let everyone = w.everyone["id"].as_str().unwrap().to_string();
    let override_path = format!("/api/v1/rooms/{}/overrides", w.room_id);
    let deny = json!({ "target_type": "channel", "target_id": w.channel, "subject_type": "role", "subject_id": everyone,
                       "allow": "0", "deny": p::USE_COMPONENTS.to_string() });
    let (s, j) = node.put(&override_path, &carol.token, deny).await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post(&path, &bob.token, ok.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "component.forbidden"));
    let neutral = json!({ "target_type": "channel", "target_id": w.channel, "subject_type": "role", "subject_id": everyone,
                          "allow": "0", "deny": p::SEND_MESSAGES.to_string() });
    let (s, j) = node.put(&override_path, &carol.token, neutral).await;
    assert!(s.is_success(), "{j}");

    // 2. a message of a bot of an installed application in this conversation.
    let (s, j) = node.post(&invoke_path(&w.channel, &util::ulid()), &bob.token, ok.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "component.not_found"));
    let (_, own) = post_as(node, &carol.token, &w.channel, json!({ "type": "text", "body": "mine" })).await;
    let (s, j) = node.post(&invoke_path(&w.channel, own["id"].as_str().unwrap()), &bob.token, ok.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "component.not_found"), "a person's message");
    let (_, other_channel) = node
        .post(
            &format!("/api/v1/rooms/{}/channels", w.room_id),
            &carol.token,
            json!({ "kind": "text", "name": "other", "encrypted": false }),
        )
        .await;
    let other = other_channel["id"].as_str().unwrap();
    let (s, j) = node.post(&invoke_path(other, &message), &bob.token, ok.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "component.not_found"), "another conversation's message");

    // 3. the values: the component must exist and be enabled; values must fit it.
    for (body, field) in [
        (json!({ "custom_id": "nope" }), "custom_id"),
        (json!({ "custom_id": "closed" }), "custom_id"),
        (json!({ "custom_id": "" }), "custom_id"),
        (json!({ "custom_id": "x".repeat(101) }), "custom_id"),
        (json!({ "custom_id": "signup", "values": ["a"] }), "values"),
        (json!({ "custom_id": "class" }), "values"),
        (json!({ "custom_id": "class", "values": ["tank", "healer", "dps"] }), "values"),
        (json!({ "custom_id": "class", "values": ["tank", "mage"] }), "values[1]"),
        (json!({ "custom_id": "class", "values": [1] }), "values[0]"),
    ] {
        let (s, j) = node.post(&path, &bob.token, body.clone()).await;
        assert_eq!((s, code(&j), path_of(&j)), (StatusCode::BAD_REQUEST, "component.values_invalid", field), "{body}");
    }
    let (s, j) =
        node.post(&path, &bob.token, json!({ "custom_id": "signup", "values_ciphertext": "AAAA", "epoch": 1 })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let (s, _) = node.post(&path, &bob.token, json!({ "custom_id": "signup", "thread_id": util::ulid() })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the thread is the message's");
    let (s, _) = node.post(&path, &bob.token, json!({ "custom_id": "signup", "extra": 1 })).await;
    assert!(s.is_client_error(), "unknown fields");

    // No receiver: the application is offline. 4. 5 interactions per 5 seconds and user.
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(node.post(&path, &bob.token, ok.clone()).await.0);
    }
    assert_eq!(statuses[0], StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(statuses[5], StatusCode::TOO_MANY_REQUESTS, "{statuses:?}");

    // A removed application: its messages lose their components.
    let (s, j) = node
        .delete(
            &format!("/api/v1/rooms/{}/applications/{}", w.room_id, w.bot.reference().replace('/', "%2F")),
            &carol.token,
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post(&path, &carol.token, ok).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "component.not_found"));
}

#[tokio::test]
async fn components_expire_with_the_message_age() {
    let w = world().await;
    let node = &w.node;
    let message = bot_card(&w).await;
    let path = invoke_path(&w.channel, &message);
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    node.state.interactions.set_clock(clock.clone());
    clock.advance(chrono::Duration::days(29));
    let (s, j) = node.post(&path, &w.bob.token, json!({ "custom_id": "signup" })).await;
    assert_eq!((s, code(&j)), (StatusCode::SERVICE_UNAVAILABLE, "interaction.app_offline"), "still usable");
    clock.advance(chrono::Duration::days(2));
    let (s, j) = node.post(&path, &w.bob.token, json!({ "custom_id": "signup" })).await;
    assert_eq!((s, code(&j)), (StatusCode::GONE, "component.expired"));

    // TAVRN_COMPONENT_MAX_AGE_DAYS = 0: no limit.
    let w = world_with(test_node_with(D, |c| c.component_max_age_days = 0).await).await;
    let message = bot_card(&w).await;
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    w.node.state.interactions.set_clock(clock.clone());
    clock.advance(chrono::Duration::days(3650));
    let (s, j) = w.node.post(&invoke_path(&w.channel, &message), &w.bob.token, json!({ "custom_id": "signup" })).await;
    assert_eq!((s, code(&j)), (StatusCode::SERVICE_UNAVAILABLE, "interaction.app_offline"));
}

#[tokio::test]
async fn modals_expire_with_their_interaction() {
    let w = world().await;
    let node = &w.node;
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    node.state.interactions.set_clock(clock.clone());
    let message = bot_card(&w).await;
    let mut r = receiver(node, &w.bot);
    let task = spawn_post(node, invoke_path(&w.channel, &message), &w.bob.token, json!({ "custom_id": "signup" }));
    let parent = r.event("component.invoke").await["interaction_id"].as_str().unwrap().to_string();
    node.post(&callback(&parent), &w.bot.secret, json!({ "type": "modal", "modal": spec_modal() })).await;
    assert_eq!(task.await.unwrap().1["outcome"], "modal");
    clock.advance(chrono::Duration::minutes(16));
    let (s, j) = node.post(&submit(&parent), &w.bob.token, json!({ "values": { "spec": "holy" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::GONE, "interaction.expired"));
}

// ---------------------------------------------------------------- encrypted conversations

#[tokio::test]
async fn encrypted_conversations_pass_ciphertext_values() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let mut carol = node.crypto_user("carol").await;
    let b = bot(&node, &alice, "Cipher").await;
    let room = node.create_room(carol.token(), "Secret").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    install(&node, carol.token(), &room_id, &b).await;
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), carol.token(), json!({ "bots_allowed": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let master = MasterSecret::generate().unwrap();
    node.put_identity(&b.session(), &master).await;
    let mut bot_dev = node.attest(b.session(), master, 2).await;
    node.create_group(&mut carol, &channel).await;
    node.add_user(&mut carol, &channel, &b.username).await;
    assert_eq!(node.accept_welcomes(&mut bot_dev).await, 1);
    let q = common::e2ee::qualified(&channel);

    // The bot's card is ciphertext; the node cannot see its components.
    let ct = bot_dev.client.encrypt_content(&q, &card().to_string()).unwrap();
    let epoch = bot_dev.client.current_epoch(&q).unwrap();
    let (s, m) = node
        .post(&format!("/api/v1/conversations/{channel}/messages"), &b.secret, json!({ "content": ct, "epoch": epoch }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let message = m["id"].as_str().unwrap().to_string();
    let path = invoke_path(&channel, &message);

    // Plaintext values are refused; the ciphertext is checked like command arguments.
    let (s, j) = node.post(&path, carol.token(), json!({ "custom_id": "class", "values": ["tank"] })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let (s, j) = node.post(&path, carol.token(), json!({ "custom_id": "class" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.ciphertext_invalid"));
    let values = json!({ "type": "component.values", "message_id": message, "custom_id": "class", "values": ["tank"],
                         "nonce": "AAAAAAAAAAAAAAAAAAAAAA", "issued_at": util::now() });
    let vct = carol.client.encrypt_content(&q, &values.to_string()).unwrap();
    let vepoch = carol.client.current_epoch(&q).unwrap() as i64;
    let (s, j) = node
        .post(&path, carol.token(), json!({ "custom_id": "class", "values_ciphertext": vct, "epoch": vepoch + 3 }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.ciphertext_invalid"));

    // Passed through unread; any custom_id is accepted since the node cannot know the components.
    let mut r = receiver(&node, &b);
    let task = spawn_post(
        &node,
        path.clone(),
        carol.token(),
        json!({ "custom_id": "class", "values_ciphertext": vct, "epoch": vepoch }),
    );
    let data = r.event("component.invoke").await;
    assert_eq!(
        (data["encrypted"].as_bool(), data["values"].clone(), data["epoch"].as_i64()),
        (Some(true), Value::Null, Some(vepoch))
    );
    let plain = bot_dev
        .client
        .decrypt_content(
            &q,
            &format!("carol@{D}"),
            &carol.session.device_id,
            data["values_ciphertext"].as_str().unwrap(),
            Some(&carol.client.device().public_key()),
        )
        .unwrap();
    let decoded: Value = serde_json::from_str(&plain).unwrap();
    assert_eq!((decoded["custom_id"].as_str(), decoded["values"].clone()), (Some("class"), json!(["tank"])));
    // The bot opens a modal; carol submits encrypted values.
    let parent = data["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node.post(&callback(&parent), &b.secret, json!({ "type": "modal", "modal": spec_modal() })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(task.await.unwrap().1["outcome"], "modal");
    let (s, j) = node.post(&submit(&parent), carol.token(), json!({ "values": { "spec": "holy" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let form = json!({ "type": "modal.values", "interaction": parent, "custom_id": "raid:spec", "values": { "spec": "holy" },
                       "nonce": "AQAAAAAAAAAAAAAAAAAAAA", "issued_at": util::now() });
    let fct = carol.client.encrypt_content(&q, &form.to_string()).unwrap();
    let task = spawn_post(&node, submit(&parent), carol.token(), json!({ "values_ciphertext": fct, "epoch": vepoch }));
    let data = r.event("modal.submit").await;
    assert_eq!((data["values"].clone(), data["values_ciphertext"].as_str()), (Value::Null, Some(fct.as_str())));
    let plain = bot_dev
        .client
        .decrypt_content(
            &q,
            &format!("carol@{D}"),
            &carol.session.device_id,
            data["values_ciphertext"].as_str().unwrap(),
            Some(&carol.client.device().public_key()),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&plain).unwrap()["values"], json!({ "spec": "holy" }));
    let sub = data["interaction_id"].as_str().unwrap().to_string();
    // `update` in an encrypted conversation: the bot's ciphertext replaces the card (plaintext is a mismatch).
    let (s, j) = node.post(&callback(&sub), &b.secret, json!({ "type": "update", "content": card() })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let mut next = card();
    next["body"] = json!("Thrall signed up");
    let nct = bot_dev.client.encrypt_content(&q, &next.to_string()).unwrap();
    let (s, j) = node
        .post(
            &callback(&sub),
            &b.secret,
            json!({ "type": "update", "content": nct, "epoch": bot_dev.client.current_epoch(&q).unwrap() }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!((res["outcome"].as_str(), res["message"]["content"].as_str()), (Some("update"), Some(nct.as_str())));

    // A member's ciphertext may carry components, but nobody can click them: the node knows the author.
    let mine = carol.client.encrypt_content(&q, &card().to_string()).unwrap();
    let (s, m) = node
        .post(
            &format!("/api/v1/conversations/{channel}/messages"),
            carol.token(),
            json!({ "content": mine, "epoch": vepoch }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let (s, j) = node
        .post(
            &invoke_path(&channel, m["id"].as_str().unwrap()),
            carol.token(),
            json!({ "custom_id": "class", "values_ciphertext": vct, "epoch": vepoch }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "component.not_found"));
    assert_eq!(b.address(), format!("{}@{D}", b.username));
}

// ---------------------------------------------------------------- permission and fixup

#[tokio::test]
async fn use_components_defaults_and_the_one_time_fixup() {
    let w = world().await;
    let (node, carol) = (&w.node, &w.carol);
    let everyone = w.everyone.clone();
    assert!(p::has(everyone["permissions"].as_str().unwrap().parse::<u64>().unwrap(), p::USE_COMPONENTS), "a default");
    let (s, readers) = node
        .post(
            &format!("/api/v1/rooms/{}/roles", w.room_id),
            &carol.token,
            json!({ "name": "Readers", "permissions": mask(&[p::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{readers}");
    let (s, writers) = node
        .post(
            &format!("/api/v1/rooms/{}/roles", w.room_id),
            &carol.token,
            json!({ "name": "Writers", "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{writers}");
    // As on a node from before the bit.
    sqlx::query("UPDATE roles SET permissions = permissions - $1 WHERE (permissions & $1) <> 0")
        .bind(p::USE_COMPONENTS as i64)
        .execute(&node.state.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_settings WHERE key = $1")
        .bind(tavrn_node::fixups::USE_COMPONENTS_MARKER)
        .execute(&node.state.db)
        .await
        .unwrap();
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert!(report.use_components_roles >= 2, "{report:?}");
    let bits = |id: &str| {
        let (db, id) = (node.state.db.clone(), id.to_string());
        async move {
            let v: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap();
            v as u64
        }
    };
    assert!(p::has(bits(everyone["id"].as_str().unwrap()).await, p::USE_COMPONENTS), "@everyone could write");
    assert!(p::has(bits(writers["id"].as_str().unwrap()).await, p::USE_COMPONENTS));
    assert!(!p::has(bits(readers["id"].as_str().unwrap()).await, p::USE_COMPONENTS), "readers could not");
    let report = tavrn_node::fixups::run(&node.state.db).await.unwrap();
    assert_eq!(report.use_components_roles, 0, "runs once");
    // The node announces the capability.
    let (_, info) = node.get_auth("/api/v1/node", &carol.token).await;
    assert!(info.to_string().contains("components.v1"), "{info}");
}

// ---------------------------------------------------------------- interactions URL

/// An interactions URL that answers the ping and then the queued answers in order.
#[derive(Clone, Default)]
struct UrlBot {
    got: Arc<Mutex<Vec<Value>>>,
    answers: Arc<Mutex<Vec<Value>>>,
}

async fn url_receive(State(r): State<UrlBot>, body: Bytes) -> axum::Json<Value> {
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    r.got.lock().unwrap().push(parsed.clone());
    if parsed["type"] == "ping" {
        return axum::Json(json!({ "challenge": parsed["challenge"] }));
    }
    let mut answers = r.answers.lock().unwrap();
    axum::Json(if answers.is_empty() { json!({ "type": "defer" }) } else { answers.remove(0) })
}

#[tokio::test]
async fn the_interactions_url_gets_components_and_modal_submits() {
    let w = world().await;
    let node = &w.node;
    let message = bot_card(&w).await;
    let url_bot = UrlBot::default();
    let app = Router::new().route("/i", post(url_receive)).with_state(url_bot.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (s, j) = node
        .patch(
            &format!("/api/v1/applications/{}", w.bot.app_id),
            &w.alice.token,
            json!({ "interactions_url": format!("http://127.0.0.1:{port}/i") }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    url_bot.answers.lock().unwrap().push(json!({ "type": "modal", "modal": note_modal() }));
    let (s, res) = node.post(&invoke_path(&w.channel, &message), &w.bob.token, json!({ "custom_id": "signup" })).await;
    assert_eq!((s, res["outcome"].as_str()), (StatusCode::OK, Some("modal")), "{res}");
    let parent = res["interaction_id"].as_str().unwrap().to_string();
    let request = url_bot.got.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        (request["type"].as_str(), request["data"]["custom_id"].as_str()),
        (Some("component.invoke"), Some("signup"))
    );
    let mut updated = card();
    updated["body"] = json!("Thrall signed up");
    url_bot.answers.lock().unwrap().push(json!({ "type": "update", "device_id": w.bot.device_id, "content": updated }));
    let (s, res) = node.post(&submit(&parent), &w.bob.token, json!({ "values": { "name": "Thrall" } })).await;
    assert_eq!((s, res["outcome"].as_str()), (StatusCode::OK, Some("update")), "{res}");
    assert_eq!(res["message"]["content"]["body"], "Thrall signed up");
    let request = url_bot.got.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        (request["type"].as_str(), request["data"]["values"]["name"].as_str()),
        (Some("modal.submit"), Some("Thrall"))
    );
}
