// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 5 step 3 (protocol/APPLICATIONS.md §5): command definitions, node approval, per-room settings, the
//! palette, invocations with every check of §5.5 in order, delivery over a bot's WebSocket (round robin) or its
//! interactions URL, the 3-second ack with an injected clock, callbacks, follow-ups, ephemeral replies and
//! encrypted conversations.

use crate::common;

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode, header},
    routing::post,
};
use common::{Session, TestNode, body_bytes, crossnode, federation, test_node, test_node_with};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tavrn_crypto::MasterSecret;
use tavrn_node::{
    hub::{Event, Scope},
    interactions::{ManualClock, ReceiverGuard},
    permissions as p, util,
};
use tokio::sync::broadcast;
use tower::ServiceExt;

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
    /// The bot as a `Session` for the E2EE helpers.
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

/// An application of `owner` with one token.
async fn bot(node: &TestNode, owner: &Session, body: Value, scopes: Option<&[&str]>) -> Bot {
    let (s, app) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (secret, device_id) = token(node, owner, &app_id, scopes).await;
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret,
        device_id,
    }
}

/// Another token (= bot device) of an application: `(secret, device id)`.
async fn token(node: &TestNode, owner: &Session, app_id: &str, scopes: Option<&[&str]>) -> (String, String) {
    let body = match scopes {
        Some(s) => json!({ "name": format!("t{}", util::ulid()), "scopes": s }),
        None => json!({ "name": format!("t{}", util::ulid()) }),
    };
    let (s, t) = node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    (t["secret"].as_str().unwrap().into(), t["token"]["device_id"].as_str().unwrap().into())
}

fn command_set() -> Value {
    json!({ "commands": [
        { "name": "weather", "description": "Forecast for a city", "dm_allowed": true, "args": [
            { "name": "city", "description": "City name", "type": "string", "required": true, "max_length": 100 },
            { "name": "units", "description": "Unit system", "type": "string",
              "options": [ { "name": "Metric", "value": "metric" }, { "name": "Imperial", "value": "imperial" } ] }
        ] },
        { "name": "admin", "description": "For room managers", "default_permissions": p::MANAGE_ROOM.to_string() },
        { "name": "ping", "description": "Pong" }
    ] })
}

/// A room of carol with alice's bot installed, bob as a member, the bot's command set.
struct World {
    node: TestNode,
    alice: Session,
    carol: Session,
    bob: Session,
    bot: Bot,
    room_id: String,
    channel: String,
    /// command name → command ref
    refs: std::collections::HashMap<String, String>,
}

impl World {
    fn r(&self, name: &str) -> String {
        self.refs[name].clone()
    }
}

async fn member(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

async fn world_with(node: TestNode) -> World {
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let b = bot(
        &node,
        &alice,
        json!({ "name": "Weather", "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) }),
        None,
    )
    .await;
    let (s, j) = node.put(&format!("/api/v1/applications/{}/commands", b.app_id), &alice.token, command_set()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let room = node.plaintext_room(&carol.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    member(&node, &carol, &room_id, &bob).await;
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": b.reference(), "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let refs = j_refs(&j, &b, &node, &alice).await;
    World { node, alice, carol, bob, bot: b, room_id, channel, refs }
}

async fn j_refs(_: &Value, b: &Bot, node: &TestNode, alice: &Session) -> std::collections::HashMap<String, String> {
    let (_, set) = node.get_auth(&format!("/api/v1/applications/{}/commands", b.app_id), &alice.token).await;
    set["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap().to_string(), format!("{}/{}", b.reference(), c["id"].as_str().unwrap())))
        .collect()
}

async fn world() -> World {
    world_with(test_node(D).await).await
}

fn invoke_path(conversation: &str) -> String {
    format!("/api/v1/conversations/{conversation}/interactions")
}

/// A request on the router in its own task (invocations wait for the bot's answer).
fn spawn_post(
    node: &TestNode,
    path: String,
    token: &str,
    body: Value,
    language: Option<&'static str>,
) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let router: Router = node.router.clone();
    let token = token.to_string();
    tokio::spawn(async move {
        let mut b = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(l) = language {
            b = b.header(header::ACCEPT_LANGUAGE, l);
        }
        let resp = router.oneshot(b.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    })
}

/// A bot connection registered as an invocation receiver, listening on the hub.
struct Receiver {
    guard: ReceiverGuard,
    rx: broadcast::Receiver<Arc<Event>>,
}

fn receiver(node: &TestNode, bot_user_id: &str, device_id: &str) -> Receiver {
    let rx = node.state.hub.subscribe();
    let guard = node.state.interactions.register(bot_user_id, device_id);
    Receiver { guard, rx }
}

impl Receiver {
    async fn invocation(&mut self) -> Value {
        let id = self.guard.id;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let ev = tokio::time::timeout_at(deadline, self.rx.recv()).await.expect("no invocation").unwrap();
            if ev.kind == "command.invoke" && matches!(ev.scope, Scope::Connection(c) if c == id) {
                return ev.data.clone();
            }
        }
    }
}

async fn hub_event(rx: &mut broadcast::Receiver<Arc<Event>>, kind: &str) -> Arc<Event> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("event missing").unwrap();
        if ev.kind == kind {
            return ev;
        }
    }
}

// ---------------------------------------------------------------- definitions (§5.1)

#[tokio::test]
async fn definitions_owner_and_bot_routes_validation_and_limits() {
    let w = world().await;
    let (node, alice, bob) = (&w.node, &w.alice, &w.bob);
    let path = format!("/api/v1/applications/{}/commands", w.bot.app_id);
    let (s, set) = node.get_auth(&path, &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(set["commands_version"], 1);
    let ids: Vec<String> =
        set["commands"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap().into()).collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(set["commands"][0]["args"][1]["options"][0]["value"], "metric");
    // The public document carries the definitions with their ids.
    let (_, doc) = node.get_auth(&format!("/api/v1/applications/{}/public", w.bot.app_id), &bob.token).await;
    assert_eq!(doc["commands"].as_array().unwrap().len(), 3);
    assert_eq!(doc["commands_version"], 1);

    // Owner only: another user gets 404 (no oracle), the bot's token is refused on owner routes.
    let (s, j) = node.get_auth(&path, &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
    let (s, j) = node.put(&path, &bob.token, command_set()).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
    let (s, j) = node.put(&path, &w.bot.secret, command_set()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));

    // Same set again: nothing changes, no new version.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.put(&path, &alice.token, command_set()).await;
    assert_eq!((s, j["commands_version"].as_i64()), (StatusCode::OK, Some(1)));
    // Changed set: ids stay per name, a removed name loses its room settings, `commands.update` to the room.
    let weather_ref = w.r("weather");
    let encoded = weather_ref.replace('/', "%2F");
    let (s, j) = node
        .put(&format!("/api/v1/rooms/{}/commands/{encoded}", w.room_id), &w.carol.token, json!({ "enabled": false }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut changed = command_set();
    changed["commands"][0]["description"] = json!("Weather everywhere");
    changed["commands"].as_array_mut().unwrap().remove(1);
    let (s, j) = node.put(&path, &alice.token, changed.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["commands_version"], 2);
    assert_eq!(j["commands"][0]["id"].as_str().unwrap(), ids[0], "ids stay stable per name");
    let ev = hub_event(&mut rx, "commands.update").await;
    assert_eq!(ev.data["room_id"], w.room_id.as_str());
    assert!(matches!(&ev.scope, Scope::Room(r) if r == &w.room_id));
    let audit: Vec<String> = sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = 'app.commands' ORDER BY id")
        .fetch_all(&node.state.db)
        .await
        .unwrap();
    assert!(audit.last().unwrap().contains("\"removed\":[\"admin\"]"), "{audit:?}");
    assert!(audit.last().unwrap().contains("\"changed\":[\"weather\"]"), "{audit:?}");
    // Removing weather drops its room setting; adding it back starts with the defaults.
    let (_, j) = node.put(&path, &alice.token, json!({ "commands": [] })).await;
    assert_eq!(j["commands"], json!([]));
    let (_, j) = node.put(&path, &alice.token, changed).await;
    let new_weather = j["commands"][0]["id"].as_str().unwrap().to_string();
    assert_ne!(new_weather, ids[0], "a removed name gets a new id");
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{}/commands", w.room_id), &w.carol.token).await;
    assert_eq!(list[0]["commands"][0]["settings"]["enabled"], true);

    // Validation: `command.invalid` with the path, `command.limit`.
    let bad =
        json!({ "commands": [ { "name": "ok", "description": "d" }, { "name": "Bad Name", "description": "d" } ] });
    let (s, j) = node.put(&path, &alice.token, bad).await;
    assert_eq!(
        (s, code(&j), j["meta"]["path"].as_str()),
        (StatusCode::BAD_REQUEST, "command.invalid", Some("commands[1].name"))
    );
    let (s, j) = node.put(&path, &alice.token, json!({ "commands": [], "extra": 1 })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "command.invalid"));
    let many: Vec<Value> = (0..101).map(|i| json!({ "name": format!("c{i}"), "description": "d" })).collect();
    let (s, j) = node.put(&path, &alice.token, json!({ "commands": many })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "command.limit"));

    // The bot's own route needs the `commands` scope.
    let (no_scope, _) = token(node, alice, &w.bot.app_id, Some(&["messages:read"])).await;
    let (s, j) = node.put("/api/v1/applications/me/commands", &no_scope, command_set()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    assert_eq!(j["meta"]["scope"], "commands");
    let (s, j) = node.get_auth("/api/v1/applications/me/commands", &w.bot.secret).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // Users have no "own" command set.
    let (s, j) = node.get_auth("/api/v1/applications/me/commands", &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));

    // 10 announcements per hour and application (owner and bot share the budget).
    let mut limited = false;
    for i in 0..12 {
        let mut set = command_set();
        set["commands"][2]["description"] = json!(format!("Pong {i}"));
        let (s, _) = node.put("/api/v1/applications/me/commands", &w.bot.secret, set).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(s, StatusCode::OK);
    }
    assert!(limited, "the 11th announcement within an hour is refused");
}

// ---------------------------------------------------------------- palette and room settings (§5.3, §5.4)

#[tokio::test]
async fn palette_follows_room_settings_and_permissions() {
    let w = world().await;
    let (node, carol, bob) = (&w.node, &w.carol, &w.bob);
    let palette = |token: String| {
        let path = format!("/api/v1/conversations/{}/commands", w.channel);
        async move { node.get_auth(&path, &token).await }
    };
    let names = |j: &Value| -> Vec<String> {
        j.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().to_string()).collect()
    };
    // bob lacks manage_room: no `admin`; carol (owner) sees all three.
    let (s, j) = palette(bob.token.clone()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(names(&j), vec!["weather", "ping"]);
    assert_eq!(j[0]["source"], "app");
    assert_eq!(j[0]["ref"], w.r("weather"));
    assert_eq!(j[0]["application"]["bot"], w.bot.address());
    assert_eq!(j[0]["application"]["name"], "Weather");
    assert_eq!(j[0]["permission"], "0");
    assert_eq!(names(&palette(carol.token.clone()).await.1), vec!["weather", "admin", "ping"]);
    // Bots never get a palette.
    let (s, j) = palette(w.bot.secret.clone()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));

    // The installation listing counts the offered commands.
    let (_, inst) = node.get_auth(&format!("/api/v1/rooms/{}/applications", w.room_id), &carol.token).await;
    assert_eq!(inst[0]["enabled_commands"], 3);

    // Room settings need manage_applications (reading: or manage_room).
    let settings = format!("/api/v1/rooms/{}/commands", w.room_id);
    let one = |name: &str| format!("{settings}/{}", w.r(name).replace('/', "%2F"));
    let (s, j) = node.get_auth(&settings, &bob.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    let (s, j) = node.put(&one("ping"), &bob.token, json!({ "enabled": false })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    let (s, j) = node.put(&one("ping"), &w.bot.secret, json!({ "enabled": false })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "settings are not in the bot route table");

    // Disable ping in the room, weather in this channel, `admin` for everyone with manage_messages.
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.put(&one("ping"), &carol.token, json!({ "enabled": false })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(hub_event(&mut rx, "commands.update").await.data["room_id"], w.room_id.as_str());
    let (s, j) = node.put(&one("weather"), &carol.token, json!({ "disabled_channels": [w.channel] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.put(&one("admin"), &carol.token, json!({ "permissions": p::MANAGE_MESSAGES.to_string() })).await;
    assert_eq!(
        (s, j["effective_permissions"].as_str()),
        (StatusCode::OK, Some(p::MANAGE_MESSAGES.to_string().as_str()))
    );
    assert_eq!(names(&palette(bob.token.clone()).await.1), Vec::<String>::new());
    let (_, inst) = node.get_auth(&format!("/api/v1/rooms/{}/applications", w.room_id), &carol.token).await;
    assert_eq!(inst[0]["enabled_commands"], 2);
    // Unknown roles and channels, malformed masks and unknown commands are refused.
    for body in [
        json!({ "allowed_roles": [util::ulid()] }),
        json!({ "disabled_channels": [util::ulid()] }),
        json!({ "permissions": "x" }),
        json!({ "unknown": true }),
    ] {
        let (s, _) = node.put(&one("ping"), &carol.token, body.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }
    let unknown = format!("{settings}/{}", format!("{}/{}", w.bot.reference(), util::ulid()).replace('/', "%2F"));
    let (s, j) = node.put(&unknown, &carol.token, json!({})).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "command.not_found"));

    // Allowed roles: only members of the role (owners always pass).
    let (s, role) =
        node.post(&format!("/api/v1/rooms/{}/roles", w.room_id), &carol.token, json!({ "name": "Weather fans" })).await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let role_id = role["id"].as_str().unwrap();
    let (s, _) = node.delete(&one("weather"), &carol.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = node.put(&one("weather"), &carol.token, json!({ "allowed_roles": [role_id] })).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!names(&palette(bob.token.clone()).await.1).contains(&"weather".to_string()));
    assert!(names(&palette(carol.token.clone()).await.1).contains(&"weather".to_string()));
    let (s, _) = node
        .patch(
            &format!("/api/v1/rooms/{}/members/{}", w.room_id, bob.user_id),
            &carol.token,
            json!({ "roles": [role_id] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(names(&palette(bob.token.clone()).await.1), vec!["weather"]);
    let audit: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM audit_log WHERE action = 'command.settings'")
            .fetch_one(&node.state.db)
            .await
            .unwrap();
    assert!(audit >= 5);
}

// ---------------------------------------------------------------- invocation checks (§5.5)

#[tokio::test]
async fn invocation_checks_run_in_order() {
    let w = world().await;
    let (node, carol, bob) = (&w.node, &w.carol, &w.bob);
    let dave = node.register("dave").await;
    let path = invoke_path(&w.channel);
    let unknown_command = format!("{}/{}", w.bot.reference(), util::ulid());
    let bad_args = |r: String| json!({ "command": r, "args": { "nope": 1 } });

    // 1. Not a member; a bot; no send_messages in the channel (even with an unknown command).
    let (s, j) = node.post(&path, &dave.token, bad_args(w.r("weather"))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"));
    let (s, j) = node.post(&path, &w.bot.secret, bad_args(w.r("weather"))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
    let (s, quiet) = node
        .post(
            &format!("/api/v1/rooms/{}/channels", w.room_id),
            &carol.token,
            json!({ "kind": "text", "name": "quiet", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{quiet}");
    let quiet = quiet["id"].as_str().unwrap().to_string();
    let (_, room) = node.get_auth(&format!("/api/v1/rooms/{}", w.room_id), &carol.token).await;
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{}/overrides", w.room_id),
            &carol.token,
            json!({ "target_type": "channel", "target_id": quiet, "subject_type": "role", "subject_id": everyone,
                    "allow": "0", "deny": p::SEND_MESSAGES.to_string() }),
        )
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post(&invoke_path(&quiet), &bob.token, bad_args(unknown_command.clone())).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "message.send_forbidden"));

    // 2. Not installed; the bot cannot view the channel ("no bots") wins over an unknown command.
    let other = bot(node, &w.alice, json!({ "name": "Other", "public": true }), None).await;
    let other_ref = format!("{}/{}", other.reference(), util::ulid());
    let (s, j) = node.post(&path, &bob.token, bad_args(other_ref)).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_installed"));
    let (s, nobots) = node
        .post(
            &format!("/api/v1/rooms/{}/channels", w.room_id),
            &carol.token,
            json!({ "kind": "text", "name": "humans", "encrypted": false }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let nobots = nobots["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{}/channels/{nobots}", w.room_id), &carol.token, json!({ "no_bots": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.post(&invoke_path(&nobots), &bob.token, bad_args(unknown_command.clone())).await;
    assert_eq!(
        (s, code(&j), j["meta"]["reason"].as_str()),
        (StatusCode::FORBIDDEN, "command.disabled", Some("bot_cannot_view"))
    );
    let (_, pal) = node.get_auth(&format!("/api/v1/conversations/{nobots}/commands"), &bob.token).await;
    assert_eq!(pal, json!([]), "nothing in the palette of a channel the bot cannot see");

    // 3. Unknown command (also with invalid arguments); malformed references.
    let (s, j) = node.post(&path, &bob.token, bad_args(unknown_command)).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "command.not_found"));
    for bad in ["", "weather", "t.local/x/y", "../../etc"] {
        let (s, j) = node.post(&path, &bob.token, json!({ "command": bad })).await;
        assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "command.not_found"), "{bad}");
    }

    // 4. Disabled in the room, then only in this channel (wins over invalid arguments).
    let one = format!("/api/v1/rooms/{}/commands/{}", w.room_id, w.r("weather").replace('/', "%2F"));
    node.put(&one, &carol.token, json!({ "enabled": false })).await;
    let (s, j) = node.post(&path, &bob.token, bad_args(w.r("weather"))).await;
    assert_eq!((s, code(&j), j["meta"]["reason"].as_str()), (StatusCode::FORBIDDEN, "command.disabled", Some("room")));
    node.put(&one, &carol.token, json!({ "disabled_channels": [w.channel] })).await;
    let (s, j) = node.post(&path, &bob.token, bad_args(w.r("weather"))).await;
    assert_eq!(
        (s, code(&j), j["meta"]["reason"].as_str()),
        (StatusCode::FORBIDDEN, "command.disabled", Some("channel"))
    );
    node.delete(&one, &carol.token).await;

    // 5. The required mask (manage_room for `admin`), and allowed roles.
    let (s, j) = node.post(&path, &bob.token, bad_args(w.r("admin"))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "command.forbidden"));
    let (_, role) =
        node.post(&format!("/api/v1/rooms/{}/roles", w.room_id), &carol.token, json!({ "name": "Insiders" })).await;
    node.put(&one, &carol.token, json!({ "allowed_roles": [role["id"]] })).await;
    let (s, j) = node.post(&path, &bob.token, bad_args(w.r("weather"))).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "command.forbidden"));
    // The owner passes the role restriction and reaches the argument check.
    let (s, j) = node.post(&path, &carol.token, bad_args(w.r("weather"))).await;
    assert_eq!(
        (s, code(&j), j["meta"]["arg"].as_str()),
        (StatusCode::BAD_REQUEST, "command.args_invalid", Some("nope"))
    );
    node.delete(&one, &carol.token).await;

    // 7. Arguments: definition and mode.
    let (s, j) =
        node.post(&path, &bob.token, json!({ "command": w.r("weather"), "args": { "units": "metric" } })).await;
    assert_eq!(
        (s, code(&j), j["meta"]["arg"].as_str()),
        (StatusCode::BAD_REQUEST, "command.args_invalid", Some("city"))
    );
    let (s, j) = node
        .post(&path, &bob.token, json!({ "command": w.r("weather"), "args": { "city": "B", "units": "kelvin" } }))
        .await;
    assert_eq!((s, j["meta"]["arg"].as_str()), (StatusCode::BAD_REQUEST, Some("units")));
    let (s, j) = node
        .post(&path, &bob.token, json!({ "command": w.r("ping"), "args_ciphertext": "AQAAAAAAAAAA", "epoch": 0 }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));

    // 6. 5 interactions per 5 seconds per user: counted before the argument check.
    for _ in 0..5 {
        let (s, _) = node.post(&path, &dave_member(node, carol, &w.room_id, &dave).await, bad_args(w.r("ping"))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (s, _) = node.post(&path, &dave.token, json!({ "command": w.r("ping") })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);

    // Valid, but the bot is not connected and has no URL.
    let (s, j) = node.post(&path, &bob.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, code(&j)), (StatusCode::SERVICE_UNAVAILABLE, "interaction.app_offline"));
}

/// dave joins the room once (idempotent) and returns his token.
async fn dave_member(node: &TestNode, carol: &Session, room_id: &str, dave: &Session) -> String {
    if node.get_auth(&format!("/api/v1/rooms/{room_id}"), &dave.token).await.0 != StatusCode::OK {
        member(node, carol, room_id, dave).await;
    }
    dave.token.clone()
}

// ---------------------------------------------------------------- responses (§5.6, §5.7)

#[tokio::test]
async fn replies_ephemeral_defer_errors_and_follow_ups() {
    let w = world().await;
    let (node, bob) = (&w.node, &w.bob);
    let path = invoke_path(&w.channel);
    let mut r = receiver(node, &w.bot.user_id, &w.bot.device_id);
    let cb = |id: &str| format!("/api/v1/interactions/{id}/callback");

    // A reply: a message of the bot with the envelope field `interaction`.
    let task = spawn_post(
        node,
        path.clone(),
        &bob.token,
        json!({ "command": w.r("weather"), "args": { "city": "Berlin", "units": "metric" } }),
        Some("de-DE,de;q=0.9"),
    );
    let data = r.invocation().await;
    assert_eq!(data["command"]["name"], "weather");
    assert_eq!(data["args"], json!({ "city": "Berlin", "units": "metric" }));
    assert_eq!(data["args_ciphertext"], Value::Null);
    assert_eq!(data["encrypted"], false);
    assert_eq!(data["user"], format!("bob@{D}"));
    assert_eq!(data["user_id"], bob.user_id.as_str());
    assert_eq!(data["device_id"], bob.device_id.as_str());
    assert_eq!(data["locale"], "de-DE");
    assert_eq!(
        (data["room_id"].as_str(), data["channel_id"].as_str()),
        (Some(w.room_id.as_str()), Some(w.channel.as_str()))
    );
    assert_eq!(data["application_id"], w.bot.app_id.as_str());
    assert!(data["permissions"].as_str().unwrap().parse::<u64>().unwrap() & p::SEND_MESSAGES != 0);
    let id = data["interaction_id"].as_str().unwrap().to_string();
    // Plaintext conversation: ciphertext content is a mismatch, nothing is acknowledged.
    let (s, j) =
        node.post(&cb(&id), &w.bot.secret, json!({ "type": "reply", "content": "AQAAAAAA", "epoch": 0 })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    // Another application's bot and users are not the interaction's owner; a token without the scope is refused.
    let other = bot(node, &w.alice, json!({ "name": "Intruder" }), None).await;
    let (s, j) = node.post(&cb(&id), &other.secret, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "interaction.not_owner"));
    let (s, j) = node.post(&cb(&id), &bob.token, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "interaction.not_owner"));
    let (no_scope, _) = token(node, &w.alice, &w.bot.app_id, Some(&["messages:write"])).await;
    let (s, j) = node.post(&cb(&id), &no_scope, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"));
    let (s, j) = node.post(&cb(&util::ulid()), &w.bot.secret, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "interaction.not_found"));
    let (s, j) = node
        .post(
            &cb(&id),
            &w.bot.secret,
            json!({ "type": "reply", "content": { "type": "text", "body": "12 °C, cloudy" } }),
        )
        .await;
    assert_eq!((s, j["outcome"].as_str()), (StatusCode::OK, Some("reply")), "{j}");
    // Duplicate callback.
    let (s, j) = node.post(&cb(&id), &w.bot.secret, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "interaction.already_acked"));
    let (s, res) = task.await.unwrap();
    assert_eq!(s, StatusCode::OK, "{res}");
    assert_eq!(res["outcome"], "reply");
    assert_eq!(res["interaction_id"], id.as_str());
    let m = &res["message"];
    assert_eq!(m["author"], w.bot.address());
    assert_eq!(m["author_kind"], "bot");
    assert_eq!(m["device_id"], w.bot.device_id.as_str());
    assert_eq!(
        m["interaction"],
        json!({ "id": id, "command": "weather", "application": w.bot.reference(), "user": format!("bob@{D}") })
    );
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{}/messages", w.channel), &bob.token).await;
    assert_eq!(list[0]["interaction"]["id"], id.as_str());
    let messages = list.as_array().unwrap().len();

    // An ephemeral reply: returned and sent to the invoker's other connections, never stored.
    let mut hub = node.state.hub.subscribe();
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "command": w.r("ping") }), None);
    let id = r.invocation().await["interaction_id"].as_str().unwrap().to_string();
    let (s, j) = node
        .post(
            &cb(&id),
            &w.bot.secret,
            json!({ "type": "reply", "ephemeral": true, "content": { "type": "text", "body": "pong" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["outcome"], "reply");
    assert_eq!(res["message"], Value::Null);
    assert_eq!(res["ephemeral"]["content"]["body"], "pong");
    assert_eq!(res["ephemeral"]["application"]["ref"], w.bot.reference());
    let ev = hub_event(&mut hub, "interaction.reply").await;
    assert!(
        matches!(&ev.scope, Scope::UsersExceptDevice { users, device } if users == &vec![bob.user_id.clone()] && device == &bob.device_id)
    );
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{}/messages", w.channel), &bob.token).await;
    assert_eq!(list.as_array().unwrap().len(), messages, "ephemeral replies are not stored");

    // Defer, then follow-ups: at most ten until the interaction expires.
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "command": w.r("ping") }), None);
    let id = r.invocation().await["interaction_id"].as_str().unwrap().to_string();
    let (s, _) = node.post(&cb(&id), &w.bot.secret, json!({ "type": "defer" })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(task.await.unwrap().1["outcome"], "defer");
    let follow = format!("/api/v1/interactions/{id}/messages");
    let (s, j) = node.post(&follow, &w.bot.secret, json!({ "content": { "type": "text", "body": "done" } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["message"]["interaction"]["id"], id.as_str());
    // Invalid follow-ups do not use up the budget.
    let (s, _) = node.post(&follow, &w.bot.secret, json!({ "content": "AQAA" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut hub = node.state.hub.subscribe();
    for i in 1..10 {
        let (s, j) = node
            .post(
                &follow,
                &w.bot.secret,
                json!({ "ephemeral": true, "content": { "type": "text", "body": format!("step {i}") } }),
            )
            .await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        assert_eq!(j["ephemeral"]["content"]["body"], format!("step {i}"));
    }
    let ev = hub_event(&mut hub, "interaction.reply").await;
    assert!(
        matches!(&ev.scope, Scope::Users(u) if u == &vec![bob.user_id.clone()]),
        "follow-ups reach all invoker devices"
    );
    let (s, j) = node.post(&follow, &w.bot.secret, json!({ "content": { "type": "text", "body": "too many" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "interaction.followup_limit"));
    let (s, j) = node.post(&follow, &w.alice.token, json!({ "content": { "type": "text", "body": "x" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "interaction.not_owner"));

    // An error: a short plain notice for the invoker; too long is refused and the interaction keeps waiting.
    let task = spawn_post(node, path.clone(), &bob.token, json!({ "command": w.r("ping") }), None);
    let id = r.invocation().await["interaction_id"].as_str().unwrap().to_string();
    let (s, _) = node.post(&cb(&id), &w.bot.secret, json!({ "type": "error", "message": "x".repeat(201) })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = node.post(&cb(&id), &w.bot.secret, json!({ "type": "error", "message": "City not found" })).await;
    assert_eq!(s, StatusCode::OK);
    let (_, res) = task.await.unwrap();
    assert_eq!((res["outcome"].as_str(), res["error"].as_str()), (Some("error"), Some("City not found")));
    drop(r);
}

#[tokio::test]
async fn the_ack_times_out_with_an_injected_clock() {
    let w = world().await;
    let node = &w.node;
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    node.state.interactions.set_clock(clock.clone());
    let mut r = receiver(node, &w.bot.user_id, &w.bot.device_id);
    let task = spawn_post(node, invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") }), None);
    let id = r.invocation().await["interaction_id"].as_str().unwrap().to_string();
    // Nothing happens in real time.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!task.is_finished());
    clock.advance(chrono::Duration::milliseconds(3001));
    let (s, j) = tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap();
    assert_eq!((s, code(&j)), (StatusCode::GATEWAY_TIMEOUT, "interaction.no_ack"));
    // The interaction is dropped: late callbacks and follow-ups are gone.
    let (s, j) =
        node.post(&format!("/api/v1/interactions/{id}/callback"), &w.bot.secret, json!({ "type": "defer" })).await;
    assert_eq!((s, code(&j)), (StatusCode::GONE, "interaction.expired"));
    let (s, j) = node
        .post(
            &format!("/api/v1/interactions/{id}/messages"),
            &w.bot.secret,
            json!({ "content": { "type": "text", "body": "x" } }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::GONE, "interaction.expired"));

    // A deferred interaction takes follow-ups for 15 minutes.
    let task = spawn_post(node, invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") }), None);
    let id = r.invocation().await["interaction_id"].as_str().unwrap().to_string();
    node.post(&format!("/api/v1/interactions/{id}/callback"), &w.bot.secret, json!({ "type": "defer" })).await;
    assert_eq!(task.await.unwrap().1["outcome"], "defer");
    clock.advance(chrono::Duration::minutes(14));
    let follow = format!("/api/v1/interactions/{id}/messages");
    let (s, _) = node
        .post(&follow, &w.bot.secret, json!({ "ephemeral": true, "content": { "type": "text", "body": "a" } }))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    clock.advance(chrono::Duration::minutes(2));
    let (s, j) = node
        .post(&follow, &w.bot.secret, json!({ "ephemeral": true, "content": { "type": "text", "body": "b" } }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::GONE, "interaction.expired"));
}

// ---------------------------------------------------------------- delivery (§5.6)

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn serve(node: &TestNode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = node.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("ws://{addr}/api/v1/ws")
}

async fn ws(url: &str, token: &str) -> Ws {
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(json!({ "op": "hello", "token": token }).to_string().into()))
        .await
        .unwrap();
    let ready = ws.next().await.unwrap().unwrap();
    assert!(ready.to_text().unwrap().contains("\"ready\""), "{ready:?}");
    ws
}

/// The next `command.invoke` on a socket within `ms`, if any.
async fn ws_invocation(ws: &mut Ws, ms: u64) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let msg = match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return None,
            Ok(m) => m?.ok()?,
        };
        let Ok(text) = msg.to_text() else { continue };
        let Ok(v) = serde_json::from_str::<Value>(text) else { continue };
        if v["type"] == "command.invoke" {
            return Some(v["data"].clone());
        }
    }
}

#[tokio::test]
async fn round_robin_over_two_bot_tokens() {
    let w = world().await;
    let node = &w.node;
    let url = serve(node).await;
    let (second, _) = token(node, &w.alice, &w.bot.app_id, None).await;
    let (no_commands, _) = token(node, &w.alice, &w.bot.app_id, Some(&["messages:read"])).await;
    let mut a = ws(&url, &w.bot.secret).await;
    let mut b = ws(&url, &second).await;
    // A token without the `commands` scope never receives invocations.
    let mut c = ws(&url, &no_commands).await;
    assert_eq!(node.state.interactions.receivers(&w.bot.user_id), 2);
    let mut got = Vec::new();
    for _ in 0..4 {
        let task = spawn_post(node, invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") }), None);
        let (which, data) = tokio::select! {
            Some(d) = ws_invocation(&mut a, 3000) => ("a", d),
            Some(d) = ws_invocation(&mut b, 3000) => ("b", d),
        };
        got.push(which);
        let token = if which == "a" { &w.bot.secret } else { &second };
        let id = data["interaction_id"].as_str().unwrap();
        let (s, _) = node.post(&format!("/api/v1/interactions/{id}/callback"), token, json!({ "type": "defer" })).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(task.await.unwrap().1["outcome"], "defer");
    }
    assert_eq!(got.iter().filter(|x| **x == "a").count(), 2, "{got:?}");
    assert_ne!(got[0], got[1], "{got:?}");
    assert_ne!(got[1], got[2], "{got:?}");
    assert!(ws_invocation(&mut c, 200).await.is_none());
    // Only one connection got each invocation.
    assert!(ws_invocation(&mut a, 200).await.is_none() && ws_invocation(&mut b, 200).await.is_none());
}

/// A receiver of interactions URL requests that answers the ping and invocations as told.
#[derive(Clone, Default)]
struct UrlBot {
    got: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    answer: Arc<Mutex<Value>>,
}

async fn url_receive(State(r): State<UrlBot>, headers: HeaderMap, body: Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    r.got.lock().unwrap().push((headers, parsed.clone()));
    if parsed["type"] == "ping" {
        return axum::Json(json!({ "challenge": parsed["challenge"] })).into_response();
    }
    let answer = r.answer.lock().unwrap().clone();
    if answer == json!("slow") {
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
    axum::Json(answer).into_response()
}

#[tokio::test]
async fn the_interactions_url_is_verified_signed_and_answers_in_the_response() {
    let w = world().await;
    let (node, alice) = (&w.node, &w.alice);
    let receiver = UrlBot::default();
    let app = Router::new().route("/interactions", post(url_receive)).with_state(receiver.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://127.0.0.1:{port}/interactions");
    let app_path = format!("/api/v1/applications/{}", w.bot.app_id);
    // Not a URL, then a verified one; the bot itself cannot set it.
    let (s, j) = node.patch(&app_path, &alice.token, json!({ "interactions_url": "ftp://x" })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.url_invalid"));
    let (s, j) = node.patch(&app_path, &alice.token, json!({ "interactions_url": url })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["interactions_url"], url.as_str());
    assert_eq!(receiver.got.lock().unwrap()[0].1["type"], "ping");
    let (s, _) = node.patch(&app_path, &w.bot.secret, json!({ "interactions_url": null })).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // The URL is preferred over the WebSocket; its answer is the callback (with the device it names).
    let _ws = receiver_guard(node, &w.bot);
    *receiver.answer.lock().unwrap() =
        json!({ "type": "reply", "device_id": w.bot.device_id, "content": { "type": "text", "body": "via URL" } });
    let (s, res) = node
        .post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("weather"), "args": { "city": "Oslo" } }))
        .await;
    assert_eq!(s, StatusCode::OK, "{res}");
    assert_eq!(res["message"]["content"]["body"], "via URL");
    assert_eq!(res["message"]["device_id"], w.bot.device_id.as_str());
    let (headers, body) = receiver.got.lock().unwrap().last().cloned().unwrap();
    assert_eq!(body["type"], "command.invoke");
    assert_eq!(body["id"], res["interaction_id"]);
    assert_eq!(body["data"]["args"]["city"], "Oslo");
    assert_eq!(headers.get("tavrn-event-type").unwrap(), "command.invoke");
    let token = headers.get("tavrn-signature").unwrap().to_str().unwrap();
    let key = node.state.signing_key();
    let expected = tavrn_node::jwt::Expected { iss: D.into(), aud: format!("app:{}", w.bot.app_id), typ: "hook" };
    let (_, claims): (tavrn_node::jwt::StandardClaims, tavrn_node::hooks::HookClaims) =
        tavrn_node::jwt::verify(token, &key.verifying(), &expected).unwrap();
    assert_eq!(claims.htu, url);

    // A device that is not the bot's, and an answer that is not a callback: no acknowledgement.
    *receiver.answer.lock().unwrap() =
        json!({ "type": "reply", "device_id": util::ulid(), "content": { "type": "text", "body": "x" } });
    let (s, j) = node.post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, code(&j)), (StatusCode::GATEWAY_TIMEOUT, "interaction.no_ack"));
    *receiver.answer.lock().unwrap() = json!({ "nonsense": true });
    let (s, j) = node.post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, code(&j)), (StatusCode::GATEWAY_TIMEOUT, "interaction.no_ack"));
    *receiver.answer.lock().unwrap() = json!({ "type": "defer" });
    let (s, j) = node.post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, j["outcome"].as_str()), (StatusCode::OK, Some("defer")));
}

fn receiver_guard(node: &TestNode, b: &Bot) -> ReceiverGuard {
    node.state.interactions.register(&b.user_id, &b.device_id)
}

// ---------------------------------------------------------------- encrypted conversations (§5.8)

#[tokio::test]
async fn encrypted_conversations_carry_ciphertext_both_ways() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let mut carol = node.crypto_user("carol").await;
    let b = bot(
        &node,
        &alice,
        json!({ "name": "Cipher", "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) }),
        None,
    )
    .await;
    node.put(&format!("/api/v1/applications/{}/commands", b.app_id), &alice.token, command_set()).await;
    let room = node.create_room(carol.token(), "Secret room").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    assert_eq!(
        room["channels"].as_array().unwrap().iter().find(|c| c["id"] == channel.as_str()).unwrap()["encrypted"],
        true
    );
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            carol.token(),
            json!({ "application": b.reference(), "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let refs = j_refs(&j, &b, &node, &alice).await;
    // New rooms keep bots out of encrypted channels unless the channel allows them.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), carol.token(), json!({ "bots_allowed": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // The bot is an E2EE participant: identity, attested device, member of the channel's group.
    let master = MasterSecret::generate().unwrap();
    node.put_identity(&b.session(), &master).await;
    let mut bot_dev = node.attest(b.session(), master, 2).await;
    node.create_group(&mut carol, &channel).await;
    node.add_user(&mut carol, &channel, &b.username).await;
    assert_eq!(node.accept_welcomes(&mut bot_dev).await, 1);
    let q = common::e2ee::qualified(&channel);
    let path = invoke_path(&channel);
    let weather = refs["weather"].clone();

    // Plaintext arguments in an encrypted channel; garbage and unknown epochs.
    let (s, j) = node.post(&path, carol.token(), json!({ "command": weather, "args": { "city": "Rome" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let (s, j) = node.post(&path, carol.token(), json!({ "command": weather })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.ciphertext_invalid"));
    let (s, j) = node
        .post(&path, carol.token(), json!({ "command": weather, "args_ciphertext": "not*base64", "epoch": 1 }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.ciphertext_invalid"));
    let args = json!({ "type": "command.args", "command": weather, "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                       "issued_at": util::now(), "args": { "city": "Rome" } });
    let ct = carol.client.encrypt_content(&q, &args.to_string()).unwrap();
    let epoch = carol.client.current_epoch(&q).unwrap() as i64;
    let (s, j) =
        node.post(&path, carol.token(), json!({ "command": weather, "args_ciphertext": ct, "epoch": epoch + 5 })).await;
    assert_eq!(
        (s, code(&j)),
        (StatusCode::BAD_REQUEST, "interaction.ciphertext_invalid"),
        "epoch must match the header"
    );

    // The node passes the opaque payload; the bot decrypts it and answers with ciphertext.
    let mut r = receiver(&node, &b.user_id, &b.device_id);
    let task = spawn_post(
        &node,
        path.clone(),
        carol.token(),
        json!({ "command": weather, "args_ciphertext": ct, "epoch": epoch }),
        None,
    );
    let data = r.invocation().await;
    assert_eq!((data["encrypted"].as_bool(), data["args"].clone()), (Some(true), Value::Null));
    assert_eq!(data["epoch"], epoch);
    let carol_key = carol.client.device().public_key();
    let plain = bot_dev
        .client
        .decrypt_content(
            &q,
            &format!("carol@{D}"),
            &carol.session.device_id,
            data["args_ciphertext"].as_str().unwrap(),
            Some(&carol_key),
        )
        .unwrap();
    let decoded: Value = serde_json::from_str(&plain).unwrap();
    assert_eq!((decoded["command"].as_str(), decoded["args"]["city"].as_str()), (Some(weather.as_str()), Some("Rome")));
    let id = data["interaction_id"].as_str().unwrap();
    let cb = format!("/api/v1/interactions/{id}/callback");
    // A plaintext reply in an encrypted channel is a mismatch.
    let (s, j) =
        node.post(&cb, &b.secret, json!({ "type": "reply", "content": { "type": "text", "body": "sunny" } })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
    let reply = bot_dev.client.encrypt_content(&q, &json!({ "type": "text", "body": "sunny" }).to_string()).unwrap();
    let reply_epoch = bot_dev.client.current_epoch(&q).unwrap();
    let (s, j) = node
        .post(&cb, &b.secret, json!({ "type": "reply", "content": reply, "epoch": reply_epoch, "ephemeral": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["ephemeral"]["content"], reply.as_str());
    assert_eq!(res["ephemeral"]["device_id"], b.device_id.as_str());
    let shown = carol
        .client
        .decrypt_content(
            &q,
            &b.address(),
            &b.device_id,
            res["ephemeral"]["content"].as_str().unwrap(),
            Some(&bot_dev.client.device().public_key()),
        )
        .unwrap();
    assert!(shown.contains("sunny"));
}

// ---------------------------------------------------------------- node approval (§5.2)

#[tokio::test]
async fn approval_is_per_definition_and_a_change_makes_it_pending_again() {
    let w = world_with(test_node_with(D, |c| c.app_commands_require_approval = true).await).await;
    let node = &w.node;
    let admin = node.login("admin").await;
    let palette = format!("/api/v1/conversations/{}/commands", w.channel);
    let (_, j) = node.get_auth(&palette, &w.bob.token).await;
    assert_eq!(j, json!([]), "pending definitions are not offered");
    let (s, j) =
        node.post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping"), "args": { "x": 1 } })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "command.pending_approval"), "check 3 before the arguments");
    let (_, inst) = node.get_auth(&format!("/api/v1/rooms/{}/applications", w.room_id), &w.carol.token).await;
    assert_eq!(inst[0]["enabled_commands"], 0);

    // Admin routes: listing by state, approving by hash; others get 403.
    let (s, j) = node.get_auth("/api/v1/admin/applications/commands?state=pending", &w.bob.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.get_auth("/api/v1/admin/applications/commands?state=bogus", &admin.token).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let (_, pending) = node.get_auth("/api/v1/admin/applications/commands?state=pending", &admin.token).await;
    assert_eq!(pending.as_array().unwrap().len(), 3);
    let hash = |name: &str, list: &Value| {
        list.as_array().unwrap().iter().find(|c| c["command"]["name"] == name).unwrap()["definition_hash"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let ping = hash("ping", &pending);
    let weather = hash("weather", &pending);
    let body = json!({ "application": w.bot.reference(), "hashes": [ping, weather] });
    let (s, _) = node.post("/api/v1/admin/applications/commands/approve", &w.bob.token, body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = node.post("/api/v1/admin/applications/commands/approve", &w.bot.secret, body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, j) = node
        .post(
            "/api/v1/admin/applications/commands/approve",
            &admin.token,
            json!({ "application": w.bot.reference(), "hashes": ["nope"] }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "command.not_found"));
    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.post("/api/v1/admin/applications/commands/approve", &admin.token, body).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    hub_event(&mut rx, "commands.update").await;
    let (s, j) = node
        .post(
            "/api/v1/admin/applications/commands/reject",
            &admin.token,
            json!({ "application": w.bot.reference(), "hashes": [hash("admin", &pending)] }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let names = |j: &Value| -> Vec<String> {
        j.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().into()).collect()
    };
    assert_eq!(names(&node.get_auth(&palette, &w.bob.token).await.1), vec!["weather", "ping"]);
    let (_, approved) = node.get_auth("/api/v1/admin/applications/commands?state=approved", &admin.token).await;
    assert_eq!(approved.as_array().unwrap().len(), 2);
    let (_, rejected) = node.get_auth("/api/v1/admin/applications/commands?state=rejected", &admin.token).await;
    assert_eq!(rejected[0]["command"]["name"], "admin");
    let (_, inst) = node.get_auth(&format!("/api/v1/rooms/{}/applications", w.room_id), &w.carol.token).await;
    assert_eq!(inst[0]["enabled_commands"], 2);

    // Changing a definition makes it pending again; the unchanged one stays approved.
    let mut changed = command_set();
    changed["commands"][2]["description"] = json!("Pong, now with latency");
    let (s, _) = node.put(&format!("/api/v1/applications/{}/commands", w.bot.app_id), &w.alice.token, changed).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(names(&node.get_auth(&palette, &w.bob.token).await.1), vec!["weather"]);
    let (s, j) = node.post(&invoke_path(&w.channel), &w.bob.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "command.pending_approval"));
    let (_, pending) = node.get_auth("/api/v1/admin/applications/commands?state=pending", &admin.token).await;
    assert_eq!(
        names(&Value::Array(pending.as_array().unwrap().iter().map(|c| c["command"].clone()).collect())),
        vec!["ping"]
    );
    let audit: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM audit_log WHERE action IN ('admin.app_commands_approve', 'admin.app_commands_reject')",
    )
    .fetch_one(&node.state.db)
    .await
    .unwrap();
    assert_eq!(audit, 2);
}

// ---------------------------------------------------------------- DMs and other nodes

#[tokio::test]
async fn direct_messages_with_the_bot_use_dm_allowed_commands() {
    let w = world().await;
    let node = &w.node;
    // The owner always gets a conversation with the bot; DMs are encrypted.
    let (s, dm) =
        node.post("/api/v1/conversations", &w.bot.secret, json!({ "kind": "dm", "members": [w.alice.username] })).await;
    assert!(s.is_success(), "{dm}");
    let dm = dm["id"].as_str().unwrap().to_string();
    let (_, pal) = node.get_auth(&format!("/api/v1/conversations/{dm}/commands"), &w.alice.token).await;
    let names: Vec<&str> = pal.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["weather"], "only dm_allowed commands");
    let (s, j) = node.post(&invoke_path(&dm), &w.alice.token, json!({ "command": w.r("ping") })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "command.dm_not_allowed"));
    let (s, j) = node
        .post(&invoke_path(&dm), &w.alice.token, json!({ "command": w.r("weather"), "args": { "city": "x" } }))
        .await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "interaction.encryption_mismatch"));
}

#[tokio::test]
async fn remote_applications_and_remote_users() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let app = bot(
        &a,
        &alice,
        json!({ "name": "Traveller", "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) }),
        None,
    )
    .await;
    let reference = format!("{}/{}", federation::A, app.app_id);
    a.put(&format!("/api/v1/applications/{}/commands", app.app_id), &alice.token, command_set()).await;
    // A user of B signed in on A cannot manage A's applications (local only).
    let carol = b.register("carol").await;
    let remote_carol = a.sign_in_from(&b, &carol).await;
    let (s, j) = a.get_auth(&format!("/api/v1/applications/{}/commands", app.app_id), &remote_carol.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"));

    // Installed on B: B keeps the definitions of the document.
    let room = b.plaintext_room(&carol.token, "Remote room").await;
    let room_id = room["id"].as_str().unwrap();
    let channel = TestNode::text_channel(&room);
    let (s, j) = b
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": reference, "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["enabled_commands"], 3);
    // A indexes the installation (app.install), so app.changed reaches B.
    b.deliver().await;
    let palette = format!("/api/v1/conversations/{channel}/commands");
    let (_, pal) = b.get_auth(&palette, &carol.token).await;
    assert_eq!(pal.as_array().unwrap().len(), 3, "{pal}");
    let ping =
        pal.as_array().unwrap().iter().find(|c| c["name"] == "ping").unwrap()["ref"].as_str().unwrap().to_string();
    assert!(ping.starts_with(&reference));

    // A changes the set: app.changed makes B refetch it, B's rooms get commands.update.
    let mut rx = b.state.hub.subscribe();
    let mut changed = command_set();
    changed["commands"].as_array_mut().unwrap().remove(0);
    a.put(&format!("/api/v1/applications/{}/commands", app.app_id), &alice.token, changed).await;
    a.deliver().await;
    hub_event(&mut rx, "commands.update").await;
    let (_, pal) = b.get_auth(&palette, &carol.token).await;
    let names: Vec<&str> = pal.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["admin", "ping"]);

    // The remote bot receives invocations over its federated WebSocket on B and answers there.
    let remote = b.sign_in_from_bot(&a, &app.secret).await;
    let mut ws = crossnode::ws(&b, &remote).await;
    let task = spawn_post(&b, invoke_path(&channel), &carol.token, json!({ "command": ping }), None);
    let data = crossnode::event(&mut ws, "command.invoke").await;
    assert_eq!(data["user"], format!("carol@{}", federation::B));
    let id = data["interaction_id"].as_str().unwrap();
    let (s, j) = b
        .post(
            &format!("/api/v1/interactions/{id}/callback"),
            &remote,
            json!({ "type": "reply", "content": { "type": "text", "body": "pong from A" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["message"]["author"], format!("{}@{}", app.username, federation::A));
    assert_eq!(res["message"]["interaction"]["application"], reference.as_str());

    // Uninstalled: B forgets the definitions.
    let (s, _) = b
        .delete(&format!("/api/v1/rooms/{room_id}/applications/{}", reference.replace('/', "%2F")), &carol.token)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM application_commands")
        .fetch_one(&b.state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
