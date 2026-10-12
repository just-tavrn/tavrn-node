// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used)]
//! Date of birth, the private age status and the age gates (protocol PROTOCOL.md §5e, `age.v1`).
use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use chrono::{Datelike, Months, NaiveDate, Utc};
use common::{Session, TestNode, federation, password, test_node, test_node_with};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

/// The date of birth of someone who is `years` old today (born exactly `years` years ago).
fn born_years_ago(years: u32) -> String {
    today().checked_sub_months(Months::new(12 * years)).unwrap().format("%Y-%m-%d").to_string()
}

/// One day short of `years` years old today.
fn one_day_short_of(years: u32) -> String {
    (today().checked_sub_months(Months::new(12 * years)).unwrap() + chrono::Days::new(1)).format("%Y-%m-%d").to_string()
}

async fn register_raw(node: &TestNode, username: &str, dob: Option<&str>) -> (StatusCode, Value) {
    let mut body = json!({ "username": username, "password": password(username), "device_name": "test" });
    if let Some(d) = dob {
        body["date_of_birth"] = json!(d);
    }
    node.req(Method::POST, "/api/v1/auth/register", None, Some(body)).await
}

async fn minor(node: &TestNode, username: &str) -> Session {
    node.register_born(username, &born_years_ago(16)).await
}

async fn me(node: &TestNode, token: &str) -> Value {
    let (s, j) = node.get_auth("/api/v1/users/me", token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j
}

/// Removes the date of birth directly in the database (an account from before `age.v1`, or one provisioned by SSO).
async fn forget_date_of_birth(node: &TestNode, user_id: &str) {
    sqlx::query("UPDATE users SET date_of_birth = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

async fn set_room_gate(node: &TestNode, token: &str, room_id: &str, gate: &str) -> (StatusCode, Value) {
    node.patch(&format!("/api/v1/rooms/{room_id}"), token, json!({ "age_gate": gate })).await
}

async fn invite_and_join(node: &TestNode, owner: &str, room_id: &str, joiner: &str) -> (StatusCode, Value) {
    let (s, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    assert_eq!(s, StatusCode::CREATED, "{invite}");
    node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), joiner, json!({})).await
}

/// A public, discoverable room of `owner`.
async fn public_room(node: &TestNode, token: &str, name: &str) -> String {
    let (s, room) =
        node.post("/api/v1/rooms", token, json!({ "name": name, "description": "d", "join_mode": "public" })).await;
    assert_eq!(s, StatusCode::CREATED, "{room}");
    let id = room["id"].as_str().unwrap().to_string();
    let (s, j) = node.patch(&format!("/api/v1/rooms/{id}"), token, json!({ "discoverable": true })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    id
}

fn assert_code(status: StatusCode, json: &Value, expected: StatusCode, code: &str) {
    assert_eq!(status, expected, "{json}");
    assert_eq!(json["code"], code, "{json}");
}

// ---------------------------------------------------------------- registration and status

#[tokio::test]
async fn registration_requires_a_plausible_date_of_birth() {
    let node = test_node("t.local").await;
    node.register("admin").await;
    let future = (today() + chrono::Days::new(1)).format("%Y-%m-%d").to_string();
    for dob in [
        None,
        Some(""),
        Some("1990-13-01"),
        Some("1990-02-30"),
        Some("1990-1-1"),
        Some("01.01.1990"),
        Some("1899-12-31"),
        Some(future.as_str()),
    ] {
        let (s, j) = register_raw(&node, "carol", dob).await;
        assert_code(s, &j, StatusCode::BAD_REQUEST, "validation.date_of_birth");
    }
    // Nothing was stored: the name is still free.
    let (s, j) = register_raw(&node, "carol", Some("1990-01-01")).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn registration_below_the_minimum_age_is_refused_and_names_it() {
    let node = test_node("t.local").await;
    assert_eq!(node.state.config.minimum_age, 16, "default minimum age");
    let (s, j) = register_raw(&node, "young", Some(&one_day_short_of(16))).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.below_minimum");
    assert_eq!(j["meta"]["minimum_age"], 16);
    assert!(j["detail"].as_str().unwrap().contains("16"), "{j}");
    // On the 16th birthday the registration works.
    let (s, j) = register_raw(&node, "young", Some(&born_years_ago(16))).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    let adults = test_node_with("t.local", |c| c.minimum_age = 18).await;
    let (s, j) = register_raw(&adults, "seventeen", Some(&born_years_ago(17))).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.below_minimum");
    assert_eq!(j["meta"]["minimum_age"], 18);
}

#[test]
fn the_minimum_age_is_validated() {
    let base = || tavrn_node::config::Config {
        domain: "x".into(),
        database_url: "postgres://x".into(),
        ..tavrn_node::config::Config::default()
    };
    for bad in [0, 12, 100] {
        let err = tavrn_node::config::Config { minimum_age: bad, ..base() }.validate().unwrap_err();
        assert!(err.to_string().contains("TAVRN_MINIMUM_AGE"), "{err}");
    }
    for ok in [13, 16, 18, 99] {
        let problems = tavrn_node::config::Config { minimum_age: ok, ..base() }.validate().err().map(|e| e.to_string());
        assert!(!problems.unwrap_or_default().contains("TAVRN_MINIMUM_AGE"), "{ok}");
    }
}

#[tokio::test]
async fn the_status_turns_adult_on_the_18th_birthday_and_only_the_user_sees_it() {
    let node = test_node("t.local").await;
    node.register("admin").await;
    let almost = node.register_born("almost", &one_day_short_of(18)).await;
    let birthday = node.register_born("birthday", &born_years_ago(18)).await;

    let a = me(&node, &almost.token).await;
    assert_eq!(a["age_status"], json!({ "tier": "minor", "method": "self" }), "{a}");
    assert_eq!(a["date_of_birth"], one_day_short_of(18));
    let b = me(&node, &birthday.token).await;
    assert_eq!(b["age_status"], json!({ "tier": "adult", "method": "self" }), "{b}");

    // The day passes: one day later the minor is 18 (the status is derived on every use).
    sqlx::query("UPDATE users SET date_of_birth = $1 WHERE id = $2")
        .bind(born_years_ago(18))
        .bind(&almost.user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    assert_eq!(me(&node, &almost.token).await["age_status"]["tier"], "adult");
}

#[tokio::test]
async fn accounts_without_a_date_of_birth_must_complete_it_first() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let old = node.register("old").await;
    forget_date_of_birth(&node, &old.user_id).await;

    let j = me(&node, &old.token).await;
    assert_eq!(j["age_status"], json!({ "tier": "unknown", "method": "none" }), "{j}");
    assert_eq!(j["date_of_birth"], Value::Null);
    for path in ["/api/v1/rooms", "/api/v1/users/me/devices", "/api/v1/users/me/friends"] {
        let (s, j) = node.get_auth(path, &old.token).await;
        assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");
    }
    let (s, j) = node.post("/api/v1/rooms", &old.token, json!({ "name": "R" })).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");
    // The terms status stays reachable (both dialogs can be completed in any order).
    let (s, j) = node.get_auth("/api/v1/users/me/terms", &old.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Invalid and too young dates are refused here too.
    let (s, j) = node.put("/api/v1/users/me/date-of-birth", &old.token, json!({ "date_of_birth": "nope" })).await;
    assert_code(s, &j, StatusCode::BAD_REQUEST, "validation.date_of_birth");
    let (s, j) =
        node.put("/api/v1/users/me/date-of-birth", &old.token, json!({ "date_of_birth": born_years_ago(12) })).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.below_minimum");
    let (s, j) = node.get_auth("/api/v1/rooms", &old.token).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");

    let (s, j) = node.put("/api/v1/users/me/date-of-birth", &old.token, json!({ "date_of_birth": "1990-05-17" })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["age_status"]["tier"], "adult");
    assert_eq!(j["date_of_birth"], "1990-05-17");
    let (s, j) = node.get_auth("/api/v1/rooms", &old.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    // Set once: corrections go through the operator.
    let (s, j) = node.put("/api/v1/users/me/date-of-birth", &old.token, json!({ "date_of_birth": "1980-01-01" })).await;
    assert_code(s, &j, StatusCode::CONFLICT, "age.date_of_birth_set");

    // The operator corrects it (audited without the date) or removes it (the user is asked again).
    let path = format!("/api/v1/admin/users/{}/date-of-birth", old.user_id);
    let (s, j) = node.put(&path, &old.token, json!({ "date_of_birth": "1980-01-01" })).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "auth.node_admin_required");
    let (s, j) = node.put(&path, &admin.token, json!({ "date_of_birth": "1980-02-30" })).await;
    assert_code(s, &j, StatusCode::BAD_REQUEST, "validation.date_of_birth");
    let (s, j) = node.put(&path, &admin.token, json!({ "date_of_birth": "1980-01-01" })).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(me(&node, &old.token).await["date_of_birth"], "1980-01-01");
    let (_, log) = node.get_auth("/api/v1/admin/audit-log", &admin.token).await;
    let entry = log.as_array().unwrap().iter().find(|e| e["action"] == "admin.date_of_birth").unwrap().clone();
    assert!(!entry.to_string().contains("1980"), "the audit entry never carries the date: {entry}");
    let (s, _) = node.put(&path, &admin.token, json!({ "date_of_birth": null })).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = node.get_auth("/api/v1/rooms", &old.token).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");

    // Sign-out always works.
    let (s, _) = node.req(Method::POST, "/api/v1/auth/logout", Some(&old.token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_websocket_of_an_account_without_a_date_of_birth_closes() {
    let node = federation::FedNode::serve_one("t.local").await;
    let old = node.register("old").await;
    forget_date_of_birth(&node, &old.user_id).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(node.ws_url()).await.unwrap();
    ws.send(Message::Text(json!({ "op": "hello", "token": old.token, "capabilities": [] }).to_string().into()))
        .await
        .unwrap();
    let frame = common::within(Duration::from_secs(5), "the next frame", ws.next()).await.unwrap().unwrap();
    let Message::Close(Some(f)) = frame else { unreachable!("expected a close frame, got {frame:?}") };
    assert_eq!(u16::from(f.code), 4002);
    assert_eq!(f.reason.as_str(), "age.status_required");
}

#[tokio::test]
async fn the_node_announces_age_v1() {
    let node = test_node_with("t.local", |c| c.minimum_age = 18).await;
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert!(info["capabilities"].as_array().unwrap().contains(&json!("age.v1")), "{info}");
    assert_eq!(info["age"], json!({ "self_declared": true, "gates": ["adults_only"], "minimum_age": 18 }));
    let (_, wk) = node.req(Method::GET, "/.well-known/tavrn", None, None).await;
    assert!(wk["capabilities"].as_array().unwrap().contains(&json!("age.v1")));
    assert_eq!(wk["age"]["minimum_age"], 18);
}

// ---------------------------------------------------------------- settings

#[tokio::test]
async fn room_and_channel_gates_are_settings_of_managers_and_only_adults_switch_them_on() {
    let node = test_node("t.local").await;
    let owner = node.register("owner").await;
    let teen = minor(&node, "teen").await;
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    assert_eq!(room["age_gate"], "none");
    let general = TestNode::text_channel(&room);
    let channel = room["channels"].as_array().unwrap().iter().find(|c| c["id"] == general.as_str()).unwrap().clone();
    assert_eq!((channel["age_gate"].as_str(), channel["age_gate_effective"].as_str()), (Some("none"), Some("none")));

    let (s, j) = set_room_gate(&node, &owner.token, room_id, "teens_only").await;
    assert_code(s, &j, StatusCode::BAD_REQUEST, "validation.age_gate");

    // A channel stricter than its room.
    let (s, gated) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &owner.token,
            json!({ "kind": "text", "name": "after-dark", "encrypted": false, "age_gate": "adults_only" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{gated}");
    assert_eq!(
        (gated["age_gate"].as_str(), gated["age_gate_effective"].as_str()),
        (Some("adults_only"), Some("adults_only"))
    );
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{general}"), &owner.token, json!({ "age_gate": "maybe" }))
        .await;
    assert_code(s, &j, StatusCode::BAD_REQUEST, "validation.age_gate");

    // A minor holding manage_room and manage_channels cannot switch a gate on (nobody locks themselves out).
    let (s, j) = invite_and_join(&node, &owner.token, room_id, &teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let managers = tavrn_node::permissions::MANAGE_ROOM | tavrn_node::permissions::MANAGE_CHANNELS;
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &owner.token,
            json!({ "name": "mods", "permissions": managers.to_string() }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/members/{}", teen.user_id),
            &owner.token,
            json!({ "roles": [role["id"]] }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = set_room_gate(&node, &teen.token, room_id, "adults_only").await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/channels/{general}"),
            &teen.token,
            json!({ "age_gate": "adults_only" }),
        )
        .await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");

    // The room's gate is every channel's minimum.
    let (s, j) = set_room_gate(&node, &owner.token, room_id, "adults_only").await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["age_gate"], "adults_only");
    for c in j["channels"].as_array().unwrap() {
        assert_eq!(c["age_gate_effective"], "adults_only", "{c}");
    }
    let general_now = j["channels"].as_array().unwrap().iter().find(|c| c["id"] == general.as_str()).unwrap();
    assert_eq!(general_now["age_gate"], "none", "the channel's own setting is unchanged");

    let after_dark = gated["id"].as_str().unwrap();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{after_dark}"), &owner.token, json!({ "age_gate": "none" }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!((j["age_gate"].as_str(), j["age_gate_effective"].as_str()), (Some("none"), Some("adults_only")));
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &owner.token).await;
    let actions: Vec<&str> = log.as_array().unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
    assert!(actions.contains(&"room.age_gate") && actions.contains(&"channel.age_gate"), "{actions:?}");
}

// ---------------------------------------------------------------- Discover and joining

#[tokio::test]
async fn discover_hides_gated_rooms_from_minors_and_anonymous_requests() {
    let node = test_node("t.local").await;
    let adult = node.register("adult").await;
    let teen = minor(&node, "teen").await;
    let open = public_room(&node, &adult.token, "Open").await;
    let gated = public_room(&node, &adult.token, "Gated").await;
    let (s, j) = set_room_gate(&node, &adult.token, &gated, "adults_only").await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let ids = |list: &Value| -> Vec<String> {
        let items = list.get("items").unwrap_or(list);
        items
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().or(r["room_id"].as_str()).unwrap().to_string())
            .collect()
    };
    for path in ["/api/v1/rooms/discover", "/api/v1/directory/rooms?local=true"] {
        let (s, anonymous) = node.req(Method::GET, path, None, None).await;
        assert_eq!(s, StatusCode::OK, "{anonymous}");
        assert_eq!(ids(&anonymous), vec![open.clone()], "{path} anonymous");
        let (_, as_minor) = node.get_auth(path, &teen.token).await;
        assert_eq!(ids(&as_minor), vec![open.clone()], "{path} minor");
        let (_, as_adult) = node.get_auth(path, &adult.token).await;
        let mut seen = ids(&as_adult);
        seen.sort();
        let mut both = vec![open.clone(), gated.clone()];
        both.sort();
        assert_eq!(seen, both, "{path} adult");
        let items = as_adult.get("items").unwrap_or(&as_adult).as_array().unwrap().clone();
        let gated_item = items.iter().find(|r| r["id"] == gated.as_str() || r["room_id"] == gated.as_str()).unwrap();
        assert_eq!(gated_item["age_gate"], "adults_only");
    }
}

#[tokio::test]
async fn minors_cannot_join_a_gated_room_even_with_an_invite() {
    let node = test_node("t.local").await;
    let adult = node.register("adult").await;
    let teen = minor(&node, "teen").await;
    let grown = node.register("grown").await;
    let room = public_room(&node, &adult.token, "Gated").await;
    set_room_gate(&node, &adult.token, &room, "adults_only").await;

    let (s, j) = node.post(&format!("/api/v1/rooms/{room}/join"), &teen.token, json!({})).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    assert_eq!(j["meta"]["age_gate"], "adults_only");

    // The invite preview explains the gate; the join is refused.
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room}/invites"), &adult.token, json!({})).await;
    let code = invite["code"].as_str().unwrap();
    let (s, preview) = node.req(Method::GET, &format!("/api/v1/invites/{code}"), None, None).await;
    assert_eq!(s, StatusCode::OK, "{preview}");
    assert_eq!(preview["room"]["age_gate"], "adults_only");
    let (s, j) = node.post(&format!("/api/v1/invites/{code}/join"), &teen.token, json!({})).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");

    // A direct invite is created like any other (the inviter learns nothing); only the join fails.
    let (s, j) = node
        .post(&format!("/api/v1/rooms/{room}/invites/direct"), &adult.token, json!({ "user": "teen@t.local" }))
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
    let (_, list) = node.get_auth("/api/v1/users/me/invites", &teen.token).await;
    let bound = list["items"][0]["invite_code"].as_str().unwrap().to_string();
    let (s, j) = node.post(&format!("/api/v1/invites/{bound}/join"), &teen.token, json!({})).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");

    let (s, j) = node.post(&format!("/api/v1/invites/{code}/join"), &grown.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "adults join: {j}");
}

// ---------------------------------------------------------------- gated channels

struct Gated {
    node: TestNode,
    owner: Session,
    teen: Session,
    room_id: String,
    open: String,
    gated: String,
}

async fn gated_channel_setup() -> Gated {
    let node = test_node("t.local").await;
    let owner = node.register("owner").await;
    let teen = minor(&node, "teen").await;
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let open = TestNode::text_channel(&room);
    let (s, gated) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &owner.token,
            json!({ "kind": "text", "name": "after-dark", "encrypted": false, "age_gate": "adults_only" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{gated}");
    let (s, j) = invite_and_join(&node, &owner.token, &room_id, &teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    Gated { gated: gated["id"].as_str().unwrap().to_string(), node, owner, teen, room_id, open }
}

#[tokio::test]
async fn gated_channels_stay_listed_but_their_content_is_refused_to_minors() {
    let g = gated_channel_setup().await;
    let (node, room_id) = (&g.node, g.room_id.as_str());
    let (s, m) = node.send(&g.owner.token, room_id, &g.gated, "secret words").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let message_id = m["id"].as_str().unwrap();
    node.send(&g.owner.token, room_id, &g.open, "open words").await;

    // Listed, with the gate.
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &g.teen.token).await;
    let listed = detail["channels"].as_array().unwrap().iter().find(|c| c["id"] == g.gated.as_str()).unwrap().clone();
    assert_eq!(listed["age_gate_effective"], "adults_only");
    let states: Vec<&str> =
        detail["read_states"].as_array().unwrap().iter().filter_map(|r| r["conversation_id"].as_str()).collect();
    assert!(!states.contains(&g.gated.as_str()), "no unread counts of a locked channel: {states:?}");

    let base = format!("/api/v1/rooms/{room_id}/channels/{}", g.gated);
    let conv = format!("/api/v1/conversations/{}", g.gated);
    for path in [format!("{base}/messages"), format!("{conv}/messages"), format!("{base}/pins"), format!("{conv}/pins")]
    {
        let (s, j) = node.get_auth(&path, &g.teen.token).await;
        assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    }
    let (s, j) = node.send(&g.teen.token, room_id, &g.gated, "hi").await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (s, j) = node
        .req(Method::PUT, &format!("{conv}/messages/{message_id}/reactions/%F0%9F%91%8D"), Some(&g.teen.token), None)
        .await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (s, j) = node
        .req(
            Method::PUT,
            &format!("{conv}/read"),
            Some(&g.teen.token),
            Some(json!({ "last_read_message_id": message_id })),
        )
        .await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");

    // The open channel works; search finds nothing of the gated one.
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{}/messages", g.open), &g.teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, found) = node.get_auth(&format!("/api/v1/rooms/{room_id}/search?q=words"), &g.teen.token).await;
    assert_eq!(s, StatusCode::OK, "{found}");
    let text = found.to_string();
    assert!(text.contains("open words") && !text.contains("secret"), "{found}");
    let (_, adult_found) = node.get_auth(&format!("/api/v1/rooms/{room_id}/search?q=words"), &g.owner.token).await;
    assert!(adult_found.to_string().contains("secret words"), "{adult_found}");

    // Adults read it.
    let (s, j) = node.get_auth(&format!("{base}/messages"), &g.owner.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn attachments_voice_and_files_of_gated_channels_are_refused() {
    let g = gated_channel_setup().await;
    let (node, room_id) = (&g.node, g.room_id.as_str());
    // An attachment in the gated channel.
    let (s, h, body) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/channels/{}/uploads", g.gated),
            &g.owner.token,
            &[("content-type", "text/plain"), ("tavrn-file-name", "a.txt")],
            b"hello".to_vec(),
        )
        .await;
    assert!(s.is_success(), "{s} {h:?} {body:?}");
    let blob: Value = serde_json::from_slice(&body).unwrap();
    let blob_id = blob["id"].as_str().or(blob["blob_id"].as_str()).unwrap();
    let (s, j) = node.get_auth(&format!("/api/v1/blobs/{blob_id}"), &g.teen.token).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (s, _, j) = node
        .raw(
            Method::POST,
            &format!("/api/v1/rooms/{room_id}/channels/{}/uploads", g.gated),
            &g.teen.token,
            &[("content-type", "text/plain"), ("tavrn-file-name", "b.txt")],
            b"x".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j:?}");

    // A gated voice channel and a gated files channel.
    let (s, voice) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &g.owner.token,
            json!({ "kind": "voice", "name": "Late", "age_gate": "adults_only" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{voice}");
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels/{}/voice/join", voice["id"].as_str().unwrap()),
            &g.teen.token,
            json!({}),
        )
        .await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (s, files) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &g.owner.token,
            json!({ "kind": "files", "name": "shared", "age_gate": "adults_only" }),
        )
        .await;
    if s == StatusCode::CREATED {
        let (s, j) = node
            .get_auth(
                &format!("/api/v1/rooms/{room_id}/channels/{}/files", files["id"].as_str().unwrap()),
                &g.teen.token,
            )
            .await;
        assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    }
}

#[tokio::test]
async fn a_room_that_becomes_gated_locks_every_channel_for_its_minor_members() {
    let g = gated_channel_setup().await;
    let (node, room_id) = (&g.node, g.room_id.as_str());
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{}/messages", g.open), &g.teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = set_room_gate(node, &g.owner.token, room_id, "adults_only").await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{}/messages", g.open), &g.teen.token).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    // Still a member who can see the room and leave it.
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &g.teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.req(Method::POST, &format!("/api/v1/rooms/{room_id}/leave"), Some(&g.teen.token), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
}

#[tokio::test]
async fn minors_get_no_events_of_gated_channels() {
    let node = federation::FedNode::serve_one("t.local").await;
    let owner = node.register("owner").await;
    let teen = minor(&node, "teen").await;
    let room = node.plaintext_room(&owner.token, "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let open = TestNode::text_channel(&room);
    let (_, gated) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels"),
            &owner.token,
            json!({ "kind": "text", "name": "after-dark", "encrypted": false, "age_gate": "adults_only" }),
        )
        .await;
    let gated = gated["id"].as_str().unwrap().to_string();
    let (s, j) = invite_and_join(&node, &owner.token, &room_id, &teen.token).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let mut teen_ws = common::crossnode::ws(&node, &teen.token).await;
    let mut owner_ws = common::crossnode::ws(&node, &owner.token).await;
    node.send(&owner.token, &room_id, &gated, "late").await;
    let ev = common::crossnode::event(&mut owner_ws, "message.create").await;
    assert_eq!(ev["conversation_id"], gated.as_str());
    assert!(common::crossnode::no_event(&mut teen_ws, "message.create", 400).await, "no gated message events");
    node.send(&owner.token, &room_id, &open, "early").await;
    let ev = common::crossnode::event(&mut teen_ws, "message.create").await;
    assert_eq!(ev["conversation_id"], open.as_str());

    // Channel metadata still reaches the minor (the channel stays listed).
    node.patch(
        &format!("/api/v1/rooms/{room_id}/channels/{gated}"),
        &owner.token,
        json!({ "topic": "after midnight" }),
    )
    .await;
    let ev = common::crossnode::event(&mut teen_ws, "channel.update").await;
    assert_eq!(ev["id"], gated.as_str());
    // A channel that becomes gated later stops its events at once.
    node.patch(&format!("/api/v1/rooms/{room_id}/channels/{open}"), &owner.token, json!({ "age_gate": "adults_only" }))
        .await;
    common::crossnode::event(&mut teen_ws, "channel.update").await;
    node.send(&owner.token, &room_id, &open, "now gated").await;
    assert!(common::crossnode::no_event(&mut teen_ws, "message.create", 400).await);
}

// ---------------------------------------------------------------- privacy

/// Walks the responses that describe users to others: none carries the date of birth or the status.
#[tokio::test]
async fn no_other_route_carries_the_date_of_birth_or_the_status() {
    let node = test_node("t.local").await;
    let admin = node.register("admin").await;
    let teen = minor(&node, "teen").await;
    let room = node.plaintext_room(&admin.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    invite_and_join(&node, &admin.token, room_id, &teen.token).await;
    let (_, msg) = node.send(&teen.token, room_id, &TestNode::text_channel(&room), "hello").await;

    let dob = born_years_ago(16);
    let leaks = |what: &str, v: &Value| {
        let text = v.to_string();
        for needle in ["date_of_birth", "age_status", "age_over_18", "\"minor\"", dob.as_str()] {
            assert!(!text.contains(needle), "{what} leaks {needle}: {text}");
        }
    };
    leaks("message", &msg);
    for path in [
        "/api/v1/users/teen@t.local/profile".to_string(),
        format!("/api/v1/rooms/{room_id}"),
        format!("/api/v1/rooms/{room_id}/members"),
        format!("/api/v1/rooms/{room_id}/channels/{}/messages", TestNode::text_channel(&room)),
        "/api/v1/admin/users".to_string(),
        "/api/v1/admin/users?q=teen".to_string(),
        "/api/v1/admin/audit-log".to_string(),
        "/api/v1/users/me/friends".to_string(),
    ] {
        let (s, j) = node.get_auth(&path, &admin.token).await;
        assert!(s.is_success(), "{path}: {s} {j}");
        leaks(&path, &j);
    }
    let (_, j) = node.req(Method::GET, "/api/v1/users/teen@t.local/profile", None, None).await;
    leaks("anonymous profile", &j);
    // A session response of the user itself is fine, but the login response of another device does not need it.
    let year = dob[..4].to_string();
    assert!(year.parse::<i32>().unwrap() > today().year() - 20);
}

// ---------------------------------------------------------------- federation

#[derive(serde::Serialize)]
struct FedClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    jti: String,
    typ: &'static str,
    kind: &'static str,
    device: String,
    pv: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_over_18: Option<Value>,
}

fn claims(home: &str, user: &str, target: &str, device: &str, age: Option<Value>) -> FedClaims {
    let now = Utc::now().timestamp();
    FedClaims {
        iss: home.into(),
        sub: format!("{user}@{home}"),
        aud: target.into(),
        iat: now,
        exp: now + 300,
        jti: tavrn_node::util::ulid(),
        typ: "federation",
        kind: "user",
        device: device.into(),
        pv: 0,
        age_over_18: age,
    }
}

fn payload(token: &str) -> Value {
    use base64::Engine;
    let part = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

#[tokio::test]
async fn the_home_node_signs_the_age_claim_and_the_hosting_node_enforces_its_gates() {
    let (a, b) = federation::two_nodes().await;
    let owner = b.register("owner").await;
    let room = public_room(&b, &owner.token, "Gated").await;
    set_room_gate(&b, &owner.token, &room, "adults_only").await;

    let grown = a.register("grown").await;
    let teen = minor(&a, "teen").await;
    let grown_token = a.federation_token(&grown, b.domain()).await;
    assert_eq!(payload(&grown_token)["age_over_18"], true);
    let teen_token = a.federation_token(&teen, b.domain()).await;
    assert_eq!(payload(&teen_token)["age_over_18"], false);
    assert!(!payload(&teen_token).to_string().contains("date_of_birth"));

    let (s, j) = b.federated_login(&grown_token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let grown_b = j["access_token"].as_str().unwrap().to_string();
    for needle in ["age_over_18", "age_status", "date_of_birth"] {
        assert!(!j.to_string().contains(needle), "the federated session response never carries {needle}: {j}");
    }
    let (_, me_b) = b.get_auth("/api/v1/users/me", &grown_b).await;
    assert!(!me_b.to_string().contains("age"), "T never shows the claim: {me_b}");
    let (s, j) = b.post(&format!("/api/v1/rooms/{room}/join"), &grown_b, json!({})).await;
    assert_eq!(s, StatusCode::OK, "adult from another node joins: {j}");

    let (s, j) = b.federated_login(&teen_token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let teen_b = j["access_token"].as_str().unwrap().to_string();
    let (s, j) = b.post(&format!("/api/v1/rooms/{room}/join"), &teen_b, json!({})).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    let (_, list) = b.get_auth("/api/v1/rooms/discover", &teen_b).await;
    assert!(list.as_array().unwrap().is_empty(), "{list}");
    let (_, list) = b.get_auth("/api/v1/rooms/discover", &grown_b).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
}

#[tokio::test]
async fn unknown_missing_and_forged_age_claims_count_as_below_18() {
    let (a, b) = federation::two_nodes().await;
    let owner = b.register("owner").await;
    let room = public_room(&b, &owner.token, "Gated").await;
    set_room_gate(&b, &owner.token, &room, "adults_only").await;
    let user = a.register("someone").await;

    // Unknown (`null`) and absent (an older home node) are both "below 18".
    for (name, claim) in [("null", Some(Value::Null)), ("absent", None)] {
        let token = a.sign(&claims(a.domain(), "someone", b.domain(), &user.device_id, claim));
        let (s, j) = b.federated_login(&token).await;
        assert_eq!(s, StatusCode::OK, "{name}: {j}");
        let session = j["access_token"].as_str().unwrap();
        let (s, j) = b.post(&format!("/api/v1/rooms/{room}/join"), session, json!({})).await;
        assert_code(s, &j, StatusCode::FORBIDDEN, "age.restricted");
    }
    // A claim of the wrong type invalidates the token.
    let token = a.sign(&claims(a.domain(), "someone", b.domain(), &user.device_id, Some(json!("yes"))));
    let (s, j) = b.federated_login(&token).await;
    assert_code(s, &j, StatusCode::UNAUTHORIZED, "federation.token_invalid");
    // A claim signed by another key than the home node's is refused.
    let forger = tavrn_node::keys::NodeKey::generate("forged");
    let forged = tavrn_node::jwt::sign(
        &forger.signing,
        &a.state.signing_key().kid,
        &claims(a.domain(), "someone", b.domain(), &user.device_id, Some(json!(true))),
    )
    .unwrap();
    let (s, j) = b.federated_login(&forged).await;
    assert_code(s, &j, StatusCode::UNAUTHORIZED, "federation.token_invalid");
    // The genuine adult claim of the home node lets the user in.
    let token = a.sign(&claims(a.domain(), "someone", b.domain(), &user.device_id, Some(json!(true))));
    let (s, j) = b.federated_login(&token).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = b.post(&format!("/api/v1/rooms/{room}/join"), j["access_token"].as_str().unwrap(), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

#[tokio::test]
async fn accounts_without_a_date_of_birth_get_no_federation_token() {
    let (a, b) = federation::two_nodes().await;
    let old = a.register("old").await;
    forget_date_of_birth(&a, &old.user_id).await;
    let (s, j) = a.post("/api/v1/federation/token", &old.token, json!({ "target": b.domain() })).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");
}

#[tokio::test]
async fn single_sign_on_accounts_complete_the_date_of_birth_after_the_first_login() {
    use common::oidc::{FakeIdp, Login, configure, exchange};
    let idp = FakeIdp::start().await;
    let i = idp.clone();
    let node = test_node_with("sso.test", move |c| configure(c, &i)).await;
    node.register("admin").await;
    idp.set_login(Login::new("sub-sam", "sam"));
    let session = exchange(&node, "login", None).await.ok();
    let token = session["access_token"].as_str().unwrap();
    assert!(!session.to_string().contains("age_status"), "the login response does not carry the status");
    let (s, j) = node.get_auth("/api/v1/rooms", token).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.status_required");
    assert_eq!(me(&node, token).await["age_status"]["tier"], "unknown");
    let (s, j) =
        node.put("/api/v1/users/me/date-of-birth", token, json!({ "date_of_birth": born_years_ago(13) })).await;
    assert_code(s, &j, StatusCode::FORBIDDEN, "age.below_minimum");
    let (s, j) =
        node.put("/api/v1/users/me/date-of-birth", token, json!({ "date_of_birth": born_years_ago(17) })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["age_status"]["tier"], "minor");
    let (s, _) = node.get_auth("/api/v1/rooms", token).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn the_privacy_templates_explain_the_date_of_birth() {
    let node = test_node_with("t.local", |c| c.minimum_age = 18).await;
    let admin = node.register("admin").await;
    for (locale, needles) in [
        (
            "en",
            [
                "Date of birth and age gates",
                "on this node only",
                "18 or older: yes or no",
                "ask us to correct it",
                "at least 18 years",
            ],
        ),
        (
            "de",
            [
                "Geburtsdatum und Altersgrenzen",
                "nur auf diesem Knoten",
                "18 oder älter: ja oder nein",
                "Berichtigung",
                "mindestens 18 Jahre",
            ],
        ),
    ] {
        let (s, t) =
            node.get_auth(&format!("/api/v1/admin/legal/templates/privacy?locale={locale}"), &admin.token).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        let text = t["markdown"].as_str().unwrap();
        for needle in needles {
            assert!(text.contains(needle), "{locale}: {needle}");
        }
        assert!(!text.contains("{{minimum_age}}"), "{locale}");
    }
}
