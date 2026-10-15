// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A bot's interaction replies and follow-ups are messages like any other: the role mention rule, the room's and
//! the node's content rules and slowmode apply to them as to the bot's own posts.

use crate::common;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{Session, TestNode, body_bytes, test_node};
use serde_json::{Value, json};
use tavrn_node::{
    hub::{Event, Scope},
    interactions::ReceiverGuard,
    permissions as p,
};
use tokio::sync::broadcast;
use tower::ServiceExt;

const D: &str = common::e2ee::DOMAIN;

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

struct Bot {
    app_id: String,
    user_id: String,
    secret: String,
    device_id: String,
}

async fn bot(node: &TestNode, owner: &Session, name: &str) -> Bot {
    let body = json!({ "name": name, "public": true, "requested_permissions": mask(&[p::SEND_MESSAGES]) });
    let (s, app) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let (s, t) =
        node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, json!({ "name": "main" })).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
        device_id: t["token"]["device_id"].as_str().unwrap().into(),
    }
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
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = body_bytes(resp).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    })
}

async fn next_invoke(rx: &mut broadcast::Receiver<Arc<Event>>, guard: &ReceiverGuard, kind: &str) -> Value {
    let deadline = common::deadline(Duration::from_secs(5));
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.expect("no event").unwrap();
        if ev.kind == kind && matches!(ev.scope, Scope::Connection(c) if c == guard.id) {
            return ev.data.clone();
        }
    }
}

/// Replies and follow-ups that ping a role nobody may ping, or carry a word the room blocks, are refused like the
/// bot's own post of the same content; clean ones go through.
#[tokio::test]
async fn interaction_answers_pass_the_checks_of_a_message() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let b = bot(&node, &alice, "Raid").await;
    let room = node.plaintext_room(&carol.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &carol.token, json!({})).await;
    let (s, _) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/applications"),
            &carol.token,
            json!({ "application": format!("{D}/{}", b.app_id), "permissions": mask(&[p::SEND_MESSAGES]) }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, role) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &carol.token, json!({ "name": "Staff", "mentionable": false }))
        .await;
    let role_id = role["id"].as_str().unwrap().to_string();
    node.patch(&format!("/api/v1/rooms/{room_id}/members/{}", bob.user_id), &carol.token, json!({ "roles": [role_id] }))
        .await;
    let rule = json!({ "name": "nope", "terms": ["forbiddenword"], "whole_word": false, "links": "off", "domains": [],
                       "exempt_roles": [], "exempt_channels": [], "action": "block" });
    let (s, j) = node.put(&format!("/api/v1/rooms/{room_id}/automod"), &carol.token, json!({ "rules": [rule] })).await;
    assert_eq!(s, StatusCode::OK, "{j}");

    let post = format!("/api/v1/conversations/{channel}/messages");
    let card = json!({ "type": "text", "body": "Card", "components": [ { "type": "row", "components": [
        { "type": "button", "style": "primary", "label": "Go", "custom_id": "go" } ] } ] });
    let (s, m) = node.post(&post, &b.secret, json!({ "content": card })).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let message = m["id"].as_str().unwrap().to_string();
    let mut rx = node.state.hub.subscribe();
    let guard = node.state.interactions.register(&b.user_id, &b.device_id);
    let task = spawn_post(
        &node,
        format!("/api/v1/conversations/{channel}/messages/{message}/interactions"),
        &bob.token,
        json!({ "custom_id": "go" }),
    );
    let id = next_invoke(&mut rx, &guard, "component.invoke").await["interaction_id"].as_str().unwrap().to_string();
    let callback = format!("/api/v1/interactions/{id}/callback");
    let role_mention = json!({ "type": "reply", "content": { "type": "text", "body": "staff!" },
                               "mentions": [format!("role:{role_id}")] });
    let (s, j) = node.post(&callback, &b.secret, role_mention).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("message.mention_role_forbidden")), "{j}");
    let blocked = json!({ "type": "reply", "content": { "type": "text", "body": "forbiddenword" } });
    let (s, j) = node.post(&callback, &b.secret, blocked).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
    // A clean reply is still possible after the refusals.
    let (s, j) =
        node.post(&callback, &b.secret, json!({ "type": "reply", "content": { "type": "text", "body": "On it" } })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (_, res) = task.await.unwrap();
    assert_eq!(res["message"]["content"]["body"], "On it", "{res}");

    let followups = format!("/api/v1/interactions/{id}/messages");
    let (s, j) = node
        .post(
            &followups,
            &b.secret,
            json!({ "content": { "type": "text", "body": "hi" }, "mentions": [format!("role:{role_id}")] }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("message.mention_role_forbidden")), "{j}");
    let (s, j) =
        node.post(&followups, &b.secret, json!({ "content": { "type": "text", "body": "forbiddenword again" } })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("automod.blocked")), "{j}");
    let (s, j) = node.post(&followups, &b.secret, json!({ "content": { "type": "text", "body": "Done" } })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    let (_, list) = node.get_auth(&post, &bob.token).await;
    let bodies: Vec<&str> = list.as_array().unwrap().iter().filter_map(|m| m["content"]["body"].as_str()).collect();
    assert!(!bodies.iter().any(|b| b.contains("forbiddenword") || b.contains("staff")), "{bodies:?}");

    // Slowmode applies to the bot's follow-ups as to its posts.
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), &carol.token, json!({ "slowmode_secs": 60 }))
        .await;
    assert!(s.is_success(), "{j}");
    let (s, j) = node.post(&followups, &b.secret, json!({ "content": { "type": "text", "body": "Again" } })).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    drop(guard);
}
