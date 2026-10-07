// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Conversation index on the home node (FEDERATION.md §4): versions, `If-Match`, limits, owner only.

use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    TestNode,
    federation::{A, two_nodes},
    test_node,
};
use serde_json::{Value, json};

const PATH: &str = "/api/v1/users/me/conversations-index";
const ROOM: &str = "01J0000000000000000000000A";
const CONV: &str = "01J0000000000000000000000B";

fn room(node: &str, id: &str) -> Value {
    json!({ "node": node, "kind": "room", "room_id": id, "conversation_id": null, "joined_at": "2026-10-04T12:00:00Z" })
}

async fn put(node: &TestNode, token: &str, if_match: Option<&str>, body: Value) -> (StatusCode, Option<String>, Value) {
    let headers: Vec<(&str, &str)> = match if_match {
        Some(v) => vec![("content-type", "application/json"), ("if-match", v)],
        None => vec![("content-type", "application/json")],
    };
    let (status, headers, bytes) = node.raw(Method::PUT, PATH, token, &headers, body.to_string().into_bytes()).await;
    let etag = headers.get("etag").map(|v| v.to_str().unwrap().to_string());
    (status, etag, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn get(node: &TestNode, token: &str) -> (StatusCode, Option<String>, Value) {
    let resp = node.get_with(PATH, token).await;
    let status = resp.status();
    let etag = resp.headers().get("etag").map(|v| v.to_str().unwrap().to_string());
    (status, etag, common::body_json(resp).await)
}

#[tokio::test]
async fn versions_and_if_match() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;

    let (status, etag, json) = get(&a, &alice.token).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(etag.as_deref(), Some("\"0\""));
    assert_eq!(json, json!({ "version": 0, "items": [] }));

    // Unknown fields are kept unchanged (forward compatibility).
    let dm = json!({ "node": A, "kind": "dm", "room_id": null, "conversation_id": CONV, "peer": "bob@b.test", "joined_at": "2026-10-04T12:00:00Z", "muted": true });
    let (status, etag, json) =
        put(&a, &alice.token, Some("\"0\""), json!({ "items": [room("community.example", ROOM), dm] })).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(etag.as_deref(), Some("\"1\""));
    assert_eq!(json["version"], 1);
    let (_, _, stored) = get(&a, &alice.token).await;
    assert_eq!(stored["items"][1]["muted"], true);
    assert_eq!(stored["items"][1]["peer"], "bob@b.test");
    assert_eq!(stored["items"][0]["node"], "community.example");

    let (status, etag, _) = put(&a, &alice.token, Some("\"1\""), json!({ "items": [room(A, ROOM)] })).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"2\"")));

    // A stale version and a create on an existing index both conflict; meta names the current version.
    for stale in ["\"1\"", "\"0\"", "5"] {
        let (status, _, json) = put(&a, &alice.token, Some(stale), json!({ "items": [] })).await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{stale}");
        assert_eq!(json["code"], "index.version_conflict");
        assert_eq!(json["meta"]["version"], 2);
    }
    let (_, _, unchanged) = get(&a, &alice.token).await;
    assert_eq!(unchanged["items"].as_array().unwrap().len(), 1, "a conflict changes nothing");

    // Without If-Match the last writer wins.
    let (status, etag, json) = put(&a, &alice.token, None, json!({ "items": [] })).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"3\"")), "{json}");
    let (status, _, json) = put(&a, &alice.token, Some("W/\"3\""), json!({ "items": [] })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.if_match")));

    // A first write without If-Match creates the index at version 1.
    let bob = a.register("bob").await;
    let (status, etag, _) = put(&a, &bob.token, None, json!({ "items": [room(A, ROOM)] })).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"1\"")));
    let (_, _, alices) = get(&a, &alice.token).await;
    assert_eq!(alices["items"], json!([]), "every user has an own index");
}

#[tokio::test]
async fn entries_are_validated() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let cases = [
        (json!({ "items": [room("localhost", ROOM)] }), "validation.domain"),
        (
            json!({ "items": [{ "node": A, "kind": "room", "joined_at": "2026-10-04T12:00:00Z" }] }),
            "validation.required",
        ),
        (
            json!({ "items": [{ "node": A, "kind": "dm", "conversation_id": "x", "joined_at": "2026-10-04T12:00:00Z" }] }),
            "validation.id",
        ),
        (
            json!({ "items": [{ "node": A, "kind": "voice", "room_id": ROOM, "joined_at": "2026-10-04T12:00:00Z" }] }),
            "validation.enum",
        ),
        (json!({ "items": [room(A, ROOM), room(A, ROOM)] }), "validation.duplicate"),
        (json!({ "items": "all" }), "validation.required"),
        (json!([]), "validation.required"),
    ];
    for (body, code) in cases {
        let (status, _, json) = put(&a, &alice.token, None, body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(json["code"], code, "{body}");
    }
    let (status, _, json) = put(&a, &alice.token, None, json!("{")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
}

#[tokio::test]
async fn limits_entries_and_body_size() {
    let a = test_node(A).await;
    let alice = a.register("alice").await;
    let ids: Vec<String> = (0..2001).map(|_| tavrn_node::util::ulid()).collect();
    let items: Vec<Value> = ids.iter().map(|id| room(A, id)).collect();
    let (status, _, json) = put(&a, &alice.token, None, json!({ "items": items[..2000] })).await;
    assert_eq!(status, StatusCode::OK, "2000 entries are fine: {}", json["code"]);
    let (status, _, json) = put(&a, &alice.token, None, json!({ "items": items })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("index.too_large")));

    let padding = "x".repeat(600 * 1024);
    let (status, _, json) =
        put(&a, &alice.token, None, json!({ "items": [{ "node": A, "kind": "room", "room_id": ROOM, "joined_at": "2026-10-04T12:00:00Z", "pad": padding }] })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("index.too_large")));
}

#[tokio::test]
async fn only_local_users_with_a_session() {
    let (a, b) = two_nodes().await;
    let (status, json) = a.req(Method::GET, PATH, None, None).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("auth.required")));

    let bob = b.register("bob").await;
    let remote = a.sign_in_from(&b, &bob).await;
    let (status, _, json) = get(&a, &remote.token).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));
    let (status, _, json) = put(&a, &remote.token, None, json!({ "items": [] })).await;
    assert_eq!((status, json["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));
}
