// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Peer directory and Discover (FEDERATION.md §7, phase 3 step 6): `node.announce`, signed room
//! listings, `discoverable`, delisting, limits and housekeeping. The nodes talk through the real
//! federation client on loopback ports; `a.test` is the reference node of the others.

use crate::common;

use std::{sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::federation::{A, B, C, FedNode, three_nodes_with, two_nodes_with};
use serde_json::{Value, json};
use tavrn_node::{
    app::router,
    auth::RateLimiter,
    federation::{announce, tokens::body_sha256},
    jwt::{self, Expected},
    store::directory as dir,
    util,
};

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Two nodes; `b.test` announces itself to `a.test`.
async fn nodes() -> (FedNode, FedNode) {
    two_nodes_with(|_| {}, |c| c.reference_nodes = A.into()).await
}

fn envelope(id: &str, from: &str, to: &str, payload: Value) -> Vec<u8> {
    json!({ "id": id, "type": "node.announce", "from": from, "to": to, "at": util::now(), "payload": payload })
        .to_string()
        .into_bytes()
}

/// Posts `body` to `to`'s inbox with a node token of `from`.
async fn deliver(from: &FedNode, to: &FedNode, body: &[u8]) -> (StatusCode, Value) {
    let n = now();
    let claims = json!({
        "iss": from.domain(), "sub": from.domain(), "aud": to.domain(), "iat": n, "exp": n + 300,
        "jti": util::ulid(), "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox",
        "body_sha256": body_sha256(body),
    });
    let token = from.sign(&claims);
    let (status, _, bytes) = to
        .raw(Method::POST, "/api/v1/federation/inbox", &token, &[("content-type", "application/json")], body.to_vec())
        .await;
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() })
}

/// `from`'s own, valid announce payload.
async fn own_payload(from: &FedNode) -> Value {
    serde_json::to_value(announce::own_announce(&from.state).await.unwrap()).unwrap()
}

async fn announce_to(from: &FedNode, to: &FedNode, payload: Value) -> (StatusCode, Value) {
    deliver(from, to, &envelope(&util::ulid(), from.domain(), to.domain(), payload)).await
}

async fn public_room(node: &FedNode, token: &str, name: &str, description: &str) -> String {
    let (status, room) = node
        .post("/api/v1/rooms", token, json!({ "name": name, "description": description, "join_mode": "public" }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{room}");
    room["id"].as_str().unwrap().to_string()
}

async fn set_discoverable(node: &FedNode, token: &str, room: &str, on: bool) -> (StatusCode, Value) {
    node.patch(&format!("/api/v1/rooms/{room}"), token, json!({ "discoverable": on })).await
}

async fn get(node: &FedNode, path: &str) -> Value {
    let (status, json) = node.req(Method::GET, path, None, None).await;
    assert_eq!(status, StatusCode::OK, "{path}: {json}");
    json
}

fn names(list: &Value) -> Vec<String> {
    list["items"].as_array().unwrap().iter().map(|i| i["name"].as_str().unwrap().to_string()).collect()
}

fn domains(list: &Value) -> Vec<String> {
    list["items"].as_array().unwrap().iter().map(|i| i["domain"].as_str().unwrap().to_string()).collect()
}

/// The listed nodes of `node`'s directory except `node` itself (which lists itself).
async fn peers(node: &FedNode) -> Vec<String> {
    domains(&get(node, "/api/v1/directory/nodes").await).into_iter().filter(|d| d != node.domain()).collect()
}

/// Polls `path` on `node` until `ok` holds (the room refresh after an announce runs in the background).
async fn until(node: &FedNode, path: &str, ok: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..100 {
        let v = get(node, path).await;
        if ok(&v) {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{path} never matched: {}", get(node, path).await);
}

/// A discoverable room on B, announced to and listed by A. Returns (owner token, room id).
async fn listed_room(a: &FedNode, b: &FedNode, name: &str) -> (String, String) {
    let owner = b.register("owner").await;
    let room = public_room(b, &owner.token, name, "All about board games").await;
    let (status, j) = set_discoverable(b, &owner.token, &room, true).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let report = b.deliver().await;
    assert_eq!(report.delivered, 1, "{report:?}");
    until(a, "/api/v1/directory/rooms", |v| names(v).contains(&name.to_string())).await;
    (owner.token, room)
}

// ---------------------------------------------------------------- announce → listed

#[tokio::test]
async fn an_announced_node_and_its_rooms_are_listed() {
    let (a, b) = nodes().await;
    let (_, room) = listed_room(&a, &b, "Board games").await;

    let nodes = get(&a, "/api/v1/directory/nodes").await;
    assert_eq!(domains(&nodes), vec![A, B], "a listing node lists itself");
    let entry = &nodes["items"][1];
    assert_eq!(entry["name"], "Test node b.test");
    assert_eq!(entry["software"]["name"], "tavrn-node");
    assert_eq!(entry["registration"], "open");
    assert_eq!(entry["public_rooms"], 1);
    assert_eq!(entry["conformance"], "unknown");
    assert!(entry["capabilities"].as_array().unwrap().contains(&json!("federation.v1")));
    assert!(entry.get("users").is_none(), "only when published");
    assert_eq!(nodes["next"], Value::Null);

    // The detail carries the key fingerprints as A sees them.
    let detail = get(&a, "/api/v1/directory/nodes/b.test").await;
    let key = b.state.signing_key();
    assert_eq!(detail["keys"][0]["kid"], key.kid.as_str());
    let fingerprint = {
        use base64::Engine;
        use sha2::Digest;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key.verifying().as_bytes()))
    };
    assert_eq!(detail["keys"][0]["sha256"], fingerprint.as_str());
    let (status, j) = a.req(Method::GET, "/api/v1/directory/nodes/c.test", None, None).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("directory.node_not_found")));

    // The room as A serves it: B's values and B's signed listing, passed on verbatim.
    let rooms = get(&a, "/api/v1/directory/rooms").await;
    let item = &rooms["items"][0];
    assert_eq!((item["node"].as_str(), item["room_id"].as_str()), (Some(B), Some(room.as_str())));
    assert_eq!(item["member_count"], 1);
    assert_eq!(item["description"], "All about board games");
    assert_eq!(item["icon_url"], Value::Null);
    let expected = Expected { iss: B.into(), aud: announce::LISTING_AUD.into(), typ: "listing" };
    let (std, claims): (_, Value) =
        jwt::verify(item["listing"].as_str().unwrap(), &key.verifying(), &expected).expect("signed by b.test");
    assert_eq!(std.sub, room);
    assert_eq!(std.exp - std.iat, 48 * 3600);
    assert_eq!(claims["name"], "Board games");
    assert_eq!(claims["member_count"], 1);

    // Filters: search, node, minimum members, local only.
    assert_eq!(names(&get(&a, "/api/v1/directory/rooms?q=BOARD").await), vec!["Board games"]);
    assert_eq!(names(&get(&a, "/api/v1/directory/rooms?q=chess").await), Vec::<String>::new());
    assert_eq!(names(&get(&a, "/api/v1/directory/rooms?q=%25").await), Vec::<String>::new(), "wildcards are literal");
    assert_eq!(names(&get(&a, "/api/v1/directory/rooms?node=b.test").await), vec!["Board games"]);
    assert!(names(&get(&a, "/api/v1/directory/rooms?node=a.test").await).is_empty());
    assert!(names(&get(&a, "/api/v1/directory/rooms?min_members=2").await).is_empty());
    assert!(names(&get(&a, "/api/v1/directory/rooms?local=true").await).is_empty(), "A's own rooms only");
    assert_eq!(names(&get(&b, "/api/v1/directory/rooms?local=true").await), vec!["Board games"]);
    let (status, j) = a.req(Method::GET, "/api/v1/directory/rooms?cursor=broken", None, None).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("directory.cursor_invalid")));
    let (status, _) = a.req(Method::GET, &format!("/api/v1/directory/rooms?q={}", "x".repeat(101)), None, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn own_rooms_are_listed_with_own_signature_and_pages() {
    let (a, _b) = nodes().await;
    let owner = a.register("owner").await;
    let mut ids = Vec::new();
    for i in 0..3 {
        let id = public_room(&a, &owner.token, &format!("Room {i}"), "").await;
        assert_eq!(set_discoverable(&a, &owner.token, &id, true).await.0, StatusCode::OK);
        ids.push(id);
    }
    let hidden = public_room(&a, &owner.token, "Not listed", "").await;
    let first = get(&a, "/api/v1/directory/rooms?limit=2").await;
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let next = first["next"].as_str().unwrap().to_string();
    let second = get(&a, &format!("/api/v1/directory/rooms?limit=2&cursor={next}")).await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["next"], Value::Null);
    let mut all: Vec<String> = [&first, &second]
        .iter()
        .flat_map(|p| p["items"].as_array().unwrap().iter().map(|i| i["room_id"].as_str().unwrap().to_string()))
        .collect();
    all.sort();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(all, expected);
    assert!(!all.contains(&hidden));
    let key = a.state.signing_key().verifying();
    for item in first["items"].as_array().unwrap() {
        let expected = Expected { iss: A.into(), aud: announce::LISTING_AUD.into(), typ: "listing" };
        let (std, _): (_, Value) = jwt::verify(item["listing"].as_str().unwrap(), &key, &expected).unwrap();
        assert_eq!(std.sub, item["room_id"].as_str().unwrap());
    }
    // The legacy discover list shows only discoverable rooms too.
    let (_, discover) = a.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn a_listing_node_lists_itself_without_announcing_to_itself() {
    // a.test is its own reference node: the announce to itself stays refused.
    let (a, b) = two_nodes_with(|c| c.reference_nodes = A.into(), |c| c.reference_nodes = A.into()).await;
    assert_eq!(announce::enqueue_all(&a.state).await.unwrap(), 0, "no announce to the own domain");
    let owner = a.register("owner").await;
    let room = public_room(&a, &owner.token, "Regulars", "At our place").await;
    assert_eq!(set_discoverable(&a, &owner.token, &room, true).await.0, StatusCode::OK);

    let nodes = get(&a, "/api/v1/directory/nodes").await;
    assert_eq!(domains(&nodes), vec![A]);
    let me = &nodes["items"][0];
    assert_eq!(me["name"], "Test node a.test");
    assert_eq!(me["software"]["name"], "tavrn-node");
    assert_eq!(me["public_rooms"], 1);
    assert_eq!(me["conformance"], "unknown", "a node does not check itself");
    assert!(me["capabilities"].as_array().unwrap().contains(&json!("federation.v1")));
    let detail = get(&a, "/api/v1/directory/nodes/a.test").await;
    let key = a.state.signing_key();
    let fingerprint = {
        use base64::Engine;
        use sha2::Digest;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(key.verifying().as_bytes()))
    };
    assert_eq!(detail["keys"][0]["kid"], key.kid.as_str());
    assert_eq!(detail["keys"][0]["sha256"], fingerprint.as_str());
    assert_eq!(names(&get(&a, "/api/v1/directory/rooms").await), vec!["Regulars"]);
    // The search applies to the own entry like to every other.
    assert_eq!(domains(&get(&a, "/api/v1/directory/nodes?q=TEST%20NODE").await), vec![A]);
    assert!(domains(&get(&a, "/api/v1/directory/nodes?q=nowhere").await).is_empty());

    // With B announced: ordered by domain, pages keep the own entry in its place.
    assert_eq!(announce::enqueue_all(&b.state).await.unwrap(), 1);
    assert_eq!(b.deliver().await.delivered, 1);
    until(&a, "/api/v1/directory/nodes", |v| domains(v) == vec![A, B]).await;
    let first = get(&a, "/api/v1/directory/nodes?limit=1").await;
    assert_eq!((domains(&first), first["next"].as_str()), (vec![A.to_string()], Some(A)));
    let second = get(&a, "/api/v1/directory/nodes?limit=1&cursor=a.test").await;
    assert_eq!(domains(&second), vec![B]);
    let third = get(&a, &format!("/api/v1/directory/nodes?limit=1&cursor={}", second["next"].as_str().unwrap())).await;
    assert!(domains(&third).is_empty());
    assert_eq!(third["next"], Value::Null);

    // B learns A (and A's rooms) from A's list, A itself included, without A announcing to itself.
    announce::pull_reference(&b.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(domains(&get(&b, "/api/v1/directory/nodes").await), vec![A, B]);
    assert!(names(&get(&b, "/api/v1/directory/rooms").await).contains(&"Regulars".to_string()));
}

#[tokio::test]
async fn a_node_without_listing_does_not_list_itself() {
    let (a, _b) = two_nodes_with(|c| c.directory_listing = false, |_| {}).await;
    assert!(domains(&get(&a, "/api/v1/directory/nodes").await).is_empty());
    let (status, j) = a.req(Method::GET, "/api/v1/directory/nodes/a.test", None, None).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("directory.node_not_found")));
}

// ---------------------------------------------------------------- reports (§9.2)

#[tokio::test]
async fn users_report_nodes_and_admins_see_and_handle_the_reports() {
    let (a, b) = nodes().await;
    let admin = a.register("admin").await; // the first user of a dev node is node admin
    let room = util::ulid();
    let (status, r) = report(
        &a,
        &admin.token,
        json!({ "domain": "B.test", "room_id": room, "check": "spam", "detail": " Ads <b>everywhere</b> " }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{r}");
    assert_eq!(
        (r["domain"].as_str(), r["room_id"].as_str(), r["check"].as_str()),
        (Some(B), Some(room.as_str()), Some("spam"))
    );
    assert_eq!(r["detail"], "Ads <b>everywhere</b>", "stored as text, trimmed");
    assert_eq!(r["reporter"], "admin@a.test");

    // Validation.
    for (body, code) in [
        (json!({ "domain": "a.test", "check": "spam" }), "directory.report_self"),
        (json!({ "domain": "not valid", "check": "spam" }), "federation.domain_invalid"),
        (json!({ "domain": B, "check": "Spam!" }), "validation.check"),
        (json!({ "domain": B, "check": "" }), "validation.check"),
        (json!({ "domain": B, "check": "spam", "room_id": "x" }), "validation.id"),
        (json!({ "domain": B, "check": "spam", "detail": "x".repeat(1001) }), "validation.length"),
    ] {
        let (status, j) = report(&a, &admin.token, body.clone()).await;
        assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{body}");
    }
    let (status, _) =
        a.req(Method::POST, "/api/v1/directory/reports", None, Some(json!({ "domain": B, "check": "spam" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Remote users report to their own home node, not here.
    let carol = b.register("carol").await;
    let remote = a.sign_in_from(&b, &carol).await;
    let (status, j) = report(&a, &remote.token, json!({ "domain": "c.test", "check": "spam" })).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));

    // Three distinct reporters within 7 days leave one admin notice.
    let u1 = a.register("user1").await;
    let u2 = a.register("user2").await;
    let u3 = a.register("user3").await;
    assert_eq!(report(&a, &u1.token, json!({ "domain": B, "check": "keys.consistent" })).await.0, StatusCode::CREATED);
    assert_eq!(report(&a, &u1.token, json!({ "domain": B, "check": "abuse" })).await.0, StatusCode::CREATED);
    assert_eq!(notices(&a, &admin.token).await, 0, "two reporters");
    assert_eq!(report(&a, &u2.token, json!({ "domain": B, "check": "spam" })).await.0, StatusCode::CREATED);
    assert_eq!(notices(&a, &admin.token).await, 1, "the third reporter");
    assert_eq!(report(&a, &u3.token, json!({ "domain": B, "check": "spam" })).await.0, StatusCode::CREATED);
    assert_eq!(notices(&a, &admin.token).await, 1, "once");
    assert_eq!(report(&a, &u3.token, json!({ "domain": "c.test", "check": "other" })).await.0, StatusCode::CREATED);

    // At most 10 per user and day.
    for _ in 0..8 {
        assert_eq!(report(&a, &u3.token, json!({ "domain": "c.test", "check": "other" })).await.0, StatusCode::CREATED);
    }
    let (status, j) = report(&a, &u3.token, json!({ "domain": "c.test", "check": "other" })).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")));

    // The admin overview: counts per node, the list, delisting from there, dismissing.
    let (status, summary) = a.get_auth("/api/v1/admin/directory/reports", &admin.token).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    let of = |d: &str| summary.as_array().unwrap().iter().find(|s| s["domain"] == d).cloned().unwrap();
    assert_eq!(
        (of(B)["reports"].as_i64(), of(B)["reporters"].as_i64(), of(B)["recent"].as_i64()),
        (Some(5), Some(4), Some(5))
    );
    assert_eq!(of("c.test")["reports"], 9);
    assert_eq!(of(B)["delisted"], false);
    let (status, list) = a.get_auth("/api/v1/admin/directory/reports/b.test", &admin.token).await;
    assert_eq!(status, StatusCode::OK);
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 5);
    assert_eq!(list[0]["reporter"], "user3@a.test", "newest first");
    assert_eq!(list[4]["room_id"], room.as_str());
    assert_eq!(list[3]["room_id"], Value::Null);
    let (status, _) = a.delete("/api/v1/admin/directory/nodes/b.test", &admin.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, summary) = a.get_auth("/api/v1/admin/directory/reports", &admin.token).await;
    assert_eq!(summary.as_array().unwrap().iter().find(|s| s["domain"] == B).unwrap()["delisted"], true);
    let (status, _) = a.delete("/api/v1/admin/directory/reports/b.test", &admin.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, j) = a.delete("/api/v1/admin/directory/reports/b.test", &admin.token).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("directory.reports_not_found")));
    let (_, log) = a.get_auth("/api/v1/admin/audit-log?limit=100", &admin.token).await;
    assert!(
        log.as_array().unwrap().iter().any(|e| e["action"] == "admin.directory_reports_dismiss" && e["target"] == B)
    );

    // Admin routes are for node admins only.
    let (status, _) = a.get_auth("/api/v1/admin/directory/reports", &u1.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = a.get_auth("/api/v1/admin/directory/reports/c.test", &u1.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

async fn report(a: &FedNode, token: &str, body: Value) -> (StatusCode, Value) {
    a.post("/api/v1/directory/reports", token, body).await
}

/// Admin notices about reported nodes in the audit log.
async fn notices(a: &FedNode, admin: &str) -> usize {
    let (_, log) = a.get_auth("/api/v1/admin/audit-log?limit=100", admin).await;
    log.as_array().unwrap().iter().filter(|e| e["action"] == "directory.reports_notice").count()
}

// ---------------------------------------------------------------- discoverable

#[tokio::test]
async fn discoverable_is_for_public_rooms_by_room_managers_and_audited() {
    let (a, _b) = nodes().await;
    let owner = a.register("owner").await;
    let guest = a.register("guest").await;
    let (_, invite_room) = a.post("/api/v1/rooms", &owner.token, json!({ "name": "Secret" })).await;
    let invite_room = invite_room["id"].as_str().unwrap().to_string();
    let (status, j) = set_discoverable(&a, &owner.token, &invite_room, true).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("room.discoverable_public_only")));

    let room = public_room(&a, &owner.token, "Open", "").await;
    let (status, j) = a.post(&format!("/api/v1/rooms/{room}/join"), &guest.token, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let (status, j) = set_discoverable(&a, &guest.token, &room, true).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.manage_forbidden")));

    let (status, detail) = set_discoverable(&a, &owner.token, &room, true).await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(detail["discoverable"], true);
    let (_, discover) = a.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover[0]["id"], room.as_str());

    // Turning the room into an invite-only room removes it from the directory.
    let (status, detail) =
        a.patch(&format!("/api/v1/rooms/{room}"), &owner.token, json!({ "join_mode": "invite" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["discoverable"], false);
    let (_, discover) = a.req(Method::GET, "/api/v1/rooms/discover", None, None).await;
    assert_eq!(discover, json!([]));

    let (_, log) = a.get_auth(&format!("/api/v1/rooms/{room}/audit-log"), &owner.token).await;
    let changes: Vec<bool> = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "room.discoverable")
        .map(|e| e["meta"]["discoverable"].as_bool().unwrap())
        .collect();
    assert_eq!(changes, vec![false, true], "newest first: listed, then unlisted");
}

// ---------------------------------------------------------------- refused announces

#[tokio::test]
async fn unverifiable_and_malformed_announces_are_refused() {
    let (a, b) = nodes().await;
    let valid = own_payload(&b).await;
    let with = |f: &dyn Fn(&mut Value)| {
        let mut p = valid.clone();
        f(&mut p);
        p
    };
    let cases = [
        (
            with(&|p| p["software"]["version"] = json!("9.9.9")),
            StatusCode::BAD_REQUEST,
            "directory.announce_unverified",
        ),
        (with(&|p| p["name"] = json!("Another name")), StatusCode::BAD_REQUEST, "directory.announce_unverified"),
        (with(&|p| p["registration"] = json!("closed")), StatusCode::BAD_REQUEST, "directory.announce_unverified"),
        (
            with(&|p| p["capabilities"].as_array_mut().unwrap().push(json!("voice.v9"))),
            StatusCode::BAD_REQUEST,
            "directory.announce_unverified",
        ),
        (with(&|p| p["domain"] = json!(C)), StatusCode::FORBIDDEN, "federation.type_forbidden"),
        (with(&|p| p["description"] = json!("d".repeat(501))), StatusCode::BAD_REQUEST, "federation.envelope_invalid"),
        (with(&|p| p["pad"] = json!("x".repeat(9000))), StatusCode::PAYLOAD_TOO_LARGE, "federation.payload_too_large"),
        (json!({ "domain": B }), StatusCode::BAD_REQUEST, "federation.envelope_invalid"),
    ];
    for (payload, status, code) in cases {
        let (s, j) = announce_to(&b, &a, payload.clone()).await;
        assert_eq!((s, j["code"].as_str()), (status, Some(code)), "{payload}: {j}");
    }
    assert!(peers(&a).await.is_empty());

    // `from` must be the sender itself (inbox authority rule); a forged `from` is spoofing and blocks the
    // sender automatically (FEDERATION.md §9.4) until the block is lifted.
    let body = envelope(&util::ulid(), C, A, valid.clone());
    let (s, j) = deliver(&b, &a, &body).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.type_forbidden")));
    let (s, j) = deliver(&b, &a, &envelope(&util::ulid(), B, A, valid.clone())).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
    assert!(tavrn_node::federation::conformance::set_manual_block(&a.state, B, false, "").await.unwrap());

    // The valid announce is accepted, a duplicate is accepted without effect.
    let id = util::ulid();
    assert_eq!(deliver(&b, &a, &envelope(&id, B, A, valid.clone())).await.0, StatusCode::ACCEPTED);
    assert_eq!(deliver(&b, &a, &envelope(&id, B, A, valid.clone())).await.0, StatusCode::ACCEPTED);
    assert_eq!(peers(&a).await, vec![B]);

    // `listing: false` takes the node out again.
    let (s, _) = announce_to(&b, &a, with(&|p| p["listing"] = json!(false))).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert!(peers(&a).await.is_empty());

    // B is down: the token still verifies with A's cached copy of B's keys, but the announce needs a
    // fresh document and is refused (B retries later).
    b.stop().await;
    let (s, j) = announce_to(&b, &a, valid).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("federation.peer_unreachable")));
}

#[tokio::test]
async fn a_node_that_opted_out_cannot_be_listed() {
    let (a, b) = two_nodes_with(
        |_| {},
        |c| {
            c.reference_nodes = A.into();
            c.directory_listing = false;
        },
    )
    .await;
    let owner = b.register("owner").await;
    let room = public_room(&b, &owner.token, "Privately listed", "").await;
    assert_eq!(set_discoverable(&b, &owner.token, &room, true).await.0, StatusCode::OK);
    // TAVRN_DIRECTORY_LISTING=false sends nothing …
    assert!(b.outbox().await.is_empty());
    assert_eq!(announce::enqueue_all(&b.state).await.unwrap(), 0);
    // … and a forged announce is refused: B's own document says it does not want to be listed.
    let (s, j) = announce_to(&b, &a, own_payload(&b).await).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("directory.announce_unverified")));
    // Not even through a reference node's list.
    assert!(!announce::add_relayed(&a.state, B).await.unwrap());
    assert!(peers(&a).await.is_empty());
}

#[tokio::test]
async fn announces_go_to_reference_nodes_only_and_replace_each_other() {
    let (a, b) = nodes().await;
    let owner = b.register("owner").await;
    let room = public_room(&b, &owner.token, "Room", "").await;
    assert!(b.outbox().await.is_empty(), "a public room alone is not listed");
    set_discoverable(&b, &owner.token, &room, true).await;
    b.patch(&format!("/api/v1/rooms/{room}"), &owner.token, json!({ "name": "New name" })).await;
    b.patch(&format!("/api/v1/rooms/{room}"), &owner.token, json!({ "rules": "Be nice" })).await;
    let queued = b.outbox().await;
    assert_eq!(queued.len(), 1, "the pending announce is replaced");
    assert_eq!((queued[0].target.as_str(), queued[0].kind.as_str()), (A, "node.announce"));
    let body: Value = serde_json::from_str(&queued[0].body).unwrap();
    assert_eq!(body["from"], B);
    assert_eq!(body["to"], A);
    assert_eq!(body["payload"]["public_rooms"], 1);
    assert_eq!(body["payload"]["listing"], true);
    // A has no reference nodes (the default): it never announces and pulls no node list.
    assert_eq!(announce::enqueue_all(&a.state).await.unwrap(), 0);
    assert_eq!(announce::pull_reference(&a.state, chrono::Utc::now()).await.unwrap(), 0);
    // Deleting a listed room announces again.
    assert_eq!(b.deliver().await.delivered, 1);
    let (status, _) = b.delete(&format!("/api/v1/rooms/{room}"), &owner.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(b.outbox().await.len(), 1);
}

// ---------------------------------------------------------------- listings

#[tokio::test]
async fn listings_are_only_accepted_when_the_hosting_node_signed_them() {
    let (a, b) = nodes().await;
    let room = util::ulid();
    let n = now();
    let claims = |iss: &str, sub: &str, aud: &str, typ: &str, iat: i64, exp: i64| {
        json!({
            "iss": iss, "sub": sub, "aud": aud, "typ": typ, "iat": iat, "exp": exp, "jti": util::ulid(),
            "name": "Room", "description": "", "icon_sha256": null, "member_count": 3,
        })
    };
    let good = b.sign(&claims(B, &room, "tavrn-directory", "listing", n, n + 3600));
    let verified = announce::verify_listing(&a.state, B, &room, &good).await.expect("valid listing");
    assert_eq!((verified.name.as_str(), verified.member_count), ("Room", 3));
    let bad = [
        // Signed by A, claiming to be B's.
        a.sign(&claims(B, &room, "tavrn-directory", "listing", n, n + 3600)),
        // B's signature for another room.
        b.sign(&claims(B, &util::ulid(), "tavrn-directory", "listing", n, n + 3600)),
        b.sign(&claims(B, &room, "b.test", "listing", n, n + 3600)),
        b.sign(&claims(B, &room, "tavrn-directory", "s2s", n, n + 3600)),
        b.sign(&claims(B, &room, "tavrn-directory", "listing", n - 7200, n - 60)),
        b.sign(&claims(B, &room, "tavrn-directory", "listing", n, n + 30 * 24 * 3600)),
        "not.a.jwt.token".to_string(),
    ];
    for token in bad {
        assert!(announce::verify_listing(&a.state, B, &room, &token).await.is_none(), "{token}");
    }
    // A listing of B is never valid for another node.
    assert!(announce::verify_listing(&a.state, C, &room, &good).await.is_none());
}

// ---------------------------------------------------------------- delisting and blocks

#[tokio::test]
async fn admins_delist_nodes_and_rooms() {
    let (a, b) = nodes().await;
    let admin = a.register("admin").await;
    let user = a.register("user").await;
    let (_owner, room) = listed_room(&a, &b, "Board games").await;

    let (status, _) = a.delete("/api/v1/admin/directory/nodes/b.test", &user.token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, j) = a.delete(&format!("/api/v1/admin/directory/rooms/b.test/{room}"), &admin.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
    assert!(names(&get(&a, "/api/v1/directory/rooms").await).is_empty());
    assert_eq!(peers(&a).await, vec![B], "the node stays");
    let (status, j) = a.delete(&format!("/api/v1/admin/directory/rooms/b.test/{room}"), &admin.token).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::CONFLICT, Some("directory.already_delisted")));
    // A refresh does not bring the room back.
    assert_eq!(announce::refresh_rooms(&a.state, B).await.unwrap(), 1, "cached, but not shown");
    assert!(names(&get(&a, "/api/v1/directory/rooms").await).is_empty());

    let (status, _) = a.delete("/api/v1/admin/directory/nodes/b.test", &admin.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(peers(&a).await.is_empty());
    let (status, _) = a.req(Method::GET, "/api/v1/directory/nodes/b.test", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A new announce is accepted but does not list the node again.
    let (s, _) = announce_to(&b, &a, own_payload(&b).await).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    assert!(peers(&a).await.is_empty());
    assert!(dir::node(&a.state.db, B).await.unwrap().is_none());

    let (status, j) = a.delete("/api/v1/admin/directory/nodes/a.test", &admin.token).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("directory.delist_self")));
    let (status, j) = a.delete("/api/v1/admin/directory/nodes/broken..x", &admin.token).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("federation.domain_invalid")));

    let (_, list) = a.get_auth("/api/v1/admin/directory/delisted", &admin.token).await;
    let entries: Vec<(String, Value)> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["node"].as_str().unwrap().to_string(), e["room_id"].clone()))
        .collect();
    assert!(entries.contains(&(B.to_string(), Value::Null)));
    assert!(entries.contains(&(B.to_string(), json!(room))));
    let (_, log) = a.get_auth("/api/v1/admin/audit-log", &admin.token).await;
    assert!(log.as_array().unwrap().iter().any(|e| e["action"] == "admin.directory_delist" && e["target"] == B));

    // Relisting brings the node back (verified again) and the room once its delisting is lifted too.
    let (status, _) = a.post("/api/v1/admin/directory/relist", &admin.token, json!({ "node": B })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    until(&a, "/api/v1/directory/nodes", |v| domains(v) == vec![A, B]).await;
    let (status, _) =
        a.post("/api/v1/admin/directory/relist", &admin.token, json!({ "node": B, "room_id": room })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    until(&a, "/api/v1/directory/rooms", |v| names(v) == vec!["Board games".to_string()]).await;
    let (status, j) = a.post("/api/v1/admin/directory/relist", &admin.token, json!({ "node": B })).await;
    assert_eq!((status, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("directory.not_delisted")));
}

#[tokio::test]
async fn blocked_nodes_are_never_listed() {
    let (a, b) = nodes().await;
    let admin = a.register("admin").await;
    listed_room(&a, &b, "Board games").await;
    // A node ban of the domain hides the node and its rooms at once.
    let (status, j) = a.post("/api/v1/admin/bans", &admin.token, json!({ "subject": B, "reason": "Spam" })).await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    assert!(peers(&a).await.is_empty());
    assert!(names(&get(&a, "/api/v1/directory/rooms").await).is_empty());
    let (status, _) = a.req(Method::GET, "/api/v1/directory/nodes/b.test", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (s, j) = announce_to(&b, &a, own_payload(&b).await).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));

    // The configured blocklist as well.
    let (a, b) = two_nodes_with(|c| c.federation_blocklist = B.into(), |c| c.reference_nodes = A.into()).await;
    let (s, j) = announce_to(&b, &a, own_payload(&b).await).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")));
    assert!(announce::add_relayed(&a.state, B).await.is_err());
}

// ---------------------------------------------------------------- limits

#[tokio::test]
async fn announces_are_rate_limited_per_domain() {
    let (mut a, b) = nodes().await;
    let strict = |a: &mut FedNode| {
        // The production limit: one announce per domain and 10 minutes.
        a.node.state.directory_announce_limiter = Arc::new(RateLimiter::new(1, Duration::from_secs(600)));
        a.node.router = router(a.node.state.clone());
    };
    strict(&mut a);
    let payload = own_payload(&b).await;
    assert_eq!(announce_to(&b, &a, payload.clone()).await.0, StatusCode::ACCEPTED);
    dir::delete_node(&a.state.db, B).await.unwrap();
    let id = util::ulid();
    let (s, j) = deliver(&b, &a, &envelope(&id, B, A, payload.clone())).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert!(dir::node(&a.state.db, B).await.unwrap().is_none());
    // A refused announce is not recorded as seen: the retry of the same message is processed.
    strict(&mut a);
    assert_eq!(deliver(&b, &a, &envelope(&id, B, A, payload)).await.0, StatusCode::ACCEPTED);
    assert!(dir::node(&a.state.db, B).await.unwrap().is_some());
}

#[tokio::test]
async fn cached_rooms_are_capped() {
    let (a, b) = two_nodes_with(|c| c.directory_max_rooms = 2, |c| c.reference_nodes = A.into()).await;
    let owner = b.register("owner").await;
    for i in 0..3 {
        let id = public_room(&b, &owner.token, &format!("Room {i}"), "").await;
        set_discoverable(&b, &owner.token, &id, true).await;
    }
    assert_eq!(b.deliver().await.delivered, 1);
    until(&a, "/api/v1/directory/nodes/b.test", |v| v["public_rooms"] == 2).await;
    assert_eq!(get(&a, "/api/v1/directory/rooms").await["items"].as_array().unwrap().len(), 2);
    assert_eq!(dir::cached_room_count(&a.state.db).await.unwrap(), 2);
}

// ---------------------------------------------------------------- housekeeping

#[tokio::test]
async fn nodes_not_announced_for_48_hours_are_removed() {
    let (a, b) = nodes().await;
    listed_room(&a, &b, "Board games").await;
    let now = chrono::Utc::now();
    let report = announce::tick(&a.state, now + chrono::Duration::hours(47)).await.unwrap();
    assert_eq!((report.pruned_nodes, report.pruned_rooms), (0, 0));
    // The room list is older than 6 hours at that time: refreshed.
    assert_eq!(report.refreshed, 1);
    assert_eq!(peers(&a).await, vec![B]);
    let report = announce::tick(&a.state, now + chrono::Duration::hours(49)).await.unwrap();
    assert_eq!((report.pruned_nodes, report.pruned_rooms), (1, 1));
    assert!(peers(&a).await.is_empty());
    assert!(names(&get(&a, "/api/v1/directory/rooms").await).is_empty());
}

// ---------------------------------------------------------------- reference node lists

#[tokio::test]
async fn nodes_learn_the_directory_from_their_reference_node() {
    // c.test announces itself to a.test; b.test pulls a.test's list and verifies c.test itself.
    let (a, b, c) =
        three_nodes_with(|_| {}, |cfg| cfg.reference_nodes = A.into(), |cfg| cfg.reference_nodes = A.into()).await;
    let owner = c.register("owner").await;
    let room = public_room(&c, &owner.token, "Chess", "").await;
    set_discoverable(&c, &owner.token, &room, true).await;
    assert_eq!(c.deliver().await.delivered, 1);
    until(&a, "/api/v1/directory/rooms", |v| names(v) == vec!["Chess".to_string()]).await;

    let verified = announce::pull_reference(&b.state, chrono::Utc::now()).await.unwrap();
    assert_eq!(verified, 2, "the reference node and c.test");
    assert_eq!(peers(&b).await, vec![A, C]);
    let rooms = get(&b, "/api/v1/directory/rooms").await;
    assert_eq!(names(&rooms), vec!["Chess"]);
    assert_eq!(rooms["items"][0]["node"], C);
    // Fresh entries are not fetched again within the refresh interval.
    assert_eq!(announce::pull_reference(&b.state, chrono::Utc::now()).await.unwrap(), 0);

    // A node a.test delisted is not passed on.
    let admin = a.register("admin").await;
    let (status, _) = a.delete("/api/v1/admin/directory/nodes/c.test", &admin.token).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!peers(&a).await.contains(&C.to_string()));
    assert!(names(&get(&a, "/api/v1/directory/rooms").await).is_empty());
}
