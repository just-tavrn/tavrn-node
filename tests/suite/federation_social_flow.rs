// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Federation, phase 3 step 4 (FEDERATION.md §4–§6): friends, DMs and group DMs across nodes, the
//! invite list, `notify` push hints and revocations to contacts' home nodes.

use crate::common;

use axum::http::StatusCode;
use common::{
    Session,
    crossnode::{event, no_event, ws},
    federation::{A, B, C, FedNode, three_nodes_with, two_nodes, two_nodes_with},
};
use serde_json::{Value, json};
use tavrn_node::config::DmPolicy;

async fn friends(node: &FedNode, s: &Session) -> Value {
    let (st, j) = node.get_auth("/api/v1/users/me/friends", &s.token).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    j
}

fn addresses(list: &Value, key: &str) -> Vec<String> {
    list[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["user"]["address"].as_str().or(e["address"].as_str()).unwrap().to_string())
        .collect()
}

async fn request(node: &FedNode, s: &Session, user: &str) -> (StatusCode, Value) {
    node.post("/api/v1/users/me/friends/requests", &s.token, json!({ "user": user })).await
}

/// alice (A) and bob (B) become friends across the nodes.
async fn befriend(a: &FedNode, alice: &Session, b: &FedNode, bob: &Session) {
    let (st, j) = request(a, alice, &format!("{}@{B}", bob.username)).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert!(a.deliver().await.delivered >= 1);
    let incoming = friends(b, bob).await["incoming"][0]["id"].as_str().unwrap().to_string();
    let (st, j) = b.post(&format!("/api/v1/users/me/friends/requests/{incoming}/accept"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert!(b.deliver().await.delivered >= 1);
    assert_eq!(addresses(&friends(a, alice).await, "friends"), vec![format!("{}@{B}", bob.username)]);
}

// ---------------------------------------------------------------- friends

#[tokio::test]
async fn friend_request_accept_and_remove_across_nodes() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let mut bob_ws = ws(&b, &bob.token).await;

    let (st, j) = request(&a, &alice, "bob@b.test").await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(j["status"], "pending");
    assert_eq!(j["user"]["address"], "bob@b.test");
    assert_eq!(addresses(&friends(&a, &alice).await, "outgoing"), vec!["bob@b.test"]);
    let kinds: Vec<String> = a.outbox().await.into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec!["friend.request"]);
    assert_eq!(a.deliver().await.delivered, 1);
    let pushed = event(&mut bob_ws, "friend.request").await;
    assert_eq!(pushed["request"]["user"]["address"], "alice@a.test");
    assert_eq!(pushed["request"]["direction"], "incoming");
    let list = friends(&b, &bob).await;
    assert_eq!(addresses(&list, "incoming"), vec!["alice@a.test"]);

    let rid = list["incoming"][0]["id"].as_str().unwrap();
    let (st, j) = b.post(&format!("/api/v1/users/me/friends/requests/{rid}/accept"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(b.deliver().await.delivered, 1);
    assert_eq!(addresses(&friends(&b, &bob).await, "friends"), vec!["alice@a.test"]);
    let list = friends(&a, &alice).await;
    assert_eq!(addresses(&list, "friends"), vec!["bob@b.test"]);
    assert!(list["outgoing"].as_array().unwrap().is_empty());

    // Unfriending on A ends the friendship on B.
    let (st, j) = a.delete("/api/v1/users/me/friends/bob@b.test", &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(a.deliver().await.delivered, 1);
    assert!(friends(&b, &bob).await["friends"].as_array().unwrap().is_empty());
    assert!(friends(&a, &alice).await["friends"].as_array().unwrap().is_empty());

    // Declining on B removes the outgoing request on A; withdrawing on A removes the incoming one on B.
    request(&a, &alice, "bob@b.test").await;
    a.deliver().await;
    let rid = friends(&b, &bob).await["incoming"][0]["id"].as_str().unwrap().to_string();
    let (st, _) = b.delete(&format!("/api/v1/users/me/friends/requests/{rid}"), &bob.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(b.deliver().await.delivered, 1);
    assert!(friends(&a, &alice).await["outgoing"].as_array().unwrap().is_empty());

    let (_, j) = request(&a, &alice, "bob@b.test").await;
    a.deliver().await;
    assert_eq!(addresses(&friends(&b, &bob).await, "incoming"), vec!["alice@a.test"]);
    let rid = j["request_id"].as_str().unwrap();
    let (st, _) = a.delete(&format!("/api/v1/users/me/friends/requests/{rid}"), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(a.deliver().await.delivered, 1);
    assert!(friends(&b, &bob).await["incoming"].as_array().unwrap().is_empty());

    // Unknown users of other nodes are not found.
    let (st, j) = request(&a, &alice, "nobody@b.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("user.not_found")), "{j}");
}

#[tokio::test]
async fn crossing_requests_become_friends_on_both_nodes() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    assert_eq!(request(&a, &alice, "bob@b.test").await.0, StatusCode::CREATED);
    assert_eq!(request(&b, &bob, "alice@a.test").await.0, StatusCode::CREATED);
    for _ in 0..3 {
        a.deliver().await;
        b.deliver().await;
    }
    assert_eq!(addresses(&friends(&a, &alice).await, "friends"), vec!["bob@b.test"]);
    assert_eq!(addresses(&friends(&b, &bob).await, "friends"), vec!["alice@a.test"]);
    assert!(friends(&a, &alice).await["outgoing"].as_array().unwrap().is_empty());
    assert!(friends(&b, &bob).await["incoming"].as_array().unwrap().is_empty());
    assert!(a.outbox().await.is_empty() && b.outbox().await.is_empty());
}

#[tokio::test]
async fn blocks_apply_on_both_sides() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;

    // bob blocks alice on B: her request is dropped there without a trace.
    let (st, j) = b.post("/api/v1/users/me/blocks", &bob.token, json!({ "user": "alice@a.test" })).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(addresses(&friends(&b, &bob).await, "blocked"), vec!["alice@a.test"]);
    let (st, j) = request(&a, &alice, "bob@b.test").await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(a.deliver().await.delivered, 1);
    assert!(friends(&b, &bob).await["incoming"].as_array().unwrap().is_empty());
    let (st, _) = b.delete("/api/v1/users/me/blocks/alice@a.test", &bob.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let rid = j["request_id"].as_str().unwrap();
    let (st, _) = a.delete(&format!("/api/v1/users/me/friends/requests/{rid}"), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    a.deliver().await;

    // Friends, then alice blocks bob on A: the friendship ends on both nodes, nothing reveals the block.
    befriend(&a, &alice, &b, &bob).await;
    let (st, _) = a.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "bob@b.test" })).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let kinds: Vec<String> = a.outbox().await.into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec!["friend.remove"]);
    let body: Value = serde_json::from_str(&a.outbox().await[0].body).unwrap();
    assert_eq!(body["payload"], json!({ "request_id": null }));
    assert_eq!(a.deliver().await.delivered, 1);
    assert!(friends(&b, &bob).await["friends"].as_array().unwrap().is_empty());
    let (st, j) = request(&a, &alice, "bob@b.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("friend.blocked")));
}

#[tokio::test]
async fn friend_messages_are_retried_while_b_is_down() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    befriend(&a, &alice, &b, &bob).await;
    b.stop().await;
    let (st, _) = a.delete("/api/v1/users/me/friends/bob@b.test", &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let report = a.deliver().await;
    assert_eq!((report.delivered, report.retried), (0, 1), "{report:?}");
    b.start().await;
    assert_eq!(a.deliver().await.delivered, 0, "not due yet");
    assert_eq!(a.deliver_at(70).await.delivered, 1);
    assert!(friends(&b, &bob).await["friends"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn undeliverable_requests_are_reported_to_the_user_and_counted() {
    let (a, b) = two_nodes().await;
    let admin = a.register("admin").await;
    let alice = a.register("alice").await;
    b.register("bob").await;
    assert_eq!(request(&a, &alice, "bob@b.test").await.0, StatusCode::CREATED);
    b.stop().await;
    let mut alice_ws = ws(&a, &alice.token).await;
    assert_eq!(a.deliver().await.retried, 1);
    let report = a.deliver_at(3 * 24 * 3600 + 1).await;
    assert_eq!(report.given_up, 1, "{report:?}");
    let notice = event(&mut alice_ws, "federation.undeliverable").await;
    assert_eq!(notice, json!({ "type": "friend.request", "to": "bob@b.test" }));
    let (st, overview) = a.get_auth("/api/v1/admin/overview", &admin.token).await;
    assert_eq!(st, StatusCode::OK, "{overview}");
    assert_eq!(overview["federation_undeliverable"], 1);
    // The request stays visible as outgoing and can be withdrawn and sent again.
    assert_eq!(addresses(&friends(&a, &alice).await, "outgoing"), vec!["bob@b.test"]);
}

// ---------------------------------------------------------------- DMs

#[tokio::test]
async fn a_dm_across_nodes_follows_dm_policy_and_carries_encrypted_messages() {
    // A allows DMs among friends only (the operator's bound): no message requests from A at all.
    let (a, b) = two_nodes_with(|c| c.dm_policy = DmPolicy::Friends, |_| {}).await;
    let mut alice = a.crypto_user("alice", 3).await;
    let mut bob = b.crypto_user("bob", 3).await;
    let create = json!({ "kind": "dm", "members": ["bob@b.test"] });
    let (st, j) = a.post("/api/v1/conversations", alice.token(), create.clone()).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.not_friends")), "{j}");

    befriend(&a, &alice.session, &b, &bob.session).await;
    let mut bob_ws = ws(&b, bob.token()).await;
    let (st, dm) = a.post("/api/v1/conversations", alice.token(), create.clone()).await;
    assert_eq!(st, StatusCode::CREATED, "{dm}");
    let dm_id = dm["id"].as_str().unwrap().to_string();
    let mut members: Vec<&str> =
        dm["members"].as_array().unwrap().iter().map(|m| m["address"].as_str().unwrap()).collect();
    members.sort();
    assert_eq!(members, vec!["alice@a.test", "bob@b.test"]);
    assert_eq!(a.post("/api/v1/conversations", alice.token(), create).await.0, StatusCode::OK, "idempotent");

    // The invitation reaches bob's invite list on B.
    assert_eq!(a.deliver().await.delivered, 1);
    let pushed = event(&mut bob_ws, "conversation.invite").await;
    assert_eq!(pushed["invite"]["conversation"]["id"], dm_id.as_str());
    let (_, list) = b.get_auth("/api/v1/users/me/invites", bob.token()).await;
    let inv = &list["items"][0];
    assert_eq!(inv["kind"], "conversation");
    assert_eq!(inv["node"], A);
    assert_eq!(inv["inviter"], "alice@a.test");
    assert_eq!(inv["conversation"]["kind"], "dm");

    // bob accepts with a federated session on A; alice adds his device through A's claim proxy.
    let remote = a.sign_in_from(&b, &bob.session).await;
    let (st, convs) = a.get_auth("/api/v1/conversations", &remote.token).await;
    assert_eq!(st, StatusCode::OK, "{convs}");
    assert_eq!(convs[0]["id"], dm_id.as_str());
    a.mls_group(A, &alice.session.token, &mut alice.client, &dm_id).await;
    a.add_to_group(A, &alice.session.token, &mut alice.client, &dm_id, "bob@b.test").await;
    assert_eq!(a.join_welcomes(A, &remote.token, &mut bob.client).await, 1);

    let (st, m) = a.send_secret(A, alice.token(), &alice.client, &dm_id, "Hello Bob").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    assert_eq!(a.read_secret(A, &remote.token, &bob.client, &dm_id).await, "Hello Bob");
    let (st, m) = a.send_secret(A, &remote.token, &bob.client, &dm_id, "Hello Alice").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    assert_eq!(m["device_id"], bob.session.device_id.as_str());
    assert_eq!(a.read_secret(A, alice.token(), &alice.client, &dm_id).await, "Hello Alice");

    // Remote users still cannot create conversations on A (they live on the initiator's home node).
    let (st, j) =
        a.post("/api/v1/conversations", &remote.token, json!({ "kind": "dm", "members": ["alice@a.test"] })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));
}

#[tokio::test]
async fn the_recipients_node_applies_its_own_dm_policy() {
    // A allows DMs with anyone, B only among friends: the invitation is dropped on B.
    let (a, b) = two_nodes_with(|c| c.dm_policy = DmPolicy::Everyone, |_| {}).await;
    let alice = a.register("alice").await;
    let carol = b.register("carol").await;
    let (st, j) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["carol@b.test"] })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(a.deliver().await.delivered, 1);
    let (_, list) = b.get_auth("/api/v1/users/me/invites", &carol.token).await;
    assert!(list["items"].as_array().unwrap().is_empty(), "{list}");

    // Blocks known on A refuse the DM there.
    let dave = b.register("dave").await;
    let (st, _) = a.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "dave@b.test" })).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["dave@b.test"] })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.blocked")), "{j}");
    let _ = dave;
}

#[tokio::test]
async fn a_group_dm_with_members_of_three_nodes() {
    let open = |c: &mut tavrn_node::config::Config| c.dm_policy = DmPolicy::Everyone;
    let (a, b, c) = three_nodes_with(open, open, open).await;
    let mut alice = a.crypto_user("alice", 3).await;
    let mut bob = b.crypto_user("bob", 3).await;
    let mut carol = c.crypto_user("carol", 3).await;
    // Non-friends: the group is a message request for bob and carol, who accept DMs from everyone.
    for (node, s) in [(&b, &bob.session), (&c, &carol.session)] {
        let (st, j) = node.patch("/api/v1/users/me", &s.token, json!({ "dm_policy": "everyone" })).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    a.deliver().await;
    let (st, group) = a
        .post(
            "/api/v1/conversations",
            alice.token(),
            json!({ "kind": "group", "name": "Three nodes", "members": ["bob@b.test", "carol@c.test"] }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{group}");
    let gid = group["id"].as_str().unwrap().to_string();
    let mut targets: Vec<String> = a.outbox().await.into_iter().map(|e| format!("{} {}", e.kind, e.target)).collect();
    targets.sort();
    assert_eq!(targets, vec!["conversation.invite b.test", "conversation.invite c.test"]);
    assert_eq!(a.deliver().await.delivered, 2);
    for (node, s) in [(&b, &bob.session), (&c, &carol.session)] {
        let (_, list) = node.get_auth("/api/v1/users/me/invites", &s.token).await;
        assert_eq!(list["items"][0]["conversation"]["id"], gid.as_str(), "{list}");
        assert_eq!(list["items"][0]["conversation"]["requested"], true, "{list}");
        let mut members: Vec<String> = list["items"][0]["conversation"]["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap().to_string())
            .collect();
        members.sort();
        assert_eq!(members, vec!["alice@a.test", "bob@b.test", "carol@c.test"]);
    }

    let rb = a.sign_in_from(&b, &bob.session).await;
    let rc = a.sign_in_from(&c, &carol.session).await;
    // Before accepting, a member of a request cannot write; the hosting node takes the accept.
    let (st, j) = a.post(&format!("/api/v1/conversations/{gid}/accept"), &rb.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, j) = a.post(&format!("/api/v1/conversations/{gid}/accept"), &rc.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(j["pending"], json!([]));
    a.mls_group(A, &alice.session.token, &mut alice.client, &gid).await;
    a.add_to_group(A, &alice.session.token, &mut alice.client, &gid, "bob@b.test").await;
    a.add_to_group(A, &alice.session.token, &mut alice.client, &gid, "carol@c.test").await;
    assert_eq!(a.join_welcomes(A, &rb.token, &mut bob.client).await, 1);
    a.catch_up_on(A, &rb.token, &mut bob.client, &gid).await;
    assert_eq!(a.join_welcomes(A, &rc.token, &mut carol.client).await, 1);

    let (st, _) = a.send_secret(A, &rc.token, &carol.client, &gid, "Greetings from C").await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(a.read_secret(A, alice.token(), &alice.client, &gid).await, "Greetings from C");
    assert_eq!(a.read_secret(A, &rb.token, &bob.client, &gid).await, "Greetings from C");
    let (st, _) = a.send_secret(A, &rb.token, &bob.client, &gid, "Greetings from B").await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(a.read_secret(A, &rc.token, &carol.client, &gid).await, "Greetings from B");

    // A remote member may add a further member through the hosting node; A invites them.
    let dave = c.register("dave").await;
    c.patch("/api/v1/users/me", &dave.token, json!({ "dm_policy": "everyone" })).await;
    let (st, j) =
        a.post(&format!("/api/v1/conversations/{gid}/members"), &rb.token, json!({ "user": "dave@c.test" })).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let kinds: Vec<String> = a.outbox().await.into_iter().map(|e| format!("{} {}", e.kind, e.target)).collect();
    assert!(kinds.contains(&"conversation.invite c.test".to_string()), "{kinds:?}");
    a.deliver().await;
    let (_, list) = c.get_auth("/api/v1/users/me/invites", &dave.token).await;
    assert_eq!(list["items"][0]["inviter"], "bob@b.test");
    // Leaving works with the remote address.
    let (st, j) = a.delete(&format!("/api/v1/conversations/{gid}/members/carol@c.test"), &rc.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
}

/// Posts an inbox message signed by `from_node` to `to_node`; returns status and problem code.
async fn inbox(
    from_node: &FedNode,
    to_node: &FedNode,
    kind: &str,
    from: &str,
    to: &str,
    payload: Value,
) -> (StatusCode, String) {
    let id = tavrn_node::util::ulid();
    let body =
        json!({ "id": id, "type": kind, "from": from, "to": to, "at": tavrn_node::util::now(), "payload": payload })
            .to_string()
            .into_bytes();
    let n = chrono::Utc::now().timestamp();
    let token = from_node.sign(&json!({
        "iss": from_node.domain(), "sub": from_node.domain(), "aud": to_node.domain(), "iat": n, "exp": n + 300,
        "jti": tavrn_node::util::ulid(), "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox",
        "body_sha256": tavrn_node::federation::tokens::body_sha256(&body),
    }));
    let (st, _, raw) = to_node
        .raw(
            axum::http::Method::POST,
            "/api/v1/federation/inbox",
            &token,
            &[("content-type", "application/json")],
            body,
        )
        .await;
    let code = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v["code"].as_str().map(String::from));
    (st, code.unwrap_or_default())
}

#[tokio::test]
async fn forged_invitations_are_refused() {
    let (a, b) = two_nodes_with(|c| c.dm_policy = DmPolicy::Everyone, |_| {}).await;
    let alice = a.register("alice").await;
    a.patch("/api/v1/users/me", &alice.token, json!({ "dm_policy": "everyone" })).await;
    let conv = |kind: &str, members: Value| json!({ "conversation": { "node": B, "id": tavrn_node::util::ulid(), "kind": kind, "name": null, "members": members } });
    let bad = (StatusCode::BAD_REQUEST, "federation.envelope_invalid".to_string());
    // A DM lives on its initiator's home node: B cannot invite on behalf of a user of another node.
    let members = json!(["mallory@c.test", "alice@a.test"]);
    assert_eq!(inbox(&b, &a, "conversation.invite", "mallory@c.test", "alice@a.test", conv("dm", members)).await, bad);
    // The inviter must be a member, and so must the recipient.
    let members = json!(["bob@b.test", "alice@a.test"]);
    assert_eq!(inbox(&b, &a, "conversation.invite", "eve@b.test", "alice@a.test", conv("group", members)).await, bad);
    let members = json!(["bob@b.test", "carol@b.test"]);
    assert_eq!(inbox(&b, &a, "conversation.invite", "bob@b.test", "alice@a.test", conv("group", members)).await, bad);
    // Rooms and conversations must be hosted by the sender.
    let room = json!({ "room": { "node": "c.test", "id": tavrn_node::util::ulid(), "name": "X", "member_count": 1 },
                       "invite_code": "abc", "expires_at": tavrn_node::util::in_seconds(3600) });
    assert_eq!(inbox(&b, &a, "room.invite", "bob@b.test", "alice@a.test", room).await, bad);
    let members = json!(["bob@b.test", "alice@a.test"]);
    let mut foreign = conv("dm", members);
    foreign["conversation"]["node"] = json!("c.test");
    assert_eq!(inbox(&b, &a, "conversation.invite", "bob@b.test", "alice@a.test", foreign).await, bad);
    // A well-formed one is stored (A's policy is open).
    let members = json!(["bob@b.test", "alice@a.test"]);
    let ok = inbox(&b, &a, "conversation.invite", "bob@b.test", "alice@a.test", conv("dm", members)).await;
    assert_eq!(ok.0, StatusCode::ACCEPTED, "{ok:?}");
    let (_, list) = a.get_auth("/api/v1/users/me/invites", &alice.token).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 1, "{list}");
}

// ---------------------------------------------------------------- notify and revocations

#[tokio::test]
async fn notify_hints_reach_the_home_node_of_offline_members() {
    let (a, b) = two_nodes_with(|c| c.dm_policy = DmPolicy::Everyone, |c| c.dm_policy = DmPolicy::Everyone).await;
    let mut alice = a.crypto_user("alice", 3).await;
    let mut bob = b.crypto_user("bob", 3).await;
    b.patch("/api/v1/users/me", bob.token(), json!({ "dm_policy": "everyone" })).await;
    a.deliver().await;
    let (_, dm) =
        a.post("/api/v1/conversations", alice.token(), json!({ "kind": "dm", "members": ["bob@b.test"] })).await;
    let dm_id = dm["id"].as_str().unwrap().to_string();
    a.deliver().await;
    let remote = a.sign_in_from(&b, &bob.session).await;
    // No hints while the DM is only a request.
    a.post(&format!("/api/v1/conversations/{dm_id}/accept"), &remote.token, json!({})).await;
    a.mls_group(A, &alice.session.token, &mut alice.client, &dm_id).await;
    a.add_to_group(A, &alice.session.token, &mut alice.client, &dm_id, "bob@b.test").await;
    a.join_welcomes(A, &remote.token, &mut bob.client).await;
    let mut bob_home = ws(&b, bob.token()).await;

    // bob has no WebSocket on A: a content-free hint goes to B.
    a.send_secret(A, alice.token(), &alice.client, &dm_id, "first secret").await;
    let entries = a.outbox().await;
    assert_eq!(entries.iter().filter(|e| e.kind == "notify").count(), 1);
    let body: Value = serde_json::from_str(&entries.iter().find(|e| e.kind == "notify").unwrap().body).unwrap();
    assert_eq!(body["from"], A);
    assert_eq!(body["to"], "bob@b.test");
    assert_eq!(
        body["payload"],
        json!({ "node": A, "conversation_id": dm_id, "room_id": null, "mention": false, "everyone": false })
    );
    assert!(!body.to_string().contains("first secret"));
    a.deliver().await;
    let hint = event(&mut bob_home, "notify").await;
    assert_eq!(hint["conversation_id"], dm_id.as_str());
    assert_eq!(hint["node"], A);
    let stored: i64 =
        sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM push_hints").fetch_one(&b.state.db).await.unwrap();
    assert_eq!(stored, 1);

    // Coalesced: no second hint within a minute.
    a.send_secret(A, alice.token(), &alice.client, &dm_id, "second").await;
    assert!(a.outbox().await.iter().all(|e| e.kind != "notify"));
    // While bob is connected to A, no hints are sent at all.
    let _bob_on_a = ws(&a, &remote.token).await;
    sqlx::query("DELETE FROM push_hints").execute(&b.state.db).await.unwrap();
    let (st, _) = a.send_secret(A, &remote.token, &bob.client, &dm_id, "third").await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(a.outbox().await.iter().all(|e| e.kind != "notify"), "alice is local, bob is online");
    assert!(no_event(&mut bob_home, "notify", 200).await);
}

#[tokio::test]
async fn key_changes_and_revocations_reach_the_home_nodes_of_contacts() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    befriend(&a, &alice, &b, &bob).await;
    assert!(a.outbox().await.is_empty());
    // alice never used B, but bob (her friend) lives there.
    let laptop = a.login("alice").await;
    let (st, _) = a.delete(&format!("/api/v1/users/me/devices/{}", laptop.device_id), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let mut sent: Vec<String> = a.outbox().await.into_iter().map(|e| format!("{} {}", e.kind, e.target)).collect();
    sent.sort();
    assert_eq!(sent, vec!["devices.changed b.test", "session.revoke b.test"]);
    assert_eq!(a.deliver().await.delivered, 2);
    let key = tavrn_node::keys::NodeKey::generate("identity").public_info().x;
    let (st, j) = a
        .post(
            "/api/v1/users/me/identity/reset",
            &alice.token,
            json!({ "identity_public_key": key, "password": common::password("alice") }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let sent: Vec<String> = a.outbox().await.into_iter().map(|e| format!("{} {}", e.kind, e.target)).collect();
    assert_eq!(sent, vec!["identity.changed b.test"]);
    let mut bob_ws = ws(&b, &bob.token).await;
    assert_eq!(a.deliver().await.delivered, 1);
    let changed = event(&mut bob_ws, "identity.changed").await;
    assert_eq!(changed["user"], "alice@a.test");
    let _ = C;
}

// ---------------------------------------------------------------- authorization audit, round 2

/// A node token request to `path` on `to_node`, signed by `from_node` (or by a stranger's key in its name).
async fn s2s(from_node: &FedNode, to_node: &FedNode, path: &str, body: Value, forged: bool) -> (StatusCode, String) {
    let body = body.to_string().into_bytes();
    let n = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": from_node.domain(), "sub": from_node.domain(), "aud": to_node.domain(), "iat": n, "exp": n + 300,
        "jti": tavrn_node::util::ulid(), "typ": "s2s", "htm": "POST", "htu": path,
        "body_sha256": tavrn_node::federation::tokens::body_sha256(&body),
    });
    let token = if forged {
        let stranger = tavrn_node::keys::NodeKey::generate(&from_node.state.signing_key().kid);
        tavrn_node::jwt::sign(&stranger.signing, &stranger.kid, &claims).unwrap()
    } else {
        from_node.sign(&claims)
    };
    let (st, _, raw) =
        to_node.raw(axum::http::Method::POST, path, &token, &[("content-type", "application/json")], body).await;
    let code = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v["code"].as_str().map(String::from));
    (st, code.unwrap_or_default())
}

fn notify_payload() -> Value {
    json!({ "node": A, "conversation_id": tavrn_node::util::ulid(), "room_id": null, "mention": false })
}

fn envelope(kind: &str, from: &str, to: &str, payload: Value) -> Value {
    json!({ "id": tavrn_node::util::ulid(), "type": kind, "from": from, "to": to, "at": tavrn_node::util::now(),
            "payload": payload })
}

/// FEDERATION.md §5.1: the per-domain inbox limit counts only requests whose signature verified, so requests forged
/// in a peer's name cannot use up its budget; a limit per client address comes before the check.
#[tokio::test]
async fn forged_inbox_requests_do_not_use_up_a_peer_s_budget() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_rate_inbox = 2).await;
    b.register("bob").await;
    let path = "/api/v1/federation/inbox";
    for _ in 0..4 {
        let env = envelope("notify", A, "bob@b.test", notify_payload());
        let (st, code) = s2s(&a, &b, path, env, true).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{code}");
    }
    for _ in 0..2 {
        let (st, code) = s2s(&a, &b, path, envelope("notify", A, "bob@b.test", notify_payload()), false).await;
        assert_eq!(st, StatusCode::ACCEPTED, "{code}");
    }
    let (st, _) = s2s(&a, &b, path, envelope("notify", A, "bob@b.test", notify_payload()), false).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "the domain limit still applies after the check");
    // Before any signature check: the client address.
    let (a, b) = two_nodes().await;
    b.register("bob").await;
    while b.state.federation_ip_limiter.check("ip:unknown").await.is_ok() {}
    let (st, _) = s2s(&a, &b, path, envelope("notify", A, "bob@b.test", notify_payload()), false).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    let claim = json!({ "user": "bob@b.test", "requester": "alice@a.test" });
    let (st, _) = s2s(&a, &b, "/api/v1/federation/key-packages/claim", claim, false).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
}

/// FEDERATION.md §5.2: a user of the receiving node named as inviter, caller or claim requester must have signed in
/// on the sending node (its federation targets, §2.4); `notify` hints and rings reach only users who did.
#[tokio::test]
async fn claims_about_local_users_need_their_session_on_the_sending_node() {
    let (a, b) = two_nodes().await;
    let bob = b.register("bob").await;
    b.register("carol").await;
    let inbox = "/api/v1/federation/inbox";
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT CAST(COUNT(*) AS BIGINT) FROM push_hints")
            .fetch_one(&b.state.db)
            .await
            .unwrap()
    };
    // bob never signed in on A: no hint, no ring, no claim in his name, no invitation from him.
    let (st, code) = s2s(&a, &b, inbox, envelope("notify", A, "bob@b.test", notify_payload()), false).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{code}");
    assert_eq!(count().await, 0, "a hint for a user who is no member on A");
    let claim = json!({ "user": "carol@b.test", "requester": "bob@b.test" });
    let (st, code) = s2s(&a, &b, "/api/v1/federation/key-packages/claim", claim.clone(), false).await;
    assert_eq!((st, code.as_str()), (StatusCode::FORBIDDEN, "federation.claim_refused"));
    let room = json!({ "room": { "node": A, "id": tavrn_node::util::ulid(), "name": "Room" },
                       "invite_code": "abcdefgh", "expires_at": tavrn_node::util::in_seconds(3600) });
    let (st, code) =
        s2s(&a, &b, inbox, envelope("room.invite", "bob@b.test", "carol@b.test", room.clone()), false).await;
    assert_eq!((st, code.as_str()), (StatusCode::BAD_REQUEST, "federation.envelope_invalid"));
    let ring = json!({ "node": A, "conversation_id": tavrn_node::util::ulid(), "room_id": null, "mention": false,
                       "call": { "state": "ring", "from": "bob@b.test", "started_at": tavrn_node::util::now(), "group": true } });
    let (st, code) = s2s(&a, &b, inbox, envelope("notify", A, "carol@b.test", ring), false).await;
    assert_eq!((st, code.as_str()), (StatusCode::BAD_REQUEST, "federation.envelope_invalid"));

    // Once bob signed in on A, all of it is accepted.
    a.sign_in_from(&b, &bob).await;
    let (st, _) = s2s(&a, &b, inbox, envelope("notify", A, "bob@b.test", notify_payload()), false).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(count().await, 1);
    let (st, code) = s2s(&a, &b, "/api/v1/federation/key-packages/claim", claim, false).await;
    assert_eq!(st, StatusCode::OK, "{code}");
    // Users of the sending node itself need nothing more.
    let (st, code) = s2s(&a, &b, inbox, envelope("room.invite", "alice@a.test", "bob@b.test", room), false).await;
    assert_eq!(st, StatusCode::ACCEPTED, "{code}");
}
