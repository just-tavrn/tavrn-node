// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Direct messages from non-friends: message requests and "Who can message me", friend
//! request messages, block reasons, and requests from users of other nodes (the recipient's home node
//! decides).
use crate::common;

use axum::http::StatusCode;
use common::e2ee::DOMAIN;
use common::federation::{A, two_nodes};
use common::{Session, TestNode, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_node::{config::DmPolicy, hub::Scope};

async fn share_room(node: &TestNode, owner: &Session, others: &[&Session]) -> String {
    let room = node.create_room(&owner.token, "Shared").await;
    let id = room["id"].as_str().unwrap().to_string();
    let (_, invite) = node.post(&format!("/api/v1/rooms/{id}/invites"), &owner.token, json!({})).await;
    for o in others {
        let (st, j) =
            node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &o.token, json!({})).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    id
}

async fn dm(node: &TestNode, from: &Session, to: &str) -> (StatusCode, Value) {
    node.post("/api/v1/conversations", &from.token, json!({ "kind": "dm", "members": [to] })).await
}

#[tokio::test]
async fn a_request_from_a_shared_room_is_accepted_into_a_normal_dm() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let room = share_room(&node, &alice.session, &[&bob.session]).await;

    let mut rx = node.state.hub.subscribe();
    let (st, c) = dm(&node, &alice.session, "bob").await;
    assert_eq!(st, StatusCode::CREATED, "{c}");
    assert_eq!(c["pending"], json!(["bob@t.local"]));
    let id = c["id"].as_str().unwrap().to_string();
    let evs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let created = evs.iter().find(|e| e.kind == "conversation.create").unwrap();
    assert!(matches!(&created.scope, Scope::Users(u) if u == &vec![alice.session.user_id.clone()]), "only alice");
    let request = evs.iter().find(|e| e.kind == "conversation.request").unwrap();
    assert!(matches!(&request.scope, Scope::Users(u) if u == &vec![bob.session.user_id.clone()]));
    assert_eq!(request.data["request"]["from"]["address"], "alice@t.local");

    // Alice writes (encrypted); bob is in the MLS group but gets no message events and no unread count.
    node.create_group(&mut alice, &id).await;
    node.add_user(&mut alice, &id, "bob").await;
    assert_eq!(node.accept_welcomes(&mut bob).await, 1);
    let mut rx = node.state.hub.subscribe();
    let (st, m) = node.send_encrypted(&alice, &id, "Hi, we know each other from the guild").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    let msg_ev = std::iter::from_fn(|| rx.try_recv().ok()).find(|e| e.kind == "message.create").unwrap();
    assert!(
        matches!(&msg_ev.scope, Scope::Users(u) if !u.contains(&bob.session.user_id)),
        "no events before accepting"
    );

    let (_, list) = node.get_auth("/api/v1/conversations", bob.token()).await;
    assert_eq!(list, json!([]), "requests are not in the conversation list");
    let (st, requests) = node.get_auth("/api/v1/conversations/requests", bob.token()).await;
    assert_eq!(st, StatusCode::OK, "{requests}");
    assert_eq!(requests.as_array().unwrap().len(), 1);
    let r = &requests[0];
    assert_eq!(r["from"]["address"], "alice@t.local");
    assert_eq!(r["shared_rooms"], json!([{ "id": room, "name": "Shared" }]));
    assert_eq!(r["first_message_id"], m["id"]);
    // The preview is readable (bob is a member), but answering needs an accept.
    let (st, msgs) = node.get_auth(&format!("/api/v1/conversations/{id}/messages"), bob.token()).await;
    assert_eq!((st, msgs.as_array().unwrap().len()), (StatusCode::OK, 1));
    let (st, j) = node.send_encrypted(&bob, &id, "Hello").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("conversation.request_pending")));

    let mut rx = node.state.hub.subscribe();
    let (st, c) = node.post(&format!("/api/v1/conversations/{id}/accept"), bob.token(), json!({})).await;
    assert_eq!(st, StatusCode::OK, "{c}");
    assert_eq!(c["pending"], json!([]));
    assert!(std::iter::from_fn(|| rx.try_recv().ok()).any(|e| e.kind == "conversation.update"
        && matches!(&e.scope, Scope::Users(u) if u.contains(&alice.session.user_id))));
    let (_, list) = node.get_auth("/api/v1/conversations", bob.token()).await;
    assert_eq!(list[0]["id"], id.as_str());
    let (_, requests) = node.get_auth("/api/v1/conversations/requests", bob.token()).await;
    assert_eq!(requests, json!([]));
    node.catch_up(&mut bob, &id).await;
    let (st, j) = node.send_encrypted(&bob, &id, "Hello back").await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    // Accepting twice is harmless; declining an accepted DM is not a thing.
    let (st, _) = node.post(&format!("/api/v1/conversations/{id}/accept"), bob.token(), json!({})).await;
    assert_eq!(st, StatusCode::OK);
    let (st, j) = node.post(&format!("/api/v1/conversations/{id}/decline"), bob.token(), json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::CONFLICT, Some("conversation.not_requested")));
}

#[tokio::test]
async fn decline_and_block_with_a_private_reason() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    share_room(&node, &alice, &[&bob, &carol]).await;

    // Declining without a block: bob leaves, the request is never sent again.
    let (_, c) = dm(&node, &carol, "bob").await;
    let carol_dm = c["id"].as_str().unwrap().to_string();
    let (st, _) = node.post(&format!("/api/v1/conversations/{carol_dm}/decline"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, again) = dm(&node, &carol, "bob").await;
    assert_eq!(st, StatusCode::OK, "{again}");
    assert_eq!(again["members"].as_array().unwrap().len(), 1, "bob stays out");
    let (_, requests) = node.get_auth("/api/v1/conversations/requests", &bob.token).await;
    assert_eq!(requests, json!([]));
    let (st, _) = node.get_auth(&format!("/api/v1/conversations/{carol_dm}"), &bob.token).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Decline and block: the reason stays private on bob's list.
    let (_, c) = dm(&node, &alice, "bob").await;
    let id = c["id"].as_str().unwrap();
    let (st, j) = node
        .post(
            &format!("/api/v1/conversations/{id}/decline"),
            &bob.token,
            json!({ "block": true, "reason": "Spam-Links" }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let (st, blocks) = node.get_auth("/api/v1/users/me/blocks", &bob.token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(blocks[0]["user"]["address"], "alice@t.local");
    assert_eq!(blocks[0]["reason"], "Spam-Links");
    assert!(blocks[0]["created_at"].is_string());
    let (st, j) = dm(&node, &alice, "bob").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.blocked")));
    // Blocking again updates the note; too long notes are refused; unblocking empties the list.
    node.post("/api/v1/users/me/blocks", &bob.token, json!({ "user": "alice", "reason": "Spam" })).await;
    let (_, blocks) = node.get_auth("/api/v1/users/me/blocks", &bob.token).await;
    assert_eq!(blocks[0]["reason"], "Spam");
    let (st, j) =
        node.post("/api/v1/users/me/blocks", &bob.token, json!({ "user": "carol", "reason": "x".repeat(257) })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")));
    node.delete("/api/v1/users/me/blocks/alice", &bob.token).await;
    let (_, blocks) = node.get_auth("/api/v1/users/me/blocks", &bob.token).await;
    assert_eq!(blocks, json!([]));
    // Nobody else can decline for bob.
    let (_, c) = dm(&node, &carol, "alice").await;
    let id = c["id"].as_str().unwrap();
    let (st, _) = node.post(&format!("/api/v1/conversations/{id}/decline"), &bob.token, json!({})).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn who_can_message_me_and_friend_request_messages() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let dave = node.register("dave").await;
    let erin = node.register("erin").await;
    share_room(&node, &alice, &[&dave]).await;

    // Friends only: a clear refusal the client turns into "send a friend request".
    node.patch("/api/v1/users/me", &dave.token, json!({ "dm_policy": "friends" })).await;
    let (st, j) = dm(&node, &alice, "dave").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.friends_only")), "{j}");
    let (st, j) = node
        .post(
            "/api/v1/users/me/friends/requests",
            &alice.token,
            json!({ "user": "dave", "message": " Alice from the guild " }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &dave.token).await;
    assert_eq!(list["incoming"][0]["message"], "Alice from the guild");
    let (_, list) = node.get_auth("/api/v1/users/me/friends", &alice.token).await;
    assert_eq!(list["outgoing"][0]["message"], "Alice from the guild");
    let (st, j) = node
        .post("/api/v1/users/me/friends/requests", &alice.token, json!({ "user": "erin", "message": "x".repeat(257) }))
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("validation.length")));
    let request = list["outgoing"][0]["id"].as_str().unwrap();
    node.post(&format!("/api/v1/users/me/friends/requests/{request}/accept"), &dave.token, json!({})).await;
    let (st, c) = dm(&node, &alice, "dave").await;
    assert_eq!(st, StatusCode::CREATED, "{c}");
    assert_eq!(c["pending"], json!([]), "friends get a normal DM");

    // everyone_shared (default) without a shared room, and everyone.
    let (st, j) = dm(&node, &alice, "erin").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.no_shared_room")));
    node.patch("/api/v1/users/me", &erin.token, json!({ "dm_policy": "everyone" })).await;
    let (st, c) = dm(&node, &alice, "erin").await;
    assert_eq!((st, &c["pending"]), (StatusCode::CREATED, &json!(["erin@t.local"])));

    // Group DMs: requests only for the members who are not friends.
    let (st, g) =
        node.post("/api/v1/conversations", &alice.token, json!({ "kind": "group", "members": ["dave", "erin"] })).await;
    assert_eq!(st, StatusCode::CREATED, "{g}");
    assert_eq!(g["pending"], json!(["erin@t.local"]));
    let (_, requests) = node.get_auth("/api/v1/conversations/requests", &erin.token).await;
    assert_eq!(requests.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_node_policy_is_the_upper_bound() {
    let node = test_node_with(DOMAIN, |c| c.dm_policy = DmPolicy::Friends).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    share_room(&node, &alice, &[&bob]).await;
    node.patch("/api/v1/users/me", &bob.token, json!({ "dm_policy": "everyone" })).await;
    let (st, j) = dm(&node, &alice, "bob").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.not_friends")));
    let (_, p) = node.req(axum::http::Method::GET, "/api/v1/users/bob/profile", None, None).await;
    assert_eq!(p["dm_policy"], "friends", "the profile shows the effective setting");
}

#[tokio::test]
async fn requests_across_nodes_are_decided_by_the_recipients_home_node() {
    let (a, b) = two_nodes().await;
    let alice = a.register("alice").await;
    let bob = b.register("bob").await;
    let carol = b.register("carol").await;
    // alice and bob share a room on B (alice with a federated session there).
    let room = b.create_room(&bob.token, "Meeting point").await;
    let room_id = room["id"].as_str().unwrap();
    let (_, invite) = b.post(&format!("/api/v1/rooms/{room_id}/invites"), &bob.token, json!({})).await;
    let remote = b.sign_in_from(&a, &alice).await;
    b.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote.token, json!({})).await;

    // A creates the DM as a request; B shows it because bob shares a room with alice on B.
    let (st, c) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["bob@b.test"] })).await;
    assert_eq!(st, StatusCode::CREATED, "{c}");
    assert_eq!(c["pending"], json!(["bob@b.test"]));
    let entries = a.outbox().await;
    let invite_body: Value =
        serde_json::from_str(&entries.iter().find(|e| e.kind == "conversation.invite").unwrap().body).unwrap();
    assert_eq!(invite_body["payload"]["requested"], true);
    assert_eq!(a.deliver().await.delivered, 1);
    let (_, list) = b.get_auth("/api/v1/users/me/invites", &bob.token).await;
    let inv = &list["items"][0]["conversation"];
    assert_eq!((inv["requested"].as_bool(), inv["kind"].as_str()), (Some(true), Some("dm")), "{list}");

    // carol shares nothing with alice: B drops the request silently (A cannot know).
    let (st, _) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["carol@b.test"] })).await;
    assert_eq!(st, StatusCode::CREATED);
    a.deliver().await;
    let (_, list) = b.get_auth("/api/v1/users/me/invites", &carol.token).await;
    assert_eq!(list["items"], json!([]));
    // With "friends only" in her mirrored profile A refuses at once.
    let dave = b.register("dave").await;
    b.patch("/api/v1/users/me", &dave.token, json!({ "dm_policy": "friends" })).await;
    let (st, j) =
        a.post("/api/v1/conversations", &alice.token, json!({ "kind": "dm", "members": ["dave@b.test"] })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("dm.friends_only")), "{j}");

    // bob accepts on A with a federated session.
    let bob_on_a = a.sign_in_from(&b, &bob).await;
    let id = c["id"].as_str().unwrap();
    let (_, requests) = a.get_auth("/api/v1/conversations/requests", &bob_on_a.token).await;
    assert_eq!(requests[0]["conversation"]["id"], id);
    let (st, c) = a.post(&format!("/api/v1/conversations/{id}/accept"), &bob_on_a.token, json!({})).await;
    assert_eq!((st, &c["pending"]), (StatusCode::OK, &json!([])));

    // Friend requests carry their message to the other node.
    let (st, _) = a
        .post(
            "/api/v1/users/me/friends/requests",
            &alice.token,
            json!({ "user": "carol@b.test", "message": "Hi Carol" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED);
    a.deliver().await;
    let (_, friends) = b.get_auth("/api/v1/users/me/friends", &carol.token).await;
    assert_eq!(friends["incoming"][0]["message"], "Hi Carol", "{friends}");
    let _ = A;
}
