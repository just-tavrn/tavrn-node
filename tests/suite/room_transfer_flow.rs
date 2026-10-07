// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Room ownership transfer (protocol MODERATION.md §4), the account deletion it unblocks, and the node admin's room
//! list with role names (single sign-on group map picker).
use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, test_node};
use serde_json::json;

const DOMAIN: &str = "t.local";

async fn join(node: &TestNode, owner: &Session, room_id: &str, who: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &who.token, json!({})).await;
    assert!(s.is_success(), "{j}");
}

#[tokio::test]
async fn the_owner_transfers_the_room_with_a_reauth_token() {
    let node = test_node(DOMAIN).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let carol = node.register("carol").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    join(&node, &alice, &room_id, &bob).await;
    let path = format!("/api/v1/rooms/{room_id}/transfer");

    let (s, j) = node.post(&path, &bob.token, json!({ "user_id": bob.user_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.owner_required")), "{j}");
    for (target, why) in [(&carol.user_id, "not a member"), (&alice.user_id, "already the owner")] {
        let (s, j) = node.post(&path, &alice.token, json!({ "user_id": target })).await;
        assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("room.transfer_invalid")), "{why}: {j}");
    }
    join(&node, &alice, &room_id, &carol).await;
    sqlx::query("UPDATE users SET kind = 'bot' WHERE id = $1")
        .bind(&carol.user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) = node.post(&path, &alice.token, json!({ "user_id": carol.user_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("room.transfer_invalid")), "bots: {j}");

    // A sensitive action: without a fresh proof the node asks for one.
    node.forget_reauth(&alice.token);
    let (s, j) = node.post(&path, &alice.token, json!({ "user_id": bob.user_id })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")), "{j}");
    let (s, proof) =
        node.post("/api/v1/auth/reauth", &alice.token, json!({ "password": common::password("alice") })).await;
    assert_eq!(s, StatusCode::OK, "{proof}");
    node.reauth.lock().unwrap().insert(alice.token.clone(), proof["reauth_token"].as_str().unwrap().to_string());

    let mut rx = node.state.hub.subscribe();
    let (s, detail) = node.post(&path, &alice.token, json!({ "user_id": bob.user_id })).await;
    assert_eq!(s, StatusCode::OK, "{detail}");
    assert_eq!(detail["owner_id"], bob.user_id.as_str());
    let ev = loop {
        let ev = rx.recv().await.unwrap();
        if ev.kind == "room.update" {
            break ev;
        }
    };
    assert_eq!(ev.data["owner_id"], bob.user_id.as_str());
    // The former owner stays a member; the new owner can now delete the room, the old one cannot.
    let (s, _) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(s, StatusCode::OK);
    let (_, log) = node.get_auth(&format!("/api/v1/rooms/{room_id}/audit-log"), &bob.token).await;
    let e = log.as_array().unwrap().iter().find(|e| e["action"] == "room.transfer").expect("audit entry");
    assert_eq!(e["target"], "bob@t.local");
    assert_eq!((e["meta"]["from"].as_str(), e["meta"]["to"].as_str()), (Some("alice@t.local"), Some("bob@t.local")));
    let (s, j) = node.delete(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");

    // Alice owns nothing any more: her account can be deleted.
    let (s, j) = node
        .req(
            Method::DELETE,
            "/api/v1/users/me",
            Some(&alice.token),
            Some(json!({ "confirm": "alice", "delete_messages": false })),
        )
        .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{j}");
}

#[tokio::test]
async fn node_admins_list_rooms_with_their_roles() {
    let node = test_node(DOMAIN).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Guild").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let (s, role) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Staff", "permissions": "0" }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    node.create_room(&alice.token, "Other place").await;

    let (s, j) = node.get_auth("/api/v1/admin/rooms", &alice.token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.node_admin_required")));
    let (s, list) = node.get_auth("/api/v1/admin/rooms?q=gui", &admin.token).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    assert_eq!(list.as_array().unwrap().len(), 1);
    let r = &list[0];
    assert_eq!(
        (r["id"].as_str(), r["name"].as_str(), r["owner"].as_str()),
        (Some(room_id.as_str()), Some("Guild"), Some("alice@t.local"))
    );
    assert_eq!(r["members"], 1);
    let names: Vec<&str> = r["roles"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Staff") && !names.contains(&"@everyone"), "{names:?}");
    assert_eq!(r["roles"].as_array().unwrap().iter().find(|x| x["name"] == "Staff").unwrap()["id"], role["id"]);
    let (_, all) = node.get_auth("/api/v1/admin/rooms?limit=1", &admin.token).await;
    assert_eq!(all.as_array().unwrap().len(), 1);
    let (_, next) = node
        .get_auth(&format!("/api/v1/admin/rooms?limit=1&after={}", all[0]["id"].as_str().unwrap()), &admin.token)
        .await;
    assert_eq!(next.as_array().unwrap().len(), 1);
    assert_ne!(next[0]["id"], all[0]["id"]);
}
