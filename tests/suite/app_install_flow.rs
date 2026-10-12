// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Phase 5 step 2 and 7 (protocol/APPLICATIONS.md §1.8, §4, §7): the public application document, the add
//! flow and its checks, uninstalling, node-level controls, the `app.*` inbox types across two nodes,
//! application reports, token expiry notices and bot presence.

use crate::common;

use axum::http::{Method, StatusCode};
use common::{Session, TestNode, crossnode, federation, test_node, test_node_with};
use serde_json::{Value, json};
use tavrn_node::{permissions as p, util};

const D: &str = "apps.test";

struct Bot {
    app_id: String,
    user_id: String,
    username: String,
    secret: String,
}

impl Bot {
    fn reference(&self, domain: &str) -> String {
        format!("{domain}/{}", self.app_id)
    }
    fn address(&self, domain: &str) -> String {
        format!("{}@{domain}", self.username)
    }
}

fn code(j: &Value) -> &str {
    j["code"].as_str().unwrap_or("")
}

fn mask(bits: &[u64]) -> String {
    bits.iter().fold(0u64, |a, b| a | b).to_string()
}

/// An application of `owner` with one token (all scopes unless given).
async fn bot(node: &TestNode, owner: &Session, body: Value, scopes: Option<&[&str]>) -> Bot {
    let (s, app) = node.post("/api/v1/applications", &owner.token, body).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let app_id = app["id"].as_str().unwrap().to_string();
    let token_body = match scopes {
        Some(s) => json!({ "name": "main", "scopes": s }),
        None => json!({ "name": "main" }),
    };
    let (s, t) = node.post(&format!("/api/v1/applications/{app_id}/tokens"), &owner.token, token_body).await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    Bot {
        app_id,
        user_id: app["bot"]["id"].as_str().unwrap().into(),
        username: app["bot"]["username"].as_str().unwrap().into(),
        secret: t["secret"].as_str().unwrap().into(),
    }
}

async fn install(node: &TestNode, token: &str, room_id: &str, body: Value) -> (StatusCode, Value) {
    node.post(&format!("/api/v1/rooms/{room_id}/applications"), token, body).await
}

/// `user` joins the room through an invite of `owner`.
async fn member(node: &TestNode, owner: &Session, room_id: &str, user: &Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), &owner.token, json!({})).await;
    let (s, j) =
        node.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &user.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
}

/// A role with `perms` at `position`, given to `user`; returns the role id.
async fn role_for(
    node: &TestNode,
    owner: &Session,
    room_id: &str,
    user: &Session,
    name: &str,
    perms: &str,
    position: i64,
) -> String {
    let (s, role) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &owner.token,
            json!({ "name": name, "permissions": perms, "position": position }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{role}");
    let id = role["id"].as_str().unwrap().to_string();
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/members/{}", user.user_id), &owner.token, json!({ "roles": [id] }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    id
}

async fn audit_meta(node: &TestNode, action: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT meta FROM audit_log WHERE action = $1 ORDER BY id")
        .bind(action)
        .fetch_all(&node.state.db)
        .await
        .unwrap()
}

// ---------------------------------------------------------------- the add flow (§4.2)

#[tokio::test]
async fn install_checks_grant_at_most_the_installers_permissions() {
    let node = test_node(D).await;
    let _admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let carol = node.register("carol").await;
    let bob = node.register("bob").await;
    let dave = node.register("dave").await;
    let requested = mask(&[p::SEND_MESSAGES, p::ATTACH_FILES, p::KICK_MEMBERS, p::MANAGE_MESSAGES]);
    let b = bot(&node, &alice, json!({ "name": "Weather", "requested_permissions": requested }), None).await;
    let room = node.create_room(&carol.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    member(&node, &carol, room_id, &bob).await;
    member(&node, &carol, room_id, &dave).await;
    let mods =
        role_for(&node, &carol, room_id, &bob, "Mods", &mask(&[p::MANAGE_APPLICATIONS, p::MANAGE_ROLES]), 5).await;
    // A lower role that has to stay below the managed role, a higher one that moves up with the caller's.
    node.post(&format!("/api/v1/rooms/{room_id}/roles"), &carol.token, json!({ "name": "Low", "position": 2 })).await;
    let (_, high) = node
        .post(&format!("/api/v1/rooms/{room_id}/roles"), &carol.token, json!({ "name": "High", "position": 9 }))
        .await;
    let reference = b.reference(D);
    let body = |perms: &str| json!({ "application": reference, "permissions": perms });

    // 1. manage_applications.
    let (s, j) = install(&node, &dave.token, room_id, body(&requested)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    // 3. unknown and malformed references: 404 without an oracle.
    for bad in [format!("{D}/{}", util::ulid()), "nonsense".into(), format!("{D}/../x"), String::new()] {
        let (s, j) = install(&node, &bob.token, room_id, json!({ "application": bad })).await;
        assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"), "{bad}");
    }
    // 5. a private application only by its owner.
    let (s, j) = install(&node, &bob.token, room_id, body(&requested)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.private"));
    node.patch(&format!("/api/v1/applications/{}", b.app_id), &alice.token, json!({ "public": true })).await;
    // 8. never administrator, never beyond the requested permissions.
    for bad in [p::ADMINISTRATOR.to_string(), mask(&[p::SEND_MESSAGES, p::BAN_MEMBERS]), "x".into(), "-1".into()] {
        let (s, j) = install(&node, &bob.token, room_id, body(&bad)).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.permissions_invalid"), "{bad}");
    }
    // Granted = requested ∩ the installer's; the rest is dropped.
    let (s, inst) = install(&node, &bob.token, room_id, body(&requested)).await;
    assert_eq!(s, StatusCode::CREATED, "{inst}");
    assert_eq!(inst["permissions"], mask(&[p::SEND_MESSAGES, p::ATTACH_FILES]));
    assert_eq!(inst["dropped_permissions"], mask(&[p::KICK_MEMBERS, p::MANAGE_MESSAGES]));
    assert_eq!(inst["application"]["ref"], reference);
    assert_eq!(inst["application"]["name"], "Weather");
    assert_eq!(inst["bot"]["kind"], "bot");
    assert_eq!(inst["installed_by"], format!("bob@{D}"));
    // The managed role: named like the application, directly below the caller's highest role.
    let role_id = inst["role_id"].as_str().unwrap();
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &carol.token).await;
    let roles = detail["roles"].as_array().unwrap();
    let pos = |id: &str| roles.iter().find(|r| r["id"] == id).unwrap()["position"].as_i64().unwrap();
    let managed = roles.iter().find(|r| r["id"] == role_id).unwrap();
    assert_eq!(managed["name"], "Weather");
    assert_eq!(managed["application_id"], reference);
    assert_eq!(managed["permissions"], inst["permissions"]);
    assert_eq!(
        (managed["hoist"].as_bool(), managed["mentionable"].as_bool(), &managed["color"]),
        (Some(false), Some(false), &Value::Null)
    );
    assert_eq!(pos(role_id), 5);
    assert_eq!(pos(&mods), 6, "the caller's role moved up");
    assert_eq!(pos(high["id"].as_str().unwrap()), 10);
    assert!(roles.iter().any(|r| r["name"] == "Low" && r["position"] == 2));
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &carol.token).await;
    let bot_member = members.as_array().unwrap().iter().find(|m| m["user"]["id"] == b.user_id.as_str()).unwrap();
    assert_eq!(bot_member["roles"], json!([role_id]));
    // The bot acts with exactly the granted permissions.
    let (_, mine) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &b.secret).await;
    let have = mine["my_permissions"].as_str().unwrap().parse::<u64>().unwrap();
    assert!(p::has(have, p::SEND_MESSAGES | p::ATTACH_FILES));
    assert!(!p::has(have, p::KICK_MEMBERS) && !p::has(have, p::MANAGE_MESSAGES));
    // 7. installed once.
    let (s, j) = install(&node, &bob.token, room_id, body("0")).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.already_installed"));
    // The list (manage_applications or manage_room).
    let (s, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), &bob.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["role_id"], role_id);
    assert_eq!(list[0]["enabled_commands"], 0);
    assert!(list[0].get("dropped_permissions").is_none());
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), &dave.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    // Audited with granted and dropped.
    let meta = audit_meta(&node, "app.install").await;
    assert!(meta[0].contains(&format!("\"dropped\":\"{}\"", mask(&[p::KICK_MEMBERS, p::MANAGE_MESSAGES]))), "{meta:?}");
    assert!(meta[0].contains(&reference));
}

#[tokio::test]
async fn manage_roles_missing_means_no_role_and_collisions_get_a_suffix() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let bob = node.register("bob").await;
    let requested = mask(&[p::SEND_MESSAGES, p::ADD_REACTIONS]);
    let b =
        bot(&node, &alice, json!({ "name": "Helper", "public": true, "requested_permissions": requested }), None).await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    member(&node, &alice, room_id, &bob).await;
    role_for(&node, &alice, room_id, &bob, "Managers", &mask(&[p::MANAGE_APPLICATIONS]), 3).await;
    let reference = b.reference(D);
    // With create_role (the default) the role needs manage_roles.
    let (s, j) =
        install(&node, &bob.token, room_id, json!({ "application": reference, "permissions": requested })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "role.manage_forbidden"));
    // Without a role the bot joins with the @everyone permissions only.
    let (s, inst) = install(
        &node,
        &bob.token,
        room_id,
        json!({ "application": reference, "permissions": requested, "create_role": false }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{inst}");
    assert_eq!(inst["role_id"], Value::Null);
    let (_, members) = node.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &alice.token).await;
    let m = members.as_array().unwrap().iter().find(|m| m["user"]["id"] == b.user_id.as_str()).unwrap();
    assert_eq!(m["roles"], json!([]));

    // Name collisions: an existing role "Other" makes the managed role "Other (2)"; an empty grant makes none.
    let other =
        bot(&node, &alice, json!({ "name": "Other", "public": true, "requested_permissions": requested }), None).await;
    node.post(&format!("/api/v1/rooms/{room_id}/roles"), &alice.token, json!({ "name": "Other" })).await;
    let (s, inst) =
        install(&node, &alice.token, room_id, json!({ "application": other.reference(D), "permissions": requested }))
            .await;
    assert_eq!(s, StatusCode::CREATED, "{inst}");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    let managed = detail["roles"].as_array().unwrap().iter().find(|r| r["id"] == inst["role_id"]).unwrap().clone();
    assert_eq!(managed["name"], "Other (2)");
    let top = detail["roles"].as_array().unwrap().iter().map(|r| r["position"].as_i64().unwrap()).max().unwrap();
    assert_eq!(managed["position"].as_i64().unwrap(), top, "an owner's install goes above every role");
    let empty = bot(&node, &alice, json!({ "name": "Empty", "public": true }), None).await;
    let (s, inst) = install(&node, &alice.token, room_id, json!({ "application": empty.reference(D) })).await;
    assert_eq!((s, &inst["role_id"]), (StatusCode::CREATED, &Value::Null));
}

#[tokio::test]
async fn bans_disabled_blocked_and_the_room_limit() {
    let node = test_node_with(D, |c| c.apps_per_room = 1).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let mallory = node.register("mallory").await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let sneaky = bot(&node, &mallory, json!({ "name": "Sneaky", "public": true }), None).await;
    let body = |b: &Bot| json!({ "application": b.reference(D) });
    // 6. the owner banned → app.owner_banned; the bot itself banned → room.banned.
    node.post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": format!("mallory@{D}") }))
        .await;
    let (s, j) = install(&node, &alice.token, room_id, body(&sneaky)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.owner_banned"));
    node.delete(&format!("/api/v1/rooms/{room_id}/bans/mallory@{D}"), &alice.token).await;
    node.post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": sneaky.address(D) })).await;
    let (s, j) = install(&node, &alice.token, room_id, body(&sneaky)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.banned"));
    // A node ban of the owner counts as well.
    let other = bot(&node, &mallory, json!({ "name": "Other", "public": true }), None).await;
    node.post("/api/v1/admin/bans", &admin.token, json!({ "subject": format!("mallory@{D}") })).await;
    let (s, j) = install(&node, &alice.token, room_id, body(&other)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    node.delete(&format!("/api/v1/admin/bans/mallory@{D}"), &admin.token).await;
    node.patch(&format!("/api/v1/admin/users/{}", mallory.user_id), &admin.token, json!({ "disabled": false })).await;

    // 4. disabled by the node admin, blocked on the node.
    let fine = bot(&node, &alice, json!({ "name": "Fine" }), None).await;
    let (s, _) = node
        .patch(&format!("/api/v1/admin/applications/{}", fine.app_id), &admin.token, json!({ "disabled": true }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, j) = install(&node, &alice.token, room_id, body(&fine)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.disabled"));
    node.patch(&format!("/api/v1/admin/applications/{}", fine.app_id), &admin.token, json!({ "disabled": false }))
        .await;
    node.post("/api/v1/admin/applications/blocks", &admin.token, json!({ "bot": fine.address(D) })).await;
    let (s, j) = install(&node, &alice.token, room_id, body(&fine)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.blocked"));
    node.delete(&format!("/api/v1/admin/applications/blocks/{}", fine.address(D)), &admin.token).await;

    // 7. the room limit (TAVRN_APPS_PER_ROOM = 1).
    let (s, j) = install(&node, &alice.token, room_id, body(&fine)).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let second = bot(&node, &alice, json!({ "name": "Second" }), None).await;
    let (s, j) = install(&node, &alice.token, room_id, body(&second)).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.room_limit"));
    assert_eq!(j["meta"]["max"], 1);
    // 2. "no bots" rooms.
    let quiet = node.create_room(&alice.token, "Quiet").await;
    let quiet_id = quiet["id"].as_str().unwrap();
    node.patch(&format!("/api/v1/rooms/{quiet_id}"), &alice.token, json!({ "no_bots": true })).await;
    let (s, j) = install(&node, &alice.token, quiet_id, body(&second)).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.room_no_bots"));
}

// ---------------------------------------------------------------- uninstalling (§4.3)

#[tokio::test]
async fn uninstall_kick_and_ban_remove_the_installation_and_tell_the_bot() {
    let (node, _other) = federation::two_nodes().await;
    let d = federation::A;
    let alice = node.register("alice").await;
    let requested = mask(&[p::SEND_MESSAGES]);
    let b =
        bot(&node, &alice, json!({ "name": "Tidy", "public": true, "requested_permissions": requested }), None).await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let mut ws = crossnode::ws(&node, &b.secret).await;
    let reference = b.reference(d);
    let (s, inst) =
        install(&node, &alice.token, room_id, json!({ "application": reference, "permissions": requested })).await;
    assert_eq!(s, StatusCode::CREATED, "{inst}");
    let ev = crossnode::event(&mut ws, "application.install").await;
    assert_eq!((ev["room_id"].as_str(), ev["node"].as_str()), (Some(room_id), Some(d)));
    assert_eq!(ev["installed_by"], format!("alice@{d}"));
    // The bot finds its rooms through the install index.
    let (s, idx) = node.get_auth("/api/v1/applications/me/installations", &b.secret).await;
    assert_eq!(s, StatusCode::OK, "{idx}");
    assert_eq!(idx[0]["room_id"], room_id);
    assert_eq!(idx[0]["node"], d);
    assert_eq!(idx[0]["room_name"], "Lobby");
    let (s, _) = node.get_auth("/api/v1/applications/me/installations", &alice.token).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "users have no installations route");

    // Removal by reference (slash percent-encoded).
    let path = format!("/api/v1/rooms/{room_id}/applications/{}", reference.replace('/', "%2F"));
    let (s, j) = node.delete(&path, &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let ev = crossnode::event(&mut ws, "application.uninstall").await;
    assert_eq!(ev["reason"], "removed");
    let (_, detail) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &alice.token).await;
    assert!(!detail["roles"].to_string().contains(inst["role_id"].as_str().unwrap()), "managed role deleted");
    let (s, j) = node.get_auth(&format!("/api/v1/rooms/{room_id}"), &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.not_member"));
    let (s, j) = node.delete(&path, &alice.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_installed"));
    let (_, idx) = node.get_auth("/api/v1/applications/me/installations", &b.secret).await;
    assert_eq!(idx, json!([]));

    // Kicking uninstalls (reason kicked), banning uninstalls and blocks the return.
    install(&node, &alice.token, room_id, json!({ "application": reference })).await;
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{}", b.user_id), &alice.token).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(crossnode::event(&mut ws, "application.uninstall").await["reason"], "kicked");
    let (_, list) = node.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), &alice.token).await;
    assert_eq!(list, json!([]));
    install(&node, &alice.token, room_id, json!({ "application": reference })).await;
    let (s, _) =
        node.post(&format!("/api/v1/rooms/{room_id}/bans"), &alice.token, json!({ "subject": b.address(d) })).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(crossnode::event(&mut ws, "application.uninstall").await["reason"], "banned");
    let (s, j) = install(&node, &alice.token, room_id, json!({ "application": reference })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "room.banned"));
    let reasons = audit_meta(&node, "app.uninstall").await;
    for reason in ["removed", "kicked", "banned"] {
        assert!(reasons.iter().any(|m| m.contains(&format!("\"reason\":\"{reason}\""))), "{reason}: {reasons:?}");
    }
}

// ---------------------------------------------------------------- public document (§1.8)

#[tokio::test]
async fn public_document_is_open_cacheable_and_hides_disabled_applications() {
    let node = test_node(D).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let b = bot(
        &node,
        &alice,
        json!({ "name": "Docs", "description": "Reads docs", "requested_permissions": "3", "scopes": ["messages:read", "commands"] }),
        None,
    )
    .await;
    let path = format!("/api/v1/applications/{}/public", b.app_id);
    let resp = node
        .router
        .clone()
        .oneshot_req(
            axum::http::Request::get(&path)
                .header("origin", "https://elsewhere.example")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "public, max-age=300");
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    let doc = common::body_json(resp).await;
    assert_eq!(doc["ref"], b.reference(D));
    assert_eq!(doc["node"], D);
    assert_eq!(doc["bot"], b.address(D));
    assert_eq!(doc["owner"], format!("alice@{D}"));
    assert_eq!(doc["public"], false, "private applications are served too");
    assert_eq!(doc["requested_permissions"], "3");
    assert_eq!(doc["scopes"], json!(["messages:read", "commands"]));
    assert_eq!(doc["commands"], json!([]));
    // Disabled, unknown and malformed ids: 404 app.not_found.
    node.patch(&format!("/api/v1/admin/applications/{}", b.app_id), &admin.token, json!({ "disabled": true })).await;
    for p in
        [path.clone(), format!("/api/v1/applications/{}/public", util::ulid()), "/api/v1/applications/x/public".into()]
    {
        let resp = node.get(&p).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{p}");
        assert_eq!(common::body_json(resp).await["code"], "app.not_found");
    }
}

trait Oneshot {
    async fn oneshot_req(self, req: axum::http::Request<axum::body::Body>) -> axum::http::Response<axum::body::Body>;
}

impl Oneshot for axum::Router {
    async fn oneshot_req(self, req: axum::http::Request<axum::body::Body>) -> axum::http::Response<axum::body::Body> {
        use tower::ServiceExt;
        self.oneshot(req).await.unwrap()
    }
}

// ---------------------------------------------------------------- node-level controls (§4.4)

#[tokio::test]
async fn admin_routes_list_disable_delete_and_block() {
    let node = test_node(D).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, json!({ "name": "Listed", "public": true }), None).await;
    let room = node.create_room(&alice.token, "One").await;
    let room2 = node.create_room(&alice.token, "Two").await;
    for r in [&room, &room2] {
        let (s, j) =
            install(&node, &alice.token, r["id"].as_str().unwrap(), json!({ "application": b.reference(D) })).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    // Node admins only.
    for (m, path) in [
        (Method::GET, "/api/v1/admin/applications".to_string()),
        (Method::GET, "/api/v1/admin/applications/blocks".into()),
        (Method::POST, "/api/v1/admin/applications/blocks".into()),
        (Method::PATCH, format!("/api/v1/admin/applications/{}", b.app_id)),
        (Method::DELETE, format!("/api/v1/admin/applications/{}", b.app_id)),
    ] {
        let (s, j) =
            node.req(m.clone(), &path, Some(&alice.token), Some(json!({ "disabled": true, "bot": "x@y.z" }))).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "auth.node_admin_required"), "{m} {path}");
        let (s, j) = node.req(m.clone(), &path, Some(&b.secret), Some(json!({}))).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"), "{m} {path}");
    }
    let (s, list) = node.get_auth("/api/v1/admin/applications", &admin.token).await;
    assert_eq!(s, StatusCode::OK);
    let entry = list.as_array().unwrap().iter().find(|a| a["id"] == b.app_id.as_str()).unwrap();
    assert_eq!(
        (entry["owner"].as_str(), entry["tokens"].as_i64(), entry["installations"].as_i64()),
        (Some(&*format!("alice@{D}")), Some(1), Some(2))
    );
    assert_eq!(entry["disabled"], false);

    // Disable: the token fails with app.disabled (reason admin), the list shows it.
    node.patch(&format!("/api/v1/admin/applications/{}", b.app_id), &admin.token, json!({ "disabled": true })).await;
    let (s, j) = node.get_auth("/api/v1/users/me", &b.secret).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.disabled"));
    let (_, list) = node.get_auth("/api/v1/admin/applications", &admin.token).await;
    assert_eq!(list[0]["disabled_reason"], "admin");
    node.patch(&format!("/api/v1/admin/applications/{}", b.app_id), &admin.token, json!({ "disabled": false })).await;
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::OK);

    // Block by address: removed from every room, tokens refused (reason blocked), installs refused.
    for bad in ["nobody", "a@b", "<x>@y.z"] {
        let (s, j) = node.post("/api/v1/admin/applications/blocks", &admin.token, json!({ "bot": bad })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.address"), "{bad}");
    }
    let (s, j) =
        node.post("/api/v1/admin/applications/blocks", &admin.token, json!({ "bot": format!("alice@{D}") })).await;
    assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "app.not_a_bot"));
    let (s, j) = node
        .post(
            "/api/v1/admin/applications/blocks",
            &admin.token,
            json!({ "bot": b.address(D).to_uppercase(), "reason": "spam" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["bot"], b.address(D));
    let (s, j) = node.post("/api/v1/admin/applications/blocks", &admin.token, json!({ "bot": b.address(D) })).await;
    assert_eq!((s, code(&j)), (StatusCode::CONFLICT, "app.already_blocked"));
    for r in [&room, &room2] {
        let (_, list) =
            node.get_auth(&format!("/api/v1/rooms/{}/applications", r["id"].as_str().unwrap()), &alice.token).await;
        assert_eq!(list, json!([]));
    }
    let (s, j) = node.get_auth("/api/v1/users/me", &b.secret).await;
    assert_eq!((s, code(&j), j["meta"]["reason"].as_str()), (StatusCode::FORBIDDEN, "app.disabled", Some("blocked")));
    let (s, blocks) = node.get_auth("/api/v1/admin/applications/blocks", &admin.token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!((blocks[0]["bot"].as_str(), blocks[0]["reason"].as_str()), (Some(&*b.address(D)), Some("spam")));
    assert_eq!(blocks[0]["created_by"], format!("admin@{D}"));
    let removed = audit_meta(&node, "app.uninstall").await;
    assert_eq!(removed.iter().filter(|m| m.contains("\"blocked\"")).count(), 2, "{removed:?}");
    assert_eq!(audit_meta(&node, "admin.app_block").await.len(), 1);
    // Unblock: no automatic reinstallation.
    let path = format!("/api/v1/admin/applications/blocks/{}", b.address(D));
    assert_eq!(node.delete(&path, &admin.token).await.0, StatusCode::NO_CONTENT);
    let (s, j) = node.delete(&path, &admin.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.block_not_found"));
    assert_eq!(audit_meta(&node, "admin.app_unblock").await.len(), 1);
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::OK);
    let (_, list) =
        node.get_auth(&format!("/api/v1/rooms/{}/applications", room["id"].as_str().unwrap()), &alice.token).await;
    assert_eq!(list, json!([]));
    // Delete.
    assert_eq!(
        node.delete(&format!("/api/v1/admin/applications/{}", b.app_id), &admin.token).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(node.get_auth("/api/v1/users/me", &b.secret).await.0, StatusCode::UNAUTHORIZED);
    let (s, j) = node.delete(&format!("/api/v1/admin/applications/{}", b.app_id), &admin.token).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
}

#[tokio::test]
async fn reports_about_applications_reach_the_admins() {
    let node = test_node(D).await;
    let admin = node.register("admin").await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, json!({ "name": "Spammy" }), None).await;
    let (s, j) = node
        .post(
            "/api/v1/directory/reports",
            &alice.token,
            json!({ "subject": { "kind": "application", "ref": b.reference(D) }, "check": "spam", "detail": "posts ads" }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["application"], b.reference(D));
    assert_eq!(j["domain"], D, "an application of this node may be reported here");
    for subject in [json!({ "kind": "user", "ref": b.reference(D) }), json!({ "kind": "application", "ref": "x" })] {
        let (s, j) =
            node.post("/api/v1/directory/reports", &alice.token, json!({ "subject": subject, "check": "spam" })).await;
        assert_eq!((s, code(&j)), (StatusCode::BAD_REQUEST, "validation.subject"));
    }
    // A node report without a domain is still refused.
    let (s, _) = node.post("/api/v1/directory/reports", &alice.token, json!({ "check": "spam" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, list) = node.get_auth(&format!("/api/v1/admin/directory/reports/{D}"), &admin.token).await;
    assert_eq!(list[0]["application"], b.reference(D));
    assert_eq!(list[0]["check"], "spam");
    // Bots cannot report.
    let (s, j) = node
        .post(
            "/api/v1/directory/reports",
            &b.secret,
            json!({ "subject": { "kind": "application", "ref": b.reference(D) }, "check": "spam" }),
        )
        .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.bot_forbidden"));
}

// ---------------------------------------------------------------- across nodes (§4.5)

#[tokio::test]
async fn cross_node_install_index_changes_and_deletion() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let requested = mask(&[p::SEND_MESSAGES]);
    let traveller =
        bot(&a, &alice, json!({ "name": "Traveller", "public": true, "requested_permissions": requested }), None).await;
    let reference = traveller.reference(federation::A);
    let mut ws = crossnode::ws(&a, &traveller.secret).await;
    // On B: carol installs the bot of A; B fetches the public document and creates a stub.
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Remote room").await;
    let room_id = room["id"].as_str().unwrap();
    let (s, inst) =
        install(&b, &carol.token, room_id, json!({ "application": reference, "permissions": requested })).await;
    assert_eq!(s, StatusCode::CREATED, "{inst}");
    assert_eq!(inst["bot"]["address"], traveller.address(federation::A));
    assert_eq!(inst["bot"]["kind"], "bot");
    assert_eq!(inst["bot"]["owner"], format!("alice@{}", federation::A));
    assert_eq!(inst["bot"]["application_id"], reference);
    assert_eq!(inst["application"]["name"], "Traveller");
    // A hears about it (S2S app.install), indexes the room and tells the bot.
    b.deliver().await;
    let ev = crossnode::event(&mut ws, "application.install").await;
    assert_eq!(
        (ev["node"].as_str(), ev["room_id"].as_str(), ev["room_name"].as_str()),
        (Some(federation::B), Some(room_id), Some("Remote room"))
    );
    assert_eq!(ev["installed_by"], format!("carol@{}", federation::B));
    let (_, idx) = a.get_auth("/api/v1/applications/me/installations", &traveller.secret).await;
    assert_eq!((idx[0]["node"].as_str(), idx[0]["room_id"].as_str()), (Some(federation::B), Some(room_id)));
    // The bot signs in on B and acts with the granted permissions.
    let remote = b.sign_in_from_bot(&a, &traveller.secret).await;
    let channel = TestNode::text_channel(&room);
    let (s, j) = b.send(&remote, room_id, &channel, "hello from A").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (_, msgs) = b.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"), &carol.token).await;
    assert_eq!(msgs[0]["author_kind"], "bot");

    // A renames the application: app.changed makes B refetch the profile.
    a.patch(&format!("/api/v1/applications/{}", traveller.app_id), &alice.token, json!({ "name": "Wanderer" })).await;
    a.deliver().await;
    let (_, members) = b.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &carol.token).await;
    let m = members.as_array().unwrap().iter().find(|m| m["user"]["kind"] == "bot").unwrap();
    assert_eq!(m["user"]["display_name"], "Wanderer");

    // Uninstall on B → app.uninstall → A drops the index entry.
    let (s, _) = b
        .delete(&format!("/api/v1/rooms/{room_id}/applications/{}", reference.replace('/', "%2F")), &carol.token)
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    b.deliver().await;
    assert_eq!(crossnode::event(&mut ws, "application.uninstall").await["reason"], "removed");
    let (_, idx) = a.get_auth("/api/v1/applications/me/installations", &traveller.secret).await;
    assert_eq!(idx, json!([]));

    // Installed again, then deleted on A: B uninstalls and refuses it.
    let (s, _) = install(&b, &carol.token, room_id, json!({ "application": reference })).await;
    assert_eq!(s, StatusCode::CREATED);
    b.deliver().await;
    let path = format!("/api/v1/applications/{}", traveller.app_id);
    let (s, _) = a.req(Method::DELETE, &path, Some(&alice.token), Some(json!({ "name": "Wanderer" }))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    a.deliver().await;
    let (_, list) = b.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), &carol.token).await;
    assert_eq!(list, json!([]));
    let (_, members) = b.get_auth(&format!("/api/v1/rooms/{room_id}/members"), &carol.token).await;
    assert!(!members.to_string().contains("\"kind\":\"bot\""));
    let (s, j) = install(&b, &carol.token, room_id, json!({ "application": reference })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
    assert!(audit_meta(&b, "app.uninstall").await.iter().any(|m| m.contains("\"deleted\"")));
}

#[tokio::test]
async fn remote_bots_refused_blocked_everywhere_and_private_by_owner_only() {
    // T refuses all foreign applications.
    let (a, b) = federation::two_nodes_with(|_| {}, |c| c.federation_remote_bots = false).await;
    let alice = a.register("alice").await;
    let x = bot(&a, &alice, json!({ "name": "Refused", "public": true }), None).await;
    let carol = b.register("carol").await;
    let room = b.create_room(&carol.token, "Room").await;
    let (s, j) =
        install(&b, &carol.token, room["id"].as_str().unwrap(), json!({ "application": x.reference(federation::A) }))
            .await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.bots_refused"));

    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let admin_b = b.register("admin").await;
    let carol = b.register("carol").await;
    let private = bot(&a, &alice, json!({ "name": "Mine" }), None).await;
    let public = bot(&a, &alice, json!({ "name": "Shared", "public": true }), None).await;
    let r1 = b.create_room(&carol.token, "One").await;
    let r2 = b.create_room(&carol.token, "Two").await;
    let (r1, r2) = (r1["id"].as_str().unwrap(), r2["id"].as_str().unwrap());
    // A private application of A: only alice (signed in on B) may install it.
    let (s, j) = install(&b, &carol.token, r1, json!({ "application": private.reference(federation::A) })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.private"));
    // An unknown application of A: 404.
    let (s, j) =
        install(&b, &carol.token, r1, json!({ "application": format!("{}/{}", federation::A, util::ulid()) })).await;
    assert_eq!((s, code(&j)), (StatusCode::NOT_FOUND, "app.not_found"));
    // A node that cannot be reached.
    let (s, j) =
        install(&b, &carol.token, r1, json!({ "application": format!("unknown.invalid/{}", util::ulid()) })).await;
    assert!(s == StatusCode::BAD_GATEWAY || s == StatusCode::FORBIDDEN, "{s} {j}");
    for r in [r1, r2] {
        let (s, j) = install(&b, &carol.token, r, json!({ "application": public.reference(federation::A) })).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
    }
    let remote = b.sign_in_from_bot(&a, &public.secret).await;
    // The admin of B blocks the bot: it leaves both rooms, its session ends, logins are refused.
    let (s, j) = b
        .post("/api/v1/admin/applications/blocks", &admin_b.token, json!({ "bot": public.address(federation::A) }))
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    for r in [r1, r2] {
        let (_, list) = b.get_auth(&format!("/api/v1/rooms/{r}/applications"), &carol.token).await;
        assert_eq!(list, json!([]));
    }
    assert_eq!(b.get_auth("/api/v1/rooms", &remote).await.0, StatusCode::UNAUTHORIZED);
    let (s, j) = a.post("/api/v1/federation/token", &public.secret, json!({ "target": federation::B })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = b.federated_login(j["token"].as_str().unwrap()).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.blocked"));
    let (s, j) = install(&b, &carol.token, r1, json!({ "application": public.reference(federation::A) })).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.blocked"));
    // A hears that the bot left both rooms.
    b.deliver().await;
    let (_, idx) = a.get_auth("/api/v1/applications/me/installations", &public.secret).await;
    assert_eq!(idx, json!([]));
}

/// Posts an inbox message signed by `from_node` to `to_node`; returns status and problem code.
async fn inbox(
    from_node: &federation::FedNode,
    to_node: &federation::FedNode,
    kind: &str,
    from: &str,
    to: &str,
    payload: Value,
) -> (StatusCode, String) {
    let body =
        json!({ "id": util::ulid(), "type": kind, "from": from, "to": to, "at": util::now(), "payload": payload })
            .to_string()
            .into_bytes();
    let n = chrono::Utc::now().timestamp();
    let token = from_node.sign(&json!({
        "iss": from_node.domain(), "sub": from_node.domain(), "aud": to_node.domain(), "iat": n, "exp": n + 300,
        "jti": util::ulid(), "typ": "s2s", "htm": "POST", "htu": "/api/v1/federation/inbox",
        "body_sha256": tavrn_node::federation::tokens::body_sha256(&body),
    }));
    let (st, _, raw) = to_node
        .raw(Method::POST, "/api/v1/federation/inbox", &token, &[("content-type", "application/json")], body)
        .await;
    let code = serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v["code"].as_str().map(String::from));
    (st, code.unwrap_or_default())
}

#[tokio::test]
async fn app_inbox_types_refuse_tampering() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let _bob = a.register("bob").await;
    let x = bot(&a, &alice, json!({ "name": "Target", "public": true }), None).await;
    let room = json!({ "node": federation::B, "id": util::ulid(), "name": "Fake" });
    let payload = json!({ "room": room, "installed_by": format!("carol@{}", federation::B) });
    let to = x.address(federation::A);
    // The room must be on the sending node.
    let wrong_room = json!({ "room": { "node": "c.test", "id": util::ulid(), "name": "x" }, "installed_by": format!("carol@{}", federation::B) });
    let (s, c) = inbox(&b, &a, "app.install", federation::B, &to, wrong_room).await;
    assert_eq!((s, c.as_str()), (StatusCode::BAD_REQUEST, "federation.envelope_invalid"));
    // Unknown bots, users and bots of other nodes are no recipients.
    for recipient in
        [format!("ghost@{}", federation::A), format!("bob@{}", federation::A), format!("xy@{}", federation::B)]
    {
        let (s, c) = inbox(&b, &a, "app.install", federation::B, &recipient, payload.clone()).await;
        assert_eq!((s, c.as_str()), (StatusCode::NOT_FOUND, "federation.recipient_unknown"), "{recipient}");
    }
    // A valid message is indexed.
    let (s, c) = inbox(&b, &a, "app.install", federation::B, &to, payload.clone()).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{c}");
    let (_, idx) = a.get_auth("/api/v1/applications/me/installations", &x.secret).await;
    assert_eq!(idx.as_array().unwrap().len(), 1);
    // A deletion notice for a bot B does not know as that application changes nothing.
    let carol = b.register("carol").await;
    let r = b.create_room(&carol.token, "Room").await;
    let rid = r["id"].as_str().unwrap();
    let (s, _) = install(&b, &carol.token, rid, json!({ "application": x.reference(federation::A) })).await;
    assert_eq!(s, StatusCode::CREATED);
    let other_app = json!({ "application_id": util::ulid(), "commands_version": 0, "deleted": true });
    let (s, _) = inbox(&a, &b, "app.changed", &to, federation::B, other_app).await;
    assert_eq!(s, StatusCode::ACCEPTED);
    let (_, list) = b.get_auth(&format!("/api/v1/rooms/{rid}/applications"), &carol.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "still installed");
    let (s, c) = inbox(&a, &b, "app.changed", &to, federation::B, json!({ "application_id": "nope" })).await;
    assert_eq!((s, c.as_str()), (StatusCode::BAD_REQUEST, "federation.envelope_invalid"));
    // Spoofed senders (each one counts as a violation of the sending node, so they come last).
    let (s, c) = inbox(&b, &a, "app.install", &format!("carol@{}", federation::B), &to, payload).await;
    assert_eq!((s, c.as_str()), (StatusCode::FORBIDDEN, "federation.type_forbidden"), "from must be the room node");
    let changed = json!({ "application_id": x.app_id, "commands_version": 0, "deleted": true });
    let (s, c) = inbox(&a, &b, "app.changed", &format!("x@{}", federation::B), federation::B, changed).await;
    assert_eq!((s, c.as_str()), (StatusCode::FORBIDDEN, "federation.type_forbidden"), "a bot of B sent by A");
    let (_, list) = b.get_auth(&format!("/api/v1/rooms/{rid}/applications"), &carol.token).await;
    assert_eq!(list.as_array().unwrap().len(), 1, "still installed");
}

// ---------------------------------------------------------------- token expiry notices (§2.2)

#[tokio::test]
async fn token_expiry_notices_go_to_owner_and_bot_once_per_threshold() {
    let node = test_node(D).await;
    let alice = node.register("alice").await;
    let b = bot(&node, &alice, json!({ "name": "Expiring" }), None).await;
    let mut rx = node.state.hub.subscribe();
    let now = chrono::Utc::now();
    // The token lives 365 days: nothing yet.
    assert_eq!(tavrn_node::applications::notify_expiring_tokens(&node.state, now).await.unwrap(), 0);
    // Six days before the expiry: the 7-day notice, once.
    let soon = now + chrono::Duration::days(359);
    assert_eq!(tavrn_node::applications::notify_expiring_tokens(&node.state, soon).await.unwrap(), 1);
    assert_eq!(tavrn_node::applications::notify_expiring_tokens(&node.state, soon).await.unwrap(), 0);
    let ev = rx.recv().await.unwrap();
    assert_eq!(ev.kind, "application.token_expiring");
    assert_eq!(ev.data["application_id"], b.app_id);
    assert_eq!(ev.data["days"], 7);
    assert!(
        matches!(&ev.scope, tavrn_node::hub::Scope::Users(users) if users.contains(&alice.user_id) && users.contains(&b.user_id)),
        "{:?}",
        ev.scope
    );
    // Hours before: the 1-day notice.
    let last = now + chrono::Duration::days(364) + chrono::Duration::hours(12);
    assert_eq!(tavrn_node::applications::notify_expiring_tokens(&node.state, last).await.unwrap(), 1);
    assert_eq!(rx.recv().await.unwrap().data["days"], 1);
    // A reset secret starts over.
    let (_, tokens) = node.get_auth(&format!("/api/v1/applications/{}/tokens", b.app_id), &alice.token).await;
    let token_id = tokens[0]["id"].as_str().unwrap();
    node.post(
        &format!("/api/v1/applications/{}/tokens/{token_id}/reset", b.app_id),
        &alice.token,
        json!({ "expires_in_days": 3 }),
    )
    .await;
    assert_eq!(tavrn_node::applications::notify_expiring_tokens(&node.state, now).await.unwrap(), 1);
}

// ---------------------------------------------------------------- bot presence (§7)

#[tokio::test]
async fn bot_presence_needs_the_presence_scope_and_activities_are_validated() {
    let (node, _other) = federation::two_nodes().await;
    let d = federation::A;
    let alice = node.register("alice").await;
    let room = node.create_room(&alice.token, "Lobby").await;
    let room_id = room["id"].as_str().unwrap();
    let with = bot(&node, &alice, json!({ "name": "Watcher" }), Some(&["presence", "members:read"])).await;
    let without = bot(&node, &alice, json!({ "name": "Silent" }), Some(&["messages:read"])).await;
    for b in [&with, &without] {
        install(&node, &alice.token, room_id, json!({ "application": b.reference(d) })).await;
    }
    // A bot is online while one of its WebSockets is open; its activity belongs to that connection.
    let _bot_ws = crossnode::ws(&node, &with.secret).await;
    let mut alice_ws = crossnode::ws(&node, &alice.token).await;
    let activity = json!({ "type": "watching", "name": "3 servers", "state": "All quiet" });
    // Without the scope: refused on every presence route.
    for (m, path, body) in [
        (Method::PUT, "/api/v1/users/me/presence", json!({ "status": "dnd" })),
        (Method::PUT, "/api/v1/users/me/activity", activity.clone()),
        (Method::DELETE, "/api/v1/users/me/activity", json!({})),
    ] {
        let (s, j) = node.req(m.clone(), path, Some(&without.secret), Some(body)).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.scope_missing"), "{m} {path}");
        assert_eq!(j["meta"]["scope"], "presence");
    }
    // With it: status and activity like a user; members see them.
    let (s, j) = node
        .put(
            "/api/v1/users/me/presence",
            &with.secret,
            json!({ "status": "dnd", "custom_status": { "text": "on duty" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.put("/api/v1/users/me/activity", &with.secret, activity).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["activity"]["state"], "All quiet");
    let deadline = common::deadline(std::time::Duration::from_secs(5));
    loop {
        let ev = crossnode::event(&mut alice_ws, "presence.update").await;
        if ev["user_id"] == with.user_id.as_str() && ev["activity"]["name"] == "3 servers" {
            assert_eq!(ev["status"], "dnd");
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "the bot's presence reaches the room");
    }
    // Rich presence fields are validated (format only).
    let start = util::in_seconds(-60);
    let app_ref = format!("games.example/{}", util::ulid());
    let (s, j) = node
        .put(
            "/api/v1/users/me/activity",
            &alice.token,
            json!({ "type": "playing", "name": "Space Miners", "details": "Ranked match", "state": "In a party (2 of 4)",
                    "started_at": start, "ends_at": util::in_seconds(1800),
                    "application": { "ref": app_ref, "name": "Space Miners" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["activity"]["application"]["ref"], app_ref);
    assert_eq!(j["activity"]["application"]["name"], "Space Miners");
    assert_eq!(j["activity"]["state"], "In a party (2 of 4)");
    assert!(j["activity"]["ends_at"].is_string());
    for bad in [
        json!({ "type": "playing", "name": "x", "state": "y".repeat(129) }),
        json!({ "type": "playing", "name": "x", "started_at": start, "ends_at": util::in_seconds(-3600) }),
        json!({ "type": "playing", "name": "x", "ends_at": "soon" }),
        json!({ "type": "playing", "name": "x", "application": { "ref": "javascript:alert(1)", "name": "x" } }),
        json!({ "type": "playing", "name": "x", "application": { "ref": app_ref, "name": "" } }),
        json!({ "type": "playing", "name": "x", "application": { "name": "no ref" } }),
    ] {
        let (s, j) = node.put("/api/v1/users/me/activity", &alice.token, bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert!(["presence.activity_invalid", "request.invalid_json"].contains(&code(&j)), "{bad}: {j}");
    }
}

#[tokio::test]
async fn installation_routes_check_permissions_for_local_and_remote_callers() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let carol = b.register("carol").await;
    let dave = b.register("dave").await;
    let x = bot(&b, &carol, json!({ "name": "Local", "public": true }), None).await;
    let room = b.create_room(&carol.token, "Room").await;
    let room_id = room["id"].as_str().unwrap();
    member(&b, &carol, room_id, &dave).await;
    // alice of A joins carol's room on B with a federated session.
    let remote = b.sign_in_from(&a, &alice).await;
    let (_, invite) = b.post(&format!("/api/v1/rooms/{room_id}/invites"), &carol.token, json!({})).await;
    let (s, j) =
        b.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let body = json!({ "application": x.reference(federation::B) });
    // Members without manage_applications (local or remote) can neither install, list nor uninstall.
    for token in [dave.token.as_str(), remote.token.as_str()] {
        let (s, j) = install(&b, token, room_id, body.clone()).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
        let (s, j) = b.get_auth(&format!("/api/v1/rooms/{room_id}/applications"), token).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "app.manage_forbidden"));
    }
    let (s, _) = install(&b, &carol.token, room_id, body.clone()).await;
    assert_eq!(s, StatusCode::CREATED);
    let path = format!("/api/v1/rooms/{room_id}/applications/{}", x.reference(federation::B).replace('/', "%2F"));
    for token in [dave.token.as_str(), remote.token.as_str(), x.secret.as_str()] {
        let (s, j) = b.delete(&path, token).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    }
    // A remote room manager may install (the room node decides, private applications only by their owner).
    let (_, role) = b
        .post(
            &format!("/api/v1/rooms/{room_id}/roles"),
            &carol.token,
            json!({ "name": "Managers", "permissions": mask(&[p::MANAGE_APPLICATIONS]) }),
        )
        .await;
    let remote_id = remote.response["user"]["id"].as_str().unwrap();
    b.patch(&format!("/api/v1/rooms/{room_id}/members/{remote_id}"), &carol.token, json!({ "roles": [role["id"]] }))
        .await;
    let y = bot(&b, &carol, json!({ "name": "Other", "public": true }), None).await;
    let (s, j) = install(&b, &remote.token, room_id, json!({ "application": y.reference(federation::B) })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["installed_by"], format!("alice@{}", federation::A));
    // The node administration and the bot's index are local-only / app-token-only.
    for (m, p) in [(Method::GET, "/api/v1/admin/applications"), (Method::GET, "/api/v1/admin/applications/blocks")] {
        let (s, j) = b.req(m, p, Some(&remote.token), None).await;
        assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"), "{p}");
    }
    let (s, j) = b.get_auth("/api/v1/applications/me/installations", &remote.token).await;
    assert_eq!((s, code(&j)), (StatusCode::FORBIDDEN, "federation.local_only"));
    // A remote bot's federated session cannot read the index on T either (it asks its home node).
    let z = bot(&a, &alice, json!({ "name": "Visitor", "public": true }), None).await;
    let rb = b.sign_in_from_bot(&a, &z.secret).await;
    let (s, _) = b.get_auth("/api/v1/applications/me/installations", &rb).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// FEDERATION.md §2.6: the home node's verified token decides the account kind. A stub created on the target before
/// the bot ever signed in there (here by a friend request) is a plain user row: the bot's federated login makes it
/// a bot with its owner, so the bot rules apply (bots enter rooms only through an installation).
#[tokio::test]
async fn a_stub_of_a_remote_bot_becomes_a_bot_at_its_first_sign_in() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    let helper = bot(&a, &alice, json!({ "name": "Helper", "public": true }), Some(&["messages:read"])).await;
    let carol = b.register("carol").await;
    let (s, j) = b
        .post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": helper.address(federation::A) }))
        .await;
    assert!(s.is_success() || s == StatusCode::FORBIDDEN, "the request may be refused, the stub stays: {s} {j}");
    let stub: (String,) = sqlx::query_as("SELECT kind FROM users WHERE username = $1 AND domain = $2")
        .bind(&helper.username)
        .bind(federation::A)
        .fetch_one(&b.state.db)
        .await
        .unwrap();
    assert_eq!(stub.0, "user", "the stub as the friend request created it");

    let remote = b.sign_in_from_bot(&a, &helper.secret).await;
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT kind, owner_id FROM users WHERE username = $1 AND domain = $2")
            .bind(&helper.username)
            .bind(federation::A)
            .fetch_one(&b.state.db)
            .await
            .unwrap();
    assert_eq!(row.0, "bot");
    assert!(row.1.is_some(), "the owner is known");
    let room = b.plaintext_room(&carol.token, "Room").await;
    let (_, invite) =
        b.post(&format!("/api/v1/rooms/{}/invites", room["id"].as_str().unwrap()), &carol.token, json!({})).await;
    let (s, j) =
        b.post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &remote, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a bot joins only through an installation: {j}");
}

/// The reverse is refused: a bot account here never becomes a user through a token naming another kind (that
/// would lift the bot rules).
#[tokio::test]
async fn a_bot_account_is_never_turned_into_a_user() {
    let (a, b) = federation::two_nodes().await;
    let alice = a.register("alice").await;
    b.sign_in_from(&a, &alice).await;
    sqlx::query("UPDATE users SET kind = 'bot' WHERE username = 'alice' AND domain = $1")
        .bind(federation::A)
        .execute(&b.state.db)
        .await
        .unwrap();
    let token = a.federation_token(&alice, federation::B).await;
    let (s, j) = b.federated_login(&token).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.kind_mismatch")), "{j}");
}
