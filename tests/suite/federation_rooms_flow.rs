// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Federation, phase 3 step 3 (FEDERATION.md §3): rooms, keys and MLS across nodes. Users of `a.test`
//! use rooms on `b.test` with federated sessions; `b.test` caches their keys and claims their
//! KeyPackages from `a.test` through the S2S claim.

use crate::common;

use axum::http::{Method, StatusCode};
use common::{
    crossnode::{event, no_event, q, ws},
    e2ee::b64,
    federation::{A, B, FedNode, two_nodes, two_nodes_with},
    perms,
};
use serde_json::{Value, json};
use tavrn_crypto::{Client, Device, MasterSecret};
use tavrn_node::{federation::tokens::body_sha256, permissions as p, util};

async fn public_room(b: &FedNode, token: &str, name: &str) -> Value {
    let (st, room) = b.post("/api/v1/rooms", token, json!({ "name": name, "join_mode": "public" })).await;
    assert_eq!(st, StatusCode::CREATED, "{room}");
    room
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_string()
}

async fn member_addresses(b: &FedNode, token: &str, room_id: &str) -> Vec<String> {
    let (st, members) = b.get_auth(&format!("/api/v1/rooms/{room_id}/members"), token).await;
    assert_eq!(st, StatusCode::OK, "{members}");
    let mut out: Vec<String> =
        members.as_array().unwrap().iter().map(|m| m["user"]["address"].as_str().unwrap().to_string()).collect();
    out.sort();
    out
}

// ---------------------------------------------------------------- rooms

#[tokio::test]
async fn a_user_of_a_joins_a_public_room_on_b_and_posts() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room = b.plaintext_room(&carol.token, "Meeting point").await;
    let room_id = id(&room);
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let channel = common::TestNode::text_channel(&room);

    let alice = a.register("alice").await;
    let remote = b.sign_in_from(&a, &alice).await;
    let (st, joined) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{joined}");
    assert_eq!(member_addresses(&b, &carol.token, &room_id).await, vec!["alice@a.test", "carol@b.test"]);

    let (st, msg) = b.send(&remote.token, &room_id, &channel, "Hello from A").await;
    assert_eq!(st, StatusCode::CREATED, "{msg}");
    assert_eq!(msg["author"], "alice@a.test");
    assert_eq!(msg["device_id"], alice.device_id.as_str(), "messages name the home device id");
    let (st, list) = b.get_auth(&format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"), &carol.token).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list[0]["content"]["body"], "Hello from A");

    // Reactions and leaving work like for local members.
    let mid = id(&msg);
    let (st, reacted) = b
        .req(
            Method::PUT,
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/messages/{mid}/reactions/%F0%9F%91%8D"),
            Some(&remote.token),
            None,
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{reacted}");
    let (st, _) = b.post(&format!("/api/v1/rooms/{room_id}/leave"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(member_addresses(&b, &carol.token, &room_id).await, vec!["carol@b.test"]);
}

#[tokio::test]
async fn direct_invites_reach_the_invite_list_on_the_home_node() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room = b.create_room(&carol.token, "Secret society").await; // invite-only
    let room_id = id(&room);
    let alice = a.register("alice").await;
    let mut alice_ws = ws(&a, &alice.token).await;

    let (st, j) = b
        .post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &carol.token, json!({ "user": "alice@a.test" }))
        .await;
    assert_eq!(st, StatusCode::ACCEPTED, "{j}");
    let code = j["invite"]["code"].as_str().unwrap().to_string();
    assert_eq!(j["invite"]["user"], "alice@a.test");
    assert_eq!(j["invite"]["max_uses"], 1);
    assert!(j["invite"]["expires_at"].is_string());
    let kinds: Vec<String> = b.outbox().await.into_iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec!["room.invite"]);
    assert_eq!(b.deliver().await.delivered, 1);

    let pushed = event(&mut alice_ws, "room.invite").await;
    assert_eq!(pushed["invite"]["invite_code"], code.as_str());
    let (st, list) = a.get_auth("/api/v1/users/me/invites", &alice.token).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{list}");
    let inv = &items[0];
    assert_eq!(inv["kind"], "room");
    assert_eq!(inv["node"], B);
    assert_eq!(inv["inviter"], "carol@b.test");
    assert_eq!(inv["invite_code"], code.as_str());
    assert_eq!(inv["room"]["id"], room_id.as_str());
    assert_eq!(inv["room"]["name"], "Secret society");
    assert!(inv["expires_at"].is_string());

    // The bound invite works only for alice.
    let mallory = a.register("mallory").await;
    let remote_mallory = b.sign_in_from(&a, &mallory).await;
    let (st, j) = b.post(&format!("/api/v1/invites/{code}/join"), &remote_mallory.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("invite.wrong_user")), "{j}");
    let dave = b.register("dave").await;
    let (st, j) = b.post(&format!("/api/v1/invites/{code}/join"), &dave.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("invite.wrong_user")), "{j}");
    let remote = b.sign_in_from(&a, &alice).await;
    let (st, j) = b.post(&format!("/api/v1/invites/{code}/join"), &remote.token, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    assert_eq!(member_addresses(&b, &carol.token, &room_id).await, vec!["alice@a.test", "carol@b.test"]);

    // Dismissing the invite on A; the list is local only.
    let inv_id = inv["id"].as_str().unwrap();
    let (st, _) = a.delete(&format!("/api/v1/users/me/invites/{inv_id}"), &alice.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) = a.delete(&format!("/api/v1/users/me/invites/{inv_id}"), &alice.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("invite.not_found")));
    let (st, j) = b.get_auth("/api/v1/users/me/invites", &remote.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")));

    // Local invitees get the entry directly.
    let (st, _) =
        b.post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &carol.token, json!({ "user": "dave" })).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let (_, list) = b.get_auth("/api/v1/users/me/invites", &dave.token).await;
    assert_eq!(list["items"][0]["node"], B);
    assert_eq!(list["items"][0]["inviter"], "carol@b.test");
}

#[tokio::test]
async fn direct_invite_refusals() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room_id = id(&b.create_room(&carol.token, "Secret society").await);
    let path = format!("/api/v1/rooms/{room_id}/invites/direct");

    let (st, j) = b.post(&path, &carol.token, json!({ "user": "nobody@a.test" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("user.not_found")), "{j}");
    let (st, j) = b.post(&path, &carol.token, json!({ "user": "x@" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{j}");
    // Only members with create_invites may invite.
    let dave = b.register("dave").await;
    let (st, j) = b.post(&path, &dave.token, json!({ "user": "alice@a.test" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.not_member")), "{j}");

    // Blocked inviters are dropped silently by the home node.
    let alice = a.register("alice").await;
    let (st, j) = a.post("/api/v1/users/me/blocks", &alice.token, json!({ "user": "carol@b.test" })).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let (st, _) = b.post(&path, &carol.token, json!({ "user": "alice@a.test" })).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    assert_eq!(b.deliver().await.delivered, 1);
    let (_, list) = a.get_auth("/api/v1/users/me/invites", &alice.token).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 0, "{list}");
}

#[tokio::test]
async fn a_domain_ban_removes_its_members_and_refuses_rejoins() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room_id = id(&public_room(&b, &carol.token, "Open").await);
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let dave = b.register("dave").await;
    let ra = b.sign_in_from(&a, &alice).await;
    let rb = b.sign_in_from(&a, &bob).await;
    for t in [&ra.token, &rb.token, &dave.token] {
        let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), t, json!({})).await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let mut carol_ws = ws(&b, &carol.token).await;

    let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/bans"), &carol.token, json!({ "subject": "a.test" })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(member_addresses(&b, &carol.token, &room_id).await, vec!["carol@b.test", "dave@b.test"]);
    let left = event(&mut carol_ws, "member.leave").await;
    assert_eq!(left["banned"], true);

    let (st, j) = b.get_auth(&format!("/api/v1/rooms/{room_id}"), &ra.token).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.not_member")));
    let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &ra.token, json!({})).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("room.banned")));
    let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/bans"), &carol.token, json!({ "subject": B })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("ban.own_domain")));

    // Lifting the ban allows joining again.
    let (st, _) = b.delete(&format!("/api/v1/rooms/{room_id}/bans/a.test"), &carol.token).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &ra.token, json!({})).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn a_node_ban_of_a_domain_ends_its_sessions_and_memberships() {
    let (a, b) = two_nodes().await;
    let admin = b.register("admin").await; // first user of a dev node is admin
    let room_id = id(&public_room(&b, &admin.token, "Open").await);
    let alice = a.register("alice").await;
    let ra = b.sign_in_from(&a, &alice).await;
    b.post(&format!("/api/v1/rooms/{room_id}/join"), &ra.token, json!({})).await;

    let (st, j) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": A })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(member_addresses(&b, &admin.token, &room_id).await, vec!["admin@b.test"]);
    let (st, _) = b.get_auth("/api/v1/users/me", &ra.token).await;
    assert_ne!(st, StatusCode::OK, "the federated session ended");
}

#[tokio::test]
async fn bans_notify_the_home_node_when_the_operator_enables_it() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_notify_bans = true).await;
    let admin = b.register("admin").await; // the first user of a dev node is node admin
    let rooms =
        [id(&public_room(&b, &admin.token, "Open").await), id(&public_room(&b, &admin.token, "Second room").await)];
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let ra = b.sign_in_from(&a, &alice).await;
    let rb = b.sign_in_from(&a, &bob).await;
    for room_id in &rooms {
        for t in [&ra.token, &rb.token] {
            assert_eq!(b.post(&format!("/api/v1/rooms/{room_id}/join"), t, json!({})).await.0, StatusCode::OK);
        }
    }
    let mut alice_ws = ws(&a, &alice.token).await;
    let mut bob_ws = ws(&a, &bob.token).await;

    // A room ban: one ban.notify to alice's home node; no reason is transmitted.
    let (st, j) = b
        .post(
            &format!("/api/v1/rooms/{}/bans", rooms[0]),
            &admin.token,
            json!({ "subject": "alice@a.test", "reason": "confidential" }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let queued = b.outbox().await;
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!((queued[0].target.as_str(), queued[0].kind.as_str()), (A, "ban.notify"));
    assert!(!queued[0].body.contains("confidential"), "no reason");
    assert_eq!(b.deliver().await.delivered, 1);
    let notice = event(&mut alice_ws, "ban.notify").await;
    assert_eq!(notice["scope"], "room");
    assert_eq!(notice["room"], json!({ "node": B, "id": rooms[0], "name": "Open" }));

    // A node ban of an address: one per room the user was removed from.
    let (st, j) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": "bob@a.test" })).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    assert_eq!(b.deliver().await.delivered, 2);
    let mut seen = Vec::new();
    for _ in 0..2 {
        let notice = event(&mut bob_ws, "ban.notify").await;
        assert_eq!(notice["scope"], "node");
        seen.push(notice["room"]["id"].as_str().unwrap().to_string());
    }
    seen.sort();
    let mut expected = rooms.to_vec();
    expected.sort();
    assert_eq!(seen, expected);
    assert!(no_event(&mut alice_ws, "ban.notify", 200).await);

    // A node ban of the whole domain blocks it: nothing is sent there any more.
    let (st, _) = b.post("/api/v1/admin/bans", &admin.token, json!({ "subject": A })).await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(b.outbox().await.is_empty());
}

#[tokio::test]
async fn bans_send_no_notice_by_default() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let room_id = id(&public_room(&b, &carol.token, "Open").await);
    let alice = a.register("alice").await;
    let ra = b.sign_in_from(&a, &alice).await;
    b.post(&format!("/api/v1/rooms/{room_id}/join"), &ra.token, json!({})).await;
    let (st, _) = b.post(&format!("/api/v1/rooms/{room_id}/bans"), &carol.token, json!({ "subject": "a.test" })).await;
    assert_eq!(st, StatusCode::CREATED);
    assert!(b.outbox().await.is_empty(), "TAVRN_FEDERATION_NOTIFY_BANS is off by default");
}

#[tokio::test]
async fn the_api_of_remote_users_is_rate_limited_per_domain() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_rate_api = 3).await;
    let alice = a.register("alice").await;
    let bob = a.register("bob").await;
    let ra = b.sign_in_from(&a, &alice).await;
    let rb = b.sign_in_from(&a, &bob).await;
    for _ in 0..3 {
        assert_eq!(b.get_auth("/api/v1/users/me", &ra.token).await.0, StatusCode::OK);
    }
    let (st, _) = b.get_auth("/api/v1/users/me", &rb.token).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "the limit counts all users of the domain");
    let local = b.register("local").await;
    assert_eq!(b.get_auth("/api/v1/users/me", &local.token).await.0, StatusCode::OK, "local users are not counted");
}

#[tokio::test]
async fn a_blocklisted_domain_is_refused_everywhere() {
    let (a, b) = two_nodes_with(|_| {}, |c| c.federation_blocklist = A.into()).await;
    a.register("alice").await;
    let carol = b.register("carol").await;
    let room_id = id(&b.create_room(&carol.token, "Secret society").await);
    let (st, j) = b
        .post(&format!("/api/v1/rooms/{room_id}/invites/direct"), &carol.token, json!({ "user": "alice@a.test" }))
        .await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")), "{j}");
    let (st, j) = b.claim_raw(&carol.token, "alice@a.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")), "{j}");
    let (st, j) = b.post("/api/v1/users/me/friends/requests", &carol.token, json!({ "user": "alice@a.test" })).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.peer_blocked")), "{j}");
}

// ---------------------------------------------------------------- keys and MLS

/// carol (B) owns a room with a private encrypted channel that alice (A) may see; alice joined.
struct PrivateChannel {
    room_id: String,
    channel: String,
}

async fn private_channel(b: &FedNode, carol: &common::crossnode::FedDev, remote_alice: &str) -> PrivateChannel {
    let room = public_room(b, carol.token(), "Room").await;
    let room_id = id(&room);
    let (st, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), remote_alice, json!({})).await;
    assert_eq!(st, StatusCode::OK, "{j}");
    let (st, channel) = b
        .post(&format!("/api/v1/rooms/{room_id}/channels"), carol.token(), json!({ "kind": "text", "name": "intern" }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "{channel}");
    let channel = id(&channel);
    let everyone = room["roles"].as_array().unwrap().iter().find(|r| r["is_everyone"] == true).unwrap()["id"].clone();
    let (_, me) = b.get_auth("/api/v1/users/me", remote_alice).await;
    for (subject_type, subject_id, allow, deny) in [
        ("role", everyone, "0".to_string(), perms(&[p::VIEW_CHANNEL])),
        ("member", me["id"].clone(), perms(&[p::VIEW_CHANNEL]), "0".to_string()),
    ] {
        let (st, j) = b
            .put(
                &format!("/api/v1/rooms/{room_id}/overrides"),
                carol.token(),
                json!({ "target_type": "channel", "target_id": channel, "subject_type": subject_type,
                        "subject_id": subject_id, "allow": allow, "deny": deny }),
            )
            .await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    PrivateChannel { room_id, channel }
}

#[tokio::test]
async fn a_member_on_b_adds_a_user_of_a_to_a_private_channel_and_both_chat_encrypted() {
    let (a, b) = two_nodes().await;
    let mut carol = b.crypto_user("carol", 3).await;
    let mut alice = a.crypto_user("alice", 3).await;
    let remote = b.sign_in_from(&a, &alice.session).await;
    let pc = private_channel(&b, &carol, &remote.token).await;

    // The room node answers key lookups for remote members from its cache.
    let (st, keys) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(st, StatusCode::OK, "{keys}");
    assert_eq!(keys["user"], "alice@a.test");
    assert_eq!(keys["identity_public_key"], b64(&alice.master.identity_public_key()).as_str());
    assert_eq!(keys["devices"][0]["device_id"], alice.session.device_id.as_str());
    let (st, j) = b.req(Method::GET, "/api/v1/users/stranger@a.test/keys", None, None).await;
    assert_eq!(
        (st, j["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("user.not_found")),
        "unknown remote users are never fetched"
    );

    b.mls_group(B, &carol.session.token, &mut carol.client, &pc.channel).await;
    // KeyPackages of alice are claimed from A through B.
    assert_eq!(a.kp_count(&alice.session.device_id).await, 3);
    let (st, claimed) = b.claim_raw(carol.token(), "alice@a.test").await;
    assert_eq!(st, StatusCode::OK, "{claimed}");
    assert_eq!(claimed["key_packages"].as_array().unwrap().len(), 1);
    assert_eq!(claimed["key_packages"][0]["device_id"], alice.session.device_id.as_str());
    assert_eq!(a.kp_count(&alice.session.device_id).await, 2, "claimed packages are deleted on the home node");
    let kps = vec![common::e2ee::unb64(&claimed["key_packages"][0]["key_package"])];
    let out = carol.client.add_members(&q(B, &pc.channel), &kps).unwrap();
    let (st, j) = b.commit(carol.token(), &pc.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    carol.client.merge_pending_commit(&q(B, &pc.channel)).unwrap();

    // alice fetches her Welcome on B with the federated session and the two talk.
    assert_eq!(b.join_welcomes(B, &remote.token, &mut alice.client).await, 1);
    let (st, m) = b.send_secret(B, &remote.token, &alice.client, &pc.channel, "secret from A").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    assert_eq!(m["device_id"], alice.session.device_id.as_str());
    assert_eq!(b.read_secret(B, carol.token(), &carol.client, &pc.channel).await, "secret from A");
    let (st, m) = b.send_secret(B, carol.token(), &carol.client, &pc.channel, "secret from B").await;
    assert_eq!(st, StatusCode::CREATED, "{m}");
    assert_eq!(b.read_secret(B, &remote.token, &alice.client, &pc.channel).await, "secret from B");

    // A self update of the remote device is accepted (rule 1 with the home node's key).
    let out = alice.client.self_update(&q(B, &pc.channel)).unwrap();
    let (st, j) = b.commit(&remote.token, &pc.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let _ = pc.room_id;
}

#[tokio::test]
async fn commits_with_unattested_remote_devices_are_refused() {
    let (a, b) = two_nodes().await;
    let mut carol = b.crypto_user("carol", 3).await;
    let alice = a.crypto_user("alice", 3).await;
    let remote = b.sign_in_from(&a, &alice.session).await;
    let pc = private_channel(&b, &carol, &remote.token).await;
    b.mls_group(B, &carol.session.token, &mut carol.client, &pc.channel).await;

    // A device of alice that A never attested, with a key of the attacker.
    let fake = Client::new(Device::generate("alice@a.test", &util::ulid()).unwrap());
    let kp = fake.create_key_package().unwrap();
    let out = carol.client.add_members(&q(B, &pc.channel), &[kp]).unwrap();
    let (st, j) = b.commit(carol.token(), &pc.channel, &out).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("mls.forbidden")), "{j}");
    carol.client.discard_pending_commit(&q(B, &pc.channel)).unwrap();

    // The attested device id of alice with another key is refused as well.
    let forged = Client::new(Device::generate("alice@a.test", &alice.session.device_id).unwrap());
    let kp = forged.create_key_package().unwrap();
    let out = carol.client.add_members(&q(B, &pc.channel), &[kp]).unwrap();
    let (st, j) = b.commit(carol.token(), &pc.channel, &out).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("mls.forbidden")), "{j}");
    carol.client.discard_pending_commit(&q(B, &pc.channel)).unwrap();

    // A second device of alice without attestation cannot act in MLS on B.
    let laptop = a.login("alice").await;
    let remote_laptop = b.sign_in_from(&a, &laptop).await;
    let mut unattested = Client::new(Device::generate("alice@a.test", &laptop.device_id).unwrap());
    let gi = unattested.create_group(&q(B, &pc.channel)).unwrap();
    let (st, j) = b
        .post(
            &format!("/api/v1/conversations/{}/mls/group", pc.channel),
            &remote_laptop.token,
            json!({ "group_info": b64(&gi) }),
        )
        .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{j}");
    let gi = b.get_auth(&format!("/api/v1/conversations/{}/mls/group-info", pc.channel), &remote_laptop.token).await;
    let out =
        unattested.join_by_external_commit(&q(B, &pc.channel), &common::e2ee::unb64(&gi.1["group_info"])).unwrap();
    let (st, j) = b.commit(&remote_laptop.token, &pc.channel, &out).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("e2ee.device_not_attested")), "{j}");

    // A user of A who is not a member of the room cannot be added.
    let mallory = a.crypto_user("mallory", 2).await;
    b.sign_in_from(&a, &mallory.session).await;
    let kps = b.claim_kps(carol.token(), "mallory@a.test").await;
    let out = carol.client.add_members(&q(B, &pc.channel), &kps).unwrap();
    let (st, j) = b.commit(carol.token(), &pc.channel, &out).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("mls.forbidden")), "{j}");
}

#[tokio::test]
async fn key_changes_on_a_reach_b() {
    let (a, b) = two_nodes().await;
    let mut carol = b.crypto_user("carol", 3).await;
    let alice = a.crypto_user("alice", 3).await;
    let laptop_session = a.login("alice").await;
    let laptop = a.attest_fed(laptop_session, MasterSecret::from_bytes(*alice.master.to_bytes()), 2).await;
    let remote = b.sign_in_from(&a, &alice.session).await;
    let pc = private_channel(&b, &carol, &remote.token).await;
    b.mls_group(B, &carol.session.token, &mut carol.client, &pc.channel).await;
    b.add_to_group(B, &carol.session.token, &mut carol.client, &pc.channel, "alice@a.test").await;
    assert_eq!(carol.client.roster(&q(B, &pc.channel)).unwrap().len(), 3, "carol and both devices of alice");
    let mut carol_ws = ws(&b, carol.token()).await;

    // A device deleted on A: devices.changed → B refetches and asks to remove the vanished leaf.
    let (st, _) = a.delete(&format!("/api/v1/users/me/devices/{}", laptop.session.device_id), alice.token()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(a.deliver().await.delivered, 2, "session.revoke and devices.changed");
    let needed = event(&mut carol_ws, "mls.remove_needed").await;
    assert_eq!(needed["conversation_id"], pc.channel.as_str());
    let laptop_identity = format!("alice@a.test/{}", laptop.session.device_id);
    assert_eq!(needed["identities"], json!([laptop_identity]));
    let (_, keys) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(keys["devices"].as_array().unwrap().len(), 1, "{keys}");
    // The vanished device may now be removed by any member (rule 4).
    let out = carol.client.remove_members(&q(B, &pc.channel), &[laptop_identity]).unwrap();
    let (st, j) = b.commit(carol.token(), &pc.channel, &out).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    carol.client.merge_pending_commit(&q(B, &pc.channel)).unwrap();

    // An identity reset on A: identity.changed → new key mirrored, all leaves to be removed.
    let new_master = MasterSecret::generate().unwrap();
    let (st, j) = a
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&new_master.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(a.deliver().await.delivered, 1);
    let needed = event(&mut carol_ws, "mls.remove_needed").await;
    assert_eq!(needed["identities"], json!([format!("alice@a.test/{}", alice.session.device_id)]));
    let (_, keys) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(keys["identity_public_key"], b64(&new_master.identity_public_key()).as_str());
    assert_eq!(keys["devices"].as_array().unwrap().len(), 0, "not re-attested yet: {keys}");
    assert!(no_event(&mut carol_ws, "mls.remove_needed", 200).await);
}

#[tokio::test]
async fn key_package_claims_are_limited_and_refused_for_blocked_requesters() {
    let (a, b) = two_nodes_with(|c| c.federation_rate_claims = 2, |_| {}).await;
    let carol = b.crypto_user("carol", 1).await;
    let alice = a.crypto_user("alice", 5).await;
    b.sign_in_from(&a, &alice.session).await;
    for _ in 0..2 {
        let (st, j) = b.claim_raw(carol.token(), "alice@a.test").await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let (st, j) = b.claim_raw(carol.token(), "alice@a.test").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "the home node limits claims per requesting node: {j}");

    let (a, b) = two_nodes().await;
    let carol = b.crypto_user("carol", 1).await;
    let alice = a.crypto_user("alice", 5).await;
    b.sign_in_from(&a, &alice.session).await;
    let (st, j) = b.claim_raw(carol.token(), "unknown@a.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("user.not_found")), "{j}");
    let (st, _) = a.post("/api/v1/users/me/blocks", alice.token(), json!({ "user": "carol@b.test" })).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, j) = b.claim_raw(carol.token(), "alice@a.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.claim_refused")), "{j}");
}

#[tokio::test]
async fn cached_keys_stand_in_for_an_unreachable_home_node_for_a_day() {
    let (a, b) = two_nodes().await;
    let carol = b.crypto_user("carol", 1).await;
    let alice = a.crypto_user("alice", 3).await;
    b.sign_in_from(&a, &alice.session).await;
    let (st, keys) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(st, StatusCode::OK, "{keys}");
    a.stop().await;

    let set_age = |hours: i64| {
        let at = util::format_time(chrono::Utc::now() - chrono::Duration::hours(hours));
        let db = b.state.db.clone();
        async move {
            sqlx::query("UPDATE remote_users SET keys_fetched_at = $1").bind(at).execute(&db).await.unwrap();
        }
    };
    set_age(2).await;
    let (st, stale) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(st, StatusCode::OK, "an expired cache is used while A is down: {stale}");
    assert_eq!(stale["devices"], keys["devices"]);
    let (st, j) = b.claim_raw(carol.token(), "alice@a.test").await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("federation.peer_unreachable")), "{j}");

    set_age(25).await;
    let (st, j) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("federation.keys_unavailable")), "{j}");
}

const CLAIM_PATH: &str = "/api/v1/federation/key-packages/claim";

fn claim_token(b: &FedNode, body: &[u8], htu: &str) -> String {
    let n = chrono::Utc::now().timestamp();
    b.sign(&json!({
        "iss": B, "sub": B, "aud": A, "iat": n, "exp": n + 300, "jti": util::ulid(), "typ": "s2s",
        "htm": "POST", "htu": htu, "body_sha256": body_sha256(body),
    }))
}

#[tokio::test]
async fn the_s2s_claim_checks_its_token_and_body() {
    let (a, b) = two_nodes().await;
    let alice = a.crypto_user("alice", 3).await;
    let body = json!({ "user": "alice@a.test", "requester": "carol@b.test" }).to_string().into_bytes();
    let post = |token: String, body: Vec<u8>| {
        let a = &a;
        async move { a.raw(Method::POST, CLAIM_PATH, &token, &[("content-type", "application/json")], body).await }
    };
    let (st, _, _) = post(claim_token(&b, &body, CLAIM_PATH), body.clone()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(a.kp_count(&alice.session.device_id).await, 2);

    let (st, _, raw) = post(claim_token(&b, &body, "/api/v1/federation/inbox"), body.clone()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "token for another route: {raw:?}");
    let other = json!({ "user": "alice@a.test", "requester": "mallory@b.test" }).to_string().into_bytes();
    let (st, _, raw) = post(claim_token(&b, &body, CLAIM_PATH), other).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "{raw:?}");
    assert!(String::from_utf8_lossy(&raw).contains("federation.body_hash_mismatch"));
    let (st, _, _) = a.raw(Method::POST, CLAIM_PATH, "no-token", &[], body.clone()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let foreign = json!({ "user": "carol@b.test", "requester": "xy@b.test" }).to_string().into_bytes();
    let (st, _, raw) = post(claim_token(&b, &foreign, CLAIM_PATH), foreign).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{raw:?}");
    let token = claim_token(&b, &body, CLAIM_PATH);
    assert_eq!(post(token.clone(), body.clone()).await.0, StatusCode::OK);
    assert_eq!(post(token, body.clone()).await.0, StatusCode::UNAUTHORIZED, "replayed token");
}
