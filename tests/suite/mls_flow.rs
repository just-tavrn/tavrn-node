// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! MLS delivery service of the node (ENCRYPTION.md §4.4, §4.5) and encrypted messages (§5.3).
use crate::common;

use axum::http::StatusCode;
use common::e2ee::{DOMAIN, Dev, b64, qualified, unb64};
use common::{TestNode, test_node};
use serde_json::{Value, json};
use tavrn_crypto::{Client, Device};
use tavrn_node::hub::Scope;

/// Alice and Bob (friends, one attested device each) with a DM whose group Alice created.
async fn dm_setup() -> (TestNode, Dev, Dev, String) {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    (node, alice, bob, dm)
}

fn events(
    rx: &mut tokio::sync::broadcast::Receiver<std::sync::Arc<tavrn_node::hub::Event>>,
) -> Vec<(String, Scope, Value)> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push((ev.kind.clone(), ev.scope.clone(), ev.data.clone()));
    }
    out
}

#[tokio::test]
async fn dm_group_lifecycle() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let carol = node.crypto_user("carol").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    let base = format!("/api/v1/conversations/{dm}/mls");

    let (s, j) = node.get_auth(&format!("{base}/group-info"), alice.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "mls.no_group");

    // A GroupInfo with someone else's device or for another conversation is refused.
    let mut fake = Client::new(Device::generate("alice@t.local", &bob.session.device_id).unwrap());
    let gi = fake.create_group(&qualified(&dm)).unwrap();
    let (s, j) = node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");
    let mut other = Client::new(
        Device::from_secret("alice@t.local", &alice.session.device_id, &alice.client.device().secret()).unwrap(),
    );
    let gi = other.create_group(&qualified("01J9ZK3G5M8Q2W4E6R8T0Y2V00")).unwrap();
    let (s, j) = node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "mls.invalid");
    let (s, j) = node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": "not base64!" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    let mut rx = node.state.hub.subscribe();
    node.create_group(&mut alice, &dm).await;
    let (s, j) = node.post(&format!("{base}/group"), bob.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "mls.group_exists");

    // Members read the GroupInfo; non-members do not even see the conversation.
    let (s, j) = node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["epoch"], 0);
    for path in [format!("{base}/group-info"), format!("{base}/messages?since_epoch=0")] {
        let (s, j) = node.get_auth(&path, carol.token()).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
        assert_eq!(j["code"], "conversation.not_found");
    }

    // Alice adds Bob; Bob's device (only that one) gets the Welcome.
    node.add_user(&mut alice, &dm, "bob").await;
    let evs = events(&mut rx);
    let commit = evs.iter().find(|e| e.0 == "mls.commit" && e.2["epoch"] == 1).expect("mls.commit");
    assert_eq!(commit.2["conversation_id"], dm.as_str());
    assert!(
        matches!(&commit.1, Scope::Users(u) if u.contains(&bob.session.user_id) && u.contains(&alice.session.user_id))
    );
    let welcome = evs.iter().find(|e| e.0 == "mls.welcome").expect("mls.welcome");
    assert!(matches!(&welcome.1, Scope::Devices(d) if d == &vec![bob.session.device_id.clone()]), "{:?}", welcome.1);
    assert_eq!(welcome.2["conversation_id"], dm.as_str());

    let (_, j) = node.get_auth("/api/v1/mls/welcomes", alice.token()).await;
    assert_eq!(j["items"], json!([]));
    let (_, j) = node.get_auth("/api/v1/mls/welcomes", bob.token()).await;
    let welcome_id = j["items"][0]["id"].as_str().unwrap().to_string();
    let (s, _) = node.delete(&format!("/api/v1/mls/welcomes/{welcome_id}"), alice.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "other users' Welcomes are invisible");
    assert_eq!(node.accept_welcomes(&mut bob).await, 1);
    let (s, j) = node.delete(&format!("/api/v1/mls/welcomes/{welcome_id}"), bob.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "mls.welcome_not_found");
    assert_eq!(bob.client.current_epoch(&qualified(&dm)).unwrap(), 1);

    // Encrypted messages round-trip; the node stores device and epoch in the envelope.
    let (s, m) = node.send_encrypted(&alice, &dm, "Hello Bob").await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["encrypted"], true);
    assert_eq!(m["epoch"], 1);
    assert_eq!(m["device_id"], alice.session.device_id.as_str());
    let (_, list) = node.get_auth(&format!("/api/v1/conversations/{dm}/messages"), bob.token()).await;
    let got = &list[0];
    let plain = bob
        .client
        .decrypt_content(
            &qualified(&dm),
            got["author"].as_str().unwrap(),
            got["device_id"].as_str().unwrap(),
            got["content"].as_str().unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&plain).unwrap()["body"], "Hello Bob");

    // Bob rotates; Alice catches up from the log.
    let up = bob.client.self_update(&qualified(&dm)).unwrap();
    let (s, j) = node.post_commit(bob.token(), &dm, &up).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["epoch"], 2);
    bob.client.merge_pending_commit(&qualified(&dm)).unwrap();
    node.catch_up(&mut alice, &dm).await;
    assert_eq!(alice.client.current_epoch(&qualified(&dm)).unwrap(), 2);
    let (_, gi) = node.get_auth(&format!("{base}/group-info"), alice.token()).await;
    assert_eq!(gi["epoch"], 2);
    assert_eq!(unb64(&gi["group_info"]), up.group_info);

    // Log pagination.
    let (_, log) = node.get_auth(&format!("{base}/messages?since_epoch=0&limit=1"), bob.token()).await;
    assert_eq!(log["items"].as_array().unwrap().len(), 1);
    assert_eq!(log["items"][0]["epoch"], 0);
    assert_eq!(log["next"], 1);
    let (_, log) = node.get_auth(&format!("{base}/messages?since_epoch=1"), bob.token()).await;
    assert_eq!(log["items"].as_array().unwrap().len(), 1);
    assert_eq!(log["items"][0]["epoch"], 1);
    assert!(log["next"].is_null());
    assert_eq!(unb64(&log["items"][0]["commit"]), up.commit);
}

#[tokio::test]
async fn first_commit_wins_and_replays_are_refused() {
    let (node, mut alice, mut bob, dm) = dm_setup().await;
    node.add_user(&mut alice, &dm, "bob").await;
    node.accept_welcomes(&mut bob).await;
    let conv = qualified(&dm);

    let a = alice.client.self_update(&conv).unwrap();
    let b = bob.client.self_update(&conv).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &a).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let (s, j) = node.post_commit(bob.token(), &dm, &b).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "mls.epoch_conflict");
    assert_eq!(j["meta"]["epoch"], 2, "current epoch in the body");
    // Replay of the accepted commit.
    let (s, j) = node.post_commit(alice.token(), &dm, &a).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    // Stale commit announced as the current epoch.
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{dm}/mls/commits"),
            bob.token(),
            json!({ "epoch": 2, "commit": b64(&b.commit), "group_info": b64(&b.group_info), "welcome": null }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    alice.client.merge_pending_commit(&conv).unwrap();
    bob.client.discard_pending_commit(&conv).unwrap();
    node.catch_up(&mut bob, &dm).await;

    // Mismatching or tampered GroupInfo, garbage commits.
    let c = alice.client.self_update(&conv).unwrap();
    let mut bad_gi = c.group_info.clone();
    let n = bad_gi.len();
    bad_gi[n - 5] ^= 1;
    for (commit, gi) in
        [(c.commit.clone(), a.group_info.clone()), (c.commit.clone(), bad_gi), (vec![0u8; 10], c.group_info.clone())]
    {
        let (s, j) = node
            .post(
                &format!("/api/v1/conversations/{dm}/mls/commits"),
                alice.token(),
                json!({ "epoch": 2, "commit": b64(&commit), "group_info": b64(&gi), "welcome": null }),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
        assert_eq!(j["code"], "mls.invalid");
    }
    // Oversized fields.
    let (s, j) = node
        .post(
            &format!("/api/v1/conversations/{dm}/mls/commits"),
            alice.token(),
            json!({ "epoch": 2, "commit": b64(&vec![0u8; 1024 * 1024 + 1]), "group_info": b64(&c.group_info), "welcome": null }),
        )
        .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");
    assert_eq!(j["code"], "mls.too_large");
    let (s, j) = node.post_commit(alice.token(), &dm, &c).await;
    assert_eq!(s, StatusCode::CREATED, "the unchanged commit still fits: {j}");

    // Rate limit for commits per device.
    alice.client.merge_pending_commit(&conv).unwrap();
    for _ in 0..10_000 {
        if node.state.commit_limiter.check(&format!("commit:{}", alice.session.device_id)).is_err() {
            break;
        }
    }
    let d = alice.client.self_update(&conv).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &d).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
}

#[tokio::test]
async fn commit_authorization_rules() {
    let (node, mut alice, mut bob, dm) = dm_setup().await;
    let carol = node.crypto_user("carol").await;
    node.befriend(&alice.session, &carol.session).await;
    let conv = qualified(&dm);

    // Adding an attested device of a user who is not a member of the DM.
    let kps = node.claim(alice.token(), "carol").await;
    let out = alice.client.add_members(&conv, &kps).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &out).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");
    alice.client.discard_pending_commit(&conv).unwrap();

    // Adding a device of a member that is not attested (KeyPackage crafted by Alice).
    let bob_phone = node.login("bob").await;
    let ghost = Client::new(Device::generate("bob@t.local", &bob_phone.device_id).unwrap());
    let out = alice.client.add_members(&conv, &[ghost.create_key_package().unwrap()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &out).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");
    alice.client.discard_pending_commit(&conv).unwrap();

    // Missing Welcome for an add.
    node.upload_kps(&bob, 1).await;
    let kps = node.claim(alice.token(), "bob").await;
    let mut out = alice.client.add_members(&conv, &kps).unwrap();
    out.welcome = None;
    let (s, j) = node.post_commit(alice.token(), &dm, &out).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "mls.welcome_missing");
    alice.client.discard_pending_commit(&conv).unwrap();
    node.add_user(&mut alice, &dm, "bob").await;
    node.accept_welcomes(&mut bob).await;

    // Bob posts Alice's commit: the committer must be the session's device.
    let up = alice.client.self_update(&conv).unwrap();
    let (s, j) = node.post_commit(bob.token(), &dm, &up).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");
    alice.client.discard_pending_commit(&conv).unwrap();

    // Removing an entitled member's attested device is refused.
    let rm = alice.client.remove_members(&conv, &[bob.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &rm).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");
    alice.client.discard_pending_commit(&conv).unwrap();

    // External join: an unattested device of a member is refused, a device whose key differs from
    // the attested one as well; an attested new device of a member may join.
    let (_, gi) = node.get_auth(&format!("/api/v1/conversations/{dm}/mls/group-info"), alice.token()).await;
    let gi = unb64(&gi["group_info"]);
    let alice_phone = node.login("alice").await;
    let mut unattested = Client::new(Device::generate("alice@t.local", &alice_phone.device_id).unwrap());
    let join = unattested.join_by_external_commit(&conv, &gi).unwrap();
    let (s, j) = node.post_commit(&alice_phone.token, &dm, &join).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");
    let mut impostor = Client::new(Device::generate("alice@t.local", &alice.session.device_id).unwrap());
    let join = impostor.join_by_external_commit(&conv, &gi).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &join).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "mls.forbidden");

    let master = tavrn_crypto::MasterSecret::from_bytes(*alice.master.to_bytes());
    let mut phone = node.attest(alice_phone, master, 1).await;
    let join = phone.client.join_by_external_commit(&conv, &gi).unwrap();
    let (s, j) = node.post_commit(phone.token(), &dm, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    phone.client.merge_pending_commit(&conv).unwrap();
    node.catch_up(&mut alice, &dm).await;
    node.catch_up(&mut bob, &dm).await;

    // A non-member cannot even reach the delivery service.
    let mut c = Client::new(
        Device::from_secret("carol@t.local", &carol.session.device_id, &carol.client.device().secret()).unwrap(),
    );
    let join = c.join_by_external_commit(&conv, &gi).unwrap();
    let (s, j) = node.post_commit(carol.token(), &dm, &join).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");

    // Removing own other device is always allowed.
    let rm = alice.client.remove_members(&conv, &[phone.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    alice.client.merge_pending_commit(&conv).unwrap();

    // Removing a deleted device of another user is allowed (housekeeping).
    let mut bob2 = node.second_device(&bob).await;
    let (_, gi) = node.get_auth(&format!("/api/v1/conversations/{dm}/mls/group-info"), bob.token()).await;
    let join = bob2.client.join_by_external_commit(&conv, &unb64(&gi["group_info"])).unwrap();
    let (s, j) = node.post_commit(bob2.token(), &dm, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    node.catch_up(&mut alice, &dm).await;
    let mut rx = node.state.hub.subscribe();
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", bob2.session.device_id), bob.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let evs = events(&mut rx);
    let needed = evs.iter().find(|e| e.0 == "mls.remove_needed").expect("mls.remove_needed");
    assert_eq!(needed.2["conversation_id"], dm.as_str());
    assert_eq!(needed.2["identities"], json!([bob2.identity()]));
    let rm = alice.client.remove_members(&conv, &[bob2.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn channel_groups_follow_room_membership_and_permissions() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let mut bob = node.crypto_user("bob").await;
    let carol = node.crypto_user("carol").await;
    let room = node.plaintext_room(alice.token(), "Room").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    let base = format!("/api/v1/conversations/{channel}/mls");

    // Unencrypted channels have no group.
    let gi = alice.client.create_group(&qualified(&channel)).unwrap();
    let (s, j) = node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "mls.not_encrypted");
    let (s, j) = node
        .patch(&format!("/api/v1/rooms/{room_id}/channels/{channel}"), alice.token(), json!({ "encrypted": true }))
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.post(&format!("{base}/group"), alice.token(), json!({ "group_info": b64(&gi) })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Bob joins the room and the group by external commit.
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), alice.token(), json!({})).await;
    let code = invite["code"].as_str().unwrap();
    node.post(&format!("/api/v1/invites/{code}/join"), bob.token(), json!({})).await;
    let (s, j) = node.get_auth(&format!("{base}/group-info"), carol.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "room.not_member");
    let (s, j) = node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let join = bob.client.join_by_external_commit(&qualified(&channel), &unb64(&j["group_info"])).unwrap();
    let (s, j) = node.post_commit(bob.token(), &channel, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    bob.client.merge_pending_commit(&qualified(&channel)).unwrap();
    node.catch_up(&mut alice, &channel).await;

    // Messages through both the room route and the conversation route.
    let (s, j) = node.send_encrypted(&bob, &channel, "through the conversation").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let content =
        bob.client.encrypt_content(&qualified(&channel), r#"{"type":"text","body":"through the room"}"#).unwrap();
    let (s, j) = node
        .post(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}/messages"),
            bob.token(),
            json!({ "content": content, "epoch": 1 }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Bob loses the read permission: he can no longer read the group or post commits.
    let (s, j) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            alice.token(),
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member", "subject_id": bob.session.user_id, "allow": "0", "deny": common::perms(&[tavrn_node::permissions::VIEW_CHANNEL]) }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, j) = node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    // ... and Alice may remove his leaf because he is no longer entitled.
    let rm = alice.client.remove_members(&qualified(&channel), &[bob.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &channel, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    alice.client.merge_pending_commit(&qualified(&channel)).unwrap();

    // Kick: the node asks the remaining members to remove the leaves.
    let (s, _) = node
        .put(
            &format!("/api/v1/rooms/{room_id}/overrides"),
            alice.token(),
            json!({ "target_type": "channel", "target_id": channel, "subject_type": "member", "subject_id": bob.session.user_id, "allow": "0", "deny": "0" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (_, j) = node.get_auth(&format!("{base}/group-info"), bob.token()).await;
    let mut bob_again =
        Client::new(Device::from_secret("bob@t.local", &bob.session.device_id, &bob.client.device().secret()).unwrap());
    let join = bob_again.join_by_external_commit(&qualified(&channel), &unb64(&j["group_info"])).unwrap();
    let (s, j) = node.post_commit(bob.token(), &channel, &join).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    node.catch_up(&mut alice, &channel).await;
    let mut rx = node.state.hub.subscribe();
    let (s, _) = node.delete(&format!("/api/v1/rooms/{room_id}/members/{}", bob.session.user_id), alice.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let evs = events(&mut rx);
    let needed = evs.iter().find(|e| e.0 == "mls.remove_needed").expect("mls.remove_needed");
    assert!(matches!(&needed.1, Scope::Room(r) if r == &room_id));
    assert_eq!(needed.2["identities"], json!([bob.identity()]));
    let (s, j) = node.get_auth(&format!("{base}/messages?since_epoch=0"), bob.token()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let rm = alice.client.remove_members(&qualified(&channel), &[bob.identity()]).unwrap();
    let (s, j) = node.post_commit(alice.token(), &channel, &rm).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn encrypted_message_checks() {
    let (node, mut alice, bob, dm) = dm_setup().await;
    let conv = qualified(&dm);
    let path = format!("/api/v1/conversations/{dm}/messages");

    let (s, j) = node.post(&path, alice.token(), json!({ "content": { "type": "text", "body": "plaintext" } })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.encryption_mismatch");
    let (s, j) = node.post(&path, alice.token(), json!({ "content": "Y2lwaGVydGV4dA", "epoch": 0 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.ciphertext_invalid");
    let content = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"hi"}"#).unwrap();
    let (s, j) = node.post(&path, alice.token(), json!({ "content": content })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.epoch_mismatch");
    let (s, j) = node.post(&path, alice.token(), json!({ "content": content, "epoch": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.epoch_mismatch");
    // Unsupported version byte.
    let mut raw = tavrn_crypto::util::b64url_decode(&content).unwrap();
    raw[0] = 2;
    let (s, j) = node.post(&path, alice.token(), json!({ "content": b64(&raw), "epoch": 0 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.ciphertext_invalid");

    // An epoch the node has not seen yet (local commit never posted).
    let mut ahead = Client::import_state(&alice.client.export_state().unwrap()).unwrap();
    ahead.self_update(&conv).unwrap();
    ahead.merge_pending_commit(&conv).unwrap();
    let c = ahead.encrypt_content(&conv, r#"{"type":"text","body":"too early"}"#).unwrap();
    let (s, j) = node.post(&path, alice.token(), json!({ "content": c, "epoch": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.epoch_unknown");

    // Unattested device of a member.
    let phone = node.login("alice").await;
    let (s, j) = node.post(&path, &phone.token, json!({ "content": content, "epoch": 0 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");

    let (s, m) =
        node.post(&path, alice.token(), json!({ "content": content, "epoch": 0, "mentions": ["bob@t.local"] })).await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    assert_eq!(m["mentions"], json!(["bob@t.local"]), "mentions stay plaintext");

    // Edits follow the same rules and record the new epoch.
    node.add_user(&mut alice, &dm, "bob").await;
    let mid = m["id"].as_str().unwrap();
    let (s, j) = node
        .patch(&format!("{path}/{mid}"), alice.token(), json!({ "content": { "type": "text", "body": "x" } }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.encryption_mismatch");
    let edited = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"bearbeitet"}"#).unwrap();
    let (s, j) = node.patch(&format!("{path}/{mid}"), alice.token(), json!({ "content": edited, "epoch": 0 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.epoch_mismatch");
    let (s, j) = node.patch(&format!("{path}/{mid}"), alice.token(), json!({ "content": edited, "epoch": 1 })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["epoch"], 1);
    let (s, j) = node.patch(&format!("{path}/{mid}"), bob.token(), json!({ "content": edited, "epoch": 1 })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "message.not_author");
}

#[tokio::test]
async fn ciphertext_without_group_is_refused() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    // Alice has a local group, the node does not know it.
    alice.client.create_group(&qualified(&dm)).unwrap();
    let (s, j) = node.send_encrypted(&alice, &dm, "hello").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "message.epoch_unknown");
}

/// ENCRYPTION.md §5.3: content only under the current epoch, or the previous one within 60 s of its commit.
#[tokio::test]
async fn stale_epochs_are_refused_after_a_short_grace() {
    let (node, mut alice, _bob, dm) = dm_setup().await;
    let conv = qualified(&dm);
    let path = format!("/api/v1/conversations/{dm}/messages");
    let at0 = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"in flight"}"#).unwrap();
    let late0 = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"late"}"#).unwrap();
    let (s, first) = node.post(&path, alice.token(), json!({ "content": at0, "epoch": 0 })).await;
    assert_eq!(s, StatusCode::CREATED, "{first}");
    node.add_user(&mut alice, &dm, "bob").await;

    // Just after the commit: the previous epoch is still accepted (content on its way while the group moved on).
    let (s, j) = node.post(&path, alice.token(), json!({ "content": at0, "epoch": 0 })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // A minute later it is stale.
    sqlx::query("UPDATE mls_groups SET updated_at = $1 WHERE conversation_id = $2")
        .bind(tavrn_node::util::format_time(chrono::Utc::now() - chrono::Duration::seconds(61)))
        .bind(&dm)
        .execute(&node.state.db)
        .await
        .unwrap();
    let (s, j) = node.post(&path, alice.token(), json!({ "content": late0, "epoch": 0 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("mls.epoch_stale")), "{j}");
    assert_eq!(j["meta"]["epoch"], 1, "{j}");
    let mid = first["id"].as_str().unwrap();
    let (s, j) = node.patch(&format!("{path}/{mid}"), alice.token(), json!({ "content": late0, "epoch": 0 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("mls.epoch_stale")), "{j}");
    // The current epoch is always fine.
    let (s, j) = node.send_encrypted(&alice, &dm, "current").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");

    // Two epochs back is stale at once, whatever the time.
    let at1 = alice.client.encrypt_content(&conv, r#"{"type":"text","body":"two behind"}"#).unwrap();
    for _ in 0..2 {
        let out = alice.client.self_update(&conv).unwrap();
        let (s, j) = node.post_commit(alice.token(), &dm, &out).await;
        assert_eq!(s, StatusCode::CREATED, "{j}");
        alice.client.merge_pending_commit(&conv).unwrap();
    }
    let (s, j) = node.post(&path, alice.token(), json!({ "content": at1, "epoch": 1 })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("mls.epoch_stale")), "{j}");
    assert_eq!(j["meta"]["epoch"], 3, "{j}");
}
