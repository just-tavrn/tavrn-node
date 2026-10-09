// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Device share keys (ENCRYPTION.md §3.1) and history shares v2 (§7b "Format v2"): every device publishes an X25519
//! share key signed by its device key; a v2 share carries one sealed box per recipient device, and every device of
//! the recipient is served only its own box.
use crate::common;

use axum::http::StatusCode;
use common::e2ee::{DOMAIN, Dev, b64, qualified};
use common::{TestNode, test_node};
use serde_json::{Value, json};
use tavrn_crypto::{Device, MasterSecret, share};

/// Publishes the share key of `dev` with the share-key route.
async fn put_share_key(node: &TestNode, dev: &Dev) -> (StatusCode, Value) {
    let d = dev.client.device();
    node.put(
        &format!("/api/v1/users/me/devices/{}/share-key", dev.session.device_id),
        dev.token(),
        json!({ "share_public_key": b64(&d.share_public_key()), "share_key_signature": b64(&d.share_key_signature()) }),
    )
    .await
}

/// The public keys document of `username`.
async fn keys_of(node: &TestNode, username: &str) -> (StatusCode, Value) {
    node.req(axum::http::Method::GET, &format!("/api/v1/users/{username}/keys"), None, None).await
}

/// The entry of `device_id` in a keys document.
fn device_entry<'a>(keys: &'a Value, device_id: &str) -> &'a Value {
    keys["devices"].as_array().unwrap().iter().find(|d| d["device_id"] == device_id).expect("device listed")
}

#[tokio::test]
async fn devices_publish_a_share_key_once_and_it_is_served_with_the_attestation() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let path = format!("/api/v1/users/me/devices/{}/share-key", alice.session.device_id);
    let d = alice.client.device();
    let (pk, sig) = (b64(&d.share_public_key()), b64(&d.share_key_signature()));

    // Not published yet: the keys document carries nulls.
    let (_, keys) = keys_of(&node, "alice").await;
    let entry = device_entry(&keys, &alice.session.device_id);
    assert_eq!((entry["share_public_key"].clone(), entry["share_key_signature"].clone()), (Value::Null, Value::Null));

    // A signature by another key, a malformed key, another session's device: refused.
    let stranger = Device::generate(&format!("alice@{DOMAIN}"), &alice.session.device_id).unwrap();
    let (s, j) = node
        .put(
            &path,
            alice.token(),
            json!({ "share_public_key": pk, "share_key_signature": b64(&stranger.share_key_signature()) }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("e2ee.share_key_invalid")), "{j}");
    let (s, j) =
        node.put(&path, alice.token(), json!({ "share_public_key": "AAAA", "share_key_signature": sig })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    let bob = node.crypto_user("bob").await;
    let (s, j) = node.put(&path, bob.token(), json!({ "share_public_key": pk, "share_key_signature": sig })).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("e2ee.wrong_device")), "{j}");
    // A device without an attested key cannot publish one.
    let carol = node.register("carol").await;
    let (s, j) = node
        .put(
            &format!("/api/v1/users/me/devices/{}/share-key", carol.device_id),
            &carol.token,
            json!({ "share_public_key": pk, "share_key_signature": sig }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("e2ee.device_not_attested")), "{j}");

    // Published once; the same key again is fine, another key is refused.
    let (s, j) = put_share_key(&node, &alice).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    assert_eq!(put_share_key(&node, &alice).await.0, StatusCode::NO_CONTENT);
    let other = Device::generate(&format!("alice@{DOMAIN}"), &alice.session.device_id).unwrap();
    // A valid signature of the same device key over another share key cannot exist without the device key; a
    // different key signed by this device key is what a second publication would look like.
    let other_share = other.share_public_key();
    let other_sig = alice_sign_share(&alice, &other_share);
    let (s, j) = node
        .put(
            &path,
            alice.token(),
            json!({ "share_public_key": b64(&other_share), "share_key_signature": b64(&other_sig) }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("e2ee.share_key_exists")), "{j}");

    // Served with the attestation; it verifies with the device key.
    let (_, keys) = keys_of(&node, "alice").await;
    let entry = device_entry(&keys, &alice.session.device_id);
    assert_eq!(
        (entry["share_public_key"].as_str(), entry["share_key_signature"].as_str()),
        (Some(pk.as_str()), Some(sig.as_str()))
    );
    let unb = |v: &Value| common::e2ee::unb64(v);
    share::verify_share_key(
        &unb(&entry["device_public_key"]).try_into().unwrap(),
        &alice.session.device_id,
        &unb(&entry["share_public_key"]).try_into().unwrap(),
        &unb(&entry["share_key_signature"]),
    )
    .expect("served share key verifies");

    // An identity reset keeps the device key and its share key; the re-attested device is served with it.
    let master = MasterSecret::generate().unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&master.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let att = alice.client.device().attest(&master).unwrap();
    let (s, j) = node
        .put(
            &format!("/api/v1/users/me/devices/{}/key", alice.session.device_id),
            alice.token(),
            json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature),
                    "share_public_key": pk, "share_key_signature": sig }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, keys) = keys_of(&node, "alice").await;
    assert_eq!(device_entry(&keys, &alice.session.device_id)["share_public_key"].as_str(), Some(pk.as_str()));
}

/// A signature of `dev`'s device key over an arbitrary share key (what a buggy client could send).
fn alice_sign_share(dev: &Dev, share_public: &[u8; 32]) -> [u8; 64] {
    use ed25519_dalek::Signer as _;
    let d = dev.client.device();
    let key = ed25519_dalek::SigningKey::from_bytes(&d.secret());
    key.sign(&share::share_key_signing_input(share_public, &d.public_key(), d.device_id())).to_bytes()
}

#[tokio::test]
async fn the_device_key_upload_carries_the_share_key_and_checks_it() {
    let node = test_node(DOMAIN).await;
    let s = node.register("erin").await;
    let master = MasterSecret::generate().unwrap();
    node.put_identity(&s, &master).await;
    let device = Device::generate(&format!("erin@{DOMAIN}"), &s.device_id).unwrap();
    let att = device.attest(&master).unwrap();
    let path = format!("/api/v1/users/me/devices/{}/key", s.device_id);
    let body = |sig: &[u8]| {
        json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature),
                "share_public_key": b64(&device.share_public_key()), "share_key_signature": b64(sig) })
    };
    // A bad share key signature refuses the whole upload: nothing is stored.
    let (st, j) = node.put(&path, &s.token, body(&[0u8; 64])).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("e2ee.share_key_invalid")), "{j}");
    let (_, keys) = keys_of(&node, "erin").await;
    assert_eq!(keys["devices"], json!([]));
    // Only both fields or none.
    let mut half = body(&device.share_key_signature());
    half.as_object_mut().unwrap().remove("share_key_signature");
    let (st, j) = node.put(&path, &s.token, half).await;
    assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("e2ee.share_key_invalid")), "{j}");
    let (st, j) = node.put(&path, &s.token, body(&device.share_key_signature())).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    let (_, keys) = keys_of(&node, "erin").await;
    assert_eq!(device_entry(&keys, &s.device_id)["share_public_key"], b64(&device.share_public_key()));
}

struct Setup {
    node: TestNode,
    alice: Dev,
    bob: Dev,
    phone: Dev,
    channel: String,
}

async fn join(node: &TestNode, owner: &str, room_id: &str, member: &common::Session) {
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), owner, json!({})).await;
    let (s, j) = node
        .post(&format!("/api/v1/invites/{}/join", invite["code"].as_str().unwrap()), &member.token, json!({}))
        .await;
    assert!(s.is_success(), "{j}");
}

async fn external_join(node: &TestNode, dev: &mut Dev, channel: &str) {
    let (s, gi) = node.get_auth(&format!("/api/v1/conversations/{channel}/mls/group-info"), dev.token()).await;
    assert_eq!(s, StatusCode::OK, "{gi}");
    let out = dev.client.join_by_external_commit(&qualified(channel), &common::e2ee::unb64(&gi["group_info"])).unwrap();
    let (s, j) = node.post_commit(dev.token(), channel, &out).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    dev.client.merge_pending_commit(&qualified(channel)).unwrap();
}

/// Alice's room (policy `all`) with an encrypted channel and one old message; Bob joined with two devices (laptop and
/// phone), both with published share keys and in the channel's group.
async fn setup() -> Setup {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let room = node.create_room(alice.token(), "Archive").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    let channel = TestNode::text_channel(&room);
    node.create_group(&mut alice, &channel).await;
    assert_eq!(node.send_encrypted(&alice, &channel, "Before").await.0, StatusCode::CREATED);
    let (s, j) = node
        .patch(
            &format!("/api/v1/rooms/{room_id}/channels/{channel}"),
            alice.token(),
            json!({ "history_for_new_members": "all" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let mut bob = node.crypto_user("bob").await;
    let mut phone = node.second_device(&bob).await;
    join(&node, alice.token(), &room_id, &bob.session).await;
    for dev in [&bob, &phone] {
        assert_eq!(put_share_key(&node, dev).await.0, StatusCode::NO_CONTENT);
    }
    external_join(&node, &mut bob, &channel).await;
    external_join(&node, &mut phone, &channel).await;
    node.catch_up(&mut alice, &channel).await;
    Setup { node, alice, bob, phone, channel }
}

/// A v2 share from Alice to Bob with boxes for `devices` (device id, share public key).
fn v2_body(s: &Setup, devices: &[(&str, [u8; 32])]) -> (Value, [u8; 32]) {
    let payload = json!({ "type": "history_keys", "v": 2, "conversation": qualified(&s.channel),
                          "to": format!("bob@{DOMAIN}"), "epochs": [] })
    .to_string();
    let (ciphertext, key) = s.alice.client.encrypt_share(&qualified(&s.channel), &payload).unwrap();
    let boxes: serde_json::Map<String, Value> = devices
        .iter()
        .map(|(id, pk)| ((*id).to_string(), json!(b64(&share::seal_share_key(pk, &key).unwrap()))))
        .collect();
    let epoch = s.alice.client.current_epoch(&qualified(&s.channel)).unwrap() as i64;
    (
        json!({ "to_user": format!("bob@{DOMAIN}"), "epoch_from": epoch, "epoch_to": epoch, "ciphertext": ciphertext,
                "v": 2, "boxes": boxes }),
        *key,
    )
}

fn share_pk(dev: &Dev) -> [u8; 32] {
    dev.client.device().share_public_key()
}

#[tokio::test]
async fn a_v2_share_serves_each_recipient_device_only_its_own_box() {
    let s = setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", s.channel);
    let (laptop_id, phone_id) = (s.bob.session.device_id.clone(), s.phone.session.device_id.clone());
    let (body, key) = v2_body(&s, &[(&laptop_id, share_pk(&s.bob)), (&phone_id, share_pk(&s.phone))]);
    let (st, j) = s.node.post(&base, s.alice.token(), body).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let share_id = j["id"].as_str().unwrap().to_string();

    for dev in [&s.bob, &s.phone] {
        let (st, j) = s.node.get_auth(&base, dev.token()).await;
        assert_eq!(st, StatusCode::OK, "{j}");
        let item = &j["items"][0];
        assert_eq!((item["id"].as_str(), item["v"].as_i64()), (Some(share_id.as_str()), Some(2)), "{j}");
        // Only its own box: it opens with this device's share key and gives the share's key.
        let opened = dev.client.open_share_box(&common::e2ee::unb64(&item["box"])).expect("own box");
        assert_eq!(*opened, key);
        assert!(item.get("boxes").is_none(), "never the other devices' boxes: {item}");
        let json = share::decrypt_content_with_key(
            &opened,
            &qualified(&s.channel),
            &format!("alice@{DOMAIN}"),
            &s.alice.session.device_id,
            item["ciphertext"].as_str().unwrap(),
            &s.alice.client.device().public_key(),
        )
        .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap()["v"], 2);
    }
    // Acknowledging (per user) drops the share and every box.
    assert_eq!(s.node.delete(&format!("{base}/{share_id}"), s.phone.token()).await.0, StatusCode::NO_CONTENT);
    let (_, j) = s.node.get_auth(&base, s.bob.token()).await;
    assert_eq!(j["items"], json!([]));
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM history_share_boxes WHERE share_id = $1")
        .bind(&share_id)
        .fetch_one(&s.node.state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn a_device_without_a_box_does_not_see_the_v2_share_but_v1_shares_stay() {
    let s = setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", s.channel);
    let laptop_id = s.bob.session.device_id.clone();
    let (body, _) = v2_body(&s, &[(&laptop_id, share_pk(&s.bob))]);
    let (st, j) = s.node.post(&base, s.alice.token(), body).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (_, j) = s.node.get_auth(&base, s.phone.token()).await;
    assert_eq!(j["items"], json!([]), "no box for the phone");
    let (_, j) = s.node.get_auth(&base, s.bob.token()).await;
    assert_eq!(j["items"].as_array().unwrap().len(), 1);

    // v1 shares are unchanged: every device of the recipient sees them, without a box.
    let ciphertext = s
        .alice
        .client
        .encrypt_content(&qualified(&s.channel), &json!({ "type": "history_keys", "v": 1 }).to_string())
        .unwrap();
    let (st, j) = s
        .node
        .post(
            &base,
            s.alice.token(),
            json!({ "to_user": format!("bob@{DOMAIN}"), "epoch_from": 0, "epoch_to": 1, "ciphertext": ciphertext }),
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let (st, j) = s
        .node
        .post(&base, s.alice.token(), json!({ "to_user": format!("bob@{DOMAIN}"), "epoch_from": 0, "epoch_to": 1, "ciphertext": ciphertext, "v": 1 }))
        .await;
    assert_eq!(st, StatusCode::CREATED, "explicit v1: {j}");
    let (_, j) = s.node.get_auth(&base, s.phone.token()).await;
    let items = j["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["v"] == 1 && i["box"].is_null()), "{j}");
}

#[tokio::test]
async fn v2_shares_need_attested_recipient_devices_with_share_keys_and_bounded_boxes() {
    let s = setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", s.channel);
    let laptop = s.bob.session.device_id.clone();
    let invalid = |st: StatusCode, j: &Value| {
        assert_eq!((st, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("history.invalid")), "{j}");
    };

    // A device of the recipient without a share key.
    let tablet = s.node.second_device(&s.bob).await;
    let (body, _) = v2_body(&s, &[(&laptop, share_pk(&s.bob)), (&tablet.session.device_id, share_pk(&tablet))]);
    let (st, j) = s.node.post(&base, s.alice.token(), body).await;
    invalid(st, &j);
    // A device of someone else (Alice's own), an unknown id, a malformed id.
    for id in [s.alice.session.device_id.as_str(), "01J9ZK3G5M8Q2W4E6R8T0Y2VZZ", "not-a-device"] {
        let (body, _) = v2_body(&s, &[(&laptop, share_pk(&s.bob)), (id, share_pk(&s.bob))]);
        let (st, j) = s.node.post(&base, s.alice.token(), body).await;
        invalid(st, &j);
    }
    // No boxes, more than 20, a box over 128 bytes, a box that is not base64url.
    let (mut body, _) = v2_body(&s, &[(&laptop, share_pk(&s.bob))]);
    body["boxes"] = json!({});
    let (st, j) = s.node.post(&base, s.alice.token(), body.clone()).await;
    invalid(st, &j);
    let many: serde_json::Map<String, Value> =
        (0..21).map(|i| (format!("01J9ZK3G5M8Q2W4E6R8T0Y2V{i:02}"), json!(b64(&[1u8; 80])))).collect();
    body["boxes"] = Value::Object(many);
    let (st, j) = s.node.post(&base, s.alice.token(), body.clone()).await;
    invalid(st, &j);
    body["boxes"] = json!({ laptop.clone(): b64(&[1u8; 129]) });
    let (st, j) = s.node.post(&base, s.alice.token(), body.clone()).await;
    invalid(st, &j);
    body["boxes"] = json!({ laptop.clone(): "!!" });
    let (st, j) = s.node.post(&base, s.alice.token(), body.clone()).await;
    invalid(st, &j);
    // Versions: v2 without boxes, v1 with boxes, unknown versions.
    let (good, _) = v2_body(&s, &[(&laptop, share_pk(&s.bob))]);
    let mut b = good.clone();
    b.as_object_mut().unwrap().remove("boxes");
    let (st, j) = s.node.post(&base, s.alice.token(), b).await;
    invalid(st, &j);
    let mut b = good.clone();
    b["v"] = json!(1);
    let (st, j) = s.node.post(&base, s.alice.token(), b).await;
    invalid(st, &j);
    let mut b = good.clone();
    b["v"] = json!(3);
    let (st, j) = s.node.post(&base, s.alice.token(), b).await;
    invalid(st, &j);
    // Nothing was stored by the refused requests; the valid one is accepted.
    let (_, j) = s.node.get_auth(&base, s.bob.token()).await;
    assert_eq!(j["items"], json!([]));
    let (st, j) = s.node.post(&base, s.alice.token(), good).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    // The capability is announced.
    let (_, info) = s.node.get_auth("/api/v1/node", s.alice.token()).await;
    assert!(info["capabilities"].as_array().unwrap().contains(&json!("history.shares2")), "{info}");
}

#[tokio::test]
async fn housekeeping_drops_the_boxes_with_their_shares() {
    let s = setup().await;
    let base = format!("/api/v1/conversations/{}/history-keys", s.channel);
    let laptop = s.bob.session.device_id.clone();
    let (body, _) = v2_body(&s, &[(&laptop, share_pk(&s.bob))]);
    let (st, j) = s.node.post(&base, s.alice.token(), body).await;
    assert_eq!(st, StatusCode::CREATED, "{j}");
    let fmt = tavrn_node::util::format_time;
    let now = chrono::Utc::now();
    let report = tavrn_node::store::history::prune(&s.node.state.db, &fmt(now), &fmt(now + chrono::Duration::hours(1)))
        .await
        .unwrap();
    assert_eq!(report.shares, 1);
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM history_share_boxes").fetch_one(&s.node.state.db).await.unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn a_room_node_serves_the_share_keys_of_remote_devices_from_its_key_cache() {
    let (a, b) = common::federation::two_nodes().await;
    let alice = a.crypto_user("alice", 1).await;
    let d = alice.client.device();
    let (st, j) = a
        .put(
            &format!("/api/v1/users/me/devices/{}/share-key", alice.session.device_id),
            alice.token(),
            json!({ "share_public_key": b64(&d.share_public_key()), "share_key_signature": b64(&d.share_key_signature()) }),
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{j}");
    b.sign_in_from(&a, &alice.session).await;
    let (st, keys) = b.req(axum::http::Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(st, StatusCode::OK, "{keys}");
    let entry = device_entry(&keys, &alice.session.device_id);
    assert_eq!(entry["share_public_key"], b64(&d.share_public_key()));
    assert_eq!(entry["share_key_signature"], b64(&d.share_key_signature()));
    // The room node accepts boxes for that device: it is an attested device of the remote user with a share key.
    let user = tavrn_node::store::federation::user_by_address(&b.state.db, "alice", "a.test").await.unwrap().unwrap();
    let devices = tavrn_node::store::e2ee::share_key_devices(&b.state.db, &user.id).await.unwrap();
    assert_eq!(devices, vec![alice.session.device_id.clone()]);
}
