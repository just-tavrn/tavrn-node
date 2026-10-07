// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Identity key rotation with continuity (ENCRYPTION.md §9a) and the device tombstones that
//! restrict re-attestation of retired devices (ENCRYPTION.md §2.3).
use crate::common;

use axum::http::{Method, StatusCode};
use chrono::{Duration, SecondsFormat, Utc};
use common::{
    crossnode::{no_event, ws},
    e2ee::{DOMAIN, Dev, b64, unb64},
    federation::two_nodes,
    test_node,
};
use serde_json::{Value, json};
use tavrn_crypto::{
    ContinuityStatement, Device, IdentityKey, MasterSecret, continuity_reaches, sign_continuity, unwrap_identity_key,
    util, verify_device_attestation, wrap_identity_key,
};

const ROTATE: &str = "/api/v1/users/me/identity/rotate";

fn address(dev: &Dev) -> String {
    format!("{}@{DOMAIN}", dev.session.username)
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Request body of a rotation `old → new` attesting `devices` (device id, device key) with `new`.
fn body(
    address: &str,
    master: &MasterSecret,
    old: &IdentityKey,
    new: &IdentityKey,
    devices: &[(String, [u8; 32])],
    at: &str,
) -> Value {
    let statement = sign_continuity(old, new, at).unwrap();
    let attestations: Vec<Value> = devices
        .iter()
        .map(|(id, key)| {
            json!({ "device_id": id, "identity_signature": b64(&new.attest_device(address, id, key).unwrap().signature) })
        })
        .collect();
    json!({
        "new_identity_public_key": b64(&new.public_key()),
        "continuity": statement,
        "identity_blob": b64(&wrap_identity_key(master, new, address).unwrap()),
        "attestations": attestations,
    })
}

fn device_of(dev: &Dev) -> (String, [u8; 32]) {
    (dev.session.device_id.clone(), dev.client.device().public_key())
}

async fn keys(node: &common::TestNode, user: &str) -> Value {
    let (s, j) = node.req(Method::GET, &format!("/api/v1/users/{user}/keys"), None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    j
}

/// Lets the last rotation of `user_id` look older than the one-hour limit.
async fn age_rotation(node: &common::TestNode, user_id: &str) {
    sqlx::query("UPDATE identity_continuity SET created_at = $1 WHERE user_id = $2")
        .bind(tavrn_node::util::format_time(Utc::now() - Duration::hours(2)))
        .bind(user_id)
        .execute(&node.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn rotation_replaces_the_key_and_keeps_devices_working() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let laptop = node.second_device(&alice).await;
    let bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let me = address(&alice);
    let k0 = IdentityKey::from_master(&alice.master);
    let k1 = IdentityKey::generate().unwrap();
    let before = keys(&node, "alice").await;
    assert_eq!((before["identity_generation"].as_i64(), before["continuity"].clone()), (Some(0), json!([])));
    let (s, j) = node.get_auth("/api/v1/users/me/identity/blob", alice.token()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("e2ee.identity_blob_not_found")), "{j}");

    let mut rx = node.state.hub.subscribe();
    let (s, j) = node
        .post(
            ROTATE,
            alice.token(),
            body(&me, &alice.master, &k0, &k1, &[device_of(&alice), device_of(&laptop)], &now()),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(
        (j["identity_generation"].as_i64(), j["identity_public_key"].as_str()),
        (Some(1), Some(b64(&k1.public_key()).as_str()))
    );
    let mut rotated = None;
    while let Ok(ev) = rx.try_recv() {
        assert_ne!(ev.kind, "mls.remove_needed", "devices keep their leaves");
        assert_ne!(ev.kind, "identity.changed", "a rotation is not a reset");
        if ev.kind == "identity.rotated" {
            let tavrn_node::hub::Scope::Users(u) = &ev.scope else { unreachable!() };
            assert!(u.contains(&bob.session.user_id) && u.contains(&alice.session.user_id), "{u:?}");
            rotated = Some(ev.data.clone());
        }
    }
    assert_eq!(rotated.unwrap()["identity_generation"], 1);

    // The keys document: new key, generation, chain, every device attested under the new key.
    let doc = keys(&node, "alice").await;
    assert_eq!(unb64(&doc["identity_public_key"]), k1.public_key().to_vec());
    assert_eq!(doc["identity_generation"], 1);
    assert!(doc["identity_reset_at"].is_null(), "not a reset");
    let chain: Vec<ContinuityStatement> = serde_json::from_value(doc["continuity"].clone()).unwrap();
    assert!(continuity_reaches(&chain, &b64(&k0.public_key()), &b64(&k1.public_key())));
    let devices = doc["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2, "{doc}");
    for d in devices {
        let att = tavrn_crypto::DeviceAttestation {
            user_address: me.clone(),
            device_id: d["device_id"].as_str().unwrap().into(),
            device_public_key: unb64(&d["device_public_key"]).try_into().unwrap(),
            identity_public_key: k1.public_key(),
            signature: unb64(&d["identity_signature"]).try_into().unwrap(),
        };
        verify_device_attestation(&att, &k1.public_key()).unwrap();
    }
    // Every device holding the master secret gets the new key back; the node holds only the wrapped form.
    let (s, j) = node.get_auth("/api/v1/users/me/identity/blob", laptop.token()).await;
    assert_eq!((s, j["identity_generation"].as_i64()), (StatusCode::OK, Some(1)), "{j}");
    let unwrapped = unwrap_identity_key(&laptop.master, &unb64(&j["identity_blob"]), &me).unwrap();
    assert_eq!(unwrapped.public_key(), k1.public_key());

    // The devices keep working: KeyPackages are accepted (attested under the current key).
    let (s, j) = node.upload_kps(&laptop, 2).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    // A new device is attested with the new key; the derived key no longer counts.
    let phone = node.login("alice").await;
    let device = Device::generate(&me, &phone.device_id).unwrap();
    let path = format!("/api/v1/users/me/devices/{}/key", phone.device_id);
    let old_att = device.attest(&alice.master).unwrap();
    let (s, j) = node
        .put(&path, &phone.token, json!({ "device_public_key": b64(&old_att.device_public_key), "identity_signature": b64(&old_att.signature) }))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::BAD_REQUEST, Some("e2ee.attestation_invalid")), "{j}");
    let new_att = k1.attest_device(&me, &phone.device_id, &device.public_key()).unwrap();
    let (s, j) = node
        .put(&path, &phone.token, json!({ "device_public_key": b64(&new_att.device_public_key), "identity_signature": b64(&new_att.signature) }))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // Retired devices keep the attestation of the key they were attested under.
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", phone.device_id), alice.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let doc = keys(&node, "alice").await;
    assert_eq!(doc["retired"][0]["attested_identity_key"], b64(&k1.public_key()).as_str());

    // One rotation per hour; after that the chain grows in order (now three devices to attest... two after the delete).
    let k2 = IdentityKey::generate().unwrap();
    let next = body(&me, &alice.master, &k1, &k2, &[device_of(&alice), device_of(&laptop)], &now());
    let (s, j) = node.post(ROTATE, alice.token(), next.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")), "{j}");
    age_rotation(&node, &alice.session.user_id).await;
    let (s, j) = node.post(ROTATE, alice.token(), next).await;
    assert_eq!((s, j["identity_generation"].as_i64()), (StatusCode::OK, Some(2)), "{j}");
    let doc = keys(&node, "alice").await;
    let chain: Vec<ContinuityStatement> = serde_json::from_value(doc["continuity"].clone()).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(
        (chain[0].new_key.clone(), chain[1].old_key.clone()),
        (b64(&k1.public_key()), b64(&k1.public_key())),
        "oldest first"
    );
    assert!(continuity_reaches(&chain, &b64(&k0.public_key()), &b64(&k2.public_key())));
    assert_eq!(doc["retired"][0]["attested_identity_key"], b64(&k1.public_key()).as_str(), "unchanged");

    // An identity reset starts over at generation 0: no chain, no blob.
    let fresh = MasterSecret::generate().unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&fresh.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let doc = keys(&node, "alice").await;
    assert_eq!((doc["identity_generation"].as_i64(), doc["continuity"].clone()), (Some(0), json!([])));
    let (s, _) = node.get_auth("/api/v1/users/me/identity/blob", alice.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rotation_requests_are_checked() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let laptop = node.second_device(&alice).await;
    let me = address(&alice);
    let k0 = IdentityKey::from_master(&alice.master);
    let k1 = IdentityKey::generate().unwrap();
    let both = [device_of(&alice), device_of(&laptop)];
    let good = || body(&me, &alice.master, &k0, &k1, &both, &now());
    let post = |b: Value| async { node.post(ROTATE, alice.token(), b).await };
    let code = |r: (StatusCode, Value)| (r.0, r.1["code"].as_str().unwrap_or("").to_string());
    let bad = |c: &str| (StatusCode::BAD_REQUEST, c.to_string());

    // Signatures: by another old key, by another new key, swapped.
    let mallory = IdentityKey::generate().unwrap();
    let mut b = good();
    b["continuity"]["sig_old"] =
        json!(sign_continuity(&mallory, &k1, b["continuity"]["at"].as_str().unwrap()).unwrap().sig_old);
    assert_eq!(code(post(b).await), bad("e2ee.continuity_invalid"));
    let mut b = good();
    b["continuity"]["sig_new"] = b["continuity"]["sig_old"].clone();
    assert_eq!(code(post(b).await), bad("e2ee.continuity_invalid"));
    // A statement from a key that is not the current one (a thief of some other key).
    assert_eq!(
        code(post(body(&me, &alice.master, &mallory, &k1, &both, &now())).await),
        bad("e2ee.continuity_invalid")
    );
    // The statement names another new key than the request.
    let mut b = good();
    b["new_identity_public_key"] = json!(b64(&mallory.public_key()));
    assert_eq!(code(post(b).await), bad("e2ee.continuity_invalid"));
    // Stale and future times.
    let at = |d: Duration| (Utc::now() + d).to_rfc3339_opts(SecondsFormat::Secs, true);
    for t in [at(Duration::minutes(-10)), at(Duration::minutes(10)), "yesterday".into()] {
        assert_eq!(
            code(post(body(&me, &alice.master, &k0, &k1, &both, &t)).await),
            bad("e2ee.continuity_stale"),
            "{t}"
        );
    }
    // Attestations: one device missing, one signed by the old key, an unknown device.
    assert_eq!(
        code(post(body(&me, &alice.master, &k0, &k1, &both[..1], &now())).await),
        bad("e2ee.rotation_incomplete")
    );
    let mut b = good();
    b["attestations"][1]["identity_signature"] = json!(b64(&k0
        .attest_device(&me, &laptop.session.device_id, &laptop.client.device().public_key())
        .unwrap()
        .signature));
    assert_eq!(code(post(b).await), bad("e2ee.rotation_incomplete"));
    let mut b = good();
    let stranger = util::b64url_encode(&[1u8; 32]);
    b["attestations"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "device_id": "01J9ZK3G5M8Q2W4E6R8T0Y2V4X", "identity_signature": stranger }));
    assert_eq!(code(post(b).await), bad("e2ee.rotation_incomplete"));
    // Blobs: wrong length, wrong version, not base64url, oversized.
    for blob in [b64(&[1u8; 60]), b64(&[[2u8].as_slice(), &[0u8; 60]].concat()), "!!".into(), "A".repeat(10_000)] {
        let mut b = good();
        b["identity_blob"] = json!(blob);
        let (s, j) = post(b).await;
        assert!(s == StatusCode::BAD_REQUEST || s == StatusCode::PAYLOAD_TOO_LARGE, "{s} {j}");
    }
    let mut b = good();
    b["new_identity_public_key"] = json!("broken");
    assert_eq!(code(post(b).await), bad("e2ee.key_invalid"));
    assert_eq!(keys(&node, "alice").await["identity_generation"], 0, "nothing changed so far");

    // Re-authentication is required (PROTOCOL.md §5c).
    node.forget_reauth(alice.token());
    let (s, j) = post(good()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("auth.reauth_required")), "{j}");
    let (s, j) =
        node.post("/api/v1/auth/reauth", alice.token(), json!({ "password": common::password("alice") })).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let (s, _, j) = node
        .raw(
            Method::POST,
            ROTATE,
            alice.token(),
            &[("tavrn-reauth", j["reauth_token"].as_str().unwrap()), ("content-type", "application/json")],
            good().to_string().into_bytes(),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&j));

    // Unauthenticated, and accounts without an identity key.
    let (s, _) = node.req(Method::POST, ROTATE, None, Some(good())).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = node.req(Method::GET, "/api/v1/users/me/identity/blob", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let carol = node.register("carol").await;
    let (s, j) = node.post(ROTATE, &carol.token, good()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::CONFLICT, Some("e2ee.identity_missing")), "{j}");
}

#[tokio::test]
async fn bots_cannot_rotate() {
    let node = test_node(DOMAIN).await;
    let owner = node.register("owner").await;
    let (s, app) = node.post("/api/v1/applications", &owner.token, json!({ "name": "helper" })).await;
    assert_eq!(s, StatusCode::CREATED, "{app}");
    let (s, token) = node
        .post(
            &format!("/api/v1/applications/{}/tokens", app["id"].as_str().unwrap()),
            &owner.token,
            json!({ "name": "main", "scopes": ["messages:read", "messages:write"] }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{token}");
    let secret = token["secret"].as_str().unwrap();
    let (s, j) = node.post(ROTATE, secret, json!({})).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    let (s, j) = node.get_auth("/api/v1/users/me/identity/blob", secret).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
}

/// `system.key_changed` entries of a welcome channel, newest first.
async fn key_log(node: &common::TestNode, token: &str, channel: &str) -> Vec<Value> {
    let (_, msgs) = node.get_auth(&format!("/api/v1/conversations/{channel}/messages"), token).await;
    msgs.as_array()
        .unwrap()
        .iter()
        .filter(|m| m["content"]["type"] == "system.key_changed")
        .map(|m| m["content"].clone())
        .collect()
}

#[tokio::test]
async fn other_nodes_log_and_follow_the_rotation() {
    let (a, b) = two_nodes().await;
    let carol = b.register("carol").await;
    let alice = a.crypto_user("alice", 2).await;
    let room = b.plaintext_room(&carol.token, "Meeting point").await;
    let room_id = room["id"].as_str().unwrap().to_string();
    b.patch(&format!("/api/v1/rooms/{room_id}"), &carol.token, json!({ "join_mode": "public" })).await;
    let wid = room["channels"].as_array().unwrap().iter().find(|c| c["kind"] == "system").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let remote = b.sign_in_from(&a, &alice.session).await;
    let (s, j) = b.post(&format!("/api/v1/rooms/{room_id}/join"), &remote.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    // B caches alice's keys.
    let (_, cached) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(unb64(&cached["identity_public_key"]), alice.master.identity_public_key().to_vec());
    let mut carol_ws = ws(&b, &carol.token).await;

    // The rotation is a home-node route: a federated session on B cannot use it.
    let me = alice.address.clone();
    let k0 = IdentityKey::from_master(&alice.master);
    let k1 = IdentityKey::generate().unwrap();
    let dev = (alice.session.device_id.clone(), alice.client.device().public_key());
    let req = body(&me, &alice.master, &k0, &k1, std::slice::from_ref(&dev), &now());
    let (s, j) = b.post(ROTATE, &remote.token, req.clone()).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::FORBIDDEN, Some("federation.local_only")), "{j}");
    let (s, j) = a.post(ROTATE, alice.token(), req).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    a.deliver().await;

    // B refetched the keys document, found the chain and wrote "rotated" into the room's security log.
    let (_, cached) = b.req(Method::GET, "/api/v1/users/alice@a.test/keys", None, None).await;
    assert_eq!(unb64(&cached["identity_public_key"]), k1.public_key().to_vec(), "{cached}");
    assert_eq!(cached["devices"].as_array().unwrap().len(), 1, "still attested: {cached}");
    let entries = key_log(&b, &carol.token, &wid).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!((entries[0]["user"].as_str(), entries[0]["rotated"].as_bool()), (Some("alice@a.test"), Some(true)));
    assert!(no_event(&mut carol_ws, "mls.remove_needed", 200).await, "the devices stay");

    // A reset instead: a plain change on B as well.
    let fresh = MasterSecret::generate().unwrap();
    let (s, j) = a
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": b64(&fresh.identity_public_key()), "password": common::password("alice") }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    a.deliver().await;
    let entries = key_log(&b, &carol.token, &wid).await;
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["rotated"], false, "newest first");
}

#[tokio::test]
async fn re_attestation_needs_a_tombstone() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let laptop = node.second_device(&alice).await;
    let me = address(&alice);
    let retire = |id: &str, key: [u8; 32]| {
        let att = tavrn_crypto::attest_device(&alice.master, &me, id, &key).unwrap();
        json!({ "device_id": id, "public_key": b64(&key), "identity_signature": b64(&att.signature) })
    };
    // A planted leaf with an id this node never had: refused.
    let planted = Device::generate(&me, &tavrn_node::util::ulid()).unwrap();
    let (s, j) = node
        .post("/api/v1/users/me/devices/retired", alice.token(), retire(planted.device_id(), planted.public_key()))
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("device.unknown")), "{j}");

    // A device this node deleted: its tombstone allows the re-attestation (after its retired key got lost).
    let laptop_id = laptop.session.device_id.clone();
    let laptop_key = laptop.client.device().public_key();
    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{laptop_id}"), alice.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    tavrn_node::store::users::forget_retired_device(&node.state.db, &laptop_id).await.unwrap();
    let (s, j) = node.post("/api/v1/users/me/devices/retired", alice.token(), retire(&laptop_id, laptop_key)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");

    // Another user cannot use alice's tombstone.
    let bob = node.crypto_user("bob").await;
    let bob_att = tavrn_crypto::attest_device(&bob.master, "bob@t.local", &laptop_id, &laptop_key).unwrap();
    let (s, j) = node
        .post(
            "/api/v1/users/me/devices/retired",
            bob.token(),
            json!({ "device_id": laptop_id, "public_key": b64(&laptop_key), "identity_signature": b64(&bob_att.signature) }),
        )
        .await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("device.unknown")), "{j}");

    // Tombstones expire with TAVRN_DEVICE_STALE_DAYS.
    tavrn_node::store::users::forget_retired_device(&node.state.db, &laptop_id).await.unwrap();
    let days = i64::from(node.state.config.device_stale_days);
    let pruned =
        tavrn_node::device_cleanup::prune_tombstones(&node.state, Utc::now() + Duration::days(days + 1)).await.unwrap();
    assert_eq!(pruned, 1);
    let (s, j) = node.post("/api/v1/users/me/devices/retired", alice.token(), retire(&laptop_id, laptop_key)).await;
    assert_eq!((s, j["code"].as_str()), (StatusCode::NOT_FOUND, Some("device.unknown")), "{j}");
}
