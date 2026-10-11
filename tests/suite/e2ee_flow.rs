// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Identity keys, device attestations, KeyPackages and identity reset (ENCRYPTION.md §2.3, §3, §9).
use crate::common;

use axum::http::{Method, StatusCode};
use common::e2ee::{DOMAIN, address, b64, unb64};
use common::test_node;
use serde_json::json;
use tavrn_crypto::{Client, Device, MasterSecret, ds::inspect_key_package};

#[tokio::test]
async fn identity_key_is_set_once_and_published() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let master = MasterSecret::generate().unwrap();

    // Public lookup before any key: no key, no devices.
    let (s, j) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["user"], "alice@t.local");
    assert!(j["identity_public_key"].is_null());
    assert_eq!(j["devices"], json!([]));

    // Malformed keys.
    for bad in ["", "not base64!", &b64(&[1u8; 31]), &b64(&[0u8; 32])] {
        let (s, j) = node.put("/api/v1/users/me/identity", &alice.token, json!({ "identity_public_key": bad })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {j}");
        assert_eq!(j["code"], "e2ee.key_invalid");
    }
    let (s, _) = node
        .req(
            Method::PUT,
            "/api/v1/users/me/identity",
            None,
            Some(json!({ "identity_public_key": b64(&master.identity_public_key()) })),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    node.put_identity(&alice, &master).await;
    let (_, me) = node.get_auth("/api/v1/users/me", &alice.token).await;
    assert_eq!(me["has_identity_key"], true);

    // Second upload (even the same key) is refused: only the reset replaces it.
    let other = MasterSecret::generate().unwrap();
    let (s, j) = node
        .put(
            "/api/v1/users/me/identity",
            &alice.token,
            json!({ "identity_public_key": b64(&other.identity_public_key()) }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.identity_exists");

    let (_, j) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(unb64(&j["identity_public_key"]), master.identity_public_key().to_vec());
    let (s, j) = node.req(Method::GET, "/api/v1/users/nobody/keys", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{j}");
    assert_eq!(j["code"], "user.not_found");
}

#[tokio::test]
async fn device_attestation_is_verified_and_immutable() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let second = node.login("alice").await;
    let master = MasterSecret::generate().unwrap();
    let device = Device::generate(&address(&alice), &alice.device_id).unwrap();
    let path = format!("/api/v1/users/me/devices/{}/key", alice.device_id);
    let att = device.attest(&master).unwrap();
    let body = json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) });

    // Without identity key there is nothing to verify against.
    let (s, j) = node.put(&path, &alice.token, body.clone()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.identity_missing");
    node.put_identity(&alice, &master).await;

    // Only the session's own device.
    let (s, j) = node.put(&path, &second.token, body.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.wrong_device");

    // Forged attestation: signed by another identity key.
    let forged = device.attest(&MasterSecret::generate().unwrap()).unwrap();
    let (s, j) = node
        .put(&path, &alice.token, json!({ "device_public_key": b64(&forged.device_public_key), "identity_signature": b64(&forged.signature) }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "e2ee.attestation_invalid");
    // Attestation of another device id (replayed signature).
    let other_dev = Device::generate(&address(&alice), &second.device_id).unwrap();
    let other_att = other_dev.attest(&master).unwrap();
    let (s, j) = node
        .put(&path, &alice.token, json!({ "device_public_key": b64(&other_att.device_public_key), "identity_signature": b64(&other_att.signature) }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "e2ee.attestation_invalid");
    let (s, j) = node.put(&path, &alice.token, json!({ "device_public_key": "x", "identity_signature": "y" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    let (s, j) = node.put(&path, &alice.token, body.clone()).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    // Immutable: neither the same nor a new key can be set again.
    let (s, j) = node.put(&path, &alice.token, body).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.device_key_exists");
    let new = Device::generate(&address(&alice), &alice.device_id).unwrap().attest(&master).unwrap();
    let (s, j) = node
        .put(
            &path,
            &alice.token,
            json!({ "device_public_key": b64(&new.device_public_key), "identity_signature": b64(&new.signature) }),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.device_key_exists");

    // Published and verifiable by others; the unattested second device is not listed.
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    let devices = keys["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1, "{keys}");
    assert_eq!(devices[0]["device_id"], alice.device_id.as_str());
    let published = tavrn_crypto::DeviceAttestation {
        user_address: address(&alice),
        device_id: alice.device_id.clone(),
        device_public_key: unb64(&devices[0]["device_public_key"]).try_into().unwrap(),
        identity_public_key: unb64(&keys["identity_public_key"]).try_into().unwrap(),
        signature: unb64(&devices[0]["identity_signature"]).try_into().unwrap(),
    };
    tavrn_crypto::verify_device_attestation(&published, &master.identity_public_key()).unwrap();
}

#[tokio::test]
async fn key_packages_are_validated_counted_and_claimed_once() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let bob = node.register("bob").await;
    let kp_path = format!("/api/v1/users/me/devices/{}/key-packages", alice.session.device_id);

    let (s, j) = node.get_auth(&kp_path, alice.token()).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    assert_eq!(j["count"], 3);

    // KeyPackage of another device identity / another key.
    let foreign = Client::new(Device::generate("alice@t.local", &bob.device_id).unwrap());
    let stranger = Client::new(Device::generate("alice@t.local", &alice.session.device_id).unwrap());
    for kp in [foreign.create_key_package().unwrap(), stranger.create_key_package().unwrap()] {
        let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": [b64(&kp)] })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
        assert_eq!(j["code"], "e2ee.key_package_mismatch");
    }
    let mut broken = alice.client.create_key_package().unwrap();
    let n = broken.len();
    broken[n - 3] ^= 1;
    let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": [b64(&broken)] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    assert_eq!(j["code"], "e2ee.key_package_invalid");
    let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": [b64(&[0u8; 5000])] })).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{j}");
    assert_eq!(j["code"], "e2ee.key_package_too_large");
    let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": [] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");
    // Uploading for a device that is not the session's own.
    let other = node.login("alice").await;
    let (s, j) = node
        .post(&kp_path, &other.token, json!({ "key_packages": [b64(&alice.client.create_key_package().unwrap())] }))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.wrong_device");
    // Unattested device.
    let unattested = Client::new(Device::generate("alice@t.local", &other.device_id).unwrap());
    let (s, j) = node
        .post(
            &format!("/api/v1/users/me/devices/{}/key-packages", other.device_id),
            &other.token,
            json!({ "key_packages": [b64(&unattested.create_key_package().unwrap())] }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");

    // At most 100 per device.
    let many: Vec<String> = (0..98).map(|_| b64(&alice.client.create_key_package().unwrap())).collect();
    let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": many })).await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.key_package_limit");
    let (s, j) = node.post(&kp_path, alice.token(), json!({ "key_packages": many[..97] })).await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    assert_eq!(j["count"], 100);

    // Claim: one per attested device, single use, removed from the store.
    let (s, j) = node.req(Method::POST, "/api/v1/users/alice/key-packages/claim", None, Some(json!({}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    let (s, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{j}");
    let items = j["key_packages"].as_array().unwrap();
    assert_eq!(items.len(), 1, "only the attested device: {j}");
    assert_eq!(items[0]["device_id"], alice.session.device_id.as_str());
    let first = unb64(&items[0]["key_package"]);
    assert_eq!(inspect_key_package(&first).unwrap().identity, alice.identity());
    let (_, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_ne!(unb64(&j["key_packages"][0]["key_package"]), first, "each KeyPackage only once");
    let (_, j) = node.get_auth(&kp_path, alice.token()).await;
    assert_eq!(j["count"], 98);
    let (s, _) = node.post("/api/v1/users/nobody/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Rate limit (production limit simulated directly at the limiter).
    let bob_id = node.login("bob").await.user_id;
    for _ in 0..10_000 {
        if node.state.claim_limiter.check(&format!("claim:{bob_id}")).is_err() {
            break;
        }
    }
    let (s, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{j}");
    assert_eq!(j["code"], "rate_limited");
}

#[tokio::test]
async fn devices_without_kps_are_omitted_and_deleted_devices_vanish() {
    let node = test_node(DOMAIN).await;
    let alice = node.crypto_user("alice").await;
    let phone = node.second_device(&alice).await;
    let bob = node.register("bob").await;
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["devices"].as_array().unwrap().len(), 2);
    // Drain the phone's KeyPackages: three claims, then only the first device remains.
    for _ in 0..3 {
        node.claim(&bob.token, "alice").await;
    }
    let (_, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!(j["key_packages"], json!([]), "all KeyPackages used up");
    node.upload_kps(&alice, 1).await;
    let (_, j) = node.post("/api/v1/users/alice/key-packages/claim", &bob.token, json!({})).await;
    assert_eq!(j["key_packages"].as_array().unwrap().len(), 1);
    assert_eq!(j["key_packages"][0]["device_id"], alice.session.device_id.as_str());

    let (s, _) = node.delete(&format!("/api/v1/users/me/devices/{}", phone.session.device_id), alice.token()).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["devices"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn identity_reset_invalidates_old_attestations() {
    let node = test_node(DOMAIN).await;
    let mut alice = node.crypto_user("alice").await;
    let bob = node.crypto_user("bob").await;
    node.befriend(&alice.session, &bob.session).await;
    let dm = node.create_dm(&alice.session, &bob.session).await;
    node.create_group(&mut alice, &dm).await;
    let (s, j) = node.send_encrypted(&alice, &dm, "before").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
    let backup_path = format!("/api/v1/users/me/backups/{DOMAIN}/{dm}");
    let (s, _, _) = node.raw(Method::PUT, &backup_path, alice.token(), &[], vec![1u8; 64]).await;
    assert_eq!(s, StatusCode::OK);

    let new_master = MasterSecret::generate().unwrap();
    let reset = |pw: &str| json!({ "identity_public_key": b64(&new_master.identity_public_key()), "password": pw });
    let (s, j) = node.post("/api/v1/users/me/identity/reset", alice.token(), reset("wrong-password")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{j}");
    assert_eq!(j["code"], "auth.invalid_credentials");
    let (s, j) = node
        .post(
            "/api/v1/users/me/identity/reset",
            alice.token(),
            json!({ "identity_public_key": "broken", "password": "password-alice-123" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{j}");

    let mut rx = node.state.hub.subscribe();
    let (s, j) = node.post("/api/v1/users/me/identity/reset", alice.token(), reset("password-alice-123")).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let mut kinds = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        kinds.push(ev.kind.clone());
        if ev.kind == "identity.changed" {
            let tavrn_node::hub::Scope::Users(u) = &ev.scope else { unreachable!("{:?}", ev.scope) };
            assert!(u.contains(&bob.session.user_id), "contacts are notified");
            assert!(u.contains(&alice.session.user_id), "own devices too");
            assert_eq!(ev.data["user"], "alice@t.local");
        }
    }
    assert!(kinds.contains(&"identity.changed".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"mls.remove_needed".to_string()), "{kinds:?}");

    // New key published, no device attested any more, backups and KeyPackages gone.
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(unb64(&keys["identity_public_key"]), new_master.identity_public_key().to_vec());
    assert!(keys["identity_reset_at"].is_string());
    assert_eq!(keys["devices"], json!([]));
    let (_, j) = node
        .get_auth(&format!("/api/v1/users/me/devices/{}/key-packages", alice.session.device_id), alice.token())
        .await;
    assert_eq!(j["count"], 0);
    let (s, _) = node.get_auth(&backup_path, alice.token()).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The old attestation no longer counts: KeyPackages, commits and encrypted messages are refused.
    let (s, j) = node
        .post(
            &format!("/api/v1/users/me/devices/{}/key-packages", alice.session.device_id),
            alice.token(),
            json!({ "key_packages": [b64(&alice.client.create_key_package().unwrap())] }),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");
    let (s, j) = node.send_encrypted(&alice, &dm, "after").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");
    let up = alice.client.self_update(&common::e2ee::qualified(&dm)).unwrap();
    let (s, j) = node.post_commit(alice.token(), &dm, &up).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{j}");
    assert_eq!(j["code"], "e2ee.device_not_attested");
    alice.client.discard_pending_commit(&common::e2ee::qualified(&dm)).unwrap();

    // The device keeps its key: re-attestation under the new identity works, a new key does not.
    let other_key = Device::generate("alice@t.local", &alice.session.device_id).unwrap().attest(&new_master).unwrap();
    let path = format!("/api/v1/users/me/devices/{}/key", alice.session.device_id);
    let (s, j) = node
        .put(&path, alice.token(), json!({ "device_public_key": b64(&other_key.device_public_key), "identity_signature": b64(&other_key.signature) }))
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "{j}");
    assert_eq!(j["code"], "e2ee.device_key_exists");
    let old_sig = alice.client.device().attest(&alice.master).unwrap();
    let (s, j) = node
        .put(&path, alice.token(), json!({ "device_public_key": b64(&old_sig.device_public_key), "identity_signature": b64(&old_sig.signature) }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the old signature no longer applies: {j}");
    let att = alice.client.device().attest(&new_master).unwrap();
    let (s, j) = node
        .put(
            &path,
            alice.token(),
            json!({ "device_public_key": b64(&att.device_public_key), "identity_signature": b64(&att.signature) }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{j}");
    let (_, keys) = node.req(Method::GET, "/api/v1/users/alice/keys", None, None).await;
    assert_eq!(keys["devices"].as_array().unwrap().len(), 1);
    let (s, j) = node.send_encrypted(&alice, &dm, "back again").await;
    assert_eq!(s, StatusCode::CREATED, "{j}");
}

#[tokio::test]
async fn capability_body_limits_and_json_errors() {
    let node = test_node(DOMAIN).await;
    let alice = node.register("alice").await;
    let wk = common::body_json(node.get("/.well-known/tavrn").await).await;
    assert!(wk["capabilities"].as_array().unwrap().contains(&json!("e2ee.mls1")), "{wk}");
    let (_, info) = node.req(Method::GET, "/api/v1/node", None, None).await;
    assert_eq!(info["dm_policy"], "everyone");

    let (s, _, body) = node
        .raw(
            Method::PUT,
            "/api/v1/users/me/identity",
            &alice.token,
            &[("content-type", "application/json")],
            b"{broken".to_vec(),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "request.invalid_json");
    let huge = json!({ "identity_public_key": "a".repeat(20_000) }).to_string().into_bytes();
    let (s, _, body) = node
        .raw(Method::PUT, "/api/v1/users/me/identity", &alice.token, &[("content-type", "application/json")], huge)
        .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem["code"], "request.too_large");
}

/// KeyPackage claims for a user by requesters who share nothing with them count against a budget per source and
/// target (`TAVRN_E2EE_CLAIMS_PER_TARGET_PER_HOUR`, ENCRYPTION.md §3.2): sybils on this node cannot drain the user's
/// KeyPackages, and they cannot lock out the user's room-mates, friends, DM partners or the user themselves.
#[tokio::test]
async fn claims_of_unrelated_requesters_are_budgeted_per_source_and_target() {
    let node = common::test_node_with(DOMAIN, |c| c.e2ee_claims_per_target_per_hour = 2).await;
    let bob = node.crypto_user("bob").await;
    let _carol = node.crypto_user("carol").await;
    let claim = |token: String, user: &'static str| {
        let node = &node;
        async move { node.post(&format!("/api/v1/users/{user}/key-packages/claim"), &token, json!({})).await }
    };
    for name in ["dave", "erin"] {
        let s = node.register(name).await;
        let (st, j) = claim(s.token.clone(), "bob").await;
        assert_eq!(st, StatusCode::OK, "{j}");
    }
    let frank = node.register("frank").await;
    let (st, j) = claim(frank.token.clone(), "bob").await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "a third unrelated requester exceeds the budget: {j}");
    let (st, j) = claim(frank.token.clone(), "carol").await;
    assert_eq!(st, StatusCode::OK, "other targets keep their own budget: {j}");
    let (st, j) = claim(bob.session.token.clone(), "bob").await;
    assert_eq!(st, StatusCode::OK, "own claims do not count: {j}");

    // A room-mate, a friend and a DM partner still claim.
    let room = node.create_room(bob.token(), "Club").await;
    let room_id = room["id"].as_str().unwrap();
    let mate = node.register("mate").await;
    let (_, invite) = node.post(&format!("/api/v1/rooms/{room_id}/invites"), bob.token(), json!({})).await;
    let code = invite["code"].as_str().unwrap();
    let (st, j) = node.post(&format!("/api/v1/invites/{code}/join"), &mate.token, json!({})).await;
    assert!(st.is_success(), "{j}");
    let (st, j) = claim(mate.token.clone(), "bob").await;
    assert_eq!(st, StatusCode::OK, "a room-mate is not limited by strangers: {j}");
    let friend = node.register("friend").await;
    node.befriend(&bob.session, &friend).await;
    let (st, j) = claim(friend.token.clone(), "bob").await;
    assert_eq!(st, StatusCode::OK, "a friend is not limited by strangers: {j}");
    let partner = node.register("partner").await;
    node.befriend(&bob.session, &partner).await;
    node.create_dm(&partner, &bob.session).await;
    tavrn_node::store::social::remove_friendship(&node.state.db, &bob.session.user_id, &partner.user_id).await.unwrap();
    let (st, j) = claim(partner.token.clone(), "bob").await;
    assert_eq!(st, StatusCode::OK, "a DM partner is not limited by strangers: {j}");
}
