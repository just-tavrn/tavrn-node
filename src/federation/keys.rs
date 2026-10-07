// SPDX-License-Identifier: AGPL-3.0-only
//! Key cache of remote users (FEDERATION.md §3.5, §3.6): identity keys and attested devices as
//! published by the user's home node at `GET /api/v1/users/{username}/keys`.
//!
//! The cache lives on the remote user's rows: `users.identity_pubkey`, the device rows keyed by
//! `(user, home device id)` with `public_key`, `identity_signature` and `attested_identity_key`, and
//! `remote_users.keys_fetched_at`. So every check that works for local devices (attested under the
//! current identity key) works unchanged for remote devices. Keys are accepted only from the user's
//! home node, and every attestation is verified against the identity key the home node publishes;
//! invalid devices are dropped.
//!
//! Freshness: the cache is used for 1 hour; a device identity that is not in the cache causes a
//! refetch at most once per minute per user; `identity.changed` and `devices.changed` invalidate it.
//! If the home node is unreachable, an expired cache may be used for up to 24 hours, beyond that the
//! request fails with `503 federation.keys_unavailable`.

use chrono::Utc;
use serde_json::Value;

use super::client::Kind;
use crate::{
    app::AppState,
    error::ApiError,
    models::UserRow,
    store::{self, federation::RemoteDeviceKey},
    util,
};

pub const TTL_SECS: i64 = 3600;
/// An expired cache may stand in for an unreachable home node this long after the last fetch.
pub const STALE_MAX_SECS: i64 = 24 * 3600;
/// A device identity missing from a fresh cache causes at most one refetch in this interval.
pub const MISS_REFETCH_SECS: i64 = 60;
/// Devices accepted per user (more are dropped).
pub const MAX_DEVICES: usize = 100;

pub fn keys_unavailable() -> ApiError {
    ApiError::Unavailable {
        code: "federation.keys_unavailable",
        detail: "The keys of this user cannot be fetched right now".into(),
    }
}

/// A validated keys document of a remote user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteKeys {
    /// base64url identity key, `None` if the user has none yet.
    pub identity: Option<String>,
    pub identity_reset_at: Option<String>,
    /// Devices whose attestation verifies under `identity`.
    pub devices: Vec<RemoteDeviceKey>,
    /// Devices that were dropped (invalid key, signature or duplicate id).
    pub dropped: usize,
    /// The continuity chain of the identity key (ENCRYPTION.md §9a), oldest first; empty if the home node
    /// publishes none or it is malformed.
    pub continuity: Vec<tavrn_crypto::ContinuityStatement>,
}

fn key32(v: Option<&Value>) -> Option<[u8; 32]> {
    let bytes = tavrn_crypto::util::b64url_decode(v?.as_str()?).ok()?;
    let key: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).ok().filter(|k| !k.is_weak()).map(|_| key)
}

/// Validates the keys document of `address` fetched from its home node.
pub fn parse_keys(address: &str, body: &[u8]) -> Result<RemoteKeys, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "not JSON")?;
    if v.get("user").and_then(Value::as_str) != Some(address) {
        return Err("address does not match");
    }
    let identity = match v.get("identity_public_key") {
        None | Some(Value::Null) => None,
        Some(k) => Some(key32(Some(k)).ok_or("invalid identity_public_key")?),
    };
    let identity_reset_at =
        v.get("identity_reset_at").and_then(Value::as_str).and_then(util::parse_time).map(util::format_time);
    let list = match v.get("devices") {
        Some(Value::Array(list)) => list,
        None | Some(Value::Null) => &Vec::new(),
        Some(_) => return Err("invalid devices"),
    };
    let mut devices: Vec<RemoteDeviceKey> = Vec::new();
    let mut dropped = 0;
    for d in list {
        match parse_device(address, identity, d, &devices) {
            Some(device) if devices.len() < MAX_DEVICES => devices.push(device),
            _ => dropped += 1,
        }
    }
    let continuity = v
        .get("continuity")
        .and_then(|c| serde_json::from_value::<Vec<tavrn_crypto::ContinuityStatement>>(c.clone()).ok())
        .filter(|c| c.len() <= tavrn_crypto::identity::MAX_CHAIN)
        .unwrap_or_default();
    Ok(RemoteKeys {
        identity: identity.map(|k| tavrn_crypto::util::b64url_encode(&k)),
        identity_reset_at,
        devices,
        dropped,
        continuity,
    })
}

/// One device entry whose attestation verifies under `identity`; `None` for anything else.
fn parse_device(
    address: &str,
    identity: Option<[u8; 32]>,
    d: &Value,
    seen: &[RemoteDeviceKey],
) -> Option<RemoteDeviceKey> {
    let identity = identity?;
    let device_id = d.get("device_id")?.as_str()?;
    if !util::is_ulid(device_id) || seen.iter().any(|x| x.home_device_id == device_id) {
        return None;
    }
    let public_key = key32(d.get("device_public_key"))?;
    let signature: [u8; 64] =
        tavrn_crypto::util::b64url_decode(d.get("identity_signature")?.as_str()?).ok()?.try_into().ok()?;
    let attestation = tavrn_crypto::DeviceAttestation {
        user_address: address.to_string(),
        device_id: device_id.to_string(),
        device_public_key: public_key,
        identity_public_key: identity,
        signature,
    };
    tavrn_crypto::verify_device_attestation(&attestation, &identity).ok()?;
    Some(RemoteDeviceKey {
        home_device_id: device_id.to_string(),
        public_key: tavrn_crypto::util::b64url_encode(&public_key),
        identity_signature: tavrn_crypto::util::b64url_encode(&signature),
    })
}

/// Fetches the keys of a remote user from its home node and stores them. Returns the home device ids
/// of devices that were attested before and are no longer published.
pub async fn refresh(state: &AppState, user: &UserRow) -> Result<Vec<String>, ApiError> {
    if user.domain == state.config.domain {
        return Ok(Vec::new());
    }
    super::check_policy(state, &user.domain).await?;
    let address = user.address();
    let path = format!("/api/v1/users/{}/keys", user.username);
    let fetched = state.federation.get(&user.domain, &path, Kind::Keys).await.map_err(|e| {
        tracing::warn!(domain = user.domain, result = e.label(), "remote keys fetch failed");
        e.to_api()
    })?;
    let keys = parse_keys(&address, &fetched.body).map_err(|reason| {
        tracing::warn!(domain = user.domain, reason, "remote keys invalid");
        super::discovery::peer_invalid(&user.domain, reason)
    })?;
    if keys.dropped > 0 {
        tracing::warn!(domain = user.domain, dropped = keys.dropped, "remote devices with invalid attestation dropped");
    }
    // A changed identity key seen on a refetch (`devices.changed` after a rotation, or simply the next lookup):
    // announce it once in the welcome channels of the user's rooms here.
    let previous = store::users::by_id(&state.db, &user.id).await?.and_then(|u| u.identity_pubkey);
    if let (Some(old), Some(new)) = (previous.as_deref(), keys.identity.as_deref())
        && old != new
        && store::federation::swap_remote_identity(&state.db, &user.id, old, new).await?
    {
        let rotated = tavrn_crypto::continuity_reaches(&keys.continuity, old, new);
        remote_key_changed(state, user, rotated).await?;
    }
    store::federation::store_remote_keys(
        &state.db,
        &user.id,
        &user.domain,
        keys.identity.as_deref(),
        keys.identity_reset_at.as_deref(),
        &keys.devices,
    )
    .await
}

/// A remote user's identity key changed: `system.key_changed` in the welcome channels of the rooms here and the
/// realtime notice to the local contacts (`identity.rotated` for a rotation with continuity, `identity.changed`
/// otherwise), so their clients re-check the key on the user's home node.
pub async fn remote_key_changed(state: &AppState, user: &UserRow, rotated: bool) -> Result<(), ApiError> {
    crate::welcome::key_changed(state, user, rotated).await;
    let mut recipients = store::social::contact_ids(&state.db, &user.id).await?;
    for (friend, _) in store::social::friends_of(&state.db, &user.id).await? {
        if !recipients.contains(&friend) {
            recipients.push(friend);
        }
    }
    let kind = if rotated { "identity.rotated" } else { "identity.changed" };
    state.hub.users(
        recipients,
        kind,
        serde_json::json!({ "user": user.address(), "user_id": user.id, "at": util::now() }),
    );
    Ok(())
}

fn age_secs(fetched_at: Option<&str>) -> Option<i64> {
    fetched_at.and_then(util::parse_time).map(|t| (Utc::now() - t).num_seconds())
}

/// Makes sure the cache of a remote user is usable: fresh (or within the stale window while the home
/// node is unreachable) and, if `device` is given, refetched once when that home device id is missing.
/// Local users need nothing.
pub async fn ensure(state: &AppState, user: &UserRow, device: Option<&str>) -> Result<(), ApiError> {
    if user.domain == state.config.domain {
        return Ok(());
    }
    let meta = store::federation::remote_meta(&state.db, &user.id).await?;
    let age = age_secs(meta.as_ref().and_then(|m| m.keys_fetched_at.as_deref()));
    if let Some(age) = age.filter(|a| *a < TTL_SECS) {
        let missing = match device {
            None => false,
            Some(home) => !device_attested(state, user, home).await?,
        };
        if !missing || age < MISS_REFETCH_SECS {
            return Ok(());
        }
    }
    // At most one refetch per user and minute through here, so an unreachable home node cannot be hammered
    // by requests (anonymous key lookups included).
    if state.keys_fetch_limiter.check(&user.id).is_err() {
        return if age.is_some_and(|a| a < STALE_MAX_SECS) { Ok(()) } else { Err(keys_unavailable()) };
    }
    match refresh(state, user).await {
        Ok(_) => Ok(()),
        Err(e) if age.is_some_and(|a| a < STALE_MAX_SECS) => {
            tracing::info!(domain = user.domain, result = e.code(), "home node unreachable, using the cached keys");
            Ok(())
        }
        Err(e) => {
            tracing::warn!(domain = user.domain, result = e.code(), "keys of a remote user unavailable");
            Err(keys_unavailable())
        }
    }
}

async fn device_attested(state: &AppState, user: &UserRow, home_device_id: &str) -> Result<bool, ApiError> {
    let Some(row_id) = store::federation::remote_device_row(&state.db, &user.id, home_device_id).await? else {
        return Ok(false);
    };
    let row = store::e2ee::device_key(&state.db, &row_id).await?;
    Ok(crate::e2ee::attested_key_of(row.as_ref(), &user.id).is_some())
}

/// The attested key and local row id of a remote user's device (after [`ensure`]).
pub async fn remote_device_key(
    state: &AppState,
    user: &UserRow,
    home_device_id: &str,
) -> Result<Option<(String, [u8; 32])>, ApiError> {
    ensure(state, user, Some(home_device_id)).await?;
    let Some(row_id) = store::federation::remote_device_row(&state.db, &user.id, home_device_id).await? else {
        return Ok(None);
    };
    let row = store::e2ee::device_key(&state.db, &row_id).await?;
    Ok(crate::e2ee::attested_key_of(row.as_ref(), &user.id).map(|k| (row_id, k)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde_json::json;
    use tavrn_crypto::{Device, MasterSecret, util::b64url_encode as b64};

    use super::*;

    const ADDR: &str = "alice@a.example";

    fn device(master: &MasterSecret, address: &str) -> (Value, String) {
        let id = util::ulid();
        let d = Device::generate(address, &id).unwrap();
        let att = d.attest(master).unwrap();
        (
            json!({ "device_id": id, "device_public_key": b64(&att.device_public_key),
                    "identity_signature": b64(&att.signature), "created_at": util::now() }),
            id,
        )
    }

    fn doc(master: &MasterSecret, devices: Vec<Value>) -> Vec<u8> {
        json!({ "user": ADDR, "identity_public_key": b64(&master.identity_public_key()),
                "identity_reset_at": null, "devices": devices })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn valid_devices_are_kept_and_forgeries_dropped() {
        let master = MasterSecret::generate().unwrap();
        let other = MasterSecret::generate().unwrap();
        let (good, good_id) = device(&master, ADDR);
        let (foreign_identity, _) = device(&other, ADDR);
        let (other_user, _) = device(&master, "mallory@a.example");
        let mut tampered = device(&master, ADDR).0;
        tampered["device_public_key"] = good["device_public_key"].clone();
        let mut duplicate = good.clone();
        duplicate["created_at"] = json!("x");
        let mut bad_id = device(&master, ADDR).0;
        bad_id["device_id"] = json!("../etc");
        let keys =
            parse_keys(ADDR, &doc(&master, vec![good, foreign_identity, other_user, tampered, duplicate, bad_id]))
                .unwrap();
        assert_eq!(keys.devices.len(), 1);
        assert_eq!(keys.devices[0].home_device_id, good_id);
        assert_eq!(keys.dropped, 5);
        assert_eq!(keys.identity, Some(b64(&master.identity_public_key())));
    }

    #[test]
    fn documents_must_name_the_user_and_carry_valid_keys() {
        let master = MasterSecret::generate().unwrap();
        assert_eq!(parse_keys("bob@a.example", &doc(&master, vec![])).unwrap_err(), "address does not match");
        let bad = json!({ "user": ADDR, "identity_public_key": "AAAA", "devices": [] }).to_string();
        assert_eq!(parse_keys(ADDR, bad.as_bytes()).unwrap_err(), "invalid identity_public_key");
        let bad = json!({ "user": ADDR, "identity_public_key": null, "devices": {} }).to_string();
        assert_eq!(parse_keys(ADDR, bad.as_bytes()).unwrap_err(), "invalid devices");
        assert_eq!(parse_keys(ADDR, b"<html>").unwrap_err(), "not JSON");
        // Without an identity key no device can be attested.
        let (d, _) = device(&master, ADDR);
        let none = json!({ "user": ADDR, "identity_public_key": null, "devices": [d] }).to_string();
        let keys = parse_keys(ADDR, none.as_bytes()).unwrap();
        assert!(keys.devices.is_empty());
        assert_eq!((keys.identity, keys.dropped), (None, 1));
    }

    #[test]
    fn the_continuity_chain_is_parsed_and_malformed_ones_ignored() {
        let master = MasterSecret::generate().unwrap();
        let old = tavrn_crypto::IdentityKey::from_master(&master);
        let new = tavrn_crypto::IdentityKey::generate().unwrap();
        let statement = tavrn_crypto::sign_continuity(&old, &new, "2026-10-06T12:00:00Z").unwrap();
        let mut v: Value = serde_json::from_slice(&doc(&master, vec![])).unwrap();
        v["continuity"] = json!([statement]);
        let keys = parse_keys(ADDR, v.to_string().as_bytes()).unwrap();
        assert_eq!(keys.continuity, vec![statement.clone()]);
        assert!(tavrn_crypto::continuity_reaches(&keys.continuity, &statement.old_key, &statement.new_key));
        v["continuity"] = json!({ "not": "a list" });
        assert!(parse_keys(ADDR, v.to_string().as_bytes()).unwrap().continuity.is_empty());
        v["continuity"] = json!([{ "old_key": 1 }]);
        assert!(parse_keys(ADDR, v.to_string().as_bytes()).unwrap().continuity.is_empty());
    }

    #[test]
    fn the_device_count_is_capped() {
        let master = MasterSecret::generate().unwrap();
        let devices: Vec<Value> = (0..MAX_DEVICES + 3).map(|_| device(&master, ADDR).0).collect();
        let keys = parse_keys(ADDR, &doc(&master, devices)).unwrap();
        assert_eq!((keys.devices.len(), keys.dropped), (MAX_DEVICES, 3));
    }
}
