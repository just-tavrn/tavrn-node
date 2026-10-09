// SPDX-License-Identifier: AGPL-3.0-only
//! Device reuse at login (PROTOCOL.md §5b, ENCRYPTION.md §3.4).
//!
//! A login normally creates a new device. A client that still holds the keys of one of the account's devices
//! proves possession of that device's attested key over a single-use login nonce of this node; the new session
//! then continues that device (same device id, same MLS leaves, the local key store stays valid) instead of
//! creating a new one. Anything that does not check out silently falls back to a new device, so a proof never
//! makes a login fail and never lets a session take over a device of another user.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    models::UserRow,
    store, util,
};

/// Lifetime of a login nonce.
pub const NONCE_TTL_SECS: i64 = 300;
const NONCE_TYP: &str = "devnonce";
const NONCE_SUBJECT: &str = "device-login";

/// Proof that the client holds the key of one of the account's devices (`device` in login requests).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DeviceProof {
    /// The device the new session should continue.
    pub id: String,
    /// A nonce of `POST /auth/device-nonce` (single use, 5 minutes).
    pub nonce: String,
    /// base64url Ed25519 signature of the device key over
    /// `"tavrn device login v1\0" || str16(device_id) || str16(user_address) || str16(nonce)`.
    pub proof: String,
}

/// A single-use login nonce for a [`DeviceProof`].
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceNonce {
    pub nonce: String,
    pub expires_in: i64,
}

/// A nonce: a short-lived token signed by this node (`typ = devnonce`), spent when a proof uses it.
pub fn issue_nonce(state: &AppState) -> Result<DeviceNonce, ApiError> {
    let key = state.signing_key();
    let now = jwt::now_unix();
    let claims = StandardClaims {
        iss: state.config.domain.clone(),
        sub: NONCE_SUBJECT.into(),
        aud: state.config.domain.clone(),
        exp: now + NONCE_TTL_SECS,
        iat: now,
        jti: util::ulid(),
        typ: NONCE_TYP.into(),
    };
    let nonce = jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))?;
    Ok(DeviceNonce { nonce, expires_in: NONCE_TTL_SECS })
}

/// Checks a device proof for `user`: the nonce is genuine, unexpired and unspent (it is spent here), the device is
/// a local device of `user` whose key is attested under the current identity key, and the signature verifies.
/// `Some(device id)` if all holds, `None` otherwise (the caller creates a new device).
pub async fn verify(state: &AppState, user: &UserRow, proof: &DeviceProof) -> Result<Option<String>, ApiError> {
    let refuse = |why: &'static str| {
        tracing::info!(user = user.address(), why, "device proof refused, new device");
        Ok(None)
    };
    if !tavrn_crypto::util::valid_ulid(&proof.id)
        || proof.nonce.len() > tavrn_crypto::device::MAX_LOGIN_NONCE_LEN
        || proof.proof.len() > 128
    {
        return refuse("malformed");
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(proof.proof.as_bytes()) else { return refuse("malformed") };
    let Ok(kid) = jwt::peek_kid(&proof.nonce) else { return refuse("nonce") };
    let Some(key) = state.keys.iter().find(|k| k.kid == kid) else { return refuse("nonce") };
    let expected = Expected { iss: state.config.domain.clone(), aud: state.config.domain.clone(), typ: NONCE_TYP };
    let Ok((claims, _)) = jwt::verify::<serde::de::IgnoredAny>(&proof.nonce, &key.verifying(), &expected) else {
        return refuse("nonce");
    };
    if claims.sub != NONCE_SUBJECT {
        return refuse("nonce");
    }
    // Single use: the pre-auth spend table keeps the jti until the nonce would have expired anyway.
    let exp = chrono::DateTime::from_timestamp(claims.exp, 0).map(util::format_time).unwrap_or_else(util::now);
    if !store::factors::spend_preauth(&state.db, &claims.jti, &exp).await? {
        return refuse("nonce spent");
    }
    if store::users::own_device(&state.db, &user.id, &proof.id).await?.is_none() {
        return refuse("unknown device");
    }
    let row = store::e2ee::device_key(&state.db, &proof.id).await?;
    let Some(device_key) = crate::e2ee::attested_key_of(row.as_ref(), &user.id) else {
        return refuse("device not attested");
    };
    if tavrn_crypto::device::verify_login_proof(&device_key, &proof.id, &user.address(), &proof.nonce, &signature)
        .is_err()
    {
        return refuse("signature");
    }
    Ok(Some(proof.id.clone()))
}

/// [`verify`] for an optional proof.
pub async fn verify_opt(
    state: &AppState,
    user: &UserRow,
    proof: Option<&DeviceProof>,
) -> Result<Option<String>, ApiError> {
    match proof {
        Some(p) => verify(state, user, p).await,
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;

    /// The protocol's reference values (`testvectors/encryption.json`): the login proof the node checks here, and the
    /// content the node's ciphertext checks (ENCRYPTION.md §5.3) must accept in every form, with and without the signed
    /// context of §5.2, and history shares.
    #[test]
    fn published_vectors() {
        let v: Value =
            serde_json::from_str(include_str!("../protocol/testvectors/encryption.json")).expect("vectors JSON");
        let s = |a: &str, b: &str| v[a][b].as_str().expect("string").to_owned();
        let d = |a: &str, b: &str| URL_SAFE_NO_PAD.decode(s(a, b)).expect("base64url");
        let key: [u8; 32] = d("device_attestation", "device_public_key").try_into().expect("32 bytes");
        let proof = d("device_login", "proof");
        let (device, user, nonce) =
            (s("device_login", "device_id"), s("device_login", "user_address"), s("device_login", "nonce"));
        assert_eq!(
            tavrn_crypto::device::login_proof_message(&device, &user, &nonce).unwrap(),
            d("device_login", "message")
        );
        tavrn_crypto::device::verify_login_proof(&key, &device, &user, &nonce, &proof).expect("valid proof");
        assert!(tavrn_crypto::device::verify_login_proof(&key, &device, &user, "other-nonce", &proof).is_err());
        assert!(
            tavrn_crypto::device::verify_login_proof(&key, &device, "mallory@node.example", &nonce, &proof).is_err()
        );
        for (section, field) in
            [("content", "content"), ("content_context", "content"), ("history_share", "ciphertext")]
        {
            let header = tavrn_crypto::content_header(&s(section, field)).expect(section);
            assert_eq!(Some(header.epoch), v[section]["epoch"].as_u64(), "{section}");
        }
    }
}
