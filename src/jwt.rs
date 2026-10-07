// SPDX-License-Identifier: AGPL-3.0-only
//! Minimal JWT encoder/verifier, `EdDSA` (Ed25519) only.
//!
//! Deliberately no library: we need exactly one algorithm, and the well-known JWT attacks
//! (`alg: none`, algorithm confusion, missing `aud`/`exp`) are made impossible here by rejecting
//! anything other than `{"alg":"EdDSA","typ":"JWT"}` with a valid signature right away.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwtError {
    #[error("Token has an invalid format")]
    Malformed,
    #[error("Token header is not EdDSA/JWT")]
    WrongHeader,
    #[error("unknown key (kid)")]
    UnknownKey,
    #[error("Invalid signature")]
    BadSignature,
    #[error("Token expired")]
    Expired,
    #[error("Invalid token claims: {0}")]
    Claims(&'static str),
}

#[derive(Serialize, Deserialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Required claims of all tavrn tokens. Callers add further claims through their type `T`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandardClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// tavrn token kind: session | federation | s2s | app
    pub typ: String,
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn sign<T: Serialize>(key: &SigningKey, kid: &str, claims: &T) -> Result<String, serde_json::Error> {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header { alg: "EdDSA", typ: "JWT", kid })?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header}.{payload}");
    let sig = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes())))
}

/// Reads `kid` from the header without verifying the signature (to pick the matching key).
pub fn peek_kid(token: &str) -> Result<String, JwtError> {
    let header_b64 = token.split('.').next().ok_or(JwtError::Malformed)?;
    let bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| JwtError::Malformed)?;
    let header: Header = serde_json::from_slice(&bytes).map_err(|_| JwtError::Malformed)?;
    if header.alg != "EdDSA" || header.typ != "JWT" {
        return Err(JwtError::WrongHeader);
    }
    Ok(header.kid.to_string())
}

/// Clock skew tolerated for `iat` of this node's own tokens (sessions, pre-auth, confirmations).
pub const LOCAL_SKEW_SECS: i64 = 60;
/// Clock skew tolerated for `iat` of tokens of other nodes (FEDERATION.md §2.1).
pub const FEDERATION_SKEW_SECS: i64 = 300;

/// Verifies signature, expiry, `iss`, `aud` and `typ` and returns the claims (60 s tolerance for `iat`).
pub fn verify<T: DeserializeOwned>(
    token: &str,
    key: &VerifyingKey,
    expected: &Expected,
) -> Result<(StandardClaims, T), JwtError> {
    verify_with_skew(token, key, expected, LOCAL_SKEW_SECS)
}

/// Like [`verify`], with `iat ≤ now + skew_secs`; `exp` stays strict (`exp > now`).
pub fn verify_with_skew<T: DeserializeOwned>(
    token: &str,
    key: &VerifyingKey,
    expected: &Expected,
    skew_secs: i64,
) -> Result<(StandardClaims, T), JwtError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(JwtError::Malformed),
    };
    peek_kid(token)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| JwtError::Malformed)?;
    // Strict Ed25519 (FEDERATION.md §2.1): rejects malleable signatures and small-order keys.
    key.verify_strict(format!("{h}.{p}").as_bytes(), &sig).map_err(|_| JwtError::BadSignature)?;

    let payload = URL_SAFE_NO_PAD.decode(p).map_err(|_| JwtError::Malformed)?;
    let std: StandardClaims =
        serde_json::from_slice(&payload).map_err(|_| JwtError::Claims("required fields missing"))?;
    let extra: T = serde_json::from_slice(&payload).map_err(|_| JwtError::Claims("invalid extra fields"))?;

    if std.exp <= now_unix() {
        return Err(JwtError::Expired);
    }
    if std.iat > now_unix() + skew_secs {
        return Err(JwtError::Claims("iat is in the future"));
    }
    if std.iss != expected.iss {
        return Err(JwtError::Claims("iss does not match"));
    }
    if std.aud != expected.aud {
        return Err(JwtError::Claims("aud does not match"));
    }
    if std.typ != expected.typ {
        return Err(JwtError::Claims("typ does not match"));
    }
    Ok((std, extra))
}

pub struct Expected {
    pub iss: String,
    pub aud: String,
    pub typ: &'static str,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Extra {
        #[serde(flatten)]
        std: StandardClaims,
        device: String,
    }

    #[derive(Deserialize, Debug)]
    struct Device {
        device: String,
    }

    fn claims(exp_offset: i64) -> Extra {
        Extra {
            std: StandardClaims {
                iss: "a.example".into(),
                sub: "u1".into(),
                aud: "a.example".into(),
                exp: now_unix() + exp_offset,
                iat: now_unix(),
                jti: "j1".into(),
                typ: "session".into(),
            },
            device: "d1".into(),
        }
    }

    fn expected() -> Expected {
        Expected { iss: "a.example".into(), aud: "a.example".into(), typ: "session" }
    }

    #[test]
    fn roundtrip() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = sign(&key, "k1", &claims(60)).unwrap();
        assert_eq!(peek_kid(&token).unwrap(), "k1");
        let (std, extra): (StandardClaims, Device) = verify(&token, &key.verifying_key(), &expected()).unwrap();
        assert_eq!(std.sub, "u1");
        assert_eq!(extra.device, "d1");
    }

    #[test]
    fn rejects_wrong_key_tampering_and_expiry() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = sign(&key, "k1", &claims(60)).unwrap();
        assert_eq!(verify::<Device>(&token, &other.verifying_key(), &expected()).unwrap_err(), JwtError::BadSignature);

        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let mut payload = URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
        let s = String::from_utf8(payload.clone()).unwrap().replace("\"sub\":\"u1\"", "\"sub\":\"u2\"");
        payload = s.into_bytes();
        parts[1] = URL_SAFE_NO_PAD.encode(payload);
        let tampered = parts.join(".");
        assert_eq!(verify::<Device>(&tampered, &key.verifying_key(), &expected()).unwrap_err(), JwtError::BadSignature);

        let expired = sign(&key, "k1", &claims(-1)).unwrap();
        assert_eq!(verify::<Device>(&expired, &key.verifying_key(), &expected()).unwrap_err(), JwtError::Expired);
    }

    #[test]
    fn rejects_alg_none_and_foreign_headers() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = sign(&key, "k1", &claims(60)).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let none_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
        let forged = format!("{none_header}.{payload}.");
        assert_eq!(verify::<Device>(&forged, &key.verifying_key(), &expected()).unwrap_err(), JwtError::WrongHeader);
        let hs = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT","kid":"k1"}"#);
        assert_eq!(peek_kid(&format!("{hs}.{payload}.x")).unwrap_err(), JwtError::WrongHeader);
        assert_eq!(peek_kid("no.token").unwrap_err(), JwtError::Malformed);
    }

    #[test]
    fn skew_is_a_parameter() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut c = claims(600);
        c.std.iat = now_unix() + 200;
        let token = sign(&key, "k1", &c).unwrap();
        let vk = key.verifying_key();
        assert_eq!(
            verify::<Device>(&token, &vk, &expected()).unwrap_err(),
            JwtError::Claims("iat is in the future"),
            "own tokens keep 60 s"
        );
        assert!(verify_with_skew::<Device>(&token, &vk, &expected(), FEDERATION_SKEW_SECS).is_ok());
        c.std.iat = now_unix() + 301;
        let token = sign(&key, "k1", &c).unwrap();
        assert!(verify_with_skew::<Device>(&token, &vk, &expected(), FEDERATION_SKEW_SECS).is_err());
        // exp stays strict whatever the skew.
        let token = sign(&key, "k1", &claims(-1)).unwrap();
        assert_eq!(
            verify_with_skew::<Device>(&token, &vk, &expected(), FEDERATION_SKEW_SECS).unwrap_err(),
            JwtError::Expired
        );
    }

    #[test]
    fn rejects_wrong_aud_iss_typ() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = sign(&key, "k1", &claims(60)).unwrap();
        let vk = key.verifying_key();
        let e = Expected { aud: "b.example".into(), ..expected() };
        assert_eq!(verify::<Device>(&token, &vk, &e).unwrap_err(), JwtError::Claims("aud does not match"));
        let e = Expected { iss: "b.example".into(), ..expected() };
        assert_eq!(verify::<Device>(&token, &vk, &e).unwrap_err(), JwtError::Claims("iss does not match"));
        let e = Expected { typ: "federation", ..expected() };
        assert_eq!(verify::<Device>(&token, &vk, &e).unwrap_err(), JwtError::Claims("typ does not match"));
    }
}
