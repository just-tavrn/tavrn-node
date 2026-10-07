// SPDX-License-Identifier: AGPL-3.0-only
//! Verification of the identity provider's ID tokens (APPLICATIONS.md §8.7).
//!
//! Pure functions (no I/O): the caller passes the provider's JWKS, the expected issuer, client id and nonce
//! and the current time. Checks, in this order:
//!
//! 1. Compact JWS with three parts, at most [`MAX_TOKEN_BYTES`]; no `crit` header.
//! 2. `alg` is one of [`ALLOWED_ALGS`] **and** announced by the provider. `none` and every HMAC algorithm
//!    are refused (an HMAC "signature" with the public key as secret is the classic confusion attack); the
//!    EdDSA-only rule applies to tokens tavrn issues, not to the provider's.
//! 3. The key: the JWKS entry with the header's `kid` (or, without `kid`, every candidate), of the family
//!    and curve the algorithm needs, not marked for encryption, with a matching `alg` if it names one, RSA
//!    moduli of at least 2048 bits. An unknown `kid` is reported separately so the caller can refetch the
//!    JWKS once.
//! 4. The signature, with the RustCrypto verifiers called explicitly (never jsonwebtoken's process-global
//!    provider).
//! 5. Claims: `iss` equals the configured issuer exactly, `aud` contains the client id, `azp` equals it when
//!    present and is required with several audiences, `exp` not passed (60 s leeway), `iat` within ±5
//!    minutes, `nbf` (if present) reached, `nonce` equals the login's nonce (constant time), `sub` 1–255
//!    characters.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey,
    crypto::rust_crypto::DEFAULT_PROVIDER,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse},
};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

/// Algorithms accepted for the provider's ID tokens.
pub const ALLOWED_ALGS: [Algorithm; 4] = [Algorithm::RS256, Algorithm::PS256, Algorithm::ES256, Algorithm::EdDSA];
/// Upper bound of an ID token.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Leeway for `exp` and `nbf`.
pub const EXP_LEEWAY_SECS: i64 = 60;
/// `iat` must lie within this distance from the node's clock.
pub const IAT_WINDOW_SECS: i64 = 300;
/// Smallest accepted RSA modulus (bytes).
const MIN_RSA_MODULUS_BYTES: usize = 256;

/// Why an ID token was refused. `UnknownKid` lets the caller refetch the JWKS once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("ID token signed with an unknown key id")]
    UnknownKid,
    #[error("ID token invalid: {0}")]
    Invalid(&'static str),
}

/// What the ID token must match.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Algorithms the provider announces (already intersected with [`ALLOWED_ALGS`]).
    pub algorithms: &'a [Algorithm],
    /// Unix seconds.
    pub now: i64,
}

/// Parses an `alg` name of a discovery document into an allowed algorithm.
pub fn allowed_alg(name: &str) -> Option<Algorithm> {
    let alg = match name {
        "RS256" => Algorithm::RS256,
        "PS256" => Algorithm::PS256,
        "ES256" => Algorithm::ES256,
        "EdDSA" => Algorithm::EdDSA,
        _ => return None,
    };
    Some(alg)
}

/// Parses a JWKS document leniently: entries that are not valid JWKs (unknown key types, encryption-only
/// algorithms the library does not model) are skipped instead of failing the whole set.
pub fn parse_jwks(doc: &Value) -> Vec<Jwk> {
    doc.get("keys")
        .and_then(Value::as_array)
        .map(|keys| keys.iter().take(100).filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok()).collect())
        .unwrap_or_default()
}

/// Verifies `token` and returns its claims.
pub fn verify(token: &str, keys: &[Jwk], expected: &Expected<'_>) -> Result<Map<String, Value>, TokenError> {
    let invalid = TokenError::Invalid;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(invalid("too large"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = parts.as_slice() else { return Err(invalid("format")) };
    // Refuses `alg: none` and unknown algorithms (the library's `Algorithm` has no `none`).
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("header"))?;
    if header.crit.is_some() {
        return Err(invalid("crit"));
    }
    if !ALLOWED_ALGS.contains(&header.alg) || !expected.algorithms.contains(&header.alg) {
        return Err(invalid("alg"));
    }
    let signature = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| invalid("signature encoding"))?;
    let message = format!("{header_b64}.{payload_b64}");

    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| header.kid.is_none() || k.common.key_id == header.kid)
        .filter(|k| key_fits(k, header.alg))
        .take(10)
        .collect();
    if candidates.is_empty() {
        return Err(if header.kid.is_some() { TokenError::UnknownKid } else { invalid("no key") });
    }
    let verified = candidates.iter().any(|jwk| verify_with(jwk, header.alg, message.as_bytes(), &signature));
    if !verified {
        return Err(invalid("signature"));
    }

    let payload = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| invalid("payload encoding"))?;
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&payload) else { return Err(invalid("payload")) };
    check_claims(&claims, expected)?;
    Ok(claims)
}

/// `true` if `jwk` can verify `alg`: family, curve, use, its own `alg` and the RSA key size.
fn key_fits(jwk: &Jwk, alg: Algorithm) -> bool {
    if matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)) {
        return false;
    }
    if let Some(key_alg) = jwk.common.key_algorithm.as_ref()
        && !key_alg_matches(key_alg, alg)
    {
        return false;
    }
    match (&jwk.algorithm, alg) {
        (AlgorithmParameters::RSA(p), Algorithm::RS256 | Algorithm::PS256) => {
            URL_SAFE_NO_PAD.decode(&p.n).is_ok_and(|n| n.len() >= MIN_RSA_MODULUS_BYTES)
        }
        (AlgorithmParameters::EllipticCurve(p), Algorithm::ES256) => p.curve == EllipticCurve::P256,
        (AlgorithmParameters::OctetKeyPair(p), Algorithm::EdDSA) => p.curve == EllipticCurve::Ed25519,
        _ => false,
    }
}

fn key_alg_matches(key_alg: &KeyAlgorithm, alg: Algorithm) -> bool {
    matches!(
        (key_alg, alg),
        (KeyAlgorithm::RS256, Algorithm::RS256)
            | (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

fn verify_with(jwk: &Jwk, alg: Algorithm, message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = DecodingKey::from_jwk(jwk) else { return false };
    let Ok(verifier) = (DEFAULT_PROVIDER.verifier_factory)(&alg, &key) else { return false };
    verifier.verify(message, &signature.to_vec()).is_ok()
}

fn check_claims(claims: &Map<String, Value>, expected: &Expected<'_>) -> Result<(), TokenError> {
    let invalid = TokenError::Invalid;
    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(invalid("iss"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => return Err(invalid("aud")),
    };
    if !audiences.contains(&expected.client_id) {
        return Err(invalid("aud"));
    }
    match claims.get("azp") {
        Some(Value::String(azp)) if azp == expected.client_id => {}
        Some(_) => return Err(invalid("azp")),
        None if audiences.len() > 1 => return Err(invalid("azp")),
        None => {}
    }
    let number = |name: &str| claims.get(name).and_then(Value::as_i64);
    let exp = number("exp").ok_or(invalid("exp"))?;
    if exp + EXP_LEEWAY_SECS <= expected.now {
        return Err(invalid("exp"));
    }
    let iat = number("iat").ok_or(invalid("iat"))?;
    if (expected.now - iat).abs() > IAT_WINDOW_SECS {
        return Err(invalid("iat"));
    }
    if claims.contains_key("nbf") && number("nbf").is_none_or(|nbf| nbf > expected.now + EXP_LEEWAY_SECS) {
        return Err(invalid("nbf"));
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).ok_or(invalid("nonce"))?;
    if !bool::from(nonce.as_bytes().ct_eq(expected.nonce.as_bytes())) {
        return Err(invalid("nonce"));
    }
    match claims.get("sub").and_then(Value::as_str) {
        Some(sub) if !sub.is_empty() && sub.chars().count() <= 255 => Ok(()),
        _ => Err(invalid("sub")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use jsonwebtoken::EncodingKey;
    use openssl::{ec::EcGroup, ec::EcKey, nid::Nid, pkey::PKey, rsa::Rsa};
    use serde_json::json;

    const ISS: &str = "https://idp.example/realms/x";
    const CLIENT: &str = "tavrn";
    const NOW: i64 = 1_800_000_000;

    struct Keys {
        rsa_der: Vec<u8>,
        rsa_jwk: Value,
        ec_der: Vec<u8>,
        ec_jwk: Value,
    }

    fn keys() -> Keys {
        let rsa = Rsa::generate(2048).unwrap();
        let rsa_jwk = json!({ "kty": "RSA", "kid": "r1", "use": "sig", "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()), "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()) });
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let (mut x, mut y) = (openssl::bn::BigNum::new().unwrap(), openssl::bn::BigNum::new().unwrap());
        ec.public_key().affine_coordinates(&group, &mut x, &mut y, &mut ctx).unwrap();
        let ec_jwk = json!({ "kty": "EC", "kid": "e1", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x.to_vec_padded(32).unwrap()), "y": URL_SAFE_NO_PAD.encode(y.to_vec_padded(32).unwrap()) });
        Keys {
            rsa_der: rsa.private_key_to_der().unwrap(),
            rsa_jwk,
            ec_der: PKey::from_ec_key(ec).unwrap().private_key_to_pkcs8().unwrap(),
            ec_jwk,
        }
    }

    fn claims() -> Value {
        json!({ "iss": ISS, "aud": CLIENT, "sub": "u-1", "exp": NOW + 300, "iat": NOW, "nonce": "n-1" })
    }

    fn sign(header: Value, claims: &Value, alg: Algorithm, key: &EncodingKey) -> String {
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signer = (DEFAULT_PROVIDER.signer_factory)(&alg, key).unwrap();
        let sig: Vec<u8> = signer.try_sign(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn rs256(k: &Keys, claims: &Value) -> String {
        sign(
            json!({ "alg": "RS256", "kid": "r1", "typ": "JWT" }),
            claims,
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&k.rsa_der),
        )
    }

    fn jwks(k: &Keys) -> Vec<Jwk> {
        parse_jwks(
            &json!({ "keys": [k.rsa_jwk, k.ec_jwk, { "kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "n": "AQAB", "e": "AQAB" }, { "kty": "weird" }] }),
        )
    }

    fn expected() -> Expected<'static> {
        Expected { issuer: ISS, client_id: CLIENT, nonce: "n-1", algorithms: &ALLOWED_ALGS, now: NOW }
    }

    #[test]
    fn valid_rs256_and_es256_tokens_pass() {
        let k = keys();
        let set = jwks(&k);
        assert_eq!(set.len(), 3, "the malformed entry is skipped, the encryption key kept but never used");
        let c = verify(&rs256(&k, &claims()), &set, &expected()).unwrap();
        assert_eq!(c["sub"], "u-1");
        let es = sign(
            json!({ "alg": "ES256", "kid": "e1" }),
            &claims(),
            Algorithm::ES256,
            &EncodingKey::from_ec_der(&k.ec_der),
        );
        verify(&es, &set, &expected()).unwrap();
    }

    #[test]
    fn claim_checks_refuse_every_mismatch() {
        let k = keys();
        let set = jwks(&k);
        let cases: Vec<(&str, Value)> = vec![
            ("iss", json!({ "iss": "https://evil.example" })),
            ("iss", json!({ "iss": format!("{ISS}/") })),
            ("aud", json!({ "aud": "other" })),
            ("aud", json!({ "aud": ["other", "x"] })),
            ("azp", json!({ "aud": [CLIENT, "other"] })),
            ("azp", json!({ "azp": "other" })),
            ("exp", json!({ "exp": NOW - 61 })),
            ("iat", json!({ "iat": NOW - 301 })),
            ("iat", json!({ "iat": NOW + 301 })),
            ("nbf", json!({ "nbf": NOW + 120 })),
            ("nonce", json!({ "nonce": "n-2" })),
            ("sub", json!({ "sub": "" })),
        ];
        for (what, patch) in cases {
            let mut c = claims();
            for (key, value) in patch.as_object().unwrap() {
                c[key] = value.clone();
            }
            assert_eq!(verify(&rs256(&k, &c), &set, &expected()), Err(TokenError::Invalid(what)), "{patch}");
        }
        let mut no_nonce = claims();
        no_nonce.as_object_mut().unwrap().remove("nonce");
        assert_eq!(verify(&rs256(&k, &no_nonce), &set, &expected()), Err(TokenError::Invalid("nonce")));
        // Several audiences are fine with the right azp.
        let mut multi = claims();
        multi["aud"] = json!([CLIENT, "other"]);
        multi["azp"] = json!(CLIENT);
        verify(&rs256(&k, &multi), &set, &expected()).unwrap();
    }

    #[test]
    fn none_hmac_and_unannounced_algorithms_are_refused() {
        let k = keys();
        let set = jwks(&k);
        let body = URL_SAFE_NO_PAD.encode(claims().to_string());
        let none = format!("{}.{body}.", URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"r1"}"#));
        assert_eq!(verify(&none, &set, &expected()), Err(TokenError::Invalid("header")));
        // HS256 with the RSA public key's modulus as "secret" (algorithm confusion).
        let secret = URL_SAFE_NO_PAD.decode(k.rsa_jwk["n"].as_str().unwrap()).unwrap();
        let hs = sign(
            json!({ "alg": "HS256", "kid": "r1" }),
            &claims(),
            Algorithm::HS256,
            &EncodingKey::from_secret(&secret),
        );
        assert_eq!(verify(&hs, &set, &expected()), Err(TokenError::Invalid("alg")));
        let only_es = Expected { algorithms: &[Algorithm::ES256], ..expected() };
        assert_eq!(verify(&rs256(&k, &claims()), &set, &only_es), Err(TokenError::Invalid("alg")));
        let crit = sign(
            json!({ "alg": "RS256", "kid": "r1", "crit": ["exp"] }),
            &claims(),
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&k.rsa_der),
        );
        assert_eq!(verify(&crit, &set, &expected()), Err(TokenError::Invalid("crit")));
    }

    #[test]
    fn keys_are_matched_strictly() {
        let k = keys();
        let set = jwks(&k);
        // Unknown kid: the caller refetches the JWKS.
        let unknown = sign(
            json!({ "alg": "RS256", "kid": "r2" }),
            &claims(),
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&k.rsa_der),
        );
        assert_eq!(verify(&unknown, &set, &expected()), Err(TokenError::UnknownKid));
        // RS256 claimed for the EC key id: no fitting key.
        let wrong_family = sign(
            json!({ "alg": "RS256", "kid": "e1" }),
            &claims(),
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&k.rsa_der),
        );
        assert_eq!(verify(&wrong_family, &set, &expected()), Err(TokenError::UnknownKid));
        // A key announced for RS256 does not verify PS256.
        let ps = sign(
            json!({ "alg": "PS256", "kid": "r1" }),
            &claims(),
            Algorithm::PS256,
            &EncodingKey::from_rsa_der(&k.rsa_der),
        );
        assert_eq!(verify(&ps, &set, &expected()), Err(TokenError::UnknownKid));
        // Without kid every fitting key is tried.
        let no_kid =
            sign(json!({ "alg": "RS256" }), &claims(), Algorithm::RS256, &EncodingKey::from_rsa_der(&k.rsa_der));
        verify(&no_kid, &set, &expected()).unwrap();
        // Tampered payload.
        let token = rs256(&k, &claims());
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let mut c = claims();
        c["sub"] = json!("admin");
        parts[1] = URL_SAFE_NO_PAD.encode(c.to_string());
        assert_eq!(verify(&parts.join("."), &set, &expected()), Err(TokenError::Invalid("signature")));
        // Small RSA keys are refused.
        let small = Rsa::generate(1024).unwrap();
        let small_jwk = parse_jwks(&json!({ "keys": [{ "kty": "RSA", "kid": "s1",
            "n": URL_SAFE_NO_PAD.encode(small.n().to_vec()), "e": URL_SAFE_NO_PAD.encode(small.e().to_vec()) }] }));
        let t = sign(
            json!({ "alg": "RS256", "kid": "s1" }),
            &claims(),
            Algorithm::RS256,
            &EncodingKey::from_rsa_der(&small.private_key_to_der().unwrap()),
        );
        assert_eq!(verify(&t, &small_jwk, &expected()), Err(TokenError::UnknownKid));
        assert_eq!(verify(&"a".repeat(MAX_TOKEN_BYTES + 1), &set, &expected()), Err(TokenError::Invalid("too large")));
        assert_eq!(verify("a.b", &set, &expected()), Err(TokenError::Invalid("format")));
    }

    #[test]
    fn allowed_alg_names() {
        assert_eq!(allowed_alg("RS256"), Some(Algorithm::RS256));
        assert_eq!(allowed_alg("EdDSA"), Some(Algorithm::EdDSA));
        assert_eq!(allowed_alg("HS256"), None);
        assert_eq!(allowed_alg("none"), None);
    }
}
