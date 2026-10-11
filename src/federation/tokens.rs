// SPDX-License-Identifier: AGPL-3.0-only
//! Federation tokens (`typ = "federation"`, §2.2) and node tokens (`typ = "s2s"`, §2.3): issuing and
//! verification of tokens of other nodes (§2.1).
//!
//! Verification of a token of another node, in this order: the unverified `iss` (only used to know where
//! the key comes from) must be a valid node domain other than this node; the caller applies the domain
//! policy and rate limits; the key for `kid` comes from the `.well-known` of exactly `iss`; then
//! signature (strict Ed25519), `iss`, `aud` = this node, `typ`, `exp > now`, `iat ≤ now + 5 min` and
//! `exp − iat` within the lifetime of the token kind. The `jti` is spent last by the caller
//! ([`spend_jti`]), so a token refused for another reason can be corrected and retried.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{
    app::AppState,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    store, util,
};

/// Lifetime of a federation token (§2.2).
pub const FEDERATION_TTL_SECS: i64 = 600;
/// Lifetime of a node token (§2.3).
pub const NODE_TTL_SECS: i64 = 300;
/// Spent `jti`s are kept until `exp` plus this grace (§2.1).
pub const REPLAY_GRACE_SECS: i64 = 300;

pub fn token_invalid() -> ApiError {
    ApiError::Unauthorized { code: "federation.token_invalid" }
}

fn token_expired() -> ApiError {
    ApiError::Unauthorized { code: "federation.token_expired" }
}

fn token_replayed() -> ApiError {
    ApiError::Unauthorized { code: "federation.token_replayed" }
}

pub fn issuer_mismatch() -> ApiError {
    ApiError::Unauthorized { code: "federation.issuer_mismatch" }
}

/// Claims of a federation token (§2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    /// `user` or `bot`.
    pub kind: String,
    /// Bots only: the owner's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Device ULID on the home node.
    pub device: String,
    /// The user's current `profile_version`.
    pub pv: i64,
    /// Bots only: the application ULID on the home node (APPLICATIONS.md §2.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Bots only: the effective scopes of the app token; absent (older home node) = all scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// `age.v1` (§2.2): 18 or older by the home node's date of birth; null = unknown (bots: their owner's value).
    /// Always sent; the hosting node treats null and absent as "below 18".
    pub age_over_18: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FederationExtra {
    kind: String,
    #[serde(default)]
    owner: Option<String>,
    device: String,
    pv: i64,
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    /// A type other than boolean or null makes the token invalid.
    #[serde(default)]
    age_over_18: Option<bool>,
}

/// The bot claims of a federation token: owner address, application ULID and effective scopes.
pub struct BotClaims<'a> {
    pub owner: String,
    pub app: &'a str,
    pub scopes: &'a [String],
}

/// Claims of a node token (§2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    pub htm: String,
    pub htu: String,
    pub body_sha256: String,
}

#[derive(Debug, Deserialize)]
struct NodeExtra {
    htm: String,
    htu: String,
    body_sha256: String,
}

/// base64url SHA-256 of the exact body bytes.
pub fn body_sha256(body: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(body))
}

fn sign<T: Serialize>(state: &AppState, claims: &T) -> Result<String, ApiError> {
    let key = state.signing_key();
    jwt::sign(&key.signing, &key.kid, claims).map_err(|e| ApiError::Internal(e.into()))
}

fn std_claims(state: &AppState, sub: String, aud: &str, typ: &str, ttl: i64) -> StandardClaims {
    let now = jwt::now_unix();
    StandardClaims {
        iss: state.config.domain.clone(),
        sub,
        aud: aud.to_string(),
        exp: now + ttl,
        iat: now,
        jti: util::ulid(),
        typ: typ.into(),
    }
}

/// Signs a federation token of a local user for `target`.
#[allow(clippy::too_many_arguments)]
pub fn issue_federation_token(
    state: &AppState,
    address: String,
    kind: &str,
    device_id: &str,
    target: &str,
    profile_version: i64,
    bot: Option<BotClaims<'_>>,
    age_over_18: Option<bool>,
) -> Result<String, ApiError> {
    let claims = FederationClaims {
        std: std_claims(state, address, target, "federation", FEDERATION_TTL_SECS),
        kind: kind.to_string(),
        owner: bot.as_ref().map(|b| b.owner.clone()),
        device: device_id.to_string(),
        pv: profile_version,
        app: bot.as_ref().map(|b| b.app.to_string()),
        scopes: bot.as_ref().map(|b| b.scopes.to_vec()),
        age_over_18,
    };
    sign(state, &claims)
}

/// Signs a node token for one POST of `body` to `path` on `target`. A fresh token per attempt.
pub fn issue_node_token(
    state: &AppState,
    target: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, ApiError> {
    let claims = NodeClaims {
        std: std_claims(state, state.config.domain.clone(), target, "s2s", NODE_TTL_SECS),
        htm: method.to_string(),
        htu: path.to_string(),
        body_sha256: body_sha256(body),
    };
    sign(state, &claims)
}

#[derive(Deserialize)]
struct Issuer {
    iss: String,
}

/// The **unverified** issuer of a token, only to decide where its key comes from. Must be a valid node
/// domain other than this node.
pub fn peek_issuer(state: &AppState, token: &str) -> Result<String, ApiError> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(token_invalid());
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| token_invalid())?;
    let Issuer { iss } = serde_json::from_slice(&bytes).map_err(|_| token_invalid())?;
    if !super::valid_node_domain(&iss) || iss == state.config.domain {
        return Err(token_invalid());
    }
    Ok(iss)
}

/// Verifies a token of `iss` (after the caller applied the domain policy and rate limits).
async fn verify_foreign<T: DeserializeOwned>(
    state: &AppState,
    token: &str,
    iss: &str,
    typ: &'static str,
    max_lifetime: i64,
) -> Result<(StandardClaims, T), ApiError> {
    let expected = Expected { iss: iss.to_string(), aud: state.config.domain.clone(), typ };
    let (std, extra) = if state.config.misbehaves("accept_bad_signatures") {
        unverified::<T>(token, &expected)?
    } else {
        let kid = jwt::peek_kid(token).map_err(|_| token_invalid())?;
        let key = super::discovery::key_for(state, iss, &kid).await?;
        let verified =
            jwt::verify_with_skew::<T>(token, &key, &expected, jwt::FEDERATION_SKEW_SECS).map_err(|e| match e {
                jwt::JwtError::Expired => token_expired(),
                _ => token_invalid(),
            })?;
        super::discovery::verified(state, iss).await;
        verified
    };
    if std.iat > std.exp || std.exp - std.iat > max_lifetime || !util::is_ulid(&std.jti) {
        return Err(token_invalid());
    }
    Ok((std, extra))
}

/// `TAVRN_DEV_MISBEHAVE=accept_bad_signatures` only (development nodes that break the protocol on
/// purpose for the conformance tests): the claims are checked, header and signature are not.
fn unverified<T: DeserializeOwned>(token: &str, expected: &Expected) -> Result<(StandardClaims, T), ApiError> {
    let payload = token.split('.').nth(1).ok_or_else(token_invalid)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| token_invalid())?;
    let std: StandardClaims = serde_json::from_slice(&bytes).map_err(|_| token_invalid())?;
    let extra: T = serde_json::from_slice(&bytes).map_err(|_| token_invalid())?;
    if std.exp <= jwt::now_unix() {
        return Err(token_expired());
    }
    if std.iss != expected.iss || std.aud != expected.aud || std.typ != expected.typ {
        return Err(token_invalid());
    }
    Ok((std, extra))
}

/// Spends the `jti` of a verified token of another node (`federation.token_replayed` if seen before).
pub async fn spend_jti(state: &AppState, std: &StandardClaims) -> Result<(), ApiError> {
    if state.config.misbehaves("replay_ok") {
        // Development nodes that break the protocol on purpose (conformance tests) accept replays.
        return Ok(());
    }
    let until = chrono::DateTime::from_timestamp(std.exp + REPLAY_GRACE_SECS, 0)
        .map(util::format_time)
        .ok_or_else(token_invalid)?;
    if !store::federation::spend_jti(&state.db, &std.iss, &std.jti, &until).await? {
        return Err(token_replayed());
    }
    Ok(())
}

/// A verified federation token (before its `jti` is spent).
#[derive(Debug, Clone)]
pub struct FederationToken {
    pub std: StandardClaims,
    pub username: String,
    pub domain: String,
    pub kind: String,
    /// Bots: `(username, domain)` of the owner.
    pub owner: Option<(String, String)>,
    pub device: String,
    pub pv: i64,
    /// Bots: the application ULID on the home node.
    pub app: Option<String>,
    /// Bots: the known scopes of the token (unknown strings dropped); `None` = all scopes.
    pub scopes: Option<Vec<String>>,
    /// The signed age claim (§2.2); `None` = unknown or absent.
    pub age_over_18: Option<bool>,
}

/// Verifies a federation token of `iss` (§2.5): §2.1, `typ`, `sub` domain = `iss`, `kind`/`owner`.
pub async fn verify_federation_token(state: &AppState, token: &str, iss: &str) -> Result<FederationToken, ApiError> {
    let (std, extra): (StandardClaims, FederationExtra) =
        verify_foreign(state, token, iss, "federation", FEDERATION_TTL_SECS).await?;
    let (username, domain) = util::parse_address(&std.sub).ok_or_else(token_invalid)?;
    if domain != std.iss {
        return Err(issuer_mismatch());
    }
    let owner = match (extra.kind.as_str(), extra.owner.as_deref()) {
        ("user", None) => None,
        ("bot", Some(owner)) => {
            let (owner_name, owner_domain) = util::parse_address(owner).ok_or_else(token_invalid)?;
            if owner_domain != std.iss {
                return Err(issuer_mismatch());
            }
            Some((owner_name.to_string(), owner_domain.to_string()))
        }
        _ => return Err(token_invalid()),
    };
    if !util::is_ulid(&extra.device) || extra.pv < 0 {
        return Err(token_invalid());
    }
    // `app` and `scopes` belong to bots only (APPLICATIONS.md §2.8).
    if extra.kind != "bot" && (extra.app.is_some() || extra.scopes.is_some()) {
        return Err(token_invalid());
    }
    if extra.app.as_deref().is_some_and(|a| !util::is_ulid(a)) || extra.scopes.as_ref().is_some_and(|s| s.len() > 64) {
        return Err(token_invalid());
    }
    let scopes = extra.scopes.map(|s| {
        let known: Vec<String> = s.into_iter().filter(|x| crate::permissions::is_scope(x)).collect();
        crate::applications::intersect(&known, &crate::permissions::all_scopes())
    });
    Ok(FederationToken {
        username: username.to_string(),
        domain: domain.to_string(),
        std,
        kind: extra.kind,
        owner,
        device: extra.device,
        pv: extra.pv,
        app: extra.app,
        scopes,
        age_over_18: extra.age_over_18,
    })
}

/// Verifies a node token of `iss` for `method` and `path` (§2.3); the body hash is checked by the caller
/// against the body bytes before parsing ([`check_body`]).
pub async fn verify_node_token(
    state: &AppState,
    token: &str,
    iss: &str,
    method: &str,
    path: &str,
) -> Result<NodeClaims, ApiError> {
    let (std, extra): (StandardClaims, NodeExtra) = verify_foreign(state, token, iss, "s2s", NODE_TTL_SECS).await?;
    if std.sub != std.iss || extra.htm != method || extra.htu != path {
        return Err(token_invalid());
    }
    Ok(NodeClaims { std, htm: extra.htm, htu: extra.htu, body_sha256: extra.body_sha256 })
}

/// `401 federation.body_hash_mismatch` unless the body hashes to the token's `body_sha256`.
pub fn check_body(claims: &NodeClaims, body: &[u8]) -> Result<(), ApiError> {
    use subtle::ConstantTimeEq;
    let actual = body_sha256(body);
    if actual.as_bytes().ct_eq(claims.body_sha256.as_bytes()).into() {
        Ok(())
    } else {
        Err(ApiError::Unauthorized { code: "federation.body_hash_mismatch" })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn body_hash_is_base64url_sha256() {
        // SHA-256("") = e3b0c442…
        assert_eq!(body_sha256(b""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
        assert_ne!(body_sha256(b"{}"), body_sha256(b"{ }"));
    }

    #[test]
    fn body_check_compares_exact_bytes() {
        let claims = NodeClaims {
            std: StandardClaims {
                iss: "a.example".into(),
                sub: "a.example".into(),
                aud: "b.example".into(),
                exp: 0,
                iat: 0,
                jti: util::ulid(),
                typ: "s2s".into(),
            },
            htm: "POST".into(),
            htu: "/api/v1/federation/inbox".into(),
            body_sha256: body_sha256(b"{\"a\":1}"),
        };
        assert!(check_body(&claims, b"{\"a\":1}").is_ok());
        let err = check_body(&claims, b"{\"a\":2}").unwrap_err();
        assert_eq!(err.code(), "federation.body_hash_mismatch");
    }
}
