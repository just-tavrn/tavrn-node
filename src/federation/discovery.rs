// SPDX-License-Identifier: AGPL-3.0-only
//! Discovery documents of peers and their signing keys (FEDERATION.md §1.1, §1.2, §1.4).
//!
//! A peer's `/.well-known/tavrn` is fetched on first need, validated and cached in `federation_peers`
//! for the response's `max-age` clamped to 5 minutes – 1 hour. Its `api` endpoint (delegation to another
//! host) is cached by the federation client with the same lifetime. An expired document is refetched; if
//! that fails, the stale copy is never used to verify anything. A token naming an unknown `kid` causes
//! one refetch at most every 5 minutes per peer, and so does an endpoint that moved (the client resolved the
//! domain again after a transport failure). A `kid` that later names a different key is a hard
//! failure: the peer stays blocked (`status = key_conflict`) until an operator clears it.

use std::time::Instant;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use crate::{app::AppState, error::ApiError, store, util};

pub const PATH: &str = "/.well-known/tavrn";
pub const STATUS_OK: &str = "ok";
pub const STATUS_KEY_CONFLICT: &str = "key_conflict";
/// Cache lifetime bounds (§1.4).
pub const MIN_TTL_SECS: u64 = 300;
pub const MAX_TTL_SECS: u64 = 3600;
/// At most one unknown-`kid` refetch per peer in this interval.
pub const KID_REFRESH_SECS: i64 = 300;
pub const MAX_KEYS: usize = 10;
/// The protocol major version this node speaks.
pub const PROTOCOL_MAJOR: u64 = 1;

#[derive(Debug, Clone)]
pub struct PeerKey {
    pub kid: String,
    /// base64url of the 32-byte public key, as published.
    pub x: String,
    pub key: VerifyingKey,
}

/// The parts of a validated discovery document this node uses.
#[derive(Debug, Clone)]
pub struct PeerDocument {
    pub domain: String,
    pub capabilities: Vec<String>,
    pub keys: Vec<PeerKey>,
}

impl PeerDocument {
    pub fn key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.iter().find(|k| k.kid == kid).map(|k| k.key)
    }
}

/// Cache lifetime of a document (and its endpoints): `max-age` clamped to 5 minutes – 1 hour.
pub fn ttl(max_age: Option<u64>) -> u64 {
    max_age.unwrap_or(MIN_TTL_SECS).clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

pub fn peer_invalid(domain: &str, reason: &str) -> ApiError {
    ApiError::BadGateway {
        code: "federation.peer_invalid",
        detail: format!("The node {domain} serves an invalid discovery document ({reason})"),
    }
}

fn valid_kid(kid: &str) -> bool {
    (1..=64).contains(&kid.len()) && kid.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Validates a discovery document fetched for `domain` (§1.4): known protocol major version, `domain`
/// equal to the requested domain, `federation.v1` announced, 1–10 well-formed Ed25519 keys with unique
/// `kid`s. Unknown fields are ignored. The error is a short reason for logs and the problem detail.
pub fn validate(domain: &str, body: &[u8]) -> Result<PeerDocument, &'static str> {
    let doc: Value = serde_json::from_slice(body).map_err(|_| "not JSON")?;
    if doc.get("tavrn").and_then(Value::as_u64) != Some(PROTOCOL_MAJOR) {
        return Err("unknown protocol version");
    }
    if doc.get("domain").and_then(Value::as_str) != Some(domain) {
        return Err("domain does not match");
    }
    for field in ["api", "ws"] {
        if !doc.get(field).is_some_and(Value::is_string) {
            return Err("required field missing");
        }
    }
    let capabilities: Vec<String> = doc
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or("capabilities missing")?
        .iter()
        .filter_map(|c| c.as_str().map(String::from))
        .collect();
    if !capabilities.iter().any(|c| c == super::CAPABILITY) {
        return Err("federation.v1 missing");
    }
    let raw_keys = doc.get("keys").and_then(Value::as_array).ok_or("keys missing")?;
    if raw_keys.is_empty() || raw_keys.len() > MAX_KEYS {
        return Err("expected 1 to 10 keys");
    }
    let mut keys: Vec<PeerKey> = Vec::with_capacity(raw_keys.len());
    for k in raw_keys {
        let kid = k.get("kid").and_then(Value::as_str).filter(|kid| valid_kid(kid)).ok_or("invalid kid")?;
        if k.get("alg").and_then(Value::as_str) != Some("EdDSA")
            || k.get("crv").and_then(Value::as_str) != Some("Ed25519")
        {
            return Err("invalid key type");
        }
        let x = k.get("x").and_then(Value::as_str).ok_or("x missing")?;
        let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(x).ok().and_then(|b| b.try_into().ok()).ok_or("invalid key")?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid key")?;
        if key.is_weak() {
            return Err("invalid key");
        }
        if keys.iter().any(|existing| existing.kid == kid) {
            return Err("duplicate kid");
        }
        keys.push(PeerKey { kid: kid.to_string(), x: x.to_string(), key });
    }
    Ok(PeerDocument { domain: domain.to_string(), capabilities, keys })
}

/// The peer's current, validated document: from the cache while fresh, otherwise fetched. A cached copy is
/// also refetched once the peer's endpoint moved (the federation client found a new one after a failure).
pub async fn document(state: &AppState, domain: &str) -> Result<PeerDocument, ApiError> {
    document_for(state, domain, false).await
}

/// [`document`] for checking the signature of a request that names `domain` as its issuer (§1.4): before the
/// signature is checked anyone can name any domain, so a recent failure is answered from the negative cache and a
/// domain this node has no row for counts against the cap of unverified peers.
async fn document_for(state: &AppState, domain: &str, unverified: bool) -> Result<PeerDocument, ApiError> {
    super::check_policy(state, domain).await?;
    let row = store::federation::peer(&state.db, domain).await?;
    if !state.federation.take_stale_document(domain)
        && let Some(row) = &row
        && row.status == STATUS_OK
        && row.expires_at > util::now()
        && let Ok(doc) = validate(domain, row.document.as_bytes())
    {
        let left = util::parse_time(&row.expires_at).map(|t| (t - Utc::now()).num_seconds().max(0) as u64);
        state.federation.seed_delegation(domain, row.document.as_bytes(), left.unwrap_or(0));
        return Ok(doc);
    }
    if unverified {
        if let Some(e) = state.federation.recent_discovery_failure(domain) {
            return Err(e);
        }
        if row.is_none()
            && store::federation::count_unverified_peers(&state.db).await?
                >= i64::from(state.config.federation_max_unverified_peers)
        {
            tracing::warn!(domain, "unverified peer limit reached, request refused before any fetch");
            return Err(ApiError::Unavailable {
                code: "federation.peer_limit",
                detail: "This node accepts requests from no further unknown nodes at the moment".into(),
            });
        }
    }
    fetch(state, domain).await
}

/// Fetches, validates and caches the document of `domain`. A failure is remembered for 60 seconds (§1.4).
pub async fn fetch(state: &AppState, domain: &str) -> Result<PeerDocument, ApiError> {
    let result = fetch_inner(state, domain).await;
    match &result {
        Ok(_) => state.federation.clear_discovery_failure(domain),
        // Only peer errors (502) are remembered; a block is final until an operator acts anyway.
        Err(e) => state.federation.note_discovery_failure(domain, e),
    }
    result
}

async fn fetch_inner(state: &AppState, domain: &str) -> Result<PeerDocument, ApiError> {
    let started = Instant::now();
    let (fetched, source) = match state.federation.get_well_known(domain).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(domain, result = %e.label(), ms = started.elapsed().as_millis() as u64, "federation document fetch failed");
            return Err(e.to_api());
        }
    };
    let doc = match validate(domain, &fetched.body) {
        Ok(doc) => doc,
        Err(reason) => {
            tracing::warn!(domain, reason, "federation document invalid");
            return Err(peer_invalid(domain, reason));
        }
    };
    let ttl = ttl(fetched.max_age);
    if let Err(reason) = state.federation.record_delegation(domain, &fetched.body, ttl, source) {
        tracing::warn!(domain, reason, "federation document names unusable endpoints");
        return Err(peer_invalid(domain, reason));
    }
    let known = store::federation::peer_keys(&state.db, domain).await?;
    for key in &doc.keys {
        if known.iter().any(|(kid, x)| kid == &key.kid && x != &key.x) {
            tracing::error!(
                domain,
                kid = key.kid,
                "federation key conflict: a kid now names another key, peer blocked"
            );
            return Err(key_conflict(state, domain).await);
        }
    }
    // A document from another source than before (well-known → SRV or back) with none of the keys seen before
    // looks exactly like a takeover; a real move keeps a key during the change (§1.2, §1.4).
    let source_name = source_name(source);
    if let Some(previous) = store::federation::peer_source(&state.db, domain).await?
        && previous != source_name
        && !known.is_empty()
        && !doc.keys.iter().any(|k| known.iter().any(|(kid, x)| kid == &k.kid && x == &k.x))
    {
        tracing::error!(
            domain,
            from = previous,
            to = source_name,
            "federation key conflict: the document moved to another source with an entirely new key set, peer blocked"
        );
        return Err(key_conflict(state, domain).await);
    }
    for key in &doc.keys {
        store::federation::add_peer_key(&state.db, domain, &key.kid, &key.x).await?;
    }
    let now = Utc::now();
    let body = String::from_utf8(fetched.body).map_err(|_| peer_invalid(domain, "not UTF-8"))?;
    store::federation::upsert_peer(
        &state.db,
        domain,
        &body,
        &util::format_time(now),
        &util::format_time(now + chrono::Duration::seconds(ttl as i64)),
        source_name,
    )
    .await?;
    tracing::info!(
        domain,
        result = "ok",
        ttl,
        ms = started.elapsed().as_millis() as u64,
        "federation document fetched"
    );
    Ok(doc)
}

/// The stored name of a document source.
fn source_name(source: super::client::DelegationSource) -> &'static str {
    match source {
        super::client::DelegationSource::Srv => "srv",
        _ => "well_known",
    }
}

/// Blocks the peer after a key conflict (`status = key_conflict` until an operator decides), records the violation
/// (§9.4) and ends the federated sessions of its users here (§2.5). Returns the error for the request.
pub async fn key_conflict(state: &AppState, domain: &str) -> ApiError {
    mark_key_conflict(state, domain).await;
    super::peer_blocked(domain)
}

/// The side effects of [`key_conflict`]; failures are logged.
pub async fn mark_key_conflict(state: &AppState, domain: &str) {
    if let Err(e) = store::federation::set_peer_status(&state.db, domain, STATUS_KEY_CONFLICT).await {
        tracing::warn!(error = %e, domain, "storing the key conflict failed");
    }
    super::conformance::violation(state, domain, super::conformance::VIOLATION_KEY_CONFLICT).await;
    if let Err(e) = super::conformance::end_sessions(state, domain).await {
        tracing::warn!(error = %e, domain, "ending the sessions of a conflicting peer failed");
    }
}

/// The key `kid` of `domain`, fetched only from that domain's own document, to check the signature of a request
/// naming `domain` as its issuer. An unknown `kid` refetches the document once (at most every 5 minutes per
/// peer), then fails with `federation.token_invalid`.
pub async fn key_for(state: &AppState, domain: &str, kid: &str) -> Result<VerifyingKey, ApiError> {
    let doc = document_for(state, domain, true).await?;
    if let Some(key) = doc.key(kid) {
        return Ok(key);
    }
    let now = Utc::now();
    let cutoff = util::format_time(now - chrono::Duration::seconds(KID_REFRESH_SECS));
    if state.federation.recent_discovery_failure(domain).is_none()
        && store::federation::claim_kid_refresh(&state.db, domain, &util::format_time(now), &cutoff).await?
    {
        tracing::info!(domain, "unknown kid, refetching the document");
        if let Some(key) = fetch(state, domain).await?.key(kid) {
            return Ok(key);
        }
    }
    Err(super::tokens::token_invalid())
}

/// Records that a signed request of `domain` verified with its keys (§1.4: the peer is no longer unverified).
pub async fn verified(state: &AppState, domain: &str) {
    let now = Utc::now();
    let cutoff = util::format_time(now - chrono::Duration::days(1));
    if let Err(e) = store::federation::mark_peer_verified(&state.db, domain, &util::format_time(now), &cutoff).await {
        tracing::debug!(error = %e, domain, "peer verification not recorded");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde_json::json;

    use super::*;

    fn key_x() -> String {
        URL_SAFE_NO_PAD.encode(crate::keys::NodeKey::generate("k").verifying().as_bytes())
    }

    fn doc() -> Value {
        json!({
            "tavrn": 1, "domain": "a.example", "api": "https://a.example/api/v1", "ws": "wss://a.example/api/v1/ws",
            "software": { "name": "x", "version": "1" }, "capabilities": ["federation", "federation.v1"],
            "keys": [{ "kid": "2026-10-04", "alg": "EdDSA", "crv": "Ed25519", "x": key_x() }],
            "unknown_field": { "ignored": true }
        })
    }

    fn check(v: &Value) -> Result<PeerDocument, &'static str> {
        validate("a.example", v.to_string().as_bytes())
    }

    /// The protocol's reference values (`testvectors/federation_node.json`): the valid document passes, every
    /// invalid one is refused with the published reason, and the node and listing tokens verify with the published
    /// key and are reproduced byte for byte by this node's signer.
    #[test]
    fn the_published_discovery_and_token_vectors() {
        let v: Value =
            serde_json::from_str(include_str!("../../protocol/testvectors/federation_node.json")).expect("vectors");
        let domain = v["discovery"]["for_domain"].as_str().unwrap();
        let doc = validate(domain, v["discovery"]["valid"].to_string().as_bytes()).unwrap();
        let x = v["signing_key"]["x"].as_str().unwrap();
        assert_eq!(doc.keys[0].x, x);
        for case in v["discovery"]["invalid"].as_array().unwrap() {
            let reason = case["reason"].as_str().unwrap();
            assert_eq!(validate(domain, case["document"].to_string().as_bytes()).err(), Some(reason), "{reason}");
        }
        let seed: [u8; 32] =
            URL_SAFE_NO_PAD.decode(v["signing_key"]["seed"].as_str().unwrap()).unwrap().try_into().unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()), x);
        let kid = v["signing_key"]["kid"].as_str().unwrap();
        assert_eq!(doc.key(kid), Some(signing.verifying_key()));
        for name in ["s2s_token", "listing_token"] {
            let token = v[name]["token"].as_str().unwrap();
            assert_eq!(crate::jwt::sign(&signing, kid, &v[name]["claims"]).unwrap(), token, "{name} reproduced");
            assert_eq!(crate::jwt::peek_kid(token).unwrap(), kid);
            let (signed, sig) = token.rsplit_once('.').unwrap();
            let sig = ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig).unwrap()).unwrap();
            doc.key(kid).unwrap().verify_strict(signed.as_bytes(), &sig).unwrap();
            let mut tampered = signed.to_string();
            tampered.push('A');
            assert!(doc.key(kid).unwrap().verify_strict(tampered.as_bytes(), &sig).is_err(), "{name}");
        }
        let s2s = &v["s2s_token"];
        let hash = crate::federation::tokens::body_sha256(s2s["body"].as_str().unwrap().as_bytes());
        assert_eq!(hash, s2s["body_sha256"].as_str().unwrap());
        assert_eq!(s2s["claims"]["body_sha256"].as_str().unwrap(), hash);
        assert_ne!(crate::federation::tokens::body_sha256(b"{}"), hash, "another body, another hash");
    }

    #[test]
    fn valid_document_passes() {
        let d = check(&doc()).unwrap();
        assert_eq!(d.domain, "a.example");
        assert_eq!(d.keys.len(), 1);
        assert!(d.key("2026-10-04").is_some());
        assert!(d.key("other").is_none());
    }

    #[test]
    fn invalid_documents_are_refused() {
        let mutate = |f: &dyn Fn(&mut Value)| {
            let mut d = doc();
            f(&mut d);
            check(&d).err()
        };
        assert_eq!(validate("a.example", b"<html>").err(), Some("not JSON"));
        assert_eq!(mutate(&|d| d["tavrn"] = json!(2)), Some("unknown protocol version"));
        assert_eq!(mutate(&|d| d["tavrn"] = json!("1")), Some("unknown protocol version"));
        assert_eq!(mutate(&|d| d["domain"] = json!("evil.example")), Some("domain does not match"));
        assert_eq!(mutate(&|d| d["domain"] = json!("A.example")), Some("domain does not match"));
        assert_eq!(
            mutate(&|d| d.as_object_mut().unwrap().remove("api").map(|_| ()).unwrap()),
            Some("required field missing")
        );
        assert_eq!(mutate(&|d| d["capabilities"] = json!(["federation"])), Some("federation.v1 missing"));
        assert_eq!(mutate(&|d| d["keys"] = json!([])), Some("expected 1 to 10 keys"));
        let eleven: Vec<Value> = (0..11)
            .map(|i| json!({ "kid": format!("k{i}"), "alg": "EdDSA", "crv": "Ed25519", "x": key_x() }))
            .collect();
        assert_eq!(mutate(&|d| d["keys"] = json!(eleven)), Some("expected 1 to 10 keys"));
        assert_eq!(mutate(&|d| d["keys"][0]["kid"] = json!("a b")), Some("invalid kid"));
        assert_eq!(mutate(&|d| d["keys"][0]["kid"] = json!("x".repeat(65))), Some("invalid kid"));
        assert_eq!(mutate(&|d| d["keys"][0]["alg"] = json!("RS256")), Some("invalid key type"));
        assert_eq!(mutate(&|d| d["keys"][0]["crv"] = json!("X25519")), Some("invalid key type"));
        assert_eq!(mutate(&|d| d["keys"][0]["x"] = json!("AAAA")), Some("invalid key"));
        // A small-order point is a weak key.
        let weak = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert_eq!(mutate(&|d| d["keys"][0]["x"] = json!(weak)), Some("invalid key"));
        let duplicate = |d: &mut Value| {
            let mut second = d["keys"][0].clone();
            second["x"] = json!(key_x());
            d["keys"].as_array_mut().unwrap().push(second);
        };
        assert_eq!(mutate(&duplicate), Some("duplicate kid"));
    }
}
