// SPDX-License-Identifier: AGPL-3.0-only
//! Mandatory second factor (PROTOCOL.md §5a): pre-auth tokens, TOTP, recovery
//! codes and the WebAuthn relying party.
//!
//! A password login (or registration) yields a short-lived **pre-auth token** (`typ = "preauth"`)
//! instead of a session. Only the enrollment and verification routes accept it; every other route
//! answers `401 auth.second_factor_required`. The token is spent when the session is issued.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use axum::{extract::FromRequestParts, http::request::Parts};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{Url, Uuid, Webauthn, WebauthnBuilder};
use zeroize::Zeroizing;

use crate::{
    app::AppState,
    auth::{self, AuthUser},
    config::Config,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    models::UserRow,
    routes::auth::{AuthResponse, SessionStatus},
    store,
    util::{self, format_time},
};

/// Lifetime of a pre-auth token.
pub const PREAUTH_TTL_SECS: i64 = 600;
/// Lifetime of a WebAuthn challenge.
pub const CHALLENGE_TTL_SECS: i64 = 300;
/// WebAuthn credentials per account.
pub const MAX_CREDENTIALS: i64 = 10;
/// Recovery codes per set.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// TOTP parameters (RFC 6238 defaults, what every authenticator app supports).
pub const TOTP_STEP_SECS: u64 = 30;
pub const TOTP_DIGITS: usize = 6;
const TOTP_SECRET_BYTES: usize = 20;
/// Crockford base32 without `i l o u`, lower case: unambiguous to read and type.
const RECOVERY_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

pub fn second_factor_required() -> ApiError {
    ApiError::Unauthorized { code: "auth.second_factor_required" }
}

pub fn preauth_invalid() -> ApiError {
    ApiError::Unauthorized { code: "auth.preauth_invalid" }
}

pub fn second_factor_invalid() -> ApiError {
    ApiError::Unauthorized { code: "auth.second_factor_invalid" }
}

// ---------------------------------------------------------------- Pre-auth tokens

/// What the pre-auth token allows: enrolling the first factor or verifying an existing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Enroll,
    Verify,
}

#[derive(Serialize)]
struct PreAuthClaims<'a> {
    #[serde(flatten)]
    std: StandardClaims,
    stage: Stage,
    /// Name of the device that the session will create.
    dn: &'a str,
    /// Device the session continues instead (a device proof checked at the password step, PROTOCOL.md §5b).
    #[serde(skip_serializing_if = "Option::is_none")]
    rd: Option<&'a str>,
}

#[derive(Deserialize)]
struct PreAuthExtra {
    stage: Stage,
    dn: String,
    #[serde(default)]
    rd: Option<String>,
}

/// A valid, unspent pre-auth token of an active local account.
#[derive(Debug, Clone)]
pub struct PreAuth {
    pub user: UserRow,
    pub stage: Stage,
    pub jti: String,
    pub exp: i64,
    pub device_name: String,
    /// Device to continue (proven at the password step), if any.
    pub reuse_device: Option<String>,
}

pub fn issue_preauth(
    state: &AppState,
    user_id: &str,
    stage: Stage,
    device_name: &str,
    reuse_device: Option<&str>,
) -> Result<String, ApiError> {
    let key = state.signing_key();
    let now = jwt::now_unix();
    let claims = PreAuthClaims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: user_id.to_string(),
            aud: state.config.domain.clone(),
            exp: now + PREAUTH_TTL_SECS,
            iat: now,
            jti: util::ulid(),
            typ: "preauth".into(),
        },
        stage,
        dn: device_name,
        rd: reuse_device,
    };
    jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))
}

/// Checks signature, expiry, type and that the token was not spent yet.
pub async fn verify_preauth(state: &AppState, token: &str) -> Result<PreAuth, ApiError> {
    let kid = jwt::peek_kid(token).map_err(|_| preauth_invalid())?;
    let key = state.keys.iter().find(|k| k.kid == kid).ok_or_else(preauth_invalid)?;
    let expected = Expected { iss: state.config.domain.clone(), aud: state.config.domain.clone(), typ: "preauth" };
    let (claims, extra): (StandardClaims, PreAuthExtra) =
        jwt::verify(token, &key.verifying(), &expected).map_err(|_| preauth_invalid())?;
    if store::factors::preauth_used(&state.db, &claims.jti).await? {
        return Err(preauth_invalid());
    }
    let user = store::users::by_id(&state.db, &claims.sub).await?.ok_or_else(preauth_invalid)?;
    if user.disabled_at.is_some() {
        return Err(ApiError::Unauthorized { code: "auth.account_disabled" });
    }
    Ok(PreAuth {
        user,
        stage: extra.stage,
        jti: claims.jti,
        exp: claims.exp,
        device_name: extra.dn,
        reuse_device: extra.rd,
    })
}

impl PreAuth {
    /// Enrollment routes: only stage `enroll`, and only while the account still has no factor
    /// (an enrollment token that leaked to a second party is worthless once the owner enrolled).
    pub async fn check_enroll(&self, state: &AppState) -> Result<(), ApiError> {
        if self.stage != Stage::Enroll {
            return Err(second_factor_required());
        }
        if store::factors::has_factor(&state.db, &self.user.id).await? {
            return Err(preauth_invalid());
        }
        Ok(())
    }

    /// Verification routes: only stage `verify`.
    pub fn check_verify(&self) -> Result<(), ApiError> {
        if self.stage != Stage::Verify {
            return Err(preauth_invalid());
        }
        Ok(())
    }
}

/// Session or pre-auth token from the `Authorization` header (enrollment routes).
#[derive(Debug, Clone)]
pub enum Principal {
    Session(AuthUser),
    PreAuth(PreAuth),
}

impl Principal {
    pub fn user(&self) -> &UserRow {
        match self {
            Self::Session(a) => &a.user,
            Self::PreAuth(p) => &p.user,
        }
    }

    /// For enrollment routes: a session, or a pre-auth token in stage `enroll`.
    pub async fn for_enrollment(self, state: &AppState) -> Result<(UserRow, Option<PreAuth>), ApiError> {
        match self {
            Self::Session(a) => Ok((a.user, None)),
            Self::PreAuth(p) => {
                p.check_enroll(state).await?;
                Ok((p.user.clone(), Some(p)))
            }
        }
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = auth::bearer(&parts.headers).ok_or(ApiError::Unauthorized { code: "auth.required" })?;
        match auth::authenticate(state, token).await {
            Ok(a) => {
                auth::check_route(state, &a, parts)?;
                Ok(Self::Session(a))
            }
            Err(ApiError::Unauthorized { code: "auth.second_factor_required" }) => {
                Ok(Self::PreAuth(verify_preauth(state, token).await?))
            }
            Err(e) => Err(e),
        }
    }
}

/// Ends the pre-auth phase: spends the token (once), creates the device and issues the session.
pub async fn complete(state: &AppState, pre: &PreAuth, client: &str) -> Result<AuthResponse, ApiError> {
    let exp = chrono::DateTime::from_timestamp(pre.exp, 0).map(format_time).unwrap_or_else(util::now);
    if !store::factors::spend_preauth(&state.db, &pre.jti, &exp).await? {
        return Err(preauth_invalid());
    }
    start_session(state, &pre.user, &pre.device_name, client, pre.reuse_device.as_deref(), true).await
}

/// The device of a new session: `reuse` (a device proven by a device proof) if it still is a device of `user`,
/// otherwise a new device (PROTOCOL.md §5b).
pub async fn session_device(
    state: &AppState,
    user: &UserRow,
    device_name: &str,
    client: &str,
    reuse: Option<&str>,
) -> Result<String, ApiError> {
    if let Some(id) = reuse
        && store::users::own_device(&state.db, &user.id, id).await?.is_some()
    {
        store::users::reuse_device(&state.db, &user.id, id, client).await?;
        return Ok(id.to_string());
    }
    Ok(store::users::create_device(&state.db, &user.id, device_name, client).await?.id)
}

/// Session for a fully authenticated user: on the device proven at login (`reuse`) or a new one. `proof`: the
/// login just proved the account's credentials (password with the second factor, a passkey); only then does the
/// session come with a reauth token (PROTOCOL.md §5c). A connect code exchange proves no credential and passes `false`.
pub async fn start_session(
    state: &AppState,
    user: &UserRow,
    device_name: &str,
    client: &str,
    reuse: Option<&str>,
    proof: bool,
) -> Result<AuthResponse, ApiError> {
    let device_id = session_device(state, user, device_name, client, reuse).await?;
    let tokens = auth::issue_session(state, &user.id, &device_id).await?;
    let reauth_token = if proof { Some(crate::reauth::for_new_session(state, &user.id, &tokens).await?) } else { None };
    Ok(AuthResponse {
        status: SessionStatus::Ok,
        user: user.to_private(),
        tokens,
        recovery_code_used: false,
        reauth_token,
    })
}

/// Counts a second-factor attempt (5 per 5 minutes per account, 20 per IP in production).
pub async fn limit_attempt(state: &AppState, user_id: &str, ip: &str) -> Result<(), ApiError> {
    state.second_factor_user_limiter.check_all(&[format!("2fa:{user_id}")]).await?;
    state.second_factor_ip_limiter.check_all(&[format!("2fa-ip:{ip}")]).await
}

/// Methods the user can use in the verify stage (`totp`, `webauthn`, `recovery_code`).
pub async fn verify_methods(state: &AppState, user_id: &str) -> Result<Vec<String>, ApiError> {
    let mut methods = Vec::new();
    if store::factors::totp(&state.db, user_id).await?.is_some_and(|t| t.confirmed_at.is_some()) {
        methods.push("totp".to_string());
    }
    if store::factors::count_credentials(&state.db, user_id).await? > 0 {
        methods.push("webauthn".to_string());
    }
    if !store::factors::unused_recovery_codes(&state.db, user_id).await?.is_empty() {
        methods.push("recovery_code".to_string());
    }
    Ok(methods)
}

// ---------------------------------------------------------------- TOTP

/// Key for TOTP secrets at rest: `HKDF-SHA256(salt = none, IKM = node secret, info = "tavrn totp at
/// rest v1")`, the node secret being `<data_dir>/keys/secrets.key` (not rotated).
fn totp_key(state: &AppState) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, state.secret_key.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    if hk.expand(b"tavrn totp at rest v1", out.as_mut()).is_err() {
        out.fill(0);
    }
    out
}

/// `nonce(12) || AES-256-GCM(secret)`, bound to the user id.
pub fn encrypt_totp_secret(state: &AppState, user_id: &str, secret: &[u8]) -> Result<Vec<u8>, ApiError> {
    let mut nonce = [0u8; 12];
    crate::util::fill_random(&mut nonce);
    let cipher = Aes256Gcm::new((&*totp_key(state)).into());
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: secret, aad: user_id.as_bytes() })
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("TOTP secret not encryptable")))?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn decrypt_totp_secret(state: &AppState, user_id: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let fail = || ApiError::Internal(anyhow::anyhow!("TOTP secret not decryptable (secrets.key replaced or lost?)"));
    if blob.len() < 12 + 16 {
        return Err(fail());
    }
    let cipher = Aes256Gcm::new((&*totp_key(state)).into());
    cipher
        .decrypt(blob[..12].try_into().map_err(|_| fail())?, Payload { msg: &blob[12..], aad: user_id.as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| fail())
}

/// TOTP generator for a secret; `account` appears in authenticator apps.
pub fn totp(secret: &[u8], issuer: &str, account: &str) -> Result<totp_rs::Totp, ApiError> {
    totp_rs::Builder::new()
        .with_secret(secret.to_vec())
        .with_digits(TOTP_DIGITS as u8)
        .with_step_duration(TOTP_STEP_SECS)
        .with_skew(1)
        .with_issuer(Some(issuer))
        .with_account_name(account)
        .build()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("TOTP: {e}")))
}

/// A fresh random secret (160 bits, RFC 4226 recommendation).
pub fn new_totp_secret() -> Zeroizing<Vec<u8>> {
    let mut secret = Zeroizing::new(vec![0u8; TOTP_SECRET_BYTES]);
    crate::util::fill_random(&mut secret);
    secret
}

/// Checks a code against the user's TOTP secret (±1 step) and accepts every step only once.
/// `confirmed` selects the active secret (`true`) or the one being enrolled (`false`).
pub async fn check_totp(state: &AppState, user: &UserRow, code: &str, confirmed: bool) -> Result<bool, ApiError> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != TOTP_DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let Some(row) = store::factors::totp(&state.db, &user.id).await? else { return Ok(false) };
    if row.confirmed_at.is_some() != confirmed {
        return Ok(false);
    }
    let secret = decrypt_totp_secret(state, &user.id, &row.secret)?;
    let generator = totp(&secret, &state.config.domain, &user.address())?;
    let now = u64::try_from(jwt::now_unix()).unwrap_or(0);
    let Some(step) = generator.check(&code, now) else { return Ok(false) };
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    store::factors::use_totp_step(&state.db, &user.id, step).await
}

// ---------------------------------------------------------------- Recovery codes

fn hash_recovery_code(salt: &str, code: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest([salt.as_bytes(), b"\0", code.as_bytes()].concat()))
}

/// `"AB12 cd34-EF56"` → `"ab12cd34ef56"`; `None` if it cannot be a code.
fn normalize_recovery_code(code: &str) -> Option<String> {
    let n: String = code.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_lowercase()).collect();
    (n.len() == 12 && n.bytes().all(|b| RECOVERY_ALPHABET.contains(&b))).then_some(n)
}

/// Ten new codes `xxxx-xxxx-xxxx` (60 random bits each); replaces the previous set.
pub async fn new_recovery_codes(state: &AppState, user_id: &str) -> Result<Vec<String>, ApiError> {
    let mut rng = util::os_rng();
    let codes: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let chars: Vec<char> =
                (0..12).map(|_| char::from(RECOVERY_ALPHABET[(rng.next_u32() & 31) as usize])).collect();
            format!(
                "{}-{}-{}",
                chars[0..4].iter().collect::<String>(),
                chars[4..8].iter().collect::<String>(),
                chars[8..12].iter().collect::<String>()
            )
        })
        .collect();
    let salt = util::random_token(16);
    let hashes: Vec<String> =
        codes.iter().filter_map(|c| normalize_recovery_code(c)).map(|c| hash_recovery_code(&salt, &c)).collect();
    store::factors::replace_recovery_codes(&state.db, user_id, &salt, &hashes).await?;
    Ok(codes)
}

/// Recovery codes for the first factor of an account (`None` if the account already has a set).
pub async fn first_factor_codes(state: &AppState, user_id: &str) -> Result<Option<Vec<String>>, ApiError> {
    if store::factors::has_recovery_codes(&state.db, user_id).await? {
        return Ok(None);
    }
    Ok(Some(new_recovery_codes(state, user_id).await?))
}

/// Consumes a matching unused recovery code (constant-time comparison of the hashes).
pub async fn use_recovery_code(state: &AppState, user_id: &str, code: &str) -> Result<bool, ApiError> {
    let Some(code) = normalize_recovery_code(code) else { return Ok(false) };
    for (id, salt, hash) in store::factors::unused_recovery_codes(&state.db, user_id).await? {
        if bool::from(hash_recovery_code(&salt, &code).as_bytes().ct_eq(hash.as_bytes())) {
            return store::factors::use_recovery_code(&state.db, &id).await;
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------- WebAuthn

/// The relying party: id = `TAVRN_WEBAUTHN_RP_ID` (default: the identity domain), origin =
/// `TAVRN_WEBAUTHN_ORIGIN` (default: the public URL).
pub fn build_webauthn(config: &Config) -> anyhow::Result<Webauthn> {
    let origin = Url::parse(&config.webauthn_origin())?;
    let rp_id = config.webauthn_rp_id();
    let builder = WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|e| anyhow::anyhow!("invalid WebAuthn configuration: {e}"))?
        .rp_name(&config.name)
        // Development: the Vite dev server and the node run on different ports.
        .allow_any_port(config.dev);
    builder.build().map_err(|e| anyhow::anyhow!("invalid WebAuthn configuration: {e}"))
}

/// WebAuthn user handle: the 16 bytes of the user's ULID.
pub fn user_handle(user_id: &str) -> Result<Uuid, ApiError> {
    ulid::Ulid::from_string(user_id)
        .map(|u| Uuid::from_u128(u.0))
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("user id is not a ULID")))
}

pub fn user_id_from_handle(handle: Uuid) -> String {
    ulid::Ulid(handle.as_u128()).to_string()
}

/// base64url credential id (path segment, method label).
pub fn credential_id_b64(id: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(id)
}

/// `true` for a syntactically valid base64url credential id (at most 1023 bytes).
pub fn valid_credential_id(id: &str) -> bool {
    tavrn_crypto::secret_storage::valid_method(&format!("passkey:{id}"))
}

/// Options as sent to the browser: resident key preferred (passkey-only login), the PRF extension
/// requested with tavrn's fixed input, and no forced conditional mediation (the client decides).
pub fn browser_options(options: impl Serialize) -> Result<Value, ApiError> {
    let mut v = serde_json::to_value(options).map_err(|e| ApiError::Internal(e.into()))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("mediation");
    }
    let prf_input = URL_SAFE_NO_PAD.encode(tavrn_crypto::secret_storage::PRF_INPUT);
    if let Some(pk) = v.get_mut("publicKey").and_then(Value::as_object_mut) {
        if let Some(sel) = pk.get_mut("authenticatorSelection").and_then(Value::as_object_mut) {
            sel.insert("residentKey".into(), Value::from("preferred"));
            sel.insert("requireResidentKey".into(), Value::from(false));
        }
        let ext = pk.entry("extensions").or_insert_with(|| Value::Object(Default::default()));
        if !ext.is_object() {
            *ext = Value::Object(Default::default());
        }
        if let Some(ext) = ext.as_object_mut() {
            ext.insert("prf".into(), serde_json::json!({ "eval": { "first": prf_input } }));
        }
    }
    Ok(v)
}

fn client_extension_results(response: &Value) -> Option<&Value> {
    response.get("clientExtensionResults").or_else(|| response.get("extensions"))
}

/// A PRF *result* is the secret that wraps the master secret; it must never reach the node.
pub fn reject_prf_output(response: &Value) -> Result<(), ApiError> {
    let leaked = client_extension_results(response).and_then(|e| e.get("prf")).and_then(|p| p.get("results"));
    if leaked.is_some() {
        tracing::warn!("client sent a PRF result to the node; request refused");
        return Err(ApiError::BadRequest {
            code: "webauthn.prf_output_sent",
            detail: "The PRF result must never leave the client (remove clientExtensionResults.prf.results)".into(),
        });
    }
    Ok(())
}

/// The client's (unsigned) report whether the credential supports the PRF extension.
pub fn prf_enabled(response: &Value) -> bool {
    client_extension_results(response)
        .and_then(|e| e.get("prf"))
        .and_then(|p| p.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn recovery_codes_normalize_and_hash() {
        assert_eq!(normalize_recovery_code(" AB12-cd34 ef56 "), Some("ab12cd34ef56".into()));
        for bad in ["", "ab12-cd34", "ab12-cd34-ef56-gh78", "ab12-cd34-efi6", "ab12-cd34-ef5!"] {
            assert_eq!(normalize_recovery_code(bad), None, "{bad}");
        }
        assert_eq!(hash_recovery_code("s", "a"), hash_recovery_code("s", "a"));
        assert_ne!(hash_recovery_code("s", "a"), hash_recovery_code("t", "a"), "the salt matters");
    }

    #[test]
    fn user_handles_roundtrip() {
        let id = util::ulid();
        assert_eq!(user_id_from_handle(user_handle(&id).unwrap()), id);
        assert!(user_handle("not-a-ulid").is_err());
    }

    #[test]
    fn prf_results_are_detected_in_both_spellings() {
        let ok = serde_json::json!({ "clientExtensionResults": { "prf": { "enabled": true } } });
        assert!(reject_prf_output(&ok).is_ok());
        assert!(prf_enabled(&ok));
        let leak = serde_json::json!({ "clientExtensionResults": { "prf": { "results": { "first": "x" } } } });
        assert!(reject_prf_output(&leak).is_err());
        let leak = serde_json::json!({ "extensions": { "prf": { "results": {} } } });
        assert!(reject_prf_output(&leak).is_err());
        assert!(!prf_enabled(&serde_json::json!({})));
    }

    #[test]
    fn browser_options_request_prf_and_resident_keys() {
        let v = browser_options(serde_json::json!({
            "publicKey": { "authenticatorSelection": { "requireResidentKey": false, "userVerification": "required" },
                           "extensions": { "uvm": true } },
            "mediation": "conditional"
        }))
        .unwrap();
        assert!(v.get("mediation").is_none());
        assert_eq!(v["publicKey"]["authenticatorSelection"]["residentKey"], "preferred");
        assert_eq!(v["publicKey"]["extensions"]["uvm"], true);
        assert_eq!(v["publicKey"]["extensions"]["prf"]["eval"]["first"], "dGF2cm4gc2VjcmV0IHN0b3JhZ2UgcHJmIHYx");
    }

    #[test]
    fn credential_ids_are_validated() {
        assert!(valid_credential_id("AbC-_09"));
        assert!(!valid_credential_id(""));
        assert!(!valid_credential_id("a b"));
        assert!(!valid_credential_id("a/b"));
        assert!(!valid_credential_id(&"a".repeat(2000)));
    }
}
