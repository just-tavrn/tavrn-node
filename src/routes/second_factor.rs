// SPDX-License-Identifier: AGPL-3.0-only
//! Second factor routes (PROTOCOL.md §5a): TOTP, recovery codes, WebAuthn
//! (second factor and passkey-only login) and completing a pre-auth token.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, WebauthnError,
};

use crate::{
    app::AppState,
    auth::{AuthUser, ClientIp},
    config::EmailMode,
    error::{ApiError, ApiJson, ProblemDetails},
    models::UserRow,
    routes::auth::{AuthResponse, client_header, device_name},
    second_factor::{self as sf, PreAuth, Principal},
    store::{
        self,
        factors::{CredentialRow, Factor, InsertCredential, NewCredential, RemoveFactor},
    },
    validate::{self, bad},
};

/// Body limit of the WebAuthn finish routes (attestation `none` keeps responses small).
pub const WEBAUTHN_BODY_LIMIT: usize = 64 * 1024;

fn challenge_invalid() -> ApiError {
    bad("webauthn.challenge_invalid", "WebAuthn ceremony unknown, expired or already used")
}

fn credential_not_found() -> ApiError {
    ApiError::NotFound { code: "webauthn.not_found", what: "Security key".into() }
}

fn last_factor() -> ApiError {
    ApiError::conflict("auth.last_factor", "The last second factor cannot be removed; set up another one first")
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(anyhow::anyhow!("WebAuthn: {e}"))
}

async fn audit(state: &AppState, user: &UserRow, action: &str, meta: Value) -> Result<(), ApiError> {
    store::rooms::audit(&state.db, None, Some(&user.id), action, &user.address(), "", meta).await
}

/// Checks the current password (rate-limited like the login).
/// Sudo mode (PROTOCOL.md §5c) for a change made with a session; enrollment with a pre-auth token is the login itself.
async fn require_reauth(state: &AppState, principal: &Principal, headers: &HeaderMap) -> Result<(), ApiError> {
    match principal {
        Principal::Session(auth) => crate::reauth::require(state, auth, headers).await,
        Principal::PreAuth(_) => Ok(()),
    }
}

// ---------------------------------------------------------------- Verification

#[derive(Deserialize, ToSchema)]
pub struct VerifyRequest {
    /// From the login (stage `verify`).
    pub preauth_token: String,
    /// Current 6-digit code of the authenticator app.
    pub totp_code: Option<String>,
    /// One of the recovery codes (`xxxx-xxxx-xxxx`; case, spaces and dashes are ignored).
    pub recovery_code: Option<String>,
}

/// Completes a password login with a TOTP code or a recovery code; returns the session.
#[utoipa::path(post, path = "/api/v1/auth/second-factor/verify", request_body = VerifyRequest,
    responses((status = 200, body = AuthResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<VerifyRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let pre = sf::verify_preauth(&state, &req.preauth_token).await?;
    pre.check_verify()?;
    if req.totp_code.is_none() && req.recovery_code.is_none() {
        return Err(bad("auth.second_factor_missing", "Provide a TOTP code or a recovery code"));
    }
    sf::limit_attempt(&state, &pre.user.id, &ip).await?;
    let (ok, recovery) = match (&req.totp_code, &req.recovery_code) {
        (Some(code), _) => (sf::check_totp(&state, &pre.user, code, true).await?, false),
        (None, Some(code)) => (sf::use_recovery_code(&state, &pre.user.id, code).await?, true),
        (None, None) => (false, false),
    };
    if !ok {
        return Err(sf::second_factor_invalid());
    }
    let mut session = sf::complete(&state, &pre, &client_header(&headers)).await?;
    if recovery {
        session.recovery_code_used = true;
        let left = store::factors::unused_recovery_codes(&state.db, &pre.user.id).await?.len();
        audit(&state, &pre.user, "user.recovery_code_used", json!({ "ip": ip, "left": left })).await?;
    }
    Ok(Json(session))
}

#[derive(Serialize, ToSchema)]
pub struct WebauthnCredential {
    /// base64url WebAuthn credential id (also used in paths).
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// The credential supports the PRF extension (can unlock the secret storage).
    pub prf_supported: bool,
}

impl From<&CredentialRow> for WebauthnCredential {
    fn from(c: &CredentialRow) -> Self {
        Self {
            id: c.credential_id.clone(),
            name: c.name.clone(),
            created_at: c.created_at.clone(),
            last_used_at: c.last_used_at.clone(),
            prf_supported: c.prf_supported != 0,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct Factors {
    pub totp: bool,
    pub webauthn: Vec<WebauthnCredential>,
    pub recovery_codes_left: i64,
}

/// The account's second factors.
#[utoipa::path(get, path = "/api/v1/auth/factors", security(("bearer" = [])), responses((status = 200, body = Factors), (status = 401, body = ProblemDetails)))]
pub async fn factors(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Factors>, ApiError> {
    let totp = store::factors::totp(&state.db, &auth.user.id).await?.is_some_and(|t| t.confirmed_at.is_some());
    let creds = store::factors::credentials(&state.db, &auth.user.id).await?;
    let left = store::factors::unused_recovery_codes(&state.db, &auth.user.id).await?.len();
    Ok(Json(Factors {
        totp,
        webauthn: creds.iter().map(WebauthnCredential::from).collect(),
        recovery_codes_left: i64::try_from(left).unwrap_or(0),
    }))
}

// ---------------------------------------------------------------- TOTP

#[derive(Serialize, ToSchema)]
pub struct TotpEnrollment {
    /// Base32 secret for manual entry.
    pub secret: String,
    /// `otpauth://totp/…` for a QR code.
    pub otpauth_url: String,
    pub issuer: String,
}

/// Starts a TOTP enrollment (session or pre-auth token in stage `enroll`). Replaces an
/// unconfirmed enrollment; a confirmed TOTP must be removed first.
#[utoipa::path(post, path = "/api/v1/auth/totp/enroll", security(("bearer" = [])),
    responses((status = 200, body = TotpEnrollment), (status = 401, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn totp_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Json<TotpEnrollment>, ApiError> {
    require_reauth(&state, &principal, &headers).await?;
    let (user, _) = principal.for_enrollment(&state).await?;
    let secret = sf::new_totp_secret();
    let encrypted = sf::encrypt_totp_secret(&state, &user.id, &secret)?;
    if !store::factors::put_pending_totp(&state.db, &user.id, &encrypted).await? {
        return Err(totp_exists());
    }
    let totp = sf::totp(&secret, &state.config.domain, &user.address())?;
    Ok(Json(TotpEnrollment {
        secret: totp.secret().to_base32(),
        otpauth_url: totp.to_url().map_err(internal)?,
        issuer: state.config.domain.clone(),
    }))
}

fn totp_exists() -> ApiError {
    ApiError::conflict("auth.totp_exists", "TOTP is already set up; remove it first")
}

#[derive(Deserialize, ToSchema)]
pub struct TotpConfirmRequest {
    pub code: String,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollmentResult {
    /// Ten single-use codes, shown once. Only set when the account had none yet (first factor).
    pub recovery_codes: Option<Vec<String>>,
    /// The session, when the enrollment was done with a pre-auth token (stage `enroll`).
    pub session: Option<AuthResponse>,
}

/// Activates the enrolled TOTP with a current code.
#[utoipa::path(post, path = "/api/v1/auth/totp/confirm", security(("bearer" = [])), request_body = TotpConfirmRequest,
    responses((status = 200, body = EnrollmentResult), (status = 401, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn totp_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    principal: Principal,
    ApiJson(req): ApiJson<TotpConfirmRequest>,
) -> Result<Json<EnrollmentResult>, ApiError> {
    require_reauth(&state, &principal, &headers).await?;
    let (user, pre) = principal.for_enrollment(&state).await?;
    match store::factors::totp(&state.db, &user.id).await? {
        None => return Err(ApiError::NotFound { code: "auth.totp_not_found", what: "TOTP enrollment".into() }),
        Some(t) if t.confirmed_at.is_some() => return Err(totp_exists()),
        Some(_) => {}
    }
    sf::limit_attempt(&state, &user.id, &ip).await?;
    if !sf::check_totp(&state, &user, &req.code, false).await? {
        return Err(sf::second_factor_invalid());
    }
    store::factors::confirm_totp(&state.db, &user.id).await?;
    audit(&state, &user, "user.second_factor_enroll", json!({ "method": "totp" })).await?;
    finish_enrollment(&state, &user, pre, &headers).await.map(Json)
}

async fn finish_enrollment(
    state: &AppState,
    user: &UserRow,
    pre: Option<PreAuth>,
    headers: &HeaderMap,
) -> Result<EnrollmentResult, ApiError> {
    let recovery_codes = sf::first_factor_codes(state, &user.id).await?;
    let session = match pre {
        Some(p) => Some(sf::complete(state, &p, &client_header(headers)).await?),
        None => None,
    };
    Ok(EnrollmentResult { recovery_codes, session })
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveTotpRequest {
    /// A current TOTP code, or
    pub code: Option<String>,
    /// the account password.
    pub password: Option<String>,
}

/// Removes TOTP. Needs the password, or a reauth token (PROTOCOL.md §5c) together with a current code; refused if it
/// is the last factor.
#[utoipa::path(delete, path = "/api/v1/auth/totp", security(("bearer" = [])), request_body = RemoveTotpRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn totp_remove(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<RemoveTotpRequest>,
) -> Result<StatusCode, ApiError> {
    crate::reauth::require_or_password(&state, &auth, &headers, req.password.as_deref()).await?;
    match (&req.code, &req.password) {
        (_, Some(password)) if !password.is_empty() => {}
        (Some(code), _) => {
            sf::limit_attempt(&state, &auth.user.id, &ip).await?;
            if !sf::check_totp(&state, &auth.user, code, true).await? {
                return Err(sf::second_factor_invalid());
            }
        }
        _ => return Err(bad("auth.proof_required", "Provide a current code or the password")),
    }
    match store::factors::remove_factor(&state.db, &auth.user.id, Factor::Totp).await? {
        RemoveFactor::Removed => {}
        RemoveFactor::NotFound => {
            return Err(ApiError::NotFound { code: "auth.totp_not_found", what: "TOTP".into() });
        }
        RemoveFactor::LastFactor => return Err(last_factor()),
    }
    audit(&state, &auth.user, "user.second_factor_remove", json!({ "method": "totp" })).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- Recovery codes

#[derive(Deserialize, ToSchema)]
pub struct PasswordConfirmation {
    /// The account password; may be empty when a reauth token is sent (`Tavrn-Reauth`, PROTOCOL.md §5c).
    #[serde(default)]
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryCodes {
    /// Ten single-use codes, shown once.
    pub recovery_codes: Vec<String>,
}

/// New recovery codes (the old set becomes invalid). Needs the password or a reauth token.
#[utoipa::path(post, path = "/api/v1/auth/recovery-codes/regenerate", security(("bearer" = [])), request_body = PasswordConfirmation,
    responses((status = 200, body = RecoveryCodes), (status = 401, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<PasswordConfirmation>,
) -> Result<Json<RecoveryCodes>, ApiError> {
    crate::reauth::require_or_password(&state, &auth, &headers, Some(&req.password)).await?;
    let recovery_codes = sf::new_recovery_codes(&state, &auth.user.id).await?;
    audit(&state, &auth.user, "user.recovery_codes_regenerate", json!({})).await?;
    Ok(Json(RecoveryCodes { recovery_codes }))
}

// ---------------------------------------------------------------- WebAuthn registration

#[derive(Serialize, ToSchema)]
pub struct WebauthnChallenge {
    /// Pass back to the finish route.
    pub challenge_id: String,
    /// `PublicKeyCredentialCreationOptions` / `…RequestOptions` as JSON (`{ "publicKey": … }`,
    /// binary values base64url), for `PublicKeyCredential.parse…OptionsFromJSON`.
    #[schema(value_type = Object)]
    pub options: Value,
}

fn passkeys(rows: &[CredentialRow]) -> Result<Vec<Passkey>, ApiError> {
    rows.iter().map(|c| serde_json::from_str(&c.passkey).map_err(internal)).collect()
}

/// Starts registering a passkey or security key (session or pre-auth token in stage `enroll`).
#[utoipa::path(post, path = "/api/v1/auth/webauthn/register/start", security(("bearer" = [])),
    responses((status = 200, body = WebauthnChallenge), (status = 401, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn webauthn_register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    principal: Principal,
) -> Result<Json<WebauthnChallenge>, ApiError> {
    require_reauth(&state, &principal, &headers).await?;
    let (user, _) = principal.for_enrollment(&state).await?;
    let existing = store::factors::credentials(&state.db, &user.id).await?;
    if existing.len() as i64 >= sf::MAX_CREDENTIALS {
        return Err(limit_reached());
    }
    let exclude = passkeys(&existing)?.iter().map(|p| p.cred_id().clone()).collect();
    let (options, reg) = state
        .webauthn
        .start_passkey_registration(sf::user_handle(&user.id)?, &user.address(), &user.display_name, Some(exclude))
        .map_err(internal)?;
    let reg = serde_json::to_string(&reg).map_err(internal)?;
    let challenge_id =
        store::factors::insert_challenge(&state.db, Some(&user.id), "register", &reg, sf::CHALLENGE_TTL_SECS).await?;
    Ok(Json(WebauthnChallenge { challenge_id, options: sf::browser_options(options)? }))
}

fn limit_reached() -> ApiError {
    ApiError::Conflict {
        code: "webauthn.limit",
        detail: format!("At most {} security keys per account", sf::MAX_CREDENTIALS),
        meta: json!({ "max": sf::MAX_CREDENTIALS }),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct WebauthnRegisterFinish {
    pub challenge_id: String,
    /// Shown in the list, 1–64 characters.
    pub name: String,
    /// `PublicKeyCredential.toJSON()` of `navigator.credentials.create()`. Remove
    /// `clientExtensionResults.prf.results` (if any) before sending.
    #[schema(value_type = Object)]
    pub response: Value,
}

#[derive(Serialize, ToSchema)]
pub struct WebauthnRegistered {
    pub credential: WebauthnCredential,
    /// Ten single-use codes when this is the account's first factor.
    pub recovery_codes: Option<Vec<String>>,
    /// The session, when registered with a pre-auth token (stage `enroll`).
    pub session: Option<AuthResponse>,
}

/// Completes the registration; with a pre-auth token it also completes the login.
#[utoipa::path(post, path = "/api/v1/auth/webauthn/register/finish", security(("bearer" = [])), request_body = WebauthnRegisterFinish,
    responses((status = 200, body = WebauthnRegistered), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails)))]
pub async fn webauthn_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    principal: Principal,
    ApiJson(req): ApiJson<WebauthnRegisterFinish>,
) -> Result<Json<WebauthnRegistered>, ApiError> {
    let name = validate::name("name", &req.name, 64)?;
    sf::reject_prf_output(&req.response)?;
    require_reauth(&state, &principal, &headers).await?;
    let (user, pre) = principal.for_enrollment(&state).await?;
    let challenge =
        store::factors::take_challenge(&state.db, &req.challenge_id).await?.ok_or_else(challenge_invalid)?;
    if challenge.kind != "register" || challenge.user_id.as_deref() != Some(user.id.as_str()) {
        return Err(challenge_invalid());
    }
    let reg: PasskeyRegistration = serde_json::from_str(&challenge.state).map_err(internal)?;
    let failed = || bad("webauthn.registration_failed", "Registering the security key failed");
    let prf_supported = sf::prf_enabled(&req.response);
    let credential: RegisterPublicKeyCredential = serde_json::from_value(req.response).map_err(|_| failed())?;
    let passkey = state.webauthn.finish_passkey_registration(&credential, &reg).map_err(|e| {
        tracing::info!(error = %e, "WebAuthn registration rejected");
        failed()
    })?;
    let credential_id = sf::credential_id_b64(passkey.cred_id().as_ref());
    let stored = store::factors::insert_credential(
        &state.db,
        NewCredential {
            credential_id: &credential_id,
            user_id: &user.id,
            name: &name,
            passkey: &serde_json::to_string(&passkey).map_err(internal)?,
            prf_supported,
        },
        sf::MAX_CREDENTIALS,
    )
    .await?;
    match stored {
        InsertCredential::Inserted => {}
        InsertCredential::LimitReached => return Err(limit_reached()),
        InsertCredential::Duplicate => {
            return Err(ApiError::conflict("webauthn.credential_exists", "This security key is already registered"));
        }
    }
    audit(&state, &user, "user.second_factor_enroll", json!({ "method": "webauthn", "name": name })).await?;
    let row =
        store::factors::credential(&state.db, &user.id, &credential_id).await?.ok_or_else(credential_not_found)?;
    let EnrollmentResult { recovery_codes, session } = finish_enrollment(&state, &user, pre, &headers).await?;
    Ok(Json(WebauthnRegistered { credential: WebauthnCredential::from(&row), recovery_codes, session }))
}

/// The account's WebAuthn credentials.
#[utoipa::path(get, path = "/api/v1/auth/webauthn/credentials", security(("bearer" = [])), responses((status = 200, body = Vec<WebauthnCredential>)))]
pub async fn webauthn_credentials(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<WebauthnCredential>>, ApiError> {
    let creds = store::factors::credentials(&state.db, &auth.user.id).await?;
    Ok(Json(creds.iter().map(WebauthnCredential::from).collect()))
}

/// Removes a credential and its secret storage entry; refused if it is the last factor.
#[utoipa::path(delete, path = "/api/v1/auth/webauthn/credentials/{credential_id}", security(("bearer" = [])), params(("credential_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn webauthn_delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    crate::reauth::require(&state, &auth, &headers).await?;
    if !sf::valid_credential_id(&credential_id) {
        return Err(credential_not_found());
    }
    let name = store::factors::credential(&state.db, &auth.user.id, &credential_id).await?.map(|c| c.name);
    match store::factors::remove_factor(&state.db, &auth.user.id, Factor::Webauthn(&credential_id)).await? {
        RemoveFactor::Removed => {}
        RemoveFactor::NotFound => return Err(credential_not_found()),
        RemoveFactor::LastFactor => return Err(last_factor()),
    }
    audit(&state, &auth.user, "user.second_factor_remove", json!({ "method": "webauthn", "name": name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- WebAuthn login

#[derive(Deserialize, ToSchema)]
pub struct WebauthnLoginStart {
    /// With a pre-auth token (stage `verify`): second factor, allow-list of the user's
    /// credentials. Without: passkey-only login with a discoverable credential.
    pub preauth_token: Option<String>,
}

/// Starts a WebAuthn assertion (second factor or passkey-only login).
#[utoipa::path(post, path = "/api/v1/auth/webauthn/login/start", request_body = WebauthnLoginStart,
    responses((status = 200, body = WebauthnChallenge), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn webauthn_login_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    ApiJson(req): ApiJson<WebauthnLoginStart>,
) -> Result<Json<WebauthnChallenge>, ApiError> {
    state.login_limiter.check_all(&[format!("ip:{ip}")]).await?;
    let (options, user_id, kind, ceremony) = match req.preauth_token {
        Some(token) => {
            let pre = sf::verify_preauth(&state, &token).await?;
            pre.check_verify()?;
            let creds = passkeys(&store::factors::credentials(&state.db, &pre.user.id).await?)?;
            if creds.is_empty() {
                return Err(bad("webauthn.no_credentials", "No security key is set up for this account"));
            }
            let (options, auth) = state.webauthn.start_passkey_authentication(&creds).map_err(internal)?;
            (sf::browser_options(options)?, Some(pre.user.id), "second_factor", serde_json::to_string(&auth))
        }
        None => {
            let (options, auth) = state.webauthn.start_discoverable_authentication().map_err(internal)?;
            (sf::browser_options(options)?, None, "passkey", serde_json::to_string(&auth))
        }
    };
    let ceremony = ceremony.map_err(internal)?;
    let challenge_id =
        store::factors::insert_challenge(&state.db, user_id.as_deref(), kind, &ceremony, sf::CHALLENGE_TTL_SECS)
            .await?;
    Ok(Json(WebauthnChallenge { challenge_id, options }))
}

#[derive(Deserialize, ToSchema)]
pub struct WebauthnLoginFinish {
    pub challenge_id: String,
    /// `PublicKeyCredential.toJSON()` of `navigator.credentials.get()` without
    /// `clientExtensionResults.prf.results`.
    #[schema(value_type = Object)]
    pub response: Value,
    /// Required for the second-factor ceremony (the one started with it).
    pub preauth_token: Option<String>,
    /// Name of the new device (passkey-only login; otherwise taken from the login).
    pub device_name: Option<String>,
    /// Passkey-only login: continue an existing device of the account (PROTOCOL.md §5b); ignored for the second
    /// factor (the password step carries it).
    pub device: Option<crate::device_proof::DeviceProof>,
}

/// Completes a WebAuthn assertion and returns the session.
#[utoipa::path(post, path = "/api/v1/auth/webauthn/login/finish", request_body = WebauthnLoginFinish,
    responses((status = 200, body = AuthResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn webauthn_login_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<WebauthnLoginFinish>,
) -> Result<Json<AuthResponse>, ApiError> {
    sf::reject_prf_output(&req.response)?;
    let challenge =
        store::factors::take_challenge(&state.db, &req.challenge_id).await?.ok_or_else(challenge_invalid)?;
    let credential: PublicKeyCredential = serde_json::from_value(req.response)
        .map_err(|_| bad("webauthn.response_invalid", "Unreadable security key response"))?;
    match challenge.kind.as_str() {
        "second_factor" => {
            let pre = sf::verify_preauth(&state, req.preauth_token.as_deref().unwrap_or("")).await?;
            pre.check_verify()?;
            if challenge.user_id.as_deref() != Some(pre.user.id.as_str()) {
                return Err(challenge_invalid());
            }
            sf::limit_attempt(&state, &pre.user.id, &ip).await?;
            let ceremony: PasskeyAuthentication = serde_json::from_str(&challenge.state).map_err(internal)?;
            let result = state.webauthn.finish_passkey_authentication(&credential, &ceremony);
            let result = assertion_result(&state, &pre.user, result, sf::second_factor_invalid).await?;
            record_use(&state, &pre.user, &result).await?;
            Ok(Json(sf::complete(&state, &pre, &client_header(&headers)).await?))
        }
        "passkey" => {
            state.login_limiter.check_all(&[format!("ip:{ip}")]).await?;
            let failed = || ApiError::Unauthorized { code: "auth.invalid_credentials" };
            let ceremony: DiscoverableAuthentication = serde_json::from_str(&challenge.state).map_err(internal)?;
            let (handle, _) = state.webauthn.identify_discoverable_authentication(&credential).map_err(|_| failed())?;
            let user = store::users::by_id(&state.db, &sf::user_id_from_handle(handle))
                .await?
                .filter(|u| u.domain == state.config.domain && u.kind == "user")
                .ok_or_else(failed)?;
            let creds = passkeys(&store::factors::credentials(&state.db, &user.id).await?)?;
            let keys: Vec<DiscoverableKey> = creds.iter().map(DiscoverableKey::from).collect();
            let result = state.webauthn.finish_discoverable_authentication(&credential, ceremony, &keys);
            let result = assertion_result(&state, &user, result, failed).await?;
            // Passkeys count as two factors only with user verification (PIN, biometrics).
            if !result.user_verified() {
                return Err(failed());
            }
            // TAVRN_OIDC_ONLY: passkeys only unlock, they never log in (break-glass admins excepted).
            crate::oidc::check_password_login(&state.config, &user.username)?;
            if user.disabled_at.is_some() {
                return Err(ApiError::Unauthorized { code: "auth.account_disabled" });
            }
            if state.config.email == EmailMode::Required && user.email_verified_at.is_none() {
                return Err(ApiError::Forbidden {
                    code: "auth.email_unverified",
                    detail: "Please confirm your email address first".into(),
                });
            }
            record_use(&state, &user, &result).await?;
            let name = device_name(req.device_name.as_deref(), "Passkey");
            let reuse = crate::device_proof::verify_opt(&state, &user, req.device.as_ref()).await?;
            Ok(Json(sf::start_session(&state, &user, &name, &client_header(&headers), reuse.as_deref()).await?))
        }
        _ => Err(challenge_invalid()),
    }
}

/// Maps the verification result; a signature counter that did not increase means a cloned
/// authenticator (WebAuthn §6.1.1) and is audited.
async fn assertion_result(
    state: &AppState,
    user: &UserRow,
    result: Result<webauthn_rs::prelude::AuthenticationResult, WebauthnError>,
    failed: impl Fn() -> ApiError,
) -> Result<webauthn_rs::prelude::AuthenticationResult, ApiError> {
    match result {
        Ok(r) => Ok(r),
        Err(WebauthnError::CredentialPossibleCompromise) => {
            tracing::warn!(user = user.id, "WebAuthn counter did not increase: possibly a cloned key");
            audit(state, user, "user.webauthn_counter_mismatch", json!({})).await?;
            Err(ApiError::Unauthorized { code: "webauthn.counter_mismatch" })
        }
        Err(e) => {
            tracing::info!(error = %e, "WebAuthn login rejected");
            Err(failed())
        }
    }
}

/// Stores the new counter and the time of use.
async fn record_use(
    state: &AppState,
    user: &UserRow,
    result: &webauthn_rs::prelude::AuthenticationResult,
) -> Result<(), ApiError> {
    let id = sf::credential_id_b64(result.cred_id().as_ref());
    let row = store::factors::credential(&state.db, &user.id, &id).await?.ok_or_else(credential_not_found)?;
    let mut passkey: Passkey = serde_json::from_str(&row.passkey).map_err(internal)?;
    passkey.update_credential(result);
    store::factors::credential_used(&state.db, &id, &serde_json::to_string(&passkey).map_err(internal)?).await
}

// ---------------------------------------------------------------- Re-authentication (sudo mode)

#[derive(Deserialize, ToSchema)]
pub struct ReauthRequest {
    /// The account password, or
    pub password: Option<String>,
    /// a WebAuthn assertion: the challenge of `POST /auth/reauth/webauthn/start` …
    pub challenge_id: Option<String>,
    /// … and `PublicKeyCredential.toJSON()` of `navigator.credentials.get()`.
    #[schema(value_type = Option<Object>)]
    pub response: Option<Value>,
}

/// Starts a WebAuthn assertion for a re-authentication (any of the account's passkeys or security keys).
#[utoipa::path(post, path = "/api/v1/auth/reauth/webauthn/start", security(("bearer" = [])),
    responses((status = 200, body = WebauthnChallenge), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails)))]
pub async fn reauth_webauthn_start(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<WebauthnChallenge>, ApiError> {
    let creds = passkeys(&store::factors::credentials(&state.db, &auth.user.id).await?)?;
    if creds.is_empty() {
        return Err(bad("webauthn.no_credentials", "No security key is set up for this account"));
    }
    let (options, ceremony) = state.webauthn.start_passkey_authentication(&creds).map_err(internal)?;
    let ceremony = serde_json::to_string(&ceremony).map_err(internal)?;
    let challenge_id =
        store::factors::insert_challenge(&state.db, Some(&auth.user.id), "reauth", &ceremony, sf::CHALLENGE_TTL_SECS)
            .await?;
    Ok(Json(WebauthnChallenge { challenge_id, options: sf::browser_options(options)? }))
}

/// Re-authentication (PROTOCOL.md §5c): the password or a WebAuthn assertion yields a reauth token for this session,
/// valid for five minutes. SSO accounts use the provider's `reauth` flow (`POST /auth/oidc/token`).
#[utoipa::path(post, path = "/api/v1/auth/reauth", security(("bearer" = [])), request_body = ReauthRequest,
    responses((status = 200, body = crate::reauth::ReauthToken), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn reauth(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    auth: AuthUser,
    ApiJson(req): ApiJson<ReauthRequest>,
) -> Result<Json<crate::reauth::ReauthToken>, ApiError> {
    // A wrong proof is a 403 (not 401): the session itself is fine, clients must not refresh or sign out.
    let refused =
        || ApiError::Forbidden { code: "auth.reauth_failed", detail: "The confirmation did not match".into() };
    match (req.password.as_deref(), req.challenge_id.as_deref(), req.response) {
        (Some(password), _, _) => match crate::reauth::check_password(&state, &auth.user, password).await {
            Ok(()) => {}
            Err(ApiError::Unauthorized { .. }) => return Err(refused()),
            Err(e) => return Err(e),
        },
        (None, Some(challenge_id), Some(response)) => {
            sf::reject_prf_output(&response)?;
            sf::limit_attempt(&state, &auth.user.id, &ip).await?;
            let challenge =
                store::factors::take_challenge(&state.db, challenge_id).await?.ok_or_else(challenge_invalid)?;
            if challenge.kind != "reauth" || challenge.user_id.as_deref() != Some(auth.user.id.as_str()) {
                return Err(challenge_invalid());
            }
            let credential: PublicKeyCredential = serde_json::from_value(response)
                .map_err(|_| bad("webauthn.response_invalid", "Unreadable security key response"))?;
            let ceremony: PasskeyAuthentication = serde_json::from_str(&challenge.state).map_err(internal)?;
            let result = state.webauthn.finish_passkey_authentication(&credential, &ceremony);
            let result = assertion_result(&state, &auth.user, result, refused).await?;
            record_use(&state, &auth.user, &result).await?;
        }
        _ => return Err(bad("auth.proof_required", "Password or a WebAuthn assertion required")),
    }
    audit(&state, &auth.user, "user.reauth", json!({ "device": auth.device_id })).await?;
    Ok(Json(crate::reauth::issue(&state, &auth).await?))
}
