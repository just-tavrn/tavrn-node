// SPDX-License-Identifier: AGPL-3.0-only
//! Registration, login, token refresh, logout, email verification.
//!
//! Password login and registration end in a pre-auth token; the session follows after the second
//! factor (`routes::second_factor`, PROTOCOL.md §5a).

use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::{self, AuthUser, ClientIp, TokenPair},
    config::{CaptchaAction, EmailMode, Registration},
    error::ApiError,
    models::{UserPrivate, UserRow},
    second_factor::{self, Stage},
    sessions::Reason,
    store,
    util::{self, now},
    validate::{self, bad},
};

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    /// Invite code, if the node only registers by invite.
    pub invite: Option<String>,
    pub device_name: Option<String>,
    /// Captcha token, if the node requires one (see `/node`).
    pub captcha_token: Option<String>,
    /// The version of the terms of service the user accepted (required when the node publishes terms,
    /// `GET /node` → `legal.pages.terms.version`).
    pub accept_terms: Option<i64>,
    /// Required (`age.v1`, PROTOCOL.md §5e): the date of birth `YYYY-MM-DD`, between 1900-01-01 and today. Below the
    /// node's minimum age (`GET /node` → `age.minimum_age`) the registration is refused with `age.below_minimum`.
    /// Stored on this node only, never shown to others.
    pub date_of_birth: Option<String>,
}

/// `ok`: the response carries a full session.
#[derive(Debug, Clone, Copy, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Ok,
}

/// A full session (after the second factor or a passkey-only login).
#[derive(Serialize, ToSchema)]
pub struct AuthResponse {
    pub status: SessionStatus,
    pub user: UserPrivate,
    #[serde(flatten)]
    pub tokens: TokenPair,
    /// `true` if a recovery code was used; the client should suggest new codes or a new factor.
    pub recovery_code_used: bool,
    /// The login was a fresh proof of the credentials: a reauth token for security-sensitive changes during the next
    /// five minutes (`Tavrn-Reauth` header, PROTOCOL.md §5c). Keep it in memory only.
    pub reauth_token: Option<String>,
}

/// What the pre-auth token is good for.
#[derive(Debug, Clone, Copy, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreAuthStatus {
    /// No factor yet: enroll TOTP or a passkey (`/auth/totp/*`, `/auth/webauthn/register/*`).
    EnrollmentRequired,
    /// Verify a factor (`/auth/second-factor/verify`, `/auth/webauthn/login/*`).
    SecondFactorRequired,
}

/// Password accepted, second factor pending. The token is valid for 10 minutes and one login.
#[derive(Serialize, ToSchema)]
pub struct PreAuthResponse {
    pub status: PreAuthStatus,
    pub preauth_token: String,
    /// Enrollment: `totp`, `webauthn`. Verification: the user's factors (`totp`, `webauthn`,
    /// `recovery_code`).
    pub methods: Vec<String>,
    pub expires_in: i64,
}

pub(crate) fn client_header(headers: &axum::http::HeaderMap) -> String {
    headers.get("tavrn-client").and_then(|v| v.to_str().ok()).unwrap_or("unknown").chars().take(200).collect()
}

fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else { return false };
    !local.is_empty()
        && local.len() <= 64
        && e.len() <= 254
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Create an account: open, by invite or closed, depending on the node setting. The answer is
/// a pre-auth token in stage `enroll`: the account becomes usable once a second factor is enrolled.
#[utoipa::path(post, path = "/api/v1/auth/register", request_body = RegisterRequest,
    responses((status = 201, body = PreAuthResponse), (status = 400, body = crate::error::ProblemDetails), (status = 403, body = crate::error::ProblemDetails), (status = 409, body = crate::error::ProblemDetails)))]
pub async fn register(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<PreAuthResponse>), ApiError> {
    state.register_limiter.check_all(&[format!("ip:{ip}")]).await?;
    let cfg = &state.config;
    state.captcha.check(cfg.captcha_required(CaptchaAction::Register), req.captcha_token.as_deref(), &ip).await?;

    let is_first = store::users::count_local(&state.db, &cfg.domain).await? == 0;
    // The invite is checked and redeemed only together with the account (below): a request that fails any other
    // check must not use it up.
    let invite = match cfg.registration {
        Registration::Closed => {
            return Err(ApiError::Forbidden {
                code: "auth.registration_closed",
                detail: "This node does not accept new accounts".into(),
            });
        }
        // The first account is always allowed (bootstrap), after that only with a valid account invite.
        Registration::Invite if !is_first => {
            let code = req.invite.as_deref().map(str::trim).unwrap_or("");
            if code.is_empty() {
                return Err(ApiError::Forbidden {
                    code: "auth.invite_required",
                    detail: "Registration by invite only".into(),
                });
            }
            Some(code)
        }
        Registration::Invite | Registration::Open => None,
    };

    let username = req.username.trim().to_lowercase();
    if !util::valid_username(&username) {
        return Err(bad(
            "auth.username_invalid",
            "Username: 2–32 characters from a-z, 0-9, _ . -, starting with a letter or digit",
        ));
    }
    // TAVRN_OIDC_ONLY: accounts come from the identity provider; break-glass admins may register (§8.3).
    crate::oidc::check_password_login(cfg, &username)?;
    // Reserved on every node for the conformance probe (FEDERATION.md §9.1), even before it exists.
    if username == crate::federation::conformance::PROBE_USERNAME || util::reserved_username(&username) {
        return Err(ApiError::conflict("auth.username_taken", "This username is already taken"));
    }
    if !auth::valid_password(&req.password) {
        return Err(bad("auth.password_weak", "Password: at least 10 characters"));
    }
    // The date of birth (PROTOCOL.md §5e): plausible, and at least the node's minimum age.
    let today = crate::age::today();
    let date_of_birth = crate::age::parse(req.date_of_birth.as_deref().unwrap_or(""), today)?;
    crate::age::check_minimum(date_of_birth, today, cfg.minimum_age)?;
    // Published terms must be accepted, in exactly the version shown.
    let terms = crate::legal::documents::terms_version(&state.db).await?;
    if let Some(version) = terms
        && req.accept_terms != Some(version)
    {
        return Err(ApiError::BadRequestMeta {
            code: "legal.terms_not_accepted",
            detail: "Accept the terms of service to register".into(),
            meta: serde_json::json!({ "version": version }),
        });
    }
    let display_name = match req.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) => validate::name("display_name", d, 64)?,
        None => username.clone(),
    };
    let email = req.email.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_lowercase);
    match (cfg.email, &email) {
        (EmailMode::Required, None) => {
            return Err(bad("auth.email_required", "This node requires an email address"));
        }
        (EmailMode::None, Some(_)) => {
            return Err(bad("auth.email_not_accepted", "This node does not accept email addresses"));
        }
        (_, Some(e)) if !valid_email(e) => return Err(bad("auth.email_invalid", "Invalid email address")),
        _ => {}
    }

    let is_admin = is_first || cfg.admin_users().iter().any(|a| a == &username);
    let password_hash = auth::hash(&state, &req.password).await?;
    // One transaction: the invite use and the account (a failing INSERT rolls the use back).
    let user = store::users::create_local_with_invite(
        &state.db,
        store::users::NewLocalUser {
            username: &username,
            domain: &cfg.domain,
            display_name: &display_name,
            password_hash: &password_hash,
            email: email.as_deref(),
            is_node_admin: is_admin,
            date_of_birth: Some(&date_of_birth.format("%Y-%m-%d").to_string()),
        },
        invite,
    )
    .await?;

    if let Some(version) = terms {
        crate::legal::documents::accept(&state.db, &user.id, version).await?;
    }
    // The browser's language until the client sends the one the user picked (mails, `mail_templates.rs`).
    let locale = crate::mail_templates::from_accept_language(
        headers.get(axum::http::header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
    );
    if locale.is_some() {
        store::users::set_locale(&state.db, &user.id, locale.as_deref()).await?;
    }
    if email.is_some() && cfg.email != EmailMode::None {
        let token = util::random_token(32);
        store::users::set_email_verification(&state.db, &user.id, &util::sha256_b64(&token), 24 * 3600).await?;
        state.mailer.send_verification(&user, locale.as_deref(), &token).await;
    }

    let token = second_factor::issue_preauth(
        &state,
        &user.id,
        Stage::Enroll,
        &device_name(req.device_name.as_deref(), "First device"),
        None,
    )?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&user.id),
        "user.register",
        &user.address(),
        "",
        serde_json::json!({ "ip": ip }),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(enrollment_required(token))))
}

fn enrollment_required(preauth_token: String) -> PreAuthResponse {
    PreAuthResponse {
        status: PreAuthStatus::EnrollmentRequired,
        preauth_token,
        methods: vec!["totp".into(), "webauthn".into()],
        expires_in: second_factor::PREAUTH_TTL_SECS,
    }
}

/// Device name for the session that a pre-auth token will create (at most 64 characters).
pub(crate) fn device_name(requested: Option<&str>, default: &str) -> String {
    let name: String = requested.map(str::trim).unwrap_or("").chars().filter(|c| !c.is_control()).take(64).collect();
    if name.is_empty() { default.to_string() } else { name }
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_name: Option<String>,
    pub captcha_token: Option<String>,
    /// Continue an existing device of this account instead of creating a new one (PROTOCOL.md §5b). An invalid
    /// proof is ignored: the session then gets a new device.
    pub device: Option<crate::device_proof::DeviceProof>,
}

/// Login with username and password. Returns a pre-auth token: `second_factor_required`
/// (verify a factor) or `enrollment_required` (the account has no factor yet). The session for the
/// new device follows the second factor.
#[utoipa::path(post, path = "/api/v1/auth/login", request_body = LoginRequest,
    responses((status = 200, body = PreAuthResponse), (status = 401, body = crate::error::ProblemDetails), (status = 403, body = crate::error::ProblemDetails), (status = 429, body = crate::error::ProblemDetails)))]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> Result<Json<PreAuthResponse>, ApiError> {
    let username = req.username.trim().to_lowercase();
    let username = username.strip_suffix(&format!("@{}", state.config.domain)).unwrap_or(&username).to_string();
    // Every attempt counts per address; per account only failed attempts count (below), so nobody can lock an
    // account out by signing in as it, and a valid device proof passes even a locked account key.
    state.login_limiter.check_all(&[format!("ip:{ip}")]).await?;
    // TAVRN_OIDC_ONLY: only the break-glass accounts of TAVRN_ADMIN_USERS sign in with a password.
    crate::oidc::check_password_login(&state.config, &username)?;
    state.captcha.check(state.config.captcha_required(CaptchaAction::Login), req.captcha_token.as_deref(), &ip).await?;
    let user_key = format!("user:{username}");
    let locked = state.login_limiter.peek(&user_key).await.err();
    if let Some(retry_after_secs) = locked.filter(|_| req.device.is_none()) {
        return Err(ApiError::RateLimited { retry_after_secs });
    }

    let failed = || ApiError::Unauthorized { code: "auth.invalid_credentials" };
    let user = store::users::by_username(&state.db, &username, &state.config.domain).await?;
    // Hash even for an unknown user (and bots, which have no interactive login, APPLICATIONS.md §1.4), so the
    // response time reveals nothing.
    let hash = user.as_ref().filter(|u| !u.is_bot()).and_then(|u| u.password_hash.as_deref());
    let ok = auth::verify(&state, &req.password, hash).await?;
    let user = match user.filter(|_| ok) {
        Some(user) => user,
        None => {
            // A failed attempt counts against the account; beyond the limit the answer is 429.
            state.login_limiter.check_all(std::slice::from_ref(&user_key)).await?;
            if let Some(retry_after_secs) = locked {
                return Err(ApiError::RateLimited { retry_after_secs });
            }
            return Err(failed());
        }
    };
    // The proven device travels in the pre-auth token to the session issued after the second factor.
    let reuse = crate::device_proof::verify_opt(&state, &user, req.device.as_ref()).await?;
    // A locked account key lets only the right password together with a valid device proof through, before
    // anything about the account's state is told.
    if let Some(retry_after_secs) = locked.filter(|_| reuse.is_none()) {
        return Err(ApiError::RateLimited { retry_after_secs });
    }
    if user.deleted_at.is_some() {
        return Err(ApiError::Unauthorized { code: "auth.account_deleted" });
    }
    if user.disabled_at.is_some() {
        return Err(ApiError::Unauthorized { code: "auth.account_disabled" });
    }
    if state.config.email == EmailMode::Required && user.email_verified_at.is_none() {
        return Err(ApiError::Forbidden {
            code: "auth.email_unverified",
            detail: "Please verify the email address first".into(),
        });
    }
    let device = device_name(req.device_name.as_deref(), "Device");
    if !store::factors::has_factor(&state.db, &user.id).await? {
        let token = second_factor::issue_preauth(&state, &user.id, Stage::Enroll, &device, reuse.as_deref())?;
        return Ok(Json(enrollment_required(token)));
    }
    let token = second_factor::issue_preauth(&state, &user.id, Stage::Verify, &device, reuse.as_deref())?;
    Ok(Json(PreAuthResponse {
        status: PreAuthStatus::SecondFactorRequired,
        preauth_token: token,
        methods: second_factor::verify_methods(&state, &user.id).await?,
        expires_in: second_factor::PREAUTH_TTL_SECS,
    }))
}

/// A single-use login nonce for a device proof (PROTOCOL.md §5b, ENCRYPTION.md §3.4): the client signs it with the
/// key of a device it still holds and sends `device` with the login, so the new session continues that device.
#[utoipa::path(post, path = "/api/v1/auth/device-nonce",
    responses((status = 200, body = crate::device_proof::DeviceNonce), (status = 429, body = crate::error::ProblemDetails)))]
pub async fn device_nonce(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
) -> Result<Json<crate::device_proof::DeviceNonce>, ApiError> {
    state.login_limiter.check_all(&[format!("nonce-ip:{ip}")]).await?;
    Ok(Json(crate::device_proof::issue_nonce(&state)?))
}

#[derive(Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// New access token; the refresh token is rotated. Parallel refreshes with the same token, and the previous token
/// within 30 seconds of its rotation, get the same new pair; an older reuse revokes the session (PROTOCOL.md §5b).
#[utoipa::path(post, path = "/api/v1/auth/refresh", request_body = RefreshRequest, responses((status = 200, body = TokenPair), (status = 401, body = crate::error::ProblemDetails)))]
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, ApiError> {
    Ok(Json(auth::refresh_session(&state, &req.refresh_token).await?))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct LogoutQuery {
    /// The client deleted this device's keys: the device is removed as well (like a deletion in the device list:
    /// `mls.remove_needed`, pending removals of its leaves, `devices.changed`). Local accounts only.
    #[serde(default)]
    pub forget_device: bool,
}

/// Log out: revoke all sessions of this device. An SSO session answers `200` with the provider's
/// logout URL when the provider has one (APPLICATIONS.md §8.6), otherwise `204`.
#[utoipa::path(post, path = "/api/v1/auth/logout", security(("bearer" = [])), params(LogoutQuery),
    responses((status = 204), (status = 200, body = crate::routes::oidc::LogoutResponse)))]
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(q): axum::extract::Query<LogoutQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let end_session_url = crate::routes::oidc::logout_url(&state, &auth.device_id).await?;
    crate::sessions::revoke_devices(&state, &auth.user, std::slice::from_ref(&auth.device_id), Reason::Logout).await?;
    if q.forget_device
        && !auth.is_remote()
        && auth.app.is_none()
        && store::users::delete_device(&state.db, &auth.user.id, &auth.device_id).await?
    {
        {
            crate::e2ee::device_removed(&state, &auth.user, &auth.device_id).await?;
            crate::federation::remote::revoke_sessions(&state, &auth.user, Some(&auth.device_id)).await?;
            crate::federation::remote::devices_changed(&state, &auth.user).await?;
        }
    }
    Ok(match end_session_url {
        Some(end_session_url) => Json(crate::routes::oidc::LogoutResponse { end_session_url }).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
}

/// Verify the email address with the token received by email.
#[utoipa::path(post, path = "/api/v1/auth/verify-email", request_body = VerifyEmailRequest, responses((status = 204), (status = 400, body = crate::error::ProblemDetails)))]
pub async fn verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<StatusCode, ApiError> {
    match store::users::consume_email_verification(&state.db, &util::sha256_b64(&req.token)).await? {
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(bad("auth.verification_invalid", "Verification link invalid or expired")),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ResendVerificationRequest {
    /// Username, address (`name@domain`) or email address of the account (at most 320 characters)
    pub account: String,
}

/// Send the confirmation mail of an unconfirmed email address again.
///
/// The new link replaces the previous one. Always answers 204, so no accounts can be guessed: confirmed, unknown and
/// disabled accounts get no mail. At most three mails per account and hour. A node without SMTP answers
/// `503 mail.unavailable`.
#[utoipa::path(post, path = "/api/v1/auth/verify-email/resend", request_body = ResendVerificationRequest,
    responses((status = 204), (status = 400, body = crate::error::ProblemDetails), (status = 429, body = crate::error::ProblemDetails),
        (status = 503, body = crate::error::ProblemDetails)))]
pub async fn resend_verification(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<StatusCode, ApiError> {
    if !state.mailer.can_deliver() {
        return Err(ApiError::Unavailable { code: "mail.unavailable", detail: "This node sends no e-mail".into() });
    }
    let account = crate::validate::text("account", &req.account, 0, 320)?.to_lowercase();
    state.register_limiter.check_all(&[format!("verify-resend:{ip}")]).await?;
    if account.is_empty() || state.config.email == EmailMode::None {
        return Ok(StatusCode::NO_CONTENT);
    }
    let account = account
        .strip_suffix(&format!("@{}", state.config.domain))
        .filter(|a| !a.contains('@'))
        .unwrap_or(&account)
        .to_string();
    let users = if account.contains('@') {
        store::users::unverified_by_email(&state.db, &state.config.domain, &account, 3).await?
    } else {
        store::users::by_username(&state.db, &account, &state.config.domain).await?.into_iter().collect()
    };
    for user in users {
        if user.kind != "user"
            || user.disabled_at.is_some()
            || user.deleted_at.is_some()
            || user.email.is_none()
            || user.email_verified_at.is_some()
        {
            continue;
        }
        // Per account, after the lookup (the answer stays 204): no mail bombing.
        if state.verify_mail_limiter.check_all(&[format!("verify-mail-user:{}", user.id)]).await.is_err() {
            continue;
        }
        let token = util::random_token(32);
        store::users::set_email_verification(&state.db, &user.id, &util::sha256_b64(&token), 24 * 3600).await?;
        mail_after_answer(&state, user, token, AccountMail::Verification);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct ForgotPasswordRequest {
    /// Username or email address
    pub account: String,
}

/// Request a password reset by email. Always answers 204, so no accounts can be guessed. At most three mails per
/// account and hour; a link that has not expired stays valid (a new request sends no new one). A node without
/// SMTP answers `503 mail.unavailable` (development nodes log the mail instead).
#[utoipa::path(post, path = "/api/v1/auth/forgot-password", request_body = ForgotPasswordRequest,
    responses((status = 204), (status = 429, body = crate::error::ProblemDetails), (status = 503, body = crate::error::ProblemDetails)))]
pub async fn forgot_password(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if !state.mailer.can_deliver() {
        return Err(ApiError::Unavailable {
            code: "mail.unavailable",
            detail: "This node sends no e-mail; ask a node admin to reset your password".into(),
        });
    }
    state.register_limiter.check_all(&[format!("forgot:{ip}")]).await?;
    let account = req.account.trim().to_lowercase();
    let account = account
        .strip_suffix(&format!("@{}", state.config.domain))
        .filter(|a| !a.contains('@'))
        .unwrap_or(&account)
        .to_string();
    let user = if account.contains('@') {
        store::admin::user_by_email(&state.db, &state.config.domain, &account).await?
    } else {
        store::users::by_username(&state.db, &account, &state.config.domain)
            .await?
            .filter(|u| u.email_verified_at.is_some())
    };
    // SSO-only accounts have no password to reset (APPLICATIONS.md §8.3).
    if let Some(user) = user.filter(|u| u.disabled_at.is_none() && u.email.is_some() && u.password_hash.is_some()) {
        // Per account (after the lookup, the answer stays 204): no mail bombing, and the link already sent stays
        // the valid one while it lasts.
        if store::admin::has_pending_password_reset(&state.db, &user.id).await?
            || state.forgot_limiter.check_all(&[format!("forgot-user:{}", user.id)]).await.is_err()
        {
            return Ok(StatusCode::NO_CONTENT);
        }
        let token = util::random_token(32);
        store::admin::set_password_reset(&state.db, &user.id, &util::sha256_b64(&token), 3600).await?;
        mail_after_answer(&state, user, token, AccountMail::PasswordReset);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The mails of the requests that answer `204` for every account.
enum AccountMail {
    Verification,
    PasswordReset,
}

/// Looks up the user's language and delivers `mail` in a background task, after the token is stored: the answer then
/// takes as long for an account that gets a mail as for an unknown one, also with a slow SMTP relay (the response
/// time must not tell which accounts exist).
fn mail_after_answer(state: &AppState, user: UserRow, token: String, mail: AccountMail) {
    let (db, mailer) = (state.db.clone(), state.mailer.clone());
    state.mailer.send_in_background(async move {
        let locale = store::users::locale(&db, &user.id).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "mail language not read, sending the default");
            None
        });
        match mail {
            AccountMail::Verification => mailer.send_verification(&user, locale.as_deref(), &token).await,
            AccountMail::PasswordReset => mailer.send_password_reset(&user, locale.as_deref(), &token).await,
        }
    });
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// Set the password with the token received by email; all sessions are signed out.
#[utoipa::path(post, path = "/api/v1/auth/reset-password", request_body = ResetPasswordRequest, responses((status = 204), (status = 400, body = crate::error::ProblemDetails)))]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if !auth::valid_password(&req.new_password) {
        return Err(bad("auth.password_weak", "Password: at least 10 characters"));
    }
    let user_id = store::admin::consume_password_reset(&state.db, &util::sha256_b64(&req.token))
        .await?
        .ok_or_else(|| bad("auth.reset_invalid", "Link invalid or expired"))?;
    if store::users::by_id(&state.db, &user_id).await?.is_some_and(|u| u.password_hash.is_none()) {
        return Err(sso_password_unavailable());
    }
    store::users::set_password_hash(&state.db, &user_id, &auth::hash(&state, &req.new_password).await?).await?;
    if let Some(user) = store::users::by_id(&state.db, &user_id).await? {
        crate::sessions::revoke_all(&state, &user, None, Reason::PasswordReset).await?;
        crate::federation::remote::revoke_sessions(&state, &user, None).await?;
    }
    store::rooms::audit(&state.db, None, Some(&user_id), "user.password_reset", "", "", serde_json::json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Own account.
#[utoipa::path(get, path = "/api/v1/users/me", security(("bearer" = [])), responses((status = 200, body = UserPrivate), (status = 401, body = crate::error::ProblemDetails)))]
pub async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<UserPrivate>, ApiError> {
    Ok(Json(own_account(&state, &auth).await?))
}

/// `GET /users/me`: the own account with the settings and, for local users, the date of birth and the private age
/// status (PROTOCOL.md §5e; nowhere else).
pub(crate) async fn own_account(state: &AppState, auth: &AuthUser) -> Result<UserPrivate, ApiError> {
    let mut me = auth.user.to_private();
    if !auth.is_remote() && auth.user.domain == state.config.domain {
        me.notification_settings = Some(crate::notifications::load(&state.db, &auth.user.id).await?);
        me.auto_preview = Some(store::users::auto_preview(&state.db, &auth.user.id).await?);
        me.locale = store::users::locale(&state.db, &auth.user.id).await?;
        if auth.user.kind == "user" {
            me.date_of_birth = Some(auth.user.date_of_birth.clone());
            me.age_status = Some(crate::age::status(&auth.user));
        }
    }
    Ok(me)
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Change the password. All other devices are signed out.
#[utoipa::path(post, path = "/api/v1/users/me/password", security(("bearer" = [])), request_body = ChangePasswordRequest, responses((status = 204), (status = 401, body = crate::error::ProblemDetails)))]
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    if auth.user.password_hash.is_none() && !auth.is_remote() {
        return Err(sso_password_unavailable());
    }
    state.login_limiter.check_all(&[format!("password-change:{}", auth.user.id)]).await?;
    let ok = auth::verify(&state, &req.current_password, auth.user.password_hash.as_deref()).await?;
    if !ok {
        return Err(ApiError::Unauthorized { code: "auth.invalid_credentials" });
    }
    if !auth::valid_password(&req.new_password) {
        return Err(bad("auth.password_weak", "Password: at least 10 characters"));
    }
    store::users::set_password_hash(&state.db, &auth.user.id, &auth::hash(&state, &req.new_password).await?).await?;
    crate::sessions::revoke_all(&state, &auth.user, Some(&auth.device_id), Reason::PasswordChange).await?;
    crate::federation::remote::revoke_sessions(&state, &auth.user, None).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.password_change",
        &auth.user.address(),
        "",
        serde_json::json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// SSO-only accounts cannot set a password in v1 (APPLICATIONS.md §8.3).
fn sso_password_unavailable() -> ApiError {
    ApiError::conflict("sso.password_unavailable", "This account signs in with single sign-on and has no password")
}

/// Sign out and remove a device (not the current one). Needs a reauth token (`Tavrn-Reauth`, PROTOCOL.md §5c).
#[utoipa::path(delete, path = "/api/v1/users/me/devices/{device_id}", security(("bearer" = [])), params(("device_id" = String, Path)), responses((status = 204), (status = 400, body = crate::error::ProblemDetails)))]
pub async fn delete_device(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthUser,
    axum::extract::Path(device_id): axum::extract::Path<String>,
) -> Result<StatusCode, ApiError> {
    if device_id == auth.device_id {
        return Err(bad("device.current", "The current device cannot be removed; please log out"));
    }
    crate::reauth::require(&state, &auth, &headers).await?;
    // Only a device of this account: delete first (scoped by the user), end its sessions only if it was one.
    if !store::users::delete_device(&state.db, &auth.user.id, &device_id).await? {
        return Err(ApiError::NotFound { code: "device.not_found", what: "Device".into() });
    }
    crate::sessions::revoke_devices(&state, &auth.user, std::slice::from_ref(&device_id), Reason::DeviceRemoved)
        .await?;
    crate::e2ee::device_removed(&state, &auth.user, &device_id).await?;
    crate::federation::remote::revoke_sessions(&state, &auth.user, Some(&device_id)).await?;
    crate::federation::remote::devices_changed(&state, &auth.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub client: String,
    pub created_at: String,
    /// Last login or token refresh of the device.
    pub last_seen_at: String,
    /// The device of this session.
    pub current: bool,
    /// Not seen for half of `TAVRN_DEVICE_STALE_DAYS` (or 30 days when the cleanup is off): likely a browser
    /// that is gone. Housekeeping deletes devices after the full period.
    pub stale: bool,
    /// When housekeeping will delete the device if it is not used again (null: never).
    pub stale_at: Option<String>,
}

/// Own devices.
#[utoipa::path(get, path = "/api/v1/users/me/devices", security(("bearer" = [])), responses((status = 200, body = Vec<DeviceInfo>)))]
pub async fn devices(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<DeviceInfo>>, ApiError> {
    let devices = store::users::devices_of(&state.db, &auth.user.id).await?;
    let stale_days = i64::from(state.config.device_stale_days);
    let warn_days = if stale_days > 0 { (stale_days / 2).max(1) } else { 30 };
    let warn_cutoff = util::format_time(chrono::Utc::now() - chrono::Duration::days(warn_days));
    let after = |t: &str, days: i64| {
        chrono::DateTime::parse_from_rfc3339(t)
            .ok()
            .map(|t| util::format_time(t.with_timezone(&chrono::Utc) + chrono::Duration::days(days)))
    };
    Ok(Json(
        devices
            .into_iter()
            .map(|d| {
                let current = d.id == auth.device_id;
                DeviceInfo {
                    stale: !current && d.last_seen_at < warn_cutoff,
                    stale_at: (stale_days > 0 && !current).then(|| after(&d.last_seen_at, stale_days)).flatten(),
                    current,
                    id: d.id,
                    name: d.name,
                    client: d.client,
                    created_at: d.created_at,
                    last_seen_at: d.last_seen_at,
                }
            })
            .collect(),
    ))
}

/// Development nodes only (not in the API description): every access token issued so far counts as expired, so the
/// e2e tests can watch clients refresh (`auth.token_expired` on REST and `4001` on the WebSocket).
pub async fn dev_expire_access_tokens(State(state): State<AppState>) -> StatusCode {
    if !state.config.dev {
        return StatusCode::NOT_FOUND;
    }
    state.access_not_before.store(crate::jwt::now_unix(), std::sync::atomic::Ordering::Relaxed);
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
pub struct DevForgetRetired {
    pub device_id: String,
}

/// Development nodes only (not in the API description): drops a retired device key, as nodes older than retired
/// devices never kept one, so the e2e tests can exercise the re-attestation path (ENCRYPTION.md §5.2).
pub async fn dev_forget_retired_device(
    State(state): State<AppState>,
    Json(req): Json<DevForgetRetired>,
) -> Result<StatusCode, ApiError> {
    if !state.config.dev {
        return Ok(StatusCode::NOT_FOUND);
    }
    store::users::forget_retired_device(&state.db, &req.device_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[allow(dead_code)]
fn _unused(_: &str) -> String {
    now()
}
