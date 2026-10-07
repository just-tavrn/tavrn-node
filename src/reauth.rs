// SPDX-License-Identifier: AGPL-3.0-only
//! Re-authentication for security-sensitive account changes ("sudo mode", PROTOCOL.md §5c).
//!
//! A new recovery key, adding or removing passkeys and TOTP, new recovery codes, deleting devices and the identity
//! reset need a proof of the account's credentials from the last five minutes, not just a session: a stolen access
//! token alone must not lock the owner out or replace their keys. The proof is a short-lived **reauth token**
//! (`typ = "reauth"`, five minutes, bound to the session and device) sent in the `Tavrn-Reauth` header. The node
//! issues it with every login (the login itself was the proof) and on `POST /auth/reauth` (password or a WebAuthn
//! assertion; SSO accounts get it from the provider's `reauth` flow). Without it the routes answer
//! `403 auth.reauth_required` with the methods the account can use in `meta.methods`.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    models::UserRow,
    store, util,
};

/// Lifetime of a reauth token.
pub const REAUTH_TTL_SECS: i64 = 300;
/// Request header that carries the reauth token.
pub const HEADER: &str = "tavrn-reauth";
const TYP: &str = "reauth";

#[derive(Serialize)]
struct Claims<'a> {
    #[serde(flatten)]
    std: StandardClaims,
    dev: &'a str,
    sid: &'a str,
}

#[derive(Deserialize)]
struct Extra {
    dev: String,
    sid: String,
}

/// A reauth token and its lifetime in seconds.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReauthToken {
    /// Send as `Tavrn-Reauth` header with the sensitive request (valid for 5 minutes, any number of requests).
    pub reauth_token: String,
    pub expires_in: i64,
}

/// A reauth token for the live session `session_id` of `device_id`.
pub fn issue_for(state: &AppState, user_id: &str, device_id: &str, session_id: &str) -> Result<ReauthToken, ApiError> {
    let key = state.signing_key();
    let now = jwt::now_unix();
    let claims = Claims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: user_id.to_string(),
            aud: state.config.domain.clone(),
            exp: now + REAUTH_TTL_SECS,
            iat: now,
            jti: util::ulid(),
            typ: TYP.into(),
        },
        dev: device_id,
        sid: session_id,
    };
    let reauth_token = jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))?;
    Ok(ReauthToken { reauth_token, expires_in: REAUTH_TTL_SECS })
}

/// A reauth token for the session of this request (its device's newest live session).
pub async fn issue(state: &AppState, auth: &AuthUser) -> Result<ReauthToken, ApiError> {
    let session = store::users::live_session_of_device(&state.db, &auth.device_id)
        .await?
        .ok_or(ApiError::Unauthorized { code: "auth.token_invalid" })?;
    issue_for(state, &auth.user.id, &auth.device_id, &session)
}

/// `true` if `token` is a valid reauth token of this user, device and a still live session.
pub async fn valid(state: &AppState, auth: &AuthUser, token: &str) -> Result<bool, ApiError> {
    let Ok(kid) = jwt::peek_kid(token) else { return Ok(false) };
    let Some(key) = state.keys.iter().find(|k| k.kid == kid) else { return Ok(false) };
    let expected = Expected { iss: state.config.domain.clone(), aud: state.config.domain.clone(), typ: TYP };
    let Ok((claims, extra)) = jwt::verify::<Extra>(token, &key.verifying(), &expected) else { return Ok(false) };
    if claims.sub != auth.user.id || extra.dev != auth.device_id {
        return Ok(false);
    }
    Ok(store::users::session_by_id(&state.db, &extra.sid)
        .await?
        .is_some_and(|s| s.device_id == auth.device_id && s.revoked_at.is_none() && s.expires_at > util::now()))
}

/// The methods `user` can re-authenticate with: `password`, `webauthn`, `sso`.
pub async fn methods(state: &AppState, user: &UserRow) -> Result<Vec<&'static str>, ApiError> {
    let mut out = Vec::new();
    if user.password_hash.is_some() {
        out.push("password");
    }
    if store::factors::count_credentials(&state.db, &user.id).await? > 0 {
        out.push("webauthn");
    }
    if let Some(oidc) = state.oidc.as_ref()
        && store::oidc::identity_of_user(&state.db, &user.id, &oidc.settings.issuer).await?.is_some()
    {
        out.push("sso");
    }
    Ok(out)
}

/// `403 auth.reauth_required` with the account's methods.
pub async fn required(state: &AppState, user: &UserRow) -> ApiError {
    let methods = methods(state, user).await.unwrap_or_default();
    ApiError::ForbiddenMeta {
        code: "auth.reauth_required",
        detail: "Confirm with your password, a passkey or single sign-on first".into(),
        meta: serde_json::json!({ "methods": methods }),
    }
}

/// `true` if the `Tavrn-Reauth` header carries a valid reauth token for this request's session.
pub async fn header_valid(state: &AppState, auth: &AuthUser, headers: &HeaderMap) -> Result<bool, ApiError> {
    let token = headers.get(HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
    Ok(!token.is_empty() && token.len() <= 2048 && valid(state, auth, token).await?)
}

/// Requires a valid reauth token in the `Tavrn-Reauth` header.
pub async fn require(state: &AppState, auth: &AuthUser, headers: &HeaderMap) -> Result<(), ApiError> {
    if header_valid(state, auth, headers).await? {
        return Ok(());
    }
    Err(required(state, &auth.user).await)
}

/// Like [`require`], but the current password in the request body counts as well (routes that always asked for it).
pub async fn require_or_password(
    state: &AppState,
    auth: &AuthUser,
    headers: &HeaderMap,
    password: Option<&str>,
) -> Result<(), ApiError> {
    match password.filter(|p| !p.is_empty()) {
        Some(p) => check_password(state, &auth.user, p).await,
        None => require(state, auth, headers).await,
    }
}

/// Checks the current password (rate-limited like the login).
pub async fn check_password(state: &AppState, user: &UserRow, password: &str) -> Result<(), ApiError> {
    state.login_limiter.check_all(&[format!("user:{}", user.username)]).await?;
    if !user.password_hash.as_deref().is_some_and(|h| crate::auth::verify_password(password, h)) {
        return Err(ApiError::Unauthorized { code: "auth.invalid_credentials" });
    }
    Ok(())
}

/// The reauth token that comes with a new session (`AuthResponse.reauth_token`): the login just proved the credentials.
pub async fn for_new_session(
    state: &AppState,
    user_id: &str,
    tokens: &crate::auth::TokenPair,
) -> Result<String, ApiError> {
    let session = store::users::session_by_hash(&state.db, &util::sha256_b64(&tokens.refresh_token))
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("new session not found")))?;
    Ok(issue_for(state, user_id, &session.device_id, &session.id)?.reauth_token)
}
