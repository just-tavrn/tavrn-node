// SPDX-License-Identifier: AGPL-3.0-only
//! Single sign-on routes (APPLICATIONS.md §8, PROTOCOL.md §5a.6): start, the provider's callback, the
//! one-time code exchange, the linked identity and the admin's group map. Every route answers
//! `404 sso.disabled` without a configured issuer.

use std::collections::BTreeMap;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    auth::{self, AuthUser, ClientIp, NodeAdmin},
    error::{ApiError, ApiJson, ApiQuery as Query, ProblemDetails},
    oidc::{self, Oidc, Purpose, account, groups},
    routes::auth::{AuthResponse, client_header, device_name},
    store,
    util::now,
};

/// The SSO routes, nested under `/api/v1` by `app::router`.
pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route("/auth/oidc/start", post(start).layer(small()))
        .route("/auth/oidc/callback", get(callback))
        .route("/auth/oidc/token", post(token).layer(small()))
        .route("/auth/oidc/identity", get(identity).delete(unlink))
        .route("/admin/sso/group-map", get(get_group_map).put(put_group_map).layer(DefaultBodyLimit::max(256 * 1024)))
}

#[derive(OpenApi)]
#[openapi(
    paths(start, callback, token, identity, unlink, get_group_map, put_group_map),
    components(schemas(
        Purpose,
        OidcStartRequest,
        OidcStartResponse,
        OidcTokenRequest,
        OidcTokenResponse,
        OidcLinked,
        OidcReauth,
        OidcIdentity,
        GroupMapDocument,
        GroupMapUpdate,
        groups::GroupRights,
        groups::RoomGrant,
        SsoInfo,
        LogoutResponse
    ))
)]
pub struct OidcApi;

fn configured(state: &AppState) -> Result<&Oidc, ApiError> {
    state.oidc.as_deref().ok_or_else(oidc::disabled)
}

/// SSO settings for the login page (`GET /node`).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SsoInfo {
    /// Button text set by the operator; null = the client's own "Sign in with SSO".
    pub label: Option<String>,
    /// `TAVRN_OIDC_ONLY`: password and passkey-only logins are disabled (break-glass admins excepted).
    pub only: bool,
}

pub fn info(state: &AppState) -> Option<SsoInfo> {
    state.oidc.as_ref().map(|o| SsoInfo { label: o.settings.label.clone(), only: o.settings.only })
}

/// The full session of a local user from the `Authorization` header (link, reauth).
async fn local_session(state: &AppState, headers: &HeaderMap) -> Result<AuthUser, ApiError> {
    let token = auth::bearer(headers).ok_or(ApiError::Unauthorized { code: "auth.required" })?;
    let auth = auth::authenticate(state, token).await?;
    if auth.is_remote() {
        return Err(crate::federation::guard::local_only());
    }
    Ok(auth)
}

fn valid_client_state(s: &str) -> bool {
    (16..=128).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Deserialize, ToSchema)]
pub struct OidcStartRequest {
    pub purpose: Purpose,
    /// The client's PKCE challenge (S256, base64url of 32 bytes); binds the final exchange to this browser.
    pub code_challenge: String,
    /// Opaque value (16–128 characters of `[A-Za-z0-9_-]`) returned unchanged on the redirect to the client.
    pub client_state: String,
    /// Name of the new device (login only).
    pub device_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OidcStartResponse {
    /// Where the browser goes next (the provider's authorization endpoint).
    pub authorization_url: String,
    pub expires_in: i64,
}

/// Starts an SSO flow (§8.2). `login` needs no session; `link` and `reauth` need the full session of a
/// local user (`link`: not linked yet, and a reauth token in `Tavrn-Reauth`, PROTOCOL.md §5c; `reauth`: linked).
#[utoipa::path(post, path = "/api/v1/auth/oidc/start", request_body = OidcStartRequest,
    responses((status = 200, body = OidcStartResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<OidcStartRequest>,
) -> Result<Json<OidcStartResponse>, ApiError> {
    let oidc = configured(&state)?;
    oidc.start_limiter.check_all(&[format!("ip:{ip}")])?;
    if !valid_client_state(&req.client_state) {
        return Err(ApiError::BadRequest { code: "validation.client_state", detail: "client_state invalid".into() });
    }
    if !crate::routes::connect::valid_challenge(&req.code_challenge) {
        return Err(ApiError::BadRequest {
            code: "validation.code_challenge",
            detail: "code_challenge: S256, base64url of 32 bytes".into(),
        });
    }
    let user_id = match req.purpose {
        Purpose::Login => None,
        Purpose::Link | Purpose::Reauth => {
            let auth = local_session(&state, &headers).await?;
            let linked = store::oidc::identity_of_user(&state.db, &auth.user.id, &oidc.settings.issuer).await?;
            match (req.purpose, linked) {
                (Purpose::Link, Some(_)) => return Err(account::already_linked()),
                (Purpose::Reauth, None) => return Err(not_linked()),
                _ => {}
            }
            // Linking adds a login method that skips the second factor (§8.4): a fresh proof, like a new passkey.
            if req.purpose == Purpose::Link {
                crate::reauth::require(&state, &auth, &headers).await?;
            }
            Some(auth.user.id)
        }
    };
    let device = device_name(req.device_name.as_deref(), "SSO");
    let url = oidc.start(req.purpose, user_id, &req.code_challenge, &req.client_state, device).await?;
    Ok(Json(OidcStartResponse { authorization_url: url, expires_in: oidc::STATE_TTL.as_secs() as i64 }))
}

fn not_linked() -> ApiError {
    ApiError::conflict("sso.not_linked", "This account is not linked to an identity of the provider")
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// The provider's redirect (register `<public URL>/api/v1/auth/oidc/callback` there). Always answers `303`
/// to the node's own web client, `<web>/sso/callback?code=…&state=<client_state>` or `?error=<code>&state=…`;
/// tokens never appear in URLs.
#[utoipa::path(get, path = "/api/v1/auth/oidc/callback", params(CallbackQuery),
    responses((status = 303, description = "Redirect to <web>/sso/callback"), (status = 404, body = ProblemDetails)))]
pub async fn callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Result<Response, ApiError> {
    let oidc = configured(&state)?;
    let provider_state = q.state.as_deref().unwrap_or("");
    let target = match oidc.callback(provider_state, q.code.as_deref(), q.error.as_deref()).await {
        Ok((client_state, code)) => oidc.web_redirect(&[("code", &code), ("state", &client_state)]),
        Err((client_state, e)) => {
            tracing::info!(issuer = oidc.settings.issuer, error = e.code(), "SSO: callback failed");
            let mut query = vec![("error", e.code().to_string())];
            if let oidc::SsoError::IdpError(detail) = &e {
                query.push(("idp_error", detail.clone()));
            }
            if let Some(s) = client_state {
                query.push(("state", s));
            }
            let pairs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();
            oidc.web_redirect(&pairs)
        }
    };
    let mut response = Redirect::to(&target).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Deserialize, ToSchema)]
pub struct OidcTokenRequest {
    /// The one-time code from the redirect.
    pub code: String,
    /// The PKCE verifier of the start request's challenge.
    pub code_verifier: String,
    /// `login`: continue an existing device of the account (PROTOCOL.md §5b); an invalid proof means a new device.
    pub device: Option<crate::device_proof::DeviceProof>,
}

#[derive(Serialize, ToSchema)]
pub struct OidcLinked {
    pub linked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct OidcReauth {
    /// Single use, for `POST /users/me/identity/reset` instead of the password.
    pub reauth_token: String,
    pub expires_in: i64,
}

/// `login`: the session; `link`: `{ linked }`; `reauth`: `{ reauth_token, expires_in }`.
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum OidcTokenResponse {
    Session(Box<AuthResponse>),
    Linked(OidcLinked),
    Reauth(OidcReauth),
}

/// Exchanges the one-time code (single use, 60 s, bound to the start request's challenge). The login is
/// completed here: the account is found or provisioned, the group map applied and the session issued
/// without a second factor (§8.4). `link` and `reauth` additionally need the session that started the flow.
#[utoipa::path(post, path = "/api/v1/auth/oidc/token", request_body = OidcTokenRequest,
    responses((status = 200, body = OidcTokenResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<OidcTokenRequest>,
) -> Result<Json<OidcTokenResponse>, ApiError> {
    let oidc = configured(&state)?;
    oidc.token_limiter.check_all(&[format!("ip:{ip}")])?;
    let pending = oidc.take_code(req.code.trim(), &req.code_verifier).await?;
    let identity = &pending.identity;
    let issuer = &oidc.settings.issuer;
    match pending.purpose {
        Purpose::Login => {
            let user = match account::login_account(&state, oidc, identity).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::info!(issuer, result = e.code(), "SSO: login refused");
                    return Err(e);
                }
            };
            groups::sync(&state, &user, &identity.groups).await?;
            let user = store::users::by_id(&state.db, &user.id)
                .await?
                .ok_or(ApiError::Unauthorized { code: "auth.account_disabled" })?;
            let reuse = crate::device_proof::verify_opt(&state, &user, req.device.as_ref()).await?;
            let session = account::start_session(
                &state,
                oidc,
                &user,
                &pending.device_name,
                &client_header(&headers),
                reuse.as_deref(),
            )
            .await?;
            tracing::info!(issuer, user = user.address(), device = session.tokens.device_id, "SSO: login");
            Ok(Json(OidcTokenResponse::Session(Box::new(session))))
        }
        Purpose::Link | Purpose::Reauth => {
            let auth = local_session(&state, &headers).await?;
            if pending.user_id.as_deref() != Some(auth.user.id.as_str()) {
                return Err(ApiError::Forbidden {
                    code: "sso.session_mismatch",
                    detail: "The flow was started by another account".into(),
                });
            }
            if pending.purpose == Purpose::Link {
                account::link(&state, oidc, &auth.user, identity).await?;
                tracing::info!(issuer, user = auth.user.address(), "SSO: identity linked");
                return Ok(Json(OidcTokenResponse::Linked(OidcLinked { linked: true })));
            }
            let linked = store::oidc::identity_of_user(&state.db, &auth.user.id, issuer).await?;
            if linked.is_none_or(|l| l.subject != identity.subject) {
                return Err(ApiError::Forbidden {
                    code: "sso.identity_mismatch",
                    detail: "The provider confirmed a different identity than the one linked to this account".into(),
                });
            }
            // The sudo-mode token of PROTOCOL.md §5c (identity reset and every other sensitive change).
            let token = crate::reauth::issue(&state, &auth).await?;
            Ok(Json(OidcTokenResponse::Reauth(OidcReauth {
                reauth_token: token.reauth_token,
                expires_in: token.expires_in,
            })))
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct OidcIdentity {
    pub issuer: String,
    pub linked_at: String,
    pub last_login_at: Option<String>,
}

/// The provider identity linked to the account, or null.
#[utoipa::path(get, path = "/api/v1/auth/oidc/identity", security(("bearer" = [])),
    responses((status = 200, body = Option<OidcIdentity>), (status = 404, body = ProblemDetails)))]
pub async fn identity(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Option<OidcIdentity>>, ApiError> {
    let oidc = configured(&state)?;
    let linked = store::oidc::identity_of_user(&state.db, &auth.user.id, &oidc.settings.issuer).await?;
    Ok(Json(linked.map(|l| OidcIdentity { issuer: l.issuer, linked_at: l.linked_at, last_login_at: l.last_login_at })))
}

/// Unlinks the identity; only if the account keeps a password and a second factor (§8.3). Needs a reauth token
/// (`Tavrn-Reauth`, PROTOCOL.md §5c).
#[utoipa::path(delete, path = "/api/v1/auth/oidc/identity", security(("bearer" = [])),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn unlink(State(state): State<AppState>, headers: HeaderMap, auth: AuthUser) -> Result<StatusCode, ApiError> {
    let oidc = configured(&state)?;
    crate::reauth::require(&state, &auth, &headers).await?;
    let issuer = &oidc.settings.issuer;
    if store::oidc::identity_of_user(&state.db, &auth.user.id, issuer).await?.is_none() {
        return Err(not_linked());
    }
    if auth.user.password_hash.is_none() || !store::factors::has_factor(&state.db, &auth.user.id).await? {
        return Err(ApiError::conflict(
            "sso.last_login_method",
            "Single sign-on is this account's only way to sign in (a password and a second factor are needed first)",
        ));
    }
    store::oidc::unlink(&state.db, &auth.user.id, issuer).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "sso.unlink",
        &auth.user.address(),
        "",
        serde_json::json!({ "issuer": issuer }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, ToSchema)]
pub struct GroupMapDocument {
    pub map: BTreeMap<String, groups::GroupRights>,
    /// `true` if `TAVRN_OIDC_GROUP_MAP` sets the map (read-only here).
    pub fixed: bool,
    /// `add` or `sync` (`TAVRN_OIDC_GROUP_SYNC`).
    pub sync: String,
}

/// The group → rights map in force (§8.5).
#[utoipa::path(get, path = "/api/v1/admin/sso/group-map", security(("bearer" = [])),
    responses((status = 200, body = GroupMapDocument), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_group_map(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<GroupMapDocument>, ApiError> {
    let oidc = configured(&state)?;
    Ok(Json(GroupMapDocument {
        map: groups::current(&state).await?,
        fixed: oidc.settings.group_map.is_some(),
        sync: match oidc.settings.group_sync {
            crate::config::OidcGroupSync::Add => "add".into(),
            crate::config::OidcGroupSync::Sync => "sync".into(),
        },
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct GroupMapUpdate {
    pub map: BTreeMap<String, groups::GroupRights>,
}

/// Replaces the group map (unless the environment fixes it). Takes effect at the users' next SSO login.
#[utoipa::path(put, path = "/api/v1/admin/sso/group-map", security(("bearer" = [])), request_body = GroupMapUpdate,
    responses((status = 200, body = GroupMapDocument), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn put_group_map(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    ApiJson(req): ApiJson<GroupMapUpdate>,
) -> Result<Json<GroupMapDocument>, ApiError> {
    let oidc = configured(&state)?;
    if oidc.settings.group_map.is_some() {
        return Err(ApiError::conflict("sso.group_map_fixed", "TAVRN_OIDC_GROUP_MAP fixes the group map"));
    }
    groups::validate(&req.map).map_err(|e| ApiError::BadRequest { code: "sso.group_map_invalid", detail: e })?;
    groups::store_map(&state, &req.map).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.sso_group_map",
        "",
        "",
        serde_json::json!({ "issuer": oidc.settings.issuer, "groups": req.map.keys().collect::<Vec<_>>(), "at": now() }),
    )
    .await?;
    get_group_map(State(state), NodeAdmin(admin)).await
}

/// `POST /auth/logout` of an SSO session: the provider's logout URL (§8.6).
#[derive(Serialize, ToSchema)]
pub struct LogoutResponse {
    pub end_session_url: String,
}

/// The provider's logout URL if `device_id` holds a live SSO session (called before it is revoked).
pub async fn logout_url(state: &AppState, device_id: &str) -> Result<Option<String>, ApiError> {
    let Some(oidc) = state.oidc.as_ref() else { return Ok(None) };
    if !store::oidc::device_has_sso_session(&state.db, device_id).await? {
        return Ok(None);
    }
    Ok(oidc.end_session_url().await)
}
