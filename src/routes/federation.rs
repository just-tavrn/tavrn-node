// SPDX-License-Identifier: AGPL-3.0-only
//! Federation routes (FEDERATION.md): federation tokens on the home node, federated sessions on the
//! target node, the signed inbox and public avatars.

use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::{AuthUser, TokenPair},
    error::{ApiError, ApiJson, ProblemDetails},
    federation::{self, client::AVATAR_TYPES, remote, tokens},
    models::UserPrivate,
    routes::auth::{SessionStatus, client_header, device_name},
    store, util,
};

#[derive(Deserialize, ToSchema)]
pub struct FederationTokenRequest {
    /// Domain of the node the token is for, e.g. `community.example`.
    pub target: String,
}

#[derive(Serialize, ToSchema)]
pub struct FederationTokenResponse {
    /// Federation token (JWT, `typ = "federation"`) for `POST /auth/federated` on the target node.
    pub token: String,
    pub target: String,
    pub expires_in: i64,
}

/// Federation token for one target node (FEDERATION.md §2.4). The home node does not contact the target.
#[utoipa::path(post, path = "/api/v1/federation/token", security(("bearer" = [])), request_body = FederationTokenRequest,
    responses((status = 200, body = FederationTokenResponse), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn issue_token(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<FederationTokenRequest>,
) -> Result<Json<FederationTokenResponse>, ApiError> {
    if !state.config.federation_enabled {
        return Err(federation::disabled());
    }
    let target = req.target.trim();
    if !federation::valid_node_domain(target) {
        return Err(ApiError::BadRequest {
            code: "federation.domain_invalid",
            detail: "Not a valid node domain (e.g. community.example)".into(),
        });
    }
    if target == state.config.domain {
        return Err(ApiError::BadRequest {
            code: "federation.target_self",
            detail: "No federation token is needed for this node itself".into(),
        });
    }
    // This node's bots may federate only with `TAVRN_APPS_FEDERATE` (APPLICATIONS.md §2.8); whether other
    // nodes accept them is their `TAVRN_FEDERATION_REMOTE_BOTS`.
    if auth.user.is_bot() && !state.config.apps_federate {
        return Err(ApiError::Forbidden {
            code: "federation.bots_refused",
            detail: "Bots of this node may not use other nodes".into(),
        });
    }
    federation::check_policy(&state, target).await?;
    state.federation_token_limiter.check_all(&[format!("token:{}", auth.device_id)]).await?;
    // Bots: owner, application and effective scopes go into the token (APPLICATIONS.md §2.8).
    let bot = match (&auth.app, auth.user.is_bot()) {
        (Some(app), true) => {
            let owner = match auth.user.owner_id.as_deref() {
                Some(owner_id) => store::users::by_id(&state.db, owner_id).await?.map(|o| o.address()),
                None => None,
            };
            let owner = owner.ok_or_else(crate::applications::bot_forbidden)?;
            Some(tokens::BotClaims { owner, app: &app.application_id, scopes: &app.scopes })
        }
        (_, true) => return Err(crate::applications::bot_forbidden()),
        _ => None,
    };
    let (profile_version, ..) = store::federation::profile_info(&state.db, &auth.user.id).await?;
    let token = tokens::issue_federation_token(
        &state,
        auth.user.address(),
        &auth.user.kind,
        &auth.device_id,
        target,
        profile_version,
        bot,
        // `age.v1`: "18 or older: yes/no/unknown", the only age information that leaves this node (FEDERATION.md §2.2).
        crate::age::claim(&state, &auth.user).await?,
    )?;
    store::federation::touch_target(&state.db, &auth.user.id, &auth.device_id, target).await?;
    tracing::info!(target, device = auth.device_id, "federation token issued");
    Ok(Json(FederationTokenResponse { token, target: target.to_string(), expires_in: tokens::FEDERATION_TTL_SECS }))
}

#[derive(Deserialize, ToSchema)]
pub struct FederatedLoginRequest {
    /// Federation token issued by the user's home node for this node.
    pub token: String,
    pub device_name: Option<String>,
}

/// Session of a remote user on this node.
#[derive(Serialize, ToSchema)]
pub struct FederatedSessionResponse {
    pub status: SessionStatus,
    pub user: UserPrivate,
    /// `device_id` is the device id on the home node.
    #[serde(flatten)]
    pub tokens: TokenPair,
    pub recovery_code_used: bool,
    /// The session ends at this time (7 days after the login) whatever the refreshes; renew it with a
    /// fresh federation token before.
    pub session_expires_at: String,
}

/// Federated login of a user of another node (FEDERATION.md §2.5). No password, captcha or second
/// factor here: the home node enforced them before issuing the token.
#[utoipa::path(post, path = "/api/v1/auth/federated", request_body = FederatedLoginRequest,
    responses((status = 200, body = FederatedSessionResponse), (status = 401, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn federated_login(
    State(state): State<AppState>,
    crate::auth::ClientIp(ip): crate::auth::ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<FederatedLoginRequest>,
) -> Result<Json<FederatedSessionResponse>, ApiError> {
    if !state.config.misbehaves("no_rate_limit") {
        state.login_limiter.check_all(&[format!("federated-ip:{ip}")]).await?;
    }
    let name = device_name(req.device_name.as_deref(), "Device of another node");
    let login = remote::federated_login(&state, &ip, &req.token, &name, &client_header(&headers)).await?;
    Ok(Json(FederatedSessionResponse {
        status: SessionStatus::Ok,
        user: login.user.to_private(),
        tokens: login.tokens,
        recovery_code_used: false,
        session_expires_at: login.session_expires_at,
    }))
}

/// Server-to-server notifications (FEDERATION.md §5.1), authenticated with a node token. Body: the
/// envelope `{ id, type, from, to, at, payload }`, at most 64 KiB.
#[utoipa::path(post, path = "/api/v1/federation/inbox", security(("bearer" = [])),
    responses((status = 202), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn inbox(
    State(state): State<AppState>,
    crate::auth::ClientIp(ip): crate::auth::ClientIp,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    federation::inbox::receive(&state, &ip, &headers, body).await
}

/// KeyPackage claim of another node on behalf of one of its users (FEDERATION.md §3.5), authenticated
/// with a node token. Body `{ user, requester }`: one KeyPackage per attested device of the local `user`.
#[utoipa::path(post, path = "/api/v1/federation/key-packages/claim", security(("bearer" = [])),
    responses((status = 200, body = crate::routes::keys::ClaimedKeyPackages), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn claim(
    State(state): State<AppState>,
    crate::auth::ClientIp(ip): crate::auth::ClientIp,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(federation::claims::serve(&state, &ip, &headers, body).await?))
}

fn avatar_not_found() -> ApiError {
    ApiError::NotFound { code: "avatar.not_found", what: "Avatar".into() }
}

/// Avatar of a user (public, FEDERATION.md §2.7): of a local user by username, or this node's mirror of
/// a remote user by address (`alice@other.example`). `404` without avatar.
#[utoipa::path(get, path = "/api/v1/users/{username}/avatar", params(("username" = String, Path)),
    responses((status = 200, content_type = "image/png"), (status = 404, body = ProblemDetails)))]
pub async fn avatar(State(state): State<AppState>, Path(username): Path<String>) -> Result<Response, ApiError> {
    let name = username.trim().to_lowercase();
    let (username, domain) = match util::parse_address(&name) {
        Some((u, d)) => (u.to_string(), d.to_string()),
        None if util::valid_username(&name) => (name.clone(), state.config.domain.clone()),
        None => return Err(avatar_not_found()),
    };
    let user = store::federation::user_by_address(&state.db, &username, &domain)
        .await?
        .filter(|u| u.disabled_at.is_none())
        .ok_or_else(avatar_not_found)?;
    // The still image of the avatar (local, or this node's mirror); the media routes serve both variants.
    let media = match user.avatar_blob_id.as_deref().filter(|id| util::is_ulid(id)) {
        Some(id) => store::media::by_id(&state.db, id).await?,
        None => None,
    };
    let Some(media) = media else { return Err(avatar_not_found()) };
    let (id, mime) = (media.id, media.mime);
    if !AVATAR_TYPES.contains(&mime.as_str()) {
        return Err(avatar_not_found());
    }
    let bytes = state.storage.read(&id).await?.ok_or_else(avatar_not_found)?;
    if bytes.len() > federation::client::Kind::Avatar.max_bytes() {
        return Err(avatar_not_found());
    }
    let mut resp = bytes.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&mime).unwrap_or(HeaderValue::from_static("image/png")));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}
