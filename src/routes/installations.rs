// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of the add flow and the node-level application controls (protocol/APPLICATIONS.md §1.8, §4):
//! the public application document, installations per room, the bot's install index and the admin routes
//! (applications, blocklist). The logic lives in `crate::installations`.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    applications as apps,
    auth::{AuthUser, NodeAdmin},
    error::{ApiError, ApiJson, ProblemDetails},
    installations::{self, InstallRequest, Installation, PublicApplication},
    models::User,
    store, util,
    validate::{self, bad},
};

pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route("/applications/{application_id}/public", get(public_document))
        .route("/applications/me/installations", get(my_installations))
        .route("/rooms/{room_id}/applications", get(list).post(install).layer(small()))
        .route("/rooms/{room_id}/applications/{application_ref}", axum::routing::delete(uninstall))
        .route("/admin/applications", get(admin_list))
        .route("/admin/applications/blocks", get(admin_blocks).post(admin_block).layer(small()))
        .route("/admin/applications/blocks/{bot}", axum::routing::delete(admin_unblock))
        .route("/admin/applications/{application_id}", patch(admin_update).delete(admin_delete).layer(small()))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        public_document,
        my_installations,
        list,
        install,
        uninstall,
        admin_list,
        admin_update,
        admin_delete,
        admin_blocks,
        admin_block,
        admin_unblock
    ),
    components(schemas(
        PublicApplication,
        InstallRequest,
        Installation,
        installations::InstalledApplication,
        InstallIndexEntry,
        AdminApplication,
        AdminApplicationUpdate,
        ApplicationBlock,
        ApplicationBlockRequest
    ))
)]
pub struct InstallationsApi;

// ---------------------------------------------------------------- public document (§1.8)

/// The public document of an application (no authentication, CORS-open, cacheable 5 minutes). Disabled,
/// blocked and deleted applications answer `404 app.not_found`.
#[utoipa::path(get, path = "/api/v1/applications/{application_id}/public", params(("application_id" = String, Path)),
    responses((status = 200, body = PublicApplication), (status = 404, body = ProblemDetails)))]
pub async fn public_document(State(state): State<AppState>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let doc = installations::document(&state, &id).await?.ok_or_else(apps::not_found)?;
    let mut response = Json(doc).into_response();
    let cache = format!("public, max-age={}", installations::DOCUMENT_MAX_AGE_SECS);
    if let Ok(v) = HeaderValue::from_str(&cache) {
        response.headers_mut().insert(header::CACHE_CONTROL, v);
    }
    Ok(response)
}

// ---------------------------------------------------------------- installations (§4.2, §4.3)

/// Install an application in a room (`manage_applications`; the nine checks of APPLICATIONS.md §4.2 in order).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/applications", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body = InstallRequest,
    responses((status = 201, body = Installation), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn install(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<InstallRequest>,
) -> Result<(StatusCode, Json<Installation>), ApiError> {
    if req.application.len() > 512 {
        return Err(apps::not_found());
    }
    Ok((StatusCode::CREATED, Json(installations::install(&state, &auth, &room_id, req).await?)))
}

/// The applications installed in a room (`manage_applications` or `manage_room`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/applications", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Vec<Installation>), (status = 403, body = ProblemDetails)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<Installation>>, ApiError> {
    Ok(Json(installations::list(&state, &auth, &room_id).await?))
}

/// Uninstall an application (`manage_applications`): the bot leaves (`member.leave`, `mls.remove_needed`), its managed
/// role is deleted, the bot is told. `application_ref` is `<domain>/<id>` (slash percent-encoded).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/applications/{application_ref}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("application_ref" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn uninstall(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, reference)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    installations::remove(&state, &auth, &room_id, &reference).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A room the bot is installed in (its home node's index).
#[derive(Serialize, ToSchema)]
pub struct InstallIndexEntry {
    /// Domain of the room's node.
    pub node: String,
    pub room_id: String,
    pub room_name: String,
    pub installed_at: String,
}

/// With an app token: every room the bot is installed in, on this node and on others (the SDK opens
/// federated sessions with those nodes).
#[utoipa::path(get, path = "/api/v1/applications/me/installations", security(("bearer" = [])),
    responses((status = 200, body = Vec<InstallIndexEntry>), (status = 404, body = ProblemDetails)))]
pub async fn my_installations(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<InstallIndexEntry>>, ApiError> {
    let app_id = match &auth.app {
        Some(app) if app.token_id.is_some() && !auth.is_remote() => app.application_id.clone(),
        _ => return Err(apps::not_found()),
    };
    Ok(Json(
        store::installations::index_of(&state.db, &app_id)
            .await?
            .into_iter()
            .map(|r| InstallIndexEntry {
                node: r.node,
                room_id: r.room_id,
                room_name: r.room_name,
                installed_at: r.installed_at,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------- node administration (§4.4)

/// A local application as node admins see it.
#[derive(Serialize, ToSchema)]
pub struct AdminApplication {
    pub id: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    pub bot: User,
    /// Owner address.
    pub owner: String,
    pub public: bool,
    pub tokens: i64,
    /// Rooms it is installed in (this node and others).
    pub installations: i64,
    pub disabled: bool,
    /// `admin`, `owner_disabled` or `blocked`.
    pub disabled_reason: Option<String>,
    pub created_at: String,
}

/// The applications of this node (node admins).
#[utoipa::path(get, path = "/api/v1/admin/applications", security(("bearer" = [])),
    responses((status = 200, body = Vec<AdminApplication>), (status = 403, body = ProblemDetails)))]
pub async fn admin_list(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<AdminApplication>>, ApiError> {
    let mut out = Vec::new();
    for app in store::installations::all_applications(&state.db).await? {
        let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { continue };
        let owner = store::users::by_id(&state.db, &app.owner_id).await?.map(|o| o.address()).unwrap_or_default();
        let reason = match apps::disabled_reason(&state, &app, &bot).await? {
            Some("disabled") => Some(app.disabled_reason.clone().unwrap_or_else(|| "admin".into())),
            other => other.map(String::from),
        };
        out.push(AdminApplication {
            id: app.id.clone(),
            reference: apps::app_ref(&state, &app.id),
            name: app.name.clone(),
            bot: bot.to_public(),
            owner,
            public: app.public != 0,
            tokens: store::applications::count_tokens(&state.db, &app.id).await?,
            installations: store::installations::index_count(&state.db, &app.id).await?,
            disabled: reason.is_some(),
            disabled_reason: reason,
            created_at: app.created_at.clone(),
        });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct AdminApplicationUpdate {
    /// Disable (`disabled_reason = admin`) or re-enable the application.
    pub disabled: bool,
}

async fn local_app(state: &AppState, id: &str) -> Result<store::applications::ApplicationRow, ApiError> {
    if !util::is_ulid(id) {
        return Err(apps::not_found());
    }
    store::applications::by_id(&state.db, id).await?.ok_or_else(apps::not_found)
}

/// Disable or re-enable an application (node admins). Disabling closes the bot's WebSockets and ends its
/// federated sessions; tokens then fail with `403 app.disabled`.
#[utoipa::path(patch, path = "/api/v1/admin/applications/{application_id}", security(("bearer" = [])),
    params(("application_id" = String, Path)), request_body = AdminApplicationUpdate,
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_update(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<AdminApplicationUpdate>,
) -> Result<StatusCode, ApiError> {
    let app = local_app(&state, &id).await?;
    store::installations::set_disabled(&state.db, &app.id, req.disabled).await?;
    if req.disabled {
        apps::close_bot(&state, &app.bot_user_id).await?;
        if let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? {
            crate::federation::remote::revoke_sessions(&state, &bot, None).await?;
        }
    }
    let bot = store::users::by_id(&state.db, &app.bot_user_id).await?.map(|b| b.address()).unwrap_or_default();
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.app_disable",
        &bot,
        "",
        json!({ "application": apps::app_ref(&state, &app.id), "disabled": req.disabled }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete an application (node admins, APPLICATIONS.md §1.7).
#[utoipa::path(delete, path = "/api/v1/admin/applications/{application_id}", security(("bearer" = [])),
    params(("application_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_delete(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let app = local_app(&state, &id).await?;
    apps::delete_application(&state, &app, &admin.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A blocked bot address.
#[derive(Serialize, ToSchema)]
pub struct ApplicationBlock {
    /// Bot address.
    pub bot: String,
    pub reason: String,
    /// Address of the admin who blocked it.
    pub created_by: Option<String>,
    pub created_at: String,
}

/// The node's application blocklist (node admins).
#[utoipa::path(get, path = "/api/v1/admin/applications/blocks", security(("bearer" = [])),
    responses((status = 200, body = Vec<ApplicationBlock>), (status = 403, body = ProblemDetails)))]
pub async fn admin_blocks(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<ApplicationBlock>>, ApiError> {
    let mut out = Vec::new();
    for b in store::installations::blocks(&state.db).await? {
        let created_by = match &b.created_by {
            Some(id) => store::users::by_id(&state.db, id).await?.map(|u| u.address()),
            None => None,
        };
        out.push(ApplicationBlock { bot: b.subject, reason: b.reason, created_by, created_at: b.created_at });
    }
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct ApplicationBlockRequest {
    /// Bot address `name@domain` (this node's or another's).
    pub bot: String,
    /// At most 500 characters.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Block a bot on this node: it is uninstalled from every room here (`reason: blocked`) and refused for
/// installations, tokens and federated logins (`403 app.blocked`).
#[utoipa::path(post, path = "/api/v1/admin/applications/blocks", security(("bearer" = [])), request_body = ApplicationBlockRequest,
    responses((status = 201, body = ApplicationBlock), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails)))]
pub async fn admin_block(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    ApiJson(req): ApiJson<ApplicationBlockRequest>,
) -> Result<(StatusCode, Json<ApplicationBlock>), ApiError> {
    let address = req.bot.trim().to_lowercase();
    if address.len() > 320
        || !util::parse_address(&address).is_some_and(|(n, d)| util::valid_username(n) && util::valid_domain(d))
    {
        return Err(bad("validation.address", "bot: name@domain"));
    }
    let reason = validate::text("reason", req.reason.as_deref().unwrap_or(""), 0, 500)?;
    if store::applications::is_blocked(&state.db, &address).await? {
        return Err(ApiError::conflict("app.already_blocked", "This bot is blocked already"));
    }
    if let Some((name, domain)) = util::parse_address(&address)
        && let Some(user) = store::federation::user_by_address(&state.db, name, domain).await?
        && !user.is_bot()
    {
        return Err(bad("app.not_a_bot", "This address is not a bot"));
    }
    installations::block(&state, &admin.user, &address, &reason).await?;
    Ok((
        StatusCode::CREATED,
        Json(ApplicationBlock {
            bot: address,
            reason,
            created_by: Some(admin.user.address()),
            created_at: util::now(),
        }),
    ))
}

/// Lift a block (no automatic reinstallation).
#[utoipa::path(delete, path = "/api/v1/admin/applications/blocks/{bot}", security(("bearer" = [])), params(("bot" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_unblock(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(bot): Path<String>,
) -> Result<StatusCode, ApiError> {
    let address = bot.trim().to_lowercase();
    if !store::installations::remove_block(&state.db, &address).await? {
        return Err(ApiError::NotFound { code: "app.block_not_found", what: "Block".into() });
    }
    store::rooms::audit(&state.db, None, Some(&admin.user.id), "admin.app_unblock", &address, "", json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}
