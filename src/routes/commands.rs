// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of application commands (protocol/APPLICATIONS.md §5): definitions (owner and bot), the node
//! approval (admins), per-room settings (`manage_applications`), the `/` palette, invocations, callbacks and
//! follow-ups. The logic lives in `crate::commands` and `crate::interactions`.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{OpenApi, ToSchema};

use crate::{
    access,
    app::AppState,
    applications as apps,
    auth::{AuthUser, NodeAdmin},
    commands::{
        self, CommandArg, CommandDefinition, CommandOption, CommandSet, CommandSettings, PaletteApplication,
        PaletteCommand, PutCommandSettings, PutCommandsRequest, RoomCommand, RoomCommands,
    },
    error::{ApiError, ApiJson, ProblemDetails},
    installations,
    interactions::{self, Callback, EphemeralReply, FollowUp, FollowUpResponse, InvokeRequest, InvokeResponse},
    routes::applications::{bot_context, owned, require_person},
    store,
};

pub fn routes() -> Router<AppState> {
    let definitions = || DefaultBodyLimit::max(commands::MAX_SET_BYTES + 16 * 1024);
    let small = || DefaultBodyLimit::max(32 * 1024);
    let answer = || DefaultBodyLimit::max(crate::routes::messages::MAX_CONTENT_BYTES + 8 * 1024);
    Router::new()
        .route("/applications/{application_id}/commands", get(get_commands).put(put_commands).layer(definitions()))
        .route("/applications/me/commands", get(get_my_commands).put(put_my_commands).layer(definitions()))
        .route("/conversations/{conversation_id}/commands", get(palette))
        .route("/conversations/{conversation_id}/interactions", post(invoke).layer(small()))
        .route("/interactions/{interaction_id}/callback", post(callback).layer(answer()))
        .route("/interactions/{interaction_id}/messages", post(follow_up).layer(answer()))
        .route("/rooms/{room_id}/commands", get(room_commands))
        .route(
            "/rooms/{room_id}/commands/{command_ref}",
            put(put_room_command).delete(reset_room_command).layer(small()),
        )
        .route("/admin/applications/commands", get(admin_commands))
        .route("/admin/applications/commands/approval", get(admin_approval))
        .route("/admin/applications/commands/approve", post(admin_approve).layer(small()))
        .route("/admin/applications/commands/reject", post(admin_reject).layer(small()))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_commands,
        put_commands,
        get_my_commands,
        put_my_commands,
        palette,
        invoke,
        callback,
        follow_up,
        room_commands,
        put_room_command,
        reset_room_command,
        admin_commands,
        admin_approval,
        admin_approve,
        admin_reject
    ),
    components(schemas(
        CommandDefinition,
        CommandArg,
        CommandOption,
        CommandSet,
        PutCommandsRequest,
        PaletteCommand,
        PaletteApplication,
        InvokeRequest,
        InvokeResponse,
        EphemeralReply,
        Callback,
        FollowUp,
        FollowUpResponse,
        CommandSettings,
        PutCommandSettings,
        RoomCommand,
        RoomCommands,
        CommandApproval,
        CommandApprovalRequest,
        CommandApprovalSettings
    ))
)]
pub struct CommandsApi;

/// The `commands` array of a `PUT …/commands` body (unknown top-level fields: `400 command.invalid`).
fn commands_of(body: &Value) -> Result<Vec<Value>, ApiError> {
    let obj = body.as_object().ok_or_else(|| commands::invalid("", "The body is an object with commands"))?;
    if let Some(k) = obj.keys().find(|k| k.as_str() != "commands") {
        return Err(commands::invalid(k.chars().take(40).collect::<String>(), "Unknown field"));
    }
    match obj.get("commands") {
        Some(Value::Array(list)) => Ok(list.clone()),
        _ => Err(commands::invalid("commands", "commands is an array")),
    }
}

// ---------------------------------------------------------------- definitions (§5.1)

/// The command set of one of the caller's applications (owner).
#[utoipa::path(get, path = "/api/v1/applications/{application_id}/commands", security(("bearer" = [])),
    params(("application_id" = String, Path)),
    responses((status = 200, body = CommandSet), (status = 404, body = ProblemDetails)))]
pub async fn get_commands(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CommandSet>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let reference = apps::app_ref(&state, &app.id);
    Ok(Json(CommandSet {
        commands: commands::local_set(&state, &reference).await?,
        commands_version: app.commands_version,
    }))
}

/// Replace the whole command set of one of the caller's applications (owner, 10 per hour).
#[utoipa::path(put, path = "/api/v1/applications/{application_id}/commands", security(("bearer" = [])),
    params(("application_id" = String, Path)), request_body = PutCommandsRequest,
    responses((status = 200, body = CommandSet), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn put_commands(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<CommandSet>, ApiError> {
    require_person(&auth)?;
    let app = owned(&state, &auth, &id).await?;
    let list = commands_of(&body)?;
    Ok(Json(commands::put_local(&state, &auth.user, &app, &list).await?))
}

async fn my_app(state: &AppState, auth: &AuthUser) -> Result<store::applications::ApplicationRow, ApiError> {
    let ctx = bot_context(auth)?;
    store::applications::by_id(&state.db, &ctx.application_id).await?.ok_or_else(apps::not_found)
}

/// The bot's own command set (app token with the `commands` scope).
#[utoipa::path(get, path = "/api/v1/applications/me/commands", security(("bearer" = [])),
    responses((status = 200, body = CommandSet), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_my_commands(State(state): State<AppState>, auth: AuthUser) -> Result<Json<CommandSet>, ApiError> {
    let app = my_app(&state, &auth).await?;
    let reference = apps::app_ref(&state, &app.id);
    Ok(Json(CommandSet {
        commands: commands::local_set(&state, &reference).await?,
        commands_version: app.commands_version,
    }))
}

/// Replace the bot's own command set (app token with the `commands` scope, 10 per hour).
#[utoipa::path(put, path = "/api/v1/applications/me/commands", security(("bearer" = [])), request_body = PutCommandsRequest,
    responses((status = 200, body = CommandSet), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn put_my_commands(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<CommandSet>, ApiError> {
    let app = my_app(&state, &auth).await?;
    let list = commands_of(&body)?;
    Ok(Json(commands::put_local(&state, &auth.user, &app, &list).await?))
}

// ---------------------------------------------------------------- palette and invocation (§5.4, §5.5)

/// The application commands the caller can invoke in this conversation right now (§5.4).
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/commands", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = Vec<PaletteCommand>), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn palette(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<Vec<PaletteCommand>>, ApiError> {
    if auth.user.is_bot() || auth.app.is_some() {
        return Err(apps::bot_forbidden());
    }
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    Ok(Json(commands::palette(&state, &auth, &conv).await?))
}

/// Invoke an application command (§5.5); waits at most 3 seconds for the application's first response.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/interactions", security(("bearer" = [])),
    params(("conversation_id" = String, Path)), request_body = InvokeRequest,
    responses((status = 200, body = InvokeResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails),
        (status = 504, body = ProblemDetails)))]
pub async fn invoke(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<InvokeRequest>,
) -> Result<Json<InvokeResponse>, ApiError> {
    if auth.user.is_bot() || auth.app.is_some() {
        return Err(apps::bot_forbidden());
    }
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    let language = headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok());
    Ok(Json(interactions::invoke(&state, &auth, &conv, req, language).await?))
}

/// The application's first response to an interaction (app token with the `commands` scope): `reply`,
/// `defer` or `error`. Only the first response counts; after 3 seconds it is `410 interaction.expired`.
#[utoipa::path(post, path = "/api/v1/interactions/{interaction_id}/callback", security(("bearer" = [])),
    params(("interaction_id" = String, Path)), request_body = Callback,
    responses((status = 200, body = InvokeResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 410, body = ProblemDetails)))]
pub async fn callback(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<Callback>,
) -> Result<Json<InvokeResponse>, ApiError> {
    Ok(Json(interactions::respond(&state, &auth, &id, body).await?))
}

/// A follow-up of the application (until the interaction expires, at most 10).
#[utoipa::path(post, path = "/api/v1/interactions/{interaction_id}/messages", security(("bearer" = [])),
    params(("interaction_id" = String, Path)), request_body = FollowUp,
    responses((status = 201, body = FollowUpResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 410, body = ProblemDetails),
        (status = 429, body = ProblemDetails)))]
pub async fn follow_up(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<FollowUp>,
) -> Result<(StatusCode, Json<FollowUpResponse>), ApiError> {
    Ok((StatusCode::CREATED, Json(interactions::follow_up(&state, &auth, &id, body).await?)))
}

// ---------------------------------------------------------------- per-room settings (§5.3)

/// The commands of every installed application with their settings in this room (`manage_applications` or
/// `manage_room`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/commands", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Vec<RoomCommands>), (status = 403, body = ProblemDetails)))]
pub async fn room_commands(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<RoomCommands>>, ApiError> {
    Ok(Json(commands::room_list(&state, &auth, &room_id).await?))
}

/// Replace the settings of one command in this room (`manage_applications`). `command_ref` is
/// `<application ref>/<command id>` with the slashes percent-encoded.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/commands/{command_ref}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("command_ref" = String, Path)), request_body = PutCommandSettings,
    responses((status = 200, body = RoomCommand), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails)))]
pub async fn put_room_command(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, command_ref)): Path<(String, String)>,
    ApiJson(body): ApiJson<PutCommandSettings>,
) -> Result<Json<RoomCommand>, ApiError> {
    Ok(Json(commands::put_room_setting(&state, &auth, &room_id, &command_ref, body).await?))
}

/// Reset one command of this room to the defaults (`manage_applications`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/commands/{command_ref}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("command_ref" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn reset_room_command(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, command_ref)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    commands::reset_room_setting(&state, &auth, &room_id, &command_ref).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- node approval (§5.2)

/// A command definition and its approval state on this node.
#[derive(Serialize, ToSchema)]
pub struct CommandApproval {
    /// Application reference.
    pub application: String,
    pub command: CommandDefinition,
    pub definition_hash: String,
    /// `pending`, `approved` or `rejected`.
    pub state: String,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct ApprovalQuery {
    /// `pending`, `approved` or `rejected`; all without.
    pub state: Option<String>,
}

/// Command definitions of the applications known on this node and their approval state (node admins).
#[utoipa::path(get, path = "/api/v1/admin/applications/commands", security(("bearer" = [])), params(ApprovalQuery),
    responses((status = 200, body = Vec<CommandApproval>), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn admin_commands(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(q): Query<ApprovalQuery>,
) -> Result<Json<Vec<CommandApproval>>, ApiError> {
    let filter = match q.state.as_deref() {
        None | Some("") => None,
        Some(s @ ("pending" | "approved" | "rejected")) => Some(s.to_string()),
        Some(_) => {
            return Err(ApiError::BadRequest {
                code: "validation.state",
                detail: "state: pending, approved or rejected".into(),
            });
        }
    };
    let decisions = store::commands::all_approvals(&state.db).await?;
    let mut out = Vec::new();
    for row in store::commands::all(&state.db).await? {
        let st = match decisions.get(&(row.application_ref.clone(), row.definition_hash.clone())).map(String::as_str) {
            Some("approved") => "approved",
            Some("rejected") => "rejected",
            _ => "pending",
        };
        if filter.as_deref().is_some_and(|f| f != st) {
            continue;
        }
        out.push(CommandApproval {
            application: row.application_ref.clone(),
            command: commands::definition_of(&row),
            definition_hash: row.definition_hash.clone(),
            state: st.into(),
        });
    }
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct CommandApprovalSettings {
    /// `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL`: commands are offered only after an admin approved their definition.
    pub required: bool,
}

/// Whether this node requires the approval of application commands (node admins; for the admin UI).
#[utoipa::path(get, path = "/api/v1/admin/applications/commands/approval", security(("bearer" = [])),
    responses((status = 200, body = CommandApprovalSettings), (status = 403, body = ProblemDetails)))]
pub async fn admin_approval(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<CommandApprovalSettings>, ApiError> {
    Ok(Json(CommandApprovalSettings { required: state.config.app_commands_require_approval }))
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandApprovalRequest {
    /// Application reference `<domain>/<id>`.
    pub application: String,
    /// `definition_hash` values of its current definitions (1–100).
    pub hashes: Vec<String>,
}

async fn decide(
    state: &AppState,
    admin: &AuthUser,
    req: CommandApprovalRequest,
    decision: &str,
) -> Result<(), ApiError> {
    let (domain, id) = installations::parse_ref(&req.application)?;
    let reference = format!("{domain}/{id}");
    if req.hashes.is_empty() || req.hashes.len() > commands::MAX_COMMANDS {
        return Err(ApiError::BadRequest {
            code: "validation.hashes",
            detail: "hashes: 1 to 100 definition hashes".into(),
        });
    }
    let current = store::commands::of_app(&state.db, &reference).await?;
    if current.is_empty() {
        return Err(apps::not_found());
    }
    for hash in &req.hashes {
        if !current.iter().any(|r| &r.definition_hash == hash) {
            return Err(ApiError::NotFound { code: "command.not_found", what: "Command definition".into() });
        }
    }
    for hash in &req.hashes {
        store::commands::set_approval(&state.db, &reference, hash, decision, &admin.user.id).await?;
    }
    let action = if decision == "approved" { "admin.app_commands_approve" } else { "admin.app_commands_reject" };
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        action,
        &reference,
        "",
        json!({ "application": reference, "hashes": req.hashes }),
    )
    .await?;
    commands::announce_to_rooms(state, &reference).await;
    Ok(())
}

/// Approve command definitions by their hash (node admins).
#[utoipa::path(post, path = "/api/v1/admin/applications/commands/approve", security(("bearer" = [])), request_body = CommandApprovalRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_approve(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    ApiJson(req): ApiJson<CommandApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    decide(&state, &admin, req, "approved").await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reject command definitions by their hash (node admins): they stay out of the palettes.
#[utoipa::path(post, path = "/api/v1/admin/applications/commands/reject", security(("bearer" = [])), request_body = CommandApprovalRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_reject(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    ApiJson(req): ApiJson<CommandApprovalRequest>,
) -> Result<StatusCode, ApiError> {
    decide(&state, &admin, req, "rejected").await?;
    Ok(StatusCode::NO_CONTENT)
}
