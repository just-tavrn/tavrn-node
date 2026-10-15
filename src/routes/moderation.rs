// SPDX-License-Identifier: AGPL-3.0-only
//! Moderation routes (protocol MODERATION.md): reports and the inbox (§1), the content rules of a room (§2), the
//! transfer of a room's ownership (§4) and the node admin's room list (single sign-on group map picker).

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access,
    app::AppState,
    auth::{AuthUser, NodeAdmin},
    automod::{self, AutomodRule},
    error::{ApiError, ApiJson, ProblemDetails},
    permissions as p,
    reports::{
        self, AppReport, AppReportList, CreateReportRequest, EvidenceEntry, MessageSnapshot, ModerationReport,
        ReportActionRecord, ReportActionRequest, ReportActionResult, ReportCreated, ReportForward, ReportList,
        ReportOrigin, UpdateReportRequest,
    },
    routes::rooms::RoomDetail,
    store::{self, reports::ListFilter},
    util, validate,
};

/// Reports carry up to 64 KiB of evidence.
const REPORT_BODY_LIMIT: usize = 128 * 1024;
/// 20 rules of up to 500 terms.
const RULES_BODY_LIMIT: usize = 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports", post(create_report).layer(DefaultBodyLimit::max(REPORT_BODY_LIMIT)))
        .route(
            "/reports/{report_id}",
            get(get_report).patch(update_report).delete(delete_report).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/reports/{report_id}/actions", post(act_on_report).layer(DefaultBodyLimit::max(16 * 1024)))
        .route("/reports/{report_id}/forward", post(forward_report).layer(DefaultBodyLimit::max(1024)))
        .route("/rooms/{room_id}/reports", get(room_reports))
        .route("/admin/reports", get(admin_reports))
        .route(
            "/rooms/{room_id}/automod",
            get(get_automod).put(put_automod).layer(DefaultBodyLimit::max(RULES_BODY_LIMIT)),
        )
        .route("/rooms/{room_id}/transfer", post(transfer_room).layer(DefaultBodyLimit::max(16 * 1024)))
        .route("/admin/rooms", get(admin_rooms))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        create_report,
        get_report,
        update_report,
        delete_report,
        act_on_report,
        forward_report,
        room_reports,
        admin_reports,
        get_automod,
        put_automod,
        transfer_room,
        admin_rooms
    ),
    components(schemas(
        CreateReportRequest,
        EvidenceEntry,
        MessageSnapshot,
        ReportCreated,
        ModerationReport,
        ReportActionRecord,
        ReportList,
        UpdateReportRequest,
        ReportActionRequest,
        ReportActionResult,
        ReportForward,
        ReportOrigin,
        AppReport,
        AppReportList,
        ReportView,
        ReportListView,
        AutomodRule,
        AutomodSettings,
        AutomodBurst,
        AutomodNode,
        PutAutomodRequest,
        TransferRoomRequest,
        AdminRoom,
        AdminRoomRole
    ))
)]
pub struct ModerationApi;

// ---------------------------------------------------------------- reports

/// One report: the full `ModerationReport` for people, the reduced `AppReport` for app tokens (MODERATION.md §1.4a).
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ReportView {
    Moderator(Box<ModerationReport>),
    App(Box<AppReport>),
}

/// A page of the inbox: `ReportList` for people, `AppReportList` for app tokens (MODERATION.md §1.4a).
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ReportListView {
    Moderator(ReportList),
    App(AppReportList),
}

/// Report a message, a user or a room.
///
/// Any authenticated user (also users of other nodes with a session here), never bots. Room content goes to the
/// room's moderators and the node admins, everything else to the node admins (MODERATION.md §1.1). For messages of
/// encrypted conversations the reporter may release their plaintext as `evidence`; plaintext messages are linked and
/// snapshotted by the node. A report of the same target by the same reporter while the first is open is merged
/// (`200`). At most `TAVRN_REPORTS_RATE_PER_HOUR` reports per hour.
#[utoipa::path(post, path = "/api/v1/reports", security(("bearer" = [])), request_body = CreateReportRequest,
    responses((status = 201, body = ReportCreated), (status = 200, description = "Merged into an open report", body = ReportCreated),
        (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create_report(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<CreateReportRequest>,
) -> Result<(StatusCode, Json<ReportCreated>), ApiError> {
    let (created, new) = reports::create(&state, &auth, req).await?;
    Ok((if new { StatusCode::CREATED } else { StatusCode::OK }, Json(created)))
}

/// One report with its evidence.
///
/// For node admins, and for the room's moderators (`moderate_members`) when the report is about the room's content
/// and not about themselves. Everybody else gets `404 report.not_found`. Moderation bots (scope `moderation`,
/// `moderate_members` in the room) get the room's reports as `AppReport`: metadata only, no detail, snapshot,
/// evidence, note or actions, the reporter as a pseudonym (MODERATION.md §1.4a).
#[utoipa::path(get, path = "/api/v1/reports/{report_id}", security(("bearer" = [])), params(("report_id" = String, Path)),
    responses((status = 200, description = "`ModerationReport`, or `AppReport` for app tokens", body = ReportView),
        (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
) -> Result<Json<ReportView>, ApiError> {
    let row = reports::visible(&state, &auth.user, &report_id).await?;
    if auth.user.is_bot() {
        return Ok(Json(ReportView::App(Box::new(reports::app_one(&state, &auth.user, row).await?))));
    }
    Ok(Json(ReportView::Moderator(Box::new(reports::one(&state, row, true).await?))))
}

/// Change a report's status, assignee or resolution note.
///
/// Whoever may see the report. `status`: `open`, `resolved` or `dismissed`; `assignee_id`: a moderator who may see
/// the report, or null. Sends `report.update`.
#[utoipa::path(patch, path = "/api/v1/reports/{report_id}", security(("bearer" = [])), params(("report_id" = String, Path)),
    request_body = UpdateReportRequest,
    responses((status = 200, body = ModerationReport), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn update_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
    ApiJson(req): ApiJson<UpdateReportRequest>,
) -> Result<Json<ModerationReport>, ApiError> {
    Ok(Json(reports::update(&state, &auth, &report_id, req).await?))
}

/// Delete a report and its evidence.
///
/// Node admins only, at any time (audited as `report.delete`).
#[utoipa::path(delete, path = "/api/v1/reports/{report_id}", security(("bearer" = [])), params(("report_id" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    reports::delete(&state, &auth, &report_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Act on a report: delete the message, time out, kick, ban or purge the reported user.
///
/// Runs the existing moderation route on the report's target with the caller's permissions (same checks and errors)
/// and records the report id in that route's audit entry (`meta.report_id`) and the action in the report.
/// `purge` is two-step: without `confirm_token` it answers with the count and a token. `resolve: true` also closes
/// the report (MODERATION.md §1.4).
#[utoipa::path(post, path = "/api/v1/reports/{report_id}/actions", security(("bearer" = [])), params(("report_id" = String, Path)),
    request_body = ReportActionRequest,
    responses((status = 200, body = ReportActionResult), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn act_on_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
    ApiJson(req): ApiJson<ReportActionRequest>,
) -> Result<Json<ReportActionResult>, ApiError> {
    Ok(Json(reports::act(&state, &auth, &report_id, req).await?))
}

/// Forward a report to the reported user's home node.
///
/// Node admins only, for reports by users about a user of another node whose home node announces `reports.v2`
/// (MODERATION.md §1.6). The node queues `report.forward` with the report's kind, category, text, snapshot or released
/// evidence and a pseudonym of the reporter (never the address). Idempotent: a forwarded report answers with its
/// `forwarded` unchanged. The reporter is told nothing. `400 report.forward_invalid` (automod entries, room reports,
/// forwarded reports), `409 report.target_local`, `409 report.forward_unsupported`.
#[utoipa::path(post, path = "/api/v1/reports/{report_id}/forward", security(("bearer" = [])), params(("report_id" = String, Path)),
    responses((status = 200, body = ModerationReport), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn forward_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
) -> Result<Json<ModerationReport>, ApiError> {
    Ok(Json(reports::forward::forward(&state, &auth, &report_id).await?))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ReportQuery {
    /// `open`, `resolved` or `dismissed` (default: all).
    pub status: Option<String>,
    /// Admin list only: `room` or `node`.
    pub scope: Option<String>,
    /// 1–100, default 50.
    pub limit: Option<i64>,
    /// A report id: older reports only (paging).
    pub before: Option<String>,
}

/// The room's reports, newest first.
///
/// `moderate_members` (owners and node admins too). Moderators never see reports about themselves; reports about
/// the owner go to the node admins only. List entries leave the evidence out (`evidence_count`). Moderation bots
/// (scope `moderation`, `moderate_members`) read the same list as `AppReportList`: metadata only, the reporter as a
/// pseudonym (MODERATION.md §1.4a).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/reports", security(("bearer" = [])), params(("room_id" = String, Path), ReportQuery),
    responses((status = 200, description = "`ReportList`, or `AppReportList` for app tokens", body = ReportListView),
        (status = 403, body = ProblemDetails)))]
pub async fn room_reports(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Query(q): Query<ReportQuery>,
) -> Result<Json<ReportListView>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if (access.member.is_none() && !access.is_node_admin) || !access.has(p::MODERATE_MEMBERS) {
        return Err(ApiError::Forbidden {
            code: "report.view_forbidden",
            detail: "Missing permission: Moderate members".into(),
        });
    }
    let filter = ListFilter {
        room_id: Some(access.room.id.clone()),
        scope: Some("room".into()),
        status: q.status,
        exclude_target: (!auth.user.is_node_admin() || auth.user.is_bot()).then(|| auth.user.id.clone()),
        before: q.before,
    };
    let limit = validate::limit(q.limit, 50, 100);
    if auth.user.is_bot() {
        return Ok(Json(ReportListView::App(reports::app_page(&state, &auth.user, filter, limit).await?)));
    }
    Ok(Json(ReportListView::Moderator(reports::page(&state, filter, limit).await?)))
}

/// Every report of the node, newest first (node admins).
#[utoipa::path(get, path = "/api/v1/admin/reports", security(("bearer" = [])), params(ReportQuery),
    responses((status = 200, body = ReportList), (status = 403, body = ProblemDetails)))]
pub async fn admin_reports(
    State(state): State<AppState>,
    NodeAdmin(_admin): NodeAdmin,
    Query(q): Query<ReportQuery>,
) -> Result<Json<ReportList>, ApiError> {
    let scope = q.scope.as_deref().map(|s| validate::one_of("scope", s, &["room", "node"])).transpose()?;
    let filter = ListFilter { room_id: None, scope, status: q.status, exclude_target: None, before: q.before };
    Ok(Json(reports::page(&state, filter, validate::limit(q.limit, 50, 100)).await?))
}

// ---------------------------------------------------------------- auto-moderation

/// The node's flood detection (read-only).
#[derive(Debug, Serialize, ToSchema)]
pub struct AutomodBurst {
    /// Messages per window above which a member is flooding (0 = off).
    pub limit: u32,
    pub window_secs: i64,
    pub timeout_minutes: u32,
}

/// The node lists that apply to every unencrypted conversation.
#[derive(Debug, Serialize, ToSchema)]
pub struct AutomodNode {
    /// `TAVRN_AUTOMOD_WORDS_FILE` is active.
    pub words: bool,
    /// `TAVRN_AUTOMOD_LINKS` is active.
    pub links: bool,
}

/// The auto-moderation settings of a room.
#[derive(Debug, Serialize, ToSchema)]
pub struct AutomodSettings {
    pub rules: Vec<AutomodRule>,
    pub burst: AutomodBurst,
    pub node: AutomodNode,
}

/// Body of `PUT /rooms/{room_id}/automod`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PutAutomodRequest {
    /// The complete list (at most 20 rules).
    pub rules: Vec<AutomodRule>,
}

fn settings(state: &AppState, rules: Vec<AutomodRule>) -> AutomodSettings {
    AutomodSettings {
        rules,
        burst: AutomodBurst {
            limit: state.config.automod_burst_limit,
            window_secs: crate::routes::messages::AUTOMOD_WINDOW_SECS,
            timeout_minutes: state.config.automod_timeout_minutes,
        },
        node: AutomodNode { words: state.node_automod.has_words(), links: state.node_automod.has_links() },
    }
}

/// The room's auto-moderation settings.
///
/// `manage_room` or `moderate_members`. Content rules apply to unencrypted channels only (MODERATION.md §2.2).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/automod", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = AutomodSettings), (status = 403, body = ProblemDetails)))]
pub async fn get_automod(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<AutomodSettings>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if !access.has(p::MANAGE_ROOM) && !access.has(p::MODERATE_MEMBERS) {
        return Err(ApiError::Forbidden {
            code: "automod.forbidden",
            detail: "Missing permission: Manage room or Moderate members".into(),
        });
    }
    let rules = automod::room_rules(&state, &access.room.id).await?;
    Ok(Json(settings(&state, rules)))
}

/// Replace the room's content rules.
///
/// `manage_room`. At most 20 rules; each needs terms or a link filter (`400 automod.rules_invalid` names the rule).
/// New rules get an id; ids sent back are kept. Audited as `automod.rules`.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/automod", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body = PutAutomodRequest,
    responses((status = 200, body = AutomodSettings), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn put_automod(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<PutAutomodRequest>,
) -> Result<Json<AutomodSettings>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROOM, "room.manage_forbidden", "Manage room")?;
    let roles = store::rooms::roles(&state.db, &access.room.id).await?;
    let channels = store::rooms::channels(&state.db, &access.room.id).await?;
    let rules = automod::validate_rules(req.rules, &roles, &channels)?;
    let encoded = serde_json::to_string(&rules).map_err(|e| ApiError::Internal(e.into()))?;
    store::automod::set_rules(&state.db, &access.room.id, &encoded, &util::now()).await?;
    automod::rules_changed(&state, &access.room.id);
    store::rooms::audit(
        &state.db,
        Some(&access.room.id),
        Some(&auth.user.id),
        "automod.rules",
        &access.room.id,
        "",
        json!({ "rules": rules.len() }),
    )
    .await?;
    Ok(Json(settings(&state, rules)))
}

// ---------------------------------------------------------------- ownership transfer

/// Body of `POST /rooms/{room_id}/transfer`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TransferRoomRequest {
    /// The member who becomes the owner.
    pub user_id: String,
}

/// Hand the room to another member.
///
/// The owner only, with a reauth token (`Tavrn-Reauth`, PROTOCOL.md §5c). The new owner must be a member, a local
/// user and not a bot (`400 room.transfer_invalid`); the former owner stays a member with their roles. Audited as
/// `room.transfer`, announced with `room.update` (MODERATION.md §4).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/transfer", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body = TransferRoomRequest,
    responses((status = 200, body = RoomDetail), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn transfer_room(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<TransferRoomRequest>,
) -> Result<Json<RoomDetail>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    if !access.is_owner || auth.user.is_bot() {
        return Err(ApiError::Forbidden {
            code: "room.owner_required",
            detail: "Only the owner can transfer the room".into(),
        });
    }
    let invalid = |detail: &str| ApiError::BadRequest { code: "room.transfer_invalid", detail: detail.into() };
    let target = match store::users::by_id(&state.db, &req.user_id).await? {
        Some(u) if store::rooms::member(&state.db, &room_id, &u.id).await?.is_some() => u,
        _ => return Err(invalid("The new owner must be a member of the room")),
    };
    if target.id == auth.user.id {
        return Err(invalid("You already own the room"));
    }
    if target.is_bot() || target.domain != state.config.domain || target.disabled_at.is_some() {
        return Err(invalid("The new owner must be an active person with an account on this node"));
    }
    crate::reauth::require(&state, &auth, &headers).await?;
    store::room_admin::set_owner(&state.db, &room_id, &target.id).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "room.transfer",
        &target.address(),
        "",
        json!({ "from": auth.user.address(), "to": target.address() }),
    )
    .await?;
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    state.hub.room(&room_id, "room.update", &access.room);
    tracing::info!(room = room_id, "room ownership transferred");
    Ok(Json(crate::routes::rooms::detail(&state, &access, &auth.user).await?))
}

// ---------------------------------------------------------------- node admin: rooms

#[derive(Debug, Deserialize, IntoParams)]
pub struct AdminRoomQuery {
    /// Part of the room name.
    pub q: Option<String>,
    /// 1–100, default 50.
    pub limit: Option<i64>,
    /// A room id: rooms after it (paging).
    pub after: Option<String>,
}

/// A role of a room in the admin's list.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminRoomRole {
    pub id: String,
    pub name: String,
    pub position: i64,
}

/// A room of this node with its roles (without `@everyone`).
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminRoom {
    pub id: String,
    pub name: String,
    /// The owner's address.
    pub owner: Option<String>,
    pub members: i64,
    pub roles: Vec<AdminRoomRole>,
}

/// The node's rooms with their roles (node admins).
///
/// For pickers such as the single sign-on group map, which names rooms and roles by id.
#[utoipa::path(get, path = "/api/v1/admin/rooms", security(("bearer" = [])), params(AdminRoomQuery),
    responses((status = 200, body = Vec<AdminRoom>), (status = 403, body = ProblemDetails)))]
pub async fn admin_rooms(
    State(state): State<AppState>,
    NodeAdmin(_admin): NodeAdmin,
    Query(q): Query<AdminRoomQuery>,
) -> Result<Json<Vec<AdminRoom>>, ApiError> {
    let search = validate::text("q", q.q.as_deref().unwrap_or(""), 0, 100)?;
    let rows =
        store::room_admin::list(&state.db, &search, q.after.as_deref(), validate::limit(q.limit, 50, 100)).await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let mut roles: Vec<AdminRoomRole> = store::rooms::roles(&state.db, &r.id)
            .await?
            .into_iter()
            .filter(|role| role.is_everyone == 0)
            .map(|role| AdminRoomRole { id: role.id, name: role.name, position: role.position })
            .collect();
        roles.sort_by_key(|r| std::cmp::Reverse(r.position));
        out.push(AdminRoom {
            owner: r.owner_username.zip(r.owner_domain).map(|(u, d)| format!("{u}@{d}")),
            id: r.id,
            name: r.name,
            members: r.members,
            roles,
        });
    }
    Ok(Json(out))
}
