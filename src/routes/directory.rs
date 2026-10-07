// SPDX-License-Identifier: AGPL-3.0-only
//! Peer directory routes (FEDERATION.md §7.3, §7.4): public lists of nodes and discoverable rooms, and
//! admin delisting.
//!
//! Everything is served from this node's own knowledge (own discoverable rooms plus what listed nodes
//! published); nothing here makes a request to another node. Blocked, delisted and non-listing nodes
//! never appear. Every room carries the listing JWT its hosting node signed, so clients can check that
//! the hosting node vouches for the name, description and member count.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};

use crate::{
    app::AppState,
    auth::{AuthUser, ClientIp, NodeAdmin},
    error::{ApiError, ProblemDetails},
    federation::{self, announce, discovery},
    store::{self, directory as dir},
    util,
    validate::{self, bad},
};

#[derive(Serialize, ToSchema)]
pub struct DirectorySoftware {
    pub name: String,
    pub version: String,
}

/// A listed node (§7.3).
#[derive(Serialize, ToSchema)]
pub struct DirectoryNode {
    pub domain: String,
    pub name: String,
    pub description: String,
    pub software: DirectorySoftware,
    pub capabilities: Vec<String>,
    /// open | invite | closed
    pub registration: String,
    /// Discoverable rooms of the node this node has cached.
    pub public_rooms: i64,
    /// Only when the node's operator publishes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<i64>,
    pub last_seen: String,
    /// Latest conformance result of this node's checks (§9.3): `pass`, `warn` or `unknown` (never
    /// checked). Nodes whose result is `fail` are not listed.
    pub conformance: String,
}

#[derive(Serialize, ToSchema)]
pub struct DirectoryNodeList {
    pub items: Vec<DirectoryNode>,
    /// Cursor of the next page, `null` on the last page.
    pub next: Option<String>,
}

/// A signing key of a node as this node sees it: `kid` and the SHA-256 of the 32 key bytes (base64url).
#[derive(Serialize, ToSchema)]
pub struct KeyFingerprint {
    pub kid: String,
    pub sha256: String,
}

#[derive(Serialize, ToSchema)]
pub struct DirectoryNodeDetail {
    #[serde(flatten)]
    pub node: DirectoryNode,
    pub keys: Vec<KeyFingerprint>,
}

/// A discoverable room (§7.3).
#[derive(Serialize, ToSchema)]
pub struct DirectoryRoom {
    /// Domain of the node that hosts the room.
    pub node: String,
    pub room_id: String,
    pub name: String,
    pub description: String,
    /// Always null: clients never load images of other nodes.
    pub icon_url: Option<String>,
    pub member_count: i64,
    /// JWT signed by the hosting node (`typ = listing`, `aud = tavrn-directory`, `sub` = room id, 48 hours).
    pub listing: String,
}

#[derive(Serialize, ToSchema)]
pub struct DirectoryRoomList {
    pub items: Vec<DirectoryRoom>,
    /// Cursor of the next page, `null` on the last page.
    pub next: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct NodeQuery {
    /// 1–100, default 100.
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    /// Search in domain, name and description (at most 100 characters).
    pub q: Option<String>,
}

#[derive(Deserialize, IntoParams)]
pub struct RoomQuery {
    /// 1–200, default 50.
    pub limit: Option<i64>,
    pub cursor: Option<String>,
    /// Search in name and description (at most 100 characters).
    pub q: Option<String>,
    /// Only rooms of this node.
    pub node: Option<String>,
    /// Only this node's own rooms.
    pub local: Option<bool>,
    /// Only rooms with at least this many members.
    pub min_members: Option<i64>,
}

fn cursor_invalid() -> ApiError {
    bad("directory.cursor_invalid", "Invalid cursor")
}

fn search(q: Option<&str>) -> Result<String, ApiError> {
    let q = q.unwrap_or("");
    if q.chars().count() > 100 {
        return Err(bad("validation.q", "Search text at most 100 characters"));
    }
    Ok(dir::like_pattern(q))
}

/// Remote entries pass only the configured domain policy (blocklist, allowlist, federation enabled).
fn passes_policy(state: &AppState, domain: &str) -> bool {
    domain == state.config.domain || state.federation.check_policy(domain).is_ok()
}

fn to_node(row: dir::NodeRow, conformance: Option<&String>) -> DirectoryNode {
    DirectoryNode {
        capabilities: serde_json::from_str(&row.capabilities).unwrap_or_default(),
        domain: row.domain,
        name: row.name,
        description: row.description,
        software: DirectorySoftware { name: row.software_name, version: row.software_version },
        registration: row.registration,
        public_rooms: row.public_rooms,
        users: row.users,
        last_seen: row.last_seen,
        conformance: conformance.cloned().unwrap_or_else(|| "unknown".into()),
    }
}

/// This node's own entry while `TAVRN_DIRECTORY_LISTING` is on (FEDERATION.md §13.1): built from the
/// values of its announce and discovery document, so a reference node lists itself without announcing
/// to itself (announces to the own domain stay refused). `conformance` is `unknown`: a node does not
/// check itself.
async fn own_node(state: &AppState) -> Result<Option<DirectoryNode>, ApiError> {
    if !state.config.directory_listing {
        return Ok(None);
    }
    let a = announce::own_announce(state).await?;
    Ok(Some(DirectoryNode {
        domain: a.domain,
        name: a.name,
        description: a.description,
        software: DirectorySoftware { name: a.software.name, version: a.software.version },
        capabilities: a.capabilities,
        registration: a.registration,
        public_rooms: a.public_rooms,
        users: a.users,
        last_seen: util::now(),
        conformance: "unknown".into(),
    }))
}

/// The search of `GET /directory/nodes` for an entry that is not in the database (the own node).
fn node_matches(node: &DirectoryNode, q: Option<&str>) -> bool {
    let q = q.unwrap_or("").trim().to_lowercase();
    q.is_empty()
        || node.domain.contains(&q)
        || node.name.to_lowercase().contains(&q)
        || node.description.to_lowercase().contains(&q)
}

/// Listed nodes (this node itself included while it allows listing), ordered by domain. Public, CORS-open.
#[utoipa::path(get, path = "/api/v1/directory/nodes", params(NodeQuery),
    responses((status = 200, body = DirectoryNodeList), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn nodes(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<NodeQuery>,
) -> Result<Json<DirectoryNodeList>, ApiError> {
    state.directory_limiter.check_all(&[format!("dir-ip:{ip}")])?;
    let limit = validate::limit(q.limit, 100, 100);
    let after = q.cursor.unwrap_or_default();
    if !after.is_empty() && !util::valid_domain(&after) {
        return Err(cursor_invalid());
    }
    let pattern = search(q.q.as_deref())?;
    let rows = dir::nodes_page(&state.db, &after, &pattern, limit).await?;
    let mut more = rows.len() as i64 == limit;
    let own = state.config.domain.clone();
    let rows: Vec<dir::NodeRow> = rows.into_iter().filter(|r| r.domain != own).collect();
    let results =
        store::conformance::results(&state.db, &rows.iter().map(|r| r.domain.clone()).collect::<Vec<_>>()).await?;
    let mut items: Vec<DirectoryNode> = rows
        .into_iter()
        .map(|r| {
            let c = results.get(&r.domain).cloned();
            to_node(r, c.as_ref())
        })
        .collect();
    if let Some(me) = own_node(&state).await?
        && me.domain > after
        && node_matches(&me, q.q.as_deref())
        // Behind the end of a full page it belongs to a later page.
        && (!more || items.last().is_some_and(|last| me.domain < last.domain))
    {
        let at = items.partition_point(|n| n.domain < me.domain);
        items.insert(at, me);
        if items.len() as i64 > limit {
            items.truncate(usize::try_from(limit).unwrap_or(0));
            more = true;
        }
    }
    let next = more.then(|| items.last().map(|n| n.domain.clone())).flatten();
    items.retain(|n| passes_policy(&state, &n.domain));
    Ok(Json(DirectoryNodeList { items, next }))
}

/// One listed node with the fingerprints of its keys as this node sees them (clients compare them with
/// their own fetch, §9.2). Public, CORS-open.
#[utoipa::path(get, path = "/api/v1/directory/nodes/{domain}", params(("domain" = String, Path)),
    responses((status = 200, body = DirectoryNodeDetail), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn node(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(domain): Path<String>,
) -> Result<Json<DirectoryNodeDetail>, ApiError> {
    state.directory_limiter.check_all(&[format!("dir-ip:{ip}")])?;
    let not_found = || ApiError::NotFound { code: "directory.node_not_found", what: "Node".into() };
    let domain = domain.to_lowercase();
    if !util::valid_domain(&domain) || !passes_policy(&state, &domain) {
        return Err(not_found());
    }
    if domain == state.config.domain {
        let node = own_node(&state).await?.ok_or_else(not_found)?;
        let keys = state
            .keys
            .iter()
            .map(|k| KeyFingerprint {
                kid: k.kid.clone(),
                sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(k.signing.verifying_key().as_bytes())),
            })
            .collect();
        return Ok(Json(DirectoryNodeDetail { node, keys }));
    }
    let row = dir::listed_node(&state.db, &domain).await?.ok_or_else(not_found)?;
    let keys = store::federation::peer(&state.db, &domain)
        .await?
        .and_then(|p| discovery::validate(&domain, p.document.as_bytes()).ok())
        .map(|doc| {
            doc.keys
                .iter()
                .map(|k| KeyFingerprint {
                    kid: k.kid.clone(),
                    sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(k.key.as_bytes())),
                })
                .collect()
        })
        .unwrap_or_default();
    let results = store::conformance::results(&state.db, std::slice::from_ref(&domain)).await?;
    Ok(Json(DirectoryNodeDetail { node: to_node(row, results.get(&domain)), keys }))
}

fn room_cursor(r: &dir::RoomEntryRow) -> String {
    format!("{}~{}~{}", r.member_count, r.node, r.room_id)
}

fn parse_room_cursor(s: &str) -> Result<dir::RoomCursor, ApiError> {
    let mut parts = s.splitn(3, '~');
    let (Some(count), Some(node), Some(room)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(cursor_invalid());
    };
    let member_count: i64 = count.parse().map_err(|_| cursor_invalid())?;
    if member_count < 0 || !util::valid_domain(node) || !util::is_ulid(room) {
        return Err(cursor_invalid());
    }
    Ok(dir::RoomCursor { member_count, node: node.into(), room_id: room.into() })
}

/// This node's discoverable rooms and the cached rooms of listed nodes, most members first. Public,
/// CORS-open; `local=true` returns only this node's own rooms (what other nodes fetch).
#[utoipa::path(get, path = "/api/v1/directory/rooms", params(RoomQuery),
    responses((status = 200, body = DirectoryRoomList), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn rooms(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(q): Query<RoomQuery>,
) -> Result<Json<DirectoryRoomList>, ApiError> {
    state.directory_limiter.check_all(&[format!("dir-ip:{ip}")])?;
    let limit = validate::limit(q.limit, 50, announce::MAX_ROOMS_PER_NODE as i64);
    let after = q.cursor.as_deref().filter(|c| !c.is_empty()).map(parse_room_cursor).transpose()?;
    let node = q.node.unwrap_or_default().to_lowercase();
    if !node.is_empty() && !util::valid_domain(&node) {
        return Err(bad("validation.node", "Not a valid domain"));
    }
    let min_members = validate::range("min_members", q.min_members.unwrap_or(0), 0, 10_000_000)?;
    let pattern = search(q.q.as_deref())?;
    let own = state.config.domain.clone();
    let now = util::now();
    let rows = dir::rooms_page(
        &state.db,
        dir::RoomQuery {
            own_domain: &own,
            local: q.local.unwrap_or(false),
            node: &node,
            pattern: &pattern,
            min_members,
            after: after.as_ref(),
            now: &now,
            limit,
        },
    )
    .await?;
    let next = (rows.len() as i64 == limit).then(|| rows.last().map(room_cursor)).flatten();
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        if !passes_policy(&state, &row.node) {
            continue;
        }
        let listing = if row.node == own && row.listing.is_empty() {
            announce::sign_listing(&state, &row.room_id, &row.name, &row.description, row.member_count)?
        } else {
            row.listing
        };
        items.push(DirectoryRoom {
            node: row.node,
            room_id: row.room_id,
            name: row.name,
            description: row.description,
            icon_url: None,
            member_count: row.member_count,
            listing,
        });
    }
    Ok(Json(DirectoryRoomList { items, next }))
}

// ---------------------------------------------------------------- admin

#[derive(Serialize, ToSchema)]
pub struct DelistedEntry {
    pub node: String,
    /// Null when the whole node is delisted.
    pub room_id: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RelistRequest {
    pub node: String,
    /// Omitted or null: the whole node.
    pub room_id: Option<String>,
}

fn node_domain(domain: &str) -> Result<String, ApiError> {
    let domain = domain.trim().to_lowercase();
    if !util::valid_domain(&domain) {
        return Err(bad("federation.domain_invalid", "Not a valid node domain"));
    }
    Ok(domain)
}

/// Delisted nodes and rooms (node admins).
#[utoipa::path(get, path = "/api/v1/admin/directory/delisted", security(("bearer" = [])),
    responses((status = 200, body = Vec<DelistedEntry>), (status = 403, body = ProblemDetails)))]
pub async fn delisted(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<Vec<DelistedEntry>>, ApiError> {
    Ok(Json(
        dir::delisted(&state.db)
            .await?
            .into_iter()
            .map(|r| DelistedEntry {
                node: r.node,
                room_id: (!r.room_id.is_empty()).then_some(r.room_id),
                created_by: r.created_by,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

/// Delists a node (§7.4): it is neither shown nor passed on, also after new announces. Audited.
#[utoipa::path(delete, path = "/api/v1/admin/directory/nodes/{domain}", security(("bearer" = [])), params(("domain" = String, Path)),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn delist_node(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(domain): Path<String>,
) -> Result<StatusCode, ApiError> {
    let domain = node_domain(&domain)?;
    if domain == state.config.domain {
        return Err(bad("directory.delist_self", "This node delists itself through TAVRN_DIRECTORY_LISTING"));
    }
    delist(&state, &admin.user.id, &domain, "").await
}

/// Delists one room (also one of this node's own rooms). Audited.
#[utoipa::path(delete, path = "/api/v1/admin/directory/rooms/{node}/{room_id}", security(("bearer" = [])),
    params(("node" = String, Path), ("room_id" = String, Path)),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn delist_room(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path((node, room_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let node = node_domain(&node)?;
    let room_id = validate::ulid("room_id", &room_id)?;
    delist(&state, &admin.user.id, &node, &room_id).await
}

async fn delist(state: &AppState, admin_id: &str, node: &str, room_id: &str) -> Result<StatusCode, ApiError> {
    if !dir::delist(&state.db, node, room_id, admin_id, &util::now()).await? {
        return Err(ApiError::Conflict {
            code: "directory.already_delisted",
            detail: "Already removed from the directory".into(),
            meta: serde_json::json!({}),
        });
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(admin_id),
        "admin.directory_delist",
        node,
        "",
        serde_json::json!({ "room_id": (!room_id.is_empty()).then_some(room_id) }),
    )
    .await?;
    tracing::info!(node, room_id, "directory entry delisted");
    Ok(StatusCode::NO_CONTENT)
}

/// Undoes a delisting. The node reappears with its next announce or refresh. Audited.
#[utoipa::path(post, path = "/api/v1/admin/directory/relist", security(("bearer" = [])), request_body = RelistRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn relist(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Json(req): Json<RelistRequest>,
) -> Result<StatusCode, ApiError> {
    let node = node_domain(&req.node)?;
    let room_id = req.room_id.as_deref().map(|r| validate::ulid("room_id", r)).transpose()?.unwrap_or_default();
    if !dir::relist(&state.db, &node, &room_id).await? {
        return Err(ApiError::NotFound { code: "directory.not_delisted", what: "Entry".into() });
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.directory_relist",
        &node,
        "",
        serde_json::json!({ "room_id": (!room_id.is_empty()).then_some(room_id.as_str()) }),
    )
    .await?;
    if room_id.is_empty() && node != state.config.domain && federation::valid_node_domain(&node) {
        // Bring the node back at once if it still wants to be listed.
        let background = state.clone();
        tokio::spawn(async move {
            if let Ok(true) = announce::add_relayed(&background, &node).await
                && let Ok(n) = announce::refresh_rooms(&background, &node).await
            {
                tracing::info!(node, rooms = n, "relisted node refreshed");
            }
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- reports (§9.2)

/// Reports a user may send per 24 hours.
pub const REPORTS_PER_DAY: i64 = 10;
/// Distinct reporters of one domain within [`REPORT_WINDOW_DAYS`] that leave an admin notice.
pub const REPORT_NOTICE_REPORTERS: i64 = 3;
pub const REPORT_WINDOW_DAYS: i64 = 7;
/// Reports are kept this long.
pub const REPORT_RETENTION_DAYS: i64 = 180;
pub const REPORT_DETAIL_MAX: usize = 1000;

/// What a report is about besides a node or room (APPLICATIONS.md §4.4).
#[derive(Deserialize, ToSchema)]
pub struct ReportSubject {
    /// `application`
    pub kind: String,
    /// Application reference `<domain>/<id>`.
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ReportRequest {
    /// Domain of the reported node (required unless `subject` is given).
    #[serde(default)]
    pub domain: Option<String>,
    /// An application (of any node, also this one); the domain is taken from its reference.
    #[serde(default)]
    pub subject: Option<ReportSubject>,
    /// One room of that node; omitted or null for the node as a whole.
    #[serde(default)]
    pub room_id: Option<String>,
    /// What is reported: a check of FEDERATION.md §9 the client observed failing (e.g. `keys.consistent`,
    /// `mls.reject`) or a reason (`spam`, `abuse`, `illegal`, `security`, `other`). 1–64 characters of
    /// `a-z`, `0-9`, `.`, `_`, `-`.
    pub check: String,
    /// Free text for the admins (at most 1000 characters).
    #[serde(default)]
    pub detail: String,
}

/// A report as admins see it.
#[derive(Serialize, ToSchema)]
pub struct DirectoryReport {
    pub id: String,
    pub domain: String,
    /// Null when the node as a whole was reported.
    pub room_id: Option<String>,
    pub check: String,
    pub detail: String,
    /// Address of the reporting user.
    pub reporter: String,
    pub created_at: String,
    /// Reference of the reported application, null for node and room reports.
    pub application: Option<String>,
}

/// Reports about one node (admin overview).
#[derive(Serialize, ToSchema)]
pub struct ReportSummary {
    pub domain: String,
    /// All stored reports (kept 180 days).
    pub reports: i64,
    /// Distinct reporting users.
    pub reporters: i64,
    /// Reports of the last 7 days.
    pub recent: i64,
    pub last_at: String,
    /// Whether the node is delisted on this node.
    pub delisted: bool,
}

fn valid_check(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

fn to_report(r: dir::ReportRow) -> DirectoryReport {
    DirectoryReport {
        id: r.id,
        domain: r.domain,
        room_id: (!r.room_id.is_empty()).then_some(r.room_id),
        check: r.kind,
        detail: r.detail,
        reporter: r.reporter,
        created_at: r.created_at,
        application: r.application_ref,
    }
}

/// Reports another node or one of its rooms to this node's admins (FEDERATION.md §9.2): local users
/// only, 10 per user and 24 hours. Reports never block anything on their own; they show up in the
/// admin's Federation tab, and the third distinct reporter of a domain within 7 days leaves an admin
/// notice in the audit log (`directory.reports_notice`).
#[utoipa::path(post, path = "/api/v1/directory/reports", security(("bearer" = [])), request_body = ReportRequest,
    responses((status = 201, body = DirectoryReport), (status = 400, body = ProblemDetails), (status = 401, body = ProblemDetails),
        (status = 403, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn report(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ReportRequest>,
) -> Result<(StatusCode, Json<DirectoryReport>), ApiError> {
    let (domain, application_ref) = match &req.subject {
        Some(subject) => {
            if subject.kind != "application" {
                return Err(bad("validation.subject", "subject.kind: application"));
            }
            let (domain, id) = crate::installations::parse_ref(&subject.reference)
                .map_err(|_| bad("validation.subject", "subject.ref: <domain>/<application id>"))?;
            let reference = format!("{domain}/{id}");
            (domain, Some(reference))
        }
        None => {
            let domain = node_domain(req.domain.as_deref().unwrap_or(""))?;
            if domain == state.config.domain {
                return Err(bad("directory.report_self", "This node cannot report itself"));
            }
            (domain, None)
        }
    };
    let room_id = match &application_ref {
        Some(_) => String::new(),
        None => req.room_id.as_deref().map(|r| validate::ulid("room_id", r)).transpose()?.unwrap_or_default(),
    };
    let check = req.check.trim().to_string();
    if !valid_check(&check) {
        return Err(bad("validation.check", "check: 1–64 characters of a-z, 0-9, . _ -"));
    }
    let detail = validate::text("detail", &req.detail, 0, REPORT_DETAIL_MAX)?;
    let now = chrono::Utc::now();
    let day_ago = util::format_time(now - chrono::Duration::hours(24));
    if dir::reports_by_since(&state.db, &auth.user.id, &day_ago).await? >= REPORTS_PER_DAY {
        return Err(ApiError::RateLimited { retry_after_secs: 3600 });
    }
    let window = util::format_time(now - chrono::Duration::days(REPORT_WINDOW_DAYS));
    let before = dir::reporters_since(&state.db, &domain, &window).await?;
    let id = util::ulid();
    let created_at = util::format_time(now);
    dir::add_report(
        &state.db,
        dir::NewReport {
            id: &id,
            reporter_id: &auth.user.id,
            domain: &domain,
            room_id: &room_id,
            kind: &check,
            detail: &detail,
            created_at: &created_at,
            application_ref: application_ref.as_deref(),
        },
    )
    .await?;
    let after = dir::reporters_since(&state.db, &domain, &window).await?;
    if before < REPORT_NOTICE_REPORTERS && after >= REPORT_NOTICE_REPORTERS {
        store::rooms::audit(
            &state.db,
            None,
            None,
            "directory.reports_notice",
            &domain,
            "",
            serde_json::json!({ "reporters": after, "days": REPORT_WINDOW_DAYS }),
        )
        .await?;
        tracing::warn!(domain, reporters = after, "node reported by several users");
    }
    tracing::info!(domain, check, "directory report stored");
    Ok((
        StatusCode::CREATED,
        Json(DirectoryReport {
            id,
            domain,
            room_id: (!room_id.is_empty()).then_some(room_id),
            check,
            detail,
            reporter: auth.user.address(),
            created_at,
            application: application_ref,
        }),
    ))
}

/// Reported nodes with their report counts, most recently reported first (node admins).
#[utoipa::path(get, path = "/api/v1/admin/directory/reports", security(("bearer" = [])),
    responses((status = 200, body = Vec<ReportSummary>), (status = 403, body = ProblemDetails)))]
pub async fn report_summary(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<ReportSummary>>, ApiError> {
    let recent = util::format_time(chrono::Utc::now() - chrono::Duration::days(REPORT_WINDOW_DAYS));
    Ok(Json(
        dir::report_summary(&state.db, &recent, 200)
            .await?
            .into_iter()
            .map(|r| ReportSummary {
                domain: r.domain,
                reports: r.reports,
                reporters: r.reporters,
                recent: r.recent,
                last_at: r.last_at,
                delisted: r.delisted != 0,
            })
            .collect(),
    ))
}

/// The reports about one node, newest first (at most 200, node admins).
#[utoipa::path(get, path = "/api/v1/admin/directory/reports/{domain}", security(("bearer" = [])), params(("domain" = String, Path)),
    responses((status = 200, body = Vec<DirectoryReport>), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn reports_of(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Path(domain): Path<String>,
) -> Result<Json<Vec<DirectoryReport>>, ApiError> {
    let domain = node_domain(&domain)?;
    Ok(Json(dir::reports_of(&state.db, &domain, 200).await?.into_iter().map(to_report).collect()))
}

/// Dismisses (deletes) the reports about one node. Audited.
#[utoipa::path(delete, path = "/api/v1/admin/directory/reports/{domain}", security(("bearer" = [])), params(("domain" = String, Path)),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn dismiss_reports(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(domain): Path<String>,
) -> Result<StatusCode, ApiError> {
    let domain = node_domain(&domain)?;
    let n = dir::dismiss_reports(&state.db, &domain).await?;
    if n == 0 {
        return Err(ApiError::NotFound { code: "directory.reports_not_found", what: "Reports".into() });
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.directory_reports_dismiss",
        &domain,
        "",
        serde_json::json!({ "reports": n }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn report_checks_are_short_identifiers() {
        for ok in ["spam", "keys.consistent", "mls.reject", "a_b-c.9"] {
            assert!(valid_check(ok), "{ok}");
        }
        for bad in ["", "Spam", "spam ", "<b>", "a/b", &"x".repeat(65), "ä"] {
            assert!(!valid_check(bad), "{bad}");
        }
    }

    #[test]
    fn room_cursors_roundtrip_and_are_checked() {
        let row = dir::RoomEntryRow {
            node: "a.example".into(),
            room_id: util::ulid(),
            name: "x".into(),
            description: String::new(),
            member_count: 7,
            listing: String::new(),
        };
        let c = parse_room_cursor(&room_cursor(&row)).unwrap();
        assert_eq!((c.member_count, c.node.as_str(), c.room_id.as_str()), (7, "a.example", row.room_id.as_str()));
        for bad in ["", "x", "1~a.example", "-1~a.example~01J", "1~A B~01J", "1~a.example~nope", "x~a.example~01J"] {
            assert_eq!(parse_room_cursor(bad).unwrap_err().code(), "directory.cursor_invalid", "{bad}");
        }
    }
}
