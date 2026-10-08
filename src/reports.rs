// SPDX-License-Identifier: AGPL-3.0-only
//! Reports with evidence and the moderation inbox (protocol MODERATION.md §1).
//!
//! A report names a message, a user or a room. Plaintext messages are linked and snapshotted by the node; for
//! encrypted ones the reporter may release the plaintext as evidence, which the node stores as received and marks
//! `evidence_source: reporter`. Reports of room content go to the room's moderators (`moderate_members`) and the
//! node admins, everything else (DMs, users without context, rooms, the room owner) to the node admins only.
//! Reporters are visible to moderators; the reported user never learns about a report. Action shortcuts run the
//! existing moderation routes with the caller's own permissions inside [`ACTING_ON`], so the audit entries those
//! routes write carry the report id.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    access::{self, ConvKind},
    app::AppState,
    auth::{AuthUser, NodeAdmin},
    error::ApiError,
    models::{User, UserRow},
    permissions as p, store,
    store::reports::{ListFilter, NewReport, ReportRow},
    util,
    validate::{self, bad},
};

pub const CATEGORIES: &[&str] = &["spam", "harassment", "illegal", "sexual", "violence", "other"];
pub const STATUSES: &[&str] = &["open", "resolved", "dismissed"];
pub const ACTIONS: &[&str] = &["delete_message", "timeout", "kick", "ban", "purge"];
pub const DETAIL_MAX: usize = 2000;
pub const NOTE_MAX: usize = 2000;
pub const EVIDENCE_MAX_ENTRIES: usize = 11;
pub const EVIDENCE_MAX_TEXT: usize = 4000;
pub const EVIDENCE_MAX_ATTACHMENTS: usize = 10;
pub const EVIDENCE_MAX_NAME: usize = 255;
pub const EVIDENCE_MAX_BYTES: usize = 64 * 1024;

tokio::task_local! {
    /// The report an action shortcut acts on: `store::rooms::audit` adds it to the audit entries as `report_id`.
    pub static ACTING_ON: String;
}

/// The report id of the action shortcut running in this task, if any.
pub fn acting_on() -> Option<String> {
    ACTING_ON.try_with(Clone::clone).ok()
}

// ---------------------------------------------------------------- API types

/// One message the reporter releases in plaintext (MODERATION.md §1.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct EvidenceEntry {
    pub message_id: Option<String>,
    /// The author's address.
    pub author: String,
    /// The sending device as the envelope names it.
    #[serde(default)]
    pub device_id: Option<String>,
    /// RFC 3339.
    pub created_at: String,
    /// The decrypted body (at most 4000 characters).
    #[serde(default)]
    pub text: String,
    /// File names of the attachments (at most 10), never the files.
    #[serde(default)]
    pub attachments: Vec<String>,
}

/// The content of a plaintext message at report time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct MessageSnapshot {
    pub author: String,
    pub created_at: String,
    pub text: String,
    pub attachments: Vec<String>,
}

/// Body of `POST /reports`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateReportRequest {
    /// `message`, `user` or `room`.
    pub kind: String,
    pub conversation_id: Option<String>,
    pub message_id: Option<String>,
    /// `message`: the node hosting the conversation when it is not this node (DMs on another node).
    pub node: Option<String>,
    /// `user`: the reported address; `message` on another node: the author.
    pub user: Option<String>,
    /// `room`: the reported room; `user`: optional context.
    pub room_id: Option<String>,
    /// `spam`, `harassment`, `illegal`, `sexual`, `violence` or `other`.
    pub category: String,
    /// At most 2000 characters.
    #[serde(default)]
    pub detail: String,
    /// Messages of encrypted conversations only: the plaintext the reporter releases (at most 11 entries).
    pub evidence: Option<Vec<EvidenceEntry>>,
}

/// Answer of `POST /reports` (`201` for a new report, `200` when merged into an open one).
#[derive(Debug, Serialize, ToSchema)]
pub struct ReportCreated {
    pub id: String,
    pub status: String,
    pub merged: bool,
}

/// An action shortcut taken on a report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ReportActionRecord {
    pub action: String,
    /// The moderator's address.
    pub actor: String,
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minutes: Option<i64>,
}

/// A report as moderators and node admins see it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ModerationReport {
    pub id: String,
    /// `user` or `automod`.
    pub source: String,
    /// `room` (the room's moderators and node admins) or `node` (node admins).
    pub scope: String,
    /// `message`, `user` or `room`.
    pub kind: String,
    pub room_id: Option<String>,
    pub room_name: Option<String>,
    pub conversation_id: Option<String>,
    /// `channel`, `dm` or `group` (null when unknown here).
    pub conversation_kind: Option<String>,
    /// The node hosting the conversation when it is not this node.
    pub node: Option<String>,
    pub message_id: Option<String>,
    /// The reported message still exists on this node.
    pub message_exists: bool,
    /// The reported user (null for an address this node does not know).
    pub target: Option<User>,
    pub target_address: String,
    /// Null for automod entries.
    pub reporter: Option<User>,
    pub category: String,
    pub detail: String,
    pub snapshot: Option<MessageSnapshot>,
    /// Only in `GET /reports/{id}` and action results.
    pub evidence: Option<Vec<EvidenceEntry>>,
    pub evidence_count: usize,
    /// `reporter` when evidence was released by the reporter.
    pub evidence_source: Option<String>,
    /// `open`, `resolved` or `dismissed`.
    pub status: String,
    pub assignee: Option<User>,
    pub note: String,
    pub actions: Vec<ReportActionRecord>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
}

/// A page of the inbox.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReportList {
    pub reports: Vec<ModerationReport>,
    /// Open reports of the list's scope (badges), whatever the filters.
    pub open: i64,
}

/// Body of `PATCH /reports/{id}`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateReportRequest {
    /// `open`, `resolved` or `dismissed`.
    pub status: Option<String>,
    /// A moderator who may see the report, or null.
    #[serde(default, with = "crate::serde_with_double_option")]
    #[schema(value_type = Option<String>)]
    pub assignee_id: Option<Option<String>>,
    /// The resolution note (at most 2000 characters).
    pub note: Option<String>,
}

/// Body of `POST /reports/{id}/actions`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReportActionRequest {
    /// `delete_message`, `timeout`, `kick`, `ban` or `purge`.
    pub action: String,
    /// `timeout`: 1–40320.
    pub minutes: Option<i64>,
    /// Passed to the route (kick, ban, timeout).
    #[serde(default)]
    pub reason: String,
    /// `purge`: the token of the preview.
    pub confirm_token: Option<String>,
    /// Also set the report `resolved`.
    #[serde(default)]
    pub resolve: bool,
}

/// Answer of an action shortcut.
#[derive(Serialize, ToSchema)]
pub struct ReportActionResult {
    pub report: ModerationReport,
    /// The preview or result of a purge.
    pub purge: Option<crate::routes::rooms::PurgeResponse>,
}

// ---------------------------------------------------------------- creating

fn target_invalid(detail: impl Into<String>) -> ApiError {
    bad("report.target_invalid", detail)
}

fn evidence_invalid(detail: impl Into<String>) -> ApiError {
    bad("report.evidence_invalid", detail)
}

/// Checks reporter-provided evidence (MODERATION.md §1.2); `reported` must be one of the entries.
pub fn validate_evidence(entries: &[EvidenceEntry], reported: &str) -> Result<String, ApiError> {
    if entries.is_empty() || entries.len() > EVIDENCE_MAX_ENTRIES {
        return Err(evidence_invalid(format!("1 to {EVIDENCE_MAX_ENTRIES} messages")));
    }
    for e in entries {
        if util::parse_address(&e.author.to_lowercase()).is_none() {
            return Err(evidence_invalid("author: an address"));
        }
        if e.message_id.as_deref().is_some_and(|id| !util::is_ulid(id))
            || e.device_id.as_deref().is_some_and(|d| d.is_empty() || d.len() > 64)
            || util::parse_time(&e.created_at).is_none()
        {
            return Err(evidence_invalid("message_id, device_id or created_at malformed"));
        }
        if e.text.chars().count() > EVIDENCE_MAX_TEXT {
            return Err(evidence_invalid(format!("text: at most {EVIDENCE_MAX_TEXT} characters")));
        }
        if e.attachments.len() > EVIDENCE_MAX_ATTACHMENTS
            || e.attachments.iter().any(|a| a.is_empty() || a.chars().count() > EVIDENCE_MAX_NAME)
        {
            return Err(evidence_invalid(format!(
                "attachments: at most {EVIDENCE_MAX_ATTACHMENTS} names of 1 to {EVIDENCE_MAX_NAME} characters"
            )));
        }
    }
    if !entries.iter().any(|e| e.message_id.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(reported))) {
        return Err(evidence_invalid("the reported message must be part of the evidence"));
    }
    let json = serde_json::to_string(entries).map_err(|e| ApiError::Internal(e.into()))?;
    if json.len() > EVIDENCE_MAX_BYTES {
        return Err(evidence_invalid(format!("at most {} KiB", EVIDENCE_MAX_BYTES / 1024)));
    }
    Ok(json)
}

/// What a report is about, resolved and checked.
struct Target {
    scope: &'static str,
    kind: &'static str,
    room_id: Option<String>,
    conversation_id: Option<String>,
    node: Option<String>,
    message_id: Option<String>,
    target_user_id: Option<String>,
    target_address: String,
    snapshot: Option<String>,
    /// Evidence is allowed (encrypted messages) for this message id.
    evidence_for: Option<String>,
}

fn ulid_field(value: Option<&str>, what: &str) -> Result<String, ApiError> {
    value
        .filter(|v| util::is_ulid(v))
        .map(|v| v.to_ascii_uppercase())
        .ok_or_else(|| target_invalid(format!("{what}: a valid id is required")))
}

fn address_field(value: Option<&str>) -> Result<String, ApiError> {
    let a = value.map(|v| v.trim().to_lowercase()).unwrap_or_default();
    if util::parse_address(&a).is_none() {
        return Err(target_invalid("user: an address user@domain is required"));
    }
    Ok(a)
}

async fn user_by_address(state: &AppState, address: &str) -> Result<Option<UserRow>, ApiError> {
    match util::parse_address(address) {
        Some((name, domain)) => store::users::by_username(&state.db, name, domain).await,
        None => Ok(None),
    }
}

/// Plaintext text and attachment names of a message for the snapshot.
async fn snapshot(state: &AppState, m: &crate::models::MessageRow, author: &UserRow) -> Result<String, ApiError> {
    let content: Value = serde_json::from_str(&m.content).unwrap_or(Value::Null);
    let text = content.get("body").and_then(Value::as_str).unwrap_or("").to_string();
    let attachments = store::blobs::by_message(&state.db, &m.id).await?.into_iter().map(|b| b.name).collect();
    serde_json::to_string(&MessageSnapshot {
        author: author.address(),
        created_at: m.created_at.clone(),
        text,
        attachments,
    })
    .map_err(|e| ApiError::Internal(e.into()))
}

async fn resolve_target(state: &AppState, auth: &AuthUser, req: &CreateReportRequest) -> Result<Target, ApiError> {
    let me = &auth.user;
    match req.kind.as_str() {
        "message" => {
            let conversation_id = ulid_field(req.conversation_id.as_deref(), "conversation_id")?;
            let message_id = ulid_field(req.message_id.as_deref(), "message_id")?;
            let node = req.node.as_deref().map(|n| n.trim().to_lowercase()).filter(|n| *n != state.config.domain);
            if let Some(node) = node {
                // A DM or group DM on another node: only the reporter's home node takes it (§1.1).
                if auth.is_remote() || !util::valid_domain(&node) {
                    return Err(target_invalid("node: conversations of other nodes are reported to your home node"));
                }
                let address = address_field(req.user.as_deref())?;
                if address == me.address() {
                    return Err(bad("report.self", "You cannot report yourself"));
                }
                let target = user_by_address(state, &address).await?;
                return Ok(Target {
                    scope: "node",
                    kind: "message",
                    room_id: None,
                    conversation_id: Some(conversation_id),
                    node: Some(node),
                    message_id: Some(message_id.clone()),
                    target_user_id: target.map(|u| u.id),
                    target_address: address,
                    snapshot: None,
                    evidence_for: Some(message_id),
                });
            }
            let conv = access::conversation(state, &conversation_id, me).await?;
            conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
            let message = store::messages::by_id(&state.db, &message_id)
                .await?
                .filter(|m| m.conversation_id == conv.id)
                .ok_or_else(|| access::not_found("Message", "message.not_found"))?;
            if message.device_id.is_none() && message.content.starts_with("{\"type\":\"system.") {
                return Err(target_invalid("System messages cannot be reported"));
            }
            let author = store::users::by_id(&state.db, &message.author_id)
                .await?
                .ok_or_else(|| access::not_found("Message", "message.not_found"))?;
            if author.id == me.id {
                return Err(bad("report.self", "You cannot report yourself"));
            }
            let (scope, room_id) = match &conv.kind {
                ConvKind::Channel { access, .. } => {
                    (if author.id == access.room.owner_id { "node" } else { "room" }, Some(access.room.id.clone()))
                }
                ConvKind::Direct { .. } => ("node", None),
            };
            let encrypted = message.encrypted != 0;
            let snapshot = if encrypted { None } else { Some(snapshot(state, &message, &author).await?) };
            Ok(Target {
                scope,
                kind: "message",
                room_id,
                conversation_id: Some(conv.id.clone()),
                node: None,
                message_id: Some(message.id.clone()),
                target_user_id: Some(author.id.clone()),
                target_address: author.address(),
                snapshot,
                evidence_for: encrypted.then(|| message.id.clone()),
            })
        }
        "user" => {
            let address = address_field(req.user.as_deref())?;
            if address == me.address() {
                return Err(bad("report.self", "You cannot report yourself"));
            }
            let target =
                user_by_address(state, &address).await?.ok_or_else(|| access::not_found("User", "user.not_found"))?;
            let (scope, room_id, conversation_id) = match (req.room_id.as_deref(), req.conversation_id.as_deref()) {
                (Some(_), Some(_)) => return Err(target_invalid("room_id or conversation_id, not both")),
                (Some(room), None) => {
                    let room = ulid_field(Some(room), "room_id")?;
                    let access = access::room_access(state, &room, me).await?;
                    (if target.id == access.room.owner_id { "node" } else { "room" }, Some(room), None)
                }
                (None, Some(conversation)) => {
                    let conversation = ulid_field(Some(conversation), "conversation_id")?;
                    let conv = access::direct(state, &conversation, &me.id).await?;
                    ("node", None, Some(conv.id))
                }
                (None, None) => ("node", None, None),
            };
            Ok(Target {
                scope,
                kind: "user",
                room_id,
                conversation_id,
                node: None,
                message_id: None,
                target_user_id: Some(target.id.clone()),
                target_address: address,
                snapshot: None,
                evidence_for: None,
            })
        }
        "room" => {
            let room_id = ulid_field(req.room_id.as_deref(), "room_id")?;
            let room = store::rooms::room_by_id(&state.db, &room_id)
                .await?
                .ok_or_else(|| access::not_found("Room", "room.not_found"))?;
            let member = store::rooms::member(&state.db, &room_id, &me.id).await?.is_some();
            if !member && !me.is_node_admin() && room.join_mode != "public" {
                return Err(access::not_found("Room", "room.not_found"));
            }
            Ok(Target {
                scope: "node",
                kind: "room",
                room_id: Some(room_id),
                conversation_id: None,
                node: None,
                message_id: None,
                target_user_id: None,
                target_address: String::new(),
                snapshot: None,
                evidence_for: None,
            })
        }
        _ => Err(target_invalid("kind: message, user or room")),
    }
}

/// `POST /reports` (MODERATION.md §1.1–§1.3). Returns the answer and whether a new report was created.
pub async fn create(
    state: &AppState,
    auth: &AuthUser,
    req: CreateReportRequest,
) -> Result<(ReportCreated, bool), ApiError> {
    if auth.user.is_bot() {
        return Err(ApiError::Forbidden { code: "report.bot_forbidden", detail: "Bots cannot report".into() });
    }
    if !CATEGORIES.contains(&req.category.as_str()) {
        return Err(bad("report.category_invalid", format!("category: one of {}", CATEGORIES.join(", "))));
    }
    let detail = validate::text("detail", &req.detail, 0, DETAIL_MAX)?;
    let target = resolve_target(state, auth, &req).await?;
    let evidence = match (&req.evidence, &target.evidence_for) {
        (None, _) => None,
        (Some(entries), Some(message_id)) => Some(validate_evidence(entries, message_id)?),
        (Some(_), None) => {
            return Err(bad(
                "report.evidence_not_allowed",
                "Evidence is only released for messages of encrypted conversations; the node links plaintext itself",
            ));
        }
    };
    let now = chrono::Utc::now();
    let hour_ago = util::format_time(now - chrono::Duration::hours(1));
    let (sent, oldest) = store::reports::sent_since(&state.db, &auth.user.id, &hour_ago).await?;
    if sent >= i64::from(state.config.reports_rate_per_hour) {
        let wait = oldest
            .and_then(|o| util::parse_time(&o))
            .map(|o| (o + chrono::Duration::hours(1) - now).num_seconds())
            .unwrap_or(3600)
            .clamp(1, 3600);
        return Err(ApiError::RateLimited { retry_after_secs: wait as u32 });
    }
    let id = util::ulid();
    let created_at = util::format_time(now);
    let new = NewReport {
        id: &id,
        source: "user",
        scope: target.scope,
        kind: target.kind,
        reporter_id: Some(&auth.user.id),
        room_id: target.room_id.as_deref(),
        conversation_id: target.conversation_id.as_deref(),
        node: target.node.as_deref(),
        message_id: target.message_id.as_deref(),
        target_user_id: target.target_user_id.as_deref(),
        target_address: &target.target_address,
        category: &req.category,
        detail: &detail,
        snapshot: target.snapshot.as_deref(),
        evidence: evidence.as_deref(),
        created_at: &created_at,
    };
    if let Some(open) = store::reports::open_duplicate(&state.db, &new).await? {
        store::reports::merge(&state.db, &open.id, &req.category, &detail, evidence.as_deref(), &created_at).await?;
        return Ok((ReportCreated { id: open.id, status: open.status, merged: true }, false));
    }
    store::reports::insert(&state.db, &new).await?;
    if let Some(row) = store::reports::by_id(&state.db, &id).await? {
        announce(state, &row).await;
    }
    tracing::info!(report = id, scope = target.scope, kind = target.kind, "report received");
    Ok((ReportCreated { id, status: "open".into(), merged: false }, true))
}

/// Opens or updates the automod entry of `author` (MODERATION.md §2.4).
pub async fn automod_entry(
    state: &AppState,
    scope: &str,
    room_id: Option<&str>,
    conversation_id: &str,
    author: &UserRow,
    detail: &str,
) -> Result<(), ApiError> {
    let now = util::now();
    if let Some(open) = store::reports::open_automod(&state.db, scope, room_id, &author.id).await? {
        return store::reports::set_detail(&state.db, &open.id, detail, &now).await;
    }
    let id = util::ulid();
    let address = author.address();
    store::reports::insert(
        &state.db,
        &NewReport {
            id: &id,
            source: "automod",
            scope,
            kind: "user",
            reporter_id: None,
            room_id,
            conversation_id: Some(conversation_id),
            node: None,
            message_id: None,
            target_user_id: Some(&author.id),
            target_address: &address,
            category: "other",
            detail,
            snapshot: None,
            evidence: None,
            created_at: &now,
        },
    )
    .await?;
    if let Some(row) = store::reports::by_id(&state.db, &id).await? {
        announce(state, &row).await;
    }
    Ok(())
}

// ---------------------------------------------------------------- visibility and events

/// May `user` see the report? Node admins see every report; room moderators (`moderate_members`) the room's
/// reports that are not about themselves.
pub async fn can_see(state: &AppState, user: &UserRow, row: &ReportRow) -> Result<bool, ApiError> {
    if user.is_node_admin() {
        return Ok(true);
    }
    if row.scope != "room" || row.target_user_id.as_deref() == Some(user.id.as_str()) || user.is_bot() {
        return Ok(false);
    }
    let Some(room_id) = row.room_id.as_deref() else { return Ok(false) };
    match access::room_access(state, room_id, user).await {
        Ok(a) => Ok(a.member.is_some() && a.has(p::MODERATE_MEMBERS)),
        Err(ApiError::Forbidden { .. } | ApiError::NotFound { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

fn not_found() -> ApiError {
    access::not_found("Report", "report.not_found")
}

/// The report `id` if `user` may see it, else `404 report.not_found` (the same answer as for a missing report).
pub async fn visible(state: &AppState, user: &UserRow, id: &str) -> Result<ReportRow, ApiError> {
    if !util::is_ulid(id) {
        return Err(not_found());
    }
    let row = store::reports::by_id(&state.db, &id.to_ascii_uppercase()).await?.ok_or_else(not_found)?;
    if !can_see(state, user, &row).await? {
        return Err(not_found());
    }
    Ok(row)
}

/// Who gets the events of a report: node admins and, for room reports, the room's moderators; never the reporter
/// or the reported user, never bots.
async fn audience(state: &AppState, row: &ReportRow) -> Result<Vec<String>, ApiError> {
    let mut ids = store::reports::node_admin_ids(&state.db).await?;
    if row.scope == "room"
        && let Some(room_id) = &row.room_id
    {
        ids.extend(store::rooms::moderator_ids(&state.db, room_id).await?);
    }
    ids.sort();
    ids.dedup();
    ids.retain(|i| Some(i) != row.reporter_id.as_ref() && Some(i) != row.target_user_id.as_ref());
    Ok(store::users::by_ids(&state.db, &ids).await?.into_iter().filter(|u| !u.is_bot()).map(|u| u.id).collect())
}

/// `report.create` (MODERATION.md §1.5): no detail, no evidence.
async fn announce(state: &AppState, row: &ReportRow) {
    let room_name = match &row.room_id {
        Some(id) => store::rooms::room_by_id(&state.db, id).await.ok().flatten().map(|r| r.name),
        None => None,
    };
    match audience(state, row).await {
        Ok(ids) => {
            state.hub.users(
                ids.clone(),
                "report.create",
                json!({ "report": { "id": row.id, "scope": row.scope, "source": row.source, "kind": row.kind,
                    "room_id": row.room_id, "room_name": room_name, "conversation_id": row.conversation_id,
                    "category": row.category, "created_at": row.created_at } }),
            );
            push_report(state, row, room_name, ids);
        }
        Err(e) => tracing::warn!(error = %e, "report.create not sent"),
    }
}

/// Web push of a new report (PROTOCOL.md §6d) to the audience's local users with a subscription and the notification
/// setting `reports` on; the push module skips those with an open connection and applies the limits. In the
/// background: the report is answered first.
fn push_report(state: &AppState, row: &ReportRow, room_name: Option<String>, audience: Vec<String>) {
    if !state.push.enabled() || audience.is_empty() {
        return;
    }
    // Room reports name their room; node reports (also those about a room or its owner) name none: the client opens
    // the room's Reports tab or the admin inbox accordingly.
    let room_id = row.room_id.clone().filter(|_| row.scope == "room");
    let room_name = room_name.filter(|_| room_id.is_some());
    let (state, kind) = (state.clone(), row.kind.clone());
    tokio::spawn(async move {
        let result: Result<(), ApiError> = async {
            for user_id in store::push::users_with_subscriptions(&state.db, &audience).await? {
                if crate::notifications::load(&state.db, &user_id).await?.global.reports {
                    crate::push::report(&state, &user_id, room_id.as_deref(), room_name.as_deref(), &kind);
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, "report push not queued");
        }
    });
}

/// `report.update` after a change, an action or a deletion.
async fn changed(state: &AppState, row: &ReportRow, status: &str) {
    match audience(state, row).await {
        Ok(ids) => {
            state.hub.users(
                ids,
                "report.update",
                json!({ "id": row.id, "scope": row.scope, "room_id": row.room_id, "status": status }),
            );
        }
        Err(e) => tracing::warn!(error = %e, "report.update not sent"),
    }
}

// ---------------------------------------------------------------- API shape

/// Reports as the API shows them; `full` adds the evidence.
pub async fn to_api(state: &AppState, rows: Vec<ReportRow>, full: bool) -> Result<Vec<ModerationReport>, ApiError> {
    use std::collections::HashMap;
    let mut user_ids: Vec<String> = rows
        .iter()
        .flat_map(|r| [r.reporter_id.clone(), r.target_user_id.clone(), r.assignee_id.clone()])
        .flatten()
        .collect();
    user_ids.sort();
    user_ids.dedup();
    let users: HashMap<String, User> =
        store::users::by_ids(&state.db, &user_ids).await?.into_iter().map(|u| (u.id.clone(), u.to_public())).collect();
    let mut rooms: HashMap<String, String> = HashMap::new();
    let mut kinds: HashMap<String, String> = HashMap::new();
    for r in &rows {
        if let Some(id) = &r.room_id
            && !rooms.contains_key(id)
            && let Some(room) = store::rooms::room_by_id(&state.db, id).await?
        {
            rooms.insert(id.clone(), room.name);
        }
        if let (Some(id), None) = (&r.conversation_id, &r.node)
            && !kinds.contains_key(id)
            && let Some(c) = store::social::conversation(&state.db, id).await?
        {
            kinds.insert(id.clone(), c.kind);
        }
    }
    let local_messages: Vec<String> =
        rows.iter().filter(|r| r.node.is_none()).filter_map(|r| r.message_id.clone()).collect();
    let existing = if local_messages.is_empty() {
        Default::default()
    } else {
        store::blobs::existing_messages(&state.db, &local_messages).await?
    };
    Ok(rows
        .into_iter()
        .map(|r| {
            let evidence: Option<Vec<EvidenceEntry>> = r.evidence.as_deref().and_then(|e| serde_json::from_str(e).ok());
            let user = |id: &Option<String>| id.as_ref().and_then(|i| users.get(i).cloned());
            ModerationReport {
                room_name: r.room_id.as_ref().and_then(|id| rooms.get(id).cloned()),
                conversation_kind: r.conversation_id.as_ref().and_then(|id| kinds.get(id).cloned()),
                message_exists: r.message_id.as_ref().is_some_and(|m| r.node.is_none() && existing.contains(m)),
                target: user(&r.target_user_id),
                reporter: user(&r.reporter_id),
                assignee: user(&r.assignee_id),
                snapshot: r.snapshot.as_deref().and_then(|s| serde_json::from_str(s).ok()),
                evidence_count: evidence.as_ref().map_or(0, Vec::len),
                evidence_source: evidence.as_ref().map(|_| "reporter".to_string()),
                evidence: if full { evidence } else { None },
                actions: serde_json::from_str(&r.actions).unwrap_or_default(),
                id: r.id,
                source: r.source,
                scope: r.scope,
                kind: r.kind,
                room_id: r.room_id,
                conversation_id: r.conversation_id,
                node: r.node,
                message_id: r.message_id,
                target_address: r.target_address,
                category: r.category,
                detail: r.detail,
                status: r.status,
                note: r.note,
                created_at: r.created_at,
                updated_at: r.updated_at,
                resolved_at: r.resolved_at,
            }
        })
        .collect())
}

pub async fn one(state: &AppState, row: ReportRow, full: bool) -> Result<ModerationReport, ApiError> {
    to_api(state, vec![row], full).await?.pop().ok_or_else(not_found)
}

/// A page of reports with the open count.
pub async fn page(state: &AppState, filter: ListFilter, limit: i64) -> Result<ReportList, ApiError> {
    if filter.status.as_deref().is_some_and(|s| !STATUSES.contains(&s)) {
        return Err(bad("report.status_invalid", format!("status: one of {}", STATUSES.join(", "))));
    }
    if filter.before.as_deref().is_some_and(|b| !util::is_ulid(b)) {
        return Err(bad("validation.id", "before: not a valid ID"));
    }
    let rows = store::reports::list(&state.db, &filter, limit).await?;
    let open = store::reports::count_open(&state.db, &filter).await?;
    Ok(ReportList { reports: to_api(state, rows, false).await?, open })
}

// ---------------------------------------------------------------- triage

/// `PATCH /reports/{id}`.
pub async fn update(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    req: UpdateReportRequest,
) -> Result<ModerationReport, ApiError> {
    let row = visible(state, &auth.user, id).await?;
    let status = match req.status.as_deref() {
        Some(s) if STATUSES.contains(&s) => s.to_string(),
        Some(_) => return Err(bad("report.status_invalid", format!("status: one of {}", STATUSES.join(", ")))),
        None => row.status.clone(),
    };
    let assignee = match req.assignee_id {
        None => row.assignee_id.clone(),
        Some(None) => None,
        Some(Some(uid)) => {
            let ok = match store::users::by_id(&state.db, &uid).await? {
                Some(u) => can_see(state, &u, &row).await?,
                None => false,
            };
            if !ok {
                return Err(bad("report.assignee_invalid", "The assignee must be a moderator who may see the report"));
            }
            Some(uid)
        }
    };
    let note = match req.note.as_deref() {
        Some(n) => validate::text("note", n, 0, NOTE_MAX)?,
        None => row.note.clone(),
    };
    let now = util::now();
    let resolved_at = match status.as_str() {
        "open" => None,
        _ if row.status == status => row.resolved_at.clone().or_else(|| Some(now.clone())),
        _ => Some(now.clone()),
    };
    store::reports::update_triage(
        &state.db,
        &row.id,
        &status,
        assignee.as_deref(),
        &note,
        resolved_at.as_deref(),
        &now,
    )
    .await?;
    let row = store::reports::by_id(&state.db, &row.id).await?.ok_or_else(not_found)?;
    changed(state, &row, &row.status).await;
    one(state, row, true).await
}

/// `DELETE /reports/{id}`: node admins only, at any time.
pub async fn delete(state: &AppState, auth: &AuthUser, id: &str) -> Result<(), ApiError> {
    if !auth.user.is_node_admin() {
        return Err(ApiError::Forbidden { code: "auth.node_admin_required", detail: "Node admins only".into() });
    }
    let row = visible(state, &auth.user, id).await?;
    store::reports::delete(&state.db, &row.id).await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "report.delete",
        &row.id,
        "",
        json!({ "scope": row.scope }),
    )
    .await?;
    changed(state, &row, "deleted").await;
    Ok(())
}

/// Deletes closed reports past `TAVRN_REPORTS_RETENTION_DAYS` (housekeeping).
pub async fn prune(state: &AppState, now: chrono::DateTime<chrono::Utc>) -> Result<u64, ApiError> {
    let cutoff = util::format_time(now - chrono::Duration::days(i64::from(state.config.reports_retention_days)));
    store::reports::prune(&state.db, &cutoff).await
}

// ---------------------------------------------------------------- action shortcuts

fn action_invalid(detail: impl Into<String>) -> ApiError {
    bad("report.action_invalid", detail)
}

fn require_admin(auth: &AuthUser) -> Result<(), ApiError> {
    if auth.user.is_node_admin() {
        Ok(())
    } else {
        Err(ApiError::Forbidden { code: "auth.node_admin_required", detail: "Node admins only".into() })
    }
}

/// Runs one shortcut with the caller's permissions; `Some` for a purge (preview or result).
async fn run_action(
    state: &AppState,
    auth: &AuthUser,
    row: &ReportRow,
    req: &ReportActionRequest,
) -> Result<Option<crate::routes::rooms::PurgeResponse>, ApiError> {
    use crate::routes::{admin, messages, rooms};
    let s = || State(state.clone());
    let user_id = || row.target_user_id.clone().ok_or_else(|| action_invalid("The report names no user of this node"));
    let room_id = || row.room_id.clone().ok_or_else(|| action_invalid("This action needs a room"));
    match req.action.as_str() {
        "delete_message" => {
            let message_id = row.message_id.clone().ok_or_else(|| action_invalid("The report names no message"))?;
            if row.node.is_some() {
                return Err(ApiError::conflict("report.target_remote", "The message is on another node"));
            }
            let conversation_id = row.conversation_id.clone().unwrap_or_default();
            let conversation = store::social::conversation(&state.db, &conversation_id)
                .await?
                .ok_or_else(|| access::not_found("Message", "message.not_found"))?;
            if conversation.kind == "channel" {
                messages::delete_conversation_message(s(), auth.clone(), Path((conversation_id, message_id))).await?;
            } else {
                // DMs and group DMs have no moderators: node admins remove the message directly.
                require_admin(auth)?;
                let author = store::messages::by_id(&state.db, &message_id).await?.map(|m| m.author_id);
                if !crate::legal::notices::delete_message(state, &message_id).await? {
                    return Err(access::not_found("Message", "message.not_found"));
                }
                store::rooms::audit(
                    &state.db,
                    None,
                    Some(&auth.user.id),
                    "message.delete",
                    &message_id,
                    "",
                    json!({ "conversation_id": conversation_id, "author_id": author }),
                )
                .await?;
            }
            Ok(None)
        }
        "timeout" => {
            let minutes = req.minutes.ok_or_else(|| action_invalid("timeout: minutes 1 to 40320"))?;
            if !(1..=crate::automod::MAX_TIMEOUT_MINUTES).contains(&minutes) {
                return Err(bad("validation.range", "minutes: between 1 and 40320"));
            }
            let body = rooms::TimeoutRequest { minutes, reason: req.reason.clone() };
            let _ = rooms::timeout_member(s(), auth.clone(), Path((room_id()?, user_id()?)), Json(body)).await?;
            Ok(None)
        }
        "kick" => {
            let body = rooms::ReasonRequest { reason: req.reason.clone() };
            rooms::kick_member(s(), auth.clone(), Path((room_id()?, user_id()?)), Some(Json(body))).await?;
            Ok(None)
        }
        "ban" => {
            if row.target_address.is_empty() {
                return Err(action_invalid("The report names no user"));
            }
            let subject = row.target_address.clone();
            if row.scope == "room" {
                let body = rooms::BanRequest { subject, reason: req.reason.clone() };
                let _ = rooms::ban(s(), auth.clone(), Path(room_id()?), Json(body)).await?;
            } else {
                require_admin(auth)?;
                let body = admin::NodeBanRequest { subject, reason: req.reason.clone() };
                let _ = admin::ban(s(), NodeAdmin(auth.clone()), Json(body)).await?;
            }
            Ok(None)
        }
        "purge" => {
            let target = user_id()?;
            if row.scope == "room" {
                let body = rooms::PurgeRequest {
                    channel_ids: Vec::new(),
                    author_id: Some(target),
                    from: None,
                    to: None,
                    confirm_token: req.confirm_token.clone(),
                };
                let Json(r) = rooms::purge(s(), auth.clone(), Path(room_id()?), Json(body)).await?;
                Ok(Some(r))
            } else {
                require_admin(auth)?;
                let body = admin::PurgeUserRequest { confirm_token: req.confirm_token.clone() };
                let Json(r) = admin::purge_user(s(), NodeAdmin(auth.clone()), Path(target), Json(body)).await?;
                Ok(Some(rooms::PurgeResponse {
                    dry_run: r.dry_run,
                    messages: r.messages,
                    confirm_token: r.confirm_token,
                }))
            }
        }
        _ => Err(action_invalid(format!("action: one of {}", ACTIONS.join(", ")))),
    }
}

/// `POST /reports/{id}/actions` (MODERATION.md §1.4).
pub async fn act(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    req: ReportActionRequest,
) -> Result<ReportActionResult, ApiError> {
    let row = visible(state, &auth.user, id).await?;
    if !ACTIONS.contains(&req.action.as_str()) {
        return Err(action_invalid(format!("action: one of {}", ACTIONS.join(", "))));
    }
    let reason = validate::text("reason", &req.reason, 0, 500)?;
    let req = ReportActionRequest { reason, ..req };
    let purge = ACTING_ON.scope(row.id.clone(), run_action(state, auth, &row, &req)).await?;
    if purge.as_ref().is_some_and(|p| p.dry_run) {
        return Ok(ReportActionResult { report: one(state, row, true).await?, purge });
    }
    let now = util::now();
    let mut actions: Vec<ReportActionRecord> = serde_json::from_str(&row.actions).unwrap_or_default();
    actions.push(ReportActionRecord {
        action: req.action.clone(),
        actor: auth.user.address(),
        at: now.clone(),
        minutes: req.minutes.filter(|_| req.action == "timeout"),
    });
    let encoded = serde_json::to_string(&actions).map_err(|e| ApiError::Internal(e.into()))?;
    store::reports::set_actions(&state.db, &row.id, &encoded, &now).await?;
    if req.resolve && row.status != "resolved" {
        store::reports::update_triage(
            &state.db,
            &row.id,
            "resolved",
            row.assignee_id.as_deref(),
            &row.note,
            Some(&now),
            &now,
        )
        .await?;
    }
    let row = store::reports::by_id(&state.db, &row.id).await?.ok_or_else(not_found)?;
    changed(state, &row, &row.status).await;
    Ok(ReportActionResult { report: one(state, row, true).await?, purge })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn entry(id: &str) -> EvidenceEntry {
        EvidenceEntry {
            message_id: Some(id.into()),
            author: "alice@a.example".into(),
            device_id: Some("dev".into()),
            created_at: "2026-10-01T10:00:00Z".into(),
            text: "hello".into(),
            attachments: vec!["a.png".into()],
        }
    }

    const ID: &str = "01J00000000000000000000001";
    const OTHER: &str = "01J00000000000000000000002";

    #[test]
    fn evidence_is_checked() {
        assert!(validate_evidence(&[entry(OTHER), entry(ID)], ID).is_ok());
        assert!(validate_evidence(&[entry(ID)], &ID.to_lowercase()).is_ok());
        let code =
            |entries: Vec<EvidenceEntry>| validate_evidence(&entries, ID).map(|_| ()).map_err(|e| e.code().to_string());
        let bad = Err("report.evidence_invalid".to_string());
        assert_eq!(code(vec![]), bad);
        assert_eq!(code(vec![entry(OTHER)]), bad, "the reported message must be included");
        assert_eq!(code((0..12).map(|_| entry(ID)).collect()), bad);
        assert_eq!(code(vec![EvidenceEntry { author: "nobody".into(), ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { created_at: "yesterday".into(), ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { text: "x".repeat(4001), ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { attachments: vec![String::new()], ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { attachments: vec!["a".into(); 11], ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { device_id: Some("d".repeat(65)), ..entry(ID) }]), bad);
        assert_eq!(code(vec![EvidenceEntry { message_id: Some("nope".into()), ..entry(ID) }, entry(ID)]), bad);
        // 11 entries of 4000 multi-byte characters exceed 64 KiB.
        let big: Vec<EvidenceEntry> = (0..11).map(|_| EvidenceEntry { text: "é".repeat(4000), ..entry(ID) }).collect();
        assert_eq!(code(big), bad);
    }

    #[tokio::test]
    async fn the_report_id_follows_the_action_task() {
        assert_eq!(acting_on(), None);
        let inner = ACTING_ON.scope("R1".to_string(), async { acting_on() }).await;
        assert_eq!(inner.as_deref(), Some("R1"));
        assert_eq!(acting_on(), None);
    }
}
