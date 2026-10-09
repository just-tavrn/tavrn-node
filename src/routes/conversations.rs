// SPDX-License-Identifier: AGPL-3.0-only
//! Direct messages and group DMs. Messages, reactions, pins and uploads of any conversation live
//! under `/conversations/{conversation_id}/…` (see `messages.rs`, `attachments.rs`); DMs and group
//! DMs are always end-to-end encrypted.
//!
//! Members may be users of other nodes (FEDERATION.md §6.1): a DM or group DM lives on the home node of
//! its creator; remote members become stubs, get a `conversation.invite` on their home node and use the
//! conversation here with a federated session.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    access::{self, ConvKind},
    app::AppState,
    auth::AuthUser,
    config::DmPolicy,
    e2ee,
    error::{ApiError, ApiJson, ProblemDetails},
    federation::{remote, social},
    models::{User, UserRow},
    store::{self, social::ConversationRow},
    validate::{self, bad},
};

/// Members of a group DM including the creator.
pub const MAX_GROUP_MEMBERS: usize = 50;
pub const MAX_NAME_CHARS: usize = 100;

#[derive(Serialize, ToSchema)]
pub struct Conversation {
    pub id: String,
    /// dm | group
    pub kind: String,
    /// Name of a group DM (null for DMs and unnamed groups).
    pub name: Option<String>,
    /// Address of the creator.
    pub creator: Option<String>,
    /// Always true for DMs and group DMs.
    pub encrypted: bool,
    pub members: Vec<User>,
    pub last_message_id: Option<String>,
    pub created_at: String,
    /// The requester's read marker (only in `GET /conversations`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_read_message_id: Option<String>,
    /// Messages of others after the marker, at most 999 (only in `GET /conversations`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_count: Option<i64>,
    /// Of those, messages mentioning the requester, at most 999 (only in `GET /conversations`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mention_count: Option<i64>,
    /// Addresses of members who have not accepted the conversation yet (message requests).
    #[serde(default)]
    pub pending: Vec<String>,
}

/// A conversation waiting in my "Message requests" (`GET /conversations/requests`, WS `conversation.request`).
#[derive(Serialize, ToSchema)]
pub struct ConversationRequest {
    pub conversation: Conversation,
    /// Who started it (its creator).
    pub from: Option<User>,
    /// Rooms of this node I share with the sender.
    pub shared_rooms: Vec<SharedRoom>,
    /// The first message (the preview; encrypted, the client decrypts it).
    pub first_message_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SharedRoom {
    pub id: String,
    pub name: String,
}

async fn view(state: &AppState, row: &ConversationRow) -> Result<Conversation, ApiError> {
    let member_ids = store::social::member_ids(&state.db, &row.id).await?;
    let members = store::users::by_ids(&state.db, &member_ids).await?;
    let creator = match &row.creator_id {
        Some(id) => store::users::by_id(&state.db, id).await?.map(|u| u.address()),
        None => None,
    };
    let requested = store::social::requested_ids(&state.db, &row.id).await?;
    let pending = members.iter().filter(|m| requested.contains(&m.id)).map(UserRow::address).collect();
    Ok(Conversation {
        id: row.id.clone(),
        kind: row.kind.clone(),
        name: row.name.clone(),
        creator,
        encrypted: row.encrypted != 0,
        members: members.iter().map(UserRow::to_public).collect(),
        last_message_id: store::social::last_message_id(&state.db, &row.id).await?,
        created_at: row.created_at.clone(),
        last_read_message_id: None,
        unread_count: None,
        mention_count: None,
        pending,
    })
}

async fn request_view(state: &AppState, row: &ConversationRow, me: &UserRow) -> Result<ConversationRequest, ApiError> {
    let from = match &row.creator_id {
        Some(id) => store::users::by_id(&state.db, id).await?,
        None => None,
    };
    let shared_rooms = match &from {
        Some(from) => store::rooms::shared_rooms(&state.db, &me.id, &from.id)
            .await?
            .into_iter()
            .map(|(id, name)| SharedRoom { id, name })
            .collect(),
        None => Vec::new(),
    };
    Ok(ConversationRequest {
        conversation: view(state, row).await?,
        from: from.as_ref().map(UserRow::to_public),
        shared_rooms,
        first_message_id: store::social::first_message_id(&state.db, &row.id).await?,
    })
}

/// Tells `user` (local, with open connections) about a new message request.
async fn announce_request(state: &AppState, row: &ConversationRow, user: &UserRow) -> Result<(), ApiError> {
    if user.domain == state.config.domain {
        let request = request_view(state, row, user).await?;
        state.hub.users(vec![user.id.clone()], "conversation.request", json!({ "request": request }));
    }
    Ok(())
}

fn member_ids(conv: &access::Conv) -> Vec<String> {
    match &conv.kind {
        ConvKind::Direct { member_ids, .. } => member_ids.clone(),
        ConvKind::Channel { .. } => Vec::new(),
    }
}

fn row(conv: &access::Conv) -> Result<&ConversationRow, ApiError> {
    match &conv.kind {
        ConvKind::Direct { row, .. } => Ok(row),
        ConvKind::Channel { .. } => Err(access::not_found("Conversation", "conversation.not_found")),
    }
}

/// Resolves a member reference (`name` or `name@domain`) to a user of this or another node (remote
/// users become stubs after their home node confirmed them).
async fn resolve(state: &AppState, reference: &str) -> Result<UserRow, ApiError> {
    if remote::parse_reference(state, reference).is_none() {
        return Err(bad("conversation.member_invalid", format!("Invalid user reference: {reference}")));
    }
    remote::resolve_or_stub(state, reference).await
}

/// How `other` joins a conversation `me` starts or adds them to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// A normal member (friends, the owner of a bot).
    Active,
    /// A message request the recipient accepts or declines.
    Requested,
}

/// May `me` start a conversation with (or add) `other`, and as what? Blocks always win; friends (and the
/// owner of a bot) become members; everyone else gets a message request if the recipient's "Who can
/// message me" allows it under this node's `dm_policy` bound: `friends` refuses (`dm.friends_only`, or
/// `dm.not_friends` when the node allows only friends), `everyone_shared` needs a shared room of this node
/// (`dm.no_shared_room`), `everyone` lets everyone ask. For recipients of other nodes their home node
/// decides when it receives the invitation (FEDERATION.md §6.1); the mirrored setting gives an early answer.
async fn admission(state: &AppState, me: &UserRow, other: &UserRow) -> Result<Admission, ApiError> {
    if store::social::blocked_either(&state.db, &me.id, &other.id).await? {
        return Err(ApiError::Forbidden { code: "dm.blocked", detail: "You cannot message this person".into() });
    }
    // The owner and its bot always talk in a normal conversation, whoever starts it (APPLICATIONS.md §2.5).
    let own_bot = (other.is_bot() && other.owner_id.as_deref() == Some(me.id.as_str()))
        || (me.is_bot() && me.owner_id.as_deref() == Some(other.id.as_str()));
    if own_bot || store::social::are_friends(&state.db, &me.id, &other.id).await? {
        return Ok(Admission::Active);
    }
    let own = &state.config.domain;
    let node = state.config.dm_policy;
    let friends_only = || ApiError::Forbidden {
        code: "dm.friends_only",
        detail: format!("{} accepts direct messages only from friends", other.address()),
    };
    if node == DmPolicy::Friends && (me.domain == *own || other.domain == *own) {
        return Err(ApiError::Forbidden {
            code: "dm.not_friends",
            detail: format!("On this node, direct messages are only possible between friends ({})", other.address()),
        });
    }
    if other.domain != *own {
        return if other.dm_policy(DmPolicy::Everyone) == DmPolicy::Friends {
            Err(friends_only())
        } else {
            Ok(Admission::Requested)
        };
    }
    match other.dm_policy(node) {
        DmPolicy::Friends => Err(friends_only()),
        DmPolicy::EveryoneShared => {
            if store::rooms::shared_rooms(&state.db, &me.id, &other.id).await?.is_empty() {
                Err(ApiError::Forbidden {
                    code: "dm.no_shared_room",
                    detail: format!(
                        "{} accepts direct messages only from friends and members of shared rooms",
                        other.address()
                    ),
                })
            } else {
                Ok(Admission::Requested)
            }
        }
        DmPolicy::Everyone => Ok(Admission::Requested),
    }
}

fn clean_name(name: Option<&str>) -> Result<Option<String>, ApiError> {
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => Ok(Some(validate::name("name", n, MAX_NAME_CHARS)?)),
        None => Ok(None),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateConversationRequest {
    /// dm | group
    pub kind: String,
    /// Other members (`username` or `username@domain`): exactly one for `dm`, 1–49 for `group`.
    pub members: Vec<String>,
    /// Optional name of a group DM.
    pub name: Option<String>,
}

/// Start a DM (idempotent: an existing DM is returned with 200) or a group DM.
#[utoipa::path(post, path = "/api/v1/conversations", security(("bearer" = [])), request_body = CreateConversationRequest,
    responses((status = 201, body = Conversation), (status = 200, body = Conversation), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<CreateConversationRequest>,
) -> Result<(StatusCode, Json<Conversation>), ApiError> {
    let kind = validate::one_of("kind", &req.kind, &["dm", "group"])?;
    let count_ok = match kind.as_str() {
        "dm" => req.members.len() == 1,
        _ => (1..MAX_GROUP_MEMBERS).contains(&req.members.len()),
    };
    if !count_ok {
        return Err(bad(
            "conversation.members_invalid",
            format!("Direct message: exactly one member; group: 2 to {MAX_GROUP_MEMBERS} members including you"),
        ));
    }
    let mut others: Vec<UserRow> = Vec::new();
    for m in &req.members {
        let user = resolve(&state, m).await?;
        if user.id == auth.user.id {
            if kind == "dm" {
                return Err(bad("conversation.self", "You cannot send a direct message to yourself"));
            }
            continue;
        }
        if !others.iter().any(|o| o.id == user.id) {
            others.push(user);
        }
    }
    if others.is_empty() {
        return Err(bad("conversation.members_invalid", "At least one other member is required"));
    }
    // Bots live in rooms and 1:1 DMs only (APPLICATIONS.md §2.5).
    if kind == "group" && (auth.user.is_bot() || others.iter().any(UserRow::is_bot)) {
        return Err(bad("app.bot_forbidden", "Bots cannot be in group DMs"));
    }
    if kind == "dm"
        && let Some(existing) =
            store::social::dm_by_key(&state.db, &store::social::dm_key(&auth.user.id, &others[0].id)).await?
    {
        return reopen_dm(&state, &auth.user, &others[0], existing).await;
    }
    let mut requested = Vec::new();
    for other in &others {
        if admission(&state, &auth.user, other).await? == Admission::Requested {
            requested.push(other.id.clone());
        }
    }
    let mut ids: Vec<String> = vec![auth.user.id.clone()];
    ids.extend(others.iter().map(|o| o.id.clone()));
    let active: Vec<String> = ids.iter().filter(|i| !requested.contains(i)).cloned().collect();

    if kind == "dm" {
        let key = store::social::dm_key(&auth.user.id, &others[0].id);
        state.conversation_limiter.check_all(&[format!("conv:{}", auth.user.id)])?;
        if auth.user.is_bot() {
            state.bot_dm_limiter.check_all(&[format!("bot-dm:{}", auth.user.id)])?;
        }
        let created =
            store::social::create_conversation(&state.db, "dm", None, &auth.user.id, Some(&key), &ids, &requested)
                .await?;
        let row = match &created {
            Some(id) => store::social::conversation(&state.db, id).await?,
            // Created concurrently by the other side.
            None => store::social::dm_by_key(&state.db, &key).await?,
        }
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("DM not found after INSERT")))?;
        let conversation = view(&state, &row).await?;
        state.hub.users(active, "conversation.create", json!({ "conversation": conversation }));
        if created.is_some() {
            for other in others.iter().filter(|o| requested.contains(&o.id)) {
                announce_request(&state, &row, other).await?;
            }
            social::invite_to_conversation(&state, &auth.user, &row, &others).await?;
        }
        return Ok((StatusCode::CREATED, Json(conversation)));
    }

    state.conversation_limiter.check_all(&[format!("conv:{}", auth.user.id)])?;
    let name = clean_name(req.name.as_deref())?;
    let id =
        store::social::create_conversation(&state.db, "group", name.as_deref(), &auth.user.id, None, &ids, &requested)
            .await?
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("group ID collision")))?;
    let row = store::social::conversation(&state.db, &id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("group not found after INSERT")))?;
    let conversation = view(&state, &row).await?;
    state.hub.users(active, "conversation.create", json!({ "conversation": conversation }));
    for other in others.iter().filter(|o| requested.contains(&o.id)) {
        announce_request(&state, &row, other).await?;
    }
    social::invite_to_conversation(&state, &auth.user, &row, &others).await?;
    Ok((StatusCode::CREATED, Json(conversation)))
}

/// `POST /conversations` for a DM that exists: returned as it is (200). A member who left it (declined a
/// request) comes back only by starting it themselves or, for the other side, once the two are friends;
/// a declined request is never sent again.
async fn reopen_dm(
    state: &AppState,
    me: &UserRow,
    other: &UserRow,
    existing: ConversationRow,
) -> Result<(StatusCode, Json<Conversation>), ApiError> {
    if store::social::blocked_either(&state.db, &me.id, &other.id).await? {
        return Err(ApiError::Forbidden { code: "dm.blocked", detail: "You cannot message this person".into() });
    }
    let members = store::social::member_ids(&state.db, &existing.id).await?;
    let mut changed = false;
    if !members.contains(&me.id) {
        admission(state, me, other).await?;
        store::social::add_member(&state.db, &existing.id, &me.id, false).await?;
        changed = true;
    }
    if !members.contains(&other.id) && admission(state, me, other).await? == Admission::Active {
        store::social::add_member(&state.db, &existing.id, &other.id, false).await?;
        social::invite_to_conversation(state, me, &existing, std::slice::from_ref(other)).await?;
        changed = true;
    }
    let conversation = view(state, &existing).await?;
    if changed {
        let ids: Vec<String> = conversation.members.iter().map(|m| m.id.clone()).collect();
        state.hub.users(ids, "conversation.create", json!({ "conversation": conversation }));
    }
    Ok((StatusCode::OK, Json(conversation)))
}

/// My DMs and group DMs, most recent activity first.
#[utoipa::path(get, path = "/api/v1/conversations", security(("bearer" = [])), responses((status = 200, body = Vec<Conversation>)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<Conversation>>, ApiError> {
    let rows = store::social::conversations_of(&state.db, &auth.user.id, store::social::STATE_ACTIVE).await?;
    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let settings = if auth.user.domain == state.config.domain {
        Some(crate::notifications::load(&state.db, &auth.user.id).await?)
    } else {
        None
    };
    let ctx = store::messages::ReadContext { settings: settings.as_ref(), ..Default::default() };
    let states = store::messages::read_states(&state.db, &auth.user.id, &auth.user.address(), &ids, "", &ctx).await?;
    let mut out = Vec::new();
    for (row, read) in rows.iter().zip(states) {
        let mut c = view(&state, row).await?;
        c.last_read_message_id = read.last_read_message_id;
        c.unread_count = Some(read.unread_count);
        c.mention_count = Some(read.mention_count);
        out.push(c);
    }
    out.sort_by(|a, b| {
        let ka = a.last_message_id.as_deref().unwrap_or(&a.id);
        let kb = b.last_message_id.as_deref().unwrap_or(&b.id);
        kb.cmp(ka)
    });
    Ok(Json(out))
}

/// One DM or group DM (members only).
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = Conversation), (status = 404, body = ProblemDetails)))]
pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<Conversation>, ApiError> {
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    Ok(Json(view(&state, row(&conv)?).await?))
}

fn require_group(row: &ConversationRow) -> Result<(), ApiError> {
    if row.kind != "group" {
        return Err(bad("conversation.not_group", "Only groups have names and changeable members"));
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateConversationRequest {
    /// New name; null or empty removes it.
    pub name: Option<String>,
}

/// Rename a group DM (any member).
#[utoipa::path(patch, path = "/api/v1/conversations/{conversation_id}", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = UpdateConversationRequest,
    responses((status = 200, body = Conversation), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<UpdateConversationRequest>,
) -> Result<Json<Conversation>, ApiError> {
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    require_group(row(&conv)?)?;
    crate::routes::messages::check_direct_write(&state, &auth, &conv).await?;
    let name = clean_name(req.name.as_deref())?;
    store::social::set_name(&state.db, &conv.id, name.as_deref()).await?;
    let updated = store::social::conversation(&state.db, &conv.id)
        .await?
        .ok_or_else(|| access::not_found("Conversation", "conversation.not_found"))?;
    let conversation = view(&state, &updated).await?;
    state.hub.users(member_ids(&conv), "conversation.update", json!({ "conversation": conversation }));
    Ok(Json(conversation))
}

/// Add a member to a group DM (any member; the new member must be allowed under the DM policy).
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/members", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = crate::routes::friends::UserRef,
    responses((status = 200, body = Conversation), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn add_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<crate::routes::friends::UserRef>,
) -> Result<Json<Conversation>, ApiError> {
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    let current = row(&conv)?;
    require_group(current)?;
    crate::routes::messages::check_direct_write(&state, &auth, &conv).await?;
    let user = resolve(&state, &req.user).await?;
    if user.is_bot() {
        return Err(bad("app.bot_forbidden", "Bots cannot be in group DMs"));
    }
    let members = member_ids(&conv);
    if members.contains(&user.id) {
        return Err(ApiError::conflict("conversation.member_exists", "Already a member"));
    }
    if members.len() >= MAX_GROUP_MEMBERS {
        return Err(bad("conversation.full", format!("At most {MAX_GROUP_MEMBERS} members")));
    }
    let requested = admission(&state, &auth.user, &user).await? == Admission::Requested;
    store::social::add_member(&state.db, &conv.id, &user.id, requested).await?;
    social::invite_to_conversation(&state, &auth.user, current, std::slice::from_ref(&user)).await?;
    let conversation = view(&state, current).await?;
    let mut all = members;
    if requested {
        announce_request(&state, current, &user).await?;
    } else {
        state.hub.users(vec![user.id.clone()], "conversation.create", json!({ "conversation": conversation }));
        all.push(user.id.clone());
    }
    state.hub.users(all, "conversation.update", json!({ "conversation": conversation }));
    Ok(Json(conversation))
}

/// My message requests: conversations of people who are not my friends, until I accept or decline them.
#[utoipa::path(get, path = "/api/v1/conversations/requests", security(("bearer" = [])),
    responses((status = 200, body = Vec<ConversationRequest>)))]
pub async fn requests(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<ConversationRequest>>, ApiError> {
    let rows = store::social::conversations_of(&state.db, &auth.user.id, store::social::STATE_REQUESTED).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(request_view(&state, row, &auth.user).await?);
    }
    out.sort_by(|a, b| b.conversation.created_at.cmp(&a.conversation.created_at));
    Ok(Json(out))
}

/// Accept a message request: the conversation becomes a normal DM or group DM (idempotent).
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/accept", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    responses((status = 200, body = Conversation), (status = 404, body = ProblemDetails)))]
pub async fn accept(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<Conversation>, ApiError> {
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    let current = row(&conv)?;
    if store::social::accept_request(&state.db, &conv.id, &auth.user.id).await? {
        let conversation = view(&state, current).await?;
        state.hub.users(vec![auth.user.id.clone()], "conversation.create", json!({ "conversation": conversation }));
        state.hub.users(member_ids(&conv), "conversation.update", json!({ "conversation": conversation }));
        return Ok(Json(conversation));
    }
    Ok(Json(view(&state, current).await?))
}

#[derive(Deserialize, ToSchema, Default)]
pub struct DeclineRequest {
    /// Also block the sender (on my home node; users of other nodes block there).
    #[serde(default)]
    pub block: bool,
    /// Private note for the block (≤ 256 characters).
    pub reason: Option<String>,
}

/// Decline a message request: I leave the conversation (the sender is not told), optionally blocking them.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/decline", security(("bearer" = [])), params(("conversation_id" = String, Path)),
    request_body = DeclineRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn decline(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    body: Option<Json<DeclineRequest>>,
) -> Result<StatusCode, ApiError> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let reason = match req.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => validate::text("reason", r, 1, crate::routes::friends::NOTE_MAX_CHARS)?,
        None => String::new(),
    };
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    let current = row(&conv)?.clone();
    if !conv.is_request_for(&auth.user.id) {
        return Err(ApiError::conflict("conversation.not_requested", "This is not a pending message request"));
    }
    store::social::remove_member(&state.db, &conv.id, &auth.user.id).await?;
    state.hub.users(vec![auth.user.id.clone()], "conversation.leave", json!({ "conversation_id": conv.id }));
    let remaining: Vec<String> = member_ids(&conv).into_iter().filter(|m| *m != auth.user.id).collect();
    if let Some(updated) = store::social::conversation(&state.db, &conv.id).await? {
        let conversation = view(&state, &updated).await?;
        state.hub.users(remaining, "conversation.update", json!({ "conversation": conversation }));
    }
    e2ee::user_left_conversation(&state, &conv.id, &auth.user).await?;
    crate::calls::drop_member(&state, &conv.id, &auth.user.id).await;
    let sender = match &current.creator_id {
        Some(id) => store::users::by_id(&state.db, id).await?,
        None => None,
    };
    if req.block
        && auth.user.domain == state.config.domain
        && let Some(sender) = sender.filter(|s| s.id != auth.user.id)
    {
        crate::routes::friends::block_user(&state, &auth.user, &sender, &reason).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Leave a group DM (own username) or, as its creator, remove a member. Remaining members get
/// `mls.remove_needed` for the leaves of the departed user.
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/members/{username}", security(("bearer" = [])), params(("conversation_id" = String, Path), ("username" = String, Path)),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn remove_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, username)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let conv = access::direct(&state, &conversation_id, &auth.user.id).await?;
    let current = row(&conv)?;
    require_group(current)?;
    let not_member = || access::not_found("Member", "conversation.member_not_found");
    let user = remote::known_user(&state, &username).await?.ok_or_else(not_member)?;
    if user.id != auth.user.id && current.creator_id.as_deref() != Some(auth.user.id.as_str()) {
        return Err(ApiError::Forbidden {
            code: "conversation.remove_forbidden",
            detail: "Only the creator of the group can remove others".into(),
        });
    }
    if !store::social::remove_member(&state.db, &conv.id, &user.id).await? {
        return Err(not_member());
    }
    state.hub.users(vec![user.id.clone()], "conversation.leave", json!({ "conversation_id": conv.id }));
    let remaining: Vec<String> = member_ids(&conv).into_iter().filter(|m| m != &user.id).collect();
    if let Some(updated) = store::social::conversation(&state.db, &conv.id).await? {
        let conversation = view(&state, &updated).await?;
        state.hub.users(remaining, "conversation.update", json!({ "conversation": conversation }));
    }
    e2ee::user_left_conversation(&state, &conv.id, &user).await?;
    crate::calls::drop_member(&state, &conv.id, &user.id).await;
    Ok(StatusCode::NO_CONTENT)
}
