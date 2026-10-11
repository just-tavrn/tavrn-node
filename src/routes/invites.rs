// SPDX-License-Identifier: AGPL-3.0-only
//! The invite list of the home node (FEDERATION.md §4): pending invitations to rooms and conversations
//! on any node. Accepting = joining on the hosting node, then dismissing the entry here.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    store::{self, invites::UserInviteRow},
};

#[derive(Serialize, ToSchema)]
pub struct UserInvite {
    pub id: String,
    /// room | conversation
    pub kind: String,
    /// Domain of the node hosting the room or conversation.
    pub node: String,
    /// Rooms: `{ node, id, name, description, icon_url, member_count }`.
    #[schema(value_type = Option<Object>)]
    pub room: Option<Value>,
    /// Conversations: `{ node, id, kind, name, members }`.
    #[schema(value_type = Option<Object>)]
    pub conversation: Option<Value>,
    /// Address of the inviting user.
    pub inviter: String,
    /// Set when the inviter is a user of a third node (neither `node` nor this node): `node` named them, but cannot
    /// vouch for them, so their identity is unverified (FEDERATION.md §5.2). Clients show "via <node>".
    pub via: Option<String>,
    /// Rooms: the invite code for `POST /invites/{code}/join` on `node`.
    pub invite_code: Option<String>,
    pub received_at: String,
    pub expires_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserInviteList {
    pub items: Vec<UserInvite>,
}

pub fn view(row: &UserInviteRow) -> UserInvite {
    let summary: Value = serde_json::from_str(&row.summary).unwrap_or(Value::Null);
    let via = summary.get("via").and_then(Value::as_str).map(String::from);
    let (room, conversation) = if row.kind == "room" { (Some(summary), None) } else { (None, Some(summary)) };
    UserInvite {
        id: row.id.clone(),
        kind: row.kind.clone(),
        node: row.node.clone(),
        room,
        conversation,
        inviter: row.inviter.clone(),
        via,
        invite_code: row.invite_code.clone(),
        received_at: row.received_at.clone(),
        expires_at: row.expires_at.clone(),
    }
}

/// Pending invitations of the user (newest first, expired ones are not listed).
#[utoipa::path(get, path = "/api/v1/users/me/invites", security(("bearer" = [])),
    responses((status = 200, body = UserInviteList), (status = 403, body = ProblemDetails)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<UserInviteList>, ApiError> {
    let rows = store::invites::list(&state.db, &auth.user.id).await?;
    Ok(Json(UserInviteList { items: rows.iter().map(view).collect() }))
}

/// Dismiss an invitation (after accepting it on the hosting node, or to decline it).
#[utoipa::path(delete, path = "/api/v1/users/me/invites/{invite_id}", security(("bearer" = [])), params(("invite_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn dismiss(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(invite_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !store::invites::delete(&state.db, &auth.user.id, &invite_id).await? {
        return Err(ApiError::NotFound { code: "invite.not_found", what: "Invite".into() });
    }
    Ok(StatusCode::NO_CONTENT)
}
