// SPDX-License-Identifier: AGPL-3.0-only
//! Read markers: a user's last read message per conversation. The node derives the
//! unread and mention counts of the room and conversation lists from them.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    models::UserRow,
    store::{self, messages::ReadState},
    validate,
};

#[derive(Deserialize, ToSchema)]
pub struct ReadRequest {
    /// Newest message the user has seen; the marker never moves backwards.
    pub last_read_message_id: String,
}

/// Mark a conversation read up to a message (members with `view_channel`; markers never move
/// backwards). The user's other connections get `read.update`.
#[utoipa::path(put, path = "/api/v1/conversations/{conversation_id}/read", security(("bearer" = [])), params(("conversation_id" = String, Path)), request_body = ReadRequest,
    responses((status = 200, body = ReadState), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn mark_read(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<ReadRequest>,
) -> Result<Json<ReadState>, ApiError> {
    state.read_limiter.check_all(&[format!("read:{}", auth.user.id)])?;
    let conv = advance(&state, &auth.user, &conversation_id, &req.last_read_message_id).await?;
    let joined = joined_since(&conv);
    let settings = if auth.user.domain == state.config.domain {
        Some(crate::notifications::load(&state.db, &auth.user.id).await?)
    } else {
        None
    };
    let (role_ids, system): (Vec<String>, Vec<String>) = match &conv.kind {
        ConvKind::Channel { access, channel } => (
            access.member_roles.iter().map(|r| r.id.clone()).collect(),
            if channel.kind == "system" { vec![channel.id.clone()] } else { Vec::new() },
        ),
        ConvKind::Direct { .. } => (Vec::new(), Vec::new()),
    };
    let ctx = store::messages::ReadContext {
        role_ids: &role_ids,
        settings: settings.as_ref(),
        room_id: conv.room_id(),
        system_channels: &system,
    };
    let mut states = store::messages::read_states(
        &state.db,
        &auth.user.id,
        &auth.user.address(),
        std::slice::from_ref(&conv.id),
        &joined,
        &ctx,
    )
    .await?;
    states.pop().map(Json).ok_or_else(|| ApiError::Internal(anyhow::anyhow!("read state missing")))
}

/// Checks access and the message, moves the marker forward and tells the user's other devices.
/// Shared by `PUT …/read` and the WebSocket operation `ack`.
pub async fn advance(
    state: &AppState,
    user: &UserRow,
    conversation_id: &str,
    message_id: &str,
) -> Result<Conv, ApiError> {
    let conv = access::conversation(state, conversation_id, user).await?;
    conv.require_entitled()?;
    validate::ulid("last_read_message_id", message_id)?;
    let message = access::message(state, user, &conv, message_id, access::Window::Ignore).await?;
    let (marker, moved) = store::messages::advance_read_marker(&state.db, &conv.id, &user.id, &message.id).await?;
    if moved {
        state.hub.users(
            vec![user.id.clone()],
            "read.update",
            json!({ "conversation_id": conv.id, "last_read_message_id": marker }),
        );
    }
    Ok(conv)
}

/// Without a marker, messages count from the user's join: the room membership for channels
/// (DMs and group DMs use their own membership inside the query).
pub fn joined_since(conv: &Conv) -> String {
    match &conv.kind {
        ConvKind::Channel { access, .. } => access.member.as_ref().map(|m| m.joined_at.clone()).unwrap_or_default(),
        ConvKind::Direct { .. } => String::new(),
    }
}
