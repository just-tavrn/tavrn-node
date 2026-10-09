// SPDX-License-Identifier: AGPL-3.0-only
//! Presence routes (`presence.rs`): the own status, custom status and activity per device,
//! the presence of others and the per-room privacy switch. Clients call these on every node they have a
//! session on.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    presence::{self, Activity, CustomStatus, MyPresence, Presence},
    store,
};

async fn reload(state: &AppState, auth: &AuthUser) -> Result<Json<MyPresence>, ApiError> {
    let user = store::users::by_id(&state.db, &auth.user.id)
        .await?
        .ok_or(ApiError::Unauthorized { code: "auth.token_invalid" })?;
    Ok(Json(presence::my_view(state, &user, &auth.device_id)))
}

/// My presence as I see it (chosen status, effective status, this device's idle flag).
#[utoipa::path(get, path = "/api/v1/users/me/presence", security(("bearer" = [])), responses((status = 200, body = MyPresence)))]
pub async fn get_mine(State(state): State<AppState>, auth: AuthUser) -> Result<Json<MyPresence>, ApiError> {
    reload(&state, &auth).await
}

#[derive(Deserialize, ToSchema)]
pub struct PresenceRequest {
    /// online | dnd | invisible (for the account) or idle (this device only, set by the client after
    /// inactivity; `online` makes the device active again).
    pub status: Option<String>,
    /// Absent: unchanged; null: removed.
    #[serde(default, deserialize_with = "crate::serde_with_double_option::deserialize")]
    #[schema(value_type = Option<CustomStatus>)]
    pub custom_status: Option<Option<CustomStatus>>,
}

/// Set my status and/or custom status. Others get `presence.update` (batched, at most one per second).
#[utoipa::path(put, path = "/api/v1/users/me/presence", security(("bearer" = [])), request_body = PresenceRequest,
    responses((status = 200, body = MyPresence), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_mine(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<PresenceRequest>,
) -> Result<Json<MyPresence>, ApiError> {
    state.presence_limiter.check_all(&[format!("presence:{}", auth.device_id)])?;
    let status = req.status.as_deref().map(presence::validate_status).transpose()?;
    let custom = match &req.custom_status {
        None => None,
        Some(None) => Some(None),
        Some(Some(c)) => Some(Some(presence::validate_custom(c)?)),
    };
    if let Some(status) = status {
        state.presence.set_idle(&auth.user.id, &auth.device_id, status == "idle");
    }
    let chosen = status.filter(|s| *s != "idle");
    presence::store_choice(&state, &auth.user.id, chosen, custom.as_ref().map(Option::as_ref)).await?;
    presence::changed(&state, &auth.user.id);
    reload(&state, &auth).await
}

/// Set what I am doing on this device ("Playing …"). Hidden from others with `hide_activity`.
#[utoipa::path(put, path = "/api/v1/users/me/activity", security(("bearer" = [])), request_body = Activity,
    responses((status = 200, body = MyPresence), (status = 400, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_activity(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<Activity>,
) -> Result<Json<MyPresence>, ApiError> {
    state.presence_limiter.check_all(&[format!("presence:{}", auth.device_id)])?;
    let activity = presence::validate_activity(&req)?;
    state.presence.set_activity(&auth.user.id, &auth.device_id, Some(activity));
    presence::changed(&state, &auth.user.id);
    reload(&state, &auth).await
}

/// Clear the activity of this device.
#[utoipa::path(delete, path = "/api/v1/users/me/activity", security(("bearer" = [])), responses((status = 200, body = MyPresence)))]
pub async fn delete_activity(State(state): State<AppState>, auth: AuthUser) -> Result<Json<MyPresence>, ApiError> {
    state.presence.set_activity(&auth.user.id, &auth.device_id, None);
    presence::changed(&state, &auth.user.id);
    reload(&state, &auth).await
}

/// Presences of the users on this node I may see and who are not offline (friends, members of shared
/// rooms that do not hide their presence there, members of shared DMs). Everyone else is offline.
#[utoipa::path(get, path = "/api/v1/presence", security(("bearer" = [])), responses((status = 200, body = Vec<Presence>)))]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<Presence>>, ApiError> {
    Ok(Json(presence::visible_to(&state, &auth.user.id).await?))
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoomPresenceSetting {
    /// Hide my presence from the members of this room (friends and other shared rooms still see it).
    pub hidden: bool,
}

/// My presence setting in one room.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/presence", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = RoomPresenceSetting), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_room_setting(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<RoomPresenceSetting>, ApiError> {
    member(&state, &auth, &room_id).await?;
    Ok(Json(RoomPresenceSetting { hidden: presence::room_hidden(&state, &room_id, &auth.user.id).await? }))
}

/// Hide or show my presence in one room.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/presence", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body = RoomPresenceSetting,
    responses((status = 200, body = RoomPresenceSetting), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_room_setting(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<RoomPresenceSetting>,
) -> Result<Json<RoomPresenceSetting>, ApiError> {
    member(&state, &auth, &room_id).await?;
    // Each toggle fans out to the whole room.
    state.presence_limiter.check_all(&[format!("presence-room:{}", auth.user.id)])?;
    presence::set_room_hidden(&state, &room_id, &auth.user.id, req.hidden).await?;
    // The room's members now see the presence (or no longer do): one update for everyone.
    if req.hidden {
        let mut members = store::rooms::member_ids(&state.db, &room_id).await?;
        members.retain(|m| *m != auth.user.id && crate::presence::is_online(&state, m));
        let user = store::users::by_id(&state.db, &auth.user.id).await?;
        if let Some(user) = user {
            let mut offline = presence::view(&state, &user, false);
            offline.status = "offline".into();
            offline.custom_status = None;
            offline.activity = None;
            // Members who still see the user through a friendship or another room get the real state
            // with the next update; a stale "offline" is the safe side.
            state.hub.users(members, "presence.update", &offline);
        }
        state.presence.forget_public(&auth.user.id);
    }
    presence::changed(&state, &auth.user.id);
    Ok(Json(RoomPresenceSetting { hidden: req.hidden }))
}

async fn member(state: &AppState, auth: &AuthUser, room_id: &str) -> Result<(), ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    if access.member.is_none() {
        return Err(ApiError::Forbidden { code: "room.not_member", detail: "Members only".into() });
    }
    Ok(())
}
