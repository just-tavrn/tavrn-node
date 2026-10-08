// SPDX-License-Identifier: AGPL-3.0-only
//! Calls in DMs and group DMs (protocol/VOICE.md §11): start, join, leave, decline, state.
//! The logic lives in `crate::calls`; these handlers check membership and issue the LiveKit tokens.

use std::time::Instant;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    calls::{self, CallState},
    error::{ApiError, ApiJson, ProblemDetails},
    routes::voice::{VideoLimits, VoiceLimits, VoiceStatePatch, ice_aliases},
    store,
    voice::{
        self,
        state::{SelfPatch, VoiceParticipant, Who},
        token::{self, Sources},
    },
};

fn disabled() -> ApiError {
    ApiError::Unavailable { code: "voice.disabled", detail: "Voice channels are switched off on this node".into() }
}

/// A DM or group DM the requester has accepted, on a node with voice.
async fn call_conversation(state: &AppState, conversation_id: &str, auth: &AuthUser) -> Result<(Conv, bool), ApiError> {
    if !state.config.voice_enabled {
        return Err(disabled());
    }
    let conv = access::conversation(state, conversation_id, &auth.user).await?;
    let group = match &conv.kind {
        ConvKind::Direct { row, .. } => row.kind == "group",
        ConvKind::Channel { .. } => {
            return Err(ApiError::BadRequest {
                code: "call.not_direct",
                detail: "Calls exist only in direct messages and groups; rooms have voice channels".into(),
            });
        }
    };
    if conv.is_request_for(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "call.request_pending",
            detail: "Accept the message request first".into(),
        });
    }
    Ok((conv, group))
}

/// What a call participant may publish: the node policies (DMs have no roles).
fn sources(state: &AppState) -> Sources {
    Sources {
        microphone: true,
        camera: state.config.camera_enabled,
        screen: state.config.screenshare_enabled,
        ..Default::default()
    }
}

#[derive(Serialize, ToSchema)]
pub struct CallJoin {
    /// LiveKit server URL (`wss://<domain>`); LiveKit SDKs append `/rtc` themselves.
    pub url: String,
    /// LiveKit access token (10 minutes) for room `call:<conversation id>`.
    pub token: String,
    pub expires_at: String,
    /// LiveKit room name `call:<conversation id>`.
    pub room: String,
    /// This device's participant identity `<user address>/<device id>` (= its MLS leaf identity).
    pub identity: String,
    pub conversation_id: String,
    /// Current MLS epoch of the conversation's group: derive the frame key from it (ENCRYPTION.md §5a).
    pub epoch: Option<i64>,
    pub limits: VoiceLimits,
    /// Participants already connected.
    pub participants: Vec<VoiceParticipant>,
    pub reconnect_grace_secs: u64,
    /// Extra addresses of the media server the client adds as ICE candidates (VOICE.md §10.2).
    pub ice_aliases: Vec<String>,
    pub call: CallState,
}

async fn join_inner(state: &AppState, auth: &AuthUser, conversation_id: &str) -> Result<CallJoin, ApiError> {
    let who = Who {
        user: auth.user.address(),
        user_id: auth.user.id.clone(),
        device_id: auth.public_device_id().to_string(),
        server_muted: false,
    };
    let identity = who.identity();
    let key = calls::key(conversation_id);
    let config = &state.config;
    let reserved = {
        let mut participants = state.calls.participants();
        if participants.occupancy(&key, &auth.user.id, Instant::now()) >= config.voice_max_participants as usize {
            return Err(ApiError::Conflict {
                code: "call.full",
                detail: format!("The call is full (at most {} participants)", config.voice_max_participants),
                meta: serde_json::json!({ "user_limit": config.voice_max_participants }),
            });
        }
        participants.reserve(&key, &who, Instant::now())
    };
    // One call session per user: another device of the same user in this call is replaced.
    for (old_key, old_identity) in &reserved.displaced {
        voice::remove_from_livekit(state, old_key, old_identity).await;
    }
    calls::answer(state, conversation_id, &auth.user).await;
    let api_key = state.voice.api_key().ok_or_else(disabled)?;
    let room = calls::room_name(conversation_id);
    let jwt =
        token::issue(&api_key.key, &api_key.secret, &identity, token::grants(&room, sources(state)), token::TOKEN_TTL)?;
    let epoch = store::e2ee::group_epoch(&state.db, conversation_id).await?;
    let call = state.calls.snapshot(conversation_id);
    let s = sources(state);
    // Stream and camera caps of the user's entitlements (DMs have no room).
    let ent = crate::entitlements::Entitlements::load(state, Some(&auth.user), None).await?;
    Ok(CallJoin {
        url: config.public_url().replacen("http", "ws", 1),
        token: jwt,
        expires_at: crate::util::in_seconds(token::TOKEN_TTL.as_secs() as i64),
        room,
        identity,
        conversation_id: conversation_id.to_string(),
        epoch,
        limits: VoiceLimits {
            audio_bitrate_kbps: i64::from(config.call_audio_bitrate_kbps()),
            audio_fec: crate::routes::voice::AUDIO_FEC,
            screenshare: VideoLimits {
                enabled: s.screen,
                max_resolution: config.screenshare_max_resolution.clone(),
                max_fps: config.screenshare_max_fps,
            },
            camera: VideoLimits {
                enabled: s.camera,
                max_resolution: config.camera_max_resolution.clone(),
                max_fps: config.camera_max_fps,
            },
            stream_max_height: ent.get(crate::entitlements::STREAM_MAX_HEIGHT),
            stream_max_fps: ent.get(crate::entitlements::STREAM_MAX_FPS),
            camera_max_height: ent.get(crate::entitlements::CAMERA_MAX_HEIGHT),
        },
        participants: call.participants.clone(),
        reconnect_grace_secs: config.voice_reconnect_grace_secs,
        ice_aliases: ice_aliases(&state.voice),
        call,
    })
}

/// Start a call (or join the running one): rings every other member (`call.ring`, on other nodes through
/// their home node) and returns a LiveKit token. Unanswered calls end after 45 seconds as missed. At most
/// 10 new calls per user and 10 minutes (`429`; development nodes 1000).
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/call/start", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = CallJoin), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn start(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<CallJoin>, ApiError> {
    let (conv, group) = call_conversation(&state, &conversation_id, &auth).await?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    if !state.calls.is_active(&conv.id) {
        state.calls.ring_limiter.check_all(&[format!("call:{}", auth.user.id)])?;
    }
    if calls::start(&state, &conv.id, &auth.user, group).await? {
        tracing::info!(conversation = %conv.id, group, "call started");
    }
    Ok(Json(join_inner(&state, &auth, &conv.id).await?))
}

/// Join (answer) a running call.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/call/join", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = CallJoin), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn join(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<CallJoin>, ApiError> {
    let (conv, _) = call_conversation(&state, &conversation_id, &auth).await?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    if !state.calls.is_active(&conv.id) {
        return Err(calls::not_active());
    }
    Ok(Json(join_inner(&state, &auth, &conv.id).await?))
}

/// Leave the call (this device). The last one to leave ends it.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/call/leave", security(("bearer" = [])),
    params(("conversation_id" = String, Path)), responses((status = 204), (status = 404, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn leave(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (conv, _) = call_conversation(&state, &conversation_id, &auth).await?;
    let key = calls::key(&conv.id);
    let identity = voice::identity(&auth.user.address(), auth.public_device_id());
    let was_there = !state.calls.participants().identities_of(&key, &auth.user.id).is_empty();
    state.calls.participants().remove(&key, &identity);
    voice::remove_from_livekit(&state, &key, &identity).await;
    if was_there {
        calls::after_change(&state, &conv.id).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Decline a ringing call. In a DM the call ends (`system.call.missed`); in a group only this user stops
/// ringing.
#[utoipa::path(post, path = "/api/v1/conversations/{conversation_id}/call/decline", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn decline(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let (conv, _) = call_conversation(&state, &conversation_id, &auth).await?;
    calls::decline(&state, &conv.id, &auth.user).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The conversation's call: running or not, who started it, who is connected and who is still ringing.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/call", security(("bearer" = [])),
    params(("conversation_id" = String, Path)),
    responses((status = 200, body = CallState), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn get_call(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<CallState>, ApiError> {
    let (conv, _) = call_conversation(&state, &conversation_id, &auth).await?;
    Ok(Json(state.calls.snapshot(&conv.id)))
}

/// Change this device's own state in the call (mute, deafen, screen share, camera).
#[utoipa::path(patch, path = "/api/v1/conversations/{conversation_id}/call/state", security(("bearer" = [])),
    params(("conversation_id" = String, Path)), request_body = VoiceStatePatch,
    responses((status = 200, body = CallState), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update_state(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    ApiJson(req): ApiJson<VoiceStatePatch>,
) -> Result<Json<CallState>, ApiError> {
    let (conv, _) = call_conversation(&state, &conversation_id, &auth).await?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    let allowed = sources(&state);
    if req.streaming == Some(true) && !allowed.screen {
        return Err(ApiError::Forbidden {
            code: "voice.stream_forbidden",
            detail: "Screen sharing is not allowed here".into(),
        });
    }
    if req.camera == Some(true) && !allowed.camera {
        return Err(ApiError::Forbidden {
            code: "voice.camera_forbidden",
            detail: "The camera is not allowed here".into(),
        });
    }
    let key = calls::key(&conv.id);
    let identity = voice::identity(&auth.user.address(), auth.public_device_id());
    let patch = SelfPatch { muted: req.muted, deafened: req.deafened, streaming: req.streaming, camera: req.camera };
    let changed = state.calls.participants().update_self(&key, &identity, patch).ok_or_else(|| ApiError::Conflict {
        code: "voice.not_connected",
        detail: "You are not connected to this call".into(),
        meta: serde_json::Value::Null,
    })?;
    if changed {
        calls::publish(&state, &conv.id).await;
    }
    Ok(Json(state.calls.snapshot(&conv.id)))
}
