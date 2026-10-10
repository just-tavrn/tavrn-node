// SPDX-License-Identifier: AGPL-3.0-only
//! Voice channels (protocol/VOICE.md): join tokens, own state, moderator actions (also the mass move),
//! the connection test, LiveKit webhooks, soundboard clips.

use std::time::Instant;

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    access::{self, RoomAccess},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiJson, ProblemDetails},
    models::{ChannelRow, UserRow},
    permissions::{self as p, Perms},
    store,
    validate::{self, bad},
    voice::{
        self, VoiceChannelState,
        state::{ChannelKey, SelfPatch, VoiceParticipant, Who},
        token::{self, Sources},
    },
};

fn disabled() -> ApiError {
    ApiError::Unavailable { code: "voice.disabled", detail: "Voice channels are disabled on this node".into() }
}

fn require_enabled(state: &AppState) -> Result<(), ApiError> {
    if state.config.voice_enabled { Ok(()) } else { Err(disabled()) }
}

/// A voice channel with the requester's room access and channel permissions.
struct VoiceChannel {
    access: RoomAccess,
    channel: ChannelRow,
    perms: Perms,
}

impl VoiceChannel {
    fn key(&self) -> ChannelKey {
        (self.channel.room_id.clone(), self.channel.id.clone())
    }

    fn has(&self, bits: Perms) -> bool {
        p::has(self.perms, bits)
    }
}

/// Loads a voice channel for a room member (node admins who are not members cannot join voice: they are not
/// entitled to the channel's MLS group).
async fn voice_channel(
    state: &AppState,
    room_id: &str,
    channel_id: &str,
    user: &UserRow,
) -> Result<VoiceChannel, ApiError> {
    require_enabled(state)?;
    let access = access::room_access(state, room_id, user).await?;
    if access.member.is_none() {
        return Err(ApiError::Forbidden {
            code: "room.not_member",
            detail: "You are not a member of this room".into(),
        });
    }
    let channel = access::channel_in_room(state, room_id, channel_id).await?;
    if channel.kind != "voice" {
        return Err(bad("voice.not_voice_channel", "This is not a voice channel"));
    }
    access::require_age(&access, &channel)?;
    let perms = access::channel_perms(state, &access, &channel, &user.id).await?;
    Ok(VoiceChannel { access, channel, perms })
}

/// What `user` may publish in `vc` under the node policies.
fn sources(state: &AppState, vc: &VoiceChannel, server_muted: bool) -> Sources {
    let c = &state.config;
    Sources {
        microphone: vc.has(p::SPEAK) && !server_muted,
        camera: c.camera_enabled && vc.has(p::USE_CAMERA),
        screen: c.screenshare_enabled && vc.has(p::STREAM),
        data: vc.has(p::USE_SOUNDBOARD),
        priority: vc.has(p::PRIORITY_SPEAKER),
    }
}

#[derive(Serialize, ToSchema)]
pub struct VideoLimits {
    /// Allowed for this participant (node policy and permission).
    pub enabled: bool,
    /// `360p` … `4k`.
    pub max_resolution: String,
    pub max_fps: u32,
}

/// LiveKit's Opus codec always offers in-band FEC (`useinbandfec=1`); announced so clients that set up Opus
/// themselves choose the same robustness.
pub const AUDIO_FEC: bool = true;

/// Quality limits the client applies to what it publishes.
#[derive(Serialize, ToSchema)]
pub struct VoiceLimits {
    /// Channel bitrate, capped by `TAVRN_VOICE_MAX_BITRATE_KBPS`.
    pub audio_bitrate_kbps: i64,
    /// Opus in-band forward error correction: the node's media server negotiates it (`useinbandfec=1`), so
    /// publishers encode with it and a lost packet is partly recovered from the next one. DTX stays on, RED
    /// stays off (end-to-end encryption).
    pub audio_fec: bool,
    pub screenshare: VideoLimits,
    pub camera: VideoLimits,
    /// Entitlement `stream.max_height` for this user in this room (pixels, 0 = only `screenshare`). Enforced
    /// by the client (soft limit: the SFU cannot cap a hostile client, ENTITLEMENTS.md §4).
    pub stream_max_height: i64,
    /// Entitlement `stream.max_fps` (0 = only `screenshare.max_fps`).
    pub stream_max_fps: i64,
    /// Entitlement `camera.max_height` (pixels, 0 = only `camera.max_resolution`).
    pub camera_max_height: i64,
}

#[derive(Serialize, ToSchema)]
pub struct VoiceJoin {
    /// LiveKit server URL (`wss://<domain>`); LiveKit SDKs append `/rtc` themselves.
    pub url: String,
    /// LiveKit access token (10 minutes) with exactly the allowed sources.
    pub token: String,
    pub expires_at: String,
    /// LiveKit room name `<room id>:<channel id>`.
    pub room: String,
    /// This device's participant identity `<user address>/<device id>` (= its MLS leaf identity).
    pub identity: String,
    pub room_id: String,
    pub channel_id: String,
    /// Current MLS epoch of the channel's group (null before the group exists): derive the frame key from it.
    pub epoch: Option<i64>,
    pub limits: VoiceLimits,
    /// Participants already connected.
    pub participants: Vec<VoiceParticipant>,
    /// How long the node keeps a dropped participant as `reconnecting` (`TAVRN_VOICE_RECONNECT_GRACE_SECS`):
    /// the client rejoins automatically within this time.
    pub reconnect_grace_secs: u64,
    /// Extra addresses of the media server the client adds as ICE candidates (`TAVRN_RTC_ADVERTISE_IPS`
    /// beyond one per address family, VOICE.md §10.2).
    pub ice_aliases: Vec<String>,
}

/// Join a voice channel: checks `connect` (or a moderator's move into this channel), the user limit and the node
/// policies and returns a LiveKit token.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/join", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    responses((status = 200, body = VoiceJoin), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn join(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<Json<VoiceJoin>, ApiError> {
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    if store::rooms::is_banned(&state.db, Some(&room_id), &auth.user.address(), &auth.user.domain).await? {
        return Err(ApiError::Forbidden { code: "room.banned", detail: "You are banned from this room".into() });
    }
    let key = vc.key();
    // A moderator's move into this channel entitles the join without `connect` (the open grant, or a rejoin of the
    // running moved participation); a timeout still refuses it.
    let timed_out = vc.access.member.as_ref().is_some_and(crate::models::MemberRow::is_timed_out);
    let moved = !timed_out && state.voice.participants().move_entitles(&key, &auth.user.id, Instant::now());
    if !vc.has(p::CONNECT) && !moved {
        return Err(ApiError::Forbidden {
            code: "voice.connect_forbidden",
            detail: "Missing permission: Join voice channel".into(),
        });
    }
    let server_muted = store::voice::server_muted(&state.db, &room_id, &auth.user.id).await?;
    let who = Who {
        user: auth.user.address(),
        user_id: auth.user.id.clone(),
        device_id: auth.public_device_id().to_string(),
        server_muted,
    };
    let identity = who.identity();
    let config = &state.config;
    let user_limit = usize::try_from(vc.channel.user_limit).unwrap_or(0);
    let node_limit = config.voice_max_participants as usize;
    // Entitlements: `voice.max_participants` of the room (0 = only the node's hard cap) and the
    // stream/camera caps the client applies.
    let ent = crate::entitlements::Entitlements::load(&state, Some(&auth.user), Some(&vc.access.room)).await?;
    let plan_limit = ent.limit(crate::entitlements::VOICE_MAX_PARTICIPANTS).map(|n| usize::try_from(n).unwrap_or(0));
    let reserved = {
        let mut participants = state.voice.participants();
        let occupancy = participants.occupancy(&key, &auth.user.id, Instant::now());
        if let Some(limit) = plan_limit.filter(|l| occupancy >= *l && *l < node_limit) {
            return Err(ApiError::Conflict {
                code: "voice.participant_limit",
                detail: format!("This voice channel allows at most {limit} participants"),
                meta: serde_json::json!({ "limit": limit }),
            });
        }
        // Members with `move_members` and moved members (the mover may fill a channel beyond its limit) may exceed it.
        let over_channel = user_limit > 0 && occupancy >= user_limit && !vc.has(p::MOVE_MEMBERS) && !moved;
        if over_channel || occupancy >= node_limit {
            let limit = if over_channel { user_limit } else { node_limit };
            return Err(ApiError::Conflict {
                code: "voice.channel_full",
                detail: format!("The voice channel is full (at most {limit} participants)"),
                meta: serde_json::json!({ "user_limit": limit }),
            });
        }
        let reserved = participants.reserve(&key, &who, Instant::now());
        participants.joined(&key, &auth.user.id);
        reserved
    };
    // One voice session per user: another device of this user is disconnected.
    for (old_key, old_identity) in &reserved.displaced {
        voice::remove_from_livekit(&state, old_key, old_identity).await;
    }
    voice::publish(&state, &reserved.changed).await;
    let sources = sources(&state, &vc, server_muted);
    let api_key = state.voice.api_key().ok_or_else(disabled)?;
    let room = voice::room_name(&key);
    let jwt = token::issue(&api_key.key, &api_key.secret, &identity, token::grants(&room, sources), token::TOKEN_TTL)?;
    let current = voice::channel_state(&state, &key).await;
    let max_bitrate = i64::from(config.voice_max_bitrate_kbps);
    Ok(Json(VoiceJoin {
        url: config.public_url().replacen("http", "ws", 1),
        token: jwt,
        expires_at: crate::util::in_seconds(token::TOKEN_TTL.as_secs() as i64),
        room,
        identity,
        room_id,
        channel_id,
        epoch: current.epoch,
        limits: VoiceLimits {
            audio_bitrate_kbps: vc.channel.bitrate_kbps.min(max_bitrate),
            audio_fec: AUDIO_FEC,
            screenshare: VideoLimits {
                enabled: sources.screen,
                max_resolution: config.screenshare_max_resolution.clone(),
                max_fps: config.screenshare_max_fps,
            },
            camera: VideoLimits {
                enabled: sources.camera,
                max_resolution: config.camera_max_resolution.clone(),
                max_fps: config.camera_max_fps,
            },
            stream_max_height: ent.get(crate::entitlements::STREAM_MAX_HEIGHT),
            stream_max_fps: ent.get(crate::entitlements::STREAM_MAX_FPS),
            camera_max_height: ent.get(crate::entitlements::CAMERA_MAX_HEIGHT),
        },
        participants: current.participants,
        reconnect_grace_secs: config.voice_reconnect_grace_secs,
        ice_aliases: ice_aliases(&state.voice),
    }))
}

/// Leave a voice channel (this device). Always allowed; disconnects the device in LiveKit as well.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/leave", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    responses((status = 204), (status = 503, body = ProblemDetails)))]
pub async fn leave(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    validate::ulid("room_id", &room_id)?;
    validate::ulid("channel_id", &channel_id)?;
    let key = (room_id, channel_id);
    let identity = voice::identity(&auth.user.address(), auth.public_device_id());
    let visible = state.voice.participants().remove(&key, &identity);
    voice::remove_from_livekit(&state, &key, &identity).await;
    if visible {
        voice::publish(&state, &[key]).await;
    } else {
        // Leaving ends a moved participation even before it was visible.
        voice::sync_moved(&state).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceStatePatch {
    pub muted: Option<bool>,
    pub deafened: Option<bool>,
    /// Screen share running (needs `stream` and the node policy).
    pub streaming: Option<bool>,
    /// Camera running (needs `use_camera` and the node policy).
    pub camera: Option<bool>,
}

/// Change this device's own voice state (mute, deafen, streaming, camera).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/state", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = VoiceStatePatch,
    responses((status = 200, body = VoiceChannelState), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update_state(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    ApiJson(req): ApiJson<VoiceStatePatch>,
) -> Result<Json<VoiceChannelState>, ApiError> {
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    let key = vc.key();
    let identity = voice::identity(&auth.user.address(), auth.public_device_id());
    let Some(current) = state.voice.participants().get(&key, &identity) else {
        return Err(not_connected());
    };
    if req.muted == Some(false) && current.server_muted {
        return Err(ApiError::Forbidden { code: "voice.server_muted", detail: "A moderator has muted you".into() });
    }
    let allowed = sources(&state, &vc, current.server_muted);
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
    let patch = SelfPatch { muted: req.muted, deafened: req.deafened, streaming: req.streaming, camera: req.camera };
    let changed = state.voice.participants().update_self(&key, &identity, patch).ok_or_else(not_connected)?;
    if changed {
        voice::publish(&state, std::slice::from_ref(&key)).await;
    }
    Ok(Json(voice::channel_state(&state, &key).await))
}

fn not_connected() -> ApiError {
    ApiError::Conflict {
        code: "voice.not_connected",
        detail: "You are not connected to this voice channel".into(),
        meta: serde_json::Value::Null,
    }
}

#[derive(Serialize, ToSchema)]
pub struct RoomVoiceStates {
    /// Voice channels with at least one participant that the requester can see.
    pub items: Vec<VoiceChannelState>,
}

/// Who is in which voice channel of a room (initial state; changes arrive as `voice.state`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/voice", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = RoomVoiceStates), (status = 403, body = ProblemDetails)))]
pub async fn room_states(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<RoomVoiceStates>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    let items = visible_states(&state, &access, &room_id, &auth.user.id).await?;
    Ok(Json(RoomVoiceStates { items }))
}

/// The voice channels of `room_id` with participants that the user of `access` can view (`view_channel`, which
/// includes a moved participation), in the shape of `voice.state`.
async fn visible_states(
    state: &AppState,
    access: &RoomAccess,
    room_id: &str,
    user_id: &str,
) -> Result<Vec<VoiceChannelState>, ApiError> {
    let keys = state.voice.participants().active_channels(room_id);
    let mut items = Vec::new();
    for key in keys {
        let Ok(channel) = access::channel_in_room(state, room_id, &key.1).await else { continue };
        let perms = access::channel_perms(state, access, &channel, user_id).await?;
        if p::has(perms, p::VIEW_CHANNEL) {
            items.push(voice::channel_state(state, &key).await);
        }
    }
    Ok(items)
}

#[derive(Serialize, ToSchema)]
pub struct MyVoiceRoom {
    pub room_id: String,
    /// Voice channels of the room with at least one participant that the requester can view.
    pub channels: Vec<VoiceChannelState>,
}

#[derive(Serialize, ToSchema)]
pub struct MyVoiceStates {
    /// Rooms of this node the requester is a member of with at least one such channel.
    pub rooms: Vec<MyVoiceRoom>,
}

/// Who is in which voice channel of every room the requester is a member of.
///
/// The initial state of a room list in one request instead of one per room (changes arrive as `voice.state`): like
/// `GET /rooms/{room_id}/voice` for every room of this node the requester is a member of, only channels with
/// participants the requester can view, rooms without such a channel left out. Rooms of other nodes are asked there.
#[utoipa::path(get, path = "/api/v1/users/me/voice", security(("bearer" = [])),
    responses((status = 200, body = MyVoiceStates)))]
pub async fn my_states(State(state): State<AppState>, auth: AuthUser) -> Result<Json<MyVoiceStates>, ApiError> {
    if !state.config.voice_enabled {
        return Ok(Json(MyVoiceStates { rooms: Vec::new() }));
    }
    // Only rooms with somebody in voice are looked at (few); membership is checked per room.
    let room_ids: std::collections::BTreeSet<String> =
        state.voice.participants().keys().into_iter().map(|(room_id, _)| room_id).collect();
    let mut rooms = Vec::new();
    for room_id in room_ids {
        if store::rooms::member(&state.db, &room_id, &auth.user.id).await?.is_none() {
            continue;
        }
        let access = match access::room_access(&state, &room_id, &auth.user).await {
            Ok(a) => a,
            // Left or deleted in between.
            Err(ApiError::Forbidden { .. } | ApiError::NotFound { .. }) => continue,
            Err(e) => return Err(e),
        };
        let channels = visible_states(&state, &access, &room_id, &auth.user.id).await?;
        if !channels.is_empty() {
            rooms.push(MyVoiceRoom { room_id, channels });
        }
    }
    Ok(Json(MyVoiceStates { rooms }))
}

// ---------------------------------------------------------------- moderator actions

/// Target of a moderator action: a room member addressed by user address, outranked by the moderator.
async fn target(state: &AppState, vc: &VoiceChannel, address: &str) -> Result<UserRow, ApiError> {
    let not_found = || access::not_found("Member", "member.not_found");
    let (username, domain) = crate::util::parse_address(address).ok_or_else(not_found)?;
    let user = store::users::by_username(&state.db, username, domain).await?.ok_or_else(not_found)?;
    store::rooms::member(&state.db, &vc.access.room.id, &user.id).await?.ok_or_else(not_found)?;
    crate::routes::rooms::moderation_target(state, &vc.access, &user.id).await
}

#[derive(Deserialize, ToSchema)]
pub struct MuteRequest {
    /// `true` mutes, `false` lifts the server mute.
    pub muted: bool,
}

/// Server mute of a member in the whole room (`mute_members`): the member loses the microphone grant
/// (also in LiveKit right away) until a moderator unmutes them.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/mute", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("address" = String, Path, description = "User address, e.g. bob@node.example")),
    request_body = MuteRequest, responses((status = 200, body = VoiceChannelState), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn mute_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, address)): Path<(String, String, String)>,
    ApiJson(req): ApiJson<MuteRequest>,
) -> Result<Json<VoiceChannelState>, ApiError> {
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    if !vc.has(p::MUTE_MEMBERS) {
        return Err(ApiError::Forbidden {
            code: "voice.mute_forbidden",
            detail: "Missing permission: Mute members".into(),
        });
    }
    let target = target(&state, &vc, &address).await?;
    store::voice::set_server_muted(&state.db, &room_id, &target.id, req.muted).await?;
    let affected = state.voice.participants().set_server_muted(&room_id, &target.id, req.muted);
    let mut changed = Vec::new();
    for (key, identity, visible) in affected {
        let Ok(channel) = access::channel_in_room(&state, &room_id, &key.1).await else { continue };
        if let Ok(target_access) = access::room_access(&state, &room_id, &target).await {
            let perms = access::channel_perms(&state, &target_access, &channel, &target.id).await?;
            let target_vc = VoiceChannel { access: target_access, channel, perms };
            voice::update_permission(&state, &key, &identity, sources(&state, &target_vc, req.muted)).await;
        }
        if visible && !changed.contains(&key) {
            changed.push(key);
        }
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        if req.muted { "voice.mute" } else { "voice.unmute" },
        &target.address(),
        "",
        serde_json::json!({ "channel_id": channel_id }),
    )
    .await?;
    voice::publish(&state, &changed).await;
    Ok(Json(voice::channel_state(&state, &vc.key()).await))
}

fn require_move(vc: &VoiceChannel) -> Result<(), ApiError> {
    if vc.has(p::MOVE_MEMBERS) {
        Ok(())
    } else {
        Err(ApiError::Forbidden {
            code: "voice.move_forbidden",
            detail: "Missing permission: Move or disconnect members".into(),
        })
    }
}

/// A moderator moved `user_id` into `key`: the grant of the user's next join there, announced before the client is
/// told (`voice.move`), so the member's connections get the channel first (`channel.create`).
async fn grant_move(state: &AppState, key: &ChannelKey, user_id: &str) {
    state.voice.participants().grant_move(key, user_id, Instant::now());
    voice::sync_moved(state).await;
}

/// Removes every device of `target` from `key` (LiveKit and state); `false` if none was there.
async fn disconnect_devices(state: &AppState, key: &ChannelKey, target: &UserRow) -> bool {
    let identities = state.voice.participants().identities_of(key, &target.id);
    if identities.is_empty() {
        return false;
    }
    let mut visible = false;
    for identity in &identities {
        visible |= state.voice.participants().remove(key, identity);
        voice::remove_from_livekit(state, key, identity).await;
    }
    if visible {
        voice::publish(state, std::slice::from_ref(key)).await;
    }
    true
}

/// Disconnect a member from the voice channel (`move_members`).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/disconnect", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("address" = String, Path)),
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn disconnect_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, address)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    require_move(&vc)?;
    let target = target(&state, &vc, &address).await?;
    if !disconnect_devices(&state, &vc.key(), &target).await {
        return Err(ApiError::NotFound { code: "voice.not_connected", what: "Member connection".into() });
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "voice.disconnect",
        &target.address(),
        "",
        serde_json::json!({ "channel_id": channel_id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct MoveRequest {
    /// Target voice channel in the same room.
    pub channel_id: String,
}

/// Move a member to another voice channel (`move_members` in both channels). The member needs no permission in
/// the target: the move grants their next join there and, while that participation lasts, a view of the channel
/// (VOICE.md §7 "Moved participations"); only the target's age gate holds. The node disconnects the member here and
/// sends `voice.move` to the member's devices, whose client then joins the target channel (a new token and frame
/// key: every channel has its own MLS group).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/voice/members/{address}/move", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("address" = String, Path)), request_body = MoveRequest,
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn move_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, address)): Path<(String, String, String)>,
    ApiJson(req): ApiJson<MoveRequest>,
) -> Result<StatusCode, ApiError> {
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    require_move(&vc)?;
    validate::ulid("channel_id", &req.channel_id)?;
    if req.channel_id == channel_id {
        return Err(bad("voice.same_channel", "The member is already in this channel"));
    }
    let to = voice_channel(&state, &room_id, &req.channel_id, &auth.user).await?;
    require_move(&to)?;
    let target = target(&state, &vc, &address).await?;
    let target_access = access::room_access(&state, &room_id, &target).await?;
    if !access::age_passes(&target_access, &to.channel) {
        return Err(ApiError::Forbidden {
            code: "voice.target_forbidden",
            detail: "The member is below the target channel's age gate".into(),
        });
    }
    if !disconnect_devices(&state, &vc.key(), &target).await {
        return Err(ApiError::NotFound { code: "voice.not_connected", what: "Member connection".into() });
    }
    grant_move(&state, &to.key(), &target.id).await;
    state.hub.users(
        vec![target.id.clone()],
        "voice.move",
        serde_json::json!({ "room_id": room_id, "from_channel_id": channel_id, "channel_id": req.channel_id, "user_id": target.id }),
    );
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "voice.move",
        &target.address(),
        "",
        serde_json::json!({ "from_channel_id": channel_id, "channel_id": req.channel_id }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveAllRequest {
    /// Move only the participants of this voice channel; absent = everybody in any voice channel of the room.
    pub from_channel_id: Option<String>,
    /// Target voice channel in the same room.
    pub to_channel_id: String,
}

#[derive(Serialize, ToSchema)]
pub struct MoveSkipped {
    /// User address.
    pub user: String,
    /// `channel_full` (the target's user limit), `target_forbidden` (below the target's age gate),
    /// `outranked` (owner, node admin or an equal or higher role) or `move_forbidden` (no `move_members`
    /// in the participant's channel).
    pub reason: String,
}

#[derive(Serialize, ToSchema)]
pub struct MoveAllResult {
    /// Addresses of the moved members (they get `voice.move` and rejoin in the target).
    pub moved: Vec<String>,
    /// Members that stayed, with the reason.
    pub skipped: Vec<MoveSkipped>,
}

/// Mass move: everybody in a voice channel of the room (or only in `from_channel_id`)
/// to `to_channel_id`, needs `move_members` in the target and in every source channel. The moved members need no
/// permission in the target (like `…/move`); the target's age gate and user limit hold: members beyond the limit
/// stay and are reported as `channel_full` (a partial result, still `200`).
/// One audit entry `voice.move_all`.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/voice/move-all", security(("bearer" = [])),
    params(("room_id" = String, Path)), request_body = MoveAllRequest,
    responses((status = 200, body = MoveAllResult), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 404, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn move_all(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    ApiJson(req): ApiJson<MoveAllRequest>,
) -> Result<Json<MoveAllResult>, ApiError> {
    validate::ulid("to_channel_id", &req.to_channel_id)?;
    let to = voice_channel(&state, &room_id, &req.to_channel_id, &auth.user).await?;
    require_move(&to)?;
    let sources: Vec<ChannelKey> = match &req.from_channel_id {
        Some(from) => {
            validate::ulid("from_channel_id", from)?;
            if *from == req.to_channel_id {
                return Err(bad("voice.same_channel", "Source and target channel are the same"));
            }
            let vc = voice_channel(&state, &room_id, from, &auth.user).await?;
            require_move(&vc)?;
            vec![vc.key()]
        }
        None => {
            state.voice.participants().active_channels(&room_id).into_iter().filter(|k| k.1 != to.channel.id).collect()
        }
    };
    let now = Instant::now();
    let limit = usize::try_from(to.channel.user_limit).unwrap_or(0);
    let node_limit = state.config.voice_max_participants as usize;
    let occupancy = state.voice.participants().occupancy(&to.key(), "", now);
    let mut room_left = if limit > 0 { limit.min(node_limit) } else { node_limit }.saturating_sub(occupancy);
    let mut moved = Vec::new();
    let mut skipped = Vec::new();
    for key in sources {
        let participants = state.voice.participants().participants(&key);
        if participants.is_empty() {
            continue;
        }
        let (visible, allowed) = match voice_channel(&state, &room_id, &key.1, &auth.user).await {
            Ok(vc) => (vc.has(p::VIEW_CHANNEL), vc.has(p::MOVE_MEMBERS)),
            Err(_) => (false, false),
        };
        // Who sits in a channel the mover cannot see stays hidden (like `GET /rooms/{id}/voice`).
        if !visible {
            continue;
        }
        let mut seen = Vec::new();
        for participant in participants {
            if seen.contains(&participant.user_id) {
                continue;
            }
            seen.push(participant.user_id.clone());
            let skip = |reason: &str| MoveSkipped { user: participant.user.clone(), reason: reason.into() };
            if !allowed {
                skipped.push(skip("move_forbidden"));
                continue;
            }
            let target = if participant.user_id == auth.user.id {
                auth.user.clone()
            } else {
                match crate::routes::rooms::moderation_target(&state, &to.access, &participant.user_id).await {
                    Ok(u) => u,
                    Err(ApiError::Forbidden { .. } | ApiError::NotFound { .. }) => {
                        skipped.push(skip("outranked"));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            };
            let below_gate = match access::room_access(&state, &room_id, &target).await {
                Ok(a) => !access::age_passes(&a, &to.channel),
                Err(_) => true,
            };
            if below_gate {
                skipped.push(skip("target_forbidden"));
                continue;
            }
            if room_left == 0 {
                skipped.push(skip("channel_full"));
                continue;
            }
            if !disconnect_devices(&state, &key, &target).await {
                continue;
            }
            room_left -= 1;
            grant_move(&state, &to.key(), &target.id).await;
            state.hub.users(
                vec![target.id.clone()],
                "voice.move",
                serde_json::json!({ "room_id": room_id, "from_channel_id": key.1, "channel_id": req.to_channel_id, "user_id": target.id }),
            );
            moved.push(target.address());
        }
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "voice.move_all",
        &req.to_channel_id,
        "",
        serde_json::json!({ "from_channel_id": req.from_channel_id, "channel_id": req.to_channel_id, "moved": moved.len(), "skipped": skipped.len() }),
    )
    .await?;
    Ok(Json(MoveAllResult { moved, skipped }))
}

// ---------------------------------------------------------------- connection test

/// Extra addresses of the media server beyond LiveKit's `node_ip` (`TAVRN_RTC_ADVERTISE_IPS`, VOICE.md
/// §10.2): the client adds every host candidate of the node once more with each of them.
pub fn ice_aliases(voice: &voice::VoiceRuntime) -> Vec<String> {
    voice.advertise().aliases
}

/// How the node's media server can be reached, for the connection test (VOICE.md §10.4).
#[derive(Serialize, ToSchema)]
pub struct RtcInfo {
    /// `explicit` (configured addresses), `stun` (detected at start) or `local` (development: interface addresses).
    pub mode: String,
    /// The configured addresses announced by LiveKit (empty in the other modes).
    pub addresses: Vec<String>,
    /// Extra addresses the client adds as candidates.
    pub ice_aliases: Vec<String>,
    /// UDP media ports `from-to`.
    pub udp_ports: String,
    /// ICE over TCP (0 = off).
    pub tcp_port: u16,
    /// TURN over UDP is offered (`TAVRN_RTC_TURN_*`).
    pub turn_udp: bool,
    /// TURN over TLS (port 443 through the reverse proxy) is offered.
    pub turn_tls: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ConnectionTest {
    /// LiveKit server URL (`wss://<domain>`).
    pub url: String,
    /// Token (one minute) for an empty, hidden test room: subscribe only, nothing can be published.
    pub token: String,
    /// `test:<random id>`.
    pub room: String,
    pub identity: String,
    pub rtc: RtcInfo,
}

/// A throwaway LiveKit room for the connection test of the voice settings (VOICE.md §10.4): the client
/// connects with chosen candidate types (UDP per address, TCP, TURN) and reports which work. The token can
/// only join that empty room, hidden and without publishing; LiveKit drops the room a minute after use.
#[utoipa::path(post, path = "/api/v1/voice/test", security(("bearer" = [])),
    responses((status = 200, body = ConnectionTest), (status = 429, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn connection_test(State(state): State<AppState>, auth: AuthUser) -> Result<Json<ConnectionTest>, ApiError> {
    require_enabled(&state)?;
    state.voice_limiter.check_all(&[format!("voice:{}", auth.user.id)])?;
    let config = &state.config;
    let api_key = state.voice.api_key().ok_or_else(disabled)?;
    let room = voice::test_room_name();
    // A device id of its own per test connection: several probes run one after another.
    let identity = voice::identity(&auth.user.address(), &crate::util::ulid());
    let grants = livekit_api::access_token::VideoGrants {
        room_join: true,
        room: room.clone(),
        can_subscribe: Some(true),
        can_publish: Some(false),
        can_publish_data: Some(false),
        can_update_own_metadata: Some(false),
        hidden: true,
        ..Default::default()
    };
    let token = token::issue(&api_key.key, &api_key.secret, &identity, grants, std::time::Duration::from_secs(60))?;
    let advertise = state.voice.advertise();
    let mode = if advertise.node_ip.is_some() {
        "explicit"
    } else if advertise.stun {
        "stun"
    } else {
        "local"
    };
    Ok(Json(ConnectionTest {
        url: config.public_url().replacen("http", "ws", 1),
        token,
        room,
        identity,
        rtc: RtcInfo {
            mode: mode.into(),
            addresses: advertise.node_ip.map(|ip| ip.split(',').map(String::from).collect()).unwrap_or_default(),
            ice_aliases: advertise.aliases,
            udp_ports: config.rtc_udp_port_range.trim().to_string(),
            tcp_port: config.rtc_tcp_port,
            turn_udp: config.rtc_turn_enabled && config.rtc_turn_udp_port != 0,
            turn_tls: config.rtc_turn_enabled && config.rtc_turn_tls_port != 0,
        },
    }))
}

// ---------------------------------------------------------------- LiveKit webhook
/// Largest webhook body accepted (LiveKit's events are a few KB).
pub const WEBHOOK_BODY_LIMIT: usize = 64 * 1024;

/// LiveKit webhooks (`Authorization`: a JWT signed with the node's LiveKit secret, carrying the SHA-256 of
/// the body). Only LiveKit (on the same host) knows the secret.
#[utoipa::path(post, path = "/api/v1/voice/webhook", request_body(content = String, content_type = "application/webhook+json"),
    responses((status = 200), (status = 401, body = ProblemDetails), (status = 503, body = ProblemDetails)))]
pub async fn webhook(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Result<StatusCode, ApiError> {
    require_enabled(&state)?;
    let invalid = || ApiError::Unauthorized { code: "voice.webhook_invalid" };
    let auth = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).ok_or_else(invalid)?;
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    let body = std::str::from_utf8(&body).map_err(|_| invalid())?;
    let key = state.voice.api_key().ok_or_else(disabled)?;
    let receiver = livekit_api::webhooks::WebhookReceiver::new(livekit_api::access_token::TokenVerifier::with_api_key(
        &key.key,
        &key.secret,
    ));
    let event = receiver.receive(body, auth).map_err(|e| {
        tracing::warn!(error = %e, "LiveKit webhook rejected");
        invalid()
    })?;
    voice::handle_webhook(&state, event).await;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------- soundboard

/// Clips per room at most.
/// Default of `TAVRN_SOUNDS_MAX_PER_ROOM`; the limit is read through entitlements (`sounds.max_per_room`).
pub const SOUNDBOARD_MAX_PER_ROOM: i64 = 50;
pub const SOUNDBOARD_MAX_BYTES: usize = 1024 * 1024;
pub const SOUNDBOARD_MAX_DURATION_MS: i64 = 5000;

fn valid_sound_name(name: &str) -> bool {
    (1..=32).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

fn valid_audio_mime(mime: &str) -> bool {
    mime.strip_prefix("audio/").is_some_and(|sub| {
        !sub.is_empty()
            && sub.len() <= 64
            && sub.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-'))
    })
}

/// Soundboard clips of a room (members).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/soundboard", security(("bearer" = [])), params(("room_id" = String, Path)),
    responses((status = 200, body = Vec<store::voice::Sound>), (status = 403, body = ProblemDetails)))]
pub async fn list_sounds(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
) -> Result<Json<Vec<store::voice::Sound>>, ApiError> {
    access::room_access(&state, &room_id, &auth.user).await?;
    Ok(Json(store::voice::sounds(&state.db, &room_id).await?))
}

/// Upload a clip (`manage_emojis`, which covers "custom emojis and sounds"). Body = the audio file
/// (`Content-Type: audio/*`, at most 1 MiB), name in `Tavrn-Sound-Name` (1–32 characters, percent-encoded
/// UTF-8 allowed), duration in `Tavrn-Sound-Duration-Ms` (at most 5000; declared by the client, which
/// trims clips; the node cannot decode audio).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/soundboard", security(("bearer" = [])), params(("room_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "audio/ogg"),
    responses((status = 201, body = store::voice::Sound), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn create_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<store::voice::Sound>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_EMOJIS, "soundboard.manage_forbidden", "Manage emojis and sounds")?;
    let clip = clip_upload(&headers, &body)?;
    // `sounds.max_per_room` (entitlements; node default `TAVRN_SOUNDS_MAX_PER_ROOM`).
    let max = crate::entitlements::Entitlements::for_room(&state, &access.room)
        .await?
        .limit(crate::entitlements::SOUNDS_MAX_PER_ROOM);
    if let Some(max) = max
        && store::voice::sound_count(&state.db, &room_id).await? >= max
    {
        return Err(ApiError::Forbidden { code: "soundboard.limit", detail: format!("At most {max} sounds per room") });
    }
    let sound = store::voice::insert_sound(
        &state.db,
        store::voice::NewSound {
            room_id: &room_id,
            name: &clip.name,
            mime: &clip.mime,
            size: body.len() as i64,
            duration_ms: clip.duration_ms,
            uploader_id: &auth.user.id,
            emoji: clip.emoji.as_deref(),
        },
    )
    .await?;
    if let Err(e) = state.storage.write(&sound.id, &body).await {
        store::voice::delete_sound(&state.db, &room_id, &sound.id).await?;
        return Err(ApiError::Internal(e));
    }
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "soundboard.create",
        &sound.id,
        "",
        serde_json::json!({ "name": clip.name }),
    )
    .await?;
    state.hub.room(&room_id, "soundboard.update", serde_json::json!({ "room_id": room_id }));
    Ok((StatusCode::CREATED, Json(sound)))
}

/// A checked clip upload: name (`Tavrn-Sound-Name`), type, declared duration (`Tavrn-Sound-Duration-Ms`),
/// optional emoji (`Tavrn-Sound-Emoji`, percent-encoded) and size.
struct ClipUpload {
    name: String,
    mime: String,
    duration_ms: i64,
    emoji: Option<String>,
}

fn clip_upload(headers: &HeaderMap, body: &Bytes) -> Result<ClipUpload, ApiError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_string();
    let decoded = |name: &str| {
        let raw = header(name);
        percent_decode(&raw).unwrap_or(raw).trim().to_string()
    };
    let name = decoded("tavrn-sound-name");
    if !valid_sound_name(&name) {
        return Err(bad("soundboard.name_invalid", "Name: 1–32 characters"));
    }
    let mime = header(header::CONTENT_TYPE.as_str()).split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if !valid_audio_mime(&mime) {
        return Err(ApiError::UnsupportedMedia {
            code: "soundboard.type_not_allowed",
            detail: "Only audio files are allowed".into(),
        });
    }
    let duration_ms =
        header("tavrn-sound-duration-ms").parse::<i64>().ok().filter(|d| (1..=SOUNDBOARD_MAX_DURATION_MS).contains(d));
    let Some(duration_ms) = duration_ms else {
        return Err(bad("soundboard.too_long", "Sounds may be at most 5 seconds long (Tavrn-Sound-Duration-Ms)"));
    };
    let emoji = Some(decoded("tavrn-sound-emoji")).filter(|e| !e.is_empty());
    check_sound_emoji(emoji.as_deref())?;
    if body.is_empty() || body.len() > SOUNDBOARD_MAX_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "soundboard.too_large",
            detail: "Sounds may be at most 1 MB in size".into(),
            meta: serde_json::json!({ "max_bytes": SOUNDBOARD_MAX_BYTES }),
        });
    }
    Ok(ClipUpload { name, mime, duration_ms, emoji })
}

fn check_sound_emoji(emoji: Option<&str>) -> Result<(), ApiError> {
    match emoji {
        Some(e) if !crate::emoji::valid_sound_emoji(e) => {
            Err(bad("soundboard.emoji_invalid", "Emoji: a Unicode emoji or a custom emoji token <:name:id>"))
        }
        _ => Ok(()),
    }
}

/// `%XX` sequences of a header value (names are UTF-8, header values ASCII).
fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Delete a clip (`manage_emojis`).
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/soundboard/{sound_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("sound_id" = String, Path)), responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, sound_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_EMOJIS, "soundboard.manage_forbidden", "Manage emojis and sounds")?;
    let sound = store::voice::sound(&state.db, &room_id, &sound_id).await?.ok_or_else(sound_not_found)?;
    store::voice::delete_sound(&state.db, &room_id, &sound.id).await?;
    state.storage.delete(&sound.id).await;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "soundboard.delete",
        &sound.id,
        "",
        serde_json::json!({ "name": sound.name }),
    )
    .await?;
    state.hub.room(&room_id, "soundboard.update", serde_json::json!({ "room_id": room_id }));
    Ok(StatusCode::NO_CONTENT)
}

fn sound_not_found() -> ApiError {
    access::not_found("Sound", "soundboard.not_found")
}

/// The clip's audio file (members). Played by the client locally (WebAudio) and mixed into its microphone track.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/soundboard/{sound_id}/audio", security(("bearer" = [])),
    params(("room_id" = String, Path), ("sound_id" = String, Path)), responses((status = 200, description = "Audio file"), (status = 404, body = ProblemDetails)))]
pub async fn sound_audio(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, sound_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    validate::ulid("sound_id", &sound_id)?;
    access::room_access(&state, &room_id, &auth.user).await?;
    let sound = store::voice::sound(&state.db, &room_id, &sound_id).await?.ok_or_else(sound_not_found)?;
    let data = state.storage.read(&sound.id).await.map_err(ApiError::Internal)?.ok_or_else(sound_not_found)?;
    let mut resp = Response::new(Body::from(data));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&sound.mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateSound {
    /// New name (1–32 characters).
    pub name: Option<String>,
    /// Unicode emoji or custom emoji token; `null` removes it, absent = unchanged.
    #[serde(default, deserialize_with = "crate::serde_with_double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub emoji: Option<Option<String>>,
}

impl UpdateSound {
    fn checked(&self) -> Result<(Option<&str>, Option<Option<&str>>), ApiError> {
        let name = self.name.as_deref().map(str::trim);
        if let Some(n) = name
            && !valid_sound_name(n)
        {
            return Err(bad("soundboard.name_invalid", "Name: 1–32 characters"));
        }
        let emoji = self.emoji.as_ref().map(|e| e.as_deref().map(str::trim).filter(|e| !e.is_empty()));
        check_sound_emoji(emoji.flatten())?;
        Ok((name, emoji))
    }
}

/// Rename a room clip or set its emoji (`manage_emojis`).
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/soundboard/{sound_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("sound_id" = String, Path)), request_body = UpdateSound,
    responses((status = 200, body = store::voice::Sound), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, sound_id)): Path<(String, String)>,
    Json(req): Json<UpdateSound>,
) -> Result<Json<store::voice::Sound>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_EMOJIS, "soundboard.manage_forbidden", "Manage emojis and sounds")?;
    let (name, emoji) = req.checked()?;
    if !store::voice::update_sound(&state.db, &room_id, &sound_id, name, emoji).await? {
        return Err(sound_not_found());
    }
    let sound = store::voice::sound(&state.db, &room_id, &sound_id).await?.ok_or_else(sound_not_found)?;
    state.hub.room(&room_id, "soundboard.update", serde_json::json!({ "room_id": room_id }));
    Ok(Json(sound))
}

/// The audio of any clip of this node, room or personal, without authentication: players of
/// every node fetch clips they are allowed to play from here. Ids are random; nothing else is revealed.
#[utoipa::path(get, path = "/api/v1/sounds/{sound_id}/audio", params(("sound_id" = String, Path), SoundQuery),
    responses((status = 200, description = "Audio file"), (status = 304), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn public_sound_audio(
    State(state): State<AppState>,
    crate::auth::ClientIp(ip): crate::auth::ClientIp,
    Path(sound_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SoundQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate::ulid("sound_id", &sound_id)?;
    let audio_type = |mime: &str| {
        if valid_audio_mime(mime) {
            HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream"))
        } else {
            HeaderValue::from_static("application/octet-stream")
        }
    };
    if let Some(host) = q.host.as_deref().filter(|h| !h.eq_ignore_ascii_case(&state.config.domain)) {
        let tag = format!("{sound_id}@{host}");
        if let Some(r) = crate::routes::emojis::not_modified(&headers, &tag) {
            return Ok(r);
        }
        crate::routes::emojis::proxy_limit(&state, &ip)?;
        let cached = crate::emoji_cache::get(&state, crate::emoji_cache::CacheKind::Sound, host, &sound_id).await?;
        return Ok(crate::routes::emojis::file_response_tagged(
            cached.data,
            audio_type(&cached.mime),
            true,
            Some(&tag),
        ));
    }
    if let Some(r) = crate::routes::emojis::not_modified(&headers, &sound_id) {
        return Ok(r);
    }
    let mime = store::voice::clip_mime(&state.db, &sound_id).await?.ok_or_else(sound_not_found)?;
    let data = state.storage.read(&sound_id).await.map_err(ApiError::Internal)?.ok_or_else(sound_not_found)?;
    Ok(crate::routes::emojis::file_response_tagged(data, audio_type(&mime), true, Some(&sound_id)))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct SoundQuery {
    /// The node hosting the clip when it is not this one: this node serves its cached copy (fetched once).
    pub host: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PersonalSounds {
    pub items: Vec<store::voice::UserSound>,
    /// Most personal clips this user may have (entitlement `sounds.max_personal`; 0 = unlimited).
    pub max_personal: i64,
    pub max_bytes: u64,
    pub max_duration_ms: i64,
}

fn local_only(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    if auth.is_remote() || auth.user.domain != state.config.domain {
        return Err(crate::federation::guard::local_only());
    }
    Ok(())
}

/// The own personal clips (home node).
#[utoipa::path(get, path = "/api/v1/users/me/sounds", security(("bearer" = [])), responses((status = 200, body = PersonalSounds)))]
pub async fn list_personal_sounds(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<PersonalSounds>, ApiError> {
    local_only(&state, &auth)?;
    Ok(Json(PersonalSounds {
        items: store::voice::user_sounds(&state.db, &auth.user.id).await?,
        max_personal: crate::emoji::personal_limits(&state, &auth.user).await?.sounds.unwrap_or(0),
        max_bytes: SOUNDBOARD_MAX_BYTES as u64,
        max_duration_ms: SOUNDBOARD_MAX_DURATION_MS,
    }))
}

/// Upload a personal clip: like room clips (`Tavrn-Sound-Name`, `Tavrn-Sound-Duration-Ms`, optional
/// `Tavrn-Sound-Emoji`), at most `TAVRN_SOUNDS_MAX_PERSONAL` per user (`403 soundboard.limit`).
#[utoipa::path(post, path = "/api/v1/users/me/sounds", security(("bearer" = [])),
    request_body(content = Vec<u8>, content_type = "audio/ogg"),
    responses((status = 201, body = store::voice::UserSound), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 415, body = ProblemDetails)))]
pub async fn create_personal_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<store::voice::UserSound>), ApiError> {
    local_only(&state, &auth)?;
    let clip = clip_upload(&headers, &body)?;
    if let Some(max) = crate::emoji::personal_limits(&state, &auth.user).await?.sounds
        && store::voice::user_sound_count(&state.db, &auth.user.id).await? >= max
    {
        return Err(ApiError::Forbidden { code: "soundboard.limit", detail: format!("At most {max} personal sounds") });
    }
    let new = store::voice::NewSound {
        room_id: "",
        name: &clip.name,
        mime: &clip.mime,
        size: body.len() as i64,
        duration_ms: clip.duration_ms,
        uploader_id: &auth.user.id,
        emoji: clip.emoji.as_deref(),
    };
    let sound = store::voice::insert_user_sound(&state.db, &auth.user.id, &new).await?;
    if let Err(e) = state.storage.write(&sound.id, &body).await {
        store::voice::delete_user_sound(&state.db, &auth.user.id, &sound.id).await?;
        return Err(ApiError::Internal(e));
    }
    Ok((StatusCode::CREATED, Json(sound)))
}

/// Rename a personal clip or set its emoji.
#[utoipa::path(patch, path = "/api/v1/users/me/sounds/{sound_id}", security(("bearer" = [])), params(("sound_id" = String, Path)),
    request_body = UpdateSound, responses((status = 200, body = store::voice::UserSound), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update_personal_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(sound_id): Path<String>,
    Json(req): Json<UpdateSound>,
) -> Result<Json<store::voice::UserSound>, ApiError> {
    local_only(&state, &auth)?;
    let (name, emoji) = req.checked()?;
    if !store::voice::update_user_sound(&state.db, &auth.user.id, &sound_id, name, emoji).await? {
        return Err(sound_not_found());
    }
    store::voice::user_sound(&state.db, &auth.user.id, &sound_id).await?.map(Json).ok_or_else(sound_not_found)
}

/// Delete a personal clip.
#[utoipa::path(delete, path = "/api/v1/users/me/sounds/{sound_id}", security(("bearer" = [])), params(("sound_id" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn delete_personal_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(sound_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    local_only(&state, &auth)?;
    if !store::voice::delete_user_sound(&state.db, &auth.user.id, &sound_id).await? {
        return Err(sound_not_found());
    }
    state.storage.delete(&sound_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
pub struct PlaySound {
    /// The clip's id.
    pub sound_id: String,
    /// The node hosting the clip when it is not this one (personal clips of users of other nodes, clips of
    /// rooms on other nodes).
    pub host: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PlayAllowed {
    /// `false`: a clip of this room; `true`: an external clip (needed `use_external_sounds`).
    pub external: bool,
    /// The clip's emoji (clips of this node only).
    pub emoji: Option<String>,
}

/// Asks to play a clip in a voice channel: `use_soundboard` and `speak` always, and
/// `use_external_sounds` for any clip that is not one of this room's (`403 soundboard.external_forbidden`).
/// The client plays the clip only after this succeeded; the SFU cannot stop a modified client from mixing
/// audio into its microphone, so this is the cooperative gate (like the stream limits).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/soundboard/play", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = PlaySound,
    responses((status = 200, body = PlayAllowed), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn play_sound(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Json(req): Json<PlaySound>,
) -> Result<Json<PlayAllowed>, ApiError> {
    validate::ulid("sound_id", &req.sound_id)?;
    let vc = voice_channel(&state, &room_id, &channel_id, &auth.user).await?;
    if !vc.has(p::USE_SOUNDBOARD | p::SPEAK) {
        return Err(ApiError::Forbidden {
            code: "soundboard.forbidden",
            detail: "Playing sounds needs use_soundboard and speak in this channel".into(),
        });
    }
    let host = req.host.as_deref().filter(|h| !h.eq_ignore_ascii_case(&state.config.domain));
    if let Some(h) = host
        && !crate::emoji::valid_host(h)
    {
        return Err(bad("soundboard.host_invalid", "host must be a node domain"));
    }
    let own = match host {
        None => store::voice::sound(&state.db, &room_id, &req.sound_id).await?,
        Some(_) => None,
    };
    let external = own.is_none();
    if external && !vc.has(p::USE_EXTERNAL_SOUNDS) {
        return Err(ApiError::Forbidden {
            code: "soundboard.external_forbidden",
            detail: "Sounds from other rooms or personal sounds need use_external_sounds in this channel".into(),
        });
    }
    let emoji = match (own, host) {
        (Some(s), _) => s.emoji,
        (None, None) => store::voice::user_sound_emoji(&state.db, &req.sound_id).await?,
        (None, Some(_)) => None,
    };
    Ok(Json(PlayAllowed { external, emoji }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sound_names_and_types() {
        assert!(valid_sound_name("Fanfare 🎺"));
        assert!(valid_sound_name(&"ä".repeat(32)));
        assert!(!valid_sound_name(""));
        assert!(!valid_sound_name(&"x".repeat(33)));
        assert!(!valid_sound_name("a\nb"));
        for ok in ["audio/ogg", "audio/mpeg", "audio/x-wav", "audio/webm", "audio/mp4"] {
            assert!(valid_audio_mime(ok), "{ok}");
        }
        for bad in ["audio/", "image/png", "audio/ogg\"", "text/html", "audio/<script>"] {
            assert!(!valid_audio_mime(bad), "{bad}");
        }
        assert_eq!(percent_decode("Fanfare%20%F0%9F%8E%BA").as_deref(), Some("Fanfare 🎺"));
        assert_eq!(percent_decode("plain"), None);
        assert_eq!(percent_decode("bad%zz"), None);
    }
}
