// SPDX-License-Identifier: AGPL-3.0-only
use axum::{Json, extract::State};
use serde::Serialize;

use crate::app::{AppState, PROTOCOL_VERSION, SOFTWARE_VERSION, capabilities};

#[derive(Serialize, utoipa::ToSchema)]
pub struct CaptchaInfo {
    /// turnstile
    pub provider: String,
    pub site_key: String,
    pub register: bool,
    pub login: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct NodeInfo {
    pub domain: String,
    pub name: String,
    pub description: String,
    pub protocol: u32,
    pub version: String,
    pub capabilities: Vec<String>,
    pub registration: String,
    /// Captcha settings for registration/login, if the operator enabled one.
    pub captcha: Option<CaptchaInfo>,
    /// GIF provider (`giphy`, `tenor`) or null.
    pub gif_provider: Option<String>,
    /// Who may start direct messages: `friends` or `open`.
    pub dm_policy: String,
    /// Voice policies of this node (protocol/VOICE.md).
    pub voice: VoiceInfo,
    /// Single sign-on (APPLICATIONS.md §8.1): button text and `TAVRN_OIDC_ONLY`; null without a provider.
    pub sso: Option<crate::routes::oidc::SsoInfo>,
    /// Images up to this size (bytes) load as previews automatically where the user's `auto_preview`
    /// setting allows it; larger ones wait for a click (`TAVRN_PREVIEW_AUTO_MAX_BYTES`).
    pub preview_auto_max_bytes: u64,
    /// Message retention of this node in days (`TAVRN_RETENTION_DAYS`, PROTOCOL.md §7f; 0 = messages are kept). Rooms
    /// can only shorten it.
    pub message_retention_days: u32,
    /// Legal pages and the notice form (protocol/LEGAL.md).
    pub legal: crate::legal::LegalInfo,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct VoiceInfo {
    pub enabled: bool,
    pub max_bitrate_kbps: u32,
    pub max_participants: u32,
    pub screenshare: crate::routes::wellknown::ScreensharePolicy,
    pub camera: crate::routes::wellknown::ScreensharePolicy,
}

/// Public summary of the node for the client (sign-in page, header).
#[utoipa::path(get, path = "/api/v1/node", responses((status = 200, body = NodeInfo)))]
pub async fn get_node(State(state): State<AppState>) -> Result<Json<NodeInfo>, crate::error::ApiError> {
    let c = &state.config;
    let legal = crate::legal::info(&state).await?;
    Ok(Json(NodeInfo {
        legal,
        domain: c.domain.clone(),
        name: c.name.clone(),
        description: c.description.clone(),
        protocol: PROTOCOL_VERSION,
        version: SOFTWARE_VERSION.into(),
        capabilities: capabilities(c).into_iter().map(String::from).collect(),
        registration: serde_json::to_value(c.registration)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default(),
        gif_provider: match c.gif_provider {
            crate::config::GifProvider::None => None,
            other => serde_json::to_value(other).ok().and_then(|v| v.as_str().map(String::from)),
        },
        dm_policy: serde_json::to_value(c.dm_policy)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default(),
        preview_auto_max_bytes: c.preview_auto_max_bytes,
        message_retention_days: c.retention_days,
        voice: VoiceInfo {
            enabled: c.voice_enabled,
            max_bitrate_kbps: c.voice_max_bitrate_kbps,
            max_participants: c.voice_max_participants,
            screenshare: crate::routes::wellknown::Policies::screenshare(c),
            camera: crate::routes::wellknown::Policies::camera(c),
        },
        sso: crate::routes::oidc::info(&state),
        captcha: match c.captcha_provider {
            crate::config::CaptchaProvider::None => None,
            crate::config::CaptchaProvider::Turnstile => Some(CaptchaInfo {
                provider: "turnstile".into(),
                site_key: c.turnstile_site_key.clone().unwrap_or_default(),
                register: c.captcha_register,
                login: c.captcha_login,
            }),
        },
    }))
}
