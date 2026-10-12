// SPDX-License-Identifier: AGPL-3.0-only
//! `/.well-known/tavrn`: the node's discovery document (PROTOCOL.md §2). `domain` is the identity domain
//! (`TAVRN_DOMAIN`); `api`, `ws` and `web` point to the host that serves the node (`TAVRN_PUBLIC_URL`,
//! delegation). `tavrn-node well-known` prints the same document for a static copy.

use axum::{Json, extract::State, http::header, response::IntoResponse};
use serde::Serialize;

use crate::{
    app::{AppState, PROTOCOL_VERSION, SOFTWARE_NAME, SOFTWARE_VERSION, capabilities},
    keys::PublicKeyInfo,
};

#[derive(Serialize, utoipa::ToSchema)]
pub struct Software {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ScreensharePolicy {
    pub enabled: bool,
    pub max_resolution: String,
    pub max_fps: u32,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct Policies {
    pub uploads_enabled: bool,
    pub upload_max_bytes: u64,
    pub voice_enabled: bool,
    pub voice_max_bitrate_kbps: u32,
    /// Participants per voice channel at most.
    pub voice_max_participants: u32,
    pub screenshare: ScreensharePolicy,
    /// Webcam sharing (same shape as `screenshare`).
    pub camera: ScreensharePolicy,
    /// Largest image (bytes) clients load as a preview without a click (`TAVRN_PREVIEW_AUTO_MAX_BYTES`).
    pub preview_auto_max_bytes: u64,
}

impl Policies {
    pub fn screenshare(c: &crate::config::Config) -> ScreensharePolicy {
        ScreensharePolicy {
            enabled: c.voice_enabled && c.screenshare_enabled,
            max_resolution: c.screenshare_max_resolution.clone(),
            max_fps: c.screenshare_max_fps,
        }
    }

    pub fn camera(c: &crate::config::Config) -> ScreensharePolicy {
        ScreensharePolicy {
            enabled: c.voice_enabled && c.camera_enabled,
            max_resolution: c.camera_max_resolution.clone(),
            max_fps: c.camera_max_fps,
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct WellKnown {
    pub tavrn: u32,
    pub domain: String,
    pub name: String,
    pub description: String,
    /// API base of the node (`<TAVRN_PUBLIC_URL>/api/v1`); its host may differ from `domain` (delegation).
    pub api: String,
    /// WebSocket URL (`wss://<public host>/api/v1/ws`).
    pub ws: String,
    /// Origin of this node's web client (FEDERATION.md §8: the connect flow redirects to
    /// `<web>/connect`); `TAVRN_WEBAUTHN_ORIGIN`, default the public URL.
    pub web: String,
    pub software: Software,
    pub capabilities: Vec<String>,
    pub keys: Vec<PublicKeyInfo>,
    pub registration: String,
    pub email: String,
    pub policies: Policies,
    pub directory_listing: bool,
    /// Present while federation is enabled (FEDERATION.md §1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationInfo>,
    /// WebAuthn relying party of this node's passkeys (PROTOCOL.md §5a.4).
    pub webauthn: WebauthnInfo,
    /// Date of birth and age gates (`age.v1`, PROTOCOL.md §5e).
    pub age: crate::age::AgeInfo,
}

/// The WebAuthn relying party of this node (PROTOCOL.md §5a.4).
#[derive(Serialize, utoipa::ToSchema)]
pub struct WebauthnInfo {
    /// The relying party id (`TAVRN_WEBAUTHN_RP_ID`, default the identity domain). It may be a parent domain of
    /// the web client's host (delegation); clients pass it as `rpId` on assertions they build themselves (the
    /// secret storage PRF).
    pub rp_id: String,
    /// Every origin the node accepts in `clientDataJSON`: the web origin first, then the origins of the node's own
    /// apps (`TAVRN_WEBAUTHN_APP_ORIGINS`, e.g. `android:apk-key-hash:<base64url>`). An app offers passkeys in its
    /// webview only while its own origin is listed, otherwise it signs in through the browser.
    pub origins: Vec<String>,
}

impl WebauthnInfo {
    pub fn of(c: &crate::config::Config) -> Self {
        Self { rp_id: c.webauthn_rp_id(), origins: c.webauthn_origins() }
    }
}

/// Per-domain limits this node applies to peers, so they can pace themselves (FEDERATION.md §1.1).
#[derive(Serialize, utoipa::ToSchema)]
pub struct FederationLimits {
    pub federated_logins_per_minute: u32,
    pub inbox_per_minute: u32,
    pub max_remote_users: u32,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct FederationInfo {
    pub version: u32,
    pub limits: FederationLimits,
}

pub fn build(state: &AppState) -> WellKnown {
    build_from(&state.config, &state.keys)
}

/// The document for `config` and the node signing keys `keys` (also used by `tavrn-node well-known`).
pub fn build_from(c: &crate::config::Config, keys: &[crate::keys::NodeKey]) -> WellKnown {
    let base = c.public_url();
    WellKnown {
        tavrn: PROTOCOL_VERSION,
        domain: c.domain.clone(),
        name: c.name.clone(),
        description: c.description.clone(),
        api: format!("{base}/api/v1"),
        ws: format!("{}/api/v1/ws", base.replacen("http", "ws", 1)),
        web: c.webauthn_origin(),
        software: Software { name: SOFTWARE_NAME.into(), version: SOFTWARE_VERSION.into() },
        capabilities: capabilities(c).into_iter().map(String::from).collect(),
        keys: keys.iter().map(|k| k.public_info()).collect(),
        registration: enum_str(&c.registration),
        email: enum_str(&c.email),
        policies: Policies {
            uploads_enabled: c.uploads_enabled,
            upload_max_bytes: c.upload_max_bytes,
            voice_enabled: c.voice_enabled,
            voice_max_bitrate_kbps: c.voice_max_bitrate_kbps,
            voice_max_participants: c.voice_max_participants,
            screenshare: Policies::screenshare(c),
            camera: Policies::camera(c),
            preview_auto_max_bytes: c.preview_auto_max_bytes,
        },
        directory_listing: c.directory_listing,
        age: crate::age::info(c),
        federation: c.federation_enabled.then_some(FederationInfo {
            version: 1,
            limits: FederationLimits {
                federated_logins_per_minute: c.federation_rate_logins,
                inbox_per_minute: c.federation_rate_inbox,
                max_remote_users: c.federation_max_remote_users,
            },
        }),
        webauthn: WebauthnInfo::of(c),
    }
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// Discovery document. Read by clients and other nodes; cacheable for 5 minutes.
#[utoipa::path(get, path = "/.well-known/tavrn", responses((status = 200, body = WellKnown)))]
pub async fn get_well_known(State(state): State<AppState>) -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "public, max-age=300")], Json(build(&state)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{config::Config, keys::NodeKey};

    fn config(public_url: Option<&str>) -> Config {
        Config {
            domain: "tavrn.org".into(),
            database_url: "postgres://x@db/x".into(),
            public_url: public_url.map(String::from),
            ..Config::default()
        }
    }

    #[test]
    fn the_document_keeps_the_identity_domain_and_points_to_the_public_url() {
        let keys = vec![NodeKey::generate("k1")];
        let doc = build_from(&config(Some("https://app.tavrn.org")), &keys);
        assert_eq!(doc.domain, "tavrn.org");
        assert_eq!(doc.api, "https://app.tavrn.org/api/v1");
        assert_eq!(doc.ws, "wss://app.tavrn.org/api/v1/ws");
        assert_eq!(doc.web, "https://app.tavrn.org");
        assert_eq!(doc.keys.len(), 1);
        assert_eq!(doc.keys[0].kid, "k1");

        let plain = build_from(&config(None), &keys);
        assert_eq!((plain.api.as_str(), plain.ws.as_str()), ("https://tavrn.org/api/v1", "wss://tavrn.org/api/v1/ws"));

        let web =
            Config { webauthn_origin: Some("https://web.tavrn.org".into()), ..config(Some("https://app.tavrn.org")) };
        assert_eq!(build_from(&web, &keys).web, "https://web.tavrn.org");
        assert_eq!(build_from(&web, &keys).webauthn.origins, vec!["https://web.tavrn.org".to_string()]);
        let app = &format!("android:apk-key-hash:{}", "A".repeat(43));
        let apps = Config { webauthn_app_origins: app.into(), ..config(Some("https://app.tavrn.org")) };
        let doc = build_from(&apps, &keys);
        assert_eq!(doc.webauthn.rp_id, "tavrn.org");
        assert_eq!(
            doc.webauthn.origins,
            vec!["https://app.tavrn.org".to_string(), app.to_string()],
            "web origin first"
        );

        let dev = Config {
            dev: true,
            domain: "a.test".into(),
            public_url: Some("http://127.0.0.1:18083".into()),
            ..Config::defaults_for(true)
        };
        let doc = build_from(&dev, &keys);
        assert_eq!((doc.domain.as_str(), doc.ws.as_str()), ("a.test", "ws://127.0.0.1:18083/api/v1/ws"));
    }
}
