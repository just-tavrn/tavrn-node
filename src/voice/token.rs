// SPDX-License-Identifier: AGPL-3.0-only
//! LiveKit access tokens: exactly the grants a member may use in one voice channel, nothing more.
//!
//! LiveKit tokens are HS256 JWTs signed with the node's LiveKit API secret (`<data>/keys/livekit.key`).
//! The node issues them in `voice/join` and verifies them itself before it proxies `/rtc` to LiveKit.

use std::time::Duration;

use livekit_api::access_token::{AccessToken, Claims, TokenVerifier, VideoGrants};

/// Lifetime of a token from `voice/join`. LiveKit only checks it when the connection is made (it hands
/// connected clients refreshed tokens itself), so a short lifetime costs nothing.
pub const TOKEN_TTL: Duration = Duration::from_secs(600);

/// LiveKit track source names (`canPublishSources`).
pub const SOURCE_MICROPHONE: &str = "microphone";
pub const SOURCE_CAMERA: &str = "camera";
pub const SOURCE_SCREEN: &str = "screen_share";
pub const SOURCE_SCREEN_AUDIO: &str = "screen_share_audio";

/// What a participant may publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sources {
    /// `speak` and not server-muted.
    pub microphone: bool,
    /// `use_camera` and `TAVRN_CAMERA_ENABLED`.
    pub camera: bool,
    /// `stream` and `TAVRN_SCREENSHARE_ENABLED` (screen video plus its audio).
    pub screen: bool,
    /// `use_soundboard`: data messages (the `soundboard.play` signal, VOICE.md §8), end-to-end encrypted
    /// by LiveKit like the media.
    pub data: bool,
    /// `priority_speaker`: own attribute updates (the `priority` attribute, VOICE.md §7a). Receivers check
    /// the permission themselves; this only keeps clients without the bit from setting it at all.
    pub priority: bool,
}

impl Sources {
    pub fn names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.microphone {
            out.push(SOURCE_MICROPHONE.to_string());
        }
        if self.camera {
            out.push(SOURCE_CAMERA.to_string());
        }
        if self.screen {
            out.push(SOURCE_SCREEN.to_string());
            out.push(SOURCE_SCREEN_AUDIO.to_string());
        }
        out
    }
}

/// Grants for joining LiveKit room `room` with `sources`. Subscribing is always allowed (listening needs
/// only `connect`); data messages only with `use_soundboard` and own metadata/attribute updates only with
/// `priority_speaker`; room administration, recording and hidden participants never.
pub fn grants(room: &str, sources: Sources) -> VideoGrants {
    let names = sources.names();
    VideoGrants {
        room_join: true,
        room: room.to_string(),
        can_subscribe: Some(true),
        // An empty `canPublishSources` means "any source" to LiveKit: without any source the
        // participant must not publish at all.
        can_publish: Some(!names.is_empty()),
        can_publish_sources: names,
        can_publish_data: Some(sources.data),
        can_update_own_metadata: Some(sources.priority),
        ..Default::default()
    }
}

/// Signs a token for `identity` with `grants`, valid for `ttl`.
pub fn issue(
    api_key: &str,
    secret: &str,
    identity: &str,
    grants: VideoGrants,
    ttl: Duration,
) -> anyhow::Result<String> {
    AccessToken::with_api_key(api_key, secret)
        .with_identity(identity)
        .with_grants(grants)
        .with_ttl(ttl)
        .to_jwt()
        .map_err(|e| anyhow::anyhow!("cannot create LiveKit token: {e}"))
}

/// Verifies signature, issuer (our API key), `exp` and `nbf` of a token, whoever issued it with our secret
/// (the node or LiveKit's token refresh).
pub fn verify(api_key: &str, secret: &str, token: &str) -> Option<Claims> {
    TokenVerifier::with_api_key(api_key, secret).verify(token).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const KEY: &str = "APItest";
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn grants_list_exactly_the_allowed_sources() {
        let g = grants("r:c", Sources { microphone: true, camera: false, screen: true, ..Default::default() });
        assert!(g.room_join);
        assert_eq!(g.room, "r:c");
        assert_eq!(g.can_publish, Some(true));
        assert_eq!(g.can_publish_sources, vec!["microphone", "screen_share", "screen_share_audio"]);
        assert_eq!(g.can_subscribe, Some(true));
        assert_eq!(g.can_publish_data, Some(false));
        assert_eq!(g.can_update_own_metadata, Some(false));
        assert!(!g.room_admin && !g.room_create && !g.room_list && !g.room_record && !g.hidden && !g.recorder);
        let all = grants("r:c", Sources { microphone: true, camera: true, screen: true, ..Default::default() });
        assert_eq!(all.can_publish_sources.len(), 4);
    }

    #[test]
    fn priority_speakers_may_update_their_attributes_and_soundboard_users_send_data() {
        let g = grants("r:c", Sources { microphone: true, priority: true, ..Default::default() });
        assert_eq!(g.can_update_own_metadata, Some(true), "the `priority` attribute needs own metadata updates");
        assert_eq!(g.can_publish_data, Some(false));
        let g = grants("r:c", Sources { microphone: true, data: true, ..Default::default() });
        assert_eq!(g.can_update_own_metadata, Some(false), "without priority_speaker no attribute updates");
        assert_eq!(g.can_publish_data, Some(true));
        // Data and attributes never widen the media sources.
        assert_eq!(g.can_publish_sources, vec!["microphone"]);
        let g = grants("r:c", Sources { data: true, priority: true, ..Default::default() });
        assert_eq!(g.can_publish, Some(false));
        assert!(g.can_publish_sources.is_empty());
    }

    #[test]
    fn no_sources_means_no_publishing_at_all() {
        let g = grants("r:c", Sources::default());
        assert_eq!(g.can_publish, Some(false), "an empty source list would otherwise allow every source");
        assert!(g.can_publish_sources.is_empty());
        assert!(!g.can_publish());
    }

    #[test]
    fn tokens_round_trip_and_reject_foreign_keys() {
        let token = issue(KEY, SECRET, "alice@n.example/DEV", grants("r:c", Sources::default()), TOKEN_TTL).unwrap();
        let claims = verify(KEY, SECRET, &token).unwrap();
        assert_eq!(claims.sub, "alice@n.example/DEV");
        assert_eq!(claims.iss, KEY);
        assert_eq!(claims.video.room, "r:c");
        let ttl = claims.exp - claims.nbf;
        assert!((590..=610).contains(&ttl), "TTL is ten minutes, got {ttl}");
        assert!(verify(KEY, "another-secret-another-secret-another-secret", &token).is_none());
        assert!(verify("APIother", SECRET, &token).is_none(), "issuer must be our API key");
        assert!(verify(KEY, SECRET, "not.a.jwt").is_none());
        // A token that expired an hour ago (beyond the 60 s leeway) and one with `alg: none`.
        let mut claims = verify(KEY, SECRET, &token).unwrap();
        claims.exp -= 3600 + TOKEN_TTL.as_secs() as usize;
        claims.nbf -= 7200;
        assert!(verify(KEY, SECRET, &sign_hs256(SECRET, &claims)).is_none());
        let unsigned =
            format!("{}.{}.", b64(br#"{"alg":"none","typ":"JWT"}"#), b64(&serde_json::to_vec(&claims).unwrap()));
        assert!(verify(KEY, SECRET, &unsigned).is_none());
    }

    fn b64(data: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Signs arbitrary claims the way LiveKit does (HS256 with the API secret).
    fn sign_hs256(secret: &str, claims: &Claims) -> String {
        use hmac::Mac;
        let input = format!("{}.{}", b64(br#"{"alg":"HS256","typ":"JWT"}"#), b64(&serde_json::to_vec(claims).unwrap()));
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(input.as_bytes());
        format!("{input}.{}", b64(&mac.finalize().into_bytes()))
    }
}
