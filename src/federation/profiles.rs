// SPDX-License-Identifier: AGPL-3.0-only
//! Profile mirrors of remote users (FEDERATION.md §2.7): display name, bio, linked accounts, DM setting
//! and the images (avatar and header, each a still and optionally an animated variant).
//!
//! The home node's profile names its images by path (`/api/v1/media/{id}` and `…/animated`) and hash.
//! This node fetches an image only when its hash changed, only from such a path on the user's home node,
//! with the size caps of [`Kind::Avatar`]/[`Kind::Header`], checks the hash and the magic bytes (raster
//! images only, never SVG) and serves its own copy, so clients never load images from other nodes.
//! Bio and links are validated like local input (links get their URL derived again here).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::client::Kind;
use crate::{
    app::AppState,
    config::DmPolicy,
    error::ApiError,
    media::{self, Format, MediaKind},
    models::UserRow,
    profile::{self, ProfileLink, ProfileLinkInput},
    store, util, validate,
};

/// Mirrors older than this are refreshed when the user is displayed or logs in.
pub const PROFILE_MAX_AGE_SECS: i64 = 24 * 3600;
/// Refreshes started by `profile.changed` per sender and user and window (§5.2).
pub const CHANGED_PER_WINDOW: u32 = 10;
pub const CHANGED_WINDOW_SECS: u64 = 600;

/// One image of a remote profile: where its variants live on the home node and their hashes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteImage {
    pub still_path: Option<String>,
    pub still_sha256: Option<String>,
    pub animated_path: Option<String>,
    pub animated_sha256: Option<String>,
}

/// A profile as served by the home node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProfile {
    pub display_name: String,
    pub profile_version: i64,
    pub avatar: RemoteImage,
    pub header: RemoteImage,
    pub bio: String,
    pub links: Vec<ProfileLink>,
    pub dm_policy: DmPolicy,
}

fn sha_field(v: &Value, key: &str) -> Result<Option<String>, &'static str> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if URL_SAFE_NO_PAD.decode(s).is_ok_and(|b| b.len() == 32) => Ok(Some(s.clone())),
        Some(_) => Err("invalid image hash"),
    }
}

/// A media path of the home node: exactly `/api/v1/media/<ULID>` (`animated` adds `/animated`).
fn media_path(v: &Value, key: &str, animated: bool) -> Result<Option<String>, &'static str> {
    let Some(s) = v.get(key).and_then(Value::as_str) else { return Ok(None) };
    let rest = s.strip_prefix("/api/v1/media/").ok_or("invalid image path")?;
    let id = if animated { rest.strip_suffix("/animated").ok_or("invalid image path")? } else { rest };
    if util::is_ulid(id) { Ok(Some(s.to_string())) } else { Err("invalid image path") }
}

fn image(v: &Value, prefix: &str) -> Result<RemoteImage, &'static str> {
    let animated_flag = v.get(format!("{prefix}_animated")).and_then(Value::as_bool).unwrap_or(false);
    let still_sha256 = sha_field(v, &format!("{prefix}_sha256"))?;
    let animated_sha256 = if animated_flag { sha_field(v, &format!("{prefix}_animated_sha256"))? } else { None };
    Ok(RemoteImage {
        still_path: media_path(v, &format!("{prefix}_still"), false)?,
        still_sha256,
        animated_path: if animated_sha256.is_some() { media_path(v, prefix, true)? } else { None },
        animated_sha256,
    })
}

/// Validates a fetched profile of `address`.
pub fn parse(address: &str, body: &[u8]) -> Result<RemoteProfile, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "not JSON")?;
    if v.get("address").and_then(Value::as_str) != Some(address) {
        return Err("address does not match");
    }
    let display_name = v.get("display_name").and_then(Value::as_str).ok_or("display_name missing")?;
    let display_name = validate::name("display_name", display_name, 64).map_err(|_| "invalid display_name")?;
    let profile_version =
        v.get("profile_version").and_then(Value::as_i64).filter(|n| *n >= 0).ok_or("invalid profile_version")?;
    let bio = match v.get("bio").and_then(Value::as_str) {
        Some(b) => profile::validate_bio(b).map_err(|_| "invalid bio")?,
        None => String::new(),
    };
    let links = match v.get("links") {
        None | Some(Value::Null) => Vec::new(),
        Some(l) => {
            let inputs: Vec<ProfileLinkInput> = serde_json::from_value(l.clone()).map_err(|_| "invalid links")?;
            // Links that this node does not accept are dropped, not the whole profile.
            inputs.iter().take(profile::MAX_LINKS).filter_map(|i| profile::validate_link(i).ok()).collect()
        }
    };
    let dm_policy = v.get("dm_policy").and_then(Value::as_str).map(DmPolicy::parse).unwrap_or(DmPolicy::Friends);
    Ok(RemoteProfile {
        display_name,
        profile_version,
        avatar: image(&v, "avatar")?,
        header: image(&v, "header")?,
        bio,
        links,
        dm_policy,
    })
}

/// Fetches and validates the profile from the home node.
pub async fn fetch(state: &AppState, username: &str, domain: &str) -> Result<RemoteProfile, ApiError> {
    let address = format!("{username}@{domain}");
    let path = format!("/api/v1/users/{username}/profile");
    match state.federation.get(domain, &path, Kind::Profile).await {
        Ok(f) => parse(&address, &f.body).map_err(|reason| super::discovery::peer_invalid(domain, reason)),
        Err(e) if e.status() == Some(404) => Err(ApiError::NotFound { code: "user.not_found", what: "User".into() }),
        Err(e) => Err(e.to_api()),
    }
}

/// Refreshes the mirror when `hint` (a token's `pv`) is newer or the mirror is stale. Failures keep the
/// old mirror and are only logged.
pub async fn refresh(state: &AppState, user: &UserRow, hint: Option<i64>) -> Result<(), ApiError> {
    let meta = store::federation::remote_meta(&state.db, &user.id).await?;
    let (version, fetched_at) = match &meta {
        Some(m) => (m.profile_version, m.profile_fetched_at.clone()),
        None => (0, None),
    };
    let cutoff = util::format_time(Utc::now() - chrono::Duration::seconds(PROFILE_MAX_AGE_SECS));
    let stale = fetched_at.is_none_or(|t| t < cutoff);
    if !stale && !hint.is_some_and(|pv| pv > version) {
        return Ok(());
    }
    match fetch(state, &user.username, &user.domain).await {
        Ok(profile) => apply(state, user, &profile).await,
        Err(e) => {
            tracing::warn!(domain = user.domain, result = e.code(), "remote profile not refreshed, mirror kept");
            Ok(())
        }
    }
}

/// A received `profile.changed` (§2.7 (d), §5.2) about `from`, a user of the sender `iss` (checked by the inbox):
/// the remote user whose mirror is older than `version`, or `None` when the message changes nothing here (a user
/// this node does not know, no stub is created; a disabled one; a version that is not newer). Limited per sender
/// and user: beyond it `429` before the message counts as received, so the sender's retry brings the change later.
pub async fn admit_changed(state: &AppState, iss: &str, from: &str, version: i64) -> Result<Option<UserRow>, ApiError> {
    let Some((name, domain)) = util::parse_address(from) else { return Ok(None) };
    if domain != iss || domain == state.config.domain {
        return Ok(None);
    }
    let Some(user) = store::federation::user_by_address(&state.db, name, domain).await? else { return Ok(None) };
    if user.disabled_at.is_some() {
        return Ok(None);
    }
    let stored = store::federation::remote_meta(&state.db, &user.id).await?.map_or(0, |m| m.profile_version);
    if version <= stored {
        return Ok(None);
    }
    state.profile_changed_limiter.check_all(&[format!("{iss}|{}", user.id)]).await?;
    Ok(Some(user))
}

/// The background refresh after an admitted `profile.changed`: fetches the profile (the old mirror stays on
/// failure) and, when the mirror changed, sends `user.update` to the user's rooms and contacts here.
pub fn spawn_changed_refresh(state: &AppState, user: UserRow, version: i64) {
    let state = state.clone();
    tokio::spawn(async move {
        let stored = |state: AppState, id: String| async move {
            store::federation::remote_meta(&state.db, &id).await.ok().flatten().map_or(0, |m| m.profile_version)
        };
        let before = stored(state.clone(), user.id.clone()).await;
        if let Err(e) = refresh(&state, &user, Some(version)).await {
            tracing::info!(domain = user.domain, result = e.code(), "profile refresh after profile.changed failed");
            return;
        }
        if stored(state.clone(), user.id.clone()).await > before
            && let Err(e) = profile::announce_user(&state, &user.id).await
        {
            tracing::debug!(error = %e, "user.update after a mirror refresh failed");
        }
    });
}

/// Stores a fetched profile in the mirror (names, bio, links, setting, images whose hash changed).
pub async fn apply(state: &AppState, user: &UserRow, profile: &RemoteProfile) -> Result<(), ApiError> {
    store::federation::store_profile(&state.db, &user.id, &profile.display_name, profile.profile_version).await?;
    let links = serde_json::to_string(&profile.links).unwrap_or_else(|_| "[]".into());
    store::federation::store_remote_profile_fields(
        &state.db,
        &user.id,
        &profile.bio,
        &links,
        profile.dm_policy.as_str(),
    )
    .await?;
    let known = store::federation::remote_image_hashes(&state.db, &user.id).await?;
    for (kind, remote, current) in [
        (MediaKind::Avatar, &profile.avatar, (&known.avatar, &known.avatar_animated)),
        (MediaKind::Header, &profile.header, (&known.header, &known.header_animated)),
    ] {
        if remote.still_sha256 != *current.0 || remote.animated_sha256 != *current.1 {
            mirror_image(state, user, kind, remote).await?;
        }
    }
    Ok(())
}

/// Fetches one variant and checks hash and type: stills may be PNG, JPEG, GIF or WebP (older nodes),
/// animated variants must be animated WebP.
async fn fetch_variant(
    state: &AppState,
    user: &UserRow,
    path: &str,
    expected: &str,
    kind: Kind,
    animated: bool,
) -> Option<(Vec<u8>, String)> {
    let fetched = match state.federation.get(&user.domain, path, kind).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(domain = user.domain, result = e.label(), "remote image fetch failed");
            return None;
        }
    };
    if URL_SAFE_NO_PAD.encode(Sha256::digest(&fetched.body)) != expected {
        tracing::warn!(domain = user.domain, "remote image does not match its hash");
        return None;
    }
    let format = media::sniff(&fetched.body);
    let ok = match format {
        Some(Format::WebPAnimated) => animated,
        Some(Format::Png | Format::Jpeg | Format::GifStill | Format::Gif | Format::WebP) => !animated,
        _ => false,
    };
    if !ok {
        tracing::warn!(domain = user.domain, "remote image has an unexpected format");
        return None;
    }
    let mime = match format {
        Some(Format::Png) => "image/png",
        Some(Format::Jpeg) => "image/jpeg",
        Some(Format::Gif | Format::GifStill) => "image/gif",
        _ => "image/webp",
    };
    Some((fetched.body, mime.to_string()))
}

async fn mirror_image(state: &AppState, user: &UserRow, kind: MediaKind, remote: &RemoteImage) -> Result<(), ApiError> {
    let fetch_kind = if kind == MediaKind::Header { Kind::Header } else { Kind::Avatar };
    // Older nodes only serve the avatar at /users/{name}/avatar.
    let legacy = format!("/api/v1/users/{}/avatar", user.username);
    let still_path = match (&remote.still_path, kind) {
        (Some(p), _) => Some(p.as_str()),
        (None, MediaKind::Avatar) if remote.still_sha256.is_some() => Some(legacy.as_str()),
        _ => None,
    };
    let still = match (still_path, &remote.still_sha256) {
        (Some(path), Some(sha)) => match fetch_variant(state, user, path, sha, fetch_kind, false).await {
            Some(v) => Some(v),
            None => return Ok(()),
        },
        _ => None,
    };
    let animated = match (&remote.animated_path, &remote.animated_sha256, &still) {
        (Some(path), Some(sha), Some(_)) => fetch_variant(state, user, path, sha, fetch_kind, true).await.map(|v| v.0),
        _ => None,
    };
    let stored = match &still {
        Some((data, mime)) => {
            Some(profile::store_media(state, kind.as_str(), &user.id, data, mime, animated.as_deref()).await?)
        }
        None => None,
    };
    profile::set_user_media(state, &user.id, kind, stored.as_ref()).await?;
    store::federation::set_remote_image_hashes(
        &state.db,
        &user.id,
        kind.as_str(),
        stored.as_ref().and(remote.still_sha256.as_deref()),
        stored.as_ref().filter(|s| s.animated).and(remote.animated_sha256.as_deref()),
        still.as_ref().map(|(_, m)| m.as_str()),
    )
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use serde_json::json;

    use super::*;

    fn sha(s: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(s))
    }

    const ID: &str = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";

    #[test]
    fn profiles_are_validated() {
        let ok = json!({
            "address": "alice@a.example", "display_name": " Alice ", "profile_version": 3,
            "avatar_sha256": sha(b"s"), "avatar_still": format!("/api/v1/media/{ID}"),
            "avatar": format!("/api/v1/media/{ID}/animated"), "avatar_animated": true, "avatar_animated_sha256": sha(b"a"),
            "header": null, "header_still": null, "header_sha256": null,
            "bio": "**hi**", "links": [{ "service": "x", "value": "@jack", "url": "https://evil.example" }, { "service": "myspace", "value": "x" }],
            "dm_policy": "everyone", "extra": 1
        });
        let p = parse("alice@a.example", ok.to_string().as_bytes()).unwrap();
        assert_eq!(p.display_name, "Alice");
        assert_eq!(p.avatar.still_path.as_deref(), Some(format!("/api/v1/media/{ID}").as_str()));
        assert_eq!(p.avatar.animated_sha256, Some(sha(b"a")));
        assert_eq!(p.header, RemoteImage::default());
        assert_eq!(p.links.len(), 1, "unknown services are dropped");
        assert_eq!(p.links[0].url.as_deref(), Some("https://x.com/jack"), "URLs are derived here, never copied");
        assert_eq!(p.dm_policy, DmPolicy::Everyone);

        // An older node: only avatar_sha256 (served at /users/{name}/avatar), no policy (strictest assumed).
        let old = json!({ "address": "alice@a.example", "display_name": "A", "profile_version": 1, "avatar_sha256": sha(b"s") });
        let p = parse("alice@a.example", old.to_string().as_bytes()).unwrap();
        assert_eq!(p.avatar.still_path, None);
        assert_eq!(p.avatar.still_sha256, Some(sha(b"s")));
        assert_eq!(p.dm_policy, DmPolicy::Friends);

        let check = |v: Value| parse("alice@a.example", v.to_string().as_bytes()).unwrap_err();
        let base = || json!({ "address": "alice@a.example", "display_name": "A", "profile_version": 1 });
        assert_eq!(
            check(json!({ "address": "mallory@a.example", "display_name": "A", "profile_version": 1 })),
            "address does not match"
        );
        let mut v = base();
        v["avatar_still"] = json!("https://tracker.example/pixel.png");
        assert_eq!(check(v), "invalid image path", "images only from media paths of the home node");
        let mut v = base();
        v["avatar_still"] = json!("/api/v1/media/../../etc/passwd");
        assert_eq!(check(v), "invalid image path");
        let mut v = base();
        v["bio"] = json!("x".repeat(600));
        assert_eq!(check(v), "invalid bio");
        let mut v = base();
        v["avatar_sha256"] = json!("short");
        assert_eq!(check(v), "invalid image hash");
        assert_eq!(parse("alice@a.example", b"<html>").unwrap_err(), "not JSON");
    }
}
