// SPDX-License-Identifier: AGPL-3.0-only
//! Profiles: bio, linked accounts and the stored images of users and rooms.
//!
//! Linked accounts are a typed list: every service has its own grammar for the display value and the
//! node derives the profile URL itself from an allowlist of hosts (https only), so a profile can never
//! link to an arbitrary site under a service's icon. Only `website` takes any https URL of a public host
//! name (no IP literals, no localhost, no credentials, no ports).

use axum::body::Bytes;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    error::ApiError,
    media::{MediaKind, Processed},
    store::{self, media::NewMedia},
    util,
    validate::bad,
};

/// Bio length in characters (Markdown subset, rendered and sanitized by clients).
pub const BIO_MAX_CHARS: usize = 512;
pub const MAX_LINKS: usize = 10;
pub const LINK_VALUE_MAX: usize = 100;

/// Services of linked accounts (no verification in v1; clients show "not verified").
pub const LINK_SERVICES: &[&str] =
    &["steam", "battlenet", "xbox", "playstation", "nintendo", "twitch", "youtube", "x", "mastodon", "website"];

/// A linked account as stored and served.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct ProfileLink {
    /// steam | battlenet | xbox | playstation | nintendo | twitch | youtube | x | mastodon | website
    pub service: String,
    /// What the profile shows, e.g. `Name#1234` or `@handle`.
    pub value: String,
    /// The account's page, derived by the node (null where the service has none).
    pub url: Option<String>,
}

/// A linked account as sent by a client; `url` is ignored (the node derives it from `value`).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ProfileLinkInput {
    pub service: String,
    pub value: String,
    #[serde(default)]
    pub url: Option<String>,
}

fn link_invalid(service: &str, detail: &str) -> ApiError {
    ApiError::BadRequest { code: "profile.link_invalid", detail: format!("{service}: {detail}") }
}

fn chars_ok(s: &str, min: usize, max: usize, allowed: impl Fn(char) -> bool) -> bool {
    let n = s.chars().count();
    (min..=max).contains(&n) && s.chars().all(allowed)
}

/// A host name of the public DNS: lowercase labels, at least one dot, no IP literal, no localhost.
fn public_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels.last().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()) && tld.len() >= 2)
        && !matches!(labels.last(), Some(&"localhost") | Some(&"local") | Some(&"internal") | Some(&"test"))
}

/// A pasted https URL of one of `hosts`: its path segments (no query, fragment, credentials or port).
fn url_path<'a>(value: &str, hosts: &[&str], buf: &'a mut Vec<String>) -> Option<&'a [String]> {
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    if !hosts.contains(&host.as_str()) {
        return None;
    }
    *buf = url.path_segments()?.filter(|s| !s.is_empty()).map(String::from).collect();
    Some(buf.as_slice())
}

/// Validates one linked account and derives its URL.
pub fn validate_link(input: &ProfileLinkInput) -> Result<ProfileLink, ApiError> {
    let service = input.service.trim().to_ascii_lowercase();
    if !LINK_SERVICES.contains(&service.as_str()) {
        return Err(bad("profile.link_service", format!("Unknown service {service}")));
    }
    let raw = input.value.trim();
    if raw.is_empty() || raw.chars().count() > 256 || raw.chars().any(char::is_control) {
        return Err(link_invalid(&service, "value missing or too long"));
    }
    let mut buf = Vec::new();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let (value, url): (String, Option<String>) = match service.as_str() {
        "steam" => {
            // Vanity name, SteamID64 or a pasted profile URL.
            let id = match url_path(raw, &["steamcommunity.com"], &mut buf) {
                Some([kind, id]) if kind == "id" || kind == "profiles" => id.clone(),
                Some(_) => return Err(link_invalid(&service, "not a Steam profile address")),
                None => raw.to_string(),
            };
            if chars_ok(&id, 17, 17, |c| c.is_ascii_digit()) {
                (id.clone(), Some(format!("https://steamcommunity.com/profiles/{id}")))
            } else if chars_ok(&id, 2, 32, |c| word(c) || c == '-') {
                (id.clone(), Some(format!("https://steamcommunity.com/id/{id}")))
            } else {
                return Err(link_invalid(&service, "Steam name or SteamID64 expected"));
            }
        }
        "battlenet" => {
            let ok = raw.split_once('#').is_some_and(|(name, num)| {
                chars_ok(name, 2, 12, char::is_alphanumeric) && chars_ok(num, 3, 6, |c| c.is_ascii_digit())
            });
            if !ok {
                return Err(link_invalid(&service, "BattleTag like Name#1234 expected"));
            }
            (raw.to_string(), None)
        }
        "xbox" => {
            if !chars_ok(raw, 1, 15, |c| c.is_ascii_alphanumeric() || c == ' ') || raw.starts_with(' ') {
                return Err(link_invalid(&service, "Gamertag (up to 15 characters) expected"));
            }
            (raw.to_string(), None)
        }
        "playstation" => {
            if !chars_ok(raw, 3, 16, |c| word(c) || c == '-') {
                return Err(link_invalid(&service, "Online ID (3–16 characters) expected"));
            }
            (raw.to_string(), None)
        }
        "nintendo" => {
            let digits: String = raw.trim_start_matches("SW-").chars().filter(char::is_ascii_digit).collect();
            let shape = raw.trim_start_matches("SW-").chars().all(|c| c.is_ascii_digit() || c == '-' || c == ' ');
            if digits.len() != 12 || !shape {
                return Err(link_invalid(&service, "friend code like SW-1234-5678-9012 expected"));
            }
            (format!("SW-{}-{}-{}", &digits[0..4], &digits[4..8], &digits[8..12]), None)
        }
        "twitch" => {
            let name = match url_path(raw, &["twitch.tv", "www.twitch.tv"], &mut buf) {
                Some([name]) => name.clone(),
                Some(_) => return Err(link_invalid(&service, "not a Twitch channel address")),
                None => raw.to_string(),
            };
            let name = name.to_ascii_lowercase();
            if !chars_ok(&name, 4, 25, word) {
                return Err(link_invalid(&service, "Twitch name (4–25 characters) expected"));
            }
            (name.clone(), Some(format!("https://www.twitch.tv/{name}")))
        }
        "youtube" => {
            let handle = match url_path(raw, &["youtube.com", "www.youtube.com", "m.youtube.com"], &mut buf) {
                Some([h]) if h.starts_with('@') => h.clone(),
                Some([kind, id]) if kind == "channel" => {
                    if !chars_ok(id, 24, 24, |c| word(c) || c == '-') || !id.starts_with("UC") {
                        return Err(link_invalid(&service, "not a channel id"));
                    }
                    let url = format!("https://www.youtube.com/channel/{id}");
                    return Ok(ProfileLink { service, value: id.clone(), url: Some(url) });
                }
                Some(_) => return Err(link_invalid(&service, "not a YouTube channel address")),
                None => format!("@{}", raw.trim_start_matches('@')),
            };
            if !chars_ok(&handle[1..], 3, 30, |c| word(c) || c == '.' || c == '-') {
                return Err(link_invalid(&service, "YouTube handle like @name expected"));
            }
            (handle.clone(), Some(format!("https://www.youtube.com/{handle}")))
        }
        "x" => {
            let handle = match url_path(raw, &["x.com", "twitter.com", "www.x.com", "www.twitter.com"], &mut buf) {
                Some([h]) => h.clone(),
                Some(_) => return Err(link_invalid(&service, "not an X profile address")),
                None => raw.trim_start_matches('@').to_string(),
            };
            if !chars_ok(&handle, 1, 15, word) {
                return Err(link_invalid(&service, "X name (up to 15 characters) expected"));
            }
            (format!("@{handle}"), Some(format!("https://x.com/{handle}")))
        }
        "mastodon" => {
            // @user@instance.example
            let Some((user, host)) = raw.trim_start_matches('@').split_once('@') else {
                return Err(link_invalid(&service, "address like @name@instance.example expected"));
            };
            let host = host.to_ascii_lowercase();
            if !chars_ok(user, 1, 30, word) || !public_host(&host) || host.len() > 100 {
                return Err(link_invalid(&service, "address like @name@instance.example expected"));
            }
            (format!("@{user}@{host}"), Some(format!("https://{host}/@{user}")))
        }
        "website" => {
            let url = reqwest::Url::parse(raw).map_err(|_| link_invalid(&service, "https address expected"))?;
            let host = url.host_str().unwrap_or("").to_ascii_lowercase();
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some()
                || !public_host(&host)
                || url.as_str().len() > 256
            {
                return Err(link_invalid(&service, "https address of a public host expected"));
            }
            let shown = format!("{host}{}", url.path().trim_end_matches('/'));
            (shown.chars().take(LINK_VALUE_MAX).collect(), Some(url.to_string()))
        }
        _ => return Err(bad("profile.link_service", format!("Unknown service {service}"))),
    };
    Ok(ProfileLink { service, value, url })
}

/// Validates the whole list (at most [`MAX_LINKS`]).
pub fn validate_links(links: &[ProfileLinkInput]) -> Result<Vec<ProfileLink>, ApiError> {
    if links.len() > MAX_LINKS {
        return Err(bad("profile.links_too_many", format!("At most {MAX_LINKS} linked accounts")));
    }
    links.iter().map(validate_link).collect()
}

/// Validates a bio: at most [`BIO_MAX_CHARS`] characters, line breaks allowed, no other control chars.
pub fn validate_bio(bio: &str) -> Result<String, ApiError> {
    let bio = bio.trim();
    if bio.chars().count() > BIO_MAX_CHARS {
        return Err(bad("profile.bio_too_long", format!("At most {BIO_MAX_CHARS} characters")));
    }
    if bio.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(bad("validation.control_chars", "bio: contains disallowed control characters"));
    }
    Ok(bio.to_string())
}

/// Parses stored links; broken JSON (never written by this node) counts as none.
pub fn parse_links(json: &str) -> Vec<ProfileLink> {
    serde_json::from_str(json).unwrap_or_default()
}

fn sha(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data))
}

/// A stored image: media id and whether it has an animated variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMedia {
    pub id: String,
    pub animated: bool,
}

/// Stores the files of a processed (or mirrored) image and its `media` row.
pub async fn store_media(
    state: &AppState,
    kind: &str,
    owner_id: &str,
    still: &[u8],
    still_mime: &str,
    animated: Option<&[u8]>,
) -> Result<StoredMedia, ApiError> {
    let id = util::ulid();
    let animated_id = animated.map(|_| util::ulid());
    state.storage.write(&id, still).await?;
    if let (Some(aid), Some(data)) = (&animated_id, animated)
        && let Err(e) = state.storage.write(aid, data).await
    {
        state.storage.delete(&id).await;
        return Err(e.into());
    }
    let inserted = store::media::insert(
        &state.db,
        NewMedia {
            id: &id,
            animated_id: animated_id.as_deref(),
            kind,
            owner_id,
            mime: still_mime,
            still_size: still.len() as i64,
            animated_size: animated.map_or(0, |a| a.len() as i64),
            still_sha256: &sha(still),
            animated_sha256: animated.map(sha).as_deref(),
        },
    )
    .await;
    if let Err(e) = inserted {
        state.storage.delete(&id).await;
        if let Some(aid) = &animated_id {
            state.storage.delete(aid).await;
        }
        return Err(e);
    }
    Ok(StoredMedia { id, animated: animated_id.is_some() })
}

/// Deletes a media row and its files.
pub async fn delete_media(state: &AppState, id: &str) -> Result<(), ApiError> {
    if let Some(row) = store::media::delete(&state.db, id).await? {
        state.storage.delete(&row.id).await;
        if let Some(aid) = row.animated_id.filter(|a| util::is_ulid(a)) {
            state.storage.delete(&aid).await;
        }
    }
    Ok(())
}

/// Runs an upload through the pipeline and stores the result.
pub async fn convert_and_store(
    state: &AppState,
    kind: MediaKind,
    owner_id: &str,
    body: Bytes,
) -> Result<StoredMedia, ApiError> {
    let Processed { still, still_mime, animated } = state.media.process(kind, body).await?;
    store_media(state, kind.as_str(), owner_id, &still, still_mime, animated.as_deref()).await
}

/// Replaces (or with `None` removes) a user's avatar, header or background; the old files go.
pub async fn set_user_media(
    state: &AppState,
    user_id: &str,
    kind: MediaKind,
    media: Option<&StoredMedia>,
) -> Result<(), ApiError> {
    let previous = store::media::set_user_media(
        &state.db,
        user_id,
        kind.as_str(),
        media.map(|m| m.id.as_str()),
        media.is_some_and(|m| m.animated),
    )
    .await?;
    if let Some(old) = previous.filter(|old| media.is_none_or(|m| m.id != *old)) {
        delete_media(state, &old).await?;
    }
    Ok(())
}

/// Replaces (or removes) a room's icon; the old files go.
pub async fn set_room_icon(state: &AppState, room_id: &str, media: Option<&StoredMedia>) -> Result<(), ApiError> {
    let previous = store::media::set_room_icon(
        &state.db,
        room_id,
        media.map(|m| m.id.as_str()),
        media.is_some_and(|m| m.animated),
    )
    .await?;
    if let Some(old) = previous.filter(|old| media.is_none_or(|m| m.id != *old)) {
        delete_media(state, &old).await?;
    }
    Ok(())
}

/// Tells the user's rooms, friends and DM contacts on this node that the public profile changed
/// (`user.update { user }`), so their clients refresh names and avatars, and for a local user the other nodes
/// that mirror the profile (`profile.changed`, FEDERATION.md §5.2; coalesced in the outbox).
pub async fn announce_user(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    let Some(user) = store::users::by_id(&state.db, user_id).await? else { return Ok(()) };
    let data = serde_json::json!({ "user": user.to_public() });
    for room_id in store::rooms::room_ids_of_user(&state.db, user_id).await? {
        state.hub.room(&room_id, "user.update", &data);
    }
    let mut users = store::social::contact_ids(&state.db, user_id).await?;
    users.extend(store::social::friends_of(&state.db, user_id).await?.into_iter().map(|(id, _)| id));
    users.push(user_id.to_string());
    users.sort();
    users.dedup();
    state.hub.users(users, "user.update", &data);
    // The change itself is stored: a failure to queue the notification must not fail it (the other nodes then
    // refresh with the next federated login or after 24 hours, FEDERATION.md §2.7).
    if let Err(e) = crate::federation::remote::profile_changed(state, &user).await {
        tracing::warn!(error = %e, "profile.changed could not be queued");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn link(service: &str, value: &str) -> Result<ProfileLink, String> {
        validate_link(&ProfileLinkInput { service: service.into(), value: value.into(), url: None })
            .map_err(|e| e.code().to_string())
    }

    fn ok(service: &str, value: &str) -> (String, Option<String>) {
        let l = link(service, value).unwrap();
        (l.value, l.url)
    }

    #[test]
    fn gaming_ids_are_validated() {
        assert_eq!(ok("battlenet", "Daniel#1234"), ("Daniel#1234".into(), None));
        assert_eq!(link("battlenet", "Daniel"), Err("profile.link_invalid".into()));
        assert_eq!(ok("xbox", "Major Nelson"), ("Major Nelson".into(), None));
        assert_eq!(link("xbox", "<script>"), Err("profile.link_invalid".into()));
        assert_eq!(ok("playstation", "psn_user-1"), ("psn_user-1".into(), None));
        assert_eq!(ok("nintendo", "SW-1234-5678-9012"), ("SW-1234-5678-9012".into(), None));
        assert_eq!(ok("nintendo", "123456789012"), ("SW-1234-5678-9012".into(), None));
        assert_eq!(link("nintendo", "SW-1234"), Err("profile.link_invalid".into()));
        assert_eq!(link("myspace", "x"), Err("profile.link_service".into()));
    }

    #[test]
    fn urls_are_derived_from_allowlisted_hosts() {
        assert_eq!(
            ok("steam", "gabelogannewell"),
            ("gabelogannewell".into(), Some("https://steamcommunity.com/id/gabelogannewell".into()))
        );
        assert_eq!(
            ok("steam", "https://steamcommunity.com/profiles/76561197960287930/"),
            ("76561197960287930".into(), Some("https://steamcommunity.com/profiles/76561197960287930".into()))
        );
        assert_eq!(link("steam", "https://evil.example/id/x"), Err("profile.link_invalid".into()));
        assert_eq!(
            ok("twitch", "https://www.twitch.tv/SomeStreamer"),
            ("somestreamer".into(), Some("https://www.twitch.tv/somestreamer".into()))
        );
        assert_eq!(link("twitch", "http://twitch.tv/abcd"), Err("profile.link_invalid".into()), "https only");
        assert_eq!(ok("youtube", "@tavrn"), ("@tavrn".into(), Some("https://www.youtube.com/@tavrn".into())));
        assert_eq!(ok("x", "@jack"), ("@jack".into(), Some("https://x.com/jack".into())));
        assert_eq!(ok("x", "https://twitter.com/jack"), ("@jack".into(), Some("https://x.com/jack".into())));
        assert_eq!(link("x", "https://x.com:8443/jack"), Err("profile.link_invalid".into()), "no ports");
        assert_eq!(
            ok("mastodon", "@alice@social.example"),
            ("@alice@social.example".into(), Some("https://social.example/@alice".into()))
        );
        assert_eq!(link("mastodon", "@alice@127.0.0.1"), Err("profile.link_invalid".into()));
        assert_eq!(link("mastodon", "@alice@localhost"), Err("profile.link_invalid".into()));
    }

    #[test]
    fn websites_must_be_public_https() {
        assert_eq!(
            ok("website", "https://example.org/about/"),
            ("example.org/about".into(), Some("https://example.org/about/".into()))
        );
        for bad in [
            "http://example.org",
            "javascript:alert(1)",
            "data:text/html,<b>x</b>",
            "https://user:pw@example.org",
            "https://10.0.0.1/",
            "https://[::1]/",
            "https://intranet/",
            "https://example.org:8080/",
            "https://printer.local/",
        ] {
            assert_eq!(link("website", bad), Err("profile.link_invalid".into()), "{bad}");
        }
    }

    #[test]
    fn lists_and_bios_are_bounded() {
        let many: Vec<ProfileLinkInput> =
            (0..11).map(|_| ProfileLinkInput { service: "x".into(), value: "jack".into(), url: None }).collect();
        assert_eq!(validate_links(&many).unwrap_err().code(), "profile.links_too_many");
        assert_eq!(validate_links(&many[..10]).unwrap().len(), 10);
        assert_eq!(validate_bio("  **hi**\nthere ").unwrap(), "**hi**\nthere");
        assert_eq!(validate_bio(&"x".repeat(513)).unwrap_err().code(), "profile.bio_too_long");
        assert_eq!(validate_bio("a\u{7}b").unwrap_err().code(), "validation.control_chars");
        assert_eq!(parse_links("not json"), Vec::new());
    }
}
