// SPDX-License-Identifier: AGPL-3.0-only
//! Custom emoji references (PROTOCOL.md §7b).
//!
//! Content and reactions name custom emojis in two forms:
//! - `:name:` – an emoji of the room the conversation belongs to (resolved by name, the old form);
//! - `<:name:ID>` / `<:name:ID@host>` – an emoji by its id: without a host it lives on the node hosting the
//!   conversation, with a host on that node. Readers load it from `GET /api/v1/emojis/{ID}/image` there.
//!
//! An emoji that is not one of the current room's own (a personal emoji, one of another room, one of another
//! node) is *external*: room channels need `use_external_emojis` for it (`403 emoji.external_forbidden`);
//! DMs and group DMs always allow it. The node can check this only where it sees the reference: reactions
//! always, message bodies only in unencrypted channels (encrypted bodies are checked by the clients).

use crate::{
    access::{Conv, ConvKind},
    app::AppState,
    error::ApiError,
    permissions as p, util,
};

/// Personal emoji and clip limits of a user: the entitlements `emoji.max_personal` and
/// `sounds.max_personal` of the acting user (node defaults `TAVRN_EMOJI_MAX_PERSONAL`, `TAVRN_SOUNDS_MAX_PERSONAL`).
/// `None` = unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonalLimits {
    pub emojis: Option<i64>,
    pub sounds: Option<i64>,
}

pub async fn personal_limits(state: &AppState, user: &crate::models::UserRow) -> Result<PersonalLimits, ApiError> {
    let ent = crate::entitlements::Entitlements::load(state, Some(user), None).await?;
    Ok(PersonalLimits {
        emojis: ent.limit(crate::entitlements::EMOJI_MAX_PERSONAL),
        sounds: ent.limit(crate::entitlements::SOUNDS_MAX_PERSONAL),
    })
}

/// Most custom emoji tokens checked per message (more are refused, `message.too_many_emojis`).
pub const MAX_TOKENS: usize = 200;

/// A custom emoji named by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojiRef<'a> {
    pub name: &'a str,
    pub id: &'a str,
    /// The node hosting the emoji; `None` = the node hosting the conversation.
    pub host: Option<&'a str>,
}

/// Emoji names: 2–32 characters of `a-z`, `0-9`, `_`.
pub fn valid_name(s: &str) -> bool {
    (2..=32).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// A ULID in canonical (uppercase) form: ids end up in URLs and must compare byte-wise.
fn canonical_ulid(s: &str) -> bool {
    util::is_ulid(s) && s.bytes().all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
}

/// A node domain as it may appear in a token: lowercase DNS labels, optionally with `:port` (development
/// nodes). Nothing that could change the meaning of a URL (no `/`, `?`, `#`, `@`, userinfo or IPv6 brackets).
pub fn valid_host(s: &str) -> bool {
    let (name, port) = match s.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (s, None),
    };
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    (1..=253).contains(&name.len())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Parses exactly one token `<:name:ID>` or `<:name:ID@host>`.
pub fn parse_token(s: &str) -> Option<EmojiRef<'_>> {
    let inner = s.strip_prefix("<:")?.strip_suffix('>')?;
    let (name, rest) = inner.split_once(':')?;
    let (id, host) = match rest.split_once('@') {
        Some((id, host)) => (id, Some(host)),
        None => (rest, None),
    };
    (valid_name(name) && canonical_ulid(id) && host.is_none_or(valid_host)).then_some(EmojiRef { name, id, host })
}

/// All well-formed tokens in a text (malformed ones are plain text).
pub fn tokens(text: &str) -> Vec<EmojiRef<'_>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<:") {
        let candidate = &rest[start..];
        // name (≤ 32) + id (26) + host (≤ 259) + punctuation: anything longer is not a token.
        let end = candidate.char_indices().take(330).find(|(_, c)| *c == '>' || c.is_whitespace()).map(|(i, _)| i);
        match end.filter(|i| candidate.as_bytes()[*i] == b'>') {
            Some(i) => {
                if let Some(t) = parse_token(&candidate[..=i]) {
                    out.push(t);
                }
                rest = &candidate[i + 1..];
            }
            None => rest = &candidate[2..],
        }
    }
    out
}

/// A Unicode emoji (or any short symbol): 1–16 characters, no whitespace, control characters or `<>`.
fn valid_unicode(e: &str) -> bool {
    let n = e.chars().count();
    (1..=16).contains(&n) && !e.chars().any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>')
}

/// A reaction: a Unicode emoji, `:name:` (the room's emoji) or a token.
pub fn valid_reaction(e: &str) -> bool {
    if e.starts_with('<') {
        return parse_token(e).is_some();
    }
    if let Some(name) = e.strip_prefix(':').and_then(|x| x.strip_suffix(':'))
        && valid_name(name)
    {
        return true;
    }
    valid_unicode(e)
}

/// The emoji of a soundboard clip: a Unicode emoji or a token (`:name:` is ambiguous outside one room).
pub fn valid_sound_emoji(e: &str) -> bool {
    if e.starts_with('<') { parse_token(e).is_some() } else { !e.starts_with(':') && valid_unicode(e) }
}

/// Is `host` this node (or absent)?
fn is_local(state: &AppState, host: Option<&str>) -> bool {
    host.is_none_or(|h| h.eq_ignore_ascii_case(&state.config.domain))
}

/// Of `refs`, those that are not emojis of `room_id` on this node.
pub async fn external<'a>(
    state: &AppState,
    room_id: &str,
    refs: &[EmojiRef<'a>],
) -> Result<Vec<EmojiRef<'a>>, ApiError> {
    let mut ids: Vec<&str> = refs.iter().filter(|r| is_local(state, r.host)).map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    let own = crate::store::emojis::existing_in_room(&state.db, room_id, &ids).await?;
    Ok(refs.iter().filter(|r| !(is_local(state, r.host) && own.contains(r.id))).cloned().collect())
}

pub fn external_forbidden() -> ApiError {
    ApiError::Forbidden {
        code: "emoji.external_forbidden",
        detail: "Emojis from other rooms or personal emojis need use_external_emojis in this channel".into(),
    }
}

/// Checks `refs` against `use_external_emojis` of the conversation (room channels only).
pub async fn check_external(state: &AppState, conv: &Conv, refs: &[EmojiRef<'_>]) -> Result<(), ApiError> {
    if refs.is_empty() || p::has(conv.perms, p::USE_EXTERNAL_EMOJIS) {
        return Ok(());
    }
    let ConvKind::Channel { access, .. } = &conv.kind else {
        return Ok(());
    };
    if refs.len() > MAX_TOKENS {
        return Err(crate::validate::bad("message.too_many_emojis", format!("At most {MAX_TOKENS} custom emojis")));
    }
    if external(state, &access.room.id, refs).await?.is_empty() { Ok(()) } else { Err(external_forbidden()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "01J9ZK8Q4V6X3M2N1P0R5S7T8W";

    #[test]
    fn tokens_parse_strictly() {
        assert_eq!(parse_token(&format!("<:pog:{ID}>")), Some(EmojiRef { name: "pog", id: ID, host: None }));
        assert_eq!(
            parse_token(&format!("<:gg_wp:{ID}@b.example:8443>")),
            Some(EmojiRef { name: "gg_wp", id: ID, host: Some("b.example:8443") })
        );
        for bad in [
            format!("<:Pog:{ID}>"),
            format!("<:p:{ID}>"),
            format!("<:pog:{}>", ID.to_lowercase()),
            "<:pog:NOTANID>".to_string(),
            format!("<:pog:{ID}@>"),
            format!("<:pog:{ID}@evil.example/x>"),
            format!("<:pog:{ID}@evil.example?x>"),
            format!("<:pog:{ID}@user@evil.example>"),
            format!("<:pog:{ID}@[::1]>"),
            format!("<:pog:{ID}@-evil.example>"),
            format!("<:pog:{ID}@evil.example:99999x>"),
            format!("<:pog:{ID}@EVIL.example>"),
            format!("<:pog:{ID}@a..b>"),
            format!("<:pog:{ID}"),
            format!(":pog:{ID}>"),
        ] {
            assert_eq!(parse_token(&bad), None, "{bad}");
        }
    }

    #[test]
    fn tokens_are_found_in_text() {
        let text = format!("hi <:pog:{ID}> and <:gg:{ID}@b.example> but not <:x:{ID}> nor <: pog:{ID}> <:pog:{ID}");
        let found = tokens(&text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "pog");
        assert_eq!(found[1].host, Some("b.example"));
        assert!(tokens("<<:::>>> <:").is_empty());
        assert!(tokens(&"<:".repeat(10_000)).is_empty());
    }

    #[test]
    fn reactions_accept_unicode_names_and_tokens() {
        assert!(valid_reaction("👍"));
        assert!(valid_reaction("🇩🇪"));
        assert!(valid_reaction("👍🏽"));
        assert!(valid_reaction(":custom:"));
        assert!(valid_reaction(":a_very_long_custom_emoji_name_32:"));
        assert!(valid_reaction(&format!("<:pog:{ID}>")));
        assert!(valid_reaction(&format!("<:pog:{ID}@b.example>")));
        assert!(!valid_reaction(""));
        assert!(!valid_reaction("a b"));
        assert!(!valid_reaction(&"x".repeat(17)));
        assert!(!valid_reaction("<:pog:nope>"));
        assert!(!valid_reaction("<b>"));
        assert!(valid_sound_emoji("🎺"));
        assert!(valid_sound_emoji(&format!("<:pog:{ID}>")));
        assert!(!valid_sound_emoji(":pog:"));
        assert!(!valid_sound_emoji("<script>"));
    }
}
