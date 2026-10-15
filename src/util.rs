// SPDX-License-Identifier: AGPL-3.0-only
//! Small helpers: timestamps, IDs, randomness.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use rand::Rng as _;

/// Now as RFC 3339 in UTC with milliseconds, e.g. `2026-10-04T12:00:00.000Z`.
/// Always the same format, so TEXT timestamps in the database sort lexicographically.
pub fn now() -> String {
    format_time(Utc::now())
}

pub fn format_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

pub fn in_seconds(secs: i64) -> String {
    format_time(Utc::now() + chrono::Duration::seconds(secs))
}

/// Monotonic ULIDs: strictly increasing within the same millisecond, so `ORDER BY id`
/// matches the creation order (messages, events, audit log).
pub fn ulid() -> String {
    use std::sync::Mutex;
    static GEN: Mutex<Option<ulid::Generator>> = Mutex::new(None);
    let mut guard = GEN.lock().unwrap_or_else(|e| e.into_inner());
    let generator = guard.get_or_insert_with(ulid::Generator::new);
    generator.generate().unwrap_or_else(|_| ulid::Ulid::generate()).to_string()
}

pub fn is_ulid(s: &str) -> bool {
    s.len() == 26 && ulid::Ulid::from_string(s).is_ok()
}

/// The operating system's CSPRNG (getrandom) as an infallible generator. Like rand 0.8's `OsRng` it
/// panics if the system RNG fails, instead of ever yielding weak randomness.
pub fn os_rng() -> rand::rand_core::UnwrapErr<rand::rngs::SysRng> {
    rand::rand_core::UnwrapErr(rand::rngs::SysRng)
}

/// Fills `buf` from the operating system's CSPRNG (keys, nonces, secrets).
pub fn fill_random(buf: &mut [u8]) {
    os_rng().fill_bytes(buf);
}

/// 32 random bytes, Base64url without padding (for refresh tokens, invite codes, etc.).
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    fill_random(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn sha256_b64(input: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// Username: 2–32 characters from `[a-z0-9_.-]`, starting with a letter or digit.
pub fn valid_username(s: &str) -> bool {
    (2..=32).contains(&s.len())
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

/// Usernames nobody can register or choose: `wh.*` belongs to the pseudo users of webhooks (APPLICATIONS.md §6.1).
pub fn reserved_username(s: &str) -> bool {
    // `wh.`: webhook pseudo users; `deleted-`: tombstones of deleted accounts.
    s.starts_with("wh.") || s.starts_with("deleted-")
}

/// Domain: lowercase letters, digits, `-`, `.`; no schemes, paths or ports.
pub fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// `alice@node.example` → (`alice`, `node.example`), only if both parts are valid.
pub fn parse_address(s: &str) -> Option<(&str, &str)> {
    let (user, domain) = s.rsplit_once('@')?;
    (valid_username(user) && valid_domain(domain)).then_some((user, domain))
}

/// The byte of a `%XX` escape at the front of `hex` (two hex digits, nothing else: `u8::from_str_radix` alone would
/// also take `+5`).
fn hex_byte(hex: &[u8]) -> Option<u8> {
    match hex {
        [a, b] if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() => {
            let digit = |c: u8| (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok());
            Some(digit(*a)? << 4 | digit(*b)?)
        }
        _ => None,
    }
}

/// Decodes `%XX` escapes (no `+` handling: not a form). Lenient: a `%` without two hex digits stays as it is, and
/// invalid UTF-8 becomes U+FFFD (URL user info, header values, file names).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i] == b'%').then(|| bytes.get(i + 1..i + 3).and_then(hex_byte)).flatten() {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes `%XX` escapes strictly: `None` for a `%` without two hex digits or invalid UTF-8.
pub fn percent_decode_strict(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(hex_byte(bytes.get(i + 1..i + 3)?)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Runs `work` to completion even if the caller is dropped, and waits for it. Axum drops a handler's future when the
/// client disconnects: side effects that must follow a stored change (events, the room's security log, cleared
/// pending removals) go through here, so a closed tab never leaves the change without them. A panic in `work` is
/// logged (as it would have ended the request).
pub async fn detached<F>(work: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Err(e) = tokio::spawn(work).await {
        tracing::error!(error = %e, "detached work did not finish");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("Image%20%C3%A4.png"), "Image ä.png");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%2"), "a%2", "an incomplete sequence is kept");
        assert_eq!(percent_decode("%+5x"), "%+5x", "only hex digits");
        assert_eq!(percent_decode("p%40ss%3Aw"), "p@ss:w");
        assert_eq!(percent_decode("%ff"), "\u{fffd}");
        assert_eq!(percent_decode_strict("Fanfare%20%F0%9F%8E%BA").as_deref(), Some("Fanfare 🎺"));
        assert_eq!(percent_decode_strict("plain").as_deref(), Some("plain"));
        assert_eq!(percent_decode_strict("bad%zz"), None);
        assert_eq!(percent_decode_strict("%+5"), None);
        assert_eq!(percent_decode_strict("%ff"), None);
        assert_eq!(percent_decode_strict("end%4"), None);
    }

    #[test]
    fn os_randomness_fills_every_byte_freshly() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        fill_random(&mut a);
        fill_random(&mut b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
        assert_ne!(random_token(32), random_token(32));
        assert_eq!(random_token(32).len(), 43);
    }

    #[test]
    fn now_is_sortable_rfc3339() {
        let a = now();
        let b = now();
        assert!(a <= b);
        assert!(a.ends_with('Z'));
        assert!(parse_time(&a).is_some());
    }

    #[test]
    fn usernames() {
        for ok in ["ab", "alice", "a1", "1a", "al.ice-x_y", &"a".repeat(32)] {
            assert!(valid_username(ok), "{ok}");
        }
        for bad in ["a", "Alice", "-alice", ".a", "al ice", "al@ice", &"a".repeat(33), "", "äöü"] {
            assert!(!valid_username(bad), "{bad}");
        }
    }

    #[test]
    fn domains() {
        for ok in ["localhost", "node.example", "a-b.c-d.eu", "x1.y2"] {
            assert!(valid_domain(ok), "{ok}");
        }
        for bad in ["", "Node.example", "node..example", "-a.b", "a.b/", "a.b:443", "a_b.c"] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_address("alice@node.example"), Some(("alice", "node.example")));
        assert_eq!(parse_address("alice"), None);
        assert_eq!(parse_address("Alice@node.example"), None);
        assert_eq!(parse_address("alice@Node"), None);
    }

    #[test]
    fn tokens_are_random_and_hash_is_stable() {
        assert_ne!(random_token(32), random_token(32));
        assert_eq!(sha256_b64("x"), sha256_b64("x"));
        assert_ne!(sha256_b64("x"), sha256_b64("y"));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn detached_work_finishes_when_the_caller_is_dropped() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        // The caller (a request handler) waits for the work and is dropped while it runs (the client went away).
        let caller = tokio::spawn(detached(async move {
            let _ = started_tx.send(());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = tx.send("written");
        }));
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(rx.await.unwrap(), "written", "the work ran to its end");
    }

    #[test]
    fn ulids_are_valid_and_monotonic() {
        assert!(is_ulid(&ulid()));
        assert!(!is_ulid("nope"));
        let ids: Vec<String> = (0..1000).map(|_| ulid()).collect();
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "{} < {}", w[0], w[1]);
        }
    }
}
