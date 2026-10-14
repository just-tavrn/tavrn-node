// SPDX-License-Identifier: AGPL-3.0-only
//! Polls (protocol PROTOCOL.md §7g): the shape of plaintext polls and votes, the poll hash and the close time.
//!
//! Encrypted polls and votes are opaque to the node; it checks the shape only where it can read the content
//! (unencrypted conversations), the plaintext close time everywhere. The rules mirror `@tavrn/e2ee` (`poll.ts`), so a
//! plaintext poll the node accepts is one every client can render.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{error::ApiError, validate::bad};

pub const POLL_TYPE: &str = "poll";
pub const VOTE_TYPE: &str = "poll.vote";
pub const MAX_QUESTION: usize = 300;
pub const MAX_LABEL: usize = 100;
pub const MAX_ID: usize = 32;
pub const OPTIONS: std::ops::RangeInclusive<usize> = 2..=20;
pub const SLOTS: std::ops::RangeInclusive<usize> = 1..=60;
/// Largest vote content (ciphertext or plaintext JSON) in bytes.
pub const MAX_VOTE_BYTES: usize = 4096;
/// Vote changes (`PUT` and `DELETE`) per user and minute.
pub const VOTES_PER_MINUTE: u32 = 10;
/// A close time lies at least this far ahead when a poll is sent.
pub const MIN_CLOSE_SECS: i64 = 60;
/// … and at most this far.
pub const MAX_CLOSE_SECS: i64 = 366 * 24 * 3600;
/// Closing early may name a time this far in the past (clock skew); the node stores its own clock then.
pub const CLOSE_SKEW_SECS: i64 = 60;

fn poll_invalid(detail: impl Into<String>) -> ApiError {
    bad("message.poll_invalid", detail.into())
}

fn vote_invalid(detail: impl Into<String>) -> ApiError {
    bad("poll.vote_invalid", detail.into())
}

/// An option or slot id: 1–32 characters of `A–Z a–z 0–9 _ -`.
fn valid_id(s: &str) -> bool {
    (1..=MAX_ID).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Trimmed text of 1..=max characters.
fn text(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| {
        let n = s.trim().chars().count();
        n >= 1 && n <= max
    })
}

/// An RFC 3339 date-time with seconds and an explicit offset (`Z` or `±hh:mm`), as polls and votes use them: the
/// same pattern as the clients (`YYYY-MM-DDThh:mm:ss[.f{1,9}](Z|±hh:mm)`), then a real time.
pub fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    let shape = b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19);
    if !shape {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=9).contains(&n) {
            return None;
        }
        rest = &frac[n..];
    }
    let offset_ok = rest == "Z" || {
        let o = rest.as_bytes();
        o.len() == 6 && (o[0] == b'+' || o[0] == b'-') && digits_at(o, 1..3) && o[3] == b':' && digits_at(o, 4..6)
    };
    if !offset_ok {
        return None;
    }
    crate::util::parse_time(s)
}

fn digits_at(b: &[u8], r: std::ops::Range<usize>) -> bool {
    b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit))
}

/// Checks a plaintext poll content object (PROTOCOL.md §7g); `400 message.poll_invalid` otherwise. Unknown fields
/// are allowed.
pub fn validate_poll(obj: &Map<String, Value>) -> Result<(), ApiError> {
    if !text(obj.get("question"), MAX_QUESTION) {
        return Err(poll_invalid(format!("question: 1 to {MAX_QUESTION} characters")));
    }
    let one_of =
        |key: &str, allowed: &[&str]| obj.get(key).and_then(Value::as_str).is_some_and(|v| allowed.contains(&v));
    if !one_of("results_visible", &["always", "after_vote", "after_close"]) {
        return Err(poll_invalid("results_visible: always, after_vote or after_close"));
    }
    if !one_of("votes_visible", &["public", "hidden_until_close"]) {
        return Err(poll_invalid("votes_visible: public or hidden_until_close"));
    }
    let mut ids = std::collections::HashSet::new();
    match obj.get("kind").and_then(Value::as_str) {
        Some("choice") => {
            let options = obj
                .get("options")
                .and_then(Value::as_array)
                .filter(|o| OPTIONS.contains(&o.len()))
                .ok_or_else(|| poll_invalid("options: 2 to 20 entries"))?;
            for o in options {
                let id = o.get("id").and_then(Value::as_str).filter(|id| valid_id(id));
                let Some(id) = id else {
                    return Err(poll_invalid("option ids: 1 to 32 characters of A-Z a-z 0-9 _ -"));
                };
                if !ids.insert(id) {
                    return Err(poll_invalid("option ids must be unique"));
                }
                if !text(o.get("label"), MAX_LABEL) {
                    return Err(poll_invalid(format!("option labels: 1 to {MAX_LABEL} characters")));
                }
            }
            let max = obj.get("max_choices").and_then(Value::as_u64);
            if !max.is_some_and(|m| m >= 1 && m as usize <= options.len()) {
                return Err(poll_invalid("max_choices: 1 to the number of options"));
            }
        }
        Some("date") => {
            let slots = obj
                .get("slots")
                .and_then(Value::as_array)
                .filter(|s| SLOTS.contains(&s.len()))
                .ok_or_else(|| poll_invalid("slots: 1 to 60 entries"))?;
            for s in slots {
                let id = s.get("id").and_then(Value::as_str).filter(|id| valid_id(id));
                let Some(id) = id else {
                    return Err(poll_invalid("slot ids: 1 to 32 characters of A-Z a-z 0-9 _ -"));
                };
                if !ids.insert(id) {
                    return Err(poll_invalid("slot ids must be unique"));
                }
                let start = s.get("start").and_then(Value::as_str).and_then(parse_time);
                let Some(start) = start else {
                    return Err(poll_invalid("slot start: RFC 3339 with an offset"));
                };
                match s.get("end") {
                    None | Some(Value::Null) => {}
                    Some(end) => {
                        if !end.as_str().and_then(parse_time).is_some_and(|e| e > start) {
                            return Err(poll_invalid("slot end: RFC 3339 with an offset, after the start"));
                        }
                    }
                }
                if !matches!(s.get("all_day"), None | Some(Value::Null) | Some(Value::Bool(_))) {
                    return Err(poll_invalid("all_day: a boolean"));
                }
            }
        }
        _ => return Err(poll_invalid("kind: choice or date")),
    }
    Ok(())
}

/// `poll_hash`: lowercase hex SHA-256 of the RFC 8785 (JCS) form of the poll content without its `ctx` member.
pub fn poll_hash(content: &Value) -> Result<String, ApiError> {
    let mut obj = content.as_object().cloned().unwrap_or_default();
    obj.remove("ctx");
    let json = serde_json::to_string(&Value::Object(obj)).map_err(|e| ApiError::Internal(e.into()))?;
    let canonical =
        tavrn_crypto::plaintext::canonical_json(&json).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    Ok(Sha256::digest(canonical.as_bytes()).iter().map(|b| format!("{b:02x}")).collect())
}

/// Checks a plaintext vote against the plaintext poll it answers (PROTOCOL.md §7g): `type`, `voted_at`, `ctx` (the
/// message id and the poll's current hash), and choices or answers that fit the poll. `400 poll.vote_invalid`.
pub fn validate_vote(vote: &Value, poll: &Value, message_id: &str) -> Result<(), ApiError> {
    let v = vote.as_object().ok_or_else(|| vote_invalid("content must be the vote object"))?;
    if v.get("type").and_then(Value::as_str) != Some(VOTE_TYPE) {
        return Err(vote_invalid("type must be poll.vote"));
    }
    if v.get("voted_at").and_then(Value::as_str).and_then(parse_time).is_none() {
        return Err(vote_invalid("voted_at: RFC 3339 with an offset"));
    }
    let ctx = v.get("ctx").and_then(Value::as_object).filter(|c| c.len() == 2);
    let (Some(ctx_poll), Some(ctx_hash)) = (
        ctx.and_then(|c| c.get("poll")).and_then(Value::as_str),
        ctx.and_then(|c| c.get("poll_hash")).and_then(Value::as_str),
    ) else {
        return Err(vote_invalid("ctx: { poll, poll_hash }"));
    };
    if ctx_poll != message_id {
        return Err(vote_invalid("ctx.poll must name this message"));
    }
    if ctx_hash != poll_hash(poll)? {
        return Err(vote_invalid("ctx.poll_hash does not match the poll"));
    }
    let ids_of = |key: &str| -> std::collections::HashSet<&str> {
        poll.get(key)
            .and_then(Value::as_array)
            .map(|l| l.iter().filter_map(|o| o.get("id").and_then(Value::as_str)).collect())
            .unwrap_or_default()
    };
    match poll.get("kind").and_then(Value::as_str) {
        Some("choice") => {
            let ids = ids_of("options");
            let max = poll.get("max_choices").and_then(Value::as_u64).unwrap_or(1) as usize;
            let choices = v.get("choices").and_then(Value::as_array);
            let fits = v.get("answers").is_none()
                && choices.is_some_and(|c| {
                    let picked: std::collections::HashSet<&str> = c.iter().filter_map(Value::as_str).collect();
                    !c.is_empty()
                        && c.len() <= max
                        && picked.len() == c.len()
                        && picked.iter().all(|id| ids.contains(id))
                });
            if !fits {
                return Err(vote_invalid(format!("choices: 1 to {max} distinct option ids of the poll")));
            }
        }
        Some("date") => {
            let ids = ids_of("slots");
            let answers = v.get("answers").and_then(Value::as_object);
            let fits = v.get("choices").is_none()
                && answers.is_some_and(|a| {
                    !a.is_empty()
                        && a.iter().all(|(k, val)| {
                            ids.contains(k.as_str()) && matches!(val.as_str(), Some("yes" | "maybe" | "no"))
                        })
                });
            if !fits {
                return Err(vote_invalid("answers: slot ids of the poll mapped to yes, maybe or no"));
            }
        }
        _ => return Err(bad("poll.not_a_poll", "The message is not a poll")),
    }
    Ok(())
}

/// The close time of a new poll: RFC 3339 with offset, one minute to a year ahead; returned in the node's UTC form.
pub fn closes_at_for_create(s: &str, now: DateTime<Utc>) -> Result<String, ApiError> {
    let t = parse_time(s).ok_or_else(|| closes_invalid("poll_closes_at: RFC 3339 with an offset"))?;
    if t < now + chrono::Duration::seconds(MIN_CLOSE_SECS) || t > now + chrono::Duration::seconds(MAX_CLOSE_SECS) {
        return Err(closes_invalid("poll_closes_at: 1 minute to 1 year ahead"));
    }
    Ok(crate::util::format_time(t))
}

/// The new close time when a poll closes early: earlier than the current one (which has not passed) and not more than
/// a minute before the node's clock; the node stores the later of the given time and its clock.
pub fn closes_at_for_close(s: &str, current: Option<&str>, now: DateTime<Utc>) -> Result<String, ApiError> {
    let t = parse_time(s).ok_or_else(|| closes_invalid("poll_closes_at: RFC 3339 with an offset"))?;
    let Some(current) = current.and_then(crate::util::parse_time) else {
        return Err(closes_invalid("This message has no close time; a poll without one cannot be closed"));
    };
    if current <= now {
        return Err(closed());
    }
    if t >= current {
        return Err(closes_invalid("A close time only moves earlier"));
    }
    if t < now - chrono::Duration::seconds(CLOSE_SKEW_SECS) {
        return Err(closes_invalid("poll_closes_at lies in the past"));
    }
    Ok(crate::util::format_time(t.max(now)))
}

fn closes_invalid(detail: &str) -> ApiError {
    bad("message.poll_closes_invalid", detail.to_string())
}

/// `409 poll.closed`.
pub fn closed() -> ApiError {
    ApiError::Conflict { code: "poll.closed", detail: "The poll is closed".into(), meta: Value::Null }
}

/// Has the close time (stored by the node, UTC) passed?
pub fn is_closed(closes_at: Option<&str>, now: DateTime<Utc>) -> bool {
    closes_at.and_then(crate::util::parse_time).is_some_and(|t| t <= now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    fn code(r: Result<(), ApiError>) -> Result<(), String> {
        r.map_err(|e| e.code().to_string())
    }

    fn choice() -> Value {
        json!({ "type": "poll", "kind": "choice", "question": "Lunch?", "options": [{ "id": "a", "label": "Pizza" }, { "id": "b", "label": "Salad" }, { "id": "c", "label": "Soup" }], "max_choices": 2, "results_visible": "always", "votes_visible": "public" })
    }

    fn date() -> Value {
        json!({ "type": "poll", "kind": "date", "question": "Dinner?", "slots": [{ "id": "s1", "start": "2026-11-06T19:00:00+01:00", "end": "2026-11-06T22:00:00+01:00" }, { "id": "s2", "start": "2026-11-07T00:00:00+01:00", "all_day": true }], "results_visible": "after_vote", "votes_visible": "hidden_until_close" })
    }

    fn with(mut v: Value, key: &str, value: Value) -> Value {
        v.as_object_mut().unwrap().insert(key.into(), value);
        v
    }

    fn check(v: &Value) -> Result<(), String> {
        code(validate_poll(v.as_object().unwrap()))
    }

    #[test]
    fn times_need_seconds_and_an_offset() {
        for ok in ["2026-11-06T19:00:00Z", "2026-11-06T19:00:00+01:00", "2026-11-06T19:00:00.123456789-05:30"] {
            assert!(parse_time(ok).is_some(), "{ok}");
        }
        for bad in [
            "2026-11-06T19:00:00",
            "2026-11-06 19:00:00Z",
            "2026-11-06t19:00:00Z",
            "2026-11-06T19:00Z",
            "2026-11-06",
            "2026-13-06T19:00:00Z",
            "2026-11-06T19:00:00.Z",
            "2026-11-06T19:00:00+0100",
            "",
        ] {
            assert!(parse_time(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn plaintext_polls_are_checked() {
        assert_eq!(check(&choice()), Ok(()));
        assert_eq!(check(&date()), Ok(()));
        assert_eq!(check(&with(choice(), "extra", json!(1))), Ok(()), "unknown fields are ignored");
        let bad = "message.poll_invalid".to_string();
        for v in [
            with(choice(), "kind", json!("ranked")),
            with(choice(), "question", json!("  ")),
            with(choice(), "question", json!("x".repeat(301))),
            with(choice(), "options", json!([{ "id": "a", "label": "A" }])),
            with(
                choice(),
                "options",
                json!((0..21).map(|i| json!({ "id": format!("o{i}"), "label": "x" })).collect::<Vec<_>>()),
            ),
            with(choice(), "options", json!([{ "id": "a", "label": "A" }, { "id": "a", "label": "B" }])),
            with(choice(), "options", json!([{ "id": "a b", "label": "A" }, { "id": "b", "label": "B" }])),
            with(choice(), "options", json!([{ "id": "x".repeat(33), "label": "A" }, { "id": "b", "label": "B" }])),
            with(choice(), "options", json!([{ "id": "a", "label": "x".repeat(101) }, { "id": "b", "label": "B" }])),
            with(choice(), "max_choices", json!(0)),
            with(choice(), "max_choices", json!(4)),
            with(choice(), "max_choices", json!(1.5)),
            with(choice(), "results_visible", json!("never")),
            with(choice(), "votes_visible", json!("anonymous")),
            with(date(), "slots", json!([])),
            with(
                date(),
                "slots",
                json!(
                    (0..61)
                        .map(|i| json!({ "id": format!("s{i}"), "start": "2026-11-06T19:00:00Z" }))
                        .collect::<Vec<_>>()
                ),
            ),
            with(date(), "slots", json!([{ "id": "s1", "start": "2026-11-06T19:00:00" }])),
            with(
                date(),
                "slots",
                json!([{ "id": "s1", "start": "2026-11-06T19:00:00Z", "end": "2026-11-06T18:00:00Z" }]),
            ),
            with(date(), "slots", json!([{ "id": "s1", "start": "2026-11-06T19:00:00Z", "all_day": "yes" }])),
            with(
                date(),
                "slots",
                json!([{ "id": "s1", "start": "2026-11-06T19:00:00Z" }, { "id": "s1", "start": "2026-11-07T19:00:00Z" }]),
            ),
        ] {
            assert_eq!(check(&v), Err(bad.clone()), "{v}");
        }
    }

    #[test]
    fn the_poll_hash_matches_the_protocol_vectors() {
        let v: Value = serde_json::from_str(include_str!("../protocol/testvectors/polls.json")).unwrap();
        let p = &v["poll_vote"];
        let poll: Value = serde_json::from_str(p["poll_input"].as_str().unwrap()).unwrap();
        assert_eq!(poll_hash(&poll).unwrap(), p["poll_hash"].as_str().unwrap());
        assert_eq!(poll_hash(&p["date_poll"]).unwrap(), p["date_poll_hash"].as_str().unwrap());
        // The plaintext vote of the vectors answers the date poll.
        let message_id = p["plaintext_vote"]["ctx"]["poll"].as_str().unwrap();
        assert_eq!(code(validate_vote(&p["plaintext_vote"], &p["date_poll"], message_id)), Ok(()));
    }

    #[test]
    fn plaintext_votes_are_checked_against_the_poll() {
        let poll = choice();
        let hash = poll_hash(&poll).unwrap();
        let vote = |choices: Value| json!({ "type": "poll.vote", "choices": choices, "voted_at": "2026-11-01T18:00:00Z", "ctx": { "poll": "M1", "poll_hash": hash } });
        assert_eq!(code(validate_vote(&vote(json!(["a", "c"])), &poll, "M1")), Ok(()));
        let bad = Err("poll.vote_invalid".to_string());
        assert_eq!(code(validate_vote(&vote(json!(["a"])), &poll, "M2")), bad, "another poll");
        assert_eq!(code(validate_vote(&vote(json!(["a", "b", "c"])), &poll, "M1")), bad, "too many");
        assert_eq!(code(validate_vote(&vote(json!(["a", "a"])), &poll, "M1")), bad, "duplicates");
        assert_eq!(code(validate_vote(&vote(json!(["z"])), &poll, "M1")), bad, "unknown option");
        assert_eq!(code(validate_vote(&vote(json!([])), &poll, "M1")), bad, "empty");
        let edited = with(poll.clone(), "question", json!("Dinner?"));
        assert_eq!(code(validate_vote(&vote(json!(["a"])), &edited, "M1")), bad, "stale hash");
        let mut extra_ctx = vote(json!(["a"]));
        extra_ctx["ctx"]["x"] = json!(1);
        assert_eq!(code(validate_vote(&extra_ctx, &poll, "M1")), bad);
        assert_eq!(code(validate_vote(&with(vote(json!(["a"])), "type", json!("text")), &poll, "M1")), bad);
        assert_eq!(code(validate_vote(&with(vote(json!(["a"])), "voted_at", json!("now")), &poll, "M1")), bad);
        let d = date();
        let dh = poll_hash(&d).unwrap();
        let answers = |a: Value| json!({ "type": "poll.vote", "answers": a, "voted_at": "2026-11-01T18:00:00+01:00", "ctx": { "poll": "M", "poll_hash": dh } });
        assert_eq!(code(validate_vote(&answers(json!({ "s1": "yes", "s2": "no" })), &d, "M")), Ok(()));
        assert_eq!(code(validate_vote(&answers(json!({ "s9": "yes" })), &d, "M")), bad);
        assert_eq!(code(validate_vote(&answers(json!({ "s1": "perhaps" })), &d, "M")), bad);
        assert_eq!(code(validate_vote(&answers(json!({})), &d, "M")), bad);
        assert_eq!(
            code(validate_vote(&vote(json!(["a"])), &json!({ "type": "text", "body": "hi" }), "M1")),
            Err("poll.vote_invalid".into()),
            "the hash of a text message never matches"
        );
    }

    #[test]
    fn close_times() {
        let now = crate::util::parse_time("2026-11-01T12:00:00Z").unwrap();
        let ok = |s: &str| closes_at_for_create(s, now).map_err(|e| e.code().to_string());
        assert_eq!(ok("2026-11-01T14:00:00+01:00"), Ok("2026-11-01T13:00:00.000Z".into()));
        assert_eq!(ok("2026-11-01T12:00:30Z"), Err("message.poll_closes_invalid".into()), "less than a minute");
        assert_eq!(ok("2027-12-01T12:00:00Z"), Err("message.poll_closes_invalid".into()), "more than a year");
        assert_eq!(ok("tomorrow"), Err("message.poll_closes_invalid".into()));
        let close = |s: &str, cur: Option<&str>| closes_at_for_close(s, cur, now).map_err(|e| e.code().to_string());
        let cur = Some("2026-11-02T00:00:00.000Z");
        assert_eq!(close("2026-11-01T18:00:00Z", cur), Ok("2026-11-01T18:00:00.000Z".into()));
        assert_eq!(close("2026-11-01T11:59:30Z", cur), Ok("2026-11-01T12:00:00.000Z".into()), "now, not the past");
        assert_eq!(close("2026-11-01T11:58:00Z", cur), Err("message.poll_closes_invalid".into()));
        assert_eq!(close("2026-11-03T00:00:00Z", cur), Err("message.poll_closes_invalid".into()), "never later");
        assert_eq!(close("2026-11-01T18:00:00Z", None), Err("message.poll_closes_invalid".into()), "never from null");
        assert_eq!(close("2026-11-01T18:00:00Z", Some("2026-11-01T11:00:00.000Z")), Err("poll.closed".into()));
        assert!(is_closed(Some("2026-11-01T12:00:00.000Z"), now));
        assert!(!is_closed(Some("2026-11-01T12:00:01.000Z"), now));
        assert!(!is_closed(None, now));
    }
}
