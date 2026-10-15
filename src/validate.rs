// SPDX-License-Identifier: AGPL-3.0-only
//! Input validation with uniform error codes.

use serde_json::{Map, Value};

use crate::error::ApiError;

pub fn bad(code: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError::BadRequest { code, detail: detail.into() }
}

/// Trimmed text with a length check in characters; control characters other than newline/tab are forbidden.
pub fn text(field: &str, value: &str, min: usize, max: usize) -> Result<String, ApiError> {
    let v = value.trim();
    let n = v.chars().count();
    if n < min || n > max {
        return Err(bad("validation.length", format!("{field}: between {min} and {max} characters (currently {n})")));
    }
    if v.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(bad("validation.control_chars", format!("{field}: contains disallowed control characters")));
    }
    Ok(v.to_string())
}

/// Single-line name (no line break).
pub fn name(field: &str, value: &str, max: usize) -> Result<String, ApiError> {
    let v = text(field, value, 1, max)?;
    if v.contains('\n') {
        return Err(bad("validation.multiline", format!("{field}: a single line only")));
    }
    Ok(v)
}

/// The rules of a text field in a JSON document (embeds, components, commands, polls, link previews): the length in
/// characters (Unicode scalar values) of the string, trimmed first with `trim`; `controls`: control characters are
/// allowed. Each content type passes the rules of its spec and keeps its own error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextRules {
    pub min: usize,
    pub max: usize,
    pub trim: bool,
    pub controls: bool,
}

/// Why a JSON text field is invalid ([`json_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    /// Not a string.
    NotText,
    /// Shorter than `min` or longer than `max`.
    Length,
    /// Contains control characters where the rules refuse them.
    Control,
}

/// Checks `s` against `rules`; returns it (trimmed when the rules say so).
pub fn text_of(s: &str, rules: TextRules) -> Result<&str, TextError> {
    let s = if rules.trim { s.trim() } else { s };
    let n = s.chars().count();
    if n < rules.min || n > rules.max {
        return Err(TextError::Length);
    }
    if !rules.controls && s.chars().any(char::is_control) {
        return Err(TextError::Control);
    }
    Ok(s)
}

/// A JSON value as text under `rules`: `Ok(None)` when absent or null, `Ok(Some(text))` for a valid string.
pub fn json_text(v: Option<&Value>, rules: TextRules) -> Result<Option<&str>, TextError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => text_of(s, rules).map(Some),
        Some(_) => Err(TextError::NotText),
    }
}

/// The first key of `obj` that `allowed` does not name.
pub fn unknown_key<'a>(obj: &'a Map<String, Value>, allowed: &[&str]) -> Option<&'a str> {
    obj.keys().map(String::as_str).find(|k| !allowed.contains(k))
}

pub fn one_of(field: &str, value: &str, allowed: &[&str]) -> Result<String, ApiError> {
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(bad("validation.enum", format!("{field}: allowed are {}", allowed.join(", "))))
    }
}

pub fn ulid(field: &str, value: &str) -> Result<String, ApiError> {
    if crate::util::is_ulid(value) {
        Ok(value.to_string())
    } else {
        Err(bad("validation.id", format!("{field}: not a valid ID")))
    }
}

pub fn range(field: &str, value: i64, min: i64, max: i64) -> Result<i64, ApiError> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(bad("validation.range", format!("{field}: between {min} and {max}")))
    }
}

pub fn color(value: &str) -> Result<String, ApiError> {
    let ok = value.len() == 7 && value.starts_with('#') && value[1..].chars().all(|c| c.is_ascii_hexdigit());
    if ok { Ok(value.to_lowercase()) } else { Err(bad("validation.color", "Specify the color as #rrggbb")) }
}

pub fn permissions(field: &str, value: &str) -> Result<u64, ApiError> {
    crate::permissions::parse(value)
        .ok_or_else(|| bad("validation.permissions", format!("{field}: invalid permission bitmask")))
}

pub fn limit(value: Option<i64>, default: i64, max: i64) -> i64 {
    value.unwrap_or(default).clamp(1, max)
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_text_rules() {
        use super::{TextError, TextRules, json_text, text_of, unknown_key};
        use serde_json::json;
        let plain = TextRules { min: 1, max: 5, trim: false, controls: false };
        assert_eq!(json_text(None, plain), Ok(None));
        assert_eq!(json_text(Some(&json!(null)), plain), Ok(None));
        assert_eq!(json_text(Some(&json!("ok")), plain), Ok(Some("ok")));
        assert_eq!(json_text(Some(&json!("toolong")), plain), Err(TextError::Length));
        assert_eq!(json_text(Some(&json!("")), plain), Err(TextError::Length));
        assert_eq!(json_text(Some(&json!("a\u{1}")), plain), Err(TextError::Control));
        assert_eq!(json_text(Some(&json!(3)), plain), Err(TextError::NotText));
        let trimmed = TextRules { min: 1, max: 3, trim: true, controls: true };
        assert_eq!(text_of("  äöü  ", trimmed), Ok("äöü"), "characters, not bytes, after trimming");
        assert_eq!(text_of("   ", trimmed), Err(TextError::Length));
        assert_eq!(text_of("a\tb", trimmed), Ok("a\tb"));
        let obj = json!({ "a": 1, "b": 2 });
        assert_eq!(unknown_key(obj.as_object().unwrap(), &["a"]), Some("b"));
        assert_eq!(unknown_key(obj.as_object().unwrap(), &["a", "b"]), None);
    }

    use super::*;

    #[test]
    fn text_trims_and_bounds() {
        assert_eq!(text("f", "  hello ", 1, 10).map_err(|e| e.code().to_string()), Ok("hello".into()));
        assert_eq!(text("f", "", 1, 10).map_err(|e| e.code().to_string()), Err("validation.length".into()));
        assert_eq!(
            text("f", "a\u{0}b", 1, 10).map_err(|e| e.code().to_string()),
            Err("validation.control_chars".into())
        );
        assert!(text("f", "a\nb", 1, 10).is_ok());
        assert!(name("f", "a\nb", 10).is_err());
    }

    #[test]
    fn enums_ids_colors() {
        assert!(one_of("k", "text", &["text", "voice"]).is_ok());
        assert!(one_of("k", "TEXT", &["text", "voice"]).is_err());
        assert!(ulid("id", "nope").is_err());
        assert_eq!(color("#AABBCC").map_err(|_| ()), Ok("#aabbcc".into()));
        assert!(color("red").is_err());
        assert_eq!(limit(Some(500), 50, 100), 100);
        assert_eq!(limit(None, 50, 100), 50);
        assert_eq!(limit(Some(0), 50, 100), 1);
    }
}
