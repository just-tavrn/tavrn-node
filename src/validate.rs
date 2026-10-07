// SPDX-License-Identifier: AGPL-3.0-only
//! Input validation with uniform error codes.

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
