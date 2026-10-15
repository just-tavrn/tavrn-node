// SPDX-License-Identifier: AGPL-3.0-only
//! Embeds in `text` content (protocol/APPLICATIONS.md §6.4): the node's half of the shared content codec.
//!
//! Plaintext content is checked here when it is sent (every author: users, bots, webhooks); encrypted content
//! is checked by the clients with the same rules (`@tavrn/e2ee` in tavrn-js, `e2ee/src/embeds.ts`). Embeds carry text,
//! one `https://` link and a colour, never images: clients never load anything from foreign hosts for them.

use serde_json::Value;

use crate::error::ApiError;

/// Embeds per message.
pub const MAX_EMBEDS: usize = 10;
/// Characters over all text fields of all embeds of a message (title, description, field names and values,
/// footer).
pub const MAX_TOTAL_CHARS: usize = 6000;
pub const MAX_TITLE: usize = 256;
pub const MAX_DESCRIPTION: usize = 4096;
pub const MAX_URL: usize = 2048;
pub const MAX_FIELDS: usize = 25;
pub const MAX_FIELD_NAME: usize = 256;
pub const MAX_FIELD_VALUE: usize = 1024;
pub const MAX_FOOTER: usize = 2048;
pub const MAX_COLOR: u64 = 0xFF_FFFF;

fn invalid(detail: impl Into<String>) -> ApiError {
    ApiError::BadRequest { code: "message.embeds_invalid", detail: detail.into() }
}

/// An optional string of at most `max` characters; returns its length in characters.
fn text(obj: &serde_json::Map<String, Value>, key: &str, max: usize) -> Result<usize, ApiError> {
    let rules = crate::validate::TextRules { min: 0, max, trim: false, controls: true };
    match crate::validate::json_text(obj.get(key), rules) {
        Ok(s) => Ok(s.map_or(0, |s| s.chars().count())),
        Err(crate::validate::TextError::NotText) => Err(invalid(format!("embeds: {key} must be a string"))),
        Err(_) => Err(invalid(format!("embeds: {key} has at most {max} characters"))),
    }
}

/// `https://` with a host, without credentials, at most [`MAX_URL`] characters.
pub fn valid_url(url: &str) -> bool {
    if url.len() > MAX_URL || !url.starts_with("https://") || url.chars().any(char::is_whitespace) {
        return false;
    }
    match reqwest::Url::parse(url) {
        Ok(u) => {
            u.scheme() == "https"
                && u.host_str().is_some_and(|h| !h.is_empty())
                && u.username().is_empty()
                && u.password().is_none()
        }
        Err(_) => false,
    }
}

/// Validates the `embeds` value of a `text` content object (`400 message.embeds_invalid`).
pub fn validate(embeds: &Value) -> Result<(), ApiError> {
    let list = embeds.as_array().ok_or_else(|| invalid("embeds must be an array"))?;
    if list.len() > MAX_EMBEDS {
        return Err(invalid(format!("At most {MAX_EMBEDS} embeds")));
    }
    let mut total = 0;
    for embed in list {
        let obj = embed.as_object().ok_or_else(|| invalid("Every embed is an object"))?;
        let title = text(obj, "title", MAX_TITLE)?;
        let description = text(obj, "description", MAX_DESCRIPTION)?;
        let footer = text(obj, "footer", MAX_FOOTER)?;
        total += title + description + footer;
        match obj.get("url") {
            None | Some(Value::Null) => {}
            Some(Value::String(u)) if valid_url(u) => {}
            Some(_) => return Err(invalid("embeds: url must be an https:// URL without credentials")),
        }
        match obj.get("color") {
            None | Some(Value::Null) => {}
            Some(Value::Number(n)) if n.as_u64().is_some_and(|c| c <= MAX_COLOR) => {}
            Some(_) => return Err(invalid("embeds: color is an integer from 0 to 16777215")),
        }
        match obj.get("timestamp") {
            None | Some(Value::Null) => {}
            Some(Value::String(t)) if t.len() <= 64 && crate::util::parse_time(t).is_some() => {}
            Some(_) => return Err(invalid("embeds: timestamp must be an RFC 3339 time")),
        }
        let mut has_fields = false;
        match obj.get("fields") {
            None | Some(Value::Null) => {}
            Some(Value::Array(fields)) => {
                if fields.len() > MAX_FIELDS {
                    return Err(invalid(format!("embeds: at most {MAX_FIELDS} fields")));
                }
                for field in fields {
                    let f = field.as_object().ok_or_else(|| invalid("embeds: every field is an object"))?;
                    let name = text(f, "name", MAX_FIELD_NAME)?;
                    let value = text(f, "value", MAX_FIELD_VALUE)?;
                    if name == 0 || value == 0 {
                        return Err(invalid("embeds: fields need a name and a value"));
                    }
                    if !matches!(f.get("inline"), None | Some(Value::Null) | Some(Value::Bool(_))) {
                        return Err(invalid("embeds: inline must be a boolean"));
                    }
                    total += name + value;
                }
                has_fields = !fields.is_empty();
            }
            Some(_) => return Err(invalid("embeds: fields must be an array")),
        }
        if title + description + footer == 0 && !has_fields {
            return Err(invalid("An embed needs a title, a description, fields or a footer"));
        }
    }
    if total > MAX_TOTAL_CHARS {
        return Err(invalid(format!("Embeds have at most {MAX_TOTAL_CHARS} characters in total")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    fn code(v: Value) -> Result<(), String> {
        validate(&v).map_err(|e| e.code().to_string())
    }

    #[test]
    fn the_example_of_the_spec_is_valid() {
        let embed = json!({ "title": "Build #128", "description": "All **42** tests passed", "url": "https://ci.example/b/128",
            "color": 3066993, "fields": [ { "name": "Branch", "value": "main", "inline": true } ],
            "footer": "ci.example", "timestamp": "2026-10-05T12:00:00Z" });
        assert_eq!(code(json!([embed])), Ok(()));
        assert_eq!(code(json!([])), Ok(()));
        assert_eq!(
            code(json!([{ "title": "t", "future_field": 1 }])),
            Ok(()),
            "unknown fields are compatible additions"
        );
    }

    #[test]
    fn limits_and_shapes_are_enforced() {
        let bad = Err("message.embeds_invalid".to_string());
        let t = |s: &str| json!([{ "title": s }]);
        assert_eq!(code(json!({ "title": "x" })), bad);
        assert_eq!(code(json!([{}])), bad, "an empty embed");
        assert_eq!(code(json!(["x"])), bad);
        assert_eq!(code(Value::Array(vec![json!({ "title": "x" }); 11])), bad);
        assert_eq!(code(t(&"a".repeat(256))), Ok(()));
        assert_eq!(code(t(&"a".repeat(257))), bad);
        assert_eq!(code(t(&"ä".repeat(256))), Ok(()), "characters, not bytes");
        assert_eq!(code(json!([{ "description": "d".repeat(4097) }])), bad);
        assert_eq!(code(json!([{ "footer": "f".repeat(2049) }])), bad);
        assert_eq!(code(json!([{ "title": 5 }])), bad);
        for url in [
            "http://ci.example",
            "javascript:alert(1)",
            "https://user:pw@ci.example/",
            "https://",
            "https://a b.example",
        ] {
            assert_eq!(code(json!([{ "title": "x", "url": url }])), bad, "{url}");
        }
        assert_eq!(code(json!([{ "title": "x", "url": format!("https://a.example/{}", "p".repeat(2048)) }])), bad);
        for color in [json!(-1), json!(16_777_216), json!(1.5), json!("#fff")] {
            assert_eq!(code(json!([{ "title": "x", "color": color }])), bad, "{color}");
        }
        assert_eq!(code(json!([{ "title": "x", "color": 16_777_215 }])), Ok(()));
        assert_eq!(code(json!([{ "title": "x", "timestamp": "yesterday" }])), bad);
        let field = json!({ "name": "n", "value": "v" });
        assert_eq!(code(json!([{ "fields": vec![field.clone(); 25] }])), Ok(()));
        assert_eq!(code(json!([{ "fields": vec![field; 26] }])), bad);
        assert_eq!(code(json!([{ "fields": [{ "name": "n".repeat(257), "value": "v" }] }])), bad);
        assert_eq!(code(json!([{ "fields": [{ "name": "n", "value": "v".repeat(1025) }] }])), bad);
        assert_eq!(code(json!([{ "fields": [{ "name": "", "value": "v" }] }])), bad);
        assert_eq!(code(json!([{ "fields": [{ "name": "n", "value": "v", "inline": "yes" }] }])), bad);
    }

    #[test]
    fn the_total_over_all_embeds_is_capped() {
        let one = json!({ "description": "d".repeat(4000) });
        assert_eq!(code(json!([one.clone()])), Ok(()));
        assert_eq!(code(json!([one.clone(), one])), Err("message.embeds_invalid".into()));
        let six = json!({ "title": "t".repeat(200), "description": "d".repeat(800) });
        assert_eq!(code(Value::Array(vec![six.clone(); 6])), Ok(()), "exactly 6000");
        let mut seven = vec![six; 6];
        seven.push(json!({ "title": "x" }));
        assert_eq!(code(Value::Array(seven)), Err("message.embeds_invalid".into()));
    }
}
