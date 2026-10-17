// SPDX-License-Identifier: AGPL-3.0-only
//! Message components (protocol/APPLICATIONS.md §5.10, `components.v1`): the node's half of the shared rules for
//! buttons and select menus in `text` content, modal definitions and the values users send back.
//!
//! Every refusal names the first offending field in `meta.path`, exactly like `@tavrn/sdk`'s `components.ts`; both
//! run the cases of `protocol/testvectors/components.json`. The node checks plaintext content only: encrypted
//! components are checked by the bots before encrypting and by the clients after decrypting.

use serde_json::{Map, Value, json};

use crate::{error::ApiError, validate::unknown_key};

pub const CAPABILITY: &str = "components.v1";
pub const MODAL_SELECT_CAPABILITY: &str = "components.modal_select.v1";
pub const MAX_ROWS: usize = 5;
pub const MAX_BUTTONS_PER_ROW: usize = 5;
pub const MAX_OPTIONS: usize = 25;
/// The serialized `components` array (UTF-8 JSON) at most.
pub const MAX_COMPONENTS_BYTES: usize = 8 * 1024;
pub const MAX_CUSTOM_ID: usize = 100;
pub const MAX_BUTTON_LABEL: usize = 80;
pub const MAX_PLACEHOLDER: usize = 150;
pub const MAX_OPTION_TEXT: usize = 100;
pub const MAX_EMOJI: usize = 32;
pub const MAX_MODAL_TITLE: usize = 45;
pub const MAX_MODAL_INPUTS: usize = 5;
pub const MAX_INPUT_LABEL: usize = 45;
pub const MAX_INPUT_PLACEHOLDER: usize = 100;
pub const MAX_INPUT_LENGTH: u64 = 4000;
/// `values_ciphertext` at most (like `args_ciphertext`).
pub const MAX_VALUES_CIPHERTEXT: usize = crate::commands::MAX_ARGS_CIPHERTEXT;
/// Encrypted modal values at most: five inputs of 4000 characters (up to 4 bytes each), encrypted and base64url.
pub const MAX_MODAL_CIPHERTEXT: usize = 160 * 1024;
/// A modal submit body at most.
pub const MAX_SUBMIT_BYTES: usize = MAX_MODAL_CIPHERTEXT + 32 * 1024;
/// Content types that only ever travel inside `values_ciphertext`, never as a message.
pub const COMPONENT_VALUES_TYPE: &str = "component.values";
pub const MODAL_VALUES_TYPE: &str = "modal.values";

const BUTTON_STYLES: &[&str] = &["primary", "secondary", "success", "danger", "link"];
const INPUT_STYLES: &[&str] = &["short", "paragraph", "select"];
const ROW_KEYS: &[&str] = &["type", "components"];
const BUTTON_KEYS: &[&str] = &["type", "style", "label", "emoji", "custom_id", "url", "disabled"];
const SELECT_KEYS: &[&str] = &["type", "custom_id", "placeholder", "options", "min", "max", "disabled"];
const OPTION_KEYS: &[&str] = &["label", "value", "description", "emoji", "default"];
const MODAL_OPTION_KEYS: &[&str] = &["label", "value", "description", "emoji"];
const MODAL_KEYS: &[&str] = &["custom_id", "title", "inputs"];
const INPUT_KEYS: &[&str] =
    &["custom_id", "label", "style", "placeholder", "min_length", "max_length", "required", "value"];
const MODAL_SELECT_KEYS: &[&str] = &["custom_id", "label", "style", "placeholder", "options", "required", "value"];

// ---------------------------------------------------------------- errors

fn refused(code: &'static str, path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    ApiError::BadRequestMeta { code, detail: detail.into(), meta: json!({ "path": path.into() }) }
}

/// `400 message.components_invalid` with `meta.path`.
pub fn invalid(path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    refused("message.components_invalid", path, detail)
}

fn modal_invalid(path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    refused("interaction.modal_invalid", path, detail)
}

/// `400 component.values_invalid` with `meta.path`.
pub fn values_invalid(path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    refused("component.values_invalid", path, detail)
}

fn modal_values_invalid(path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    refused("interaction.values_invalid", path, detail)
}

// ---------------------------------------------------------------- field rules

fn absent(v: Option<&Value>) -> bool {
    v.is_none_or(Value::is_null)
}

/// The rules of the component texts: `min`–`max` characters (Unicode scalar values) without control characters.
fn rules(min: usize, max: usize) -> crate::validate::TextRules {
    crate::validate::TextRules { min, max, trim: false, controls: false }
}

/// A string of `min`–`max` characters without control characters.
fn text(v: Option<&Value>, min: usize, max: usize) -> bool {
    matches!(crate::validate::json_text(v, rules(min, max)), Ok(Some(_)))
}

/// `custom_id`: 1–100 characters without control characters.
pub fn valid_custom_id(s: &str) -> bool {
    crate::validate::text_of(s, rules(1, MAX_CUSTOM_ID)).is_ok()
}

/// One Unicode emoji (1–16 characters without whitespace, control characters, `:`, `<`, `>`) or `:name:` (name 2–30
/// of `a-z0-9_`).
pub fn valid_emoji(e: &str) -> bool {
    if e.chars().count() > MAX_EMOJI {
        return false;
    }
    if e.len() >= 2 && e.starts_with(':') && e.ends_with(':') {
        let name = &e[1..e.len() - 1];
        return (2..=30).contains(&name.len())
            && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    }
    let n = e.chars().count();
    (1..=16).contains(&n) && !e.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, ':' | '<' | '>'))
}

fn opt_emoji(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => valid_emoji(s),
        Some(_) => false,
    }
}

fn opt_bool(v: Option<&Value>) -> bool {
    matches!(v, None | Some(Value::Null | Value::Bool(_)))
}

/// An integer in `min..=max`, or `default` when absent; `None` when invalid.
fn int_or(v: Option<&Value>, default: u64, min: u64, max: u64) -> Option<u64> {
    match v {
        None | Some(Value::Null) => Some(default),
        Some(n) => n.as_u64().filter(|n| *n >= min && *n <= max),
    }
}

// ---------------------------------------------------------------- components (§5.10.1)

fn check_button(b: &Map<String, Value>, p: &str) -> Result<(), ApiError> {
    if let Some(k) = unknown_key(b, BUTTON_KEYS) {
        return Err(invalid(format!("{p}.{k}"), "Unknown field"));
    }
    let style = b.get("style").and_then(Value::as_str).filter(|s| BUTTON_STYLES.contains(s));
    let Some(style) = style else {
        return Err(invalid(format!("{p}.style"), "style: primary, secondary, success, danger or link"));
    };
    let has_emoji = !absent(b.get("emoji"));
    let empty = Value::String(String::new());
    let label = if absent(b.get("label")) { Some(&empty) } else { b.get("label") };
    if !text(label, usize::from(!has_emoji), MAX_BUTTON_LABEL) {
        return Err(invalid(format!("{p}.label"), "label: 1 to 80 characters (empty only with an emoji)"));
    }
    if !opt_emoji(b.get("emoji")) {
        return Err(invalid(format!("{p}.emoji"), "emoji: one Unicode emoji or :shortcode:"));
    }
    let link = style == "link";
    let custom_id_ok = if link {
        absent(b.get("custom_id"))
    } else {
        b.get("custom_id").and_then(Value::as_str).is_some_and(valid_custom_id)
    };
    if !custom_id_ok {
        let detail = if link { "Link buttons carry no custom_id" } else { "custom_id: 1 to 100 characters" };
        return Err(invalid(format!("{p}.custom_id"), detail));
    }
    let url_ok = if link {
        b.get("url").and_then(Value::as_str).is_some_and(crate::embeds::valid_url)
    } else {
        absent(b.get("url"))
    };
    if !url_ok {
        let detail = if link { "url: an https:// URL without credentials" } else { "Only link buttons carry a url" };
        return Err(invalid(format!("{p}.url"), detail));
    }
    if !opt_bool(b.get("disabled")) {
        return Err(invalid(format!("{p}.disabled"), "disabled: a boolean"));
    }
    Ok(())
}

fn check_select(s: &Map<String, Value>, p: &str) -> Result<(), ApiError> {
    if let Some(k) = unknown_key(s, SELECT_KEYS) {
        return Err(invalid(format!("{p}.{k}"), "Unknown field"));
    }
    if !s.get("custom_id").and_then(Value::as_str).is_some_and(valid_custom_id) {
        return Err(invalid(format!("{p}.custom_id"), "custom_id: 1 to 100 characters"));
    }
    if !absent(s.get("placeholder")) && !text(s.get("placeholder"), 0, MAX_PLACEHOLDER) {
        return Err(invalid(format!("{p}.placeholder"), "placeholder: at most 150 characters"));
    }
    let options = check_options(s, p, false)?;
    let n = options.len() as u64;
    let min = int_or(s.get("min"), 1, 0, MAX_OPTIONS as u64)
        .filter(|m| *m <= n)
        .ok_or_else(|| invalid(format!("{p}.min"), "min: 0 to 25, at most the number of options"))?;
    int_or(s.get("max"), 1, 1, MAX_OPTIONS as u64)
        .filter(|m| *m >= min && *m <= n)
        .ok_or_else(|| invalid(format!("{p}.max"), "max: 1 to 25, at least min, at most the number of options"))?;
    if !opt_bool(s.get("disabled")) {
        return Err(invalid(format!("{p}.disabled"), "disabled: a boolean"));
    }
    Ok(())
}

/// Message and modal selects share option limits; only message options permit a default flag.
fn check_options<'a>(s: &'a Map<String, Value>, p: &str, modal: bool) -> Result<&'a [Value], ApiError> {
    let error = |path: String, detail: &str| {
        if modal { modal_invalid(path, detail) } else { invalid(path, detail) }
    };
    let keys = if modal { MODAL_OPTION_KEYS } else { OPTION_KEYS };
    let options = match s.get("options") {
        Some(Value::Array(list)) if (1..=MAX_OPTIONS).contains(&list.len()) => list,
        _ => return Err(error(format!("{p}.options"), "options: 1 to 25")),
    };
    let mut values: Vec<&str> = Vec::new();
    for (i, o) in options.iter().enumerate() {
        let q = format!("{p}.options[{i}]");
        let o = o.as_object().ok_or_else(|| error(q.clone(), "An option is an object"))?;
        if let Some(k) = unknown_key(o, keys) {
            return Err(error(format!("{q}.{k}"), "Unknown field"));
        }
        if !text(o.get("label"), 1, MAX_OPTION_TEXT) {
            return Err(error(format!("{q}.label"), "label: 1 to 100 characters"));
        }
        let value = o.get("value").filter(|v| text(Some(v), 1, MAX_OPTION_TEXT)).and_then(Value::as_str);
        match value {
            Some(v) if !values.contains(&v) => values.push(v),
            _ => return Err(error(format!("{q}.value"), "value: 1 to 100 characters, unique")),
        }
        if !absent(o.get("description")) && !text(o.get("description"), 0, MAX_OPTION_TEXT) {
            return Err(error(format!("{q}.description"), "description: at most 100 characters"));
        }
        if !opt_emoji(o.get("emoji")) {
            return Err(error(format!("{q}.emoji"), "emoji: one Unicode emoji or :shortcode:"));
        }
        if !modal && !opt_bool(o.get("default")) {
            return Err(error(format!("{q}.default"), "default: a boolean"));
        }
    }
    Ok(options)
}

/// Checks the `components` value of a `text` content object (`400 message.components_invalid` with `meta.path`).
pub fn validate(components: &Value) -> Result<(), ApiError> {
    let rows = components.as_array().ok_or_else(|| invalid("components", "components is an array of rows"))?;
    let size = serde_json::to_string(components).map_err(|e| ApiError::Internal(e.into()))?.len();
    if size > MAX_COMPONENTS_BYTES {
        return Err(invalid("components", format!("components: at most {MAX_COMPONENTS_BYTES} bytes")));
    }
    if rows.len() > MAX_ROWS {
        return Err(invalid("components", format!("At most {MAX_ROWS} rows")));
    }
    let mut ids: Vec<&str> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let rp = format!("components[{i}]");
        let row = row.as_object().ok_or_else(|| invalid(&rp, "A row is an object"))?;
        if let Some(k) = unknown_key(row, ROW_KEYS) {
            return Err(invalid(format!("{rp}.{k}"), "Unknown field"));
        }
        if row.get("type").and_then(Value::as_str) != Some("row") {
            return Err(invalid(format!("{rp}.type"), "type: \"row\""));
        }
        let items = match row.get("components") {
            Some(Value::Array(list)) if (1..=MAX_BUTTONS_PER_ROW).contains(&list.len()) => list,
            _ => return Err(invalid(format!("{rp}.components"), "A row holds 1 to 5 buttons or one select")),
        };
        if items.len() > 1 && items.iter().any(|e| e.get("type").and_then(Value::as_str) == Some("select")) {
            return Err(invalid(format!("{rp}.components"), "A select fills its row alone"));
        }
        for (j, el) in items.iter().enumerate() {
            let p = format!("{rp}.components[{j}]");
            let el = el.as_object().ok_or_else(|| invalid(&p, "A component is an object"))?;
            match el.get("type").and_then(Value::as_str) {
                Some("button") => check_button(el, &p)?,
                Some("select") => check_select(el, &p)?,
                _ => return Err(invalid(format!("{p}.type"), "type: button or select")),
            }
            if let Some(id) = el.get("custom_id").and_then(Value::as_str) {
                if ids.contains(&id) {
                    return Err(invalid(format!("{p}.custom_id"), "custom_id is unique within the message"));
                }
                ids.push(id);
            }
        }
    }
    Ok(())
}

/// The content object carries a (non-null) `components` field.
pub fn has_components(content: &Value) -> bool {
    content.get("components").is_some_and(|c| !c.is_null())
}

/// The content carries at least one row (the body may then be empty).
pub fn has_rows(content: &Value) -> bool {
    content.get("components").and_then(Value::as_array).is_some_and(|c| !c.is_empty())
}

/// Plaintext content of a person or a webhook: components are refused (§5.10.1).
pub fn refuse_unless_bot(content: &Value, is_bot: bool) -> Result<(), ApiError> {
    if !is_bot && has_components(content) {
        return Err(invalid("components", "Only applications' bots send components"));
    }
    Ok(())
}

/// The enabled button or select named `custom_id` in a content object (link buttons have none).
fn find<'a>(content: &'a Value, custom_id: &str) -> Option<&'a Map<String, Value>> {
    content
        .get("components")?
        .as_array()?
        .iter()
        .filter_map(|r| r.get("components").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_object)
        .find(|c| {
            c.get("custom_id").and_then(Value::as_str) == Some(custom_id)
                && c.get("style").and_then(Value::as_str) != Some("link")
        })
}

/// Check 3 of §5.10.2 in plaintext conversations: `custom_id` names an enabled button or select of the message's
/// current content and `values` fit it (null for buttons; `min`–`max` distinct option values for selects).
pub fn validate_values(content: &Value, custom_id: &str, values: Option<&Value>) -> Result<(), ApiError> {
    let component = find(content, custom_id)
        .filter(|c| c.get("disabled").and_then(Value::as_bool) != Some(true))
        .ok_or_else(|| values_invalid("custom_id", "No enabled component with this custom_id"))?;
    if component.get("type").and_then(Value::as_str) == Some("button") {
        return if absent(values) { Ok(()) } else { Err(values_invalid("values", "Buttons carry no values")) };
    }
    let list = values
        .and_then(Value::as_array)
        .ok_or_else(|| values_invalid("values", "values: the selected option values"))?;
    let (min, max) = (
        component.get("min").and_then(Value::as_u64).unwrap_or(1),
        component.get("max").and_then(Value::as_u64).unwrap_or(1),
    );
    if (list.len() as u64) < min || list.len() as u64 > max {
        return Err(values_invalid("values", format!("values: {min} to {max} options")));
    }
    let options: Vec<&str> = component
        .get("options")
        .and_then(Value::as_array)
        .map(|o| o.iter().filter_map(|o| o.get("value").and_then(Value::as_str)).collect())
        .unwrap_or_default();
    let mut seen: Vec<&str> = Vec::new();
    for (i, v) in list.iter().enumerate() {
        match v.as_str() {
            Some(v) if options.contains(&v) && !seen.contains(&v) => seen.push(v),
            _ => return Err(values_invalid(format!("values[{i}]"), "An option value of the select, once")),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- modals (§5.10.3, §5.10.4)

/// Checks a modal definition (`400 interaction.modal_invalid` with `meta.path` below the modal).
pub fn validate_modal(modal: &Value) -> Result<(), ApiError> {
    let m = modal.as_object().ok_or_else(|| modal_invalid("", "The modal is an object"))?;
    if let Some(k) = unknown_key(m, MODAL_KEYS) {
        return Err(modal_invalid(k, "Unknown field"));
    }
    if !m.get("custom_id").and_then(Value::as_str).is_some_and(valid_custom_id) {
        return Err(modal_invalid("custom_id", "custom_id: 1 to 100 characters"));
    }
    if !text(m.get("title"), 1, MAX_MODAL_TITLE) {
        return Err(modal_invalid("title", "title: 1 to 45 characters"));
    }
    let inputs = match m.get("inputs") {
        Some(Value::Array(list)) if (1..=MAX_MODAL_INPUTS).contains(&list.len()) => list,
        _ => return Err(modal_invalid("inputs", "inputs: 1 to 5")),
    };
    let mut ids: Vec<&str> = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let p = format!("inputs[{i}]");
        let input = input.as_object().ok_or_else(|| modal_invalid(&p, "An input is an object"))?;
        let select = input.get("style").and_then(Value::as_str) == Some("select");
        if let Some(k) = unknown_key(input, if select { MODAL_SELECT_KEYS } else { INPUT_KEYS }) {
            return Err(modal_invalid(format!("{p}.{k}"), "Unknown field"));
        }
        let Some(id) = input.get("custom_id").and_then(Value::as_str).filter(|s| valid_custom_id(s)) else {
            return Err(modal_invalid(format!("{p}.custom_id"), "custom_id: 1 to 100 characters"));
        };
        if !text(input.get("label"), 1, MAX_INPUT_LABEL) {
            return Err(modal_invalid(format!("{p}.label"), "label: 1 to 45 characters"));
        }
        if !input.get("style").and_then(Value::as_str).is_some_and(|s| INPUT_STYLES.contains(&s)) {
            return Err(modal_invalid(format!("{p}.style"), "style: short, paragraph or select"));
        }
        if !absent(input.get("placeholder")) && !text(input.get("placeholder"), 0, MAX_INPUT_PLACEHOLDER) {
            return Err(modal_invalid(format!("{p}.placeholder"), "placeholder: at most 100 characters"));
        }
        if select {
            let options = check_options(input, &p, true)?;
            if !opt_bool(input.get("required")) {
                return Err(modal_invalid(format!("{p}.required"), "required: a boolean"));
            }
            if !absent(input.get("value"))
                && !input.get("value").and_then(Value::as_str).is_some_and(|value| {
                    options.iter().any(|option| option.get("value").and_then(Value::as_str) == Some(value))
                })
            {
                return Err(modal_invalid(format!("{p}.value"), "value: an option value of the select"));
            }
        } else {
            let min = int_or(input.get("min_length"), 0, 0, MAX_INPUT_LENGTH)
                .ok_or_else(|| modal_invalid(format!("{p}.min_length"), "min_length: 0 to 4000"))?;
            let max = int_or(input.get("max_length"), MAX_INPUT_LENGTH, 1, MAX_INPUT_LENGTH)
                .filter(|m| *m >= min)
                .ok_or_else(|| {
                    modal_invalid(format!("{p}.max_length"), "max_length: 1 to 4000, at least min_length")
                })?;
            if !opt_bool(input.get("required")) {
                return Err(modal_invalid(format!("{p}.required"), "required: a boolean"));
            }
            let value_ok = match input.get("value") {
                None | Some(Value::Null) => true,
                Some(Value::String(s)) => s.chars().count() as u64 <= max,
                Some(_) => false,
            };
            if !value_ok {
                return Err(modal_invalid(format!("{p}.value"), "value: at most max_length characters"));
            }
        }
        if ids.contains(&id) {
            return Err(modal_invalid(format!("{p}.custom_id"), "custom_id is unique within the modal"));
        }
        ids.push(id);
    }
    Ok(())
}

/// A plaintext modal submit against the definition the node kept (`400 interaction.values_invalid` with
/// `meta.path`): input `custom_id` → string, every required input filled, text lengths within the limits and select
/// values matching an option exactly. Returns the values as sent.
pub fn validate_modal_values(modal: &Value, values: Option<&Value>) -> Result<Value, ApiError> {
    let obj = values
        .and_then(Value::as_object)
        .ok_or_else(|| modal_values_invalid("values", "values: an object of input custom_id to text"))?;
    let inputs: Vec<&Map<String, Value>> = modal
        .get("inputs")
        .and_then(Value::as_array)
        .map(|l| l.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    let id_of = |i: &Map<String, Value>| i.get("custom_id").and_then(Value::as_str).unwrap_or("").to_string();
    for (key, value) in obj {
        if !value.is_string() || !inputs.iter().any(|i| id_of(i) == *key) {
            return Err(modal_values_invalid(format!("values.{key}"), "An input of the modal, as text"));
        }
    }
    for input in &inputs {
        let id = id_of(input);
        let text = obj.get(&id).and_then(Value::as_str).unwrap_or("");
        if input.get("style").and_then(Value::as_str) == Some("select") {
            if text.is_empty() {
                if input.get("required").and_then(Value::as_bool).unwrap_or(true) {
                    return Err(modal_values_invalid(format!("values.{id}"), "This input is required"));
                }
            } else if !input.get("options").and_then(Value::as_array).is_some_and(|options| {
                options.iter().any(|option| option.get("value").and_then(Value::as_str) == Some(text))
            }) {
                return Err(modal_values_invalid(format!("values.{id}"), "An option value of the select"));
            }
            continue;
        }
        let n = text.chars().count() as u64;
        // Whitespace only counts as empty: a required input needs real text (the clients check the same).
        if text.trim().is_empty() {
            if input.get("required").and_then(Value::as_bool).unwrap_or(true) {
                return Err(modal_values_invalid(format!("values.{id}"), "This input is required"));
            }
            continue;
        }
        let min = input.get("min_length").and_then(Value::as_u64).unwrap_or(0);
        let max = input.get("max_length").and_then(Value::as_u64).unwrap_or(MAX_INPUT_LENGTH);
        if n < min || n > max {
            return Err(modal_values_invalid(format!("values.{id}"), "The text is too short or too long"));
        }
    }
    Ok(Value::Object(obj.clone()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn path(e: &ApiError) -> String {
        e.to_problem(None).meta.get("path").and_then(Value::as_str).unwrap_or("?").to_string()
    }

    /// The shared cases of `protocol/testvectors/components.json`: the same code and `meta.path` as the SDK.
    #[test]
    fn protocol_test_vectors() {
        let doc: Value = serde_json::from_str(include_str!("../protocol/testvectors/components.json")).unwrap();
        let cases = doc["validation"].as_array().unwrap();
        assert!(cases.len() > 40);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let result = match c["input"].get("modal") {
                Some(m) => validate_modal(m),
                None => validate(&c["input"]["components"]),
            };
            let got = result.err().map(|e| json!({ "code": e.code(), "path": path(&e) }));
            assert_eq!(got.unwrap_or(Value::Null), c["expected"], "{name}");
        }
    }

    fn content() -> Value {
        json!({ "type": "text", "body": "", "components": [
            { "type": "row", "components": [
                { "type": "button", "style": "success", "label": "Sign up", "custom_id": "signup" },
                { "type": "button", "style": "secondary", "label": "Later", "custom_id": "later", "disabled": true },
                { "type": "button", "style": "link", "label": "Guide", "url": "https://guide.example/" } ] },
            { "type": "row", "components": [ { "type": "select", "custom_id": "class", "min": 1, "max": 2, "options": [
                { "label": "Tank", "value": "tank" }, { "label": "Healer", "value": "healer" }, { "label": "Damage", "value": "dps" } ] } ] } ] })
    }

    #[test]
    fn values_fit_the_component() {
        let c = content();
        let p = |id: &str, v: Value| validate_values(&c, id, Some(&v)).err().map(|e| path(&e));
        assert_eq!(p("signup", Value::Null), None);
        assert_eq!(validate_values(&c, "signup", None).err().map(|e| path(&e)), None);
        assert_eq!(p("class", json!(["healer"])), None);
        assert_eq!(p("class", json!(["dps", "tank"])), None);
        assert_eq!(p("nope", Value::Null).as_deref(), Some("custom_id"));
        assert_eq!(p("later", Value::Null).as_deref(), Some("custom_id"), "disabled");
        assert_eq!(p("signup", json!([])).as_deref(), Some("values"));
        assert_eq!(p("class", Value::Null).as_deref(), Some("values"));
        assert_eq!(p("class", json!([])).as_deref(), Some("values"));
        assert_eq!(p("class", json!(["tank", "healer", "dps"])).as_deref(), Some("values"));
        assert_eq!(p("class", json!(["tank", "mage"])).as_deref(), Some("values[1]"));
        assert_eq!(p("class", json!(["tank", "tank"])).as_deref(), Some("values[1]"));
        assert_eq!(validate_values(&c, "class", Some(&json!([1]))).unwrap_err().code(), "component.values_invalid");
        assert_eq!(p("signup", Value::Null), None);
        assert!(find(&json!({ "type": "text", "body": "x" }), "signup").is_none());
    }

    #[test]
    fn modal_values_follow_the_definition() {
        let modal = json!({ "custom_id": "m", "title": "Note", "inputs": [
            { "custom_id": "note", "label": "Note", "style": "paragraph", "max_length": 10, "required": false },
            { "custom_id": "name", "label": "Name", "style": "short", "min_length": 2 } ] });
        validate_modal(&modal).unwrap();
        let p = |v: Value| validate_modal_values(&modal, Some(&v)).err().map(|e| path(&e));
        assert_eq!(p(json!({ "name": "Al" })), None);
        assert_eq!(p(json!({ "name": "Al", "note": "" })), None);
        assert_eq!(p(json!({ "name": "Al", "note": "line\nline" })), None);
        assert_eq!(validate_modal_values(&modal, None).err().map(|e| path(&e)).as_deref(), Some("values"));
        assert_eq!(p(json!({})).as_deref(), Some("values.name"));
        assert_eq!(p(json!({ "name": "A" })).as_deref(), Some("values.name"));
        assert_eq!(p(json!({ "name": "   " })).as_deref(), Some("values.name"), "whitespace is empty");
        assert_eq!(p(json!({ "name": "Al", "note": "  " })), None, "an optional input may be blank");
        assert_eq!(p(json!({ "name": "Al", "note": "x".repeat(11) })).as_deref(), Some("values.note"));
        assert_eq!(p(json!({ "name": "Al", "extra": "x" })).as_deref(), Some("values.extra"));
        assert_eq!(p(json!({ "name": 5 })).as_deref(), Some("values.name"));
        assert_eq!(validate_modal_values(&modal, Some(&json!({}))).unwrap_err().code(), "interaction.values_invalid");
    }

    fn select_modal() -> Value {
        json!({ "custom_id": "raid:spec", "title": "Choose your specialization", "inputs": [
            { "custom_id": "spec", "label": "Specialization", "style": "select", "placeholder": "Choose one",
              "value": "protection", "options": [
                { "label": "Protection", "value": "protection", "description": "Tank", "emoji": "🛡️" },
                { "label": "Holy", "value": "holy", "emoji": ":healer:" } ] },
            { "custom_id": "note", "label": "Note", "style": "short", "required": false } ] })
    }

    #[test]
    fn modal_select_definitions_reuse_option_bounds() {
        validate_modal(&select_modal()).unwrap();
        let mut modal = select_modal();
        modal["inputs"][0]["options"] = json!(
            (0..MAX_OPTIONS)
                .map(|i| json!({ "label": format!("Option {i}"), "value": i.to_string() }))
                .collect::<Vec<_>>()
        );
        modal["inputs"][0]["value"] = json!("0");
        validate_modal(&modal).unwrap();
        modal["inputs"][0]["options"].as_array_mut().unwrap().push(json!({ "label": "Extra", "value": "extra" }));
        assert_eq!(path(&validate_modal(&modal).unwrap_err()), "inputs[0].options");
    }

    #[test]
    fn modal_select_definitions_refuse_malformed_fields() {
        let input = select_modal()["inputs"][0].clone();
        for (key, value, expected) in [
            ("options", json!([]), "options"),
            ("options", json!([null]), "options[0]"),
            (
                "options",
                json!([{ "label": "A", "value": "same" }, { "label": "B", "value": "same" }]),
                "options[1].value",
            ),
            ("options", json!([{ "label": "", "value": "x" }]), "options[0].label"),
            ("options", json!([{ "label": "A".repeat(101), "value": "x" }]), "options[0].label"),
            ("options", json!([{ "label": "A", "value": "" }]), "options[0].value"),
            ("options", json!([{ "label": "A", "value": "x".repeat(101) }]), "options[0].value"),
            (
                "options",
                json!([{ "label": "A", "value": "x", "description": "x".repeat(101) }]),
                "options[0].description",
            ),
            ("options", json!([{ "label": "A", "value": "x", "emoji": "bad emoji" }]), "options[0].emoji"),
            ("options", json!([{ "label": "A", "value": "x", "default": true }]), "options[0].default"),
            ("options", json!([{ "label": "A", "value": "x", "default": null }]), "options[0].default"),
            ("options", json!([{ "label": "A", "value": "x", "extra": 1 }]), "options[0].extra"),
            ("value", json!("other"), "value"),
            ("value", json!(""), "value"),
            ("value", json!(["protection"]), "value"),
            ("required", json!(1), "required"),
            ("placeholder", json!("x".repeat(101)), "placeholder"),
            ("min_length", json!(null), "min_length"),
            ("max_length", json!(4000), "max_length"),
            ("default", json!(true), "default"),
            ("extra", json!(1), "extra"),
        ] {
            let mut modified = input.clone();
            modified[key] = value;
            let modal = json!({ "custom_id": "m", "title": "Choice", "inputs": [modified] });
            let err = validate_modal(&modal).unwrap_err();
            assert_eq!(err.code(), "interaction.modal_invalid");
            assert_eq!(path(&err), format!("inputs[0].{expected}"), "{modal}");
        }
        // Text inputs retain their existing schema; adding select-only fields does not change them.
        let mut modal = select_modal();
        modal["inputs"][1]["options"] = json!([]);
        assert_eq!(path(&validate_modal(&modal).unwrap_err()), "inputs[1].options");
        modal = select_modal();
        modal["inputs"][1]["custom_id"] = json!("spec");
        assert_eq!(path(&validate_modal(&modal).unwrap_err()), "inputs[1].custom_id");
    }

    #[test]
    fn modal_select_submits_require_an_exact_option_value() {
        let mut modal = select_modal();
        let good = json!({ "spec": "holy", "note": "late" });
        assert_eq!(validate_modal_values(&modal, Some(&good)).unwrap(), good);
        for values in [
            json!({}),
            json!({ "spec": "" }),
            json!({ "spec": "unknown" }),
            json!({ "spec": " holy " }),
            json!({ "spec": ["holy"] }),
        ] {
            let err = validate_modal_values(&modal, Some(&values)).unwrap_err();
            assert_eq!((err.code(), path(&err)), ("interaction.values_invalid", "values.spec".into()), "{values}");
        }
        modal["inputs"][0]["required"] = json!(false);
        for values in [json!({}), json!({ "spec": "" }), json!({ "spec": "protection" })] {
            assert_eq!(validate_modal_values(&modal, Some(&values)).unwrap(), values);
        }
        assert!(validate_modal_values(&modal, Some(&json!({ "spec": "unknown" }))).is_err());
        assert!(validate_modal_values(&modal, Some(&json!({ "spec": "   " }))).is_err());
        modal["inputs"][0]["options"] = json!([{ "label": "Opaque", "value": " " }]);
        modal["inputs"][0]["value"] = json!(" ");
        modal["inputs"][0]["required"] = json!(true);
        validate_modal(&modal).unwrap();
        assert!(
            validate_modal_values(&modal, Some(&json!({ "spec": " " }))).is_ok(),
            "option values are exact opaque strings"
        );
    }

    #[test]
    fn people_and_webhooks_send_no_components() {
        let c = content();
        assert_eq!(path(&refuse_unless_bot(&c, false).unwrap_err()), "components");
        refuse_unless_bot(&c, true).unwrap();
        refuse_unless_bot(&json!({ "type": "text", "body": "x", "components": null }), false).unwrap();
        assert!(refuse_unless_bot(&json!({ "type": "text", "body": "x", "components": [] }), false).is_err());
        assert!(has_rows(&c) && !has_rows(&json!({ "components": [] })));
    }

    #[test]
    fn emojis() {
        assert!(valid_emoji("👍🏽") && valid_emoji("🇩🇪") && valid_emoji(":tada:") && valid_emoji("1️⃣"));
        assert!(!valid_emoji(":x:") && !valid_emoji(":Tada:") && !valid_emoji("<b>") && !valid_emoji(""));
        assert!(!valid_emoji("a b") && !valid_emoji(&"x".repeat(17)) && !valid_emoji(&format!(":{}:", "a".repeat(31))));
        assert!(valid_custom_id(&"x".repeat(100)) && !valid_custom_id(&"x".repeat(101)) && !valid_custom_id("a\nb"));
    }
}
