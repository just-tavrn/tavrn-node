// SPDX-License-Identifier: AGPL-3.0-only
//! Application commands (protocol/APPLICATIONS.md §5.1–§5.5): validation and storage of command definitions,
//! the node approval of definitions, per-room settings, the `/` palette of a conversation and the checks 1–5
//! and 7 of an invocation. Delivery and responses live in `interactions.rs`.
//!
//! Definitions are stored per application reference (`<domain>/<ULID>`): the home node writes the set of a
//! local application (`PUT …/commands`), a room node keeps the set of a remote application from its public
//! document. Every definition is stored in its JCS form (RFC 8785) without `id`; `definition_hash` is the
//! base64url SHA-256 of exactly that text, so the node approval (§5.2) follows every change.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    applications as apps,
    auth::AuthUser,
    error::ApiError,
    installations,
    models::UserRow,
    permissions::{self as p, Perms},
    store::{self, applications::ApplicationRow, commands::CommandRow},
    util,
};

/// Announced by nodes and clients that implement §5.
pub const CAPABILITY: &str = "commands.v1";
pub const MAX_COMMANDS: usize = 100;
pub const MAX_ARGS: usize = 25;
pub const MAX_OPTIONS: usize = 25;
/// The serialized command set (§9.1).
pub const MAX_SET_BYTES: usize = 64 * 1024;
pub const DESCRIPTION_MAX: usize = 100;
pub const OPTION_NAME_MAX: usize = 100;
pub const MAX_LENGTH_LIMIT: u64 = 1000;
/// String arguments without `max_length` are capped at this length.
pub const DEFAULT_STRING_MAX: usize = 1000;
pub const ARG_TYPES: &[&str] = &["string", "integer", "number", "boolean", "user", "channel", "role"];
/// `allowed_roles` and `disabled_channels` per room setting.
pub const MAX_SETTING_IDS: usize = 100;
/// An encrypted argument payload (`args_ciphertext`) is at most this long.
pub const MAX_ARGS_CIPHERTEXT: usize = 16 * 1024;
/// Plaintext `args` of an invocation (serialized).
pub const MAX_ARGS_BYTES: usize = 8 * 1024;

// ---------------------------------------------------------------- errors

pub fn invalid(path: impl Into<String>, detail: impl Into<String>) -> ApiError {
    ApiError::BadRequestMeta { code: "command.invalid", detail: detail.into(), meta: json!({ "path": path.into() }) }
}

fn limit(detail: impl Into<String>, max: usize) -> ApiError {
    ApiError::BadRequestMeta { code: "command.limit", detail: detail.into(), meta: json!({ "max": max }) }
}

pub fn not_found() -> ApiError {
    ApiError::NotFound { code: "command.not_found", what: "Command".into() }
}

fn pending_approval() -> ApiError {
    ApiError::Forbidden { code: "command.pending_approval", detail: "This command awaits the node's approval".into() }
}

fn disabled(reason: &str) -> ApiError {
    ApiError::ForbiddenMeta {
        code: "command.disabled",
        detail: "This command is disabled here".into(),
        meta: json!({ "reason": reason }),
    }
}

fn forbidden() -> ApiError {
    ApiError::Forbidden { code: "command.forbidden", detail: "You may not use this command here".into() }
}

fn dm_not_allowed() -> ApiError {
    ApiError::Forbidden {
        code: "command.dm_not_allowed",
        detail: "This command cannot be used in direct messages".into(),
    }
}

fn not_installed() -> ApiError {
    ApiError::NotFound { code: "app.not_installed", what: "Installation".into() }
}

pub fn args_invalid(arg: &str, detail: impl Into<String>) -> ApiError {
    ApiError::BadRequestMeta { code: "command.args_invalid", detail: detail.into(), meta: json!({ "arg": arg }) }
}

// ---------------------------------------------------------------- definitions (§5.1)

/// A choice of an argument (`options`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct CommandOption {
    /// 1–100 characters, shown in the pick list.
    pub name: String,
    /// A value of the argument's type (string, integer or number).
    #[schema(value_type = Value)]
    pub value: Value,
}

/// One argument of a command.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct CommandArg {
    /// `^[a-z0-9_-]{1,32}$`
    pub name: String,
    /// 1–100 characters.
    pub description: String,
    /// `string`, `integer`, `number`, `boolean`, `user`, `channel`, `role`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    /// Choices (at most 25), only for `string`, `integer` and `number`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<CommandOption>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Strings only, at most 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
}

/// A command definition (registry shape of §5.1). `id` is set by the node.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct CommandDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `^[a-z0-9_-]{1,32}$`, unique per application.
    pub name: String,
    /// 1–100 characters.
    pub description: String,
    /// At most 25, required ones first.
    #[serde(default)]
    pub args: Vec<CommandArg>,
    /// Decimal mask the invoker must hold unless the room overrides it; null = none.
    #[serde(default)]
    pub default_permissions: Option<String>,
    /// Usable in a DM with the bot (default false).
    #[serde(default)]
    pub dm_allowed: bool,
}

/// `PUT /applications/{id}/commands` and `PUT /applications/me/commands`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PutCommandsRequest {
    /// The whole set (replaces the previous one); ids are assigned by the node and stay stable per name.
    pub commands: Vec<CommandDefinition>,
}

/// An application's command set.
#[derive(Debug, Serialize, ToSchema)]
pub struct CommandSet {
    pub commands: Vec<CommandDefinition>,
    pub commands_version: i64,
}

/// A validated definition in its stored form.
#[derive(Debug, Clone)]
pub struct Validated {
    pub name: String,
    /// JCS of the definition without `id`.
    pub canonical: String,
    pub hash: String,
    /// `id` of a definition from another node's document (ULID), otherwise `None`.
    pub id: Option<String>,
}

fn valid_name(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn text(path: &str, v: Option<&Value>, max: usize) -> Result<String, ApiError> {
    let s = v.and_then(Value::as_str).ok_or_else(|| invalid(path, format!("{path}: a string is required")))?;
    let n = s.chars().count();
    if n == 0 || n > max || s.trim().is_empty() || s.chars().any(char::is_control) {
        return Err(invalid(path, format!("{path}: 1 to {max} characters without control characters")));
    }
    Ok(s.to_string())
}

fn only_keys(path: &str, obj: &Map<String, Value>, allowed: &[&str]) -> Result<(), ApiError> {
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(invalid(format!("{path}.{k}"), format!("Unknown field {k:.40}"))),
        None => Ok(()),
    }
}

fn opt_bool(path: &str, v: Option<&Value>) -> Result<bool, ApiError> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(invalid(path, format!("{path}: true or false"))),
    }
}

fn opt_number(path: &str, v: Option<&Value>) -> Result<Option<f64>, ApiError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            n.as_f64().filter(|f| f.is_finite()).map(Some).ok_or_else(|| invalid(path, "a finite number"))
        }
        Some(_) => Err(invalid(path, format!("{path}: a number"))),
    }
}

/// Is `v` a value of `kind` (for options)?
fn value_of_type(kind: &str, v: &Value) -> bool {
    match kind {
        "string" => v.as_str().is_some_and(|s| !s.is_empty() && s.chars().count() <= DEFAULT_STRING_MAX),
        "integer" => v.as_i64().is_some() || v.as_u64().is_some_and(|n| n <= i64::MAX as u64),
        "number" => v.as_f64().is_some_and(f64::is_finite),
        _ => false,
    }
}

fn parse_arg(path: &str, v: &Value) -> Result<Value, ApiError> {
    let obj = v.as_object().ok_or_else(|| invalid(path, "An argument is an object"))?;
    only_keys(path, obj, &["name", "description", "type", "required", "options", "min", "max", "max_length"])?;
    let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
    if !valid_name(name) {
        return Err(invalid(format!("{path}.name"), "Argument names: 1–32 characters of a-z 0-9 _ -"));
    }
    let description = text(&format!("{path}.description"), obj.get("description"), DESCRIPTION_MAX)?;
    let kind = obj.get("type").and_then(Value::as_str).unwrap_or("");
    if !ARG_TYPES.contains(&kind) {
        return Err(invalid(format!("{path}.type"), "type: string, integer, number, boolean, user, channel or role"));
    }
    let required = opt_bool(&format!("{path}.required"), obj.get("required"))?;
    let mut out = json!({ "name": name, "description": description, "type": kind, "required": required });
    let numeric = matches!(kind, "integer" | "number");
    if let Some(options) = obj.get("options").filter(|o| !o.is_null()) {
        let path = format!("{path}.options");
        if !matches!(kind, "string" | "integer" | "number") {
            return Err(invalid(&path, "options only for string, integer and number"));
        }
        let list = options.as_array().ok_or_else(|| invalid(&path, "options is an array"))?;
        if list.is_empty() {
            return Err(invalid(&path, "options: at least one choice"));
        }
        if list.len() > MAX_OPTIONS {
            return Err(limit(format!("At most {MAX_OPTIONS} options"), MAX_OPTIONS));
        }
        let mut seen: Vec<&Value> = Vec::new();
        let mut parsed = Vec::new();
        for (i, o) in list.iter().enumerate() {
            let path = format!("{path}[{i}]");
            let obj = o.as_object().ok_or_else(|| invalid(&path, "An option is an object"))?;
            only_keys(&path, obj, &["name", "value"])?;
            let name = text(&format!("{path}.name"), obj.get("name"), OPTION_NAME_MAX)?;
            let value = obj.get("value").cloned().unwrap_or(Value::Null);
            if !value_of_type(kind, &value) {
                return Err(invalid(format!("{path}.value"), format!("A value of type {kind}")));
            }
            if seen.contains(&&list[i]["value"]) {
                return Err(invalid(format!("{path}.value"), "Option values must be unique"));
            }
            seen.push(&list[i]["value"]);
            parsed.push(json!({ "name": name, "value": value }));
        }
        out["options"] = Value::Array(parsed);
    }
    let min = opt_number(&format!("{path}.min"), obj.get("min"))?;
    let max = opt_number(&format!("{path}.max"), obj.get("max"))?;
    if (min.is_some() || max.is_some()) && !numeric {
        return Err(invalid(format!("{path}.min"), "min and max only for integer and number"));
    }
    if kind == "integer" && [min, max].iter().flatten().any(|f| f.fract() != 0.0) {
        return Err(invalid(format!("{path}.min"), "min and max of an integer are integers"));
    }
    if let (Some(a), Some(b)) = (min, max)
        && a > b
    {
        return Err(invalid(format!("{path}.max"), "max must not be below min"));
    }
    if let Some(m) = min {
        out["min"] = json!(m);
    }
    if let Some(m) = max {
        out["max"] = json!(m);
    }
    if let Some(len) = obj.get("max_length").filter(|v| !v.is_null()) {
        let path = format!("{path}.max_length");
        if kind != "string" {
            return Err(invalid(&path, "max_length only for string"));
        }
        let n = len.as_u64().filter(|n| (1..=MAX_LENGTH_LIMIT).contains(n));
        out["max_length"] = json!(n.ok_or_else(|| invalid(&path, format!("max_length: 1 to {MAX_LENGTH_LIMIT}")))?);
    }
    Ok(out)
}

/// Validates one definition and returns its stored (canonical) form. `id` is accepted (and returned) but not
/// part of the canonical form.
pub fn validate_definition(path: &str, v: &Value) -> Result<Validated, ApiError> {
    let obj = v.as_object().ok_or_else(|| invalid(path, "A command is an object"))?;
    only_keys(path, obj, &["id", "name", "description", "args", "default_permissions", "dm_allowed"])?;
    let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
    if !valid_name(name) {
        return Err(invalid(format!("{path}.name"), "Command names: 1–32 characters of a-z 0-9 _ -"));
    }
    let description = text(&format!("{path}.description"), obj.get("description"), DESCRIPTION_MAX)?;
    let raw_args = match obj.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err(invalid(format!("{path}.args"), "args is an array")),
    };
    if raw_args.len() > MAX_ARGS {
        return Err(limit(format!("At most {MAX_ARGS} arguments per command"), MAX_ARGS));
    }
    let mut args = Vec::new();
    let mut names = HashSet::new();
    let mut optional_seen = false;
    for (i, a) in raw_args.iter().enumerate() {
        let path = format!("{path}.args[{i}]");
        let arg = parse_arg(&path, a)?;
        let arg_name = arg["name"].as_str().unwrap_or("").to_string();
        if !names.insert(arg_name) {
            return Err(invalid(format!("{path}.name"), "Argument names must be unique"));
        }
        let required = arg["required"].as_bool().unwrap_or(false);
        if required && optional_seen {
            return Err(invalid(format!("{path}.required"), "Required arguments come first"));
        }
        optional_seen |= !required;
        args.push(arg);
    }
    let default_permissions = match obj.get("default_permissions") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(s)) => {
            let mask = p::parse(s.trim())
                .ok_or_else(|| invalid(format!("{path}.default_permissions"), "A decimal permission mask"))?;
            Value::String(mask.to_string())
        }
        Some(_) => return Err(invalid(format!("{path}.default_permissions"), "A decimal permission mask or null")),
    };
    let dm_allowed = opt_bool(&format!("{path}.dm_allowed"), obj.get("dm_allowed"))?;
    let id = match obj.get("id") {
        Some(Value::String(s)) if util::is_ulid(s) => Some(s.clone()),
        _ => None,
    };
    let definition = json!({
        "name": name, "description": description, "args": args,
        "default_permissions": default_permissions, "dm_allowed": dm_allowed,
    });
    let canonical = tavrn_crypto::plaintext::canonical_json(&definition.to_string())
        .map_err(|_| invalid(path, "The definition cannot be canonicalized"))?;
    Ok(Validated { name: name.to_string(), hash: util::sha256_b64(&canonical), canonical, id })
}

/// Validates a whole set (`400 command.invalid` with `meta.path`, `400 command.limit`).
pub fn validate_set(commands: &[Value]) -> Result<Vec<Validated>, ApiError> {
    if commands.len() > MAX_COMMANDS {
        return Err(limit(format!("At most {MAX_COMMANDS} commands per application"), MAX_COMMANDS));
    }
    let size: usize = commands.iter().map(|c| c.to_string().len()).sum();
    if size > MAX_SET_BYTES {
        return Err(limit(format!("The command set is at most {} KiB", MAX_SET_BYTES / 1024), MAX_SET_BYTES));
    }
    let mut out: Vec<Validated> = Vec::new();
    for (i, c) in commands.iter().enumerate() {
        let v = validate_definition(&format!("commands[{i}]"), c)?;
        if out.iter().any(|o| o.name == v.name) {
            return Err(invalid(format!("commands[{i}].name"), "Command names must be unique"));
        }
        out.push(v);
    }
    Ok(out)
}

/// A stored definition with its id (the registry shape of §5.1).
pub fn definition_of(row: &CommandRow) -> CommandDefinition {
    let mut d: CommandDefinition = serde_json::from_str(&row.definition).unwrap_or(CommandDefinition {
        id: None,
        name: row.name.clone(),
        description: String::new(),
        args: Vec::new(),
        default_permissions: None,
        dm_allowed: false,
    });
    d.id = Some(row.id.clone());
    d
}

/// The definitions of an application as JSON values with `id` (public document).
pub fn values_of(rows: &[CommandRow]) -> Vec<Value> {
    rows.iter()
        .filter_map(|r| {
            let mut v: Value = serde_json::from_str(&r.definition).ok()?;
            v["id"] = json!(r.id);
            Some(v)
        })
        .collect()
}

/// What changed between two sets (for the audit log and the settings cleanup).
pub struct SetChange {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
    /// Ids of removed commands.
    pub removed_ids: Vec<String>,
    /// Order or content differs.
    pub any: bool,
}

/// Stores a validated set for `application_ref`: ids stay stable per name (or are taken from another node's
/// document), removed names lose their room settings on this node.
pub async fn store_set(state: &AppState, application_ref: &str, set: &[Validated]) -> Result<SetChange, ApiError> {
    let old = store::commands::of_app(&state.db, application_ref).await?;
    let by_name: HashMap<&str, &CommandRow> = old.iter().map(|r| (r.name.as_str(), r)).collect();
    let mut rows = Vec::new();
    let (mut added, mut changed) = (Vec::new(), Vec::new());
    for v in set {
        let id = match (by_name.get(v.name.as_str()), &v.id) {
            (_, Some(remote)) => remote.clone(),
            (Some(r), None) => r.id.clone(),
            (None, None) => util::ulid(),
        };
        match by_name.get(v.name.as_str()) {
            None => added.push(v.name.clone()),
            Some(r) if r.definition_hash != v.hash => changed.push(v.name.clone()),
            Some(_) => {}
        }
        rows.push(store::commands::NewCommand {
            id,
            name: v.name.clone(),
            definition: v.canonical.clone(),
            definition_hash: v.hash.clone(),
        });
    }
    let kept: HashSet<&str> = set.iter().map(|v| v.name.as_str()).collect();
    let gone: Vec<&CommandRow> = old.iter().filter(|r| !kept.contains(r.name.as_str())).collect();
    let removed: Vec<String> = gone.iter().map(|r| r.name.clone()).collect();
    // A command that keeps its name but gets another id (another node's document) counts as removed here too.
    let new_ids: HashSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    let removed_ids: Vec<String> =
        old.iter().filter(|r| !new_ids.contains(r.id.as_str())).map(|r| r.id.clone()).collect();
    let order_changed = old.iter().map(|r| r.name.as_str()).ne(set.iter().map(|v| v.name.as_str()));
    let any = !added.is_empty() || !changed.is_empty() || !removed.is_empty() || order_changed;
    if any || old.iter().zip(&rows).any(|(o, n)| o.id != n.id) {
        store::commands::replace_set(&state.db, application_ref, &rows).await?;
    }
    if !removed_ids.is_empty() {
        store::commands::delete_settings_of_commands(&state.db, &removed_ids).await?;
    }
    Ok(SetChange { added, changed, removed, removed_ids, any })
}

/// `commands.update { room_id }` to the members of every room of this node where the application is
/// installed (and queued for their subscriptions).
pub async fn announce_to_rooms(state: &AppState, application_ref: &str) {
    let rooms = match store::commands::rooms_of_app(&state.db, application_ref).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "rooms of an application not readable");
            return;
        }
    };
    for room_id in rooms {
        announce_room(state, &room_id).await;
    }
}

/// `commands.update { room_id }` to one room.
pub async fn announce_room(state: &AppState, room_id: &str) {
    crate::subscriptions::room_event(state, room_id, "commands.update", json!({ "room_id": room_id })).await;
}

/// Replaces the set of a local application (owner or bot), bumps `commands_version`, tells the room nodes
/// (`app.changed`) and the local rooms (`commands.update`), audits `app.commands`.
pub async fn put_local(
    state: &AppState,
    actor: &UserRow,
    app: &ApplicationRow,
    commands: &[Value],
) -> Result<CommandSet, ApiError> {
    let set = validate_set(commands)?;
    state.app_commands_limiter.check_all(&[format!("app-cmd:{}", app.id)])?;
    let reference = apps::app_ref(state, &app.id);
    let change = store_set(state, &reference, &set).await?;
    let mut version = app.commands_version;
    if change.any {
        version = store::commands::bump_version(&state.db, &app.id).await?;
        let mut updated = app.clone();
        updated.commands_version = version;
        installations::changed(state, &updated, false).await;
        announce_to_rooms(state, &reference).await;
        let bot = store::users::by_id(&state.db, &app.bot_user_id).await?.map(|b| b.address()).unwrap_or_default();
        store::rooms::audit(
            &state.db,
            None,
            Some(&actor.id),
            "app.commands",
            &bot,
            "",
            json!({
                "application": reference, "added": change.added, "changed": change.changed,
                "removed": change.removed, "commands_version": version,
            }),
        )
        .await?;
    }
    Ok(CommandSet { commands: local_set(state, &reference).await?, commands_version: version })
}

pub async fn local_set(state: &AppState, application_ref: &str) -> Result<Vec<CommandDefinition>, ApiError> {
    Ok(store::commands::of_app(&state.db, application_ref).await?.iter().map(definition_of).collect())
}

/// Parses the `commands` of another node's public document: invalid or id-less definitions (e.g. newer
/// argument types) are ignored, duplicates by name keep the first.
pub fn parse_remote(commands: &[Value]) -> Vec<Validated> {
    let mut out: Vec<Validated> = Vec::new();
    for (i, c) in commands.iter().take(MAX_COMMANDS).enumerate() {
        match validate_definition(&format!("commands[{i}]"), c) {
            Ok(v) if v.id.is_some() && !out.iter().any(|o| o.name == v.name || o.id == v.id) => out.push(v),
            _ => {}
        }
    }
    out
}

/// Stores the commands of a remote application's document on this room node and tells its rooms when the
/// set changed.
pub async fn store_remote(state: &AppState, application_ref: &str, commands: &[Value]) -> Result<(), ApiError> {
    let set = parse_remote(commands);
    let change = store_set(state, application_ref, &set).await?;
    if change.any {
        announce_to_rooms(state, application_ref).await;
    }
    Ok(())
}

// ---------------------------------------------------------------- approval (§5.2)

/// Is a definition offered on this node (approval switched off, or its hash approved)?
pub fn approved(state: &AppState, approvals: &HashMap<String, String>, hash: &str) -> bool {
    !state.config.app_commands_require_approval || approvals.get(hash).map(String::as_str) == Some("approved")
}

/// The approval state of a definition as listed to admins.
pub fn state_of(approvals: &HashMap<String, String>, hash: &str) -> &'static str {
    match approvals.get(hash).map(String::as_str) {
        Some("approved") => "approved",
        Some("rejected") => "rejected",
        _ => "pending",
    }
}

// ---------------------------------------------------------------- per-room settings (§5.3)

/// The effective settings of a command in a room.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CommandSettings {
    pub enabled: bool,
    /// Room override of `default_permissions` (decimal mask), null = the definition's default.
    pub permissions: Option<String>,
    /// Role ids; empty = no role restriction (owners and administrators always pass).
    pub allowed_roles: Vec<String>,
    /// Channel ids where the command is disabled.
    pub disabled_channels: Vec<String>,
}

impl CommandSettings {
    pub fn of(row: Option<&store::commands::SettingRow>) -> Self {
        match row {
            Some(r) => Self {
                enabled: r.enabled != 0,
                permissions: r.permissions.map(|p| (p as u64).to_string()),
                allowed_roles: r.allowed_roles(),
                disabled_channels: r.disabled_channels(),
            },
            None => Self { enabled: true, permissions: None, allowed_roles: Vec::new(), disabled_channels: Vec::new() },
        }
    }

    /// The mask the invoker must hold: the room override or the definition's default.
    pub fn required(&self, def: &CommandDefinition) -> Perms {
        self.permissions.as_deref().or(def.default_permissions.as_deref()).and_then(p::parse).unwrap_or(0)
    }
}

// ---------------------------------------------------------------- palette and checks (§5.4, §5.5)

/// The application of a command as the palette shows it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PaletteApplication {
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    /// The bot's address.
    pub bot: String,
}

/// A command the caller can invoke in a conversation (registry shape of §5.4).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaletteCommand {
    pub id: String,
    /// `<application ref>/<command id>`
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    pub description: String,
    pub args: Vec<CommandArg>,
    /// The effective required mask (decimal).
    pub permission: String,
    /// Always `app`.
    pub source: String,
    pub application: PaletteApplication,
    pub dm_allowed: bool,
}

/// An application that offers commands in a conversation, with what the checks need.
pub struct Offer {
    pub reference: String,
    pub name: String,
    pub bot: UserRow,
    pub local: Option<ApplicationRow>,
    /// Channels: the bot can view the channel (§5.5 check 2).
    pub bot_can_view: bool,
    pub commands: Vec<CommandRow>,
    pub approvals: HashMap<String, String>,
}

/// The caller's side of the checks in one conversation.
pub struct Caller<'a> {
    pub conv: &'a Conv,
    /// Room channels: the room settings of every command, by id.
    pub settings: HashMap<String, store::commands::SettingRow>,
}

/// The bot's effective permissions in a channel (scopes of a local application; none known for remote bots).
async fn bot_can_view(
    state: &AppState,
    conv: &Conv,
    bot: &UserRow,
    local: Option<&ApplicationRow>,
) -> Result<bool, ApiError> {
    let ConvKind::Channel { access, channel } = &conv.kind else { return Ok(true) };
    let mut bot = bot.clone();
    bot.app_scopes = local.map(ApplicationRow::scopes);
    match access::room_access(state, &access.room.id, &bot).await {
        Ok(a) => Ok(p::has(access::channel_perms(state, &a, channel, &bot.id).await?, p::VIEW_CHANNEL)),
        Err(ApiError::Forbidden { .. } | ApiError::ForbiddenMeta { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Is a local or remote application usable on this node right now (not disabled or blocked)?
async fn usable(state: &AppState, bot: &UserRow, local: Option<&ApplicationRow>) -> Result<bool, ApiError> {
    if store::applications::is_blocked(&state.db, &bot.address()).await? {
        return Ok(false);
    }
    match local {
        Some(app) => Ok(apps::disabled_reason(state, app, bot).await?.is_none()),
        None => Ok(bot.disabled_at.is_none()),
    }
}

async fn offer_of(state: &AppState, conv: &Conv, reference: &str, bot: UserRow) -> Result<Option<Offer>, ApiError> {
    let local =
        if bot.domain == state.config.domain { store::applications::by_bot(&state.db, &bot.id).await? } else { None };
    if !usable(state, &bot, local.as_ref()).await? {
        return Ok(None);
    }
    let bot_can_view = bot_can_view(state, conv, &bot, local.as_ref()).await?;
    Ok(Some(Offer {
        reference: reference.to_string(),
        name: bot.display_name.clone(),
        commands: store::commands::of_app(&state.db, reference).await?,
        approvals: store::commands::approvals(&state.db, reference).await?,
        local,
        bot_can_view,
        bot,
    }))
}

/// The bot of a 1:1 DM, if the other member is one.
async fn dm_bot(state: &AppState, conv: &Conv, caller_id: &str) -> Result<Option<UserRow>, ApiError> {
    let ConvKind::Direct { row, member_ids, .. } = &conv.kind else { return Ok(None) };
    if row.kind != "dm" {
        return Ok(None);
    }
    let Some(other) = member_ids.iter().find(|m| *m != caller_id) else { return Ok(None) };
    Ok(store::users::by_id(&state.db, other).await?.filter(UserRow::is_bot))
}

/// Every application that can offer commands in the conversation (installed in the room, or the bot of a DM).
pub async fn offers(state: &AppState, conv: &Conv, caller_id: &str) -> Result<Vec<Offer>, ApiError> {
    let mut out = Vec::new();
    match &conv.kind {
        ConvKind::Channel { access, .. } => {
            for inst in store::installations::of_room(&state.db, &access.room.id).await? {
                let Some(bot) = store::users::by_id(&state.db, &inst.bot_user_id).await? else { continue };
                if let Some(o) = offer_of(state, conv, &inst.application_ref, bot).await? {
                    out.push(o);
                }
            }
        }
        ConvKind::Direct { .. } => {
            if let Some(bot) = dm_bot(state, conv, caller_id).await?
                && let Some(reference) = installations::bot_ref(&bot)
                && let Some(o) = offer_of(state, conv, &reference, bot).await?
            {
                out.push(o);
            }
        }
    }
    Ok(out)
}

/// Checks 3–5 of §5.5 for one command of an offer (check 2's `dm_allowed` included); returns the required mask.
pub fn check_command(
    state: &AppState,
    caller: &Caller<'_>,
    offer: &Offer,
    row: &CommandRow,
    def: &CommandDefinition,
) -> Result<Perms, ApiError> {
    let conv = caller.conv;
    if matches!(conv.kind, ConvKind::Direct { .. }) && !def.dm_allowed {
        return Err(dm_not_allowed());
    }
    // 3. approved on this node.
    if !approved(state, &offer.approvals, &row.definition_hash) {
        return Err(pending_approval());
    }
    // 4. enabled in the room, not disabled in the channel.
    let settings = CommandSettings::of(caller.settings.get(&row.id));
    if let ConvKind::Channel { channel, .. } = &conv.kind {
        if !settings.enabled {
            return Err(disabled("room"));
        }
        if settings.disabled_channels.iter().any(|c| c == &channel.id) {
            return Err(disabled("channel"));
        }
    }
    // 5. the required mask and, if set, one of the allowed roles (owners and administrators always pass).
    let required = settings.required(def);
    if !p::has(conv.perms, required) {
        return Err(forbidden());
    }
    if let ConvKind::Channel { access, .. } = &conv.kind
        && !settings.allowed_roles.is_empty()
        && !(access.is_owner || access.is_node_admin || access.has(p::ADMINISTRATOR))
        && !access.member_roles.iter().any(|r| settings.allowed_roles.contains(&r.id))
    {
        return Err(forbidden());
    }
    Ok(required)
}

/// Check 1 of §5.5: a person (never a bot) who may view the conversation and send messages there.
pub fn check_caller(auth: &AuthUser, conv: &Conv) -> Result<(), ApiError> {
    if auth.user.is_bot() || auth.app.is_some() {
        return Err(apps::bot_forbidden());
    }
    if let ConvKind::Channel { access, .. } = &conv.kind
        && access.member.is_none()
    {
        return Err(ApiError::Forbidden { code: "room.not_member", detail: "Only members can use commands".into() });
    }
    if conv.is_request_for(&auth.user.id) {
        return Err(ApiError::Forbidden {
            code: "conversation.request_pending",
            detail: "Accept the message request first".into(),
        });
    }
    conv.require(p::VIEW_CHANNEL | p::SEND_MESSAGES, "message.send_forbidden", "Send messages")
}

async fn caller_of<'a>(state: &AppState, conv: &'a Conv) -> Result<Caller<'a>, ApiError> {
    let settings = match conv.room_id() {
        Some(room_id) => store::commands::settings_of_room(&state.db, room_id).await?,
        None => HashMap::new(),
    };
    Ok(Caller { conv, settings })
}

/// `GET /conversations/{id}/commands`: the commands that pass checks 1–5 for the caller (check 6, the
/// interaction rate limit, is transient and not applied to the list).
pub async fn palette(state: &AppState, auth: &AuthUser, conv: &Conv) -> Result<Vec<PaletteCommand>, ApiError> {
    if check_caller(auth, conv).is_err() {
        if auth.user.is_bot() || auth.app.is_some() {
            return Err(apps::bot_forbidden());
        }
        return Ok(Vec::new());
    }
    let caller = caller_of(state, conv).await?;
    let mut out = Vec::new();
    for offer in offers(state, conv, &auth.user.id).await? {
        if !offer.bot_can_view {
            continue;
        }
        for row in &offer.commands {
            let def = definition_of(row);
            let Ok(required) = check_command(state, &caller, &offer, row, &def) else { continue };
            out.push(PaletteCommand {
                id: row.id.clone(),
                reference: format!("{}/{}", offer.reference, row.id),
                name: def.name.clone(),
                description: def.description.clone(),
                args: def.args.clone(),
                permission: required.to_string(),
                source: "app".into(),
                application: PaletteApplication {
                    reference: offer.reference.clone(),
                    name: offer.name.clone(),
                    bot: offer.bot.address(),
                },
                dm_allowed: def.dm_allowed,
            });
        }
    }
    Ok(out)
}

/// Splits a command reference `<domain>/<application ULID>/<command ULID>` (`404 command.not_found`).
pub fn parse_command_ref(reference: &str) -> Result<(String, String), ApiError> {
    let (app, id) = reference.trim().rsplit_once('/').ok_or_else(not_found)?;
    let (domain, app_id) = installations::parse_ref(app).map_err(|_| not_found())?;
    if !util::is_ulid(id) {
        return Err(not_found());
    }
    Ok((format!("{domain}/{app_id}"), id.to_string()))
}

/// A resolved invocation target after checks 1–5.
pub struct Target {
    pub offer: Offer,
    pub row: CommandRow,
    pub def: CommandDefinition,
}

/// Checks 1–5 of §5.5 in order for `command_ref` in `conv`.
pub async fn resolve_invocation(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    command_ref: &str,
) -> Result<Target, ApiError> {
    // 1. a person who may view the conversation and send messages there.
    check_caller(auth, conv)?;
    // 2. the application is installed in the room (DMs: the DM is with its bot) and the bot can view the channel.
    let (app_ref, command_id) = parse_command_ref(command_ref)?;
    let offer = offers(state, conv, &auth.user.id)
        .await?
        .into_iter()
        .find(|o| o.reference.eq_ignore_ascii_case(&app_ref))
        .ok_or_else(not_installed)?;
    if !offer.bot_can_view {
        return Err(disabled("bot_cannot_view"));
    }
    // 3. the command exists (and is approved, in `check_command`).
    let row = offer.commands.iter().find(|r| r.id == command_id).cloned().ok_or_else(not_found)?;
    let def = definition_of(&row);
    let caller = caller_of(state, conv).await?;
    check_command(state, &caller, &offer, &row, &def)?;
    Ok(Target { offer, row, def })
}

// ---------------------------------------------------------------- arguments (§5.5 check 7)

fn number_in(arg: &CommandArg, n: f64) -> bool {
    arg.min.is_none_or(|m| n >= m) && arg.max.is_none_or(|m| n <= m)
}

/// Validates plaintext arguments against the definition and returns them normalized (only known arguments).
pub fn validate_args(def: &CommandDefinition, args: Option<&Value>) -> Result<Value, ApiError> {
    let empty = Map::new();
    let obj = match args {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(o)) => o,
        Some(_) => return Err(args_invalid("", "args is an object")),
    };
    if serde_json::to_vec(obj).map(|v| v.len()).unwrap_or(usize::MAX) > MAX_ARGS_BYTES {
        return Err(args_invalid("", "args are too large"));
    }
    if let Some(unknown) = obj.keys().find(|k| !def.args.iter().any(|a| &a.name == *k)) {
        return Err(args_invalid(unknown.chars().take(32).collect::<String>().as_str(), "Unknown argument"));
    }
    let mut out = Map::new();
    for arg in &def.args {
        let value = match obj.get(&arg.name) {
            None | Some(Value::Null) if arg.required => {
                return Err(args_invalid(&arg.name, "This argument is required"));
            }
            None | Some(Value::Null) => continue,
            Some(v) => v,
        };
        let bad = || args_invalid(&arg.name, format!("A value of type {}", arg.kind));
        let ok = match arg.kind.as_str() {
            "string" => value.as_str().is_some_and(|s| {
                let n = s.chars().count();
                n > 0 && n <= arg.max_length.map_or(DEFAULT_STRING_MAX, |m| m as usize) && !s.contains('\0')
            }),
            "integer" => value.as_i64().is_some_and(|n| number_in(arg, n as f64)),
            "number" => value.as_f64().is_some_and(|n| n.is_finite() && number_in(arg, n)),
            "boolean" => value.is_boolean(),
            "user" => {
                value.as_str().is_some_and(|s| s.len() <= 320 && util::parse_address(&s.to_lowercase()).is_some())
            }
            "channel" | "role" => value.as_str().is_some_and(util::is_ulid),
            _ => false,
        };
        if !ok {
            return Err(bad());
        }
        if let Some(options) = &arg.options
            && !options
                .iter()
                .any(|o| o.value == *value || (o.value.as_f64().is_some() && o.value.as_f64() == value.as_f64()))
        {
            return Err(args_invalid(&arg.name, "Not one of the choices"));
        }
        let normalized =
            if arg.kind == "user" { json!(value.as_str().unwrap_or("").to_lowercase()) } else { value.clone() };
        out.insert(arg.name.clone(), normalized);
    }
    Ok(Value::Object(out))
}

// ---------------------------------------------------------------- room settings routes (§5.3)

/// One command of an installed application with its settings in a room.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoomCommand {
    /// `<application ref>/<command id>`
    #[serde(rename = "ref")]
    pub reference: String,
    pub command: CommandDefinition,
    pub settings: CommandSettings,
    /// The mask the invoker needs with these settings (decimal).
    pub effective_permissions: String,
    /// Offered on this node (approval switched off or the definition approved).
    pub approved: bool,
}

/// An installed application and its commands in a room.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoomCommands {
    pub application: PaletteApplication,
    pub commands: Vec<RoomCommand>,
}

/// `GET /rooms/{room_id}/commands` (`manage_applications` or `manage_room`, like the installation list).
pub async fn room_list(state: &AppState, auth: &AuthUser, room_id: &str) -> Result<Vec<RoomCommands>, ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_view_applications()?;
    let settings = store::commands::settings_of_room(&state.db, room_id).await?;
    let mut out = Vec::new();
    for inst in store::installations::of_room(&state.db, room_id).await? {
        let Some(bot) = store::users::by_id(&state.db, &inst.bot_user_id).await? else { continue };
        let approvals = store::commands::approvals(&state.db, &inst.application_ref).await?;
        let commands = store::commands::of_app(&state.db, &inst.application_ref)
            .await?
            .iter()
            .map(|row| {
                let def = definition_of(row);
                let s = CommandSettings::of(settings.get(&row.id));
                RoomCommand {
                    reference: format!("{}/{}", inst.application_ref, row.id),
                    effective_permissions: s.required(&def).to_string(),
                    approved: approved(state, &approvals, &row.definition_hash),
                    command: def,
                    settings: s,
                }
            })
            .collect();
        out.push(RoomCommands {
            application: PaletteApplication {
                reference: inst.application_ref.clone(),
                name: bot.display_name.clone(),
                bot: bot.address(),
            },
            commands,
        });
    }
    Ok(out)
}

/// The number of an installation's commands offered in the room (enabled and approved), for `enabled_commands`.
pub async fn enabled_count(state: &AppState, room_id: &str, application_ref: &str) -> Result<i64, ApiError> {
    let settings = store::commands::settings_of_room(&state.db, room_id).await?;
    let approvals = store::commands::approvals(&state.db, application_ref).await?;
    Ok(store::commands::of_app(&state.db, application_ref)
        .await?
        .iter()
        .filter(|r| CommandSettings::of(settings.get(&r.id)).enabled && approved(state, &approvals, &r.definition_hash))
        .count() as i64)
}

/// `PUT /rooms/{room_id}/commands/{command_ref}` body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutCommandSettings {
    /// Default true.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Decimal mask replacing `default_permissions`; null = the default.
    #[serde(default)]
    pub permissions: Option<String>,
    /// Role ids of this room; empty = no role restriction.
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    /// Channel ids of this room where the command is disabled.
    #[serde(default)]
    pub disabled_channels: Vec<String>,
}

/// The command `command_ref` of an application installed in the room (`404 command.not_found`).
async fn room_command(state: &AppState, room_id: &str, command_ref: &str) -> Result<(String, CommandRow), ApiError> {
    let (app_ref, id) = parse_command_ref(command_ref)?;
    let inst = store::installations::of_room(&state.db, room_id)
        .await?
        .into_iter()
        .find(|i| i.application_ref.eq_ignore_ascii_case(&app_ref))
        .ok_or_else(not_found)?;
    let row = store::commands::of_app(&state.db, &inst.application_ref)
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(not_found)?;
    Ok((inst.application_ref, row))
}

/// `PUT /rooms/{room_id}/commands/{command_ref}` (`manage_applications`): replaces the settings of one command.
pub async fn put_room_setting(
    state: &AppState,
    auth: &AuthUser,
    room_id: &str,
    command_ref: &str,
    req: PutCommandSettings,
) -> Result<RoomCommand, ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_manage_applications()?;
    let (app_ref, row) = room_command(state, room_id, command_ref).await?;
    let bad = |field: &str, detail: &str| ApiError::BadRequestMeta {
        code: "validation.invalid",
        detail: detail.to_string(),
        meta: json!({ "field": field }),
    };
    let permissions = match req.permissions.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => Some(p::parse(s).ok_or_else(|| bad("permissions", "permissions: a decimal permission mask"))?),
    };
    if req.allowed_roles.len() > MAX_SETTING_IDS || req.disabled_channels.len() > MAX_SETTING_IDS {
        return Err(bad("allowed_roles", "At most 100 roles and 100 channels"));
    }
    let roles = store::rooms::roles(&state.db, room_id).await?;
    let mut allowed_roles: Vec<String> = Vec::new();
    for id in &req.allowed_roles {
        let role = roles
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| bad("allowed_roles", "allowed_roles: roles of this room"))?;
        if !allowed_roles.contains(&role.id) {
            allowed_roles.push(role.id.clone());
        }
    }
    let channels = store::rooms::channels(&state.db, room_id).await?;
    let mut disabled_channels: Vec<String> = Vec::new();
    for id in &req.disabled_channels {
        let channel = channels
            .iter()
            .find(|c| c.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| bad("disabled_channels", "disabled_channels: channels of this room"))?;
        if !disabled_channels.contains(&channel.id) {
            disabled_channels.push(channel.id.clone());
        }
    }
    let enabled = req.enabled.unwrap_or(true);
    store::commands::put_setting(
        &state.db,
        store::commands::NewSetting {
            room_id,
            command_id: &row.id,
            application_ref: &app_ref,
            enabled,
            permissions,
            allowed_roles: &allowed_roles,
            disabled_channels: &disabled_channels,
        },
    )
    .await?;
    let reference = format!("{app_ref}/{}", row.id);
    let settings =
        CommandSettings { enabled, permissions: permissions.map(|p| p.to_string()), allowed_roles, disabled_channels };
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(&auth.user.id),
        "command.settings",
        &reference,
        "",
        json!({ "command": reference, "name": row.name, "settings": settings }),
    )
    .await?;
    announce_room(state, room_id).await;
    let def = definition_of(&row);
    let approvals = store::commands::approvals(&state.db, &app_ref).await?;
    Ok(RoomCommand {
        reference,
        effective_permissions: settings.required(&def).to_string(),
        approved: approved(state, &approvals, &row.definition_hash),
        command: def,
        settings,
    })
}

/// `DELETE /rooms/{room_id}/commands/{command_ref}` (`manage_applications`): back to the defaults.
pub async fn reset_room_setting(
    state: &AppState,
    auth: &AuthUser,
    room_id: &str,
    command_ref: &str,
) -> Result<(), ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_manage_applications()?;
    let (app_ref, row) = room_command(state, room_id, command_ref).await?;
    store::commands::delete_setting(&state.db, room_id, &row.id).await?;
    let reference = format!("{app_ref}/{}", row.id);
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(&auth.user.id),
        "command.settings",
        &reference,
        "",
        json!({ "command": reference, "name": row.name, "settings": null }),
    )
    .await?;
    announce_room(state, room_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn weather() -> Value {
        json!({
            "name": "weather", "description": "Forecast for a city",
            "args": [
                { "name": "city", "description": "City name", "type": "string", "required": true, "max_length": 100 },
                { "name": "units", "description": "Unit system", "type": "string", "required": false,
                  "options": [ { "name": "Metric", "value": "metric" }, { "name": "Imperial", "value": "imperial" } ] },
                { "name": "days", "description": "Days", "type": "integer", "min": 1, "max": 7 }
            ],
            "default_permissions": null, "dm_allowed": true
        })
    }

    fn path_of(e: &ApiError) -> String {
        e.to_problem(None).meta["path"].as_str().unwrap_or("").to_string()
    }

    #[test]
    fn definitions_are_canonical_and_hashed() {
        let v = validate_definition("c", &weather()).unwrap();
        assert!(v.canonical.starts_with("{\"args\":["), "{}", v.canonical);
        assert!(v.canonical.contains("\"max\":7,\"min\":1"), "integers stay integers in JCS: {}", v.canonical);
        assert_eq!(v.hash, util::sha256_b64(&v.canonical));
        // The same definition with its keys in another order and an id has the same hash.
        let mut other = weather();
        other["id"] = json!(util::ulid());
        let o = other.as_object().unwrap().clone();
        let reordered: Map<String, Value> = o.into_iter().rev().collect();
        assert_eq!(validate_definition("c", &Value::Object(reordered)).unwrap().hash, v.hash);
        // A changed description changes the hash.
        let mut changed = weather();
        changed["description"] = json!("Another text");
        assert_ne!(validate_definition("c", &changed).unwrap().hash, v.hash);
    }

    #[test]
    fn invalid_definitions_name_the_path() {
        type Tweak = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(Tweak, &str)> = vec![
            (Box::new(|v| v["name"] = json!("Weather")), "c.name"),
            (Box::new(|v| v["name"] = json!("a".repeat(33))), "c.name"),
            (Box::new(|v| v["description"] = json!("")), "c.description"),
            (Box::new(|v| v["description"] = json!("x".repeat(101))), "c.description"),
            (Box::new(|v| v["extra"] = json!(1)), "c.extra"),
            (Box::new(|v| v["args"][0]["type"] = json!("date")), "c.args[0].type"),
            (Box::new(|v| v["args"][0]["unknown"] = json!(true)), "c.args[0].unknown"),
            (Box::new(|v| v["args"][2]["required"] = json!(true)), "c.args[2].required"),
            (Box::new(|v| v["args"][1]["name"] = json!("city")), "c.args[1].name"),
            (Box::new(|v| v["args"][1]["options"][0]["value"] = json!(3)), "c.args[1].options[0].value"),
            (Box::new(|v| v["args"][1]["options"][1]["value"] = json!("metric")), "c.args[1].options[1].value"),
            (Box::new(|v| v["args"][0]["max_length"] = json!(1001)), "c.args[0].max_length"),
            (Box::new(|v| v["args"][2]["max_length"] = json!(10)), "c.args[2].max_length"),
            (Box::new(|v| v["args"][0]["min"] = json!(1)), "c.args[0].min"),
            (Box::new(|v| v["args"][2]["min"] = json!(1.5)), "c.args[2].min"),
            (Box::new(|v| v["args"][2]["min"] = json!(9)), "c.args[2].max"),
            (
                Box::new(|v| v["args"][2]["options"] = json!([{ "name": "x", "value": "1" }])),
                "c.args[2].options[0].value",
            ),
            (Box::new(|v| v["default_permissions"] = json!("nope")), "c.default_permissions"),
            (Box::new(|v| v["dm_allowed"] = json!("yes")), "c.dm_allowed"),
        ];
        for (tweak, path) in cases {
            let mut v = weather();
            tweak(&mut v);
            let err = validate_definition("c", &v).unwrap_err();
            assert_eq!((err.code(), path_of(&err).as_str()), ("command.invalid", path), "{v}");
        }
        // Booleans and users take no options.
        let mut v = weather();
        v["args"][1]["type"] = json!("boolean");
        assert_eq!(path_of(&validate_definition("c", &v).unwrap_err()), "c.args[1].options");
    }

    #[test]
    fn set_limits() {
        let many: Vec<Value> =
            (0..=MAX_COMMANDS).map(|i| json!({ "name": format!("c{i}"), "description": "d" })).collect();
        assert_eq!(validate_set(&many).unwrap_err().code(), "command.limit");
        assert!(validate_set(&many[..MAX_COMMANDS]).is_ok());
        let args: Vec<Value> =
            (0..=MAX_ARGS).map(|i| json!({ "name": format!("a{i}"), "description": "d", "type": "string" })).collect();
        let err = validate_set(&[json!({ "name": "x", "description": "d", "args": args })]).unwrap_err();
        assert_eq!(err.code(), "command.limit");
        let options: Vec<Value> = (0..=MAX_OPTIONS).map(|i| json!({ "name": format!("o{i}"), "value": i })).collect();
        let arg = json!({ "name": "a", "description": "d", "type": "integer", "options": options });
        assert_eq!(
            validate_set(&[json!({ "name": "x", "description": "d", "args": [arg] })]).unwrap_err().code(),
            "command.limit"
        );
        let dup = [json!({ "name": "x", "description": "d" }), json!({ "name": "x", "description": "e" })];
        assert_eq!(path_of(&validate_set(&dup).unwrap_err()), "commands[1].name");
        // 64 KiB over the whole set.
        let big: Vec<Value> = (0..100)
            .map(|i| {
                let args: Vec<Value> = (0..25)
                    .map(|j| json!({ "name": format!("a{j}"), "description": "d".repeat(100), "type": "string" }))
                    .collect();
                json!({ "name": format!("c{i}"), "description": "d", "args": args })
            })
            .collect();
        assert_eq!(validate_set(&big).unwrap_err().code(), "command.limit");
    }

    #[test]
    fn remote_sets_skip_what_they_cannot_parse() {
        let mut good = weather();
        good["id"] = json!(util::ulid());
        let mut future = json!({ "name": "later", "description": "d", "args": [{ "name": "a", "description": "d", "type": "date" }] });
        future["id"] = json!(util::ulid());
        let no_id = json!({ "name": "anon", "description": "d" });
        let parsed = parse_remote(&[good.clone(), future, no_id, good]);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "weather");
    }

    #[test]
    fn arguments_follow_the_definition() {
        let v = validate_definition("c", &weather()).unwrap();
        let def: CommandDefinition = serde_json::from_str(&v.canonical).unwrap();
        let ok = validate_args(&def, Some(&json!({ "city": "Berlin", "units": "metric", "days": 3 }))).unwrap();
        assert_eq!(ok, json!({ "city": "Berlin", "units": "metric", "days": 3 }));
        let arg_of = |args: Value| {
            let e = validate_args(&def, Some(&args)).unwrap_err();
            (e.code().to_string(), e.to_problem(None).meta["arg"].as_str().unwrap_or("").to_string())
        };
        let bad = "command.args_invalid".to_string();
        assert_eq!(arg_of(json!({})), (bad.clone(), "city".into()));
        assert_eq!(arg_of(json!({ "city": "B", "units": "kelvin" })), (bad.clone(), "units".into()));
        assert_eq!(arg_of(json!({ "city": "B", "days": 8 })), (bad.clone(), "days".into()));
        assert_eq!(arg_of(json!({ "city": "B", "days": 2.5 })), (bad.clone(), "days".into()));
        assert_eq!(arg_of(json!({ "city": "x".repeat(101) })), (bad.clone(), "city".into()));
        assert_eq!(arg_of(json!({ "city": 5 })), (bad.clone(), "city".into()));
        assert_eq!(arg_of(json!({ "city": "B", "evil": 1 })), (bad.clone(), "evil".into()));
        assert_eq!(validate_args(&def, Some(&json!([1]))).unwrap_err().code(), "command.args_invalid");
        // Users are addresses, channels and roles ids.
        let users: CommandDefinition = serde_json::from_value(json!({
            "name": "u", "description": "d", "args": [
                { "name": "who", "description": "d", "type": "user", "required": true },
                { "name": "where", "description": "d", "type": "channel" },
                { "name": "flag", "description": "d", "type": "boolean" }
            ]
        }))
        .unwrap();
        assert_eq!(
            validate_args(&users, Some(&json!({ "who": "Alice@Node.Test" }))).unwrap()["who"],
            "alice@node.test"
        );
        assert!(validate_args(&users, Some(&json!({ "who": "alice" }))).is_err());
        assert!(validate_args(&users, Some(&json!({ "who": "ab@b.test", "where": "general" }))).is_err());
        assert!(validate_args(&users, Some(&json!({ "who": "ab@b.test", "flag": "yes" }))).is_err());
        assert!(
            validate_args(&users, Some(&json!({ "who": "ab@b.test", "where": util::ulid(), "flag": true }))).is_ok()
        );
    }

    #[test]
    fn command_references() {
        let (a, c) = (util::ulid(), util::ulid());
        assert_eq!(parse_command_ref(&format!("Node.Test/{a}/{c}")).unwrap(), (format!("node.test/{a}"), c.clone()));
        for bad in ["", "x", &format!("node.test/{a}"), &format!("node.test/{a}/x"), &format!("{a}/{c}")] {
            assert_eq!(parse_command_ref(bad).unwrap_err().code(), "command.not_found", "{bad}");
        }
    }
}
