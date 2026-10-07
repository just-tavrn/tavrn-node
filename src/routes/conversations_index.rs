// SPDX-License-Identifier: AGPL-3.0-only
//! Conversation index (FEDERATION.md §4): the client-maintained list of every room and conversation the
//! user belongs to, on any node. The home node stores it in plaintext, never validates entries against
//! other nodes and keeps unknown entry fields unchanged. Writes replace the whole list; `If-Match` with
//! the current version (`ETag`) makes them conditional.

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    federation::{guard::local_only, valid_node_domain},
    store, util,
    validate::bad,
};

/// At most this many entries (§4).
pub const MAX_ENTRIES: usize = 2000;
/// Largest accepted request body (§4).
pub const MAX_BODY_BYTES: usize = 512 * 1024;

/// One index entry. Unknown fields are stored and returned unchanged.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct IndexEntry {
    /// Domain of the node that hosts the room or conversation (the own domain included).
    pub node: String,
    /// `room`, `dm` or `group`.
    pub kind: String,
    /// Required for `room`, null otherwise.
    pub room_id: Option<String>,
    /// Required for `dm` and `group`, null for `room`.
    pub conversation_id: Option<String>,
    /// `dm` only: the other party's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// RFC 3339 time of the join.
    pub joined_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct ConversationIndex {
    /// Grows with every write; also sent as `ETag: "<version>"`. 0 = no index stored yet.
    pub version: i64,
    #[schema(value_type = Vec<IndexEntry>)]
    pub items: Vec<Value>,
}

#[derive(Deserialize, ToSchema)]
pub struct PutConversationIndex {
    pub items: Vec<IndexEntry>,
}

fn too_large() -> ApiError {
    ApiError::PayloadTooLarge {
        code: "index.too_large",
        detail: format!("The index may have at most {MAX_ENTRIES} entries and {} KiB", MAX_BODY_BYTES / 1024),
        meta: serde_json::json!({ "max_entries": MAX_ENTRIES, "max_bytes": MAX_BODY_BYTES }),
    }
}

fn respond(version: i64, items: Vec<Value>) -> Response {
    let mut resp = Json(ConversationIndex { version, items }).into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&format!("\"{version}\"")) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The own index; only local users with a full session (remote users: `federation.local_only`).
fn owner(auth: &AuthUser) -> Result<(), ApiError> {
    if auth.is_remote() { Err(local_only()) } else { Ok(()) }
}

fn str_field<'a>(entry: &'a Map<String, Value>, field: &str) -> Result<Option<&'a str>, ApiError> {
    match entry.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(bad("validation.type", format!("{field}: expected text"))),
    }
}

/// Validates one entry and returns its identity `(node, kind, id)` for the uniqueness check.
pub fn validate_entry(own_domain: &str, entry: &Value) -> Result<(String, String, String), ApiError> {
    let e = entry.as_object().ok_or_else(|| bad("validation.type", "Every entry must be an object"))?;
    let node = str_field(e, "node")?.ok_or_else(|| bad("validation.required", "node is missing"))?;
    if node != own_domain && !valid_node_domain(node) {
        return Err(bad("validation.domain", format!("node: '{node}' is not a valid node domain")));
    }
    let kind = str_field(e, "kind")?.ok_or_else(|| bad("validation.required", "kind is missing"))?;
    let room_id = str_field(e, "room_id")?;
    let conversation_id = str_field(e, "conversation_id")?;
    let id = match kind {
        "room" => {
            if conversation_id.is_some() {
                return Err(bad("validation.field", "conversation_id: not allowed with kind = room"));
            }
            room_id.ok_or_else(|| bad("validation.required", "room_id is missing"))?
        }
        "dm" | "group" => {
            if room_id.is_some() {
                return Err(bad("validation.field", "room_id: only with kind = room"));
            }
            conversation_id.ok_or_else(|| bad("validation.required", "conversation_id is missing"))?
        }
        _ => return Err(bad("validation.enum", "kind: allowed are room, dm, group")),
    };
    if !util::is_ulid(id) {
        return Err(bad("validation.id", "room_id/conversation_id: not a valid ID"));
    }
    if let Some(peer) = str_field(e, "peer")?
        && util::parse_address(peer).is_none()
    {
        return Err(bad("validation.address", "peer: expected an address like alice@node.example"));
    }
    let joined_at = str_field(e, "joined_at")?.ok_or_else(|| bad("validation.required", "joined_at is missing"))?;
    if util::parse_time(joined_at).is_none() {
        return Err(bad("validation.time", "joined_at: expected an RFC 3339 timestamp"));
    }
    Ok((node.to_string(), kind.to_string(), id.to_string()))
}

/// Validates a whole list: entries, limits and uniqueness of `(node, kind, id)`.
pub fn validate_items(own_domain: &str, items: &[Value]) -> Result<(), ApiError> {
    if items.len() > MAX_ENTRIES {
        return Err(too_large());
    }
    let mut seen = std::collections::HashSet::with_capacity(items.len());
    for entry in items {
        let key = validate_entry(own_domain, entry)?;
        if !seen.insert(key) {
            return Err(bad("validation.duplicate", "A room or conversation appears twice in the index"));
        }
    }
    Ok(())
}

/// `If-Match: "7"` (or `7`) → `Some(7)`; missing or `*` → `None` (unconditional write).
pub fn parse_if_match(headers: &HeaderMap) -> Result<Option<i64>, ApiError> {
    let Some(raw) = headers.get(header::IF_MATCH) else { return Ok(None) };
    let value = raw.to_str().map_err(|_| bad("validation.if_match", "Invalid If-Match"))?.trim();
    if value == "*" {
        return Ok(None);
    }
    let version = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
    version
        .parse::<i64>()
        .ok()
        .filter(|v| *v >= 0)
        .map(Some)
        .ok_or_else(|| bad("validation.if_match", "If-Match: expected a version like \"7\""))
}

/// The own conversation index (`ETag` = version).
#[utoipa::path(get, path = "/api/v1/users/me/conversations-index", security(("bearer" = [])),
    responses((status = 200, body = ConversationIndex), (status = 401, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn get_index(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    owner(&auth)?;
    let (version, items) = match store::home::conversation_index(&state.db, &auth.user.id).await? {
        Some((version, raw)) => (version, serde_json::from_str::<Vec<Value>>(&raw).unwrap_or_default()),
        None => (0, Vec::new()),
    };
    Ok(respond(version, items))
}

/// Replaces the conversation index. With `If-Match: "<version>"` a stale version fails with
/// `412 index.version_conflict` (`meta.version` = current); the client merges and retries. Without
/// `If-Match` the last writer wins.
#[utoipa::path(put, path = "/api/v1/users/me/conversations-index", security(("bearer" = [])),
    params(("If-Match" = Option<String>, Header, description = "Current version, e.g. \"7\"")),
    request_body = PutConversationIndex,
    responses((status = 200, body = ConversationIndex), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
        (status = 412, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_index(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    owner(&auth)?;
    state.read_limiter.check_all(&[format!("index:{}", auth.user.id)])?;
    let expected = parse_if_match(&headers)?;
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| too_large())?;
    let req: Value =
        serde_json::from_slice(&bytes).map_err(|_| bad("validation.json", "Expected a JSON object with items"))?;
    let items = req
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("validation.required", "items: expected a list"))?
        .clone();
    validate_items(&state.config.domain, &items)?;
    let raw = serde_json::to_string(&items).map_err(|e| ApiError::Internal(e.into()))?;
    match store::home::put_conversation_index(&state.db, &auth.user.id, &raw, expected).await? {
        Some(version) => Ok(respond(version, items)),
        None => {
            let current = store::home::conversation_index(&state.db, &auth.user.id).await?.map(|(v, _)| v).unwrap_or(0);
            Err(ApiError::PreconditionFailed {
                code: "index.version_conflict",
                detail: "The index has changed in the meantime; reload, merge and send again".into(),
                meta: serde_json::json!({ "version": current }),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    const ROOM: &str = "01J0000000000000000000000A";
    const CONV: &str = "01J0000000000000000000000B";

    fn room(node: &str) -> Value {
        json!({ "node": node, "kind": "room", "room_id": ROOM, "conversation_id": null, "joined_at": "2026-10-04T12:00:00Z" })
    }

    #[test]
    fn valid_entries_pass() {
        assert!(validate_entry("h.example", &room("community.example")).is_ok());
        assert!(validate_entry("localhost", &room("localhost")).is_ok(), "the own domain is always fine");
        let dm = json!({ "node": "h.example", "kind": "dm", "conversation_id": CONV, "peer": "bob@b.example", "joined_at": "2026-10-04T12:00:00.000Z", "x-future": [1] });
        assert_eq!(validate_entry("h.example", &dm).unwrap(), ("h.example".into(), "dm".into(), CONV.into()));
        let group = json!({ "node": "h.example", "kind": "group", "room_id": null, "conversation_id": CONV, "joined_at": "2026-10-04T12:00:00Z" });
        assert!(validate_entry("h.example", &group).is_ok());
    }

    #[test]
    fn malformed_entries_fail_with_validation_codes() {
        let code = |v: Value| validate_entry("h.example", &v).err().map(|e| e.code().to_string()).unwrap_or_default();
        assert_eq!(code(json!("x")), "validation.type");
        assert_eq!(code(room("localhost")), "validation.domain", "a foreign dotless name is no node domain");
        assert_eq!(code(room("https://evil.example")), "validation.domain");
        assert_eq!(
            code(
                json!({ "node": "a.example", "kind": "channel", "room_id": ROOM, "joined_at": "2026-10-04T12:00:00Z" })
            ),
            "validation.enum"
        );
        assert_eq!(
            code(json!({ "node": "a.example", "kind": "room", "joined_at": "2026-10-04T12:00:00Z" })),
            "validation.required"
        );
        assert_eq!(
            code(
                json!({ "node": "a.example", "kind": "room", "room_id": "nope", "joined_at": "2026-10-04T12:00:00Z" })
            ),
            "validation.id"
        );
        assert_eq!(
            code(
                json!({ "node": "a.example", "kind": "room", "room_id": ROOM, "conversation_id": CONV, "joined_at": "2026-10-04T12:00:00Z" })
            ),
            "validation.field"
        );
        assert_eq!(
            code(
                json!({ "node": "a.example", "kind": "dm", "room_id": ROOM, "conversation_id": CONV, "joined_at": "2026-10-04T12:00:00Z" })
            ),
            "validation.field"
        );
        assert_eq!(
            code(
                json!({ "node": "a.example", "kind": "dm", "conversation_id": CONV, "peer": "bob", "joined_at": "2026-10-04T12:00:00Z" })
            ),
            "validation.address"
        );
        assert_eq!(
            code(json!({ "node": "a.example", "kind": "room", "room_id": ROOM, "joined_at": "yesterday" })),
            "validation.time"
        );
        assert_eq!(
            code(json!({ "node": "a.example", "kind": "room", "room_id": 5, "joined_at": "2026-10-04T12:00:00Z" })),
            "validation.type"
        );
    }

    #[test]
    fn lists_are_unique_and_bounded() {
        assert_eq!(
            validate_items("h.example", &[room("a.example"), room("a.example")]).unwrap_err().code(),
            "validation.duplicate"
        );
        assert!(
            validate_items("h.example", &[room("a.example"), room("b.example")]).is_ok(),
            "same id on two nodes is fine"
        );
        let many: Vec<Value> = (0..=MAX_ENTRIES).map(|_| room("a.example")).collect();
        assert_eq!(validate_items("h.example", &many).unwrap_err().code(), "index.too_large");
    }

    #[test]
    fn if_match_parsing() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::IF_MATCH, HeaderValue::from_str(v).unwrap());
            parse_if_match(&h)
        };
        assert_eq!(parse_if_match(&HeaderMap::new()).unwrap(), None);
        assert_eq!(with("\"7\"").unwrap(), Some(7));
        assert_eq!(with("0").unwrap(), Some(0));
        assert_eq!(with("*").unwrap(), None);
        assert!(with("\"-1\"").is_err());
        assert!(with("W/\"abc\"").is_err());
    }
}
