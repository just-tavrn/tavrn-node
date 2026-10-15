// SPDX-License-Identifier: AGPL-3.0-only
//! `GET /rooms/{room_id}/search` (PROTOCOL.md §7d): full-text search over the
//! unencrypted channels of a room the caller may read. Encrypted channels and DMs are never searched here
//! (their search is the client's local index, protocol/SEARCH.md); DMs are always encrypted, so there is no
//! conversation search route.

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiQuery as Query, ProblemDetails},
    history,
    models::Message,
    permissions as p,
    search::{self, Cursor, Dialect, Order, Scope},
    store, util,
    validate::{self, bad},
};

pub fn routes() -> Router<AppState> {
    Router::new().route("/rooms/{room_id}/search", get(search_room))
}

#[derive(OpenApi)]
#[openapi(paths(search_room), components(schemas(SearchResponse, SearchHit, Searched)))]
pub struct SearchApi;

#[derive(Debug, Deserialize, IntoParams)]
pub struct SearchParams {
    /// Words to find (prefix match, all required), at most 256 characters; never interpreted as syntax.
    /// May be empty when a filter is set (e.g. all files of an author).
    pub q: Option<String>,
    /// Only this channel of the room.
    pub channel: Option<String>,
    /// Only messages of this author (`user@domain`).
    pub author: Option<String>,
    /// Only messages created before this time (RFC 3339 or `YYYY-MM-DD`, exclusive).
    pub before: Option<String>,
    /// Only messages created at or after this time (RFC 3339 or `YYYY-MM-DD`).
    pub after: Option<String>,
    /// `file`: only messages with attachments.
    pub has: Option<String>,
    /// `newest` (default) or `relevance`.
    pub sort: Option<String>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
    /// Results per page, 1–50 (default 25).
    pub limit: Option<i64>,
}

/// One result: the message envelope (like `GET …/messages`) and a snippet of its text.
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchHit {
    pub message: Message,
    /// Plain text around the first match, at most about 130 characters; every match is wrapped in U+0001 …
    /// U+0002 (never markup: clients render the markers as highlights and escape everything else).
    pub snippet: String,
    /// Relevance (higher is better; 0 without query words). Only comparable within one response.
    pub rank: f64,
}

/// What was searched, so that clients can say so honestly.
#[derive(Debug, Serialize, ToSchema)]
pub struct Searched {
    /// Always `node`: the node's full-text index over plaintext.
    pub kind: String,
    /// Unencrypted channels of the room the caller may read that were searched.
    pub channels: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchResponse {
    pub results: Vec<SearchHit>,
    /// Cursor of the next page; null on the last page.
    pub next_cursor: Option<String>,
    pub searched: Searched,
}

/// A time filter as a ULID floor (message ids are ULIDs, so `id >= floor(t)` selects messages from `t` on).
fn time_floor(field: &'static str, value: &str) -> Result<String, ApiError> {
    let t: Option<DateTime<Utc>> = util::parse_time(value).or_else(|| {
        NaiveDate::parse_from_str(value, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc())
    });
    match t {
        Some(t) if t.timestamp_millis() >= 0 => Ok(history::ulid_floor(t)),
        _ => Err(bad("search.date_invalid", format!("{field}: RFC 3339 time or YYYY-MM-DD"))),
    }
}

fn parse_cursor(order: Order, cursor: Option<&str>) -> Result<Cursor, ApiError> {
    let invalid = || bad("search.cursor_invalid", "cursor: the next_cursor of the previous page");
    match (order, cursor) {
        (_, None) => Ok(Cursor::Start),
        (Order::Newest, Some(c)) if util::is_ulid(c) => Ok(Cursor::Before(c.to_ascii_uppercase())),
        (Order::Relevance, Some(c)) => {
            let n =
                c.strip_prefix('o').filter(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()));
            match n.and_then(|n| n.parse::<i64>().ok()) {
                Some(o) if (1..=search::MAX_OFFSET).contains(&o) => Ok(Cursor::Offset(o)),
                _ => Err(invalid()),
            }
        }
        _ => Err(invalid()),
    }
}

/// Search the unencrypted channels of a room (`view_channel`; without `read_history` only since the join).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/search", security(("bearer" = [])), params(("room_id" = String, Path), SearchParams),
    responses((status = 200, body = SearchResponse), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails),
              (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn search_room(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, ApiError> {
    if !state.config.search_enabled {
        return Err(ApiError::NotFound { code: "search.disabled", what: "Search".into() });
    }
    state.search_limiter.check_all(&[format!("search:{}", auth.user.id)])?;
    let access = access::room_access(&state, &room_id, &auth.user).await?;

    // Input: limits first, then the filters.
    let q = params.q.as_deref().unwrap_or("").trim();
    if q.chars().count() > search::MAX_QUERY_CHARS {
        return Err(bad("search.query_too_long", format!("q: at most {} characters", search::MAX_QUERY_CHARS)));
    }
    let terms = search::query_terms(q);
    let channel =
        params.channel.as_deref().map(|c| validate::ulid("channel", c)).transpose()?.map(|c| c.to_ascii_uppercase());
    let after = params.after.as_deref().map(|v| time_floor("after", v)).transpose()?;
    let before = params.before.as_deref().map(|v| time_floor("before", v)).transpose()?;
    let has_file = match params.has.as_deref() {
        None => false,
        Some("file") => true,
        Some(_) => return Err(bad("search.has_invalid", "has: only `file`")),
    };
    let order = match params.sort.as_deref() {
        None | Some("newest") => Order::Newest,
        Some("relevance") => Order::Relevance,
        Some(_) => return Err(bad("search.sort_invalid", "sort: newest or relevance")),
    };
    let cursor = parse_cursor(order, params.cursor.as_deref())?;
    let limit = validate::limit(params.limit, search::DEFAULT_RESULTS, search::MAX_RESULTS);
    let author = match params.author.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(a) => {
            let lower = a.to_lowercase();
            let (username, domain) =
                util::parse_address(&lower).ok_or_else(|| bad("search.author_invalid", "author: user@domain"))?;
            // An unknown author matches nothing (no error: the answer must not tell who exists).
            Some(store::users::by_username(&state.db, username, domain).await?.map(|u| u.id).unwrap_or_default())
        }
    };
    if terms.is_empty() && author.is_none() && !has_file && after.is_none() && before.is_none() {
        return Err(bad("search.query_empty", "q needs at least one word (letters or digits) unless a filter is set"));
    }

    // Scope: unencrypted channels with user messages (not voice, files or the welcome channel, whose
    // system messages are never indexed) the caller may view; without `read_history` from the join on.
    let channels = store::rooms::channels(&state.db, &room_id).await?;
    let overrides = store::rooms::overrides_of_room(&state.db, &room_id).await?;
    let joined_floor = access.member.as_ref().and_then(|m| util::parse_time(&m.joined_at)).map(history::ulid_floor);
    let mut scope = Scope::default();
    let searchable = |c: &&crate::models::ChannelRow| {
        c.encrypted == 0
            && !matches!(c.kind.as_str(), "voice" | "files" | "system")
            && channel.as_ref().is_none_or(|id| *id == c.id)
    };
    for c in channels.iter().filter(searchable) {
        let perms = access::channel_perms_with(&access, c, &overrides, &auth.user.id);
        if !p::has(perms, p::VIEW_CHANNEL) {
            continue;
        }
        match (&joined_floor, p::has(perms, p::READ_HISTORY)) {
            (Some(floor), false) => scope.cut.push((c.id.clone(), floor.clone())),
            _ => scope.full.push(c.id.clone()),
        }
    }

    let query = search::Query {
        terms: &terms,
        scope: &scope,
        author_id: author.as_deref(),
        after,
        before,
        has_file,
        order,
        cursor: cursor.clone(),
        limit,
    };
    let mut hits = search::run(&state.db, Dialect::of(&state.config.database_url), &query).await?;
    let more = hits.len() as i64 > limit;
    hits.truncate(limit as usize);
    let next_cursor = more
        .then(|| match (order, &cursor) {
            (Order::Newest, _) => hits.last().map(|h| h.message_id.clone()),
            (Order::Relevance, Cursor::Offset(o)) => Some(format!("o{}", o + limit)),
            (Order::Relevance, _) => Some(format!("o{limit}")),
        })
        .flatten()
        .filter(|c| !c.starts_with('o') || c[1..].parse::<i64>().is_ok_and(|o| o <= search::MAX_OFFSET));

    let ids: Vec<String> = hits.iter().map(|h| h.message_id.clone()).collect();
    let rows = store::messages::by_ids(&state.db, &ids).await?;
    let messages = crate::routes::messages::enrich(&state, &auth.user.id, &rows).await?;
    let mut by_id: std::collections::HashMap<String, Message> =
        messages.into_iter().map(|m| (m.id.clone(), m)).collect();
    let results = hits
        .into_iter()
        .filter_map(|h| {
            let m = by_id.remove(&h.message_id)?;
            let files: Vec<String> = m.attachments.iter().map(|a| a.name.clone()).collect();
            let content = serde_json::to_string(&m.content).unwrap_or_default();
            let text = search::searchable_text(&content, &files).unwrap_or_default();
            Some(SearchHit { snippet: search::snippet(&text, &terms), message: m, rank: h.rank })
        })
        .collect();
    Ok(Json(SearchResponse {
        results,
        next_cursor,
        searched: Searched { kind: "node".into(), channels: scope.len() as i64 },
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn time_filters() {
        assert_eq!(
            time_floor("after", "2026-10-06").unwrap(),
            history::ulid_floor(util::parse_time("2026-10-06T00:00:00Z").unwrap())
        );
        assert!(time_floor("after", "2026-10-06T12:00:00+02:00").is_ok());
        for bad in ["", "yesterday", "2026-13-01", "1969-12-31", "2026-10-06 12:00"] {
            assert_eq!(time_floor("after", bad).unwrap_err().code(), "search.date_invalid", "{bad}");
        }
    }

    #[test]
    fn cursors_are_strict() {
        let id = util::ulid();
        assert_eq!(parse_cursor(Order::Newest, None).unwrap(), Cursor::Start);
        assert_eq!(parse_cursor(Order::Newest, Some(&id)).unwrap(), Cursor::Before(id.clone()));
        assert_eq!(parse_cursor(Order::Relevance, Some("o25")).unwrap(), Cursor::Offset(25));
        for (order, c) in [
            (Order::Newest, "o25"),
            (Order::Relevance, id.as_str()),
            (Order::Relevance, "o0"),
            (Order::Relevance, "o501"),
            (Order::Relevance, "o-1"),
            (Order::Relevance, "o"),
            (Order::Relevance, "o99999"),
            (Order::Newest, "' OR 1=1 --"),
        ] {
            assert_eq!(parse_cursor(order, Some(c)).unwrap_err().code(), "search.cursor_invalid", "{c}");
        }
    }
}
