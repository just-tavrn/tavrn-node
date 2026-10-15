// SPDX-License-Identifier: AGPL-3.0-only
//! Node-side message search (PROTOCOL.md §7d, protocol/SEARCH.md §2).
//!
//! The node indexes only what it can read anyway: plaintext `text`/`action` messages of unencrypted room
//! channels (body, embed titles and descriptions, attachment file names). Encrypted channels and DMs are
//! never indexed here; their search runs in the client's local encrypted index.
//!
//! The index is the table `message_search` (migration 0210) with the normalized words of a message in
//! `terms`. PostgreSQL searches it through a generated `tsvector` column (configuration `simple`, so no
//! extension is needed) with a GIN index, SQLite (`--dev`) through an FTS5 external-content table. Both are
//! created by [`ensure_schema`] at startup. Rows are written when a message is sent or edited, removed with
//! the message (`ON DELETE CASCADE`, also purges and channel deletions), dropped for a whole channel when it
//! is switched to encrypted and filled again when it is switched back. [`backfill`] indexes existing
//! messages once (nodes that had messages before the search existed, or ran with search disabled).
//!
//! User input never reaches the query syntax: the query string is split into words (letters and digits
//! only) and every word becomes a quoted prefix term (`'word':*` for PostgreSQL, `"word"*` for FTS5), bound
//! as a parameter.

use std::collections::HashMap;

use serde_json::Value;
use sqlx::Row;
use unicode_normalization::UnicodeNormalization;

use crate::{app::AppState, db::Pool, error::ApiError};

/// Characters of a query (after trimming).
pub const MAX_QUERY_CHARS: usize = 256;
/// Words of a query that are used (more are ignored).
pub const MAX_TERMS: usize = 16;
/// Longest word kept (longer words are cut, on both the index and the query side).
pub const MAX_WORD_CHARS: usize = 64;
/// Characters of a message that are indexed.
pub const MAX_TEXT_CHARS: usize = 8000;
/// Results per page (default and maximum).
pub const DEFAULT_RESULTS: i64 = 25;
pub const MAX_RESULTS: i64 = 50;
/// Deepest page of the relevance order (offset cursor).
pub const MAX_OFFSET: i64 = 500;
/// Highlight markers in snippets: plain control characters, never markup (clients render them).
pub const MARK_START: char = '\u{1}';
pub const MARK_END: char = '\u{2}';
/// Characters of context on each side of the first match in a snippet.
pub const SNIPPET_CONTEXT: usize = 60;
/// Messages per backfill batch.
const BACKFILL_BATCH: i64 = 500;
/// `node_settings` key of the backfill progress (the last message id looked at).
const BACKFILL_CURSOR: &str = "search.backfill_cursor";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Sqlite,
}

impl Dialect {
    pub fn of(database_url: &str) -> Self {
        if database_url.starts_with("sqlite:") { Self::Sqlite } else { Self::Postgres }
    }
}

// ---------------------------------------------------------------- text

/// Lowercase NFKC (full-width letters, ligatures and compatibility forms become their plain form).
pub fn normalize(s: &str) -> String {
    s.nfkc().collect::<String>().to_lowercase()
}

/// Diacritics removed (`müller` → `muller`, `ß` → `ss`), for the folded variants in the index.
pub fn fold(s: &str) -> String {
    s.nfd().filter(|c| !unicode_normalization::char::is_combining_mark(*c)).collect::<String>().replace('ß', "ss")
}

/// The normalized words of a text: maximal runs of letters and digits, at most [`MAX_WORD_CHARS`] each.
/// Everything else (punctuation, quotes, operators, emoji, control characters) separates words.
pub fn words(text: &str) -> Vec<String> {
    let normalized = normalize(text);
    normalized
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.chars().take(MAX_WORD_CHARS).collect())
        .collect()
}

/// The `terms` column of a text: every distinct word and its folded variant, separated by spaces.
pub fn index_terms(text: &str) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for w in words(text) {
        let folded = fold(&w);
        for v in [w, folded] {
            // The folded variant may contain separators again in rare cases (decomposed compatibility
            // characters): split it like any text.
            for part in v.split(|c: char| !c.is_alphanumeric()).filter(|p| !p.is_empty()) {
                if seen.insert(part.to_string()) {
                    out.push(part.to_string());
                }
            }
        }
    }
    out.join(" ")
}

/// The words of a query, distinct, at most [`MAX_TERMS`]. The query is never interpreted as syntax.
pub fn query_terms(query: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in words(query) {
        if !out.contains(&w) {
            out.push(w);
        }
        if out.len() == MAX_TERMS {
            break;
        }
    }
    out
}

/// PostgreSQL `to_tsquery` text: every term a quoted prefix lexeme, all required.
pub fn pg_tsquery(terms: &[String]) -> String {
    terms.iter().map(|t| format!("'{}':*", t.replace('\\', "\\\\").replace('\'', "''"))).collect::<Vec<_>>().join(" & ")
}

/// FTS5 `MATCH` text: every term a quoted string with a prefix star, all required (implicit AND).
pub fn fts5_query(terms: &[String]) -> String {
    terms.iter().map(|t| format!("\"{}\"*", t.replace('"', "\"\""))).collect::<Vec<_>>().join(" ")
}

/// The searchable text of a plaintext content object (`text` and `action`): the body, embed titles,
/// descriptions, field names and values, and the attachment file names. `None` for anything else (system
/// messages, encrypted content, unknown types).
pub fn searchable_text(content: &str, files: &[String]) -> Option<String> {
    searchable_text_of(&serde_json::from_str(content).ok()?, files)
}

/// [`searchable_text`] of a parsed content object.
pub fn searchable_text_of(v: &Value, files: &[String]) -> Option<String> {
    let kind = v.get("type").and_then(Value::as_str)?;
    if kind != "text" && kind != "action" {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    if let Some(body) = v.get("body").and_then(Value::as_str) {
        parts.push(body);
    }
    for embed in v.get("embeds").and_then(Value::as_array).into_iter().flatten() {
        for key in ["title", "description"] {
            if let Some(s) = embed.get(key).and_then(Value::as_str) {
                parts.push(s);
            }
        }
        for field in embed.get("fields").and_then(Value::as_array).into_iter().flatten() {
            for key in ["name", "value"] {
                if let Some(s) = field.get(key).and_then(Value::as_str) {
                    parts.push(s);
                }
            }
        }
    }
    parts.extend(files.iter().map(String::as_str));
    let text: String =
        parts.join("\n").chars().filter(|c| *c != MARK_START && *c != MARK_END).take(MAX_TEXT_CHARS).collect();
    (!text.trim().is_empty()).then_some(text)
}

/// Does `word` (normalized) match a query term (prefix match, also diacritic-insensitive)?
fn word_matches(word: &str, terms: &[String]) -> bool {
    let folded = fold(word);
    terms.iter().any(|t| word.starts_with(t.as_str()) || folded.starts_with(t.as_str()) || folded.starts_with(&fold(t)))
}

/// A snippet of `text` around the first match of `terms` with every matching word wrapped in
/// [`MARK_START`]/[`MARK_END`]; `…` where the text was cut. Without a match: the start of the text.
pub fn snippet(text: &str, terms: &[String]) -> String {
    let chars: Vec<char> = text.chars().filter(|c| *c != MARK_START && *c != MARK_END).collect();
    // Word spans (char indices) of the original text that match a term.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_alphanumeric() {
            let start = i;
            while i < chars.len() && chars[i].is_alphanumeric() {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            if !terms.is_empty() && word_matches(&normalize(&word), terms) {
                spans.push((start, i));
            }
        } else {
            i += 1;
        }
    }
    let (from, to) = match spans.first() {
        Some(&(s, e)) => (s.saturating_sub(SNIPPET_CONTEXT), (e + SNIPPET_CONTEXT).min(chars.len())),
        None => (0, (2 * SNIPPET_CONTEXT).min(chars.len())),
    };
    let mut out = String::new();
    if from > 0 {
        out.push('…');
    }
    let mut pos = from;
    for &(s, e) in spans.iter().filter(|(s, e)| *s >= from && *e <= to) {
        out.extend(chars[pos..s].iter());
        out.push(MARK_START);
        out.extend(chars[s..e].iter());
        out.push(MARK_END);
        pos = e;
    }
    out.extend(chars[pos..to].iter());
    if to < chars.len() {
        out.push('…');
    }
    // Line breaks become spaces: a snippet is one line.
    out.split(['\n', '\r']).collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------- schema

/// Creates the database-specific full-text structures (idempotent; runs after the migrations).
pub async fn ensure_schema(db: &Pool, dialect: Dialect) -> anyhow::Result<()> {
    let statements: Vec<String> = match dialect {
        Dialect::Postgres => {
            let mut s = vec!["CREATE SEQUENCE IF NOT EXISTS message_search_rid_seq".to_string()];
            let int4: Option<String> = sqlx::query_scalar(
                "SELECT data_type FROM information_schema.columns WHERE table_name = 'message_search' AND column_name = 'rid' AND data_type = 'integer'",
            )
            .fetch_optional(db)
            .await?;
            if int4.is_some() {
                s.push("ALTER TABLE message_search ALTER COLUMN rid TYPE BIGINT".into());
            }
            s.extend([
                "ALTER TABLE message_search ALTER COLUMN rid SET DEFAULT nextval('message_search_rid_seq')".into(),
                "ALTER SEQUENCE message_search_rid_seq OWNED BY message_search.rid".into(),
                "ALTER TABLE message_search ADD COLUMN IF NOT EXISTS tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', terms)) STORED".into(),
                "CREATE INDEX IF NOT EXISTS message_search_tsv ON message_search USING GIN (tsv)".into(),
            ]);
            s
        }
        Dialect::Sqlite => vec![
            "CREATE VIRTUAL TABLE IF NOT EXISTS message_search_fts USING fts5(terms, content='message_search', content_rowid='rid', tokenize='unicode61 remove_diacritics 0')".into(),
            "CREATE TRIGGER IF NOT EXISTS message_search_ai AFTER INSERT ON message_search BEGIN
               INSERT INTO message_search_fts(rowid, terms) VALUES (new.rid, new.terms);
             END".into(),
            "CREATE TRIGGER IF NOT EXISTS message_search_ad AFTER DELETE ON message_search BEGIN
               INSERT INTO message_search_fts(message_search_fts, rowid, terms) VALUES ('delete', old.rid, old.terms);
             END".into(),
            "CREATE TRIGGER IF NOT EXISTS message_search_au AFTER UPDATE ON message_search BEGIN
               INSERT INTO message_search_fts(message_search_fts, rowid, terms) VALUES ('delete', old.rid, old.terms);
               INSERT INTO message_search_fts(rowid, terms) VALUES (new.rid, new.terms);
             END".into(),
        ],
    };
    for sql in statements {
        sqlx::query(&sql).execute(db).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------- writing

/// What decides whether a message is indexed.
struct Candidate {
    id: String,
    conversation_id: String,
    author_id: String,
    encrypted: i64,
    content: String,
    kind: String,
    conversation_encrypted: i64,
}

const CANDIDATE_SQL: &str = "SELECT m.id AS id, m.conversation_id AS conversation_id, m.author_id AS author_id, m.encrypted AS encrypted, m.content AS content, c.kind AS kind, c.encrypted AS conversation_encrypted
     FROM messages m JOIN conversations c ON c.id = m.conversation_id";

fn candidate(row: &sqlx::any::AnyRow) -> Result<Candidate, sqlx::Error> {
    Ok(Candidate {
        id: row.try_get("id")?,
        conversation_id: row.try_get("conversation_id")?,
        author_id: row.try_get("author_id")?,
        encrypted: row.try_get("encrypted")?,
        content: row.try_get("content")?,
        kind: row.try_get("kind")?,
        conversation_encrypted: row.try_get("conversation_encrypted")?,
    })
}

/// File names of the attachments of `ids`.
async fn file_names(db: &Pool, ids: &[String]) -> Result<HashMap<String, Vec<String>>, ApiError> {
    Ok(crate::store::blobs::by_messages(db, ids)
        .await?
        .into_iter()
        .map(|(id, blobs)| (id, blobs.into_iter().map(|b| b.name).collect()))
        .collect())
}

/// Writes or removes the index rows of `candidates`.
async fn apply(db: &Pool, candidates: &[Candidate]) -> Result<usize, ApiError> {
    if candidates.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = candidates.iter().map(|c| c.id.clone()).collect();
    let files = file_names(db, &ids).await?;
    let mut written = 0;
    for c in candidates {
        let eligible = c.kind == "channel" && c.encrypted == 0 && c.conversation_encrypted == 0;
        let text =
            eligible.then(|| searchable_text(&c.content, files.get(&c.id).map(Vec::as_slice).unwrap_or(&[]))).flatten();
        match text.map(|t| index_terms(&t)).filter(|t| !t.is_empty()) {
            Some(terms) => {
                sqlx::query(
                    "INSERT INTO message_search (message_id, conversation_id, author_id, terms) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (message_id) DO UPDATE SET terms = excluded.terms",
                )
                .bind(&c.id)
                .bind(&c.conversation_id)
                .bind(&c.author_id)
                .bind(&terms)
                .execute(db)
                .await?;
                written += 1;
            }
            None => {
                sqlx::query("DELETE FROM message_search WHERE message_id = $1").bind(&c.id).execute(db).await?;
            }
        }
    }
    Ok(written)
}

/// Indexes (or re-indexes after an edit) one message if it is searchable, from the message as it was just written
/// or edited (no read back; `channel` = it is in a room channel), and removes it otherwise. The caller runs it after
/// the broadcast, so the index never delays delivery, and only for unencrypted conversations. Best effort: a
/// failure is logged and never fails the request that wrote the message (the next start's backfill does not see it
/// again, so this is logged as a warning).
pub async fn index(state: &AppState, message: &crate::models::Message, channel: bool) {
    if !state.config.search_enabled {
        return;
    }
    let files: Vec<String> = message.attachments.iter().map(|a| a.name.clone()).collect();
    let text = (channel && !message.encrypted).then(|| searchable_text_of(&message.content, &files)).flatten();
    let result = match text.map(|t| index_terms(&t)).filter(|t| !t.is_empty()) {
        Some(terms) => sqlx::query(
            "INSERT INTO message_search (message_id, conversation_id, author_id, terms) VALUES ($1, $2, $3, $4)
             ON CONFLICT (message_id) DO UPDATE SET terms = excluded.terms",
        )
        .bind(&message.id)
        .bind(&message.conversation_id)
        .bind(&message.author_id)
        .bind(&terms)
        .execute(&state.db)
        .await
        .map(|_| ()),
        None => sqlx::query("DELETE FROM message_search WHERE message_id = $1")
            .bind(&message.id)
            .execute(&state.db)
            .await
            .map(|_| ()),
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, message_id = message.id, "search index not updated");
    }
}

/// Drops every index row of a conversation (a channel switched to encrypted).
pub async fn drop_conversation(db: &Pool, conversation_id: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM message_search WHERE conversation_id = $1")
        .bind(conversation_id)
        .execute(db)
        .await?
        .rows_affected())
}

/// Indexes the plaintext messages of one conversation again (a channel switched back to unencrypted).
pub async fn reindex_conversation(state: &AppState, conversation_id: &str) -> Result<usize, ApiError> {
    if !state.config.search_enabled {
        return Ok(0);
    }
    let mut cursor = String::new();
    let mut total = 0;
    loop {
        let rows = sqlx::query(&format!(
            "{CANDIDATE_SQL} WHERE m.conversation_id = $1 AND m.id > $2 AND m.encrypted = 0 ORDER BY m.id LIMIT $3"
        ))
        .bind(conversation_id)
        .bind(&cursor)
        .bind(BACKFILL_BATCH)
        .fetch_all(&state.db)
        .await?;
        let candidates = rows.iter().map(candidate).collect::<Result<Vec<_>, _>>()?;
        let Some(last) = candidates.last() else { break };
        cursor = last.id.clone();
        total += apply(&state.db, &candidates).await?;
        if (candidates.len() as i64) < BACKFILL_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Indexes every plaintext channel message after the stored progress (resumable, batches of 500), then
/// stores the newest id looked at. Messages written while it runs are indexed by the write path anyway.
pub async fn backfill(state: &AppState) -> Result<usize, ApiError> {
    if !state.config.search_enabled {
        return Ok(0);
    }
    let mut cursor: String = sqlx::query_scalar("SELECT value FROM node_settings WHERE key = $1")
        .bind(BACKFILL_CURSOR)
        .fetch_optional(&state.db)
        .await?
        .unwrap_or_default();
    let mut total = 0;
    loop {
        let rows = sqlx::query(&format!(
            "{CANDIDATE_SQL} WHERE m.id > $1 AND m.encrypted = 0 AND c.kind = 'channel' AND c.encrypted = 0
               AND NOT EXISTS (SELECT 1 FROM message_search s WHERE s.message_id = m.id)
             ORDER BY m.id LIMIT $2"
        ))
        .bind(&cursor)
        .bind(BACKFILL_BATCH)
        .fetch_all(&state.db)
        .await?;
        let candidates = rows.iter().map(candidate).collect::<Result<Vec<_>, _>>()?;
        let Some(last) = candidates.last() else { break };
        cursor = last.id.clone();
        total += apply(&state.db, &candidates).await?;
        sqlx::query(
            "INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(BACKFILL_CURSOR)
        .bind(&cursor)
        .bind(crate::util::now())
        .execute(&state.db)
        .await?;
        if (candidates.len() as i64) < BACKFILL_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Runs [`backfill`] once in the background after the start.
pub fn spawn_backfill(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match backfill(&state).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(messages = n, "search index filled"),
            Err(e) => tracing::warn!(error = %e, "search backfill failed (retried at the next start)"),
        }
    })
}

// ---------------------------------------------------------------- querying

/// The channels a caller may search: all of `full`, and of `cut` only messages from the given id on
/// (members without `read_history` see what was written since their join).
#[derive(Debug, Default, Clone)]
pub struct Scope {
    pub full: Vec<String>,
    pub cut: Vec<(String, String)>,
}

impl Scope {
    pub fn len(&self) -> usize {
        self.full.len() + self.cut.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Newest,
    Relevance,
}

/// Where a page continues: older than a message id (newest first) or an offset (relevance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cursor {
    Start,
    Before(String),
    Offset(i64),
}

pub struct Query<'a> {
    pub terms: &'a [String],
    pub scope: &'a Scope,
    pub author_id: Option<&'a str>,
    /// ULID floors: `after <= id < before`.
    pub after: Option<String>,
    pub before: Option<String>,
    pub has_file: bool,
    pub order: Order,
    pub cursor: Cursor,
    pub limit: i64,
}

/// One hit: the message id and its rank (higher is better; 0 without terms).
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub message_id: String,
    pub rank: f64,
}

/// Runs a search. Returns at most `limit + 1` hits (the extra one tells that there is a next page).
pub async fn run(db: &Pool, dialect: Dialect, q: &Query<'_>) -> Result<Vec<Hit>, ApiError> {
    if q.scope.is_empty() {
        return Ok(Vec::new());
    }
    let mut binds: Vec<String> = Vec::new();
    let mut bind = |v: String| {
        binds.push(v);
        format!("${}", binds.len())
    };
    let (select, from, mut clauses) = if q.terms.is_empty() {
        (
            "s.message_id AS message_id, CAST(0 AS DOUBLE PRECISION) AS rank".to_string(),
            "message_search s".to_string(),
            vec![],
        )
    } else {
        match dialect {
            Dialect::Postgres => {
                let p = bind(pg_tsquery(q.terms));
                (
                    format!(
                        "s.message_id AS message_id, CAST(ts_rank(s.tsv, to_tsquery('simple', {p})) AS DOUBLE PRECISION) AS rank"
                    ),
                    "message_search s".to_string(),
                    vec![format!("s.tsv @@ to_tsquery('simple', {p})")],
                )
            }
            Dialect::Sqlite => {
                let p = bind(fts5_query(q.terms));
                (
                    "s.message_id AS message_id, -bm25(message_search_fts) AS rank".to_string(),
                    "message_search_fts JOIN message_search s ON s.rid = message_search_fts.rowid".to_string(),
                    vec![format!("message_search_fts MATCH {p}")],
                )
            }
        }
    };
    let mut scope: Vec<String> = Vec::new();
    if !q.scope.full.is_empty() {
        let list: Vec<String> = q.scope.full.iter().map(|c| bind(c.clone())).collect();
        scope.push(format!("s.conversation_id IN ({})", list.join(", ")));
    }
    for (channel, floor) in &q.scope.cut {
        let c = bind(channel.clone());
        let f = bind(floor.clone());
        scope.push(format!("(s.conversation_id = {c} AND s.message_id >= {f})"));
    }
    clauses.push(format!("({})", scope.join(" OR ")));
    if let Some(author) = q.author_id {
        let a = bind(author.to_string());
        clauses.push(format!("s.author_id = {a}"));
    }
    if let Some(after) = &q.after {
        let a = bind(after.clone());
        clauses.push(format!("s.message_id >= {a}"));
    }
    if let Some(before) = &q.before {
        let b = bind(before.clone());
        clauses.push(format!("s.message_id < {b}"));
    }
    if q.has_file {
        clauses.push("EXISTS (SELECT 1 FROM blobs b WHERE b.message_id = s.message_id)".into());
    }
    let limit = q.limit + 1;
    let tail = match (&q.order, &q.cursor) {
        (Order::Newest, Cursor::Before(id)) => {
            let c = bind(id.clone());
            clauses.push(format!("s.message_id < {c}"));
            format!("ORDER BY s.message_id DESC LIMIT {limit}")
        }
        (Order::Newest, _) => format!("ORDER BY s.message_id DESC LIMIT {limit}"),
        (Order::Relevance, Cursor::Offset(o)) => {
            format!("ORDER BY rank DESC, s.message_id DESC LIMIT {limit} OFFSET {o}")
        }
        (Order::Relevance, _) => format!("ORDER BY rank DESC, s.message_id DESC LIMIT {limit}"),
    };
    let sql = format!("SELECT {select} FROM {from} WHERE {} {tail}", clauses.join(" AND "));
    let mut query = sqlx::query(&sql);
    for b in &binds {
        query = query.bind(b);
    }
    let rows = query.fetch_all(db).await?;
    rows.iter()
        .map(|r| Ok(Hit { message_id: r.try_get("message_id")?, rank: r.try_get::<f64, _>("rank")? }))
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn words_are_letters_and_digits_only() {
        assert_eq!(words("Hello, World! foo_bar 3.14"), s(&["hello", "world", "foo", "bar", "3", "14"]));
        assert_eq!(words("ＡＢＣ ﬁle"), s(&["abc", "file"]), "NFKC");
        assert_eq!(words("Müller-Lüdenscheidt"), s(&["müller", "lüdenscheidt"]));
        assert_eq!(words(&"x".repeat(100))[0].chars().count(), MAX_WORD_CHARS);
        assert!(words("🎉 ... \u{1}\u{2}").is_empty());
    }

    #[test]
    fn index_terms_hold_folded_variants() {
        assert_eq!(index_terms("Müller Straße Müller"), "müller muller straße strasse");
        assert_eq!(index_terms("plain"), "plain");
    }

    #[test]
    fn query_syntax_is_never_interpreted() {
        for (q, want) in [
            ("\"foo\" (bar)", vec!["foo", "bar"]),
            ("foo OR bar", vec!["foo", "or", "bar"]),
            ("NEAR(a b)", vec!["near", "a", "b"]),
            ("a:b * -c", vec!["a", "b", "c"]),
            ("'; DROP TABLE messages; --", vec!["drop", "table", "messages"]),
            ("\\' \\\" &|!<->", vec![]),
        ] {
            let terms = query_terms(q);
            assert_eq!(terms, s(&want), "{q}");
            for t in &terms {
                assert!(t.chars().all(char::is_alphanumeric), "{t}");
            }
        }
        assert_eq!(query_terms(&"a ".repeat(40)).len(), 1, "deduplicated");
        assert_eq!(query_terms(&(0..40).map(|i| format!("w{i} ")).collect::<String>()).len(), MAX_TERMS);
        assert_eq!(pg_tsquery(&s(&["foo", "bar"])), "'foo':* & 'bar':*");
        assert_eq!(fts5_query(&s(&["foo", "bar"])), "\"foo\"* \"bar\"*");
        assert_eq!(pg_tsquery(&s(&["it's"])), "'it''s':*", "quotes escaped even though words never hold them");
        assert_eq!(fts5_query(&s(&["a\"b"])), "\"a\"\"b\"*");
    }

    #[test]
    fn searchable_text_of_contents() {
        let t = |v: Value| searchable_text(&v.to_string(), &[]);
        assert_eq!(t(serde_json::json!({ "type": "text", "body": "hi" })), Some("hi".into()));
        assert_eq!(t(serde_json::json!({ "type": "action", "body": "waves" })), Some("waves".into()));
        assert_eq!(t(serde_json::json!({ "type": "system.join", "user": "a@b" })), None);
        assert_eq!(t(serde_json::json!({ "type": "text", "body": " " })), None);
        let e = serde_json::json!({ "type": "text", "body": "", "embeds": [{ "title": "Build", "description": "ok", "fields": [{ "name": "n", "value": "v" }] }] });
        assert_eq!(t(e), Some("\nBuild\nok\nn\nv".into()));
        assert_eq!(
            searchable_text(&serde_json::json!({ "type": "text", "body": "see" }).to_string(), &s(&["report.pdf"])),
            Some("see\nreport.pdf".into())
        );
        assert_eq!(searchable_text("Y2lwaGVy", &[]), None, "ciphertext");
        assert_eq!(
            t(serde_json::json!({ "type": "text", "body": "a\u{1}b\u{2}c" })),
            Some("abc".into()),
            "markers stripped"
        );
    }

    #[test]
    fn snippets_mark_matches_and_cut() {
        let terms = s(&["wor"]);
        assert_eq!(snippet("Hello World, world!", &terms), "Hello \u{1}World\u{2}, \u{1}world\u{2}!");
        let long = format!("{} needle {}", "a ".repeat(100), "b ".repeat(100));
        let sn = snippet(&long, &s(&["needle"]));
        assert!(sn.starts_with('…') && sn.ends_with('…') && sn.contains("\u{1}needle\u{2}"), "{sn}");
        assert!(sn.chars().count() <= 2 * SNIPPET_CONTEXT + 12, "{sn}");
        assert_eq!(snippet("Müller kam", &s(&["muller"])), "\u{1}Müller\u{2} kam", "diacritic-insensitive");
        assert_eq!(snippet("line1\nline2", &s(&["line2"])), "line1 \u{1}line2\u{2}");
        assert_eq!(snippet("no match here", &s(&["zzz"])), "no match here");
        assert_eq!(snippet("x\u{1}y", &[]), "xy", "markers in the text are removed");
    }

    #[test]
    fn dialect_from_url() {
        assert_eq!(Dialect::of("sqlite::memory:"), Dialect::Sqlite);
        assert_eq!(Dialect::of("sqlite://x.db"), Dialect::Sqlite);
        assert_eq!(Dialect::of("postgres://u@h/db"), Dialect::Postgres);
    }
}
