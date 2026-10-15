// SPDX-License-Identifier: AGPL-3.0-only
//! Content auto-moderation of unencrypted conversations (protocol MODERATION.md §2.2–§2.4).
//!
//! The node can only filter what it can read: [`evaluate`] returns early for encrypted conversations and never
//! looks at ciphertext. Room rules (`manage_room`) hold word lists with `*` wildcards and link filters; the
//! operator's node lists (`TAVRN_AUTOMOD_WORDS_FILE`, `TAVRN_AUTOMOD_LINKS`) apply everywhere with the action
//! `block`. A match writes an audit entry with the matched term (never the message text), alerts the moderators
//! and opens or updates an automod entry in the moderation inbox.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use aho_corasick::AhoCorasick;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;
use utoipa::ToSchema;

use crate::{
    access::{Conv, ConvKind},
    app::AppState,
    config::Config,
    error::ApiError,
    models::{ChannelRow, RoleRow, UserRow},
    store, util,
};

pub const MAX_RULES: usize = 20;
pub const MAX_TERMS: usize = 500;
pub const MAX_TERM_CHARS: usize = 100;
pub const MAX_STARS: usize = 5;
pub const MAX_DOMAINS: usize = 500;
pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_TIMEOUT_MINUTES: i64 = 40_320;
/// Node lists: at most this many entries and bytes per file.
pub const MAX_NODE_ENTRIES: usize = 10_000;
pub const MAX_NODE_FILE_BYTES: u64 = 1024 * 1024;

pub const ACTIONS: &[&str] = &["block", "delete", "timeout"];
pub const LINK_MODES: &[&str] = &["off", "block_all", "allow_list", "block_list"];

fn yes() -> bool {
    true
}
fn off() -> String {
    "off".into()
}

/// A content rule of a room.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct AutomodRule {
    /// Assigned by the node; kept when the rule is sent back with it.
    #[serde(default)]
    pub id: Option<String>,
    /// 1–64 characters, unique in the room; named in the error a blocked sender sees.
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Words or phrases (at most 500, 1–100 characters each); `*` matches any run of non-space characters.
    #[serde(default)]
    pub terms: Vec<String>,
    /// Matches must start and end at a word boundary.
    #[serde(default)]
    pub whole_word: bool,
    /// `off`, `block_all`, `allow_list` or `block_list`.
    #[serde(default = "off")]
    pub links: String,
    /// Domains of the link filter (at most 500; a domain covers its subdomains).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Role ids of the room the rule does not apply to.
    #[serde(default)]
    pub exempt_roles: Vec<String>,
    /// Channel ids of the room the rule does not apply to.
    #[serde(default)]
    pub exempt_channels: Vec<String>,
    /// `block`, `delete` or `timeout`.
    pub action: String,
    /// `timeout` only: 1–40320 minutes.
    #[serde(default)]
    pub timeout_minutes: Option<i64>,
}

// ---------------------------------------------------------------- normalization and matching

/// The form text and terms are compared in: NFKC, lowercase, whitespace runs folded to one space.
pub fn normalize(s: &str) -> String {
    let lower: String = s.nfkc().collect::<String>().to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut space = false;
    for c in lower.chars() {
        if c.is_whitespace() {
            if !space && !out.is_empty() {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn boundary_before(text: &str, pos: usize) -> bool {
    text[..pos].chars().next_back().is_none_or(|c| !is_word(c))
}

fn boundary_after(text: &str, pos: usize) -> bool {
    text[pos..].chars().next().is_none_or(|c| !is_word(c))
}

/// A term split at its `*` (runs of stars count as one): `"spam*"` → `["spam", ""]`, `"*coin"` → `["", "coin"]`.
pub fn parts(term: &str) -> Vec<String> {
    let raw: Vec<&str> = term.split('*').collect();
    let last = raw.len() - 1;
    raw.iter().enumerate().filter(|(i, p)| !p.is_empty() || *i == 0 || *i == last).map(|(_, p)| p.to_string()).collect()
}

/// Start positions (bytes) of every occurrence of `part` in `text`, overlapping ones included.
fn occurrences(text: &str, part: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = text[from..].find(part) {
        let at = from + off;
        out.push(at);
        from = at + text[at..].chars().next().map_or(1, char::len_utf8);
    }
    out
}

/// For every byte position, the position of the next whitespace character at or after it (or the text's end).
fn next_whitespace(text: &str) -> Vec<usize> {
    let mut out = vec![text.len(); text.len() + 1];
    let mut next = text.len();
    for (i, c) in text.char_indices().rev() {
        if c.is_whitespace() {
            next = i;
        }
        for slot in out.iter_mut().skip(i).take(c.len_utf8()) {
            *slot = next;
        }
    }
    out
}

/// The earliest position in the sorted `list` that is at least `from` and at most `until`.
fn earliest(list: &[usize], from: usize, until: usize) -> Option<usize> {
    let i = list.partition_point(|&p| p < from);
    list.get(i).copied().filter(|&p| p <= until)
}

/// Does the term (its [`parts`]) occur in the normalized `text`?
///
/// Every literal after the first must follow the previous one with only non-space characters in between (what a
/// `*` matches). Each start of the first literal is tried; the following literals take their earliest possible
/// occurrence, which never loses a match because literals after a `*` contain no spaces ([`validate_rules`]). The
/// cost is linear in the text per literal plus a binary search per start: no backtracking a crafted text could
/// blow up.
pub fn term_matches(text: &str, parts: &[String], whole_word: bool) -> bool {
    let ws = std::cell::OnceCell::new();
    matches_with(text, parts, whole_word, &|_, lit| Cow::Owned(occurrences(text, lit)), &ws)
}

/// [`term_matches`] with the occurrences of the term's `j`-th literal given by `occurrences_of` (one automaton pass
/// over the text finds those of every term at once, [`Terms::find`]) and the whitespace table shared between the
/// terms of one text.
fn matches_with<'a>(
    text: &str,
    parts: &[String],
    whole_word: bool,
    occurrences_of: &dyn Fn(usize, &str) -> Cow<'a, [usize]>,
    ws: &std::cell::OnceCell<Vec<usize>>,
) -> bool {
    let literals: Vec<&str> = parts.iter().map(String::as_str).filter(|p| !p.is_empty()).collect();
    let Some(first) = literals.first() else { return false };
    // A leading (trailing) star extends the match to the start (end) of its non-space run, which is a boundary.
    let leading_star = parts.first().is_some_and(String::is_empty);
    let trailing_star = parts.len() > 1 && parts.last().is_some_and(String::is_empty);
    let last = literals.len() - 1;
    let mut lists: Vec<Cow<'a, [usize]>> = Vec::with_capacity(literals.len());
    for (j, lit) in literals.iter().enumerate() {
        let mut list = occurrences_of(j, lit);
        if list.is_empty() {
            return false;
        }
        if whole_word && j == 0 && !leading_star {
            list.to_mut().retain(|&p| boundary_before(text, p));
        }
        if whole_word && j == last && !trailing_star {
            list.to_mut().retain(|&p| boundary_after(text, p + lit.len()));
        }
        if list.is_empty() {
            return false;
        }
        lists.push(list);
    }
    if literals.len() == 1 {
        return true;
    }
    let ws = ws.get_or_init(|| next_whitespace(text));
    'starts: for &start in lists[0].iter() {
        let mut pos = start + first.len();
        for j in 1..literals.len() {
            match earliest(&lists[j], pos, ws[pos]) {
                Some(at) => pos = at + literals[j].len(),
                None => continue 'starts,
            }
        }
        return true;
    }
    false
}

/// The hosts of the links in a normalized text: `http(s)://` URLs and `www.` hosts.
pub fn link_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let stop = |c: char| c.is_whitespace() || "/?#\"'<>()[]{}|\\^`,;!".contains(c);
    let mut take = |start: usize| {
        let rest = &text[start..];
        let end = rest.find(stop).unwrap_or(rest.len());
        let mut host = &rest[..end];
        if let Some((_, h)) = host.rsplit_once('@') {
            host = h;
        }
        if let Some((h, _)) = host.split_once(':') {
            host = h;
        }
        let host = host.trim_end_matches('.');
        if !host.is_empty() && !hosts.iter().any(|h: &String| h == host) {
            hosts.push(host.to_string());
        }
    };
    for scheme in ["http://", "https://"] {
        for (pos, _) in text.match_indices(scheme) {
            take(pos + scheme.len());
        }
    }
    for (pos, _) in text.match_indices("www.") {
        if text[..pos].chars().next_back().is_none_or(|c| !(is_word(c) || c == '.' || c == '-' || c == '/')) {
            take(pos);
        }
    }
    hosts
}

/// `host` is `domain` or one of its subdomains.
pub fn covers(domain: &str, host: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|p| p.ends_with('.'))
}

fn host_char(c: char) -> bool {
    c.is_alphanumeric() || c == '-'
}

/// A listed domain written somewhere in the text, with or without a scheme (block lists).
fn mentions_domain(text: &str, domain: &str) -> bool {
    text.match_indices(domain).any(|(pos, _)| {
        let before_ok = text[..pos].chars().next_back().is_none_or(|c| !host_char(c));
        let after = &text[pos + domain.len()..];
        let mut chars = after.chars();
        let after_ok = match chars.next() {
            None => true,
            Some('.') => chars.next().is_none_or(|c| !host_char(c)),
            Some(c) => !host_char(c),
        };
        before_ok && after_ok
    })
}

// ---------------------------------------------------------------- compiled rules

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Links {
    Off,
    BlockAll,
    AllowList,
    BlockList,
}

impl Links {
    fn parse(s: &str) -> Self {
        match s {
            "block_all" => Self::BlockAll,
            "allow_list" => Self::AllowList,
            "block_list" => Self::BlockList,
            _ => Self::Off,
        }
    }
}

/// A word list ready for matching: literal single words of whole-word lists are looked up in a set; the literals
/// of every other term are found in one pass over the text (an Aho-Corasick automaton, linear in the text and the
/// matches), and only then are the boundary and `*` rules of each term checked on those positions.
#[derive(Debug, Default, Clone)]
pub struct Terms {
    whole_word: bool,
    exact: HashSet<String>,
    patterns: Vec<Pattern>,
    /// Over the distinct literals of `patterns` (`None` without patterns).
    automaton: Option<AhoCorasick>,
    literals: usize,
}

#[derive(Debug, Clone)]
struct Pattern {
    term: String,
    parts: Vec<String>,
    /// The automaton's ids of the non-empty parts, in order.
    ids: Vec<usize>,
}

impl Terms {
    pub fn new(terms: &[String], whole_word: bool) -> Self {
        let mut t = Self { whole_word, ..Default::default() };
        let mut literals: Vec<String> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for term in terms {
            if whole_word && term.chars().all(is_word) {
                t.exact.insert(term.clone());
                continue;
            }
            let parts = parts(term);
            let ids = parts
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| {
                    *index.entry(p.clone()).or_insert_with(|| {
                        literals.push(p.clone());
                        literals.len() - 1
                    })
                })
                .collect();
            t.patterns.push(Pattern { term: term.clone(), parts, ids });
        }
        t.literals = literals.len();
        // Building fails only for automata beyond its size limits, far above 500 terms × 100 characters (room
        // rules) or 10 000 entries (node lists); the term-by-term scan stays as the fallback.
        t.automaton = (!literals.is_empty()).then(|| AhoCorasick::new(&literals).ok()).flatten();
        t
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.patterns.is_empty()
    }

    /// The first term found in the normalized `text`.
    pub fn find(&self, text: &str) -> Option<String> {
        if !self.exact.is_empty() {
            for word in text.split(|c: char| !is_word(c)).filter(|w| !w.is_empty()) {
                if self.exact.contains(word) {
                    return Some(word.to_string());
                }
            }
        }
        if self.patterns.is_empty() {
            return None;
        }
        let ws = std::cell::OnceCell::new();
        let Some(automaton) = &self.automaton else {
            return self
                .patterns
                .iter()
                .find(|p| term_matches(text, &p.parts, self.whole_word))
                .map(|p| p.term.clone());
        };
        // Every occurrence (overlapping ones included) of every literal, in one pass.
        let mut found: Vec<Vec<usize>> = vec![Vec::new(); self.literals];
        for m in automaton.find_overlapping_iter(text) {
            found[m.pattern().as_usize()].push(m.start());
        }
        for list in &mut found {
            list.sort_unstable();
        }
        self.patterns
            .iter()
            .find(|p| {
                p.ids.iter().all(|&id| !found[id].is_empty())
                    && matches_with(text, &p.parts, self.whole_word, &|j, _| Cow::Borrowed(&found[p.ids[j]]), &ws)
            })
            .map(|p| p.term.clone())
    }
}

/// What matched: `word` (the term) or `link` (the host or domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    pub kind: &'static str,
    pub value: String,
}

fn find_link(texts: &[String], mode: Links, domains: &[String]) -> Option<Matched> {
    let link = |value: String| Some(Matched { kind: "link", value });
    for text in texts {
        match mode {
            Links::Off => return None,
            Links::BlockList => {
                if let Some(d) = domains.iter().find(|d| mentions_domain(text, d)) {
                    return link(d.clone());
                }
            }
            Links::BlockAll | Links::AllowList => {
                for host in link_hosts(text) {
                    if mode == Links::BlockAll || !domains.iter().any(|d| covers(d, &host)) {
                        return link(host);
                    }
                }
            }
        }
    }
    None
}

fn find_in(texts: &[String], terms: &Terms, links: Links, domains: &[String]) -> Option<Matched> {
    if !terms.is_empty()
        && let Some(value) = texts.iter().find_map(|t| terms.find(t))
    {
        return Some(Matched { kind: "word", value });
    }
    find_link(texts, links, domains)
}

/// A room rule ready for matching.
#[derive(Debug)]
struct Compiled {
    rule: AutomodRule,
    terms: Terms,
    links: Links,
}

impl Compiled {
    fn new(rule: AutomodRule) -> Self {
        Self { terms: Terms::new(&rule.terms, rule.whole_word), links: Links::parse(&rule.links), rule }
    }
}

// ---------------------------------------------------------------- validation of room rules

fn invalid(rule: &str, problem: impl std::fmt::Display) -> ApiError {
    ApiError::BadRequest {
        code: "automod.rules_invalid",
        detail: if rule.is_empty() { problem.to_string() } else { format!("Rule \"{rule}\": {problem}") },
    }
}

/// Normalizes and checks a room's rule list (MODERATION.md §2.2); assigns ids to new rules.
pub fn validate_rules(
    rules: Vec<AutomodRule>,
    roles: &[RoleRow],
    channels: &[ChannelRow],
) -> Result<Vec<AutomodRule>, ApiError> {
    if rules.len() > MAX_RULES {
        return Err(invalid("", format!("at most {MAX_RULES} rules per room")));
    }
    let mut names: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(rules.len());
    for mut r in rules {
        let name = r.name.trim().to_string();
        let n = name.chars().count();
        if n == 0 || n > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return Err(invalid(&name, format!("the name needs 1 to {MAX_NAME_CHARS} characters on one line")));
        }
        if names.iter().any(|x| x.to_lowercase() == name.to_lowercase()) {
            return Err(invalid(&name, "names must be unique"));
        }
        names.push(name.clone());
        r.name = name.clone();
        if r.terms.len() > MAX_TERMS {
            return Err(invalid(&name, format!("at most {MAX_TERMS} terms")));
        }
        let mut terms: Vec<String> = Vec::new();
        for t in &r.terms {
            let term = normalize(t);
            let chars = term.chars().count();
            if chars == 0 || chars > MAX_TERM_CHARS {
                return Err(invalid(&name, format!("terms need 1 to {MAX_TERM_CHARS} characters")));
            }
            if term.matches('*').count() > MAX_STARS {
                return Err(invalid(&name, format!("at most {MAX_STARS} wildcards per term")));
            }
            if term.chars().all(|c| c == '*') {
                return Err(invalid(&name, "a term needs more than wildcards"));
            }
            if !star_placement_ok(&term) {
                return Err(invalid(&name, "in a phrase with spaces, * may only stand at its start or end"));
            }
            if !terms.contains(&term) {
                terms.push(term);
            }
        }
        r.terms = terms;
        if !LINK_MODES.contains(&r.links.as_str()) {
            return Err(invalid(&name, format!("links: one of {}", LINK_MODES.join(", "))));
        }
        if r.domains.len() > MAX_DOMAINS {
            return Err(invalid(&name, format!("at most {MAX_DOMAINS} domains")));
        }
        let mut domains: Vec<String> = Vec::new();
        for d in &r.domains {
            let d = d.trim().trim_end_matches('.').to_lowercase();
            if !util::valid_domain(&d) {
                return Err(invalid(&name, format!("{d} is not a domain")));
            }
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        r.domains = domains;
        if matches!(r.links.as_str(), "allow_list" | "block_list") && r.domains.is_empty() && r.terms.is_empty() {
            return Err(invalid(&name, "the link list needs domains"));
        }
        if r.terms.is_empty() && r.links == "off" {
            return Err(invalid(&name, "a rule needs terms or a link filter"));
        }
        if !ACTIONS.contains(&r.action.as_str()) {
            return Err(invalid(&name, format!("action: one of {}", ACTIONS.join(", "))));
        }
        r.timeout_minutes = match (r.action.as_str(), r.timeout_minutes) {
            ("timeout", Some(m)) if (1..=MAX_TIMEOUT_MINUTES).contains(&m) => Some(m),
            ("timeout", _) => return Err(invalid(&name, format!("timeout_minutes: 1 to {MAX_TIMEOUT_MINUTES}"))),
            _ => None,
        };
        for role in &r.exempt_roles {
            if !roles.iter().any(|x| x.id == *role && x.is_everyone == 0) {
                return Err(invalid(&name, format!("{role} is not a role of the room")));
            }
        }
        for channel in &r.exempt_channels {
            if !channels.iter().any(|x| x.id == *channel) {
                return Err(invalid(&name, format!("{channel} is not a channel of the room")));
            }
        }
        r.exempt_roles.dedup();
        r.exempt_channels.dedup();
        let id = r.id.take().filter(|i| util::is_ulid(i) && !ids.contains(i)).unwrap_or_else(util::ulid);
        ids.push(id.clone());
        r.id = Some(id);
        out.push(r);
    }
    Ok(out)
}

/// The stored rules of a room (an unreadable document counts as no rules).
pub async fn room_rules(state: &AppState, room_id: &str) -> Result<Vec<AutomodRule>, ApiError> {
    let raw = store::automod::rules(&state.db, room_id).await?;
    Ok(parse_rules(&raw))
}

fn parse_rules(raw: &str) -> Vec<AutomodRule> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// The compiled rules of a room, shared between messages (parsing and compiling 20 rules × 500 terms per message
/// would cost more than the matching).
struct CachedRules {
    /// The stored document they were compiled from.
    raw: String,
    rules: Arc<Vec<Compiled>>,
    checked: Instant,
}

/// Compiled rules per room (`<domain>|<room id>`). A change on this instance replaces them at once
/// ([`rules_changed`]); a change on another instance is seen within [`RULES_RECHECK`], when the stored document is
/// read again and compiled only if it differs.
static ROOM_RULES: LazyLock<Mutex<HashMap<String, CachedRules>>> = LazyLock::new(Mutex::default);
const RULES_RECHECK: Duration = Duration::from_secs(5);
/// Rooms kept; more empty the cache (it refills from the messages that follow).
const MAX_CACHED_ROOMS: usize = 4096;

fn cache_key(state: &AppState, room_id: &str) -> String {
    format!("{}|{room_id}", state.config.domain)
}

fn rule_cache() -> std::sync::MutexGuard<'static, HashMap<String, CachedRules>> {
    ROOM_RULES.lock().unwrap_or_else(|e| e.into_inner())
}

/// The room's rules were replaced on this instance (`PUT /rooms/{id}/automod`).
pub fn rules_changed(state: &AppState, room_id: &str) {
    rule_cache().remove(&cache_key(state, room_id));
}

async fn compiled_rules(state: &AppState, room_id: &str) -> Result<Arc<Vec<Compiled>>, ApiError> {
    let key = cache_key(state, room_id);
    if let Some(hit) = rule_cache().get(&key).filter(|c| c.checked.elapsed() < RULES_RECHECK) {
        return Ok(hit.rules.clone());
    }
    let raw = store::automod::rules(&state.db, room_id).await?;
    if let Some(hit) = rule_cache().get_mut(&key).filter(|c| c.raw == raw) {
        hit.checked = Instant::now();
        return Ok(hit.rules.clone());
    }
    let rules: Arc<Vec<Compiled>> =
        Arc::new(parse_rules(&raw).into_iter().filter(|r| r.enabled).map(Compiled::new).collect());
    let mut cache = rule_cache();
    if cache.len() >= MAX_CACHED_ROOMS {
        cache.clear();
    }
    cache.insert(key, CachedRules { raw, rules: rules.clone(), checked: Instant::now() });
    Ok(rules)
}

// ---------------------------------------------------------------- node lists

/// The operator's lists (MODERATION.md §2.3): read at start, read again by the hourly housekeeping and on SIGHUP
/// ([`reload_node_lists`]); an invalid file keeps the lists in force.
#[derive(Debug, Default)]
pub struct NodeFilter {
    lists: std::sync::RwLock<NodeLists>,
}

#[derive(Debug, Default)]
struct NodeLists {
    words: Vec<String>,
    terms: Terms,
    domains: Vec<String>,
}

impl NodeLists {
    fn new(words: Vec<String>, domains: Vec<String>) -> Self {
        Self { terms: Terms::new(&words, true), words, domains }
    }
}

/// What a reload changed: entries added to and removed from each list.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ListChanges {
    pub words_added: usize,
    pub words_removed: usize,
    pub domains_added: usize,
    pub domains_removed: usize,
}

impl ListChanges {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Entries of `new` missing in `old`, and of `old` missing in `new`.
fn diff(old: &[String], new: &[String]) -> (usize, usize) {
    let (o, n): (HashSet<&String>, HashSet<&String>) = (old.iter().collect(), new.iter().collect());
    (n.difference(&o).count(), o.difference(&n).count())
}

/// Phrases with spaces take `*` only at their ends (the matcher's greedy search relies on it).
pub fn star_placement_ok(term: &str) -> bool {
    !term.contains(' ') || !term.trim_matches('*').contains('*')
}

/// Reads the node's word list ([`read_list`]) and checks every term like a room rule's.
pub fn read_terms(path: &str) -> Result<Vec<String>, String> {
    let terms = read_list(path)?;
    if let Some(bad) = terms.iter().find(|t| !star_placement_ok(t) || t.matches('*').count() > MAX_STARS) {
        return Err(format!(
            "{path}: \"{bad}\": at most {MAX_STARS} wildcards, in phrases with spaces only at the start or end"
        ));
    }
    Ok(terms)
}

/// Reads a node list: one entry per line, empty lines and `#` comments ignored.
pub fn read_list(path: &str) -> Result<Vec<String>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    if meta.len() > MAX_NODE_FILE_BYTES {
        return Err(format!("{path} is larger than {} KiB", MAX_NODE_FILE_BYTES / 1024));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let entries: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalize)
        .filter(|l| !l.chars().all(|c| c == '*'))
        .collect();
    if entries.len() > MAX_NODE_ENTRIES {
        return Err(format!("{path} has more than {MAX_NODE_ENTRIES} entries"));
    }
    Ok(entries)
}

/// Reads both node lists of the configuration; every problem is named with its variable.
fn read_node_lists(config: &Config) -> Result<(Vec<String>, Vec<String>), Vec<String>> {
    let mut problems = Vec::new();
    let words = match config.automod_words_file.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(path) => read_terms(path).unwrap_or_else(|e| {
            problems.push(format!("TAVRN_AUTOMOD_WORDS_FILE: {e}"));
            Vec::new()
        }),
        None => Vec::new(),
    };
    let domains = match config.automod_links.trim() {
        "" | "off" => Vec::new(),
        path => match read_list(path) {
            Ok(list) => list.into_iter().map(|d| d.trim_end_matches('.').to_string()).collect(),
            Err(e) => {
                problems.push(format!("TAVRN_AUTOMOD_LINKS: {e}"));
                Vec::new()
            }
        },
    };
    if problems.is_empty() { Ok((words, domains)) } else { Err(problems) }
}

impl NodeFilter {
    pub fn new(words: Vec<String>, domains: Vec<String>) -> Self {
        Self { lists: std::sync::RwLock::new(NodeLists::new(words, domains)) }
    }

    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let (words, domains) = read_node_lists(config).map_err(|p| anyhow::anyhow!(p.join("; ")))?;
        Ok(Self::new(words, domains))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, NodeLists> {
        self.lists.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Reads the files again (validated like `check-config`). Invalid or unreadable files keep **both** lists in
    /// force and return the problems; otherwise the new lists apply at once.
    pub fn reload(&self, config: &Config) -> Result<ListChanges, Vec<String>> {
        let (words, domains) = read_node_lists(config)?;
        let mut lists = self.lists.write().unwrap_or_else(|e| e.into_inner());
        let (words_added, words_removed) = diff(&lists.words, &words);
        let (domains_added, domains_removed) = diff(&lists.domains, &domains);
        let changes = ListChanges { words_added, words_removed, domains_added, domains_removed };
        *lists = NodeLists::new(words, domains);
        Ok(changes)
    }

    pub fn has_words(&self) -> bool {
        !self.read().terms.is_empty()
    }

    pub fn has_links(&self) -> bool {
        !self.read().domains.is_empty()
    }

    pub fn find(&self, texts: &[String]) -> Option<Matched> {
        let lists = self.read();
        let links = if lists.domains.is_empty() { Links::Off } else { Links::BlockList };
        find_in(texts, &lists.terms, links, &lists.domains)
    }
}

/// Reads the node lists again (hourly housekeeping on every instance, and SIGHUP) and logs what changed or why the
/// old lists stay in force.
pub async fn reload_node_lists(state: &AppState) -> Result<ListChanges, Vec<String>> {
    let (filter, config) = (state.node_automod.clone(), state.config.clone());
    let result = tokio::task::spawn_blocking(move || filter.reload(&config))
        .await
        .unwrap_or_else(|e| Err(vec![format!("reload task failed: {e}")]));
    match &result {
        Ok(c) if !c.is_empty() => tracing::info!(
            words_added = c.words_added,
            words_removed = c.words_removed,
            domains_added = c.domains_added,
            domains_removed = c.domains_removed,
            "Auto-moderation node lists reloaded"
        ),
        Ok(_) => {}
        Err(problems) => tracing::warn!(
            problems = %problems.join("; "),
            "Auto-moderation node lists not reloaded, the previous lists stay in force"
        ),
    }
    result
}

// ---------------------------------------------------------------- checking messages

/// A rule that matched a message.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The rule's name (`node` for the node lists).
    pub rule: String,
    /// `room` or `node`.
    pub scope: &'static str,
    pub matched: Matched,
    pub action: String,
    pub timeout_minutes: Option<i64>,
}

impl Hit {
    pub fn blocks(&self) -> bool {
        self.action == "block"
    }
}

/// The texts of a plaintext content object the rules look at (MODERATION.md §2.2): every string except the
/// type, the provider's GIF and inline preview images.
pub fn content_texts(content: &Value) -> Vec<String> {
    fn walk(v: &Value, key: &str, depth: usize, out: &mut Vec<String>) {
        if depth > 8 || matches!(key, "type" | "gif" | "image") {
            return;
        }
        match v {
            Value::String(s) if !s.is_empty() => out.push(normalize(s)),
            Value::Array(items) => items.iter().for_each(|i| walk(i, "", depth + 1, out)),
            Value::Object(map) => map.iter().for_each(|(k, v)| walk(v, k, depth + 1, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(content, "", 0, &mut out);
    out
}

/// Checks a message of an unencrypted conversation against the node lists and the room's rules. Never looks at
/// encrypted conversations. `names` are the attachments' file names.
pub async fn evaluate(
    state: &AppState,
    conv: &Conv,
    content: &Value,
    names: &[String],
) -> Result<Option<Hit>, ApiError> {
    if conv.encrypted || !content.is_object() {
        return Ok(None);
    }
    let mut texts = content_texts(content);
    texts.extend(names.iter().filter(|n| !n.is_empty()).map(|n| normalize(n)));
    if texts.is_empty() {
        return Ok(None);
    }
    if let Some(matched) = state.node_automod.find(&texts) {
        return Ok(Some(Hit {
            rule: "node".into(),
            scope: "node",
            matched,
            action: "block".into(),
            timeout_minutes: None,
        }));
    }
    let ConvKind::Channel { access, channel } = &conv.kind else { return Ok(None) };
    if access.is_owner || access.is_node_admin {
        return Ok(None);
    }
    let rules = compiled_rules(state, &access.room.id).await?;
    for c in rules.iter() {
        let rule = &c.rule;
        if rule.exempt_channels.contains(&channel.id)
            || access.member_roles.iter().any(|r| rule.exempt_roles.contains(&r.id))
        {
            continue;
        }
        if let Some(matched) = find_in(&texts, &c.terms, c.links, &rule.domains) {
            return Ok(Some(Hit {
                rule: rule.name.clone(),
                scope: "room",
                matched,
                action: rule.action.clone(),
                timeout_minutes: rule.timeout_minutes,
            }));
        }
    }
    Ok(None)
}

/// A `block` hit: the alert, then the error for the sender (`403 automod.blocked`).
pub async fn blocked(state: &AppState, conv: &Conv, author: &UserRow, hit: &Hit) -> ApiError {
    alert(state, conv, author, hit, None).await;
    ApiError::ForbiddenMeta {
        code: "automod.blocked",
        detail: if hit.scope == "node" {
            "This message was blocked by the node's content filter".into()
        } else {
            format!("This message was blocked by the auto-moderation rule \"{}\"", hit.rule)
        },
        meta: json!({ "rule": hit.rule, "scope": hit.scope }),
    }
}

/// A `delete` or `timeout` hit after the message was stored: it is deleted right away (only `message.delete` goes
/// out), the author gets the timeout, and the moderators the alert.
pub async fn remove(
    state: &AppState,
    conv: &Conv,
    author: &UserRow,
    hit: &Hit,
    message_id: &str,
) -> Result<(), ApiError> {
    let blobs = store::blobs::by_message(&state.db, message_id).await?;
    store::messages::delete(&state.db, message_id).await?;
    for b in &blobs {
        state.storage.delete(&b.id).await;
    }
    conv.publish(
        &state.hub,
        "message.delete",
        json!({ "room_id": conv.room_id(), "conversation_id": conv.id, "id": message_id }),
    );
    if let (Some(minutes), Some(room_id)) = (hit.timeout_minutes.filter(|_| hit.action == "timeout"), conv.room_id()) {
        let until = util::in_seconds(minutes * 60);
        crate::routes::rooms::set_timeout_announced(state, room_id, &author.id, Some(&until)).await?;
    }
    alert(state, conv, author, hit, Some(message_id)).await;
    Ok(())
}

/// Audit entry, `moderation.alert` and the inbox entry of a hit (MODERATION.md §2.4). Failures are logged: the
/// moderation decision itself stands.
async fn alert(state: &AppState, conv: &Conv, author: &UserRow, hit: &Hit, message_id: Option<&str>) {
    if let Err(e) = try_alert(state, conv, author, hit, message_id).await {
        tracing::warn!(error = %e, "auto-moderation alert not recorded");
    }
}

async fn try_alert(
    state: &AppState,
    conv: &Conv,
    author: &UserRow,
    hit: &Hit,
    message_id: Option<&str>,
) -> Result<(), ApiError> {
    let room_id = conv.room_id();
    store::rooms::audit(
        &state.db,
        room_id,
        None,
        "automod.content",
        &author.address(),
        &hit.rule,
        json!({ "rule": hit.rule, "scope": hit.scope, "kind": hit.matched.kind, "matched": hit.matched.value,
            "action": hit.action, "channel_id": conv.id, "message_id": message_id }),
    )
    .await?;
    let mut recipients = match (hit.scope, room_id) {
        ("room", Some(room_id)) => store::rooms::moderator_ids(&state.db, room_id).await?,
        _ => store::reports::node_admin_ids(&state.db).await?,
    };
    recipients.retain(|r| r != &author.id);
    state.hub.users(
        recipients,
        "moderation.alert",
        json!({ "room_id": room_id, "channel_id": conv.id, "user": author.to_public(), "kind": "content",
            "rule": hit.rule, "scope": hit.scope, "matched": hit.matched.value, "action": hit.action, "at": util::now() }),
    );
    let detail = format!(
        "Rule \"{}\" matched the {} \"{}\" ({})",
        hit.rule,
        if hit.matched.kind == "link" { "link" } else { "term" },
        hit.matched.value,
        hit.action
    );
    crate::reports::automod_entry(state, hit.scope, room_id, &conv.id, author, &detail).await?;
    tracing::info!(rule = hit.rule, scope = hit.scope, action = hit.action, "Auto-moderation: content rule matched");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn m(text: &str, term: &str, whole: bool) -> bool {
        term_matches(&normalize(text), &parts(&normalize(term)), whole)
    }

    #[test]
    fn normalization_folds_case_width_and_space() {
        assert_eq!(normalize("  Hello\t\nWORLD  "), "hello world");
        assert_eq!(normalize("ＦＵＬＬ ｗｉｄｔｈ"), "full width");
        assert_eq!(normalize("Straße"), "straße");
    }

    #[test]
    fn parts_split_at_stars() {
        assert_eq!(parts("spam*"), vec!["spam", ""]);
        assert_eq!(parts("*coin"), vec!["", "coin"]);
        assert_eq!(parts("fr*e"), vec!["fr", "e"]);
        assert_eq!(parts("a**b"), vec!["a", "b"]);
        assert_eq!(parts("plain"), vec!["plain"]);
    }

    #[test]
    fn substrings_and_whole_words() {
        assert!(m("you are a BadWord!", "badword", true));
        assert!(m("badwordy", "badword", false));
        assert!(!m("badwordy", "badword", true));
        assert!(!m("nobadword", "badword", true));
        assert!(m("a forbidden  phrase.", "forbidden phrase", true));
        assert!(!m("forbidden phrases", "forbidden phrase", true));
        assert!(m("snake_case_word", "case", false));
        assert!(!m("snake_case_word", "case", true), "underscores are word characters");
    }

    #[test]
    fn wildcards_stay_within_a_run_of_non_space_characters() {
        assert!(m("spammity", "spam*", true));
        assert!(m("bitcoin", "*coin", true));
        assert!(m("x-bitcoin", "*coin", true));
        assert!(m("free", "fr*e", true));
        assert!(m("frEEEe", "fr*e", true));
        assert!(!m("fr e", "fr*e", true), "a star never crosses a space");
        assert!(m("abxb", "a*b", true), "backtracks to a later literal for the boundary");
        assert!(!m("abxbc", "a*b", true));
        assert!(m("abxbc", "a*b", false));
        assert!(m("a.b.c.d", "a*b*c*d", true));
        assert!(!m("nothing", "spam*", true));
    }

    #[test]
    fn crafted_text_cannot_make_matching_slow() {
        let text = "a".repeat(4000);
        let started = std::time::Instant::now();
        for term in ["a*a*a*a*a*b", "*a*a*a*b", "a*b"] {
            assert!(!m(&text, term, true));
            assert!(!m(&text, term, false));
        }
        assert!(m(&format!("{text}b"), "a*a*a*a*a*b", true));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn stars_in_phrases_only_at_their_ends() {
        assert!(star_placement_ok("forbidden phrase*"));
        assert!(star_placement_ok("*coin scam"));
        assert!(star_placement_ok("fr*e"));
        assert!(!star_placement_ok("buy * now"));
        assert!(m("buy now!", "buy now*", true));
        assert!(m("so buy nowadays", "buy now*", true));
    }

    #[test]
    fn matching_handles_multibyte_text() {
        assert!(m("größe ärger", "ärg*", true));
        assert!(m("日本語のテキスト", "テキ", false));
        assert!(!m("ééé", "e", false));
        assert!(m("😀 smile 😀", "smile", true));
    }

    #[test]
    fn exact_word_sets_and_patterns() {
        let t = Terms::new(&["bad".into(), "two words".into(), "x*y".into()], true);
        assert_eq!(t.find("so bad"), Some("bad".into()));
        assert_eq!(t.find("badly"), None);
        assert_eq!(t.find("two words here"), Some("two words".into()));
        assert_eq!(t.find("xzzy"), Some("x*y".into()));
        assert!(Terms::new(&[], true).is_empty());
    }

    /// One pass over the text finds what the term-by-term scan finds, for every kind of term.
    #[test]
    fn the_automaton_finds_what_each_term_finds_alone() {
        let terms: Vec<String> = [
            "bad",
            "two words",
            "x*y",
            "spam*",
            "*coin",
            "fr*e",
            "a*b",
            "a*a*a*b",
            "buy now*",
            "ärg*",
            "テキ",
            "e",
            "case",
            "forbidden phrase",
        ]
        .iter()
        .map(|t| normalize(t))
        .collect();
        let texts = [
            "so bad",
            "badly",
            "two words here",
            "xzzy",
            "spammity",
            "x-bitcoin",
            "frEEEe",
            "fr e",
            "abxb",
            "abxbc",
            "aaaaab",
            "so buy nowadays",
            "größe ärger",
            "日本語のテキスト",
            "ééé",
            "snake_case_word",
            "a forbidden  phrase.",
            "nothing at all",
        ];
        for whole in [true, false] {
            for term in &terms {
                let one = Terms::new(std::slice::from_ref(term), whole);
                for text in texts {
                    let text = normalize(text);
                    let expected = term_matches(&text, &parts(term), whole);
                    let exact = whole && term.chars().all(is_word);
                    if !exact {
                        assert_eq!(one.find(&text).is_some(), expected, "{term:?} in {text:?} (whole {whole})");
                    }
                }
            }
            // All terms together report the first matching term of the list.
            let all = Terms::new(&terms, whole);
            for text in texts {
                let text = normalize(text);
                let expected = terms.iter().find(|t| {
                    if whole && t.chars().all(is_word) {
                        text.split(|c: char| !is_word(c)).any(|w| w == t.as_str())
                    } else {
                        term_matches(&text, &parts(t), whole)
                    }
                });
                assert_eq!(all.find(&text).is_some(), expected.is_some(), "{text:?} (whole {whole})");
            }
        }
    }

    /// 20 rules × 500 terms against a 4000-character message: the automaton against the scan per term (run with
    /// `--ignored --nocapture` for the numbers).
    #[test]
    #[ignore = "benchmark"]
    fn bench_room_rules() {
        let rules: Vec<Vec<String>> = (0..20)
            .map(|r| (0..500).map(|t| format!("w{r}x{t}*{}", if t % 3 == 0 { "z" } else { "" })).collect())
            .collect();
        let text = normalize(&"lorem ipsum dolor sit amet, consectetur adipiscing elit ".repeat(72)[..4000]);
        let started = Instant::now();
        let compiled: Vec<Terms> = rules.iter().map(|r| Terms::new(r, true)).collect();
        let compile = started.elapsed();
        let rounds = 20;
        let started = Instant::now();
        for _ in 0..rounds {
            for t in &compiled {
                assert!(t.find(&text).is_none());
            }
        }
        let automaton = started.elapsed() / rounds;
        let started = Instant::now();
        for _ in 0..rounds {
            for r in &rules {
                assert!(!r.iter().any(|t| term_matches(&text, &parts(t), true)));
            }
        }
        let scan = started.elapsed() / rounds;
        println!("compile {compile:?} once; per message: automaton {automaton:?}, term by term {scan:?}");
    }

    #[test]
    fn links_and_domains() {
        let text = normalize("See HTTPS://User@Docs.Example.org:8080/x?y and www.Other.test, also (http://a.b).");
        assert_eq!(link_hosts(&text), vec!["a.b", "docs.example.org", "www.other.test"]);
        assert!(link_hosts("no links, only example.org").is_empty());
        assert!(covers("example.org", "docs.example.org"));
        assert!(covers("example.org", "example.org"));
        assert!(!covers("example.org", "badexample.org"));
        assert!(mentions_domain("visit evil.test now", "evil.test"));
        assert!(mentions_domain("cdn.evil.test/x", "evil.test"));
        assert!(mentions_domain("end evil.test.", "evil.test"));
        assert!(!mentions_domain("notevil.test", "evil.test"));
        assert!(!mentions_domain("evil.testing", "evil.test"));
        assert!(!mentions_domain("evil.test.other.com", "evil.test"));
        let texts = vec![normalize("go to https://elsewhere.test and https://docs.example.org")];
        let allow = vec!["example.org".to_string()];
        assert_eq!(find_link(&texts, Links::AllowList, &allow).map(|m| m.value), Some("elsewhere.test".into()));
        assert_eq!(find_link(&texts, Links::BlockAll, &[]).map(|m| m.value), Some("elsewhere.test".into()));
        assert_eq!(find_link(&texts, Links::Off, &[]), None);
        let only_allowed = vec![normalize("https://docs.example.org")];
        assert_eq!(find_link(&only_allowed, Links::AllowList, &allow), None);
    }

    #[test]
    fn content_texts_skip_types_gifs_and_images() {
        let content = json!({ "type": "text", "body": "Hello", "gif": { "url": "https://media.giphy.com/x" },
            "preview": { "url": "https://a.test", "title": "Title", "image": "data:image/png;base64,AAAA" },
            "embeds": [{ "title": "E", "fields": [{ "name": "N", "value": "V" }] }] });
        let mut texts = content_texts(&content);
        texts.sort();
        assert_eq!(texts, vec!["e", "hello", "https://a.test", "n", "title", "v"]);
    }

    fn rule(name: &str, terms: &[&str]) -> AutomodRule {
        AutomodRule {
            id: None,
            name: name.into(),
            enabled: true,
            terms: terms.iter().map(|t| t.to_string()).collect(),
            whole_word: false,
            links: "off".into(),
            domains: vec![],
            exempt_roles: vec![],
            exempt_channels: vec![],
            action: "block".into(),
            timeout_minutes: Some(5),
        }
    }

    #[test]
    fn rules_are_normalized_and_checked() {
        let out = validate_rules(vec![rule(" Slurs ", &["BAD ", "bad", "Spam*"])], &[], &[]).unwrap();
        assert_eq!(out[0].name, "Slurs");
        assert_eq!(out[0].terms, vec!["bad", "spam*"]);
        assert_eq!(out[0].timeout_minutes, None, "only timeout rules keep minutes");
        assert!(out[0].id.as_deref().is_some_and(util::is_ulid));
        let kept = validate_rules(out.clone(), &[], &[]).unwrap();
        assert_eq!(kept[0].id, out[0].id);
        let code =
            |rules: Vec<AutomodRule>| validate_rules(rules, &[], &[]).map(|_| ()).map_err(|e| e.code().to_string());
        let bad = Err("automod.rules_invalid".to_string());
        assert_eq!(code(vec![rule("", &["x"])]), bad);
        assert_eq!(code(vec![rule("a", &[])]), bad);
        assert_eq!(code(vec![rule("a", &["*"])]), bad);
        assert_eq!(code(vec![rule("a", &["x"]), rule("A", &["y"])]), bad);
        let mut t = rule("t", &["x"]);
        t.action = "timeout".into();
        t.timeout_minutes = None;
        assert_eq!(code(vec![t.clone()]), bad);
        t.timeout_minutes = Some(40_321);
        assert_eq!(code(vec![t.clone()]), bad);
        t.timeout_minutes = Some(30);
        assert_eq!(code(vec![t]), Ok(()));
        let mut l = rule("l", &[]);
        l.links = "block_list".into();
        assert_eq!(code(vec![l.clone()]), bad);
        l.domains = vec!["Evil.Test.".into()];
        assert_eq!(validate_rules(vec![l], &[], &[]).unwrap()[0].domains, vec!["evil.test"]);
        assert_eq!(code((0..21).map(|i| rule(&format!("r{i}"), &["x"])).collect()), bad);
    }

    #[test]
    fn node_lists_reload_and_keep_the_old_lists_when_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let (words, links) = (dir.path().join("words.txt"), dir.path().join("links.txt"));
        std::fs::write(&words, "spam\n").unwrap();
        std::fs::write(&links, "evil.test\nbad.test\n").unwrap();
        let config = Config {
            automod_words_file: Some(words.to_string_lossy().into()),
            automod_links: links.to_string_lossy().into(),
            ..Config::default()
        };
        let f = NodeFilter::from_config(&config).unwrap();
        let hit = |text: &str| f.find(&[normalize(text)]).map(|m| m.value);
        assert_eq!(f.reload(&config), Ok(ListChanges::default()), "unchanged files change nothing");

        std::fs::write(&words, "spam\nscam\neggs\n").unwrap();
        std::fs::write(&links, "bad.test\n").unwrap();
        let changes = f.reload(&config).unwrap();
        assert_eq!(changes, ListChanges { words_added: 2, words_removed: 0, domains_added: 0, domains_removed: 1 });
        assert!(!changes.is_empty());
        assert_eq!(hit("a scam"), Some("scam".into()));
        assert_eq!(hit("http://evil.test/x"), None, "removed domain");
        assert_eq!(hit("http://bad.test/x"), Some("bad.test".into()));

        // An invalid or unreadable list keeps both old lists.
        std::fs::write(&words, "a*b*c*d*e*f*g\n").unwrap();
        std::fs::write(&links, "").unwrap();
        let err = f.reload(&config).unwrap_err();
        assert!(err.iter().any(|e| e.contains("TAVRN_AUTOMOD_WORDS_FILE")), "{err:?}");
        assert_eq!(hit("a scam"), Some("scam".into()));
        assert_eq!(hit("http://bad.test/x"), Some("bad.test".into()), "links kept too");
        std::fs::remove_file(&links).unwrap();
        std::fs::write(&words, "eggs\n").unwrap();
        assert!(f.reload(&config).unwrap_err().iter().any(|e| e.contains("TAVRN_AUTOMOD_LINKS")));
        assert_eq!(hit("a scam"), Some("scam".into()));
    }

    #[test]
    fn node_lists_read_and_match_whole_words() {
        let dir = std::env::temp_dir().join(format!("automod-{}", util::ulid()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("words.txt");
        std::fs::write(&path, "# comment\n\n Scam* \nforbidden phrase\n*\n").unwrap();
        let list = read_list(&path.to_string_lossy()).unwrap();
        assert_eq!(list, vec!["scam*", "forbidden phrase"]);
        assert!(read_list("/nonexistent/list.txt").is_err());
        let f = NodeFilter::new(list, vec!["malware.test".into()]);
        assert!(f.has_words() && f.has_links());
        assert_eq!(f.find(&[normalize("scammers here")]).map(|m| m.value), Some("scam*".into()));
        assert_eq!(f.find(&[normalize("http://x.malware.test")]).map(|m| m.kind), Some("link"));
        assert_eq!(f.find(&[normalize("forbidden phrases")]), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
