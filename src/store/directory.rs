// SPDX-License-Identifier: AGPL-3.0-only
//! Peer directory (FEDERATION.md §7): listed nodes, cached rooms of other nodes, admin delisting.
//!
//! "Listed" always means: not delisted by an admin of this node, not banned as a domain (node ban), no
//! block of the peer (`federation_peers.status`) and no failed conformance check (§7.4). The configured block- and allowlists are
//! applied by the callers (they live in the configuration, not in the database).

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError};

/// SQL condition: the domain in `col` is neither delisted as a whole, nor banned, nor blocked, nor failing
/// the conformance check.
fn listed(col: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM directory_delisted l WHERE l.node = {col} AND l.room_id = '')
         AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.room_id IS NULL AND b.subject = {col})
         AND NOT EXISTS (SELECT 1 FROM federation_peers p WHERE p.domain = {col}
                         AND (p.status <> 'ok' OR p.conformance_result = 'fail'))"
    )
}

/// `%text%` for `LIKE … ESCAPE '\'`, lowercased, with `%`, `_` and `\` escaped; empty for no search.
pub fn like_pattern(q: &str) -> String {
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return String::new();
    }
    let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{escaped}%")
}

// ---------------------------------------------------------------- nodes

const NODE_COLS: &str = "domain, name, description, software_name, software_version, capabilities, registration, public_rooms, users, source, first_seen, last_seen, last_announce, rooms_fetched_at";

#[derive(Debug, Clone, FromRow)]
pub struct NodeRow {
    pub domain: String,
    pub name: String,
    pub description: String,
    pub software_name: String,
    pub software_version: String,
    /// JSON array of strings.
    pub capabilities: String,
    pub registration: String,
    pub public_rooms: i64,
    pub users: Option<i64>,
    /// `announce` or `relay`.
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub last_announce: Option<String>,
    pub rooms_fetched_at: Option<String>,
}

/// A node as verified through its own discovery document.
pub struct NewNode<'a> {
    pub domain: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub software_name: &'a str,
    pub software_version: &'a str,
    pub capabilities: &'a str,
    pub registration: &'a str,
    pub public_rooms: i64,
    pub users: Option<i64>,
    /// `announce` or `relay`. A node that once announced itself stays `announce`.
    pub source: &'a str,
}

/// Inserts or refreshes a node; `last_seen = now`, and `last_announce = now` for announces.
pub async fn upsert_node(db: &Pool, n: NewNode<'_>, now: &str) -> Result<(), ApiError> {
    let announce = (n.source == "announce").then_some(now);
    sqlx::query(
        "INSERT INTO directory_nodes (domain, name, description, software_name, software_version, capabilities,
             registration, public_rooms, users, source, first_seen, last_seen, last_announce)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $12)
         ON CONFLICT (domain) DO UPDATE SET name = $2, description = $3, software_name = $4, software_version = $5,
             capabilities = $6, registration = $7, public_rooms = $8, users = $9,
             source = CASE WHEN directory_nodes.source = 'announce' THEN 'announce' ELSE $10 END,
             last_seen = $11, last_announce = COALESCE($12, directory_nodes.last_announce)",
    )
    .bind(n.domain)
    .bind(n.name)
    .bind(n.description)
    .bind(n.software_name)
    .bind(n.software_version)
    .bind(n.capabilities)
    .bind(n.registration)
    .bind(n.public_rooms)
    .bind(n.users)
    .bind(n.source)
    .bind(now)
    .bind(announce)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn node(db: &Pool, domain: &str) -> Result<Option<NodeRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {NODE_COLS} FROM directory_nodes WHERE domain = $1"))
        .bind(domain)
        .fetch_optional(db)
        .await?)
}

/// A listed node (see the module comment), or `None`.
pub async fn listed_node(db: &Pool, domain: &str) -> Result<Option<NodeRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {NODE_COLS} FROM directory_nodes d WHERE d.domain = $1 AND {}",
        listed("d.domain")
    ))
    .bind(domain)
    .fetch_optional(db)
    .await?)
}

/// Listed nodes ordered by domain, after `after`, optionally matching `pattern` (see [`like_pattern`])
/// in domain, name or description.
pub async fn nodes_page(db: &Pool, after: &str, pattern: &str, limit: i64) -> Result<Vec<NodeRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {NODE_COLS} FROM directory_nodes d
         WHERE d.domain > $1 AND {}
           AND ($2 = '' OR d.domain LIKE $2 ESCAPE '\\' OR LOWER(d.name) LIKE $2 ESCAPE '\\'
                OR LOWER(d.description) LIKE $2 ESCAPE '\\')
         ORDER BY d.domain LIMIT $3",
        listed("d.domain")
    ))
    .bind(after)
    .bind(pattern)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Every known node domain (for the room refresh and the configured block- and allowlists).
pub async fn node_domains(db: &Pool) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT domain FROM directory_nodes ORDER BY domain").fetch_all(db).await?)
}

/// Domains whose room list was not fetched since `cutoff`, oldest first.
pub async fn nodes_due(db: &Pool, cutoff: &str, limit: i64) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT domain FROM directory_nodes WHERE rooms_fetched_at IS NULL OR rooms_fetched_at < $1
         ORDER BY rooms_fetched_at, domain LIMIT $2",
    )
    .bind(cutoff)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Removes a node and its cached rooms.
pub async fn delete_node(db: &Pool, domain: &str) -> Result<bool, ApiError> {
    sqlx::query("DELETE FROM directory_rooms WHERE node = $1").bind(domain).execute(db).await?;
    let n =
        sqlx::query("DELETE FROM directory_nodes WHERE domain = $1").bind(domain).execute(db).await?.rows_affected();
    Ok(n > 0)
}

pub async fn count_nodes(db: &Pool) -> Result<i64, ApiError> {
    Ok(sqlx::query("SELECT COUNT(*) AS n FROM directory_nodes").fetch_one(db).await?.try_get::<i64, _>("n")?)
}

/// Keeps the `keep` most recently seen nodes and removes the rest (with their rooms).
pub async fn trim_nodes(db: &Pool, keep: i64) -> Result<u64, ApiError> {
    let gone: Vec<String> = sqlx::query_scalar("SELECT domain FROM directory_nodes ORDER BY last_seen DESC, domain")
        .fetch_all(db)
        .await?
        .into_iter()
        .skip(usize::try_from(keep).unwrap_or(0))
        .collect();
    for domain in &gone {
        delete_node(db, domain).await?;
    }
    Ok(gone.len() as u64)
}

// ---------------------------------------------------------------- rooms

/// A room of another node with its verified listing.
pub struct NewListing<'a> {
    pub room_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub member_count: i64,
    pub listing: &'a str,
    pub expires_at: &'a str,
}

/// Replaces the cached rooms of `node` with `rooms`, keeping the total of cached rooms of all nodes at
/// `max_total` (rooms beyond it are not stored). Records the fetch time and the stored count. Returns
/// the number of stored rooms.
pub async fn replace_rooms(
    db: &Pool,
    node: &str,
    rooms: &[NewListing<'_>],
    now: &str,
    max_total: i64,
) -> Result<i64, ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM directory_rooms WHERE node = $1").bind(node).execute(&mut *tx).await?;
    let others =
        sqlx::query("SELECT COUNT(*) AS n FROM directory_rooms").fetch_one(&mut *tx).await?.try_get::<i64, _>("n")?;
    let room = usize::try_from((max_total - others).max(0)).unwrap_or(0);
    let mut stored = 0i64;
    for r in rooms.iter().take(room) {
        sqlx::query(
            "INSERT INTO directory_rooms (node, room_id, name, description, member_count, listing, expires_at, fetched_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(node)
        .bind(r.room_id)
        .bind(r.name)
        .bind(r.description)
        .bind(r.member_count)
        .bind(r.listing)
        .bind(r.expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        stored += 1;
    }
    sqlx::query("UPDATE directory_nodes SET rooms_fetched_at = $1, public_rooms = $2 WHERE domain = $3")
        .bind(now)
        .bind(stored)
        .bind(node)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(stored)
}

/// Records a failed room fetch, so the node is retried at the next refresh interval.
pub async fn touch_rooms_fetched(db: &Pool, node: &str, now: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE directory_nodes SET rooms_fetched_at = $1 WHERE domain = $2")
        .bind(now)
        .bind(node)
        .execute(db)
        .await?;
    Ok(())
}

/// One row of `GET /directory/rooms`: an own room (`listing` empty, signed by the caller) or a cached
/// room of another node.
#[derive(Debug, Clone, FromRow)]
pub struct RoomEntryRow {
    pub node: String,
    pub room_id: String,
    pub name: String,
    pub description: String,
    pub member_count: i64,
    pub listing: String,
    /// `none` or `adults_only` (PROTOCOL.md §5e); rooms of other nodes are never gated (gated rooms do not federate).
    pub age_gate: String,
}

/// Position after which a page continues (order: member count descending, node, room id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomCursor {
    pub member_count: i64,
    pub node: String,
    pub room_id: String,
}

pub struct RoomQuery<'a> {
    pub own_domain: &'a str,
    /// Only this node's own rooms.
    pub local: bool,
    /// Only rooms of this node (empty: all).
    pub node: &'a str,
    /// See [`like_pattern`].
    pub pattern: &'a str,
    pub min_members: i64,
    pub after: Option<&'a RoomCursor>,
    pub now: &'a str,
    pub limit: i64,
    /// Include rooms with an age gate (the requester is an adult, PROTOCOL.md §5e).
    pub include_gated: bool,
}

/// Own discoverable public rooms plus unexpired rooms of listed nodes, without delisted rooms.
pub async fn rooms_page(db: &Pool, q: RoomQuery<'_>) -> Result<Vec<RoomEntryRow>, ApiError> {
    let sql = format!(
        "SELECT node, room_id, name, description, member_count, listing, age_gate FROM (
             SELECT CAST($1 AS TEXT) AS node, r.id AS room_id, r.name AS name, r.description AS description,
                    (SELECT COUNT(*) FROM room_members m WHERE m.room_id = r.id) AS member_count, '' AS listing,
                    r.age_gate AS age_gate
             FROM rooms r WHERE r.discoverable = 1 AND r.join_mode = 'public' AND ($12 = 1 OR r.age_gate = 'none')
             UNION ALL
             SELECT d.node, d.room_id, d.name, d.description, d.member_count, d.listing, 'none' AS age_gate
             FROM directory_rooms d JOIN directory_nodes n ON n.domain = d.node
             WHERE $2 = 0 AND d.expires_at > $3
         ) x
         WHERE NOT EXISTS (SELECT 1 FROM directory_delisted l WHERE l.node = x.node AND l.room_id = x.room_id)
           AND (x.node = $1 OR ({}))
           AND ($4 = '' OR x.node = $4)
           AND ($5 = '' OR LOWER(x.name) LIKE $5 ESCAPE '\\' OR LOWER(x.description) LIKE $5 ESCAPE '\\')
           AND x.member_count >= $6
           AND ($7 = 0 OR x.member_count < $8 OR (x.member_count = $8 AND (x.node > $9 OR (x.node = $9 AND x.room_id > $10))))
         ORDER BY x.member_count DESC, x.node, x.room_id
         LIMIT $11",
        listed("x.node")
    );
    let (has_cursor, count, node, room) = match q.after {
        Some(c) => (1i64, c.member_count, c.node.as_str(), c.room_id.as_str()),
        None => (0, 0, "", ""),
    };
    Ok(sqlx::query_as(&sql)
        .bind(q.own_domain)
        .bind(i64::from(q.local))
        .bind(q.now)
        .bind(q.node)
        .bind(q.pattern)
        .bind(q.min_members)
        .bind(has_cursor)
        .bind(count)
        .bind(node)
        .bind(room)
        .bind(q.limit)
        .bind(i64::from(q.include_gated))
        .fetch_all(db)
        .await?)
}

/// Number of this node's own discoverable public rooms (the `public_rooms` of its announce).
pub async fn own_room_count(db: &Pool) -> Result<i64, ApiError> {
    Ok(sqlx::query("SELECT COUNT(*) AS n FROM rooms WHERE discoverable = 1 AND join_mode = 'public'")
        .fetch_one(db)
        .await?
        .try_get::<i64, _>("n")?)
}

pub async fn cached_room_count(db: &Pool) -> Result<i64, ApiError> {
    Ok(sqlx::query("SELECT COUNT(*) AS n FROM directory_rooms").fetch_one(db).await?.try_get::<i64, _>("n")?)
}

// ---------------------------------------------------------------- delisting

#[derive(Debug, Clone, FromRow)]
pub struct DelistedRow {
    pub node: String,
    /// Empty for the whole node.
    pub room_id: String,
    pub created_by: Option<String>,
    pub created_at: String,
}

/// Delists a node (`room_id` empty) or a room and drops what is cached of it. `false` if it was
/// delisted already.
pub async fn delist(db: &Pool, node: &str, room_id: &str, by: &str, now: &str) -> Result<bool, ApiError> {
    let r =
        sqlx::query("INSERT INTO directory_delisted (node, room_id, created_by, created_at) VALUES ($1, $2, $3, $4)")
            .bind(node)
            .bind(room_id)
            .bind(by)
            .bind(now)
            .execute(db)
            .await;
    match r {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    if room_id.is_empty() {
        delete_node(db, node).await?;
    } else {
        sqlx::query("DELETE FROM directory_rooms WHERE node = $1 AND room_id = $2")
            .bind(node)
            .bind(room_id)
            .execute(db)
            .await?;
    }
    Ok(true)
}

/// Undoes a delisting; `false` if there was none.
pub async fn relist(db: &Pool, node: &str, room_id: &str) -> Result<bool, ApiError> {
    let n = sqlx::query("DELETE FROM directory_delisted WHERE node = $1 AND room_id = $2")
        .bind(node)
        .bind(room_id)
        .execute(db)
        .await?
        .rows_affected();
    Ok(n > 0)
}

pub async fn delisted(db: &Pool) -> Result<Vec<DelistedRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT node, room_id, created_by, created_at FROM directory_delisted ORDER BY created_at DESC LIMIT 1000",
    )
    .fetch_all(db)
    .await?)
}

/// `true` if the node is delisted as a whole.
pub async fn node_delisted(db: &Pool, node: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM directory_delisted WHERE node = $1 AND room_id = ''")
        .bind(node)
        .fetch_optional(db)
        .await?
        .is_some())
}

// ---------------------------------------------------------------- reports (§9.2)

/// A stored report of a local user about another node or one of its rooms.
#[derive(Debug, Clone, FromRow)]
pub struct ReportRow {
    pub id: String,
    pub domain: String,
    /// Empty for the node as a whole.
    pub room_id: String,
    pub kind: String,
    pub detail: String,
    /// Address of the reporting user.
    pub reporter: String,
    pub created_at: String,
    /// Reference of a reported application (APPLICATIONS.md §4.4).
    pub application_ref: Option<String>,
}

pub struct NewReport<'a> {
    pub id: &'a str,
    pub reporter_id: &'a str,
    pub domain: &'a str,
    pub room_id: &'a str,
    pub kind: &'a str,
    pub detail: &'a str,
    pub created_at: &'a str,
    pub application_ref: Option<&'a str>,
}

pub async fn add_report(db: &Pool, r: NewReport<'_>) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO directory_reports (id, reporter_id, domain, room_id, kind, detail, created_at, application_ref)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(r.id)
    .bind(r.reporter_id)
    .bind(r.domain)
    .bind(r.room_id)
    .bind(r.kind)
    .bind(r.detail)
    .bind(r.created_at)
    .bind(r.application_ref)
    .execute(db)
    .await?;
    Ok(())
}

/// Reports `reporter_id` made since `since` (the per-user limit).
pub async fn reports_by_since(db: &Pool, reporter_id: &str, since: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS n FROM directory_reports WHERE reporter_id = $1 AND created_at >= $2",
    )
    .bind(reporter_id)
    .bind(since)
    .fetch_one(db)
    .await?
    .try_get::<i64, _>("n")?)
}

/// Distinct users who reported `domain` since `since`.
pub async fn reporters_since(db: &Pool, domain: &str, since: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query(
        "SELECT CAST(COUNT(DISTINCT reporter_id) AS BIGINT) AS n FROM directory_reports
         WHERE domain = $1 AND created_at >= $2",
    )
    .bind(domain)
    .bind(since)
    .fetch_one(db)
    .await?
    .try_get::<i64, _>("n")?)
}

/// Reports per reported domain for the admin overview.
#[derive(Debug, Clone, FromRow)]
pub struct ReportSummaryRow {
    pub domain: String,
    pub reports: i64,
    pub reporters: i64,
    /// Reports made since the `recent` cutoff of the query.
    pub recent: i64,
    pub last_at: String,
    /// 1 if the node is delisted here.
    pub delisted: i64,
}

/// Reported domains, most recently reported first (at most `limit`).
pub async fn report_summary(db: &Pool, recent_since: &str, limit: i64) -> Result<Vec<ReportSummaryRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT r.domain AS domain, CAST(COUNT(*) AS BIGINT) AS reports,
                CAST(COUNT(DISTINCT r.reporter_id) AS BIGINT) AS reporters,
                CAST(SUM(CASE WHEN r.created_at >= $1 THEN 1 ELSE 0 END) AS BIGINT) AS recent,
                MAX(r.created_at) AS last_at,
                CAST(MAX(CASE WHEN l.node IS NULL THEN 0 ELSE 1 END) AS BIGINT) AS delisted
         FROM directory_reports r
         LEFT JOIN directory_delisted l ON l.node = r.domain AND l.room_id = ''
         GROUP BY r.domain ORDER BY MAX(r.created_at) DESC, r.domain LIMIT $2",
    )
    .bind(recent_since)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// The reports about `domain`, newest first (at most `limit`).
pub async fn reports_of(db: &Pool, domain: &str, limit: i64) -> Result<Vec<ReportRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT r.id, r.domain, r.room_id, r.kind, r.detail, u.username || '@' || u.domain AS reporter, r.created_at,
                r.application_ref
         FROM directory_reports r JOIN users u ON u.id = r.reporter_id
         WHERE r.domain = $1 ORDER BY r.created_at DESC, r.id DESC LIMIT $2",
    )
    .bind(domain)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

/// Deletes the reports about `domain`; returns how many there were.
pub async fn dismiss_reports(db: &Pool, domain: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM directory_reports WHERE domain = $1").bind(domain).execute(db).await?.rows_affected())
}

/// Deletes reports older than `cutoff`.
pub async fn prune_reports(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM directory_reports WHERE created_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected())
}

// ---------------------------------------------------------------- inbox and outbox

/// `true` if the inbox already recorded message `id` of `iss` (dedupe, FEDERATION.md §5.1).
pub async fn inbox_seen(db: &Pool, iss: &str, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM federation_inbox_seen WHERE iss = $1 AND id = $2")
        .bind(iss)
        .bind(id)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Drops queued (undelivered) notifications of `kind` to `target`; a newer one replaces them.
pub async fn delete_pending(db: &Pool, target: &str, kind: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM federation_outbox WHERE target = $1 AND type = $2")
        .bind(target)
        .bind(kind)
        .execute(db)
        .await?
        .rows_affected())
}

// ---------------------------------------------------------------- housekeeping

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DirectoryPrune {
    pub nodes: u64,
    pub rooms: u64,
}

/// Removes nodes not seen since `node_cutoff` (with their rooms) and rooms whose listing expired.
pub async fn prune(db: &Pool, now: &str, node_cutoff: &str) -> Result<DirectoryPrune, ApiError> {
    let stale: Vec<String> = sqlx::query_scalar("SELECT domain FROM directory_nodes WHERE last_seen < $1")
        .bind(node_cutoff)
        .fetch_all(db)
        .await?;
    let mut report = DirectoryPrune::default();
    for domain in &stale {
        report.rooms +=
            sqlx::query("DELETE FROM directory_rooms WHERE node = $1").bind(domain).execute(db).await?.rows_affected();
        report.nodes += sqlx::query("DELETE FROM directory_nodes WHERE domain = $1")
            .bind(domain)
            .execute(db)
            .await?
            .rows_affected();
    }
    report.rooms +=
        sqlx::query("DELETE FROM directory_rooms WHERE expires_at <= $1").bind(now).execute(db).await?.rows_affected();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_pattern("  "), "");
        assert_eq!(like_pattern("Gaming"), "%gaming%");
        assert_eq!(like_pattern("100%_x\\"), "%100\\%\\_x\\\\%");
    }
}
