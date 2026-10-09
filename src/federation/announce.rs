// SPDX-License-Identifier: AGPL-3.0-only
//! Peer directory (FEDERATION.md §7): `node.announce`, signed room listings, and the directory worker.
//!
//! **Announcing** (outbound): at start, every 6 hours and whenever a listing-relevant room setting
//! changes, a node with `TAVRN_DIRECTORY_LISTING=true` queues `node.announce` to each reference node
//! (`TAVRN_REFERENCE_NODES`). A pending announce to the same target is replaced, so bursts of changes
//! send one message.
//!
//! **Receiving** (inbound, [`receive`]): the inbox has already verified the node token against the
//! sender's own `.well-known`. Then: payload at most 8 KiB with capped fields, `domain` equal to the
//! sender, dedupe, admin delisting, one announce per domain per 10 minutes, and a **fresh** fetch of the
//! sender's discovery document: name, description, software, capabilities and registration mode of the
//! payload must equal the document, and the document must say `directory_listing: true`. The node row is
//! built from the document, never from the payload alone. Afterwards the node's room list is fetched in
//! the background ([`refresh_rooms`]).
//!
//! **Rooms**: a node serves its own discoverable rooms with a listing JWT it signs (`typ = listing`,
//! `aud = tavrn-directory`, 48 hours). Rooms of other nodes are only taken from the hosting node itself
//! (`GET /api/v1/directory/rooms?local=true`, at most 200) and only with a listing that node signed for
//! exactly that room; the signed values are stored.
//!
//! **Worker** ([`spawn`]): hourly it prunes nodes not seen for 48 hours and expired listings and
//! refreshes room lists older than 6 hours; every 6 hours (and at start) it announces this node and pulls
//! the node lists of the reference nodes, verifying every new domain through its own `.well-known`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{client::Kind, discovery, outbox};
use crate::{
    app::{AppState, SOFTWARE_NAME, SOFTWARE_VERSION, capabilities},
    error::ApiError,
    jwt::{self, Expected, StandardClaims},
    store::{self, directory as dir},
    util,
};

pub const KIND: &str = "node.announce";
/// `aud` of room listings (§7.3).
pub const LISTING_AUD: &str = "tavrn-directory";
pub const LISTING_TYP: &str = "listing";
pub const LISTING_TTL_SECS: i64 = 48 * 3600;
/// Announce interval (and interval of the reference node pull).
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Room lists of listed nodes are refreshed after this long.
pub const ROOM_REFRESH_SECS: i64 = 6 * 3600;
/// Nodes neither announced nor confirmed through a reference node for this long are removed.
pub const NODE_TTL_SECS: i64 = 48 * 3600;
pub const MAX_NODES: i64 = 10_000;
pub const MAX_ROOMS_PER_NODE: usize = 200;
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;
pub const NAME_MAX: usize = 64;
pub const DESCRIPTION_MAX: usize = 500;
/// Pages of 100 read from a reference node's node list per pull, and new domains verified per pull.
pub const PULL_PAGES: usize = 10;
pub const PULL_VERIFY_MAX: usize = 200;
/// Room lists refreshed per hourly round.
pub const REFRESH_BATCH: i64 = 50;
const TICK: Duration = Duration::from_secs(3600);

// ---------------------------------------------------------------- payload

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Software {
    pub name: String,
    pub version: String,
}

/// Payload of `node.announce` (§7.2). Unknown fields are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    pub domain: String,
    pub name: String,
    pub description: String,
    pub software: Software,
    pub capabilities: Vec<String>,
    pub registration: String,
    pub public_rooms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<i64>,
    pub listing: bool,
}

/// The first `max` characters of `s`.
pub fn cap(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// This node's announce.
pub async fn own_announce(state: &AppState) -> Result<Announce, ApiError> {
    let c = &state.config;
    Ok(Announce {
        domain: c.domain.clone(),
        name: cap(&c.name, NAME_MAX),
        description: cap(&c.description, DESCRIPTION_MAX),
        software: Software { name: SOFTWARE_NAME.into(), version: SOFTWARE_VERSION.into() },
        capabilities: capabilities(c).into_iter().map(String::from).collect(),
        registration: enum_str(&c.registration),
        public_rooms: dir::own_room_count(&state.db).await?,
        users: None,
        listing: true,
    })
}

/// Whether this node announces itself at all: federation on, listing on, a real node domain.
pub fn announces(state: &AppState) -> bool {
    let c = &state.config;
    c.federation_enabled && c.directory_listing && super::valid_node_domain(&c.domain)
}

/// Queues `node.announce` to every reference node (replacing a pending one). Returns the number of
/// queued messages; nothing with `TAVRN_DIRECTORY_LISTING=false`.
pub async fn enqueue_all(state: &AppState) -> Result<usize, ApiError> {
    if !announces(state) {
        return Ok(0);
    }
    let own = &state.config.domain;
    let payload = serde_json::to_value(own_announce(state).await?).map_err(|e| ApiError::Internal(e.into()))?;
    let mut queued = 0;
    for target in state.config.reference_nodes() {
        if &target == own || super::check_policy(state, &target).await.is_err() {
            continue;
        }
        dir::delete_pending(&state.db, &target, KIND).await?;
        outbox::enqueue(state, &target, KIND, own, &target, payload.clone()).await?;
        queued += 1;
    }
    Ok(queued)
}

/// A listing-relevant setting changed (a room became (un)discoverable, a discoverable room was renamed
/// or deleted): announce again. Failures are logged; they never fail the user's request.
pub async fn listing_changed(state: &AppState) {
    if let Err(e) = enqueue_all(state).await {
        tracing::warn!(error = %e, "node.announce could not be queued");
    }
}

// ---------------------------------------------------------------- receiving

fn invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

fn unverified(detail: &str) -> ApiError {
    ApiError::BadRequest {
        code: "directory.announce_unverified",
        detail: format!("The announcement does not match the node's discovery document ({detail})"),
    }
}

/// Parses and bounds an announce payload (§7.2: name 64, description 500 characters).
pub fn parse_payload(iss: &str, payload: &Value) -> Result<Announce, ApiError> {
    let size = serde_json::to_vec(payload).map(|b| b.len()).unwrap_or(usize::MAX);
    if size > MAX_PAYLOAD_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "federation.payload_too_large",
            detail: "Announcement larger than 8 KiB".into(),
            meta: json!({ "max_bytes": MAX_PAYLOAD_BYTES }),
        });
    }
    let a: Announce = serde_json::from_value(payload.clone()).map_err(|_| invalid("invalid payload"))?;
    if a.domain != iss {
        return Err(ApiError::Forbidden {
            code: "federation.type_forbidden",
            detail: "A node can only announce itself".into(),
        });
    }
    let short = |s: &str, max: usize| s.chars().count() <= max;
    if !short(&a.name, NAME_MAX)
        || !short(&a.description, DESCRIPTION_MAX)
        || !short(&a.software.name, 64)
        || !short(&a.software.version, 64)
        || !short(&a.registration, 16)
        || a.capabilities.len() > 64
        || a.capabilities.iter().any(|c| !short(c, 64))
        || !(0..=1_000_000).contains(&a.public_rooms)
        || a.users.is_some_and(|u| !(0..=1_000_000_000).contains(&u))
    {
        return Err(invalid("payload field too long or out of range"));
    }
    Ok(a)
}

/// The directory-relevant fields of a peer's validated discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocInfo {
    pub name: String,
    pub description: String,
    pub software: Software,
    pub capabilities: Vec<String>,
    pub registration: String,
    pub directory_listing: bool,
}

/// Reads [`DocInfo`] from a discovery document (already validated by [`discovery::validate`]).
pub fn doc_info(raw: &str) -> Option<DocInfo> {
    let doc: Value = serde_json::from_str(raw).ok()?;
    let s = |v: &Value| v.as_str().map(String::from);
    Some(DocInfo {
        name: cap(&s(&doc["name"]).unwrap_or_default(), NAME_MAX),
        description: cap(&s(&doc["description"]).unwrap_or_default(), DESCRIPTION_MAX),
        software: Software {
            name: cap(&s(&doc["software"]["name"])?, 64),
            version: cap(&s(&doc["software"]["version"])?, 64),
        },
        capabilities: doc["capabilities"].as_array()?.iter().filter_map(s).take(64).map(|c| cap(&c, 64)).collect(),
        registration: cap(&s(&doc["registration"]).unwrap_or_default(), 16),
        directory_listing: doc["directory_listing"].as_bool().unwrap_or(false),
    })
}

/// Compares an announce with the sender's document; the reason of the first difference.
pub fn compare(a: &Announce, doc: &DocInfo) -> Result<(), &'static str> {
    if !doc.directory_listing {
        return Err("directory_listing");
    }
    if a.name != doc.name || a.description != doc.description {
        return Err("name");
    }
    if a.software != doc.software {
        return Err("software");
    }
    if a.registration != doc.registration {
        return Err("registration");
    }
    let mut ours = a.capabilities.clone();
    let mut theirs = doc.capabilities.clone();
    ours.sort();
    ours.dedup();
    theirs.sort();
    theirs.dedup();
    if ours != theirs {
        return Err("capabilities");
    }
    Ok(())
}

/// The document of `domain`: freshly fetched (`fresh`) or from the cache while valid.
async fn document_info(state: &AppState, domain: &str, fresh: bool) -> Result<DocInfo, ApiError> {
    if fresh {
        discovery::fetch(state, domain).await?;
    } else {
        discovery::document(state, domain).await?;
    }
    store::federation::peer(&state.db, domain)
        .await?
        .and_then(|row| doc_info(&row.document))
        .ok_or_else(|| discovery::peer_invalid(domain, "directory fields missing"))
}

fn new_node<'a>(
    domain: &'a str,
    doc: &'a DocInfo,
    caps: &'a str,
    public_rooms: i64,
    users: Option<i64>,
    source: &'a str,
) -> dir::NewNode<'a> {
    dir::NewNode {
        domain,
        name: &doc.name,
        description: &doc.description,
        software_name: &doc.software.name,
        software_version: &doc.software.version,
        capabilities: caps,
        registration: &doc.registration,
        public_rooms,
        users,
        source,
    }
}

async fn keep_node_limit(state: &AppState) -> Result<(), ApiError> {
    if dir::count_nodes(&state.db).await? > MAX_NODES {
        let dropped = dir::trim_nodes(&state.db, MAX_NODES).await?;
        tracing::info!(dropped, "directory full, least recently seen nodes dropped");
    }
    Ok(())
}

/// Handles a `node.announce` from `iss` (authority already checked by the inbox). Returns the outcome
/// for the inbox log.
pub async fn receive(state: &AppState, iss: &str, id: &str, payload: &Value) -> Result<&'static str, ApiError> {
    let announce = parse_payload(iss, payload)?;
    if dir::inbox_seen(&state.db, iss, id).await? {
        return Ok("duplicate");
    }
    if !announce.listing {
        // The node no longer wants to be listed.
        dir::delete_node(&state.db, iss).await?;
        store::federation::mark_seen(&state.db, iss, id, KIND).await?;
        return Ok("unlisted");
    }
    if dir::node_delisted(&state.db, iss).await? {
        store::federation::mark_seen(&state.db, iss, id, KIND).await?;
        return Ok("delisted");
    }
    state.directory_announce_limiter.check_all(&[format!("domain:{iss}")])?;
    let doc = document_info(state, iss, true).await?;
    if let Err(field) = compare(&announce, &doc) {
        tracing::warn!(sender = iss, field, "node.announce does not match the discovery document");
        return Err(unverified(field));
    }
    let caps = serde_json::to_string(&doc.capabilities).map_err(|e| ApiError::Internal(e.into()))?;
    let now = util::now();
    dir::upsert_node(&state.db, new_node(iss, &doc, &caps, announce.public_rooms, announce.users, "announce"), &now)
        .await?;
    keep_node_limit(state).await?;
    store::federation::mark_seen(&state.db, iss, id, KIND).await?;
    let background = state.clone();
    let domain = iss.to_string();
    tokio::spawn(async move {
        if let Err(e) = refresh_rooms(&background, &domain).await {
            tracing::info!(domain, result = e.code(), "directory room refresh failed");
        }
    });
    Ok("handled")
}

// ---------------------------------------------------------------- listings

/// Claims of a room listing (§7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingClaims {
    #[serde(flatten)]
    pub std: StandardClaims,
    pub name: String,
    pub description: String,
    pub icon_sha256: Option<String>,
    pub member_count: i64,
}

#[derive(Debug, Deserialize)]
struct ListingExtra {
    name: String,
    description: String,
    member_count: i64,
}

/// Signs the listing of one of this node's rooms (48 hours).
pub fn sign_listing(
    state: &AppState,
    room_id: &str,
    name: &str,
    description: &str,
    member_count: i64,
) -> Result<String, ApiError> {
    let now = jwt::now_unix();
    let claims = ListingClaims {
        std: StandardClaims {
            iss: state.config.domain.clone(),
            sub: room_id.to_string(),
            aud: LISTING_AUD.into(),
            exp: now + LISTING_TTL_SECS,
            iat: now,
            jti: util::ulid(),
            typ: LISTING_TYP.into(),
        },
        name: name.to_string(),
        description: description.to_string(),
        icon_sha256: None,
        member_count,
    };
    let key = state.signing_key();
    jwt::sign(&key.signing, &key.kid, &claims).map_err(|e| ApiError::Internal(e.into()))
}

/// A verified listing of another node's room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedListing {
    pub room_id: String,
    pub name: String,
    pub description: String,
    pub member_count: i64,
    pub expires_at: String,
}

/// Verifies a listing of `node` for `room_id` with the key named by its `kid`, taken from `node`'s own
/// document. `None` for anything invalid (wrong signer, room, audience or type, expired, too long).
pub async fn verify_listing(state: &AppState, node: &str, room_id: &str, token: &str) -> Option<VerifiedListing> {
    if token.len() > 4096 || !util::is_ulid(room_id) {
        return None;
    }
    let kid = jwt::peek_kid(token).ok()?;
    let key = discovery::key_for(state, node, &kid).await.ok()?;
    let expected = Expected { iss: node.to_string(), aud: LISTING_AUD.into(), typ: LISTING_TYP };
    let (std, extra): (StandardClaims, ListingExtra) =
        jwt::verify_with_skew(token, &key, &expected, jwt::FEDERATION_SKEW_SECS).ok()?;
    let name_len = extra.name.chars().count();
    if std.sub != room_id
        || std.exp - std.iat > LISTING_TTL_SECS + 600
        || !(1..=100).contains(&name_len)
        || extra.description.chars().count() > 1000
        || !(0..=10_000_000).contains(&extra.member_count)
    {
        return None;
    }
    Some(VerifiedListing {
        room_id: room_id.to_string(),
        name: extra.name,
        description: extra.description,
        member_count: extra.member_count,
        expires_at: util::format_time(DateTime::from_timestamp(std.exp, 0)?),
    })
}

#[derive(Debug, Deserialize)]
struct RemoteRoomPage {
    items: Vec<RemoteRoom>,
}

#[derive(Debug, Deserialize)]
struct RemoteRoom {
    node: String,
    room_id: String,
    listing: String,
}

/// Fetches the discoverable rooms of `domain` from `domain` itself and replaces the cached ones with
/// those whose listing verifies. A node whose document no longer allows listing is removed. Returns
/// the number of stored rooms.
pub async fn refresh_rooms(state: &AppState, domain: &str) -> Result<i64, ApiError> {
    super::check_policy(state, domain).await?;
    let now = util::now();
    if dir::node_delisted(&state.db, domain).await? {
        dir::delete_node(&state.db, domain).await?;
        return Ok(0);
    }
    let doc = match document_info(state, domain, false).await {
        Ok(doc) => doc,
        Err(e) => {
            dir::touch_rooms_fetched(&state.db, domain, &now).await?;
            return Err(e);
        }
    };
    if !doc.directory_listing {
        dir::delete_node(&state.db, domain).await?;
        return Ok(0);
    }
    let path = format!("/api/v1/directory/rooms?local=true&limit={MAX_ROOMS_PER_NODE}");
    let fetched = match state.federation.get(domain, &path, Kind::Directory).await {
        Ok(f) => f,
        Err(e) => {
            dir::touch_rooms_fetched(&state.db, domain, &now).await?;
            return Err(e.to_api());
        }
    };
    let page: RemoteRoomPage =
        serde_json::from_slice(&fetched.body).map_err(|_| discovery::peer_invalid(domain, "invalid room list"))?;
    let mut verified: Vec<(VerifiedListing, String)> = Vec::new();
    let mut refused = 0usize;
    for room in page.items.into_iter().take(MAX_ROOMS_PER_NODE) {
        if room.node != domain || verified.iter().any(|(v, _)| v.room_id == room.room_id) {
            refused += 1;
            continue;
        }
        match verify_listing(state, domain, &room.room_id, &room.listing).await {
            Some(v) => verified.push((v, room.listing)),
            None => refused += 1,
        }
    }
    let rows: Vec<dir::NewListing<'_>> = verified
        .iter()
        .map(|(v, listing)| dir::NewListing {
            room_id: &v.room_id,
            name: &v.name,
            description: &v.description,
            member_count: v.member_count,
            listing,
            expires_at: &v.expires_at,
        })
        .collect();
    let stored =
        dir::replace_rooms(&state.db, domain, &rows, &now, i64::from(state.config.directory_max_rooms)).await?;
    tracing::info!(domain, stored, refused, "directory rooms refreshed");
    Ok(stored)
}

// ---------------------------------------------------------------- reference node pull

#[derive(Debug, Deserialize)]
struct RemoteNodePage {
    items: Vec<RemoteNode>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteNode {
    domain: String,
}

/// Verifies `domain` through its own document and lists it (`relay`) if the document allows listing.
pub async fn add_relayed(state: &AppState, domain: &str) -> Result<bool, ApiError> {
    super::check_policy(state, domain).await?;
    if dir::node_delisted(&state.db, domain).await? {
        return Ok(false);
    }
    let doc = document_info(state, domain, false).await?;
    if !doc.directory_listing {
        dir::delete_node(&state.db, domain).await?;
        return Ok(false);
    }
    let caps = serde_json::to_string(&doc.capabilities).map_err(|e| ApiError::Internal(e.into()))?;
    let public_rooms = dir::node(&state.db, domain).await?.map_or(0, |n| n.public_rooms);
    dir::upsert_node(&state.db, new_node(domain, &doc, &caps, public_rooms, None, "relay"), &util::now()).await?;
    Ok(true)
}

/// Reads the node lists of the reference nodes and lists every domain that verifies (the reference
/// nodes themselves included). Domains seen within the refresh interval are not fetched again. Returns
/// the number of newly verified nodes.
pub async fn pull_reference(state: &AppState, now: DateTime<Utc>) -> Result<usize, ApiError> {
    let own = state.config.domain.clone();
    let fresh_after = util::format_time(now - chrono::Duration::seconds(ROOM_REFRESH_SECS));
    let mut candidates: Vec<String> = Vec::new();
    for reference in state.config.reference_nodes() {
        if reference == own || super::check_policy(state, &reference).await.is_err() {
            continue;
        }
        candidates.push(reference.clone());
        let mut cursor: Option<String> = None;
        for _ in 0..PULL_PAGES {
            let mut path = "/api/v1/directory/nodes?limit=100".to_string();
            if let Some(c) = &cursor {
                path.push_str(&format!("&cursor={}", urlencoding(c)));
            }
            let page = match state.federation.get(&reference, &path, Kind::Directory).await {
                Ok(f) => serde_json::from_slice::<RemoteNodePage>(&f.body).ok(),
                Err(e) => {
                    tracing::info!(domain = reference, result = e.label(), "reference node list not available");
                    None
                }
            };
            let Some(page) = page else { break };
            candidates.extend(page.items.into_iter().map(|n| n.domain));
            match page.next {
                Some(next) if !next.is_empty() && next.len() <= 512 => cursor = Some(next),
                _ => break,
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    let mut todo = Vec::new();
    for domain in candidates {
        if domain == own || !super::valid_node_domain(&domain) {
            continue;
        }
        if dir::node(&state.db, &domain).await?.is_some_and(|n| n.last_seen > fresh_after) {
            continue;
        }
        todo.push(domain);
        if todo.len() >= PULL_VERIFY_MAX {
            break;
        }
    }
    let results: Vec<bool> = futures::stream::iter(todo)
        .map(|domain| async move {
            match add_relayed(state, &domain).await {
                Ok(true) => {
                    if let Err(e) = refresh_rooms(state, &domain).await {
                        tracing::info!(domain, result = e.code(), "directory room refresh failed");
                    }
                    true
                }
                Ok(false) => false,
                Err(e) => {
                    tracing::info!(domain, result = e.code(), "relayed node not verified");
                    false
                }
            }
        })
        .buffer_unordered(8)
        .collect()
        .await;
    keep_node_limit(state).await?;
    Ok(results.into_iter().filter(|ok| *ok).count())
}

/// Percent-encodes a cursor for a query string (unreserved characters stay).
fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

// ---------------------------------------------------------------- worker

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub pruned_nodes: u64,
    pub pruned_rooms: u64,
    pub refreshed: usize,
}

/// Hourly round: prune stale nodes and expired listings, refresh room lists older than 6 hours.
pub async fn tick(state: &AppState, now: DateTime<Utc>) -> Result<TickReport, ApiError> {
    let pruned = dir::prune(
        &state.db,
        &util::format_time(now),
        &util::format_time(now - chrono::Duration::seconds(NODE_TTL_SECS)),
    )
    .await?;
    let mut report = TickReport { pruned_nodes: pruned.nodes, pruned_rooms: pruned.rooms, refreshed: 0 };
    if !state.config.federation_enabled {
        return Ok(report);
    }
    let cutoff = util::format_time(now - chrono::Duration::seconds(ROOM_REFRESH_SECS));
    for domain in dir::nodes_due(&state.db, &cutoff, REFRESH_BATCH).await? {
        match refresh_rooms(state, &domain).await {
            Ok(_) => report.refreshed += 1,
            Err(e) => tracing::info!(domain, result = e.code(), "directory room refresh failed"),
        }
    }
    Ok(report)
}

/// Every 6 hours: announce this node and pull the reference nodes' lists.
pub async fn sync(state: &AppState, now: DateTime<Utc>) -> Result<(), ApiError> {
    if !state.config.federation_enabled {
        return Ok(());
    }
    let queued = enqueue_all(state).await?;
    let verified = pull_reference(state, now).await?;
    tracing::info!(queued, verified, "directory sync");
    Ok(())
}

/// Runs the directory worker: a sync shortly after the start and then every 6 hours (±10 minutes), a
/// tick every hour.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Let the server bind first: peers fetch our document while handling the announce.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut next_sync = tokio::time::Instant::now();
        loop {
            // Several instances: the leader announces and prunes (`cache::leader`).
            if !state.cluster.is_leader() {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            if tokio::time::Instant::now() >= next_sync {
                if let Err(e) = sync(&state, Utc::now()).await {
                    tracing::warn!(error = %e, "directory sync failed");
                }
                let jitter: i64 = rand::RngExt::random_range(&mut rand::rng(), -600..=600);
                let secs = (ANNOUNCE_EVERY.as_secs() as i64 + jitter).max(60) as u64;
                next_sync = tokio::time::Instant::now() + Duration::from_secs(secs);
            }
            match tick(&state, Utc::now()).await {
                Ok(r) if r != TickReport::default() => tracing::info!(
                    pruned_nodes = r.pruned_nodes,
                    pruned_rooms = r.pruned_rooms,
                    refreshed = r.refreshed,
                    "directory housekeeping"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "directory housekeeping failed"),
            }
            tokio::time::sleep(TICK).await;
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn announce() -> Value {
        json!({
            "domain": "a.example", "name": "Node A", "description": "Hello",
            "software": { "name": "tavrn-node", "version": "0.1.0" },
            "capabilities": ["federation", "federation.v1"], "registration": "open",
            "public_rooms": 3, "listing": true, "future": "ignored"
        })
    }

    fn doc() -> DocInfo {
        DocInfo {
            name: "Node A".into(),
            description: "Hello".into(),
            software: Software { name: "tavrn-node".into(), version: "0.1.0".into() },
            capabilities: vec!["federation.v1".into(), "federation".into()],
            registration: "open".into(),
            directory_listing: true,
        }
    }

    #[test]
    fn payloads_are_bounded() {
        let a = parse_payload("a.example", &announce()).unwrap();
        assert_eq!(a.public_rooms, 3);
        assert_eq!(a.users, None);
        let code = |v: Value| parse_payload("a.example", &v).unwrap_err().code().to_string();
        assert_eq!(code(json!({})), "federation.envelope_invalid");
        let mut v = announce();
        v["domain"] = json!("b.example");
        assert_eq!(code(v), "federation.type_forbidden", "a node announces only itself");
        let mut v = announce();
        v["name"] = json!("n".repeat(65));
        assert_eq!(code(v), "federation.envelope_invalid");
        let mut v = announce();
        v["description"] = json!("d".repeat(501));
        assert_eq!(code(v), "federation.envelope_invalid");
        let mut v = announce();
        v["capabilities"] = json!((0..65).map(|i| format!("c{i}")).collect::<Vec<_>>());
        assert_eq!(code(v), "federation.envelope_invalid");
        let mut v = announce();
        v["public_rooms"] = json!(-1);
        assert_eq!(code(v), "federation.envelope_invalid");
        let mut v = announce();
        v["pad"] = json!("x".repeat(9000));
        assert_eq!(code(v), "federation.payload_too_large");
        // Characters, not bytes, are counted.
        let mut v = announce();
        v["name"] = json!("ä".repeat(64));
        assert!(parse_payload("a.example", &v).is_ok());
    }

    #[test]
    fn announces_must_match_the_document() {
        let a = parse_payload("a.example", &announce()).unwrap();
        assert_eq!(compare(&a, &doc()), Ok(()), "capability order does not matter");
        let with = |f: &dyn Fn(&mut DocInfo)| {
            let mut d = doc();
            f(&mut d);
            compare(&a, &d)
        };
        assert_eq!(with(&|d| d.directory_listing = false), Err("directory_listing"));
        assert_eq!(with(&|d| d.name = "Other".into()), Err("name"));
        assert_eq!(with(&|d| d.software.version = "9.9.9".into()), Err("software"));
        assert_eq!(with(&|d| d.registration = "closed".into()), Err("registration"));
        assert_eq!(with(&|d| d.capabilities.push("voice".into())), Err("capabilities"));
    }

    #[test]
    fn document_fields_are_read_and_capped() {
        let raw = json!({
            "name": "n".repeat(100), "description": "Desc", "software": { "name": "x", "version": "1" },
            "capabilities": ["federation.v1", 5], "registration": "invite", "directory_listing": true
        })
        .to_string();
        let d = doc_info(&raw).unwrap();
        assert_eq!(d.name.len(), NAME_MAX);
        assert_eq!(d.capabilities, vec!["federation.v1"]);
        assert_eq!(d.registration, "invite");
        assert!(d.directory_listing);
        let without = json!({ "software": { "name": "x", "version": "1" }, "capabilities": [] }).to_string();
        assert!(!doc_info(&without).unwrap().directory_listing, "missing means not listed");
        assert!(doc_info("{}").is_none());
    }

    #[test]
    fn cursors_are_percent_encoded() {
        assert_eq!(urlencoding("a.test"), "a.test");
        assert_eq!(urlencoding("a b&c=d"), "a%20b%26c%3Dd");
    }
}
