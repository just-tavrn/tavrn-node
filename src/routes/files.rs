// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of files channels (`protocol/FILES.md`): list and search, folders, streamed
//! uploads and ranged downloads, rename/move, recursive delete, usage, and the per-channel storage backend.
//! End-to-end encrypted channels (§8) take client-chosen ids and entry records instead of names, store the
//! clients' ciphertext as it is, keep thumbnails, and serve records only inside the requester's history window.
//!
//! Permissions (channel level): `view_channel` browses and downloads; `attach_files` uploads, creates folders
//! and renames, moves or deletes the member's own entries; `manage_files` does that for everybody's entries;
//! the backend needs `manage_channels` and `manage_files`. Bots have no access (not in `APP_ROUTES`).

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::{AuthUser, RateLimiter},
    entitlements::{self, Entitlements},
    error::{ApiError, ProblemDetails},
    files::{
        self, ByteStream, FileEntry, MAX_DEPTH, MAX_ENTRIES_PER_CHANNEL,
        remote::{self, Kind, RemoteConfig, RemoteStore},
    },
    permissions as p,
    store::{self, files::EntryRow},
    util,
    validate::{self, bad},
};

/// The routes (merged under `/api/v1`); the upload route is mounted separately without the 30-second
/// request timeout ([`upload_route`]).
pub fn routes() -> Router<AppState> {
    let small = || DefaultBodyLimit::max(16 * 1024);
    let base = "/rooms/{room_id}/channels/{channel_id}/files";
    Router::new()
        .route(base, get(list))
        .route(&format!("{base}/folders"), post(create_folder).layer(small()))
        .route(&format!("{base}/usage"), get(usage))
        .route(&format!("{base}/mine"), get(mine))
        .route(&format!("{base}/records"), get(records))
        .route(
            &format!("{base}/{{entry_id}}/thumbnail"),
            get(get_thumbnail).put(put_thumbnail).layer(DefaultBodyLimit::disable()),
        )
        .route(&format!("{base}/backend"), get(get_backend).put(put_backend).layer(small()))
        .route(&format!("{base}/backend/test"), post(test_backend).layer(small()))
        .route(&format!("{base}/{{entry_id}}"), get(get_entry).patch(update).delete(delete).layer(small()))
        .route(&format!("{base}/{{entry_id}}/download"), get(download))
}

/// Path of the upload route (full, mounted outside the API timeout: large files take longer than 30 s).
pub const UPLOAD_PATH: &str = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/upload";
/// Longest upload (the read timeout of the body stream still ends stalled uploads).
pub const UPLOAD_TIMEOUT: Duration = Duration::from_secs(6 * 3600);

pub fn upload_route() -> axum::routing::MethodRouter<AppState> {
    post(upload).layer(DefaultBodyLimit::disable())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list,
        create_folder,
        upload,
        download,
        get_entry,
        update,
        delete,
        usage,
        mine,
        records,
        put_thumbnail,
        get_thumbnail,
        get_backend,
        put_backend,
        test_backend
    ),
    components(schemas(
        FileEntry,
        FileList,
        Crumb,
        FileEntryDetail,
        CreateFolderRequest,
        UpdateEntryRequest,
        DeleteResult,
        FilesInfo,
        MineList,
        RecordList,
        BackendInfo,
        BackendRequest,
        BackendTest
    ))
)]
pub struct FilesApi;

// ---------------------------------------------------------------- Helpers

/// The files channel addressed by the route, with the requester's permissions (`view_channel` required).
async fn files_channel(state: &AppState, room_id: &str, channel_id: &str, auth: &AuthUser) -> Result<Conv, ApiError> {
    let conv = access::channel_conversation(state, room_id, channel_id, &auth.user).await?;
    match &conv.kind {
        ConvKind::Channel { channel, .. } if channel.kind == "files" => {}
        _ => return Err(bad("channel.not_files", "This channel is not a files channel")),
    }
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "view channel")?;
    Ok(conv)
}

fn room_of(conv: &Conv) -> &crate::models::Room {
    match &conv.kind {
        ConvKind::Channel { access, .. } => &access.room,
        // `files_channel` only returns channels.
        ConvKind::Direct { .. } => unreachable!("files channels are room channels"),
    }
}

fn entry_not_found() -> ApiError {
    access::not_found("File", "files.not_found")
}

fn name_taken(name: &str) -> ApiError {
    ApiError::Conflict {
        code: "files.name_taken",
        detail: format!("\"{name}\" already exists in this folder"),
        meta: serde_json::json!({ "name": name }),
    }
}

fn disabled() -> ApiError {
    ApiError::Forbidden { code: "files.disabled", detail: "Files channels are not available for this room".into() }
}

/// `files_channels.enabled` of the room (its owner's entitlements).
pub async fn enabled_for(state: &AppState, room: &crate::models::Room) -> Result<bool, ApiError> {
    Ok(Entitlements::for_room(state, room).await?.get(entitlements::FILES_CHANNELS_ENABLED) != 0)
}

async fn entry_in(state: &AppState, conv: &Conv, entry_id: &str) -> Result<EntryRow, ApiError> {
    if !util::is_ulid(entry_id) {
        return Err(entry_not_found());
    }
    store::files::entry(&state.db, &conv.id, entry_id).await?.ok_or_else(entry_not_found)
}

/// Start of the requester's history window for entry records (RFC 3339; FILES.md §8.7), `None` = no limit.
/// Only encrypted channels and room members (node admins who are not members cannot decrypt anyway).
fn record_cut(conv: &Conv) -> Option<String> {
    if !conv.encrypted {
        return None;
    }
    let ConvKind::Channel { access, channel } = &conv.kind else { return None };
    let member = access.member.as_ref()?;
    let joined = util::parse_time(&member.joined_at)?;
    let policy = crate::history::Policy::of(channel.history_for_new_members.as_deref());
    crate::history::cutoff(policy, p::has(conv.perms, p::READ_HISTORY), joined).map(util::format_time)
}

/// Checks an entry record like message content (FILES.md §8.4) and returns it as stored with the session's user
/// and device.
async fn check_record<'a>(
    state: &AppState,
    auth: &'a AuthUser,
    author: &'a str,
    conv: &Conv,
    record: Option<&'a str>,
    epoch: Option<i64>,
) -> Result<store::files::Record<'a>, ApiError> {
    let record = files::record_shape(record)?;
    let epoch = crate::routes::messages::check_ciphertext(state, auth, &conv.id, record, epoch).await?;
    Ok(store::files::Record { record, epoch, author, device_id: auth.public_device_id() })
}

fn encrypted_names() -> ApiError {
    bad("files.encrypted", "This channel is end-to-end encrypted: names travel inside the entry record")
}

fn not_encrypted() -> ApiError {
    bad("files.not_encrypted", "This files channel is not end-to-end encrypted")
}

fn crumbs(path: Vec<EntryRow>, cut: Option<&str>) -> Vec<Crumb> {
    path.into_iter()
        .map(|f| {
            let e = f.to_api_cut(cut);
            Crumb {
                id: f.id,
                name: f.name,
                record: e.record,
                record_epoch: e.record_epoch,
                record_author: e.record_author,
                record_device_id: e.record_device_id,
            }
        })
        .collect()
}

/// A folder of this channel (`None` = top level).
async fn folder_in(state: &AppState, conv: &Conv, id: Option<&str>) -> Result<Option<EntryRow>, ApiError> {
    let Some(id) = id.filter(|s| !s.is_empty()) else { return Ok(None) };
    let entry = entry_in(state, conv, id).await.map_err(|_| access::not_found("Folder", "files.parent_not_found"))?;
    if !entry.is_folder() {
        return Err(bad("files.parent_not_folder", "The target is not a folder"));
    }
    Ok(Some(entry))
}

/// The folders from the top level down to `folder` (inclusive); refuses chains deeper than the limit.
async fn ancestors(state: &AppState, conv: &Conv, folder: Option<&EntryRow>) -> Result<Vec<EntryRow>, ApiError> {
    let mut chain = Vec::new();
    let mut next = folder.cloned();
    while let Some(f) = next {
        if chain.len() > MAX_DEPTH {
            return Err(ApiError::Internal(anyhow::anyhow!("folder chain of {} is too deep or cyclic", f.id)));
        }
        next = match &f.parent_id {
            Some(pid) => store::files::entry(&state.db, &conv.id, pid).await?,
            None => None,
        };
        chain.push(f);
    }
    chain.reverse();
    Ok(chain)
}

/// The entry and everything below it (breadth first), bounded by depth and the channel's entry limit.
async fn subtree(state: &AppState, conv: &Conv, root: &EntryRow) -> Result<Vec<EntryRow>, ApiError> {
    let mut all = vec![root.clone()];
    let mut level: Vec<String> = if root.is_folder() { vec![root.id.clone()] } else { Vec::new() };
    let mut depth = 0;
    while !level.is_empty() {
        depth += 1;
        if depth > MAX_DEPTH + 1 || all.len() as i64 > MAX_ENTRIES_PER_CHANNEL {
            return Err(ApiError::Internal(anyhow::anyhow!("subtree of {} exceeds the limits", root.id)));
        }
        let children = store::files::children_of(&state.db, &conv.id, &level).await?;
        level = children.iter().filter(|c| c.is_folder()).map(|c| c.id.clone()).collect();
        all.extend(children);
    }
    Ok(all)
}

/// Levels of folders in a subtree (1 for a folder without subfolders, 0 for a file).
fn folder_height(root: &EntryRow, all: &[EntryRow]) -> usize {
    if !root.is_folder() {
        return 0;
    }
    let mut height = 0;
    let mut level = vec![root.id.as_str()];
    while !level.is_empty() {
        height += 1;
        level = all
            .iter()
            .filter(|e| e.is_folder() && e.parent_id.as_deref().is_some_and(|p| level.contains(&p)))
            .map(|e| e.id.as_str())
            .collect();
    }
    height
}

/// Own entries need `attach_files`, entries of others `manage_files`.
fn require_modify(conv: &Conv, user_id: &str, entries: &[&EntryRow]) -> Result<(), ApiError> {
    let others = entries.iter().any(|e| e.created_by.as_deref() != Some(user_id));
    if others {
        conv.require(p::MANAGE_FILES, "files.manage_forbidden", "manage files")
    } else {
        conv.require(p::ATTACH_FILES, "files.manage_forbidden", "attach files")
    }
}

/// Tells open browsers that a folder changed (`files.update`).
fn changed(state: &AppState, conv: &Conv, parents: &[Option<&str>]) {
    let room_id = &room_of(conv).id;
    let mut seen = HashSet::new();
    for p in parents {
        if seen.insert(*p) {
            state.hub.room(
                room_id,
                "files.update",
                serde_json::json!({ "room_id": room_id, "channel_id": conv.id, "parent_id": p }),
            );
        }
    }
}

/// Where a channel keeps its bytes.
pub enum Storage {
    Internal,
    Remote { store: Box<RemoteStore>, encrypt: bool },
}

fn external_disabled() -> ApiError {
    ApiError::Forbidden {
        code: "files.external_disabled",
        detail: "External storage is switched off on this node (TAVRN_FILES_EXTERNAL)".into(),
    }
}

fn internal_disabled() -> ApiError {
    ApiError::Forbidden {
        code: "files.internal_disabled",
        detail: "This node keeps no files of files channels: choose an external store first (TAVRN_FILES_INTERNAL)"
            .into(),
    }
}

/// The kind of the channel's store as clients see it: `internal`, `webdav`, `s3`, or `none` on a node without
/// internal storage (`TAVRN_FILES_INTERNAL=off`) while the channel has no external store (FILES.md §5).
fn backend_kind(state: &AppState, row: Option<&store::files::BackendRow>) -> String {
    match row.filter(|r| r.kind != "internal") {
        Some(r) => r.kind.clone(),
        None if !state.config.files_internal.on() => "none".into(),
        None => "internal".into(),
    }
}

/// New entries (uploads, folders) need a store: on a node without internal storage, an external one.
async fn require_store(state: &AppState, channel_id: &str) -> Result<(), ApiError> {
    if state.config.files_internal.on() {
        return Ok(());
    }
    match store::files::backend(&state.db, channel_id).await? {
        Some(row) if row.kind != "internal" => Ok(()),
        _ => Err(internal_disabled()),
    }
}

/// The channel's limit in bytes (`None` = unlimited, FILES.md §4/§5): an external store's own `max_bytes`, set by the
/// channel's managers; the node quota `files_channels.max_bytes` (entitlements) only for the node's own storage.
fn channel_quota(ent: &Entitlements, storage: &Storage) -> Option<i64> {
    match storage {
        Storage::Remote { store, .. } => {
            Some(i64::try_from(store.config().max_bytes).unwrap_or(i64::MAX)).filter(|q| *q > 0)
        }
        Storage::Internal => ent.limit(entitlements::FILES_CHANNELS_MAX_BYTES),
    }
}

/// The channel's storage (no backend row: internal). External stores need `TAVRN_FILES_EXTERNAL=on`.
pub async fn storage_of(state: &AppState, channel_id: &str) -> Result<Storage, ApiError> {
    let Some(row) = store::files::backend(&state.db, channel_id).await? else { return Ok(Storage::Internal) };
    let kind = Kind::parse(&row.kind).unwrap_or(Kind::Internal);
    if kind == Kind::Internal {
        return Ok(Storage::Internal);
    }
    if !state.config.files_external.on() {
        return Err(external_disabled());
    }
    let config = files::open_config(state, channel_id, &row.config)?;
    Ok(Storage::Remote {
        store: Box::new(RemoteStore::new(kind, config, state.config.files_external_private.on())),
        encrypt: row.encrypt_files != 0,
    })
}

/// The sealed configuration of a channel's external store, read before its rows go.
#[derive(Clone)]
pub struct StoreRef {
    kind: String,
    config: String,
}

/// The external stores of `channels` (channels without one are left out).
async fn stores_of(state: &AppState, channels: &[String]) -> Result<HashMap<String, StoreRef>, ApiError> {
    let mut out = HashMap::new();
    for c in channels {
        if let Some(row) = store::files::backend(&state.db, c).await?
            && row.kind != "internal"
        {
            out.insert(c.clone(), StoreRef { kind: row.kind, config: row.config });
        }
    }
    Ok(out)
}

/// Removes the bytes of deleted entries: internal files and thumbnails now; external objects go through the queue
/// of pending deletes (FILES.md §6), except those of the channels in `keep` (§9). Returns the objects kept.
async fn remove_bytes(
    state: &AppState,
    entries: Vec<EntryRow>,
    stores: &HashMap<String, StoreRef>,
    keep: &HashSet<String>,
) -> u64 {
    let mut remote: HashMap<String, Vec<String>> = HashMap::new();
    let mut kept = 0;
    for e in entries {
        if let Some(tid) = e.thumbnail_id.as_deref().filter(|s| util::is_ulid(s)) {
            state.storage.delete(tid).await;
        }
        if e.is_folder() {
            continue;
        }
        if let Some(sid) = e.storage_id.as_deref().filter(|s| util::is_ulid(s)) {
            state.storage.delete(sid).await;
        } else if e.backend != "internal" {
            if keep.contains(&e.channel_id) {
                kept += 1;
                continue;
            }
            if e.encrypted != 0 {
                // Without its key the wrapped object is unreadable at once, whenever the store deletes it.
                state.storage.delete_key(&e.id).await;
            }
            remote.entry(e.channel_id.clone()).or_default().push(e.id);
        }
    }
    for (channel, keys) in remote {
        let Some(store_ref) = stores.get(&channel) else {
            tracing::warn!(channel = %channel, objects = keys.len(), "external objects not deleted (no store configuration)");
            continue;
        };
        match store::files::enqueue_deletes(&state.db, &channel, &store_ref.kind, &store_ref.config, &keys).await {
            Ok(ids) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_pending_deletes(&state, Some(&ids), chrono::Utc::now()).await {
                        tracing::warn!(error = %e, "external objects not deleted yet (retried by housekeeping)");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, channel = %channel, "external deletes could not be queued"),
        }
    }
    kept
}

/// What a run of the queue of pending external deletes did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PendingReport {
    pub deleted: u64,
    pub failed: u64,
    /// Objects older than [`PENDING_GIVE_UP_DAYS`] that were dropped from the queue (logged).
    pub given_up: u64,
}

/// Queued deletes older than this are given up.
pub const PENDING_GIVE_UP_DAYS: i64 = 7;
const PENDING_BATCH: i64 = 500;

/// Deletes queued external objects (FILES.md §6): the given queue ids, or every entry due at `now` (housekeeping).
/// A failure is retried after 1, 2, 4 … (at most 24) hours; entries older than 7 days are given up. Paused while
/// `TAVRN_FILES_EXTERNAL=off`.
pub async fn run_pending_deletes(
    state: &AppState,
    ids: Option<&[String]>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PendingReport, ApiError> {
    let mut report = PendingReport::default();
    if !state.config.files_external.on() {
        return Ok(report);
    }
    let now_s = util::format_time(now);
    let give_up_before = util::format_time(now - chrono::Duration::days(PENDING_GIVE_UP_DAYS));
    loop {
        let rows = store::files::pending_deletes(&state.db, &now_s, ids, PENDING_BATCH).await?;
        let count = rows.len() as i64;
        let mut stores: HashMap<(String, String), Option<Arc<RemoteStore>>> = HashMap::new();
        let mut work = Vec::new();
        for row in rows {
            if row.created_at < give_up_before {
                tracing::warn!(object = %row.object_key, channel = %row.channel_id, "external object given up after 7 days");
                store::files::delete_pending(&state.db, &row.id).await?;
                report.given_up += 1;
                continue;
            }
            let store = stores
                .entry((row.channel_id.clone(), row.config.clone()))
                .or_insert_with(|| {
                    let kind = Kind::parse(&row.kind).filter(|k| *k != Kind::Internal)?;
                    let config = files::open_config(state, &row.channel_id, &row.config).ok()?;
                    Some(Arc::new(RemoteStore::new(kind, config, state.config.files_external_private.on())))
                })
                .clone();
            work.push((row, store));
        }
        let results: Vec<(store::files::PendingDelete, bool)> = futures::stream::iter(work)
            .map(|(row, store)| async move {
                let ok = match store {
                    Some(store) => store.delete(&row.object_key).await.is_ok(),
                    None => false,
                };
                (row, ok)
            })
            .buffer_unordered(4)
            .collect()
            .await;
        for (row, ok) in results {
            if ok {
                store::files::delete_pending(&state.db, &row.id).await?;
                report.deleted += 1;
            } else {
                let attempts = row.attempts + 1;
                let hours = 1i64 << (attempts - 1).clamp(0, 5);
                let next = util::format_time(now + chrono::Duration::hours(hours.min(24)));
                store::files::pending_failed(&state.db, &row.id, attempts, &next).await?;
                report.failed += 1;
            }
        }
        if ids.is_some() || count < PENDING_BATCH {
            break;
        }
    }
    Ok(report)
}

/// What deleting a channel or a room must remove besides its rows: collected before the delete.
pub struct Cleanup {
    entries: Vec<EntryRow>,
    stores: HashMap<String, StoreRef>,
    keep: HashSet<String>,
}

impl Cleanup {
    /// Collects the stored entries of a channel (`channel_id`) or a room (`room_id`) and the configurations of
    /// their external stores. `keep_external`: the objects of unencrypted external channels stay (FILES.md §9).
    pub async fn collect(state: &AppState, column: &str, id: &str, keep_external: bool) -> Result<Self, ApiError> {
        let entries = store::files::stored_of(&state.db, column, id).await?;
        let mut channels: Vec<String> =
            entries.iter().filter(|e| e.backend != "internal").map(|e| e.channel_id.clone()).collect();
        channels.sort();
        channels.dedup();
        let stores = stores_of(state, &channels).await?;
        let mut keep = HashSet::new();
        if keep_external {
            for c in &channels {
                if !store::files::channel_encrypted(&state.db, c).await? {
                    keep.insert(c.clone());
                }
            }
        }
        Ok(Self { entries, stores, keep })
    }

    /// External objects that will be kept.
    pub fn kept_objects(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| !e.is_folder() && e.backend != "internal" && self.keep.contains(&e.channel_id))
            .count() as u64
    }

    /// Deletes the bytes (after the rows are gone).
    pub async fn run(self, state: &AppState) {
        remove_bytes(state, self.entries, &self.stores, &self.keep).await;
    }
}

/// Backend changes and connection tests per user (`files-backend:<user id>`, 20 per 10 minutes).
fn backend_limiter() -> &'static RateLimiter {
    static L: OnceLock<RateLimiter> = OnceLock::new();
    L.get_or_init(|| RateLimiter::new(20, Duration::from_secs(600)))
}

// ---------------------------------------------------------------- Listing

#[derive(Deserialize, IntoParams)]
pub struct ListQuery {
    /// Folder to list (absent: top level).
    pub parent: Option<String>,
    /// Search by name across the whole channel (case-insensitive substring; `parent` is ignored).
    pub q: Option<String>,
    /// 1–200, default 100.
    pub limit: Option<i64>,
    /// Cursor: the last entry id of the previous page.
    pub after: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Crumb {
    pub id: String,
    /// Empty in encrypted channels (the name is in the folder's record).
    pub name: String,
    /// Encrypted channels: the folder's record as in [`FileEntry`] (absent elsewhere).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_epoch: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_device_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct FileList {
    /// Folders first, then files, by name.
    pub entries: Vec<FileEntry>,
    /// Cursor of the next page (`after`), `null` on the last one.
    pub next_after: Option<String>,
    /// The listed folder and its ancestors, top level first (empty for the top level and for searches).
    pub path: Vec<Crumb>,
}

/// Entries of a folder, or a name search across the channel (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ListQuery),
    responses((status = 200, body = FileList), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Json<FileList>, ApiError> {
    state.files_limiter.check_all(&[format!("files:{}", auth.user.id)])?;
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let limit = validate::limit(q.limit, files::LIST_DEFAULT, files::LIST_MAX);
    if conv.encrypted && q.q.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return Err(bad("files.search_unavailable", "Search runs on the clients in end-to-end encrypted channels"));
    }
    let cut = record_cut(&conv);
    let after = match q.after.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => Some(entry_in(&state, &conv, a).await.map_err(|_| bad("files.cursor_invalid", "Unknown cursor"))?),
        None => None,
    };
    let (rows, path) = match q.q.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(term) => {
            let pattern = files::search_pattern(term)?;
            (store::files::search(&state.db, &conv.id, &pattern, after.as_ref(), limit + 1).await?, Vec::new())
        }
        None => {
            let folder = folder_in(&state, &conv, q.parent.as_deref()).await?;
            let path = ancestors(&state, &conv, folder.as_ref()).await?;
            let rows = store::files::list(
                &state.db,
                &conv.id,
                folder.as_ref().map(|f| f.id.as_str()),
                after.as_ref(),
                limit + 1,
            )
            .await?;
            (rows, path)
        }
    };
    let more = rows.len() as i64 > limit;
    let entries: Vec<FileEntry> = rows.iter().take(limit as usize).map(|r| r.to_api_cut(cut.as_deref())).collect();
    Ok(Json(FileList {
        next_after: if more { entries.last().map(|e| e.id.clone()) } else { None },
        entries,
        path: crumbs(path, cut.as_deref()),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct FileEntryDetail {
    pub entry: FileEntry,
    /// The entry's folder chain, top level first (the entry itself last).
    pub path: Vec<Crumb>,
}

/// One entry with its location (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)),
    responses((status = 200, body = FileEntryDetail), (status = 404, body = ProblemDetails)))]
pub async fn get_entry(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
) -> Result<Json<FileEntryDetail>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let entry = entry_in(&state, &conv, &entry_id).await?;
    let path = ancestors(&state, &conv, Some(&entry)).await?;
    let cut = record_cut(&conv);
    Ok(Json(FileEntryDetail { entry: entry.to_api_cut(cut.as_deref()), path: crumbs(path, cut.as_deref()) }))
}

// ---------------------------------------------------------------- Folders

#[derive(Deserialize, ToSchema)]
pub struct CreateFolderRequest {
    /// Parent folder (`null` or absent: top level).
    pub parent_id: Option<String>,
    /// Unencrypted channels: the name (refused in encrypted channels).
    pub name: Option<String>,
    /// Encrypted channels: the client-chosen id (a fresh ULID), the entry record and its epoch (FILES.md §8.5).
    pub id: Option<String>,
    pub record: Option<String>,
    pub record_epoch: Option<i64>,
}

/// Creates a folder (`attach_files`); 409 `files.name_taken` when the name exists in the parent.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/folders", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = CreateFolderRequest,
    responses((status = 201, body = FileEntry), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn create_folder(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Json(req): Json<CreateFolderRequest>,
) -> Result<(StatusCode, Json<FileEntry>), ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    conv.require(p::ATTACH_FILES, "files.upload_forbidden", "attach files")?;
    if !enabled_for(&state, room_of(&conv)).await? {
        return Err(disabled());
    }
    require_store(&state, &conv.id).await?;
    let author = auth.user.address();
    let (id, name, record) = if conv.encrypted {
        if req.name.is_some() {
            return Err(encrypted_names());
        }
        let id = files::client_id(req.id.as_deref(), now_ms())?;
        let record = check_record(&state, &auth, &author, &conv, req.record.as_deref(), req.record_epoch).await?;
        (id, String::new(), Some(record))
    } else {
        if req.id.is_some() || req.record.is_some() {
            return Err(not_encrypted());
        }
        (store::files::new_id(), files::entry_name(req.name.as_deref().unwrap_or(""))?, None)
    };
    let parent = folder_in(&state, &conv, req.parent_id.as_deref()).await?;
    if ancestors(&state, &conv, parent.as_ref()).await?.len() >= MAX_DEPTH {
        return Err(bad("files.too_deep", format!("Folders nest at most {MAX_DEPTH} levels deep")));
    }
    check_entry_count(&state, &conv).await?;
    let row = store::files::insert(
        &state.db,
        store::files::NewEntry {
            id: &id,
            room_id: &room_of(&conv).id,
            channel_id: &conv.id,
            parent_id: parent.as_ref().map(|p| p.id.as_str()),
            kind: "folder",
            name: &name,
            storage_id: None,
            backend: "internal",
            encrypted: false,
            mime: "",
            size: 0,
            sha256: "",
            created_by: &auth.user.id,
            record,
        },
    )
    .await?
    .ok_or_else(|| if conv.encrypted { id_taken() } else { name_taken(&name) })?;
    changed(&state, &conv, &[row.parent_id.as_deref()]);
    Ok((StatusCode::CREATED, Json(row.to_api())))
}

fn id_taken() -> ApiError {
    ApiError::conflict("files.id_taken", "An entry with this id exists already")
}

fn now_ms() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

async fn check_entry_count(state: &AppState, conv: &Conv) -> Result<(), ApiError> {
    let (_, files_n, folders_n) = store::files::usage(&state.db, &conv.id).await?;
    if files_n + folders_n >= MAX_ENTRIES_PER_CHANNEL {
        return Err(bad(
            "files.too_many_entries",
            format!("A files channel holds at most {MAX_ENTRIES_PER_CHANNEL} entries"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- Upload

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn too_large(max: u64) -> ApiError {
    ApiError::PayloadTooLarge {
        code: "upload.too_large",
        detail: format!("At most {} MB per file", max / 1024 / 1024),
        meta: serde_json::json!({ "max_bytes": max }),
    }
}

fn quota_exceeded(limit: i64, used: i64) -> ApiError {
    ApiError::PayloadTooLarge {
        code: "files.quota_exceeded",
        detail: "The storage of this files channel is full".into(),
        meta: serde_json::json!({ "limit_bytes": limit, "used_bytes": used }),
    }
}

/// Upload a file (`attach_files`). The body is the raw file (streamed, never held in memory as a whole); name
/// in `Tavrn-File-Name` (UTF-8, percent-encoded), folder in `Tavrn-Parent` (absent or empty: top level),
/// type in `Content-Type`; `Tavrn-Conflict: rename` stores a taken name as `name (2).ext` instead of 409.
/// Limits: the uploader's `upload.max_bytes` and the channel's `files_channels.max_bytes`; upload categories
/// and the executable rule as for attachments. External stores need `Content-Length`.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/upload", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 201, body = FileEntry), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn upload(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<FileEntry>), ApiError> {
    if !state.config.uploads_enabled {
        return Err(ApiError::Forbidden {
            code: "upload.disabled",
            detail: "Uploads are switched off on this node".into(),
        });
    }
    state.files_limiter.check_all(&[format!("files-upload:{}", auth.user.id)])?;
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    conv.require(p::ATTACH_FILES, "files.upload_forbidden", "attach files")?;
    let room = room_of(&conv).clone();
    let ent = Entitlements::load(&state, Some(&auth.user), Some(&room)).await?;
    if ent.get(entitlements::FILES_CHANNELS_ENABLED) == 0 {
        return Err(disabled());
    }
    require_store(&state, &conv.id).await?;
    let max = ent.upload_max_bytes(&state.config);
    let storage = storage_of(&state, &conv.id).await?;
    let quota = channel_quota(&ent, &storage);

    let author = auth.user.address();
    // Encrypted channels: client-chosen id, the record instead of a name, the category as declared (FILES.md §8.5).
    let mut e2ee = None;
    if conv.encrypted {
        if headers.contains_key("tavrn-file-name") || headers.contains_key("tavrn-conflict") {
            return Err(encrypted_names());
        }
        let id = files::client_id(header_str(&headers, "tavrn-entry-id"), now_ms())?;
        let epoch = header_str(&headers, "tavrn-record-epoch").and_then(|v| v.trim().parse::<i64>().ok());
        let record = check_record(&state, &auth, &author, &conv, header_str(&headers, "tavrn-record"), epoch).await?;
        let class = crate::uploads::declared(header_str(&headers, "tavrn-upload-category")).ok_or_else(|| {
            bad(
                "upload.category_invalid",
                "Tavrn-Upload-Category: images, audio, video, documents, archives, other or executable",
            )
        })?;
        if store::files::id_exists(&state.db, &id).await? {
            return Err(id_taken());
        }
        e2ee = Some((id, record, class));
    }
    let parent = folder_in(&state, &conv, header_str(&headers, "tavrn-parent")).await?;
    let parent_id = parent.as_ref().map(|p| p.id.clone());
    let mut name = String::new();
    if e2ee.is_none() {
        let raw_name = header_str(&headers, "tavrn-file-name")
            .map(crate::routes::attachments::percent_decode)
            .ok_or_else(|| bad("files.name_invalid", "Tavrn-File-Name is missing"))?;
        name = files::entry_name(&raw_name)?;
    }
    let rename = header_str(&headers, "tavrn-conflict").is_some_and(|v| v.eq_ignore_ascii_case("rename"));
    if e2ee.is_none() && store::files::name_taken(&state.db, &conv.id, parent_id.as_deref(), &name).await? {
        if !rename {
            return Err(name_taken(&name));
        }
        let mut found = None;
        for n in 2..=100 {
            let candidate = files::numbered(&name, n);
            if candidate.chars().count() <= files::MAX_NAME
                && !store::files::name_taken(&state.db, &conv.id, parent_id.as_deref(), &candidate).await?
            {
                found = Some(candidate);
                break;
            }
        }
        name = found.ok_or_else(|| name_taken(&name))?;
    }
    check_entry_count(&state, &conv).await?;

    let (used, _, _) = store::files::usage(&state.db, &conv.id).await?;
    let declared = header_str(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max) {
        return Err(too_large(max));
    }
    let remaining = quota.map(|q| u64::try_from(q.saturating_sub(used)).unwrap_or(0));
    if let (Some(q), Some(left)) = (quota, remaining)
        && declared.unwrap_or(1) > left
    {
        return Err(quota_exceeded(q, used));
    }
    let limit = remaining.map_or(max, |r| r.min(max));
    if matches!(storage, Storage::Remote { .. }) && declared.is_none() {
        return Err(bad("files.length_required", "Uploads to an external store need a Content-Length"));
    }

    // The body as a stream; client errors (aborted uploads) are remembered.
    let client_failed = Arc::new(AtomicBool::new(false));
    let flag = client_failed.clone();
    let body: ByteStream = Box::pin(body.into_data_stream().map_err(move |e| {
        flag.store(true, Ordering::Relaxed);
        std::io::Error::other(e)
    }));
    let (stream, meter) = files::metered(body, limit);
    let (id, mime, stream, record) = match e2ee {
        Some((id, record, class)) => {
            crate::routes::attachments::check_category(&state, &conv, &auth.user.id, class).await?;
            (id, String::new(), stream, Some(record))
        }
        None => {
            let (head, stream) = files::read_head(stream, files::SNIFF_BYTES)
                .await
                .map_err(|_| upload_error(&meter, &client_failed, max, quota, used))?;
            let mime = files::upload_mime(header_str(&headers, "content-type"), &name, &head);
            let class = crate::uploads::classify(&head, &name, &mime);
            crate::routes::attachments::check_category(&state, &conv, &auth.user.id, class).await?;
            (store::files::new_id(), mime, stream, None)
        }
    };
    // Client-chosen ids never name a stored file: the node picks the storage id (they share one namespace).
    let internal_id = if record.is_some() { store::files::new_id() } else { id.clone() };
    let (storage_id, backend, encrypted) = match &storage {
        Storage::Internal => {
            if let Err(e) = state.storage.write_stream(&internal_id, stream).await {
                let err = upload_error(&meter, &client_failed, max, quota, used);
                if matches!(err, ApiError::Internal(_)) {
                    return Err(ApiError::Internal(e));
                }
                return Err(err);
            }
            (Some(internal_id.clone()), "internal", false)
        }
        Storage::Remote { store, encrypt } => {
            let plain_len = declared.unwrap_or(0);
            // End-to-end encrypted channels store the clients' ciphertext as it is.
            let encrypt = &(*encrypt && record.is_none());
            let (body, len) = if *encrypt {
                let key = state.storage.new_external_key(&id).await.map_err(ApiError::Internal)?;
                (files::sealed(stream, key), crate::storage::encrypted_len(plain_len))
            } else {
                (stream, plain_len)
            };
            let result = store.put(&id, reqwest::Body::wrap_stream(body), len).await;
            let complete = meter.lock().is_ok_and(|m| m.len == plain_len && !m.exceeded);
            if result.is_err() || !complete {
                if *encrypt {
                    state.storage.delete_key(&id).await;
                }
                let _ = store.delete(&id).await;
                let err = upload_error(&meter, &client_failed, max, quota, used);
                return Err(match (result, err) {
                    (_, e @ (ApiError::PayloadTooLarge { .. } | ApiError::BadRequest { .. })) => e,
                    (Err(remote), _) => remote.into_api(),
                    (Ok(()), e) => e,
                });
            }
            (None, store.kind().as_str(), *encrypt)
        }
    };
    let (size, sha256) = {
        let m = meter.lock().map_err(|_| ApiError::Internal(anyhow::anyhow!("meter poisoned")))?;
        (m.len as i64, m.sha256())
    };
    let is_e2ee = record.is_some();
    let inserted = store::files::insert(
        &state.db,
        store::files::NewEntry {
            id: &id,
            room_id: &room.id,
            channel_id: &conv.id,
            parent_id: parent_id.as_deref(),
            kind: "file",
            name: &name,
            storage_id: storage_id.as_deref(),
            backend,
            encrypted,
            mime: &mime,
            size,
            sha256: &sha256,
            created_by: &auth.user.id,
            record,
        },
    )
    .await;
    let row = match inserted {
        Ok(Some(row)) => row,
        other => {
            // Name or id taken meanwhile (or a database error): the stored bytes go again, unless an entry that
            // took the same client-chosen id owns the external object of that id.
            let owned_elsewhere =
                is_e2ee && storage_id.is_none() && store::files::id_exists(&state.db, &id).await.unwrap_or(true);
            let ghost = EntryRow {
                id: id.clone(),
                room_id: room.id.clone(),
                channel_id: conv.id.clone(),
                parent_id: None,
                kind: "file".into(),
                name: name.clone(),
                name_key: String::new(),
                storage_id,
                backend: backend.into(),
                encrypted: i64::from(encrypted),
                mime,
                size,
                sha256,
                created_by: None,
                created_at: String::new(),
                updated_at: String::new(),
                record: None,
                record_epoch: None,
                record_author: None,
                record_device_id: None,
                record_at: None,
                thumbnail_id: None,
                thumbnail_size: 0,
            };
            if !owned_elsewhere {
                let stores = stores_of(&state, std::slice::from_ref(&conv.id)).await.unwrap_or_default();
                remove_bytes(&state, vec![ghost], &stores, &HashSet::new()).await;
            }
            return Err(match other {
                Err(e) => e,
                _ if is_e2ee => id_taken(),
                _ => name_taken(&name),
            });
        }
    };
    changed(&state, &conv, &[row.parent_id.as_deref()]);
    Ok((StatusCode::CREATED, Json(row.to_api())))
}

/// The error of a failed upload stream: too large, quota, aborted by the client, or internal.
fn upload_error(
    meter: &Arc<std::sync::Mutex<files::Meter>>,
    client_failed: &AtomicBool,
    max: u64,
    quota: Option<i64>,
    used: i64,
) -> ApiError {
    let exceeded = meter.lock().is_ok_and(|m| m.exceeded);
    if exceeded {
        let len = meter.lock().map(|m| m.len).unwrap_or(0);
        return match quota {
            Some(q) if len <= max => quota_exceeded(q, used),
            _ => too_large(max),
        };
    }
    if client_failed.load(Ordering::Relaxed) {
        return bad("upload.aborted", "The upload was interrupted");
    }
    ApiError::Internal(anyhow::anyhow!("upload failed"))
}

// ---------------------------------------------------------------- Download

fn range_not_satisfiable(len: u64) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    if let Ok(v) = HeaderValue::from_str(&format!("bytes */{len}")) {
        resp.headers_mut().insert(header::CONTENT_RANGE, v);
    }
    resp
}

fn disposition(name: &str) -> HeaderValue {
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' })
        .filter(|c| !matches!(c, '"' | '\\'))
        .collect();
    let encoded = crate::files::sigv4::uri_encode(name, false);
    HeaderValue::from_str(&format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}"))
        .unwrap_or(HeaderValue::from_static("attachment"))
}

/// Download a file (`view_channel`): always `Content-Disposition: attachment`, `nosniff` and a sandboxing CSP;
/// only raster images, audio, video, PDF and plain text keep their type. Single byte ranges (`Range`) are
/// answered with 206.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}/download", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)),
    responses((status = 200, description = "File content"), (status = 206, description = "Partial content"), (status = 404, body = ProblemDetails), (status = 416, description = "Range not satisfiable"), (status = 502, body = ProblemDetails)))]
pub async fn download(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let entry = entry_in(&state, &conv, &entry_id).await?;
    if entry.is_folder() {
        return Err(bad("files.is_folder", "Folders cannot be downloaded"));
    }
    let len = u64::try_from(entry.size).unwrap_or(0);
    let range = match files::parse_range(header_str(&headers, "range"), len) {
        Some(Err(())) => return Ok(range_not_satisfiable(len)),
        Some(Ok(r)) => Some(r),
        None => None,
    };
    let (start, end) = range.unwrap_or((0, len.saturating_sub(1)));
    let take = if len == 0 { 0 } else { end - start + 1 };
    let stream: ByteStream = match (&entry.storage_id, entry.backend.as_str()) {
        (Some(sid), "internal") => {
            let (reader, skip) = state
                .storage
                .open_reader_at(sid, start)
                .await
                .map_err(ApiError::Internal)?
                .ok_or_else(entry_not_found)?;
            files::sliced(Box::pin(reader.into_stream()), skip, take)
        }
        _ => {
            let Storage::Remote { store, .. } = storage_of(&state, &conv.id).await? else {
                return Err(entry_not_found());
            };
            if store.kind().as_str() != entry.backend {
                return Err(entry_not_found());
            }
            if len == 0 {
                Box::pin(futures::stream::empty())
            } else if entry.encrypted != 0 {
                let key = state.storage.external_key(&entry.id).await.map_err(ApiError::Internal)?;
                let (first, a, b) = crate::storage::sealed_range(len, start, end);
                let resp = store.get(&entry.id, Some((a, b))).await.map_err(remote::RemoteError::into_api)?;
                let partial = resp.status() == StatusCode::PARTIAL_CONTENT;
                let body: ByteStream = Box::pin(resp.bytes_stream().map_err(std::io::Error::other));
                // A store that ignored the range sends the whole object (from the magic on).
                let (opener, skip) = if partial || a == 0 {
                    (
                        crate::storage::ChunkOpener::new(&key, len, first, a == 0),
                        start - first * crate::storage::CHUNK as u64,
                    )
                } else {
                    (crate::storage::ChunkOpener::new(&key, len, 0, true), start)
                };
                files::sliced(files::opened(body, opener), skip, take)
            } else {
                let resp = store.get(&entry.id, Some((start, end))).await.map_err(remote::RemoteError::into_api)?;
                let skip = if resp.status() == StatusCode::PARTIAL_CONTENT { 0 } else { start };
                files::sliced(Box::pin(resp.bytes_stream().map_err(std::io::Error::other)), skip, take)
            }
        }
    };
    let mut resp = Response::new(Body::from_stream(stream));
    if range.is_some() {
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        if let Ok(v) = HeaderValue::from_str(&format!("bytes {start}-{end}/{len}")) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    let h = resp.headers_mut();
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(take));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(files::served_mime(&entry.mime))
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // Encrypted entries have no name on the node: the download is named by its id.
    h.insert(header::CONTENT_DISPOSITION, disposition(if entry.record.is_some() { &entry.id } else { &entry.name }));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{}\"", entry.sha256)) {
        h.insert(header::ETAG, v);
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}

// ---------------------------------------------------------------- Rename, move, delete

#[derive(Deserialize, ToSchema)]
pub struct UpdateEntryRequest {
    /// New name (unencrypted channels).
    pub name: Option<String>,
    /// Encrypted channels: a new entry record (rename) and its epoch (FILES.md §8.5).
    pub record: Option<String>,
    pub record_epoch: Option<i64>,
    /// New folder (`null`: top level; absent: unchanged).
    #[serde(default, with = "crate::serde_with_double_option")]
    #[schema(value_type = Option<String>)]
    pub parent_id: Option<Option<String>>,
}

/// Rename and/or move an entry (own: `attach_files`; others': `manage_files`). Moving a folder into itself or
/// one of its subfolders is refused (`files.move_into_self`), as is nesting deeper than 32 levels.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)), request_body = UpdateEntryRequest,
    responses((status = 200, body = FileEntry), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
    Json(req): Json<UpdateEntryRequest>,
) -> Result<Json<FileEntry>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let entry = entry_in(&state, &conv, &entry_id).await?;
    require_modify(&conv, &auth.user.id, &[&entry])?;
    let author = auth.user.address();
    let record = if conv.encrypted {
        if req.name.is_some() {
            return Err(encrypted_names());
        }
        match req.record.as_deref() {
            Some(r) => Some(check_record(&state, &auth, &author, &conv, Some(r), req.record_epoch).await?),
            None => None,
        }
    } else {
        if req.record.is_some() {
            return Err(not_encrypted());
        }
        None
    };
    let name = match &req.name {
        Some(n) => files::entry_name(n)?,
        None => entry.name.clone(),
    };
    let parent_id = match &req.parent_id {
        None => entry.parent_id.clone(),
        Some(target) => {
            let folder = folder_in(&state, &conv, target.as_deref()).await?;
            let chain = ancestors(&state, &conv, folder.as_ref()).await?;
            if chain.iter().any(|f| f.id == entry.id) {
                return Err(bad("files.move_into_self", "A folder cannot be moved into itself or its subfolders"));
            }
            if entry.is_folder() {
                let tree = subtree(&state, &conv, &entry).await?;
                if chain.len() + folder_height(&entry, &tree) > MAX_DEPTH {
                    return Err(bad("files.too_deep", format!("Folders nest at most {MAX_DEPTH} levels deep")));
                }
            }
            folder.map(|f| f.id)
        }
    };
    if record.is_none() && name == entry.name && parent_id == entry.parent_id {
        return Ok(Json(entry.to_api_cut(record_cut(&conv).as_deref())));
    }
    if conv.encrypted {
        store::files::update_encrypted(&state.db, &entry.id, record, parent_id.as_deref()).await?;
    } else if !store::files::update(&state.db, &entry.id, &name, parent_id.as_deref()).await? {
        return Err(name_taken(&name));
    }
    let fresh = store::files::entry(&state.db, &conv.id, &entry.id).await?.ok_or_else(entry_not_found)?;
    changed(&state, &conv, &[entry.parent_id.as_deref(), fresh.parent_id.as_deref()]);
    Ok(Json(fresh.to_api_cut(record_cut(&conv).as_deref())))
}

#[derive(Serialize, ToSchema)]
pub struct DeleteResult {
    /// Files deleted (including those inside deleted folders).
    pub files: u64,
    /// Folders deleted.
    pub folders: u64,
    /// Bytes freed.
    pub bytes: u64,
}

/// Delete an entry; folders with everything inside (own entries: `attach_files`; as soon as one entry of
/// someone else is involved: `manage_files`). Permanent; recorded in the audit log.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)),
    responses((status = 200, body = DeleteResult), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
) -> Result<Json<DeleteResult>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let entry = entry_in(&state, &conv, &entry_id).await?;
    require_modify(&conv, &auth.user.id, &[&entry])?;
    let tree = subtree(&state, &conv, &entry).await?;
    require_modify(&conv, &auth.user.id, &tree.iter().collect::<Vec<_>>())?;
    let result = DeleteResult {
        files: tree.iter().filter(|e| !e.is_folder()).count() as u64,
        folders: tree.iter().filter(|e| e.is_folder()).count() as u64,
        bytes: tree.iter().map(|e| u64::try_from(e.stored_bytes()).unwrap_or(0)).sum(),
    };
    let needs_remote = tree.iter().any(|e| !e.is_folder() && e.backend != "internal");
    let stores = if needs_remote { stores_of(&state, std::slice::from_ref(&conv.id)).await? } else { HashMap::new() };
    // Deepest entries first, so that no parent row disappears before its children.
    let ids: Vec<String> = tree.iter().rev().map(|e| e.id.clone()).collect();
    store::files::delete_ids(&state.db, &ids).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_of(&conv).id),
        Some(&auth.user.id),
        "files.delete",
        &entry.id,
        "",
        serde_json::json!({
            "channel_id": conv.id, "name": entry.name, "kind": entry.kind,
            "files": result.files, "folders": result.folders, "bytes": result.bytes,
        }),
    )
    .await?;
    remove_bytes(&state, tree, &stores, &HashSet::new()).await;
    changed(&state, &conv, &[entry.parent_id.as_deref()]);
    Ok(Json(result))
}

// ---------------------------------------------------------------- Usage

#[derive(Serialize, ToSchema)]
pub struct FilesInfo {
    /// Files channels are available for this room (`files_channels.enabled`).
    pub enabled: bool,
    pub used_bytes: i64,
    /// The channel's limit (0 = unlimited): on the node's storage `files_channels.max_bytes` of the room, on an
    /// external store the store's own `max_bytes` (FILES.md §4/§5).
    pub limit_bytes: i64,
    pub files: i64,
    pub folders: i64,
    /// Largest upload for the requester.
    pub max_upload_bytes: u64,
    /// `internal`, `webdav` or `s3`; `none` on a node without internal storage (`TAVRN_FILES_INTERNAL=off`) while
    /// the channel has no external store: no uploads or folders until one is set (FILES.md §5).
    pub backend: String,
    /// External store with encryption (files unreadable outside tavrn).
    pub encrypt_files: bool,
    /// The channel is end-to-end encrypted (FILES.md §8).
    pub encrypted: bool,
    /// Members with `manage_channels`: the external store's host (`""` for the node's storage), for the deletion
    /// dialog (FILES.md §9); `null` for everybody else.
    pub backend_host: Option<String>,
    /// Members with `manage_channels`: the object prefix on the external store (`""` for the node's storage).
    pub backend_prefix: Option<String>,
    /// The requester may upload and create folders.
    pub can_upload: bool,
    /// The requester may manage everybody's entries (`manage_files`).
    pub can_manage: bool,
    /// The requester may configure the storage backend.
    pub can_configure: bool,
    /// Upload categories of the requester here.
    pub allowed_categories: Vec<String>,
    pub executables_allowed: bool,
}

/// Storage used and the requester's abilities in a files channel (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/usage", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    responses((status = 200, body = FilesInfo), (status = 403, body = ProblemDetails)))]
pub async fn usage(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<Json<FilesInfo>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let ent = Entitlements::load(&state, Some(&auth.user), Some(room_of(&conv))).await?;
    let enabled = ent.get(entitlements::FILES_CHANNELS_ENABLED) != 0;
    let (used, files_n, folders_n) = store::files::usage(&state.db, &conv.id).await?;
    let backend = store::files::backend(&state.db, &conv.id).await?;
    let allowed = access::upload_categories(&state, &conv, &auth.user.id).await?;
    let kind = backend_kind(&state, backend.as_ref());
    let can_upload = enabled && state.config.uploads_enabled && p::has(conv.perms, p::ATTACH_FILES) && kind != "none";
    // Where the files are, for those who may delete the channel (never the credentials).
    let location = if p::has(conv.perms, p::MANAGE_CHANNELS) {
        let c = stored_config(&state, &conv.id, backend.as_ref().filter(|b| b.kind != "internal")).unwrap_or_default();
        let host = reqwest::Url::parse(&c.url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
        Some((host, c.prefix))
    } else {
        None
    };
    Ok(Json(FilesInfo {
        enabled,
        used_bytes: used,
        limit_bytes: limit_bytes(&state, &ent, &conv.id, backend.as_ref()),
        files: files_n,
        folders: folders_n,
        max_upload_bytes: ent.upload_max_bytes(&state.config),
        backend: kind,
        encrypt_files: backend.as_ref().is_some_and(|b| b.encrypt_files != 0),
        encrypted: conv.encrypted,
        backend_host: location.as_ref().map(|l| l.0.clone()),
        backend_prefix: location.map(|l| l.1),
        can_upload,
        can_manage: p::has(conv.perms, p::MANAGE_FILES),
        can_configure: p::has(conv.perms, p::MANAGE_CHANNELS | p::MANAGE_FILES),
        allowed_categories: crate::uploads::names(allowed),
        executables_allowed: state.config.upload_allow_executables && allowed & crate::uploads::OTHER != 0,
    }))
}

// ---------------------------------------------------------------- Own entries, records, thumbnails

#[derive(Deserialize, IntoParams)]
pub struct MineQuery {
    /// 1–200, default 100.
    pub limit: Option<i64>,
    /// Cursor: the last entry id of the previous page.
    pub after: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct MineList {
    /// The requester's entries, oldest first, without records.
    pub entries: Vec<FileEntry>,
    pub next_after: Option<String>,
    /// Totals of all the requester's entries in the channel (bytes: files and thumbnails).
    pub files: i64,
    pub folders: i64,
    pub bytes: i64,
}

/// The requester's own entries with ids, kinds, sizes and dates, never records or names (`view_channel`): a member
/// who lost their keys can still find and delete their uploads (FILES.md §8.8).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/mine", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), MineQuery),
    responses((status = 200, body = MineList), (status = 403, body = ProblemDetails)))]
pub async fn mine(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<MineQuery>,
) -> Result<Json<MineList>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let limit = validate::limit(q.limit, files::LIST_DEFAULT, files::LIST_MAX);
    let after = q.after.unwrap_or_default();
    if !after.is_empty() && !util::is_ulid(&after) {
        return Err(bad("files.cursor_invalid", "Unknown cursor"));
    }
    let rows = store::files::mine(&state.db, &conv.id, &auth.user.id, &after, limit + 1).await?;
    let more = rows.len() as i64 > limit;
    let entries: Vec<FileEntry> = rows
        .iter()
        .take(limit as usize)
        .map(|r| {
            let mut e = r.to_api();
            (e.record, e.record_epoch, e.record_author, e.record_device_id) = (None, None, None, None);
            e
        })
        .collect();
    let (files_n, folders_n, bytes) = store::files::mine_totals(&state.db, &conv.id, &auth.user.id).await?;
    Ok(Json(MineList {
        next_after: if more { entries.last().map(|e| e.id.clone()) } else { None },
        entries,
        files: files_n,
        folders: folders_n,
        bytes,
    }))
}

#[derive(Deserialize, IntoParams)]
pub struct RecordsQuery {
    /// Only records of this epoch.
    pub epoch: Option<i64>,
    /// Only records written at or after this time (RFC 3339).
    pub since: Option<String>,
    /// Cursor: the last entry id of the previous page.
    pub after: Option<String>,
    /// 1–200, default 100.
    pub limit: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct RecordList {
    /// Entries with a record inside the requester's history window, oldest record first.
    pub entries: Vec<FileEntry>,
    pub next_after: Option<String>,
}

/// Entry records of an encrypted files channel in the order they were written (`view_channel`), only inside the
/// requester's history window (FILES.md §8.7): for the key checks of history shares and the clients' search sync.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/records", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), RecordsQuery),
    responses((status = 200, body = RecordList), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails)))]
pub async fn records(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<RecordsQuery>,
) -> Result<Json<RecordList>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    if !conv.encrypted {
        return Err(not_encrypted());
    }
    let limit = validate::limit(q.limit, files::LIST_DEFAULT, files::LIST_MAX);
    if q.epoch.is_some_and(|e| e < 0) {
        return Err(bad("validation.range", "epoch must not be negative"));
    }
    let since = match q.since.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(
            util::parse_time(s)
                .map(util::format_time)
                .ok_or_else(|| bad("validation.time", "since must be an RFC 3339 time"))?,
        ),
        None => None,
    };
    let cut = record_cut(&conv);
    let since = match (since, cut) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let after = match q.after.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => {
            let e = entry_in(&state, &conv, a).await.map_err(|_| bad("files.cursor_invalid", "Unknown cursor"))?;
            Some((e.record_at.unwrap_or_default(), e.id))
        }
        None => None,
    };
    let rows = store::files::records(
        &state.db,
        &conv.id,
        store::files::RecordQuery {
            epoch: q.epoch,
            since: since.as_deref(),
            after: after.as_ref().map(|(a, b)| (a.as_str(), b.as_str())),
            limit: limit + 1,
        },
    )
    .await?;
    let more = rows.len() as i64 > limit;
    let entries: Vec<FileEntry> = rows.iter().take(limit as usize).map(EntryRow::to_api).collect();
    Ok(Json(RecordList { next_after: if more { entries.last().map(|e| e.id.clone()) } else { None }, entries }))
}

/// Store the client-made thumbnail of a file in an encrypted channel (own entries `attach_files`, others'
/// `manage_files`): ciphertext of the part `thumbnail` (FILES.md §8.3), at most 1 MiB; replaces an earlier one.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}/thumbnail", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses((status = 204), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails)))]
pub async fn put_thumbnail(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
    body: Body,
) -> Result<StatusCode, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    if !conv.encrypted {
        return Err(not_encrypted());
    }
    let entry = entry_in(&state, &conv, &entry_id).await?;
    if entry.is_folder() {
        return Err(bad("files.is_folder", "Folders have no thumbnail"));
    }
    require_modify(&conv, &auth.user.id, &[&entry])?;
    let too_large = || ApiError::PayloadTooLarge {
        code: "files.thumbnail_too_large",
        detail: "A thumbnail has at most 1 MiB".into(),
        meta: serde_json::json!({ "max_bytes": files::MAX_THUMBNAIL_BYTES }),
    };
    let bytes = axum::body::to_bytes(body, files::MAX_THUMBNAIL_BYTES).await.map_err(|_| too_large())?;
    if bytes.is_empty() {
        return Err(bad("upload.empty", "Empty thumbnail"));
    }
    let size = bytes.len() as i64;
    let ent = Entitlements::load(&state, Some(&auth.user), Some(room_of(&conv))).await?;
    if let Some(quota) = channel_quota(&ent, &storage_of(&state, &conv.id).await?) {
        let (used, _, _) = store::files::usage(&state.db, &conv.id).await?;
        if used.saturating_sub(entry.thumbnail_size).saturating_add(size) > quota {
            return Err(quota_exceeded(quota, used));
        }
    }
    let storage_id = store::files::new_id();
    state.storage.write(&storage_id, &bytes).await.map_err(ApiError::Internal)?;
    match store::files::set_thumbnail(&state.db, &entry.id, &storage_id, size).await {
        Ok(Some(old)) if util::is_ulid(&old) => state.storage.delete(&old).await,
        Ok(_) => {}
        Err(e) => {
            state.storage.delete(&storage_id).await;
            return Err(e);
        }
    }
    changed(&state, &conv, &[entry.parent_id.as_deref()]);
    Ok(StatusCode::NO_CONTENT)
}

/// The thumbnail ciphertext of a file in an encrypted channel (`view_channel`).
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/{entry_id}/thumbnail", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path), ("entry_id" = String, Path)),
    responses((status = 200, description = "Thumbnail ciphertext"), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn get_thumbnail(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id, entry_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    if !conv.encrypted {
        return Err(not_encrypted());
    }
    let entry = entry_in(&state, &conv, &entry_id).await?;
    let missing = || access::not_found("Thumbnail", "files.no_thumbnail");
    let sid = entry.thumbnail_id.as_deref().filter(|s| util::is_ulid(s)).ok_or_else(missing)?;
    let bytes = state.storage.read(sid).await.map_err(ApiError::Internal)?.ok_or_else(missing)?;
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(resp)
}

// ---------------------------------------------------------------- Backend

#[derive(Serialize, ToSchema)]
pub struct BackendInfo {
    /// `internal`, `webdav` or `s3`; `none` while a node without internal storage has no external store for the
    /// channel.
    pub kind: String,
    pub url: String,
    pub username: String,
    /// A WebDAV password is stored (never returned).
    pub password_set: bool,
    pub access_key: String,
    /// An S3 secret key is stored (never returned).
    pub secret_key_set: bool,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub encrypt_files: bool,
    /// External stores: the channel's limit on the store in bytes (0 = unlimited); always 0 for the node's storage.
    pub max_bytes: u64,
    /// External stores are allowed on this node (`TAVRN_FILES_EXTERNAL`).
    pub external_allowed: bool,
    /// The node's own storage may be chosen (`TAVRN_FILES_INTERNAL`); `false`: only external stores.
    pub internal_allowed: bool,
    /// Private addresses and plain http are allowed (`TAVRN_FILES_EXTERNAL_PRIVATE`).
    pub private_allowed: bool,
    /// The channel has files (the store can no longer be switched).
    pub has_files: bool,
    pub updated_at: Option<String>,
}

#[derive(Deserialize, ToSchema, Default)]
pub struct BackendRequest {
    /// `internal`, `webdav` or `s3`.
    pub kind: String,
    /// WebDAV: the base collection URL; S3: the endpoint (path-style, e.g. `https://s3.eu-central-1.amazonaws.com`).
    pub url: Option<String>,
    pub username: Option<String>,
    /// Absent or empty: keep the stored password.
    pub password: Option<String>,
    pub access_key: Option<String>,
    /// Absent or empty: keep the stored secret key.
    pub secret_key: Option<String>,
    pub region: Option<String>,
    pub bucket: Option<String>,
    /// Key prefix inside the store (default `tavrn/<channel id>/`).
    pub prefix: Option<String>,
    /// Wrap files with the storage encryption before they are written (unreadable outside tavrn).
    pub encrypt_files: Option<bool>,
    /// External stores: the channel's limit on the store in bytes (absent or 0 = unlimited, at most 1 PiB). The node
    /// quota never applies to external stores; the node's own storage takes none (`400 files.backend_invalid`).
    pub max_bytes: Option<u64>,
}

async fn backend_access(state: &AppState, room_id: &str, channel_id: &str, auth: &AuthUser) -> Result<Conv, ApiError> {
    let conv = files_channel(state, room_id, channel_id, auth).await?;
    conv.require(p::MANAGE_CHANNELS | p::MANAGE_FILES, "files.backend_forbidden", "manage channels and files")?;
    Ok(conv)
}

/// The channel's limit for `GET usage` (0 = unlimited): an external store's `max_bytes`, else the node quota.
fn limit_bytes(state: &AppState, ent: &Entitlements, channel_id: &str, row: Option<&store::files::BackendRow>) -> i64 {
    match row.filter(|r| r.kind != "internal") {
        Some(r) => stored_config(state, channel_id, Some(r))
            .map(|c| i64::try_from(c.max_bytes).unwrap_or(i64::MAX))
            .unwrap_or(0),
        None => ent.get(entitlements::FILES_CHANNELS_MAX_BYTES),
    }
}

/// The stored configuration of a channel (empty for internal).
fn stored_config(
    state: &AppState,
    channel_id: &str,
    row: Option<&store::files::BackendRow>,
) -> Result<RemoteConfig, ApiError> {
    match row {
        Some(r) if !r.config.is_empty() => files::open_config(state, channel_id, &r.config),
        _ => Ok(RemoteConfig::default()),
    }
}

/// The storage backend of a files channel (`manage_channels` + `manage_files`); secrets are never returned.
#[utoipa::path(get, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/backend", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)),
    responses((status = 200, body = BackendInfo), (status = 403, body = ProblemDetails)))]
pub async fn get_backend(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
) -> Result<Json<BackendInfo>, ApiError> {
    let conv = backend_access(&state, &room_id, &channel_id, &auth).await?;
    let row = store::files::backend(&state.db, &conv.id).await?;
    let c = stored_config(&state, &conv.id, row.as_ref())?;
    let (_, files_n, _) = store::files::usage(&state.db, &conv.id).await?;
    Ok(Json(BackendInfo {
        kind: backend_kind(&state, row.as_ref()),
        url: c.url,
        username: c.username,
        password_set: !c.password.is_empty(),
        access_key: c.access_key,
        secret_key_set: !c.secret_key.is_empty(),
        region: c.region,
        bucket: c.bucket,
        prefix: c.prefix,
        max_bytes: c.max_bytes,
        encrypt_files: row.as_ref().is_some_and(|r| r.encrypt_files != 0),
        external_allowed: state.config.files_external.on(),
        internal_allowed: state.config.files_internal.on(),
        private_allowed: state.config.files_external_private.on(),
        has_files: files_n > 0,
        updated_at: row.map(|r| r.updated_at),
    }))
}

/// The requested configuration, validated, with stored secrets kept where the request leaves them empty.
fn requested_config(
    state: &AppState,
    conv: &Conv,
    req: BackendRequest,
    row: Option<&store::files::BackendRow>,
) -> Result<(Kind, RemoteConfig, bool), ApiError> {
    let kind = Kind::parse(req.kind.trim()).ok_or_else(|| bad("validation.enum", "kind: internal, webdav or s3"))?;
    if kind == Kind::Internal {
        if !state.config.files_internal.on() {
            return Err(internal_disabled());
        }
        if req.max_bytes.unwrap_or(0) != 0 {
            return Err(bad(
                "files.backend_invalid",
                "max_bytes is for external stores; the node's storage follows files_channels.max_bytes",
            ));
        }
        return Ok((kind, RemoteConfig::default(), false));
    }
    if !state.config.files_external.on() {
        return Err(external_disabled());
    }
    let stored = match row {
        Some(r) if r.kind == kind.as_str() => stored_config(state, &conv.id, Some(r))?,
        _ => RemoteConfig::default(),
    };
    // Stored secrets are reused only for the same server and account: otherwise anybody with the right to configure
    // the backend could send the stored credentials to a host of their choice (FILES.md §5: secrets never leave).
    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
    let region = |s: &str| if s.trim().is_empty() { "us-east-1".to_string() } else { s.trim().to_string() };
    let same_place = norm(req.url.as_deref().unwrap_or("")) == norm(&stored.url)
        && req.username.as_deref().unwrap_or("") == stored.username
        && req.access_key.as_deref().unwrap_or("") == stored.access_key
        && req.bucket.as_deref().unwrap_or("") == stored.bucket
        && (kind != Kind::S3 || region(req.region.as_deref().unwrap_or("")) == region(&stored.region));
    let keep = |new: Option<String>, old: String| {
        new.filter(|s| !s.is_empty()).unwrap_or(if same_place { old } else { String::new() })
    };
    let config = RemoteConfig {
        url: req.url.unwrap_or_default(),
        username: req.username.unwrap_or_default(),
        password: keep(req.password, stored.password),
        access_key: req.access_key.unwrap_or_default(),
        secret_key: keep(req.secret_key, stored.secret_key),
        region: req.region.unwrap_or_default(),
        bucket: req.bucket.unwrap_or_default(),
        prefix: req.prefix.unwrap_or_else(|| format!("tavrn/{}/", conv.id)),
        max_bytes: req.max_bytes.unwrap_or(0),
    };
    let config = remote::validate(kind, config, state.config.files_external_private.on())
        .map_err(remote::RemoteError::into_api)?;
    Ok((kind, config, req.encrypt_files.unwrap_or(false)))
}

/// Configure the storage backend (`manage_channels` + `manage_files`). Switching the store (kind or location)
/// is allowed only while the channel has no files (409 `files.backend_not_empty`); credentials and the
/// encryption toggle can change any time. A WebDAV store gets its prefix collections created. Audit-logged
/// without secrets.
#[utoipa::path(put, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/backend", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body = BackendRequest,
    responses((status = 200, body = BackendInfo), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn put_backend(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Json(req): Json<BackendRequest>,
) -> Result<Json<BackendInfo>, ApiError> {
    let conv = backend_access(&state, &room_id, &channel_id, &auth).await?;
    backend_limiter().check_all(&[format!("files-backend:{}", auth.user.id)])?;
    let row = store::files::backend(&state.db, &conv.id).await?;
    let (kind, config, encrypt) = requested_config(&state, &conv, req, row.as_ref())?;
    if conv.encrypted && encrypt {
        return Err(bad(
            "files.backend_invalid",
            "encrypt_files is only for channels that are not end-to-end encrypted (their files are ciphertext already)",
        ));
    }
    let old_kind = row.as_ref().and_then(|r| Kind::parse(&r.kind)).unwrap_or(Kind::Internal);
    let old_location = if old_kind == Kind::Internal {
        String::new()
    } else {
        remote::location(old_kind, &stored_config(&state, &conv.id, row.as_ref())?)
    };
    let moved = kind != old_kind || remote::location(kind, &config) != old_location;
    if moved {
        let (_, files_n, _) = store::files::usage(&state.db, &conv.id).await?;
        if files_n > 0 {
            return Err(ApiError::Conflict {
                code: "files.backend_not_empty",
                detail: "The storage can only be switched while the channel has no files".into(),
                meta: serde_json::json!({ "files": files_n }),
            });
        }
    }
    let sealed = if kind == Kind::Internal {
        String::new()
    } else {
        let store = RemoteStore::new(kind, config.clone(), state.config.files_external_private.on());
        store.prepare().await.map_err(remote::RemoteError::into_api)?;
        files::seal_config(&state, &conv.id, &config)?
    };
    store::files::set_backend(&state.db, &conv.id, kind.as_str(), &sealed, encrypt, &auth.user.id).await?;
    let host = reqwest::Url::parse(&config.url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "files.backend",
        &conv.id,
        "",
        serde_json::json!({ "kind": kind.as_str(), "host": host, "encrypt_files": encrypt }),
    )
    .await?;
    tracing::info!(channel = %conv.id, kind = kind.as_str(), "files channel storage changed");
    state.hub.room(
        &room_id,
        "files.backend",
        serde_json::json!({ "room_id": room_id, "channel_id": conv.id, "backend": kind.as_str() }),
    );
    get_backend(State(state), auth, Path((room_id, channel_id))).await
}

#[derive(Serialize, ToSchema)]
pub struct BackendTest {
    pub ok: bool,
    /// The store's kind that was tested.
    pub kind: String,
}

/// Connection test (`manage_channels` + `manage_files`): with a body (as for PUT) the given configuration is
/// tested (stored secrets fill empty fields), without one the stored configuration. The store must answer,
/// accept the prefix and write, read and delete a probe object. Failures are 4xx/502 problems.
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/channels/{channel_id}/files/backend/test", security(("bearer" = [])),
    params(("room_id" = String, Path), ("channel_id" = String, Path)), request_body(content = Option<BackendRequest>, content_type = "application/json"),
    responses((status = 200, body = BackendTest), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
pub async fn test_backend(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<BackendTest>, ApiError> {
    let conv = backend_access(&state, &room_id, &channel_id, &auth).await?;
    backend_limiter().check_all(&[format!("files-backend:{}", auth.user.id)])?;
    let row = store::files::backend(&state.db, &conv.id).await?;
    let (kind, config) = if body.iter().all(u8::is_ascii_whitespace) {
        let kind = row.as_ref().and_then(|r| Kind::parse(&r.kind)).unwrap_or(Kind::Internal);
        if kind == Kind::Internal && !state.config.files_internal.on() {
            return Err(internal_disabled());
        }
        if kind != Kind::Internal && !state.config.files_external.on() {
            return Err(external_disabled());
        }
        (kind, stored_config(&state, &conv.id, row.as_ref())?)
    } else {
        let req: BackendRequest =
            serde_json::from_slice(&body).map_err(|e| bad("validation.json", format!("Invalid request: {e}")))?;
        let (kind, config, _) = requested_config(&state, &conv, req, row.as_ref())?;
        (kind, config)
    };
    if kind != Kind::Internal {
        RemoteStore::new(kind, config, state.config.files_external_private.on())
            .test()
            .await
            .map_err(remote::RemoteError::into_api)?;
    }
    Ok(Json(BackendTest { ok: true, kind: kind.as_str().into() }))
}
