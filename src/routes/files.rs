// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of files channels (`protocol/FILES.md`): list and search, folders, streamed
//! uploads and ranged downloads, rename/move, recursive delete, usage, and the per-channel storage backend.
//!
//! Permissions (channel level): `view_channel` browses and downloads; `attach_files` uploads, creates folders
//! and renames, moves or deletes the member's own entries; `manage_files` does that for everybody's entries;
//! the backend needs `manage_channels` and `manage_files`. Bots have no access (not in `APP_ROUTES`).

use std::{
    collections::HashSet,
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

/// Removes the bytes of deleted entries: internal files now, external objects in the background.
async fn remove_bytes(state: &AppState, storage: Option<Storage>, entries: Vec<EntryRow>) {
    let mut remote_keys = Vec::new();
    for e in entries.into_iter().filter(|e| !e.is_folder()) {
        if let Some(sid) = e.storage_id.as_deref().filter(|s| util::is_ulid(s)) {
            state.storage.delete(sid).await;
        } else if e.backend != "internal" {
            remote_keys.push((e.id, e.encrypted != 0));
        }
    }
    if remote_keys.is_empty() {
        return;
    }
    let Some(Storage::Remote { store, .. }) = storage else {
        tracing::warn!(objects = remote_keys.len(), "external objects not deleted (store not available)");
        return;
    };
    let state = state.clone();
    tokio::spawn(async move {
        let store = Arc::new(store);
        futures::stream::iter(remote_keys)
            .for_each_concurrent(4, |(key, encrypted)| {
                let (store, state) = (store.clone(), state.clone());
                async move {
                    if let Err(e) = store.delete(&key).await {
                        tracing::warn!(object = %key, error = ?e, "external object could not be deleted");
                    }
                    if encrypted {
                        state.storage.delete_key(&key).await;
                    }
                }
            })
            .await;
    });
}

/// What deleting a channel or a room must remove besides its rows: collected before the delete.
pub struct Cleanup {
    entries: Vec<EntryRow>,
    storages: Vec<(String, Option<Storage>)>,
}

impl Cleanup {
    /// Collects the stored entries of a channel (`channel_id`) or a room (`room_id`).
    pub async fn collect(state: &AppState, column: &str, id: &str) -> Result<Self, ApiError> {
        let entries = store::files::stored_of(&state.db, column, id).await?;
        let mut channels: Vec<String> =
            entries.iter().filter(|e| e.backend != "internal").map(|e| e.channel_id.clone()).collect();
        channels.sort();
        channels.dedup();
        let mut storages = Vec::new();
        for c in channels {
            let s = storage_of(state, &c).await.ok();
            storages.push((c, s));
        }
        Ok(Self { entries, storages })
    }

    /// Deletes the bytes (after the rows are gone).
    pub async fn run(self, state: &AppState) {
        let Self { mut entries, storages } = self;
        for (channel, storage) in storages {
            let (theirs, rest): (Vec<EntryRow>, Vec<EntryRow>) =
                entries.into_iter().partition(|e| e.channel_id == channel && e.backend != "internal");
            entries = rest;
            remove_bytes(state, storage, theirs).await;
        }
        remove_bytes(state, None, entries).await;
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
    pub name: String,
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
    responses((status = 200, body = FileList), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, channel_id)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Result<Json<FileList>, ApiError> {
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    let limit = validate::limit(q.limit, files::LIST_DEFAULT, files::LIST_MAX);
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
    let entries: Vec<FileEntry> = rows.iter().take(limit as usize).map(EntryRow::to_api).collect();
    Ok(Json(FileList {
        next_after: if more { entries.last().map(|e| e.id.clone()) } else { None },
        entries,
        path: path.into_iter().map(|f| Crumb { id: f.id, name: f.name }).collect(),
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
    Ok(Json(FileEntryDetail {
        entry: entry.to_api(),
        path: path.into_iter().map(|f| Crumb { id: f.id, name: f.name }).collect(),
    }))
}

// ---------------------------------------------------------------- Folders

#[derive(Deserialize, ToSchema)]
pub struct CreateFolderRequest {
    /// Parent folder (`null` or absent: top level).
    pub parent_id: Option<String>,
    pub name: String,
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
    let name = files::entry_name(&req.name)?;
    let parent = folder_in(&state, &conv, req.parent_id.as_deref()).await?;
    if ancestors(&state, &conv, parent.as_ref()).await?.len() >= MAX_DEPTH {
        return Err(bad("files.too_deep", format!("Folders nest at most {MAX_DEPTH} levels deep")));
    }
    check_entry_count(&state, &conv).await?;
    let id = store::files::new_id();
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
        },
    )
    .await?
    .ok_or_else(|| name_taken(&name))?;
    changed(&state, &conv, &[row.parent_id.as_deref()]);
    Ok((StatusCode::CREATED, Json(row.to_api())))
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
    responses((status = 201, body = FileEntry), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 502, body = ProblemDetails)))]
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
    let conv = files_channel(&state, &room_id, &channel_id, &auth).await?;
    conv.require(p::ATTACH_FILES, "files.upload_forbidden", "attach files")?;
    let room = room_of(&conv).clone();
    let ent = Entitlements::load(&state, Some(&auth.user), Some(&room)).await?;
    if ent.get(entitlements::FILES_CHANNELS_ENABLED) == 0 {
        return Err(disabled());
    }
    let max = ent.upload_max_bytes(&state.config);
    let quota = ent.limit(entitlements::FILES_CHANNELS_MAX_BYTES);

    let raw_name = header_str(&headers, "tavrn-file-name")
        .map(crate::routes::attachments::percent_decode)
        .ok_or_else(|| bad("files.name_invalid", "Tavrn-File-Name is missing"))?;
    let mut name = files::entry_name(&raw_name)?;
    let parent = folder_in(&state, &conv, header_str(&headers, "tavrn-parent")).await?;
    let parent_id = parent.as_ref().map(|p| p.id.clone());
    let rename = header_str(&headers, "tavrn-conflict").is_some_and(|v| v.eq_ignore_ascii_case("rename"));
    if store::files::name_taken(&state.db, &conv.id, parent_id.as_deref(), &name).await? {
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
    let storage = storage_of(&state, &conv.id).await?;
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
    let (head, stream) = files::read_head(stream, files::SNIFF_BYTES)
        .await
        .map_err(|_| upload_error(&meter, &client_failed, max, quota, used))?;
    let mime = files::upload_mime(header_str(&headers, "content-type"), &name, &head);
    let class = crate::uploads::classify(&head, &name, &mime);
    crate::routes::attachments::check_category(&state, &conv, &auth.user.id, class).await?;

    let id = store::files::new_id();
    let (storage_id, backend, encrypted) = match &storage {
        Storage::Internal => {
            if let Err(e) = state.storage.write_stream(&id, stream).await {
                let err = upload_error(&meter, &client_failed, max, quota, used);
                if matches!(err, ApiError::Internal(_)) {
                    return Err(ApiError::Internal(e));
                }
                return Err(err);
            }
            (Some(id.clone()), "internal", false)
        }
        Storage::Remote { store, encrypt } => {
            let plain_len = declared.unwrap_or(0);
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
        },
    )
    .await;
    let row = match inserted {
        Ok(Some(row)) => row,
        other => {
            // Name taken meanwhile (or a database error): the stored bytes go again.
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
            };
            remove_bytes(&state, Some(storage), vec![ghost]).await;
            return Err(match other {
                Err(e) => e,
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
    h.insert(header::CONTENT_DISPOSITION, disposition(&entry.name));
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
    /// New name.
    pub name: Option<String>,
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
    if name == entry.name && parent_id == entry.parent_id {
        return Ok(Json(entry.to_api()));
    }
    if !store::files::update(&state.db, &entry.id, &name, parent_id.as_deref()).await? {
        return Err(name_taken(&name));
    }
    let fresh = store::files::entry(&state.db, &conv.id, &entry.id).await?.ok_or_else(entry_not_found)?;
    changed(&state, &conv, &[entry.parent_id.as_deref(), fresh.parent_id.as_deref()]);
    Ok(Json(fresh.to_api()))
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
        bytes: tree.iter().map(|e| u64::try_from(e.size).unwrap_or(0)).sum(),
    };
    let needs_remote = tree.iter().any(|e| !e.is_folder() && e.backend != "internal");
    let storage = if needs_remote { storage_of(&state, &conv.id).await.ok() } else { None };
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
    remove_bytes(&state, storage, tree).await;
    changed(&state, &conv, &[entry.parent_id.as_deref()]);
    Ok(Json(result))
}

// ---------------------------------------------------------------- Usage

#[derive(Serialize, ToSchema)]
pub struct FilesInfo {
    /// Files channels are available for this room (`files_channels.enabled`).
    pub enabled: bool,
    pub used_bytes: i64,
    /// `files_channels.max_bytes` of the room (0 = unlimited).
    pub limit_bytes: i64,
    pub files: i64,
    pub folders: i64,
    /// Largest upload for the requester.
    pub max_upload_bytes: u64,
    /// `internal`, `webdav` or `s3`.
    pub backend: String,
    /// External store with encryption (files unreadable outside tavrn).
    pub encrypt_files: bool,
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
    let can_upload = enabled && state.config.uploads_enabled && p::has(conv.perms, p::ATTACH_FILES);
    Ok(Json(FilesInfo {
        enabled,
        used_bytes: used,
        limit_bytes: ent.get(entitlements::FILES_CHANNELS_MAX_BYTES),
        files: files_n,
        folders: folders_n,
        max_upload_bytes: ent.upload_max_bytes(&state.config),
        backend: backend.as_ref().map_or("internal".to_string(), |b| b.kind.clone()),
        encrypt_files: backend.as_ref().is_some_and(|b| b.encrypt_files != 0),
        can_upload,
        can_manage: p::has(conv.perms, p::MANAGE_FILES),
        can_configure: p::has(conv.perms, p::MANAGE_CHANNELS | p::MANAGE_FILES),
        allowed_categories: crate::uploads::names(allowed),
        executables_allowed: state.config.upload_allow_executables && allowed & crate::uploads::OTHER != 0,
    }))
}

// ---------------------------------------------------------------- Backend

#[derive(Serialize, ToSchema)]
pub struct BackendInfo {
    /// `internal`, `webdav` or `s3`.
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
    /// External stores are allowed on this node (`TAVRN_FILES_EXTERNAL`).
    pub external_allowed: bool,
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
}

async fn backend_access(state: &AppState, room_id: &str, channel_id: &str, auth: &AuthUser) -> Result<Conv, ApiError> {
    let conv = files_channel(state, room_id, channel_id, auth).await?;
    conv.require(p::MANAGE_CHANNELS | p::MANAGE_FILES, "files.backend_forbidden", "manage channels and files")?;
    Ok(conv)
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
        kind: row.as_ref().map_or("internal".to_string(), |r| r.kind.clone()),
        url: c.url,
        username: c.username,
        password_set: !c.password.is_empty(),
        access_key: c.access_key,
        secret_key_set: !c.secret_key.is_empty(),
        region: c.region,
        bucket: c.bucket,
        prefix: c.prefix,
        encrypt_files: row.as_ref().is_some_and(|r| r.encrypt_files != 0),
        external_allowed: state.config.files_external.on(),
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
        return Ok((kind, RemoteConfig::default(), false));
    }
    if !state.config.files_external.on() {
        return Err(external_disabled());
    }
    let stored = match row {
        Some(r) if r.kind == kind.as_str() => stored_config(state, &conv.id, Some(r))?,
        _ => RemoteConfig::default(),
    };
    let keep = |new: Option<String>, old: String| new.filter(|s| !s.is_empty()).unwrap_or(old);
    let config = RemoteConfig {
        url: req.url.unwrap_or_default(),
        username: req.username.unwrap_or_default(),
        password: keep(req.password, stored.password),
        access_key: req.access_key.unwrap_or_default(),
        secret_key: keep(req.secret_key, stored.secret_key),
        region: req.region.unwrap_or_default(),
        bucket: req.bucket.unwrap_or_default(),
        prefix: req.prefix.unwrap_or_else(|| format!("tavrn/{}/", conv.id)),
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
