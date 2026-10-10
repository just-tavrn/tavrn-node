// SPDX-License-Identifier: AGPL-3.0-only
//! Periodic housekeeping of the node (hourly): pruning of the MLS handshake log and of Welcomes
//! nobody fetched (ENCRYPTION.md §4.4), of federation state, and of remote users nothing ties to this
//! node any more (FEDERATION.md §2.6), orphaned files, and the in-place encryption of stored files that are
//! still plaintext.

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::{app::AppState, db::Pool, error::ApiError, util};

/// The newest epochs of every conversation are always kept …
pub const KEEP_EPOCHS: i64 = 1000;
/// … and so is every commit younger than this.
pub const COMMIT_MAX_AGE_DAYS: i64 = 90;
/// Welcomes not fetched within this time are deleted (the device rejoins by external commit).
pub const WELCOME_MAX_AGE_DAYS: i64 = 30;
pub const INTERVAL: Duration = Duration::from_secs(3600);
/// Wait before the first round, so a fresh instance of several knows whether it leads.
const LEADER_SETTLE: Duration = Duration::from_secs(6);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub commits: u64,
    pub welcomes: u64,
}

/// Deletes commits that are both older than 90 days and not among the newest 1000 epochs of their
/// conversation, and Welcomes older than 30 days. A client further behind rejoins by external commit.
pub async fn prune_handshake_log(db: &Pool, now: DateTime<Utc>) -> Result<PruneReport, ApiError> {
    let commit_cutoff = util::format_time(now - chrono::Duration::days(COMMIT_MAX_AGE_DAYS));
    let welcome_cutoff = util::format_time(now - chrono::Duration::days(WELCOME_MAX_AGE_DAYS));
    let commits = sqlx::query(
        "DELETE FROM mls_commits WHERE created_at < $1
         AND epoch <= (SELECT MAX(c.epoch) FROM mls_commits c WHERE c.conversation_id = mls_commits.conversation_id) - $2",
    )
    .bind(commit_cutoff)
    .bind(KEEP_EPOCHS)
    .execute(db)
    .await?
    .rows_affected();
    let welcomes = sqlx::query("DELETE FROM mls_welcomes WHERE created_at < $1")
        .bind(welcome_cutoff)
        .execute(db)
        .await?
        .rows_affected();
    Ok(PruneReport { commits, welcomes })
}

/// Inbox message ids are kept this long for the dedupe (FEDERATION.md §5.1).
pub const INBOX_SEEN_DAYS: i64 = 7;
/// Federation targets without a new token for this long are dropped (§2.4).
pub const TARGETS_DAYS: i64 = 30;

/// Prunes the federation replay store, inbox dedupe ids and stale federation targets.
pub async fn prune_federation(
    db: &Pool,
    now: DateTime<Utc>,
) -> Result<crate::store::federation::FederationPrune, ApiError> {
    crate::store::federation::prune(
        db,
        &util::format_time(now),
        &util::format_time(now - chrono::Duration::days(INBOX_SEEN_DAYS)),
        &util::format_time(now - chrono::Duration::days(TARGETS_DAYS)),
    )
    .await
}

/// Remote users deleted per housekeeping round (the rest follow an hour later).
pub const REMOTE_USER_BATCH: i64 = 500;

/// SQL condition on the users row `u` (bound: `$1` own domain, `$2` inactivity cutoff, `$3` now): a
/// remote user without a federated login since the cutoff, without a live session, and without
/// anything that still ties it to this node: room or conversation memberships, friendships, friend
/// requests and blocks (in either direction), authored messages, reactions, pins, uploads, custom
/// emojis, rooms it owns, bans it issued or that name its address, bots it owns, invite links it
/// created. Entries the node wrote about the user (welcome channel `system.join`/`system.leave`) do not
/// tie it; they are deleted with the user. Messages, pins and room ownership also keep the row because deleting it would change
/// what other members see; blocks because a local user's block must survive.
const REMOTE_USER_UNUSED: &str = "u.domain <> $1
    AND COALESCE((SELECT r.last_login_at FROM remote_users r WHERE r.user_id = u.id), u.created_at) < $2
    AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > $3)
    AND NOT EXISTS (SELECT 1 FROM room_members x WHERE x.user_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM conversation_members x WHERE x.user_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM friends x WHERE x.user_id = u.id OR x.friend_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM friend_requests x WHERE x.from_user_id = u.id OR x.to_user_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM user_blocks x WHERE x.user_id = u.id OR x.blocked_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM messages x WHERE x.author_id = u.id AND NOT (x.device_id IS NULL AND x.content LIKE '%\"type\":\"system.%'))
    AND NOT EXISTS (SELECT 1 FROM reactions x WHERE x.user_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM pins x WHERE x.pinned_by = u.id)
    AND NOT EXISTS (SELECT 1 FROM blobs x WHERE x.uploader_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM emojis x WHERE x.uploader_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM rooms x WHERE x.owner_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM bans x WHERE x.actor_id = u.id OR x.subject = u.username || '@' || u.domain)
    AND NOT EXISTS (SELECT 1 FROM users x WHERE x.owner_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM invites x WHERE x.creator_id = u.id)
    AND NOT EXISTS (SELECT 1 FROM threads x WHERE x.created_by = u.id OR x.title_author_id = u.id)";

/// Deletes remote users that had no federated login for `TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`
/// (default 90) and that nothing ties to this node any more (see [`REMOTE_USER_UNUSED`]), with their
/// devices, sessions, KeyPackages, key cache and mirrored avatar (FEDERATION.md §2.6). They are created
/// again as a stub or by their next federated login. Returns the number of deleted users.
pub async fn prune_remote_users(state: &AppState, now: DateTime<Utc>) -> Result<u64, ApiError> {
    let days = state.config.federation_remote_user_retention_days;
    if days == 0 {
        return Ok(0);
    }
    let db = &state.db;
    let own = &state.config.domain;
    let cutoff = util::format_time(now - chrono::Duration::days(i64::from(days)));
    let now = util::format_time(now);
    let candidates: Vec<(String, Option<String>)> = sqlx::query_as(&format!(
        "SELECT u.id, u.avatar_blob_id FROM users u WHERE {REMOTE_USER_UNUSED} ORDER BY u.id LIMIT $4"
    ))
    .bind(own)
    .bind(&cutoff)
    .bind(&now)
    .bind(REMOTE_USER_BATCH)
    .fetch_all(db)
    .await?;
    let mut deleted = 0;
    for (id, avatar) in candidates {
        // The node's entries about the user go first (messages reference their author).
        sqlx::query(
            "DELETE FROM messages WHERE author_id = $1 AND device_id IS NULL AND content LIKE '%\"type\":\"system.%'",
        )
        .bind(&id)
        .execute(db)
        .await?;
        // The conditions are checked again in the delete: the user may have signed in meanwhile.
        let n = sqlx::query(&format!(
            "DELETE FROM users WHERE id = $4 AND id IN (SELECT u.id FROM users u WHERE u.id = $4 AND {REMOTE_USER_UNUSED})"
        ))
        .bind(own)
        .bind(&cutoff)
        .bind(&now)
        .bind(&id)
        .execute(db)
        .await?
        .rows_affected();
        if n > 0 {
            deleted += n;
            if let Some(blob) = avatar.filter(|b| util::is_ulid(b)) {
                state.storage.delete(&blob).await;
            }
        }
    }
    Ok(deleted)
}

/// Orphans (uploads never sent, images nothing points to, files without a row) are deleted after this.
pub const ORPHAN_AGE_HOURS: i64 = 24;
/// Rows handled per query and round.
const ORPHAN_BATCH: i64 = 500;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OrphanReport {
    /// Upload rows never bound to a message (and their files).
    pub uploads: u64,
    /// Media rows (avatars, headers, icons, backgrounds, room avatars) no user, room or membership uses.
    pub media: u64,
    /// Files in the blob storage without any row (`blobs`, `media`, `emojis`, `soundboard_sounds`,
    /// `user_emojis`, `user_sounds`).
    pub files: u64,
    /// Wrapped file keys (`blob_keys`) whose file no row knows any more (a crash between the deletes).
    pub keys: u64,
    /// Files channel entries whose stored file is missing.
    pub file_entries: u64,
}

/// Deletes orphaned files older than [`ORPHAN_AGE_HOURS`] (deleted means gone): uploads
/// that never became part of a message, media rows nothing references any more, and files in the blob
/// storage that no row knows (e.g. left behind by a crash between a row delete and the file delete).
pub async fn sweep_orphans(state: &AppState, now: DateTime<Utc>) -> Result<OrphanReport, ApiError> {
    let db = &state.db;
    let cutoff = now - chrono::Duration::hours(ORPHAN_AGE_HOURS);
    let cutoff_s = util::format_time(cutoff);
    let mut report = OrphanReport::default();
    loop {
        let ids = crate::store::blobs::orphans_before(db, &cutoff_s, ORPHAN_BATCH).await?;
        if ids.is_empty() {
            break;
        }
        crate::store::blobs::delete_rows(db, &ids).await?;
        for id in &ids {
            state.storage.delete(id).await;
        }
        report.uploads += ids.len() as u64;
        if (ids.len() as i64) < ORPHAN_BATCH {
            break;
        }
    }
    let media: Vec<(String,)> = sqlx::query_as(
        "SELECT m.id FROM media m WHERE m.created_at < $1
           AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_blob_id = m.id OR u.header_blob_id = m.id OR u.background_blob_id = m.id)
           AND NOT EXISTS (SELECT 1 FROM rooms r WHERE r.icon_blob_id = m.id OR r.banner_blob_id = m.id)
           AND NOT EXISTS (SELECT 1 FROM room_members x WHERE x.avatar_media_id = m.id)
         LIMIT $2",
    )
    .bind(&cutoff_s)
    .bind(ORPHAN_BATCH)
    .fetch_all(db)
    .await?;
    for (id,) in &media {
        crate::profile::delete_media(state, id).await?;
        report.media += 1;
    }
    let files = state.storage.files_before(cutoff.into()).await.map_err(ApiError::Internal)?;
    for chunk in files.chunks(ORPHAN_BATCH as usize) {
        let ids: Vec<&str> = chunk.iter().map(|(name, _)| name.as_str()).filter(|n| util::is_ulid(n)).collect();
        let known = known_storage_ids(db, &ids).await?;
        for (name, path) in chunk {
            let partial = name.strip_suffix(".part").is_some_and(util::is_ulid);
            if partial || (util::is_ulid(name) && !known.contains(name.as_str())) {
                state.storage.delete_path(path).await;
                report.files += 1;
            }
        }
    }
    report.keys = sqlx::query(
        "DELETE FROM blob_keys WHERE created_at < $1
           AND storage_id NOT IN (SELECT id FROM blobs) AND storage_id NOT IN (SELECT id FROM media)
           AND storage_id NOT IN (SELECT animated_id FROM media WHERE animated_id IS NOT NULL)
           AND storage_id NOT IN (SELECT id FROM emojis) AND storage_id NOT IN (SELECT id FROM soundboard_sounds)
           AND storage_id NOT IN (SELECT still_id FROM emojis WHERE still_id IS NOT NULL)
           AND storage_id NOT IN (SELECT id FROM user_emojis)
           AND storage_id NOT IN (SELECT still_id FROM user_emojis WHERE still_id IS NOT NULL)
           AND storage_id NOT IN (SELECT id FROM user_sounds)
           AND storage_id NOT IN (SELECT id FROM remote_emoji_cache)
           AND storage_id NOT IN (SELECT id FROM file_entries)
           AND storage_id NOT IN (SELECT storage_id FROM file_entries WHERE storage_id IS NOT NULL)
           AND storage_id NOT IN (SELECT thumbnail_id FROM file_entries WHERE thumbnail_id IS NOT NULL)",
    )
    .bind(&cutoff_s)
    .execute(db)
    .await?
    .rows_affected();
    report.file_entries = sweep_file_entries(state, &cutoff_s).await?;
    Ok(report)
}

/// Files channel entries (internal storage) whose stored file is gone: the rows are deleted, so that the
/// browser does not list files that cannot be downloaded. Folders and external files are not touched (the
/// node does not list external stores).
async fn sweep_file_entries(state: &AppState, cutoff: &str) -> Result<u64, ApiError> {
    let mut deleted = 0;
    let mut after = String::new();
    loop {
        let rows = crate::store::files::internal_files_page(&state.db, cutoff, &after, ORPHAN_BATCH).await?;
        let Some(last) = rows.last() else { break };
        after = last.id.clone();
        let mut missing = Vec::new();
        for row in &rows {
            let Some(path) = row.storage_id.as_deref().and_then(|s| state.storage.path_of(s)) else { continue };
            if !tokio::fs::try_exists(&path).await.unwrap_or(true) {
                tracing::warn!(entry = %row.id, channel = %row.channel_id, "files channel entry without its stored file removed");
                missing.push(row.id.clone());
            }
        }
        crate::store::files::delete_ids(&state.db, &missing).await?;
        deleted += missing.len() as u64;
        if (rows.len() as i64) < ORPHAN_BATCH {
            break;
        }
    }
    Ok(deleted)
}

/// Retries the queued deletes of objects on external stores of files channels (FILES.md §6) that are due at `now`.
pub async fn retry_external_deletes(
    state: &AppState,
    now: DateTime<Utc>,
) -> Result<crate::routes::files::PendingReport, ApiError> {
    crate::routes::files::run_pending_deletes(state, None, now).await
}

/// Which of `ids` some row names as its file.
async fn known_storage_ids(db: &Pool, ids: &[&str]) -> Result<std::collections::HashSet<String>, ApiError> {
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let list = (1..=ids.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT id FROM blobs WHERE id IN ({list})
         UNION SELECT id FROM media WHERE id IN ({list})
         UNION SELECT animated_id AS id FROM media WHERE animated_id IN ({list})
         UNION SELECT id FROM emojis WHERE id IN ({list})
         UNION SELECT id FROM soundboard_sounds WHERE id IN ({list})
         UNION SELECT still_id AS id FROM emojis WHERE still_id IN ({list})
         UNION SELECT id FROM user_emojis WHERE id IN ({list})
         UNION SELECT still_id AS id FROM user_emojis WHERE still_id IN ({list})
         UNION SELECT id FROM user_sounds WHERE id IN ({list})
         UNION SELECT id FROM remote_emoji_cache WHERE id IN ({list})
         UNION SELECT storage_id AS id FROM file_entries WHERE storage_id IN ({list})
         UNION SELECT thumbnail_id AS id FROM file_entries WHERE thumbnail_id IN ({list})"
    );
    let mut q = sqlx::query_as::<_, (String,)>(&sql);
    for id in ids {
        q = q.bind(*id);
    }
    Ok(q.fetch_all(db).await?.into_iter().map(|(id,)| id).collect())
}

/// Attachments handled per batch by retention, and the time one housekeeping round may spend on them.
pub const RETENTION_BATCH: i64 = 500;
pub const RETENTION_BUDGET: Duration = Duration::from_secs(60);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    /// Attachments whose files were deleted and that are now marked `expired`.
    pub expired: u64,
    /// The time budget ran out; the rest follows in the next round.
    pub incomplete: bool,
}

/// Attachment retention: deletes the files of attachments older than the retention of
/// their conversation and marks the rows `expired_at` (messages keep listing them as `expired`). The node
/// value (`TAVRN_ATTACHMENT_RETENTION_DAYS`, DMs and every room) runs first; rooms with a shorter retention
/// (own setting or room grant) follow. Exempt: attachments of pinned messages; profile media, emojis and
/// sounds are not attachments; files channel entries live in `file_entries`, not in `blobs`, and are never
/// touched. Works in batches of [`RETENTION_BATCH`] within `budget`.
pub async fn expire_attachments(
    state: &AppState,
    now: DateTime<Utc>,
    budget: Duration,
) -> Result<RetentionReport, ApiError> {
    let started = std::time::Instant::now();
    let db = &state.db;
    let node_days = i64::from(state.config.attachment_retention_days);
    // (room or None for everything, retention days). The node pass is valid for every room because a room
    // can only shorten the node value.
    let mut passes: Vec<(Option<String>, i64)> = Vec::new();
    if node_days > 0 {
        passes.push((None, node_days));
    }
    for room in crate::store::entitlements::retention_rooms(db, &util::format_time(now)).await? {
        let Some(room) = crate::store::rooms::room_by_id(db, &room).await? else { continue };
        let days = crate::entitlements::Entitlements::for_room(state, &room)
            .await?
            .get(crate::entitlements::ATTACHMENTS_RETENTION_DAYS);
        if days > 0 && (node_days == 0 || days < node_days) {
            passes.push((Some(room.id), days));
        }
    }
    let mut report = RetentionReport::default();
    for (room, days) in passes {
        let cutoff = util::format_time(now - chrono::Duration::days(days));
        loop {
            if started.elapsed() >= budget {
                report.incomplete = true;
                return Ok(report);
            }
            let ids = crate::store::blobs::retention_candidates(db, &cutoff, room.as_deref(), RETENTION_BATCH).await?;
            if ids.is_empty() {
                break;
            }
            // Files first: a crash in between leaves rows that the next round handles again.
            for id in &ids {
                state.storage.delete(id).await;
            }
            crate::store::blobs::mark_expired(db, &ids).await?;
            report.expired += ids.len() as u64;
            if (ids.len() as i64) < RETENTION_BATCH {
                break;
            }
        }
    }
    Ok(report)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MessageRetentionReport {
    /// Messages deleted.
    pub deleted: u64,
    /// The time budget ran out; the rest follows in the next round.
    pub incomplete: bool,
}

/// Message retention (PROTOCOL.md §7f): deletes messages older than the retention of their conversation, with
/// their attachments (rows cascade, files are deleted here; a crash in between leaves files the orphan sweep
/// removes), reactions, pins and search rows. The node value (`TAVRN_RETENTION_DAYS`, DMs, group DMs and every room)
/// runs first; rooms with a shorter own value (`message_retention_days`) follow. Exempt: pinned messages and the
/// welcome channel's entries (the room's security log). Threads that lost messages count again. Works in batches of
/// [`RETENTION_BATCH`] within `budget`; writes one node audit entry `retention.messages` when it deleted something.
pub async fn expire_messages(
    state: &AppState,
    now: DateTime<Utc>,
    budget: Duration,
) -> Result<MessageRetentionReport, ApiError> {
    let started = std::time::Instant::now();
    let db = &state.db;
    let node_days = i64::from(state.config.retention_days);
    let mut passes: Vec<(Option<String>, i64)> = Vec::new();
    if node_days > 0 {
        passes.push((None, node_days));
    }
    for (room, days) in crate::store::rooms::message_retention_rooms(db).await? {
        if days > 0 && (node_days == 0 || days < node_days) {
            passes.push((Some(room), days));
        }
    }
    let rooms = passes.iter().filter(|(room, _)| room.is_some()).count();
    let mut report = MessageRetentionReport::default();
    'passes: for (room, days) in passes {
        let cutoff = util::format_time(now - chrono::Duration::days(days));
        loop {
            if started.elapsed() >= budget {
                report.incomplete = true;
                break 'passes;
            }
            let ids =
                crate::store::messages::retention_candidates(db, &cutoff, room.as_deref(), RETENTION_BATCH).await?;
            if ids.is_empty() {
                break;
            }
            report.deleted += delete_messages(state, &ids).await?;
            if (ids.len() as i64) < RETENTION_BATCH {
                break;
            }
        }
    }
    if report.deleted > 0 {
        crate::store::rooms::audit(
            db,
            None,
            None,
            "retention.messages",
            "",
            "",
            serde_json::json!({ "deleted": report.deleted, "node_days": node_days, "rooms": rooms,
                "incomplete": report.incomplete }),
        )
        .await?;
    }
    Ok(report)
}

/// Deletes the messages `ids` for retention: rows first, then the files of their attachments, then the threads count
/// their messages again.
async fn delete_messages(state: &AppState, ids: &[String]) -> Result<u64, ApiError> {
    let db = &state.db;
    let list = (1..=ids.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
    let filter = format!("id IN ({list})");
    let blobs = crate::store::blobs::ids_for_messages(db, &filter, ids).await?;
    let threads = crate::store::threads::ids_for_messages(db, &filter, ids).await?;
    let deleted = crate::store::messages::delete_for_retention(db, ids).await?;
    // A message pinned meanwhile stays, and so do its files.
    for chunk in blobs.chunks(ORPHAN_BATCH as usize) {
        let refs: Vec<&str> = chunk.iter().map(String::as_str).collect();
        let kept = known_storage_ids(db, &refs).await?;
        for id in chunk.iter().filter(|b| !kept.contains(b.as_str())) {
            state.storage.delete(id).await;
        }
    }
    crate::store::threads::recount(db, &threads).await?;
    for id in &threads {
        crate::threads::publish(state, "thread.update", id).await?;
    }
    Ok(deleted)
}

/// Expired entitlement grants are kept this long (shown as expired in the admin UI), then deleted.
pub const GRANT_KEEP_DAYS: i64 = 7;

/// Encrypts the stored files that are still plaintext (see `BlobStorage::encrypt_plaintext`):
/// runs at the start and again in the hourly housekeeping until a run finds nothing left. Logs progress.
pub async fn encrypt_stored_files(state: &AppState) {
    if !state.storage.encrypts() || state.storage.plaintext_clean() {
        return;
    }
    match state.storage.encrypt_plaintext(u64::MAX, crate::storage::MIGRATION_BYTES_PER_SEC).await {
        Ok(r) if r.encrypted > 0 || r.failed > 0 => {
            tracing::info!(files = r.encrypted, bytes = r.bytes, failed = r.failed, "stored plaintext files encrypted");
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "encryption of stored files failed (retried in an hour)"),
    }
}

/// Runs the housekeeping tasks every hour (first run one interval after the start).
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let db = state.db.clone();
        let mut tick = tokio::time::interval(INTERVAL);
        tick.tick().await;
        // Several instances: housekeeping runs on the leader only (`cache::leader`). The first leader check waits
        // for the lease (a fresh instance holds it within a third of the lease time).
        if state.cluster.is_shared() {
            tokio::time::sleep(LEADER_SETTLE).await;
        }
        // Files left unencrypted by an older version or by TAVRN_STORAGE_ENCRYPTION=off: right away.
        if state.cluster.is_leader() {
            encrypt_stored_files(&state).await;
        }
        loop {
            tick.tick().await;
            // Every instance holds its own copy of the operator's auto-moderation lists (MODERATION.md §2.3).
            let _ = crate::automod::reload_node_lists(&state).await;
            if !state.cluster.is_leader() {
                continue;
            }
            encrypt_stored_files(&state).await;
            match prune_handshake_log(&db, Utc::now()).await {
                Ok(r) if r != PruneReport::default() => {
                    tracing::info!(commits = r.commits, welcomes = r.welcomes, "Handshake log pruned");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Housekeeping failed"),
            }
            match prune_federation(&db, Utc::now()).await {
                Ok(r) if r != crate::store::federation::FederationPrune::default() => {
                    tracing::info!(
                        replay = r.replay,
                        inbox = r.inbox_seen,
                        targets = r.targets,
                        hints_and_invites = r.hints_and_invites,
                        "Federation state pruned"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Federation housekeeping failed"),
            }
            match sweep_orphans(&state, Utc::now()).await {
                Ok(r) if r != OrphanReport::default() => {
                    tracing::info!(
                        uploads = r.uploads,
                        media = r.media,
                        files = r.files,
                        file_entries = r.file_entries,
                        "Orphaned files deleted"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Orphan sweep failed"),
            }
            match retry_external_deletes(&state, Utc::now()).await {
                Ok(r) if r != crate::routes::files::PendingReport::default() => {
                    tracing::info!(
                        deleted = r.deleted,
                        failed = r.failed,
                        given_up = r.given_up,
                        "External objects of files channels deleted"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "External deletes failed"),
            }
            match expire_attachments(&state, Utc::now(), RETENTION_BUDGET).await {
                Ok(r) if r != RetentionReport::default() => {
                    tracing::info!(attachments = r.expired, incomplete = r.incomplete, "Expired attachments deleted");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Attachment retention failed"),
            }
            match expire_messages(&state, Utc::now(), RETENTION_BUDGET).await {
                Ok(r) if r != MessageRetentionReport::default() => {
                    tracing::info!(messages = r.deleted, incomplete = r.incomplete, "Expired messages deleted");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Message retention failed"),
            }
            let grants_cutoff = util::format_time(Utc::now() - chrono::Duration::days(GRANT_KEEP_DAYS));
            if let Err(e) = crate::store::entitlements::prune_grants(&db, &grants_cutoff).await {
                tracing::warn!(error = %e, "Entitlement housekeeping failed");
            }
            match crate::threads::auto_archive(&state, Utc::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(threads = n, "Idle threads archived"),
                Err(e) => tracing::warn!(error = %e, "Thread auto-archive failed"),
            }
            match crate::emoji_cache::evict_unused(&state, Utc::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(copies = n, "Unused cached emojis and clips of other nodes evicted"),
                Err(e) => tracing::warn!(error = %e, "Media cache housekeeping failed"),
            }
            match crate::emoji_cache::enforce_total_cap(&state).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(copies = n, "Cached emojis and clips of other nodes evicted (TAVRN_MEDIA_CACHE_MAX_BYTES)"),
                Err(e) => tracing::warn!(error = %e, "Media cache cap failed"),
            }
            let (acked, old) = (
                util::format_time(Utc::now() - chrono::Duration::hours(crate::history::ACKED_KEEP_HOURS)),
                util::format_time(Utc::now() - chrono::Duration::days(crate::history::MAX_AGE_DAYS)),
            );
            match crate::store::history::prune(&db, &acked, &old).await {
                Ok(r) if r != crate::store::history::HistoryPrune::default() => {
                    tracing::info!(shares = r.shares, pending = r.pending, "History shares pruned");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "History share housekeeping failed"),
            }
            let decided_before =
                util::format_time(Utc::now() - chrono::Duration::days(crate::history::RESTORE_VALID_DAYS));
            match crate::store::history::prune_requests(&db, &decided_before).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(requests = n, "Decided history restore requests pruned"),
                Err(e) => tracing::warn!(error = %e, "History request housekeeping failed"),
            }
            match crate::device_cleanup::run(&state, Utc::now()).await {
                Ok(r) if r != crate::device_cleanup::CleanupReport::default() => {
                    tracing::info!(
                        devices = r.devices,
                        ghosts = r.ghosts,
                        expired = r.expired,
                        "Devices and MLS leaves cleaned up"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Device housekeeping failed"),
            }
            match crate::applications::notify_expiring_tokens(&state, Utc::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(tokens = n, "App token expiry notices sent"),
                Err(e) => tracing::warn!(error = %e, "App token expiry notices failed"),
            }
            match prune_remote_users(&state, Utc::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(users = n, "Unused remote users deleted"),
                Err(e) => tracing::warn!(error = %e, "Remote user housekeeping failed"),
            }
            let reports_cutoff =
                util::format_time(Utc::now() - chrono::Duration::days(crate::routes::directory::REPORT_RETENTION_DAYS));
            if let Err(e) = crate::store::directory::prune_reports(&db, &reports_cutoff).await {
                tracing::warn!(error = %e, "Report housekeeping failed");
            }
            match crate::reports::prune(&state, Utc::now()).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(reports = n, "Closed reports past their retention deleted"),
                Err(e) => tracing::warn!(error = %e, "Report retention failed"),
            }
            // Legal: notice retention, interrupted content deletions, accounts past their grace period.
            match crate::legal::housekeeping(&state, Utc::now()).await {
                Ok((0, 0, 0)) => {}
                Ok((notices, resumed, erased)) => {
                    tracing::info!(
                        notices,
                        resumed,
                        erased,
                        "Legal housekeeping: notices pruned, deletions continued, accounts erased"
                    );
                }
                Err(e) => tracing::warn!(error = %e, "Legal housekeeping failed"),
            }
            // Web push: expired subscriptions and those of signed-out devices.
            match crate::store::push::prune(&db).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(subscriptions = n, "Stale push subscriptions deleted"),
                Err(e) => tracing::warn!(error = %e, "Push subscription housekeeping failed"),
            }
            state.metrics.housekeeping_last_run.set(Utc::now().timestamp());
        }
    })
}
