// SPDX-License-Identifier: AGPL-3.0-only
//! Data fixes that run at every start after the migrations and need fresh ULIDs or audit entries, which
//! portable SQL migrations cannot produce. Each one is idempotent and cheap when there is nothing to do.
//!
//! - Every room gets its welcome channel (rooms created before migration 0060), and rooms that had
//!   switched it off (the former `welcome_channel_enabled` setting) show it again: it is the room's security log
//!   and can no longer be hidden. Both count in `welcome_channels`.
//! - Management-class permissions are removed from `@everyone` roles and from `allow` masks of
//!   `@everyone` overrides (`permissions::EVERYONE_RESTRICTED`), each removal audited in the room.
//! - `use_external_emojis` and `use_external_sounds` (bits 31/32) are added once to the
//!   `@everyone` role of every room that existed before they were introduced. The marker
//!   [`EXTERNAL_EMOJI_MARKER`] in `node_settings` records the run, so a role whose owner removes the bits
//!   later is never touched again (new rooms get them from `DEFAULT_EVERYONE`).
//! - `read_history` (bit 34) is added once to the `@everyone` role of every room that
//!   existed before it was introduced; the marker [`READ_HISTORY_MARKER`] in `node_settings` records the run,
//!   so a role whose owner removes the bit later is never touched again.
//! - `manage_applications` (bit 35) replaced `manage_room` as the right to install applications and to
//!   edit the room's command settings: it is added once to every role that holds `manage_room` (marker
//!   [`MANAGE_APPLICATIONS_MARKER`]), so nobody who could install bots before loses the ability; rooms narrow it later.
//! - `bots_in_encrypted_channels`: rooms that existed before the setting keep `allowed` (the column
//!   default of migration 0240; new rooms are created with `per_channel`). The first start with the setting records
//!   that decision once in the audit log of each such room (`room.bots_in_encrypted_channels`, `meta.reason =
//!   existing_room`), so room managers can see why their encrypted channels stay open to bots, and sets the marker
//!   [`BOTS_IN_ENCRYPTED_MARKER`].
//! - `manage_threads` (bit 36) is added once to every role that holds `manage_messages` (marker
//!   [`MANAGE_THREADS_MARKER`]), so moderators keep moderating threads; rooms narrow it later. `create_threads`
//!   (bit 6) has been part of `@everyone`'s defaults since the first release and needs no fixup.
//! - `voice_status` (bit 38) is added once to every role that holds `manage_channels` (marker
//!   [`VOICE_STATUS_MARKER`]), so the people who manage channels can set a voice channel's status from the start;
//!   rooms hand it to other roles afterwards (VOICE.md §2a).
//! - `create_polls` (bit 39) is added once to every role that holds `send_messages`, `@everyone` included, and to the
//!   `allow` mask of every override that allows `send_messages` (marker [`CREATE_POLLS_MARKER`]), so whoever could
//!   write a message can still send a poll (PROTOCOL.md §7g); rooms narrow it afterwards. New rooms get it from
//!   `DEFAULT_EVERYONE`.
//! - `use_components` (bit 40) is added once to every role that holds `send_messages`, `@everyone` included (marker
//!   [`USE_COMPONENTS_MARKER`]; overrides are not touched: the bit is independent of writing), so everybody who could
//!   use commands can use the buttons of their answers (APPLICATIONS.md §5.10). New rooms get it from
//!   `DEFAULT_EVERYONE`.
//! - `whisper` (bit 41) is granted once to existing roles holding `speak`, including `@everyone`.
//!   Marker `fixup.whisper` prevents later owner changes from being overwritten; overrides stay independent.
//! - Overrides carry channel-scoped bits only (`permissions::CHANNEL_SCOPED`, layered overrides of 2026-10-09):
//!   other bits are removed from the `allow` and `deny` masks of every override, an override left with nothing at
//!   all is deleted, and each change is audited in the room as `role.override_restricted`.

use sqlx::Row;

use crate::{db::Pool, permissions, store, util};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FixupReport {
    pub welcome_channels: u64,
    pub everyone_roles: u64,
    pub everyone_overrides: u64,
    /// `@everyone` roles that got `use_external_emojis`/`use_external_sounds`.
    pub external_emoji_roles: u64,
    /// `@everyone` roles that got `read_history`.
    pub read_history_roles: u64,
    /// Roles holding `manage_room` that got `manage_applications`.
    pub manage_applications_roles: u64,
    /// Existing rooms whose `bots_in_encrypted_channels = allowed` was recorded.
    pub bots_encrypted_rooms: u64,
    /// Roles holding `manage_messages` that got `manage_threads`.
    pub manage_threads_roles: u64,
    /// Overrides whose bits outside `CHANNEL_SCOPED` were removed (or that were deleted for it).
    pub override_restricted: u64,
    /// Roles holding `manage_channels` that got `voice_status`.
    pub voice_status_roles: u64,
    /// Roles and overrides allowing `send_messages` that got `create_polls`.
    pub create_polls_grants: u64,
    /// Roles holding `send_messages` that got `use_components`.
    pub use_components_roles: u64,
    /// Existing roles holding speak granted whisper initiation once.
    pub whisper_roles: u64,
}

/// `node_settings` key: the one-time grant of the external emoji and sound bits has run.
pub const EXTERNAL_EMOJI_MARKER: &str = "fixup.everyone_external_emojis";

/// `node_settings` key: the one-time grant of `read_history` to `@everyone` has run.
pub const READ_HISTORY_MARKER: &str = "fixup.everyone_read_history";

/// `node_settings` key: the one-time grant of `manage_applications` to roles holding `manage_room` has run.
pub const MANAGE_APPLICATIONS_MARKER: &str = "fixup.manage_applications";

/// `node_settings` key: the one-time grant of `manage_threads` to roles holding `manage_messages` has run.
pub const MANAGE_THREADS_MARKER: &str = "fixup.manage_threads";

/// `node_settings` key: the one-time grant of `create_polls` to roles and overrides with `send_messages` has run.
pub const CREATE_POLLS_MARKER: &str = "fixup.create_polls";

/// `node_settings` key: the one-time grant of `use_components` to roles holding `send_messages` has run.
pub const USE_COMPONENTS_MARKER: &str = "fixup.use_components";

/// `node_settings` key: the one-time grant of `voice_status` to roles holding `manage_channels` has run.
pub const VOICE_STATUS_MARKER: &str = "fixup.voice_status";

/// `node_settings` key: the `allowed` default of existing rooms for `bots_in_encrypted_channels` was recorded.
pub const BOTS_IN_ENCRYPTED_MARKER: &str = "fixup.bots_in_encrypted_channels";

pub async fn run(db: &Pool) -> anyhow::Result<FixupReport> {
    let mut report = FixupReport::default();
    let rooms = sqlx::query(
        "SELECT r.id AS id FROM rooms r WHERE NOT EXISTS
           (SELECT 1 FROM channels c WHERE c.room_id = r.id AND c.kind = 'system' AND c.system_name = $1)",
    )
    .bind(store::rooms::WELCOME)
    .fetch_all(db)
    .await?;
    for row in rooms {
        let room_id: String = row.try_get("id")?;
        let mut tx = db.begin().await?;
        store::rooms::insert_welcome_channel(&mut tx, &room_id, &util::now()).await?;
        tx.commit().await?;
        report.welcome_channels += 1;
    }
    // The column stays (portable migrations never drop), but nothing reads it any more: reset it so the data says
    // what the node does.
    report.welcome_channels +=
        sqlx::query("UPDATE rooms SET welcome_channel_enabled = 1 WHERE welcome_channel_enabled = 0")
            .execute(db)
            .await?
            .rows_affected();

    let mask = permissions::EVERYONE_RESTRICTED as i64;
    let roles =
        sqlx::query("SELECT id, room_id, permissions FROM roles WHERE is_everyone = 1 AND (permissions & $1) <> 0")
            .bind(mask)
            .fetch_all(db)
            .await?;
    for row in roles {
        let (id, room_id, perms): (String, String, i64) =
            (row.try_get("id")?, row.try_get("room_id")?, row.try_get("permissions")?);
        let removed = perms as u64 & permissions::EVERYONE_RESTRICTED;
        sqlx::query("UPDATE roles SET permissions = $1 WHERE id = $2")
            .bind((perms as u64 & !permissions::EVERYONE_RESTRICTED) as i64)
            .bind(&id)
            .execute(db)
            .await?;
        audit_strip(db, &room_id, &id, removed, "role").await?;
        report.everyone_roles += 1;
    }
    let overrides = sqlx::query(
        "SELECT o.id AS id, o.room_id AS room_id, o.allow AS allow, o.target_id AS target_id FROM permission_overrides o
         JOIN roles r ON r.id = o.subject_id AND r.is_everyone = 1
         WHERE o.subject_type = 'role' AND (o.allow & $1) <> 0",
    )
    .bind(mask)
    .fetch_all(db)
    .await?;
    for row in overrides {
        let (id, room_id, allow, target): (String, String, i64, String) =
            (row.try_get("id")?, row.try_get("room_id")?, row.try_get("allow")?, row.try_get("target_id")?);
        let removed = allow as u64 & permissions::EVERYONE_RESTRICTED;
        sqlx::query("UPDATE permission_overrides SET allow = $1 WHERE id = $2")
            .bind((allow as u64 & !permissions::EVERYONE_RESTRICTED) as i64)
            .bind(&id)
            .execute(db)
            .await?;
        audit_strip(db, &room_id, &target, removed, "override").await?;
        report.everyone_overrides += 1;
    }
    report.external_emoji_roles = grant_external_emojis(db).await?;
    report.read_history_roles = grant_read_history(db).await?;
    report.manage_applications_roles = grant_manage_applications(db).await?;
    report.bots_encrypted_rooms = record_bots_in_encrypted(db).await?;
    report.manage_threads_roles = grant_manage_threads(db).await?;
    report.override_restricted = strip_unscoped_overrides(db).await?;
    report.voice_status_roles = grant_voice_status(db).await?;
    report.create_polls_grants = grant_create_polls(db).await?;
    report.use_components_roles = grant_to_roles(
        db,
        USE_COMPONENTS_MARKER,
        Some(permissions::SEND_MESSAGES),
        permissions::USE_COMPONENTS,
        Everyone::Included,
    )
    .await?;
    report.whisper_roles =
        grant_to_roles(db, "fixup.whisper", Some(permissions::SPEAK), permissions::WHISPER, Everyone::Included).await?;
    if report != FixupReport::default() {
        tracing::info!(?report, "Data fixups applied");
    }
    Ok(report)
}

/// Adds bits 31/32 to every `@everyone` role lacking them, once per node (see the module docs).
async fn grant_external_emojis(db: &Pool) -> anyhow::Result<u64> {
    let bits = permissions::USE_EXTERNAL_EMOJIS | permissions::USE_EXTERNAL_SOUNDS;
    grant_to_roles(db, EXTERNAL_EMOJI_MARKER, None, bits, Everyone::Only).await
}

async fn audit_strip(db: &Pool, room_id: &str, target: &str, removed: u64, kind: &str) -> anyhow::Result<()> {
    store::rooms::audit(
        db,
        Some(room_id),
        None,
        "role.everyone_restricted",
        target,
        "Management permissions can no longer be granted to @everyone",
        serde_json::json!({ "kind": kind, "removed": removed.to_string(), "names": permissions::names(removed) }),
    )
    .await?;
    Ok(())
}

/// Removes bits outside `CHANNEL_SCOPED` from every override (see the module docs). Idempotent: the query only
/// finds overrides that still carry such bits.
async fn strip_unscoped_overrides(db: &Pool) -> anyhow::Result<u64> {
    let mask = !permissions::CHANNEL_SCOPED as i64;
    let rows = sqlx::query(
        "SELECT id, room_id, target_type, target_id, subject_type, subject_id, allow, deny, upload_allow, upload_deny
         FROM permission_overrides WHERE (allow & $1) <> 0 OR (deny & $1) <> 0",
    )
    .bind(mask)
    .fetch_all(db)
    .await?;
    let mut changed = 0;
    for row in rows {
        let (id, room_id, target_type, target_id): (String, String, String, String) =
            (row.try_get("id")?, row.try_get("room_id")?, row.try_get("target_type")?, row.try_get("target_id")?);
        let (subject_type, subject_id): (String, String) = (row.try_get("subject_type")?, row.try_get("subject_id")?);
        let (allow, deny) = (row.try_get::<i64, _>("allow")? as u64, row.try_get::<i64, _>("deny")? as u64);
        let uploads = row.try_get::<i64, _>("upload_allow")? != 0 || row.try_get::<i64, _>("upload_deny")? != 0;
        let removed = (allow | deny) & !permissions::CHANNEL_SCOPED;
        let (allow, deny) = (allow & permissions::CHANNEL_SCOPED, deny & permissions::CHANNEL_SCOPED);
        let mut tx = db.begin().await?;
        if allow == 0 && deny == 0 && !uploads {
            sqlx::query("DELETE FROM permission_overrides WHERE id = $1").bind(&id).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE permission_overrides SET allow = $1, deny = $2 WHERE id = $3")
                .bind(allow as i64)
                .bind(deny as i64)
                .bind(&id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        store::rooms::audit(
            db,
            Some(&room_id),
            None,
            "role.override_restricted",
            &target_id,
            "Room-wide permissions can no longer be set per channel or category",
            serde_json::json!({ "target_type": target_type, "subject_type": subject_type, "subject_id": subject_id,
                                "removed": removed.to_string(), "names": permissions::names(removed) }),
        )
        .await?;
        changed += 1;
    }
    Ok(changed)
}

/// Adds `read_history` to every `@everyone` role lacking it, once per node (see the module docs).
async fn grant_read_history(db: &Pool) -> anyhow::Result<u64> {
    grant_to_roles(db, READ_HISTORY_MARKER, None, permissions::READ_HISTORY, Everyone::Only).await
}

async fn marker_set(db: &Pool, key: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query("SELECT value FROM node_settings WHERE key = $1").bind(key).fetch_optional(db).await?.is_some())
}

/// Adds `manage_applications` to every role holding `manage_room`, once per node (see the module docs).
async fn grant_manage_applications(db: &Pool) -> anyhow::Result<u64> {
    grant_to_roles(
        db,
        MANAGE_APPLICATIONS_MARKER,
        Some(permissions::MANAGE_ROOM),
        permissions::MANAGE_APPLICATIONS,
        Everyone::Excluded,
    )
    .await
}

/// Adds `manage_threads` to every role holding `manage_messages`, once per node (see the module docs).
async fn grant_manage_threads(db: &Pool) -> anyhow::Result<u64> {
    grant_to_roles(
        db,
        MANAGE_THREADS_MARKER,
        Some(permissions::MANAGE_MESSAGES),
        permissions::MANAGE_THREADS,
        Everyone::Excluded,
    )
    .await
}

async fn grant_voice_status(db: &Pool) -> anyhow::Result<u64> {
    grant_to_roles(
        db,
        VOICE_STATUS_MARKER,
        Some(permissions::MANAGE_CHANNELS),
        permissions::VOICE_STATUS,
        Everyone::Excluded,
    )
    .await
}

/// Adds `create_polls` to every role holding `send_messages` (`@everyone` included) and to every override allowing it,
/// once per node (see the module docs).
async fn grant_create_polls(db: &Pool) -> anyhow::Result<u64> {
    if marker_set(db, CREATE_POLLS_MARKER).await? {
        return Ok(0);
    }
    let (have, add) = (permissions::SEND_MESSAGES, permissions::CREATE_POLLS);
    let mut tx = db.begin().await?;
    let mut changed = add_bits(&mut tx, "roles", "permissions", Some(have), add, "").await?;
    changed += add_bits(&mut tx, "permission_overrides", "allow", Some(have), add, "").await?;
    set_marker(&mut tx, CREATE_POLLS_MARKER).await?;
    tx.commit().await?;
    Ok(changed)
}

/// Whether a one-time grant also reaches the `@everyone` roles.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Everyone {
    Included,
    Excluded,
    /// Only the `@everyone` roles.
    Only,
}

/// Adds `add` to every role holding `have` (every role for `None`; `@everyone` as `everyone` says), once per node
/// (`marker` in `node_settings`).
async fn grant_to_roles(
    db: &Pool,
    marker: &str,
    have: Option<u64>,
    add: u64,
    everyone: Everyone,
) -> anyhow::Result<u64> {
    if marker_set(db, marker).await? {
        return Ok(0);
    }
    let mut tx = db.begin().await?;
    let which = match everyone {
        Everyone::Included => "",
        Everyone::Excluded => " AND is_everyone = 0",
        Everyone::Only => " AND is_everyone = 1",
    };
    let changed = add_bits(&mut tx, "roles", "permissions", have, add, which).await?;
    set_marker(&mut tx, marker).await?;
    tx.commit().await?;
    Ok(changed)
}

/// Sets the bits `add` in `column` of every row of `table` that lacks one of them (and holds one of `have`), in one
/// statement; `condition` narrows the rows further. Returns the rows changed.
async fn add_bits(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    table: &str,
    column: &str,
    have: Option<u64>,
    add: u64,
    condition: &str,
) -> anyhow::Result<u64> {
    let holding = if have.is_some() { format!(" AND ({column} & $2) <> 0") } else { String::new() };
    let sql = format!("UPDATE {table} SET {column} = {column} | $1 WHERE ({column} & $1) <> $1{holding}{condition}");
    let mut q = sqlx::query(&sql).bind(add as i64);
    if let Some(have) = have {
        q = q.bind(have as i64);
    }
    Ok(q.execute(&mut **tx).await?.rows_affected())
}

async fn set_marker(tx: &mut sqlx::Transaction<'_, sqlx::Any>, marker: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)")
        .bind(marker)
        .bind("done")
        .bind(util::now())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Records once that the rooms existing when `bots_in_encrypted_channels` was introduced keep `allowed`.
async fn record_bots_in_encrypted(db: &Pool) -> anyhow::Result<u64> {
    if marker_set(db, BOTS_IN_ENCRYPTED_MARKER).await? {
        return Ok(0);
    }
    let rooms: Vec<String> = sqlx::query_scalar("SELECT id FROM rooms WHERE bots_in_encrypted_channels = $1")
        .bind(permissions::BOTS_ALLOWED)
        .fetch_all(db)
        .await?;
    for room_id in &rooms {
        store::rooms::audit(
            db,
            Some(room_id),
            None,
            "room.bots_in_encrypted_channels",
            room_id,
            "Rooms created before the setting keep bots in encrypted channels",
            serde_json::json!({ "value": permissions::BOTS_ALLOWED, "reason": "existing_room" }),
        )
        .await?;
    }
    sqlx::query("INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)")
        .bind(BOTS_IN_ENCRYPTED_MARKER)
        .bind("done")
        .bind(util::now())
        .execute(db)
        .await?;
    Ok(rooms.len() as u64)
}
