// SPDX-License-Identifier: AGPL-3.0-only
//! Account deletion (GDPR Art. 17; protocol/LEGAL.md §3).
//!
//! Deleting an account is immediate, needs a reauth token and the confirmation phrase (the username), and works the
//! same for the user, for a node admin acting on request, and — for a remote user's stub — for S2S `user.deleted`:
//!
//! * A **tombstone** row (`deleted-<random>@<domain>`, display name "Deleted user", no avatar, no profile) takes over
//!   everything that stays for the other users' sake: messages (envelopes keep their place, replies and threads stay
//!   intact; device ids and signatures are stripped so nothing links back), pins, uploads, room emojis and sounds,
//!   bans and invites the user issued, open legal notices, and the audit log (actor and the address in its texts
//!   become the tombstone's).
//! * Always deleted at once: profile (avatar, header, background, bio, links, status), presence, devices and keys
//!   (MLS leaves get `mls.remove_needed`), sessions and federated sessions, secret storage and backups, friends,
//!   requests and blocks, room and DM memberships, personal emojis, sounds and whiteboards, notification settings,
//!   second factors, applications (owner cascade) and admin tokens.
//! * With `delete_messages` a background job also removes the content of every message (plaintext and ciphertext)
//!   and its files; a `system.deleted` placeholder keeps the slot. Clients get `message.redact` per batch.
//! * The account row itself stays disabled with its username reserved, password hash, e-mail and single sign-on link
//!   (only so the admin can undo within `TAVRN_ACCOUNT_DELETE_GRACE_DAYS`); housekeeping erases it afterwards.
//! * Other nodes hear `user.deleted { delete_messages }` and do the same for the user's stub there.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::{app::AppState, db::Pool, error::ApiError, models::UserRow, store, util};

/// Content of a message whose content was deleted with its author's account.
pub const PLACEHOLDER: &str = r#"{"type":"system.deleted"}"#;
/// S2S type (FEDERATION.md §5.2): from the user, to every node that knows the user.
pub const KIND: &str = "user.deleted";
/// Messages per batch of the content deletion job.
pub const BATCH: i64 = 500;
/// Display name of tombstones (clients show their own translation).
pub const TOMBSTONE_NAME: &str = "Deleted user";

#[derive(Debug, Clone, FromRow)]
pub struct DeletionRow {
    pub id: String,
    pub user_id: String,
    pub tombstone_id: String,
    pub address: String,
    pub requested_by: Option<String>,
    pub delete_messages: i64,
    pub state: String,
    pub messages_total: i64,
    pub messages_done: i64,
    pub status_token_hash: Option<String>,
    pub created_at: String,
    pub purge_after: String,
    pub finished_at: Option<String>,
    pub undone_at: Option<String>,
    pub purged_at: Option<String>,
}

const COLS: &str = "id, user_id, tombstone_id, address, requested_by, delete_messages, state, messages_total, messages_done, status_token_hash, created_at, purge_after, finished_at, undone_at, purged_at";

/// A deletion as its owner (status link) and node admins see it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AccountDeletion {
    pub id: String,
    /// The deleted account (admins only; empty for the status link).
    pub user_id: String,
    /// The address the account had (admins only).
    pub address: String,
    /// processing (content deletion running) | done | undone | purged
    pub state: String,
    pub delete_messages: bool,
    pub messages_total: i64,
    pub messages_done: i64,
    pub created_at: String,
    /// The admin can undo until then; afterwards the account is erased and the username is free.
    pub purge_after: String,
    pub finished_at: Option<String>,
    /// A node admin deleted the account (on request).
    pub by_admin: bool,
}

impl DeletionRow {
    pub fn to_api(&self, admin_view: bool) -> AccountDeletion {
        AccountDeletion {
            id: self.id.clone(),
            user_id: if admin_view { self.user_id.clone() } else { String::new() },
            address: if admin_view { self.address.clone() } else { String::new() },
            state: self.state.clone(),
            delete_messages: self.delete_messages != 0,
            messages_total: self.messages_total,
            messages_done: self.messages_done,
            created_at: self.created_at.clone(),
            purge_after: self.purge_after.clone(),
            finished_at: self.finished_at.clone(),
            by_admin: self.requested_by.as_deref().is_some_and(|r| !r.starts_with("node:")),
        }
    }
}

/// The answer to a deletion: the progress and, once, the token of the status link (`GET /account-deletions/{id}`).
#[derive(Debug, Serialize, ToSchema)]
pub struct DeletionStarted {
    #[serde(flatten)]
    pub deletion: AccountDeletion,
    pub status_token: String,
}

/// Body of `DELETE /users/me` and `POST /admin/users/{user_id}/delete`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    /// The account's username, typed to confirm.
    pub confirm: String,
    /// Also delete the content of every message and every file of the account (default: messages stay as
    /// "Deleted user").
    #[serde(default)]
    pub delete_messages: bool,
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<DeletionRow>, ApiError> {
    if !util::is_ulid(id) {
        return Ok(None);
    }
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM account_deletions WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// The open (not undone, not purged) deletion of an account.
pub async fn open_of_user(db: &Pool, user_id: &str) -> Result<Option<DeletionRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM account_deletions WHERE user_id = $1 AND state IN ('processing', 'done') ORDER BY id DESC LIMIT 1"
    ))
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

pub async fn list(db: &Pool, limit: i64) -> Result<Vec<DeletionRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM account_deletions WHERE requested_by IS NULL OR requested_by NOT LIKE 'node:%' ORDER BY id DESC LIMIT {limit}"
    ))
    .fetch_all(db)
    .await?)
}

/// The deletion's progress for the status link (same answer for unknown ids and wrong tokens).
pub async fn status_for_owner(db: &Pool, id: &str, token: &str) -> Result<AccountDeletion, ApiError> {
    use subtle::ConstantTimeEq;
    let row = by_id(db, id).await?;
    let presented = util::sha256_b64(token);
    let stored = row.as_ref().and_then(|r| r.status_token_hash.clone()).unwrap_or_else(|| util::sha256_b64("-"));
    let ok = bool::from(stored.as_bytes().ct_eq(presented.as_bytes())) && !token.is_empty();
    row.filter(|r| ok && r.status_token_hash.is_some())
        .map(|r| r.to_api(false))
        .ok_or_else(|| ApiError::NotFound { code: "account.deletion_not_found", what: "Deletion".into() })
}

fn tombstone_username() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("deleted-{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Creates the tombstone row of `user` (same domain, no credentials, disabled).
async fn create_tombstone(db: &Pool, user: &UserRow) -> Result<UserRow, ApiError> {
    let id = util::ulid();
    let now = util::now();
    sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, created_at, disabled_at, deleted_at)
         VALUES ($1, $2, $3, $4, 'user', $5, $5, $5)",
    )
    .bind(&id)
    .bind(tombstone_username())
    .bind(&user.domain)
    .bind(TOMBSTONE_NAME)
    .bind(&now)
    .execute(db)
    .await?;
    store::users::by_id(db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("tombstone missing")))
}

/// Moves what stays for the other users from `from` to `to` (tombstone and back for an undo): authorship, pins,
/// uploads, room emojis and sounds, issued bans and invites, notices, and the audit log's actor and texts.
async fn move_references(db: &Pool, from: &UserRow, to: &UserRow) -> Result<(), ApiError> {
    for (table, column) in [
        ("messages", "author_id"),
        ("message_search", "author_id"),
        ("pins", "pinned_by"),
        ("blobs", "uploader_id"),
        ("emojis", "uploader_id"),
        ("soundboard_sounds", "uploader_id"),
        ("bans", "actor_id"),
        ("invites", "creator_id"),
        ("account_invites", "created_by"),
        ("room_creation_grants", "granted_by"),
        ("audit_log", "actor_id"),
        ("legal_notices", "target_user_id"),
        ("legal_counter_notices", "user_id"),
        ("file_entries", "created_by"),
        ("conversations", "creator_id"),
        ("threads", "created_by"),
        ("threads", "title_author_id"),
    ] {
        sqlx::query(&format!("UPDATE {table} SET {column} = $1 WHERE {column} = $2"))
            .bind(&to.id)
            .bind(&from.id)
            .execute(db)
            .await?;
    }
    let (a, b) = (from.address(), to.address());
    sqlx::query("UPDATE legal_notices SET target_address = $1 WHERE target_address = $2")
        .bind(&b)
        .bind(&a)
        .execute(db)
        .await?;
    // Pseudonymised audit trail: the address and the account id in the texts become the tombstone's.
    sqlx::query(
        "UPDATE audit_log SET target = REPLACE(target, $1, $2), reason = REPLACE(reason, $1, $2),
           meta = REPLACE(REPLACE(meta, $1, $2), $3, $4)
         WHERE target LIKE $5 OR reason LIKE $5 OR meta LIKE $5 OR meta LIKE $6",
    )
    .bind(&a)
    .bind(&b)
    .bind(&from.id)
    .bind(&to.id)
    .bind(format!("%{a}%"))
    .bind(format!("%{}%", from.id))
    .execute(db)
    .await?;
    // Bots of the account keep their tombstone, owned by nobody (the owner row is erased later).
    sqlx::query("UPDATE users SET owner_address = $1 WHERE owner_id = $2 AND owner_address = $3")
        .bind(&b)
        .bind(&from.id)
        .bind(&a)
        .execute(db)
        .await?;
    Ok(())
}

/// Ends every room and conversation membership of `user` (events, MLS removals, voice) and returns the rooms and
/// the people who saw the user (for `user.deleted` events).
async fn end_memberships(state: &AppState, user: &UserRow) -> Result<(Vec<String>, Vec<String>), ApiError> {
    let mut rooms = Vec::new();
    for room_id in store::rooms::room_ids_of_user(&state.db, &user.id).await? {
        if store::rooms::remove_member(&state.db, &room_id, &user.id).await? {
            crate::subscriptions::room_event(
                state,
                &room_id,
                "member.leave",
                json!({ "room_id": room_id, "user_id": user.id, "deleted": true }),
            )
            .await;
            crate::e2ee::user_left_room(state, &room_id, user).await?;
            rooms.push(room_id);
        }
    }
    let mut people = Vec::new();
    for state_name in ["active", "requested"] {
        for conv in store::social::conversations_of(&state.db, &user.id, state_name).await? {
            let members = store::social::member_ids(&state.db, &conv.id).await?;
            if store::social::remove_member(&state.db, &conv.id, &user.id).await? {
                let others: Vec<String> = members.into_iter().filter(|m| m != &user.id).collect();
                state.hub.users(
                    others.clone(),
                    "conversation.member_deleted",
                    json!({ "conversation_id": conv.id, "user_id": user.id }),
                );
                crate::e2ee::user_left_conversation(state, &conv.id, user).await?;
                people.extend(others);
            }
        }
    }
    people.extend(store::social::contact_ids(&state.db, &user.id).await?);
    people.extend(store::social::friends_of(&state.db, &user.id).await?.into_iter().map(|(id, _)| id));
    people.sort();
    people.dedup();
    Ok((rooms, people))
}

/// Deletes everything personal of `user` that never stays (see the module docs). The account row keeps only what an
/// undo needs (username, password hash, e-mail, single sign-on link).
async fn erase_personal(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    let db = &state.db;
    // Applications: deleted like the owner would (tokens, devices, memberships; the bot stays a tombstone).
    for app in store::applications::of_owner(db, &user.id).await? {
        crate::applications::delete_application(state, &app, user).await?;
    }
    sqlx::query("UPDATE users SET owner_id = NULL WHERE owner_id = $1").bind(&user.id).execute(db).await?;
    // Devices and keys: MLS removals for every leaf, then the rows (sessions, key packages and device keys cascade).
    let devices: Vec<String> = store::users::devices_of(db, &user.id).await?.into_iter().map(|d| d.id).collect();
    for device in &devices {
        crate::e2ee::device_removed(state, user, device).await?;
    }
    if !devices.is_empty() {
        state.hub.devices(devices.clone(), crate::federation::inbox::SESSION_REVOKED_EVENT, json!({}));
    }
    for table in [
        "sessions",
        "devices",
        "key_packages",
        "secret_storage",
        "key_backups",
        "identity_continuity",
        "retired_devices",
        "device_tombstones",
        "conversation_index",
        "user_invites",
        "push_hints",
        "read_markers",
        "notification_settings",
        "whiteboard_scenes",
        "user_emojis",
        "user_sounds",
        "reactions",
        "totp_secrets",
        "recovery_codes",
        "webauthn_credentials",
        "webauthn_challenges",
        "sso_grants",
        "history_pending",
        "federation_targets",
        "friend_sync",
        "email_verifications",
        "password_resets",
        "terms_acceptances",
        "directory_reports",
        "application_transfers",
    ] {
        let column = match table {
            "application_transfers" => "from_user_id",
            "directory_reports" => "reporter_id",
            _ => "user_id",
        };
        sqlx::query(&format!("DELETE FROM {table} WHERE {column} = $1")).bind(&user.id).execute(db).await?;
    }
    sqlx::query("DELETE FROM application_transfers WHERE to_user_id = $1").bind(&user.id).execute(db).await?;
    sqlx::query("DELETE FROM friends WHERE user_id = $1 OR friend_id = $1").bind(&user.id).execute(db).await?;
    sqlx::query("DELETE FROM friend_requests WHERE from_user_id = $1 OR to_user_id = $1")
        .bind(&user.id)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM friend_sync WHERE other_id = $1").bind(&user.id).execute(db).await?;
    sqlx::query("DELETE FROM user_blocks WHERE user_id = $1 OR blocked_id = $1").bind(&user.id).execute(db).await?;
    sqlx::query("DELETE FROM admin_tokens WHERE created_by = $1").bind(&user.id).execute(db).await?;
    sqlx::query("DELETE FROM room_creation_grants WHERE user_id = $1").bind(&user.id).execute(db).await?;
    // Profile: images go with their files, texts are cleared.
    use crate::media::MediaKind;
    for kind in [MediaKind::Avatar, MediaKind::Header, MediaKind::Background] {
        crate::profile::set_user_media(state, &user.id, kind, None).await?;
    }
    sqlx::query(
        "UPDATE users SET display_name = username, bio = '', links = '[]', custom_status = NULL, presence_status = 'invisible',
           identity_pubkey = NULL, identity_reset_at = NULL, is_node_admin = 0, profile_version = profile_version + 1
         WHERE id = $1",
    )
    .bind(&user.id)
    .execute(db)
    .await?;
    Ok(())
}

/// Node-written entries about the user (welcome channel join/leave, key changes) carry the name in their content:
/// they go instead of moving to the tombstone.
async fn delete_system_entries(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM messages WHERE author_id = $1 AND device_id IS NULL AND content LIKE '%\"type\":\"system.%'",
    )
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(())
}

/// The account `user` owns rooms: they must be transferred (`POST /rooms/{id}/transfer`) or deleted first.
async fn check_owned_rooms(db: &Pool, user: &UserRow) -> Result<(), ApiError> {
    let rooms: Vec<(String, String)> = sqlx::query_as("SELECT id, name FROM rooms WHERE owner_id = $1 ORDER BY id")
        .bind(&user.id)
        .fetch_all(db)
        .await?;
    if rooms.is_empty() {
        return Ok(());
    }
    Err(ApiError::Conflict {
        code: "account.owns_rooms",
        detail: "Transfer or delete the rooms this account owns first".into(),
        meta: json!({ "rooms": rooms.iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>() }),
    })
}

/// Strips device ids and signatures of the tombstone's messages: nothing in the envelopes links back to the
/// account's devices.
async fn strip_envelopes(db: &Pool, tombstone_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE messages SET device_id = NULL, signature = NULL WHERE author_id = $1")
        .bind(tombstone_id)
        .execute(db)
        .await?;
    sqlx::query("UPDATE threads SET title_device_id = NULL WHERE title_author_id = $1")
        .bind(tombstone_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Deletes the local account `user` (by the user or `admin`). Returns the deletion and the status token.
pub async fn delete_local(
    state: &AppState,
    user: &UserRow,
    admin: Option<&UserRow>,
    delete_messages: bool,
) -> Result<DeletionStarted, ApiError> {
    if user.domain != state.config.domain || user.is_bot() {
        return Err(ApiError::NotFound { code: "user.not_found", what: "User".into() });
    }
    if user.deleted_at.is_some() {
        return Err(ApiError::conflict("account.deleted", "This account is already deleted"));
    }
    check_owned_rooms(&state.db, user).await?;
    // Who hears about it, computed before friendships and memberships go.
    let domains = crate::federation::remote::notification_domains(state, user).await.unwrap_or_default();
    let mut domains = domains;
    for d in membership_domains(&state.db, &user.id).await? {
        if !domains.contains(&d) {
            domains.push(d);
        }
    }
    let tombstone = tombstone_user(state, user).await?;
    // The account row: disabled at once (every session ends), the username stays reserved.
    let now = util::now();
    sqlx::query("UPDATE users SET deleted_at = $1, disabled_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(&user.id)
        .execute(&state.db)
        .await?;
    crate::federation::remote::revoke_sessions(state, user, None).await?;
    for domain in domains.iter().filter(|d| **d != state.config.domain) {
        if crate::federation::check_policy(state, domain).await.is_err() {
            continue;
        }
        let payload = json!({ "delete_messages": delete_messages });
        if let Err(e) = crate::federation::outbox::enqueue(state, domain, KIND, &user.address(), domain, payload).await
        {
            tracing::warn!(error = %e, domain, "user.deleted could not be queued");
        }
    }
    let token = util::random_token(32);
    let id = util::ulid();
    let purge_after = util::in_seconds(i64::from(state.config.account_delete_grace_days) * 24 * 3600);
    insert_deletion(
        &state.db,
        &id,
        user,
        &tombstone,
        admin.map(|a| a.id.as_str()),
        delete_messages,
        Some(&token),
        &purge_after,
    )
    .await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(admin.map_or(tombstone.id.as_str(), |a| a.id.as_str())),
        if admin.is_some() { "admin.user_delete" } else { "user.delete" },
        &tombstone.address(),
        "",
        json!({ "deletion_id": id, "delete_messages": delete_messages, "user_id": user.id }),
    )
    .await?;
    if let Some(email) = user.email.as_deref() {
        let body = format!(
            "The account {} on {} was deleted{}.\n\nA node admin can undo the deletion until {purge_after}; after that the account is erased and the username becomes free.",
            user.address(),
            state.config.domain,
            if admin.is_some() { " by a node admin" } else { "" }
        );
        state.mailer.send(email, "Account deleted", &body).await;
    }
    let row = by_id(&state.db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("deletion missing")))?;
    if delete_messages {
        spawn_redaction(state, id.clone());
    }
    Ok(DeletionStarted { deletion: row.to_api(admin.is_some()), status_token: token })
}

/// The domains of rooms the user joined on other nodes (the conversation index) — they host the user's messages.
async fn membership_domains(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    let index: Option<String> = sqlx::query_scalar("SELECT items FROM conversation_index WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .unwrap_or(None);
    let mut out: Vec<String> = Vec::new();
    if let Some(items) = index.and_then(|i| serde_json::from_str::<Value>(&i).ok()) {
        for item in items.as_array().into_iter().flatten() {
            if let Some(node) = item.get("node").and_then(Value::as_str).filter(|n| util::valid_domain(n))
                && !out.iter().any(|o| o == node)
            {
                out.push(node.to_string());
            }
        }
    }
    let targets: Vec<String> = sqlx::query_scalar("SELECT DISTINCT target FROM federation_targets WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    for t in targets {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn insert_deletion(
    db: &Pool,
    id: &str,
    user: &UserRow,
    tombstone: &UserRow,
    requested_by: Option<&str>,
    delete_messages: bool,
    token: Option<&str>,
    purge_after: &str,
) -> Result<(), ApiError> {
    let total: i64 = if delete_messages {
        sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE author_id = $1")
            .bind(&tombstone.id)
            .fetch_one(db)
            .await?
    } else {
        0
    };
    let now = util::now();
    sqlx::query(
        "INSERT INTO account_deletions (id, user_id, tombstone_id, address, requested_by, delete_messages, state, messages_total,
           messages_done, status_token_hash, created_at, purge_after, finished_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(&user.id)
    .bind(&tombstone.id)
    .bind(user.address())
    .bind(requested_by)
    .bind(delete_messages as i64)
    .bind(if delete_messages { "processing" } else { "done" })
    .bind(total)
    .bind(token.map(util::sha256_b64))
    .bind(&now)
    .bind(purge_after)
    .bind((!delete_messages).then_some(now.clone()))
    .execute(db)
    .await?;
    Ok(())
}

/// The shared part of a local deletion and a remote `user.deleted`: tombstone, moved references, stripped envelopes,
/// ended memberships, erased personal data, events to the people who saw the user.
async fn tombstone_user(state: &AppState, user: &UserRow) -> Result<UserRow, ApiError> {
    delete_system_entries(&state.db, &user.id).await?;
    let tombstone = create_tombstone(&state.db, user).await?;
    move_references(&state.db, user, &tombstone).await?;
    strip_envelopes(&state.db, &tombstone.id).await?;
    let (rooms, people) = end_memberships(state, user).await?;
    erase_personal(state, user).await?;
    let data = json!({ "user_id": user.id, "address": user.address(), "tombstone": tombstone.to_public() });
    for room_id in &rooms {
        state.hub.room(room_id, "user.deleted", &data);
    }
    if !people.is_empty() {
        state.hub.users(people, "user.deleted", &data);
    }
    Ok(tombstone)
}

/// S2S `user.deleted` (§5.2) from the user's home node: the stub here is tombstoned the same way (no undo), its
/// message content deleted when the user asked for it; the request is recorded in the audit log.
pub async fn receive_remote(
    state: &AppState,
    iss: &str,
    user: &UserRow,
    payload: &Value,
) -> Result<&'static str, ApiError> {
    if user.domain != iss || user.domain == state.config.domain || user.deleted_at.is_some() {
        return Ok("ignored");
    }
    let delete_messages = payload.get("delete_messages").and_then(Value::as_bool).unwrap_or(false);
    let tombstone = tombstone_user(state, user).await?;
    sqlx::query("DELETE FROM remote_users WHERE user_id = $1").bind(&user.id).execute(&state.db).await?;
    let id = util::ulid();
    insert_deletion(
        &state.db,
        &id,
        user,
        &tombstone,
        Some(&format!("node:{iss}")),
        delete_messages,
        None,
        &util::now(),
    )
    .await?;
    store::rooms::audit(
        &state.db,
        None,
        None,
        "federation.user_deleted",
        &tombstone.address(),
        "",
        json!({ "origin": iss, "deletion_id": id, "delete_messages": delete_messages }),
    )
    .await?;
    // The stub goes now: nothing refers to it any more (a later federated login creates a new one).
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = $1").bind(&user.id).execute(&state.db).await {
        tracing::warn!(error = %e, user = user.address(), "remote stub not deletable, renamed");
        sqlx::query(
            "UPDATE users SET username = $1, deleted_at = $2, disabled_at = $2, age_over_18 = NULL WHERE id = $3",
        )
        .bind(tombstone_username())
        .bind(util::now())
        .bind(&user.id)
        .execute(&state.db)
        .await?;
    }
    if delete_messages {
        spawn_redaction(state, id);
    }
    Ok("handled")
}

/// Undo by a node admin within the grace period: the account comes back (username, password, e-mail, single sign-on
/// link) with its messages and uploads; memberships, friends, devices and keys do not (the user signs in, sets up a
/// second factor and a new key). Message content already deleted stays deleted.
pub async fn undelete(state: &AppState, admin: &UserRow, user_id: &str) -> Result<AccountDeletion, ApiError> {
    let row = open_of_user(&state.db, user_id)
        .await?
        .filter(|r| r.requested_by.as_deref().is_none_or(|r| !r.starts_with("node:")))
        .ok_or_else(|| ApiError::NotFound { code: "account.deletion_not_found", what: "Deletion".into() })?;
    if row.purge_after.as_str() <= util::now().as_str() {
        return Err(ApiError::conflict("account.undo_expired", "The grace period of this deletion is over"));
    }
    let user = store::users::by_id(&state.db, &row.user_id)
        .await?
        .ok_or_else(|| ApiError::conflict("account.undo_expired", "The account was erased"))?;
    let tombstone = store::users::by_id(&state.db, &row.tombstone_id).await?;
    if let Some(t) = &tombstone {
        move_references(&state.db, t, &user).await?;
    }
    sqlx::query("UPDATE users SET deleted_at = NULL, disabled_at = NULL WHERE id = $1")
        .bind(&user.id)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE account_deletions SET state = 'undone', undone_at = $1 WHERE id = $2")
        .bind(util::now())
        .bind(&row.id)
        .execute(&state.db)
        .await?;
    // The tombstone row stays (the deletion record names it); nothing refers to it any more and it is hidden.
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.id),
        "admin.user_undelete",
        &user.address(),
        "",
        json!({ "deletion_id": row.id }),
    )
    .await?;
    if let Some(email) = user.email.as_deref() {
        state
            .mailer
            .send(
                email,
                "Account restored",
                &format!("A node admin restored the account {}. Sign in again to use it.", user.address()),
            )
            .await;
    }
    Ok(by_id(&state.db, &row.id).await?.unwrap_or(row).to_api(true))
}

// ---------------------------------------------------------------- content deletion job

fn spawn_redaction(state: &AppState, deletion_id: String) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = redact(&state, &deletion_id).await {
            tracing::warn!(error = %e, deletion = deletion_id, "content deletion stopped; housekeeping continues it");
        }
    });
}

/// Deletes the content of the tombstone's messages batch by batch (plaintext and ciphertext, files, search terms)
/// and keeps a placeholder in each slot. Idempotent; housekeeping resumes deletions a restart interrupted.
pub async fn redact(state: &AppState, deletion_id: &str) -> Result<(), ApiError> {
    let Some(row) = by_id(&state.db, deletion_id).await? else { return Ok(()) };
    if row.state != "processing" {
        return Ok(());
    }
    loop {
        let batch: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT id, conversation_id FROM messages WHERE author_id = $1 AND NOT (encrypted = 0 AND content = $2)
             ORDER BY id LIMIT {BATCH}"
        ))
        .bind(&row.tombstone_id)
        .bind(PLACEHOLDER)
        .fetch_all(&state.db)
        .await?;
        if batch.is_empty() {
            break;
        }
        let ids: Vec<String> = batch.iter().map(|(id, _)| id.clone()).collect();
        let blobs = store::blobs::by_messages(&state.db, &ids).await?;
        for chunk in ids.chunks(100) {
            let list = (3..3 + chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
            let update = format!(
                "UPDATE messages SET content = $1, content_size = $2, encrypted = 0, epoch = NULL, mentions = '[]',
                   mentions_everyone = 0, device_id = NULL, signature = NULL WHERE id IN ({list})"
            );
            let mut q = sqlx::query(&update).bind(PLACEHOLDER).bind(PLACEHOLDER.len() as i64);
            for id in chunk {
                q = q.bind(id);
            }
            q.execute(&state.db).await?;
            let list = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
            for table in ["message_search", "blobs"] {
                let delete = format!("DELETE FROM {table} WHERE message_id IN ({list})");
                let mut q = sqlx::query(&delete);
                for id in chunk {
                    q = q.bind(id);
                }
                q.execute(&state.db).await?;
            }
        }
        for b in blobs.values().flatten() {
            state.storage.delete(&b.id).await;
        }
        let mut by_conversation: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for (id, conversation) in &batch {
            by_conversation.entry(conversation.clone()).or_default().push(id.clone());
        }
        for (conversation_id, ids) in by_conversation {
            let room_id = store::social::conversation(&state.db, &conversation_id).await?.and_then(|c| c.room_id);
            super::notices::publish_to_conversation(
                state,
                &conversation_id,
                "message.redact",
                json!({ "room_id": room_id, "conversation_id": conversation_id, "ids": ids, "author_id": row.tombstone_id }),
            )
            .await;
        }
        sqlx::query("UPDATE account_deletions SET messages_done = messages_done + $1 WHERE id = $2")
            .bind(batch.len() as i64)
            .bind(&row.id)
            .execute(&state.db)
            .await?;
        // Undone meanwhile: the remaining messages belong to the account again.
        if by_id(&state.db, &row.id).await?.is_none_or(|r| r.state != "processing") {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    sqlx::query("UPDATE account_deletions SET state = 'done', finished_at = $1, messages_done = messages_total WHERE id = $2 AND state = 'processing'")
        .bind(util::now())
        .bind(&row.id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Housekeeping: resumes interrupted content deletions and erases accounts whose grace period ended (the username
/// becomes free). Returns (resumed, purged).
pub async fn housekeeping(state: &AppState, now: chrono::DateTime<chrono::Utc>) -> Result<(usize, usize), ApiError> {
    let processing: Vec<String> =
        sqlx::query_scalar("SELECT id FROM account_deletions WHERE state = 'processing'").fetch_all(&state.db).await?;
    for id in &processing {
        redact(state, id).await?;
    }
    let due: Vec<DeletionRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM account_deletions WHERE state = 'done' AND purge_after < $1 AND purged_at IS NULL"
    ))
    .bind(util::format_time(now))
    .fetch_all(&state.db)
    .await?;
    let mut purged = 0;
    for d in &due {
        purge(state, d).await?;
        purged += 1;
    }
    Ok((processing.len(), purged))
}

/// Erases the account row after the grace period (everything still tied to it cascades).
async fn purge(state: &AppState, d: &DeletionRow) -> Result<(), ApiError> {
    let still_deleted = store::users::by_id(&state.db, &d.user_id).await?.is_some_and(|u| u.deleted_at.is_some());
    if still_deleted
        && let Err(e) = sqlx::query("DELETE FROM users WHERE id = $1").bind(&d.user_id).execute(&state.db).await
    {
        // Something still refers to the row: free the username at least, the rest stays disabled.
        tracing::warn!(error = %e, user = d.user_id, "deleted account not erasable, username released");
        sqlx::query(
            "UPDATE users SET username = $1, email = NULL, password_hash = NULL, date_of_birth = NULL WHERE id = $2",
        )
        .bind(tombstone_username())
        .bind(&d.user_id)
        .execute(&state.db)
        .await?;
        sqlx::query("DELETE FROM external_identities WHERE user_id = $1").bind(&d.user_id).execute(&state.db).await?;
    }
    sqlx::query(
        "UPDATE account_deletions SET state = 'purged', purged_at = $1, status_token_hash = NULL WHERE id = $2",
    )
    .bind(util::now())
    .bind(&d.id)
    .execute(&state.db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn tombstone_names_are_valid_usernames() {
        let name = super::tombstone_username();
        assert!(crate::util::valid_username(&name), "{name}");
        assert!(name.starts_with("deleted-"));
        assert_ne!(name, super::tombstone_username());
    }
}
