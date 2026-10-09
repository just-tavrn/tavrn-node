// SPDX-License-Identifier: AGPL-3.0-only
//! Data access and portability (GDPR Art. 15 and 20, protocol/LEGAL.md §3.1).
//!
//! `GET /users/me/export` is a JSON archive of everything this node holds about the account in plaintext. It is
//! **streamed**: the account sections are small and built at once, the messages follow page by page straight from
//! the database, so an account with a million messages needs no background job and no temporary file, and the
//! request is not bound by the 30-second request timeout (the response starts at once). Not in the archive: secrets
//! and key material (password hash, TOTP secret, recovery codes, passkey keys, refresh tokens, the secret storage and
//! key backups, identity and device keys, KeyPackages), ciphertext (encrypted messages are listed with their metadata
//! only: the node cannot read them, the user's devices can), files (the attachment list names them) and other users'
//! data beyond the addresses of the user's own contacts.
//!
//! `GET /users/me/data` is the human-readable summary of the same: categories with counts and since when, the nodes
//! the account is shared with, the applications with access, and the operator's retention periods.

use axum::body::{Body, Bytes};
use serde::Serialize;
use serde_json::{Map, Value, json};
use utoipa::ToSchema;

use crate::{app::AppState, error::ApiError, models::UserRow, util};

/// Messages per page of the stream.
const PAGE: i64 = 500;
pub const FORMAT: &str = "tavrn.export.v1";

/// `[(a, b, …)]` rows as JSON objects with the given keys (portable: no JSON functions in SQL).
async fn table(state: &AppState, sql: &str, user_id: &str, keys: &[&str]) -> Result<Vec<Value>, ApiError> {
    use sqlx::Row;
    let out = sqlx::query(sql).bind(user_id).fetch_all(&state.db).await?;
    let mut items = Vec::with_capacity(out.len());
    for r in out {
        let mut m = Map::new();
        for (i, k) in keys.iter().enumerate() {
            let v: Value = if let Ok(s) = r.try_get::<Option<String>, _>(i) {
                s.map(Value::String).unwrap_or(Value::Null)
            } else if let Ok(n) = r.try_get::<Option<i64>, _>(i) {
                n.map(Value::from).unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            m.insert((*k).to_string(), v);
        }
        items.push(Value::Object(m));
    }
    Ok(items)
}

/// Everything but the messages, as one JSON object.
pub async fn head(state: &AppState, user: &UserRow) -> Result<Map<String, Value>, ApiError> {
    let id = user.id.as_str();
    let (bio, links, _) = crate::store::users::profile_extra(&state.db, id).await.unwrap_or_default();
    let mut m = Map::new();
    m.insert("format".into(), json!(FORMAT));
    m.insert("generated_at".into(), json!(util::now()));
    m.insert("node".into(), json!(state.config.domain));
    m.insert(
        "note".into(),
        json!("Everything this node holds about the account in plaintext. Encrypted messages are listed without their content (only your devices can read them); secrets and keys are never exported."),
    );
    m.insert(
        "account".into(),
        json!({
            "id": user.id,
            "address": user.address(),
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "email_verified": user.email_verified_at.is_some(),
            "created_at": user.created_at,
            "node_admin": user.is_node_admin(),
            "has_password": user.password_hash.is_some(),
            "has_identity_key": user.identity_pubkey.is_some(),
            "dm_policy": user.dm_policy,
            "presence_status": user.presence_status,
            "custom_status": user.custom_status.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()),
            "hide_activity": user.hide_activity != 0,
            "auto_preview": crate::store::users::auto_preview(&state.db, id).await.ok(),
            // The self-declared date of birth (PROTOCOL.md §5e).
            "date_of_birth": user.date_of_birth,
        }),
    );
    m.insert(
        "profile".into(),
        json!({
            "bio": bio,
            "links": serde_json::from_str::<Value>(&links).unwrap_or(json!([])),
            "avatar": crate::models::media_url(user.avatar_blob_id.as_deref(), false),
            "header": crate::models::media_url(user.header_blob_id.as_deref(), false),
        }),
    );
    m.insert(
        "notification_settings".into(),
        serde_json::to_value(crate::notifications::load(&state.db, id).await?).unwrap_or(Value::Null),
    );
    m.insert(
        "devices".into(),
        json!(
            table(
                state,
                "SELECT id, name, client, created_at, last_seen_at FROM devices WHERE user_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "client", "created_at", "last_seen_at"]
            )
            .await?
        ),
    );
    m.insert(
        "sessions".into(),
        json!(table(state, "SELECT device_id, created_at, expires_at, revoked_at FROM sessions WHERE user_id = $1 ORDER BY created_at", id, &["device_id", "created_at", "expires_at", "revoked_at"]).await?),
    );
    let totp: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM totp_secrets WHERE user_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await?;
    m.insert(
        "second_factor".into(),
        json!({
            "totp": totp > 0,
            "recovery_codes": codes,
            "passkeys": table(state, "SELECT name, created_at, last_used_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at", id, &["name", "created_at", "last_used_at"]).await?,
        }),
    );
    m.insert(
        "single_sign_on".into(),
        json!(
            table(
                state,
                "SELECT issuer, subject, linked_at, last_login_at FROM external_identities WHERE user_id = $1",
                id,
                &["issuer", "subject", "linked_at", "last_login_at"]
            )
            .await?
        ),
    );
    m.insert(
        "rooms".into(),
        json!(table(state, "SELECT r.id, r.name, m.joined_at, m.nickname, m.bio FROM room_members m JOIN rooms r ON r.id = m.room_id WHERE m.user_id = $1 ORDER BY m.joined_at", id, &["id", "name", "joined_at", "nickname", "room_bio"]).await?),
    );
    m.insert(
        "room_roles".into(),
        json!(table(state, "SELECT mr.room_id, ro.name FROM member_roles mr JOIN roles ro ON ro.id = mr.role_id WHERE mr.user_id = $1 ORDER BY mr.room_id", id, &["room_id", "role"]).await?),
    );
    m.insert(
        "rooms_owned".into(),
        json!(
            table(
                state,
                "SELECT id, name, created_at FROM rooms WHERE owner_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "created_at"]
            )
            .await?
        ),
    );
    m.insert(
        "conversations".into(),
        json!(table(state, "SELECT c.id, c.kind, c.created_at, cm.state FROM conversation_members cm JOIN conversations c ON c.id = cm.conversation_id WHERE cm.user_id = $1 ORDER BY c.created_at", id, &["id", "kind", "created_at", "state"]).await?),
    );
    m.insert(
        "conversation_members".into(),
        json!(table(state, "SELECT cm2.conversation_id, u.username || '@' || u.domain FROM conversation_members cm JOIN conversation_members cm2 ON cm2.conversation_id = cm.conversation_id JOIN users u ON u.id = cm2.user_id WHERE cm.user_id = $1 AND cm2.user_id <> cm.user_id ORDER BY cm2.conversation_id", id, &["conversation_id", "member"]).await?),
    );
    m.insert(
        "friends".into(),
        json!(table(state, "SELECT u.username || '@' || u.domain, f.created_at FROM friends f JOIN users u ON u.id = f.friend_id WHERE f.user_id = $1 ORDER BY f.created_at", id, &["address", "since"]).await?),
    );
    m.insert(
        "friend_requests".into(),
        json!(table(state, "SELECT CASE WHEN r.from_user_id = $1 THEN 'outgoing' ELSE 'incoming' END, u.username || '@' || u.domain, r.created_at FROM friend_requests r JOIN users u ON u.id = CASE WHEN r.from_user_id = $1 THEN r.to_user_id ELSE r.from_user_id END WHERE r.from_user_id = $1 OR r.to_user_id = $1", id, &["direction", "address", "created_at"]).await?),
    );
    m.insert(
        "blocks".into(),
        json!(table(state, "SELECT u.username || '@' || u.domain, b.created_at FROM user_blocks b JOIN users u ON u.id = b.blocked_id WHERE b.user_id = $1", id, &["address", "created_at"]).await?),
    );
    m.insert(
        "attachments".into(),
        json!(table(state, "SELECT b.id, CASE WHEN c.encrypted = 0 THEN b.name ELSE NULL END, b.mime, b.size, b.created_at, b.conversation_id, b.message_id, b.expired_at FROM blobs b JOIN conversations c ON c.id = b.conversation_id WHERE b.uploader_id = $1 ORDER BY b.created_at", id, &["id", "name", "mime", "size", "created_at", "conversation_id", "message_id", "expired_at"]).await?),
    );
    m.insert(
        "reactions".into(),
        json!(
            table(
                state,
                "SELECT message_id, emoji, created_at FROM reactions WHERE user_id = $1 ORDER BY created_at",
                id,
                &["message_id", "emoji", "created_at"]
            )
            .await?
        ),
    );
    m.insert(
        "personal_emojis".into(),
        json!(
            table(
                state,
                "SELECT id, name, mime, size, created_at FROM user_emojis WHERE user_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "mime", "size", "created_at"]
            )
            .await?
        ),
    );
    m.insert(
        "personal_sounds".into(),
        json!(
            table(
                state,
                "SELECT id, name, mime, size, created_at FROM user_sounds WHERE user_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "mime", "size", "created_at"]
            )
            .await?
        ),
    );
    m.insert(
        "whiteboards".into(),
        json!(
            table(
                state,
                "SELECT id, name, created_at, updated_at FROM whiteboard_scenes WHERE user_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "created_at", "updated_at"]
            )
            .await?
        ),
    );
    m.insert(
        "applications".into(),
        json!(
            table(
                state,
                "SELECT id, name, created_at FROM applications WHERE owner_id = $1 ORDER BY created_at",
                id,
                &["id", "name", "created_at"]
            )
            .await?
        ),
    );
    m.insert(
        "terms_acceptances".into(),
        json!(
            table(
                state,
                "SELECT version, accepted_at FROM terms_acceptances WHERE user_id = $1 ORDER BY version",
                id,
                &["version", "accepted_at"]
            )
            .await?
        ),
    );
    // Audit entries about the account: its own node-level actions and entries naming it (never other members' rows).
    let address = user.address();
    let audit: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, action, target, reason, created_at FROM audit_log
         WHERE (actor_id = $1 AND room_id IS NULL) OR target = $2 ORDER BY id LIMIT 10000",
    )
    .bind(id)
    .bind(&address)
    .fetch_all(&state.db)
    .await?;
    m.insert(
        "audit_log".into(),
        json!(audit.into_iter().map(|(id, action, target, reason, at)| json!({ "id": id, "action": action, "target": target, "reason": reason, "created_at": at })).collect::<Vec<_>>()),
    );
    // Notices about the account's content: the decision and statement, never the reporter's data.
    m.insert(
        "legal_notices".into(),
        json!(table(state, "SELECT id, basis, state, statement, created_at, decided_at FROM legal_notices WHERE target_user_id = $1 ORDER BY id", id, &["case_id", "basis", "state", "statement", "created_at", "decided_at"]).await?),
    );
    m.insert("federation".into(), json!({ "nodes": shared_nodes(state, id).await? }));
    m.insert("retention".into(), retention(state));
    Ok(m)
}

/// The nodes the account is shared with: federated sessions (federation tokens issued) and conversations hosted on
/// other nodes.
pub async fn shared_nodes(state: &AppState, user_id: &str) -> Result<Vec<String>, ApiError> {
    let mut nodes: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT target FROM federation_targets WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    let index: Option<String> = sqlx::query_scalar("SELECT items FROM conversation_index WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    if let Some(items) = index.and_then(|i| serde_json::from_str::<Value>(&i).ok()) {
        for item in items.as_array().into_iter().flatten() {
            if let Some(node) = item.get("node").and_then(Value::as_str)
                && node != state.config.domain
                && util::valid_domain(node)
            {
                nodes.push(node.to_string());
            }
        }
    }
    nodes.sort();
    nodes.dedup();
    Ok(nodes)
}

fn retention(state: &AppState) -> Value {
    let c = &state.config;
    json!({
        "session_refresh_days": c.session_refresh_days,
        "device_stale_days": c.device_stale_days,
        "attachment_retention_days": c.attachment_retention_days,
        "legal_notice_retention_days": c.legal_notice_retention_days,
        "account_delete_grace_days": c.account_delete_grace_days,
        "remote_user_retention_days": c.federation_remote_user_retention_days,
    })
}

fn message_json(r: &(String, String, String, i64, String, Option<String>, Option<String>, i64)) -> Value {
    let (id, conversation_id, content, encrypted, created_at, edited_at, reply_to_id, size) = r;
    json!({
        "id": id,
        "conversation_id": conversation_id,
        "created_at": created_at,
        "edited_at": edited_at,
        "reply_to_id": reply_to_id,
        "encrypted": *encrypted != 0,
        "size": size,
        // The node cannot read ciphertext: it is left out.
        "content": if *encrypted != 0 { Value::Null } else { serde_json::from_str::<Value>(content).unwrap_or(Value::Null) },
    })
}

type MessageRow = (String, String, String, i64, String, Option<String>, Option<String>, i64);

/// The archive as a streamed JSON body: the head object, then `"messages": [...]` page by page.
pub async fn stream(state: AppState, user: UserRow) -> Result<Body, ApiError> {
    let head = head(&state, &user).await?;
    let mut text = serde_json::to_string(&Value::Object(head)).map_err(|e| ApiError::Internal(e.into()))?;
    text.pop(); // the closing brace: the messages follow
    text.push_str(",\"messages\":[");
    enum Phase {
        Head(String),
        Page { after: String, first: bool },
        Done,
    }
    let user_id = user.id.clone();
    let stream = futures::stream::unfold(Phase::Head(text), move |phase| {
        let state = state.clone();
        let user_id = user_id.clone();
        async move {
            match phase {
                Phase::Head(t) => Some((
                    Ok::<Bytes, std::io::Error>(Bytes::from(t)),
                    Phase::Page { after: String::new(), first: true },
                )),
                Phase::Page { after, first } => {
                    let page: Result<Vec<MessageRow>, sqlx::Error> = sqlx::query_as(&format!(
                        "SELECT id, conversation_id, content, encrypted, created_at, edited_at, reply_to_id, content_size
                         FROM messages WHERE author_id = $1 AND id > $2 AND NOT (device_id IS NULL AND content LIKE '%\"type\":\"system.%')
                         ORDER BY id LIMIT {PAGE}"
                    ))
                    .bind(&user_id)
                    .bind(&after)
                    .fetch_all(&state.db)
                    .await;
                    match page {
                        Err(e) => Some((Err(std::io::Error::other(e)), Phase::Done)),
                        Ok(rows) if rows.is_empty() => Some((Ok(Bytes::from_static(b"]}")), Phase::Done)),
                        Ok(rows) => {
                            let mut chunk = String::new();
                            let mut first = first;
                            for r in &rows {
                                if !first {
                                    chunk.push(',');
                                }
                                first = false;
                                chunk.push_str(&message_json(r).to_string());
                            }
                            let after = rows.last().map(|r| r.0.clone()).unwrap_or_default();
                            Some((Ok(Bytes::from(chunk)), Phase::Page { after, first }))
                        }
                    }
                }
                Phase::Done => None,
            }
        }
    });
    Ok(Body::from_stream(stream))
}

/// One category of the summary.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataCategory {
    /// account, profile, devices, sessions, rooms, conversations, friends, blocks, messages, encrypted_messages,
    /// attachments, reactions, personal_emojis, personal_sounds, whiteboards, applications, audit_log,
    /// legal_notices, terms_acceptances
    pub key: String,
    pub count: i64,
    /// Oldest entry (null when empty or not dated).
    pub since: Option<String>,
}

/// An application with access to the account's data.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataApplication {
    pub name: String,
    /// owned (the user's own application) | room (a bot in one of the user's rooms; it reads what the room lets it)
    pub relation: String,
    /// The room, for `room`.
    pub room: Option<String>,
}

/// `GET /users/me/data`: what the node holds, in plain words for the "My data" page.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataSummary {
    pub address: String,
    pub created_at: String,
    pub categories: Vec<DataCategory>,
    /// Other nodes the account is shared with (federated sessions, conversations hosted elsewhere).
    pub nodes: Vec<String>,
    pub applications: Vec<DataApplication>,
    /// The operator's retention settings (days; 0 = kept until deleted).
    #[schema(value_type = Object)]
    pub retention: Value,
}

pub async fn summary(state: &AppState, user: &UserRow) -> Result<DataSummary, ApiError> {
    let id = user.id.as_str();
    let mut categories = vec![DataCategory { key: "account".into(), count: 1, since: Some(user.created_at.clone()) }];
    for (key, sql) in [
        ("devices", "SELECT COUNT(*), MIN(created_at) FROM devices WHERE user_id = $1"),
        ("sessions", "SELECT COUNT(*), MIN(created_at) FROM sessions WHERE user_id = $1"),
        ("rooms", "SELECT COUNT(*), MIN(joined_at) FROM room_members WHERE user_id = $1"),
        (
            "conversations",
            "SELECT COUNT(*), MIN(c.created_at) FROM conversation_members m JOIN conversations c ON c.id = m.conversation_id WHERE m.user_id = $1",
        ),
        ("friends", "SELECT COUNT(*), MIN(created_at) FROM friends WHERE user_id = $1"),
        ("blocks", "SELECT COUNT(*), MIN(created_at) FROM user_blocks WHERE user_id = $1"),
        (
            "messages",
            "SELECT COUNT(*), MIN(created_at) FROM messages WHERE author_id = $1 AND encrypted = 0 AND device_id IS NOT NULL",
        ),
        (
            "encrypted_messages",
            "SELECT COUNT(*), MIN(created_at) FROM messages WHERE author_id = $1 AND encrypted <> 0",
        ),
        ("attachments", "SELECT COUNT(*), MIN(created_at) FROM blobs WHERE uploader_id = $1"),
        ("reactions", "SELECT COUNT(*), MIN(created_at) FROM reactions WHERE user_id = $1"),
        ("personal_emojis", "SELECT COUNT(*), MIN(created_at) FROM user_emojis WHERE user_id = $1"),
        ("personal_sounds", "SELECT COUNT(*), MIN(created_at) FROM user_sounds WHERE user_id = $1"),
        ("whiteboards", "SELECT COUNT(*), MIN(created_at) FROM whiteboard_scenes WHERE user_id = $1"),
        ("applications", "SELECT COUNT(*), MIN(created_at) FROM applications WHERE owner_id = $1"),
        ("audit_log", "SELECT COUNT(*), MIN(created_at) FROM audit_log WHERE actor_id = $1 AND room_id IS NULL"),
        ("legal_notices", "SELECT COUNT(*), MIN(created_at) FROM legal_notices WHERE target_user_id = $1"),
        ("terms_acceptances", "SELECT COUNT(*), MIN(accepted_at) FROM terms_acceptances WHERE user_id = $1"),
    ] {
        let (count, since): (i64, Option<String>) = sqlx::query_as(sql).bind(id).fetch_one(&state.db).await?;
        categories.push(DataCategory { key: key.into(), count, since });
    }
    let (bio, _, _) = crate::store::users::profile_extra(&state.db, id).await.unwrap_or_default();
    let profile_items =
        [user.avatar_blob_id.is_some(), user.header_blob_id.is_some(), !bio.is_empty()].iter().filter(|b| **b).count();
    categories.insert(1, DataCategory { key: "profile".into(), count: profile_items as i64 + 1, since: None });
    let mut applications: Vec<DataApplication> =
        sqlx::query_scalar::<_, String>("SELECT name FROM applications WHERE owner_id = $1 ORDER BY name")
            .bind(id)
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .map(|name| DataApplication { name, relation: "owned".into(), room: None })
            .collect();
    let bots: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT u.display_name, r.name FROM room_members mine
         JOIN room_members other ON other.room_id = mine.room_id
         JOIN users u ON u.id = other.user_id
         JOIN rooms r ON r.id = mine.room_id
         WHERE mine.user_id = $1 AND u.kind = 'bot' ORDER BY r.name, u.display_name LIMIT 200",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    applications.extend(bots.into_iter().map(|(name, room)| DataApplication {
        name,
        relation: "room".into(),
        room: Some(room),
    }));
    Ok(DataSummary {
        address: user.address(),
        created_at: user.created_at.clone(),
        categories,
        nodes: shared_nodes(state, id).await?,
        applications,
        retention: retention(state),
    })
}
