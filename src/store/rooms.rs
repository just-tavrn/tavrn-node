// SPDX-License-Identifier: AGPL-3.0-only
use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    models::{AuditRow, Ban, Category, ChannelRow, Invite, MemberRow, OverrideRow, RoleRow, Room},
    permissions,
    util::{now, ulid},
};

const ROOM_COLS: &str = "id, name, description, rules, join_mode, owner_id, icon_blob_id, banner_blob_id, created_at, discoverable, icon_animated, no_bots, bots_in_encrypted_channels, attachment_retention_days, message_retention_days, age_gate, history_restore";
const ROLE_COLS: &str = "id, room_id, name, color, position, permissions, hoist, mentionable, is_everyone, upload_categories, application_id";
const CHANNEL_COLS: &str = "c.id, c.room_id, c.category_id, c.kind, c.name, c.topic, c.position, c.slowmode_secs, c.bitrate_kbps, c.user_limit, v.encrypted, c.system_name, c.no_bots, CAST(CASE WHEN EXISTS (SELECT 1 FROM rooms nr WHERE nr.id = c.room_id AND nr.no_bots = 1) OR EXISTS (SELECT 1 FROM categories nc WHERE nc.id = c.category_id AND nc.no_bots = 1) THEN 1 ELSE 0 END AS BIGINT) AS inherited_no_bots, c.bots_allowed, COALESCE((SELECT br.bots_in_encrypted_channels FROM rooms br WHERE br.id = c.room_id), 'per_channel') AS bots_in_encrypted_channels, c.history_for_new_members, CAST(CASE WHEN EXISTS (SELECT 1 FROM webhooks wh WHERE wh.channel_id = c.id) THEN 1 ELSE 0 END AS BIGINT) AS has_webhooks, c.auto_archive_minutes, c.forum_tags, c.age_gate, COALESCE((SELECT ar.age_gate FROM rooms ar WHERE ar.id = c.room_id), 'none') AS room_age_gate";
const OVERRIDE_COLS: &str =
    "id, room_id, target_type, target_id, subject_type, subject_id, allow, deny, upload_allow, upload_deny";
const MEMBER_COLS: &str = "room_id, user_id, nickname, joined_at, rules_accepted_at, timeout_until, avatar_media_id, avatar_animated, bio, key_reset_at, history_restored_at";

/// `system_name` of the welcome channel (`kind = 'system'`).
pub const WELCOME: &str = "welcome";
/// Position of the welcome channel: before every other channel.
pub const WELCOME_POSITION: i64 = -1;

/// New text, announcement and forum channels (and the default channel of a new room) are end-to-end
/// encrypted unless created with `encrypted: false`; voice channels always are.
pub const DEFAULT_CHANNEL_ENCRYPTED: bool = true;

// ---------------------------------------------------------------- Rooms

pub struct NewRoom<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub join_mode: &'a str,
    pub owner_id: &'a str,
}

/// Creates the room, the `@everyone` role, the default category, a text and a voice channel and the
/// owner's membership in one transaction.
pub async fn create_room(db: &Pool, r: NewRoom<'_>) -> Result<Room, ApiError> {
    let mut tx = db.begin().await?;
    let room_id = ulid();
    let ts = now();
    sqlx::query(
        "INSERT INTO rooms (id, name, description, join_mode, owner_id, created_at, bots_in_encrypted_channels) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&room_id)
    .bind(r.name)
    .bind(r.description)
    .bind(r.join_mode)
    .bind(r.owner_id)
    .bind(&ts)
    .bind(permissions::BOTS_PER_CHANNEL)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO roles (id, room_id, name, position, permissions, is_everyone, upload_categories) VALUES ($1, $2, '@everyone', 0, $3, 1, $4)")
        .bind(ulid())
        .bind(&room_id)
        .bind(permissions::DEFAULT_EVERYONE as i64)
        .bind(crate::uploads::DEFAULT_EVERYONE as i64)
        .execute(&mut *tx)
        .await?;
    insert_welcome_channel(&mut tx, &room_id, &ts).await?;
    sqlx::query("INSERT INTO room_members (room_id, user_id, joined_at, rules_accepted_at) VALUES ($1, $2, $3, $3)")
        .bind(&room_id)
        .bind(r.owner_id)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
    let category_id = ulid();
    sqlx::query(
        "INSERT INTO categories (id, room_id, name, position, system_name) VALUES ($1, $2, 'General', 0, 'general')",
    )
    .bind(&category_id)
    .bind(&room_id)
    .execute(&mut *tx)
    .await?;
    for (kind, name, position) in [("text", "general", 0i64), ("voice", "Voice", 1)] {
        let id = ulid();
        let encrypted = kind == "voice" || DEFAULT_CHANNEL_ENCRYPTED;
        sqlx::query(
            "INSERT INTO conversations (id, kind, room_id, encrypted, created_at) VALUES ($1, 'channel', $2, $3, $4)",
        )
        .bind(&id)
        .bind(&room_id)
        .bind(encrypted as i64)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO channels (id, room_id, category_id, kind, name, position, system_name) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&id)
        .bind(&room_id)
        .bind(&category_id)
        .bind(kind)
        .bind(name)
        .bind(position)
        .bind(if kind == "voice" { "voice" } else { "general" })
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    room_by_id(db, &room_id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("room not found after INSERT")))
}

/// Creates the welcome channel of a room: a plaintext conversation (only the node writes there, system
/// messages are never encrypted) and a channel of kind `system` at the top, outside every category.
pub async fn insert_welcome_channel(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    room_id: &str,
    ts: &str,
) -> Result<String, ApiError> {
    let id = ulid();
    sqlx::query(
        "INSERT INTO conversations (id, kind, room_id, encrypted, created_at) VALUES ($1, 'channel', $2, 0, $3)",
    )
    .bind(&id)
    .bind(room_id)
    .bind(ts)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO channels (id, room_id, category_id, kind, name, position, system_name) VALUES ($1, $2, NULL, 'system', 'welcome', $3, $4)",
    )
    .bind(&id)
    .bind(room_id)
    .bind(WELCOME_POSITION)
    .bind(WELCOME)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

/// The welcome channel of a room (also when it is switched off).
pub async fn welcome_channel(db: &Pool, room_id: &str) -> Result<Option<ChannelRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLS} FROM channels c JOIN conversations v ON v.id = c.id WHERE c.room_id = $1 AND c.kind = 'system' AND c.system_name = $2"
    ))
    .bind(room_id)
    .bind(WELCOME)
    .fetch_optional(db)
    .await?)
}

pub async fn room_by_id(db: &Pool, id: &str) -> Result<Option<Room>, ApiError> {
    let room: Option<Room> =
        sqlx::query_as(&format!("SELECT {ROOM_COLS} FROM rooms WHERE id = $1")).bind(id).fetch_optional(db).await?;
    Ok(room.map(Room::with_icon))
}

pub async fn rooms_of_user(db: &Pool, user_id: &str) -> Result<Vec<Room>, ApiError> {
    let rooms: Vec<Room> = sqlx::query_as(&format!(
        "SELECT {ROOM_COLS} FROM rooms WHERE id IN (SELECT room_id FROM room_members WHERE user_id = $1) ORDER BY created_at"
    ))
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rooms.into_iter().map(Room::with_icon).collect())
}

/// Public rooms their owners listed in the directory (FEDERATION.md §7.3), newest first.
/// Discoverable public rooms; rooms with an age gate only when `include_gated` (an adult asks, PROTOCOL.md §5e).
pub async fn public_rooms(db: &Pool, limit: i64, include_gated: bool) -> Result<Vec<Room>, ApiError> {
    let rooms: Vec<Room> = sqlx::query_as(&format!(
        "SELECT {ROOM_COLS} FROM rooms WHERE join_mode = 'public' AND discoverable = 1 AND ($2 = 1 OR age_gate = 'none')
         ORDER BY created_at DESC LIMIT $1"
    ))
    .bind(limit)
    .bind(i64::from(include_gated))
    .fetch_all(db)
    .await?;
    Ok(rooms.into_iter().map(Room::with_icon).collect())
}

/// Sets a room's age gate (`none` | `adults_only`, validated by the caller).
pub async fn set_room_age_gate(db: &Pool, room_id: &str, gate: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE rooms SET age_gate = $1 WHERE id = $2").bind(gate).bind(room_id).execute(db).await?;
    Ok(())
}

/// Sets a channel's own age gate (`none` | `adults_only`, validated by the caller).
pub async fn set_channel_age_gate(db: &Pool, channel_id: &str, gate: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE channels SET age_gate = $1 WHERE id = $2").bind(gate).bind(channel_id).execute(db).await?;
    Ok(())
}

pub async fn rooms_owned_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM rooms WHERE owner_id = $1").bind(user_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

pub struct RoomUpdate<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
    pub rules: Option<&'a str>,
    pub join_mode: Option<&'a str>,
    pub discoverable: Option<bool>,
}

pub async fn update_room(db: &Pool, id: &str, u: RoomUpdate<'_>) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE rooms SET name = COALESCE($1, name), description = COALESCE($2, description), rules = COALESCE($3, rules), join_mode = COALESCE($4, join_mode), discoverable = COALESCE($5, discoverable) WHERE id = $6",
    )
    .bind(u.name)
    .bind(u.description)
    .bind(u.rules)
    .bind(u.join_mode)
    .bind(u.discoverable.map(i64::from))
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Storage ids of every file that belongs to a room: uploads in its channels, custom emojis and
/// soundboard clips (query before deleting the room; the rows cascade).
pub async fn room_files(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let mut ids = crate::store::blobs::ids_of_room(db, room_id).await?;
    for sql in [
        "SELECT id FROM emojis WHERE room_id = $1",
        "SELECT still_id AS id FROM emojis WHERE room_id = $1 AND still_id IS NOT NULL",
        "SELECT id FROM soundboard_sounds WHERE room_id = $1",
    ] {
        for row in sqlx::query(sql).bind(room_id).fetch_all(db).await? {
            ids.push(row.try_get::<String, _>("id")?);
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Media ids of the members' per-room avatars.
pub async fn room_member_media(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let rows =
        sqlx::query("SELECT avatar_media_id FROM room_members WHERE room_id = $1 AND avatar_media_id IS NOT NULL")
            .bind(room_id)
            .fetch_all(db)
            .await?;
    rows.iter().map(|r| r.try_get::<String, _>("avatar_media_id").map_err(Into::into)).collect()
}

pub async fn delete_room(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM rooms WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

pub async fn member_count(db: &Pool, room_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT COUNT(*) AS n FROM room_members WHERE room_id = $1").bind(room_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

// ---------------------------------------------------------------- Members

pub async fn member(db: &Pool, room_id: &str, user_id: &str) -> Result<Option<MemberRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {MEMBER_COLS} FROM room_members WHERE room_id = $1 AND user_id = $2"))
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?)
}

pub async fn members(db: &Pool, room_id: &str, limit: i64, after: Option<&str>) -> Result<Vec<MemberRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {MEMBER_COLS} FROM room_members WHERE room_id = $1 AND user_id > $2 ORDER BY user_id LIMIT $3"
    ))
    .bind(room_id)
    .bind(after.unwrap_or(""))
    .bind(limit)
    .fetch_all(db)
    .await?)
}

pub async fn add_member(db: &Pool, room_id: &str, user_id: &str, rules_accepted: bool) -> Result<(), ApiError> {
    let ts = now();
    sqlx::query("INSERT INTO room_members (room_id, user_id, joined_at, rules_accepted_at) VALUES ($1, $2, $3, $4)")
        .bind(room_id)
        .bind(user_id)
        .bind(&ts)
        .bind(rules_accepted.then_some(&ts))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn remove_member(db: &Pool, room_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM room_members WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn set_timeout(db: &Pool, room_id: &str, user_id: &str, until: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET timeout_until = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(until)
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_nickname(db: &Pool, room_id: &str, user_id: &str, nickname: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET nickname = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(nickname)
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn set_member_bio(db: &Pool, room_id: &str, user_id: &str, bio: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE room_members SET bio = $1 WHERE room_id = $2 AND user_id = $3")
        .bind(bio)
        .bind(room_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Points the member's per-room avatar at `media_id` (or none); returns the previous media id.
pub async fn set_member_avatar(
    db: &Pool,
    room_id: &str,
    user_id: &str,
    media_id: Option<&str>,
    animated: bool,
) -> Result<Option<String>, ApiError> {
    let previous = member(db, room_id, user_id).await?.and_then(|m| m.avatar_media_id);
    sqlx::query(
        "UPDATE room_members SET avatar_media_id = $1, avatar_animated = $2 WHERE room_id = $3 AND user_id = $4",
    )
    .bind(media_id)
    .bind(animated as i64)
    .bind(room_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(previous)
}

/// Per-room profiles of the authors of messages in room channels: `(conversation id, member row)` for
/// every author that is (still) a member of the channel's room and has a nickname or room avatar.
pub async fn author_profiles(
    db: &Pool,
    conversation_ids: &[String],
    author_ids: &[String],
) -> Result<Vec<(String, MemberRow)>, ApiError> {
    if conversation_ids.is_empty() || author_ids.is_empty() || conversation_ids.len() + author_ids.len() > 1000 {
        return Ok(Vec::new());
    }
    let convs: Vec<String> = (1..=conversation_ids.len()).map(|i| format!("${i}")).collect();
    let authors: Vec<String> =
        (conversation_ids.len() + 1..=conversation_ids.len() + author_ids.len()).map(|i| format!("${i}")).collect();
    let cols = MEMBER_COLS.split(", ").map(|c| format!("m.{c}")).collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT c.id AS conversation_id, {cols} FROM channels c JOIN room_members m ON m.room_id = c.room_id
         WHERE c.id IN ({}) AND m.user_id IN ({}) AND (m.nickname IS NOT NULL OR m.avatar_media_id IS NOT NULL)",
        convs.join(", "),
        authors.join(", ")
    );
    let mut q = sqlx::query(&sql);
    for v in conversation_ids.iter().chain(author_ids) {
        q = q.bind(v);
    }
    let mut out = Vec::new();
    for row in q.fetch_all(db).await? {
        let conversation_id: String = row.try_get("conversation_id")?;
        out.push((conversation_id, <MemberRow as sqlx::FromRow<'_, sqlx::any::AnyRow>>::from_row(&row)?));
    }
    Ok(out)
}

pub async fn member_role_ids(db: &Pool, room_id: &str, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT role_id FROM member_roles WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| r.try_get::<String, _>("role_id").map_err(Into::into)).collect()
}

pub async fn set_member_roles(db: &Pool, room_id: &str, user_id: &str, role_ids: &[String]) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM member_roles WHERE room_id = $1 AND user_id = $2")
        .bind(room_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    for role_id in role_ids {
        sqlx::query("INSERT INTO member_roles (room_id, user_id, role_id) VALUES ($1, $2, $3)")
            .bind(room_id)
            .bind(user_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------- Roles

pub async fn roles(db: &Pool, room_id: &str) -> Result<Vec<RoleRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {ROLE_COLS} FROM roles WHERE room_id = $1 ORDER BY position DESC, id"))
        .bind(room_id)
        .fetch_all(db)
        .await?)
}

pub async fn role_by_id(db: &Pool, room_id: &str, role_id: &str) -> Result<Option<RoleRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {ROLE_COLS} FROM roles WHERE room_id = $1 AND id = $2"))
        .bind(room_id)
        .bind(role_id)
        .fetch_optional(db)
        .await?)
}

pub struct NewRole<'a> {
    pub name: &'a str,
    pub color: Option<&'a str>,
    pub position: i64,
    pub permissions: u64,
    pub hoist: bool,
    pub mentionable: bool,
    pub upload_categories: Option<u64>,
}

pub async fn create_role(db: &Pool, room_id: &str, r: NewRole<'_>) -> Result<String, ApiError> {
    let id = ulid();
    sqlx::query("INSERT INTO roles (id, room_id, name, color, position, permissions, hoist, mentionable, is_everyone, upload_categories) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9)")
        .bind(&id)
        .bind(room_id)
        .bind(r.name)
        .bind(r.color)
        .bind(r.position)
        .bind(r.permissions as i64)
        .bind(r.hoist as i64)
        .bind(r.mentionable as i64)
        .bind(r.upload_categories.map(|c| c as i64))
        .execute(db)
        .await?;
    Ok(id)
}

pub struct RoleUpdate<'a> {
    pub name: Option<&'a str>,
    pub color: Option<Option<&'a str>>,
    pub position: Option<i64>,
    pub permissions: Option<u64>,
    pub hoist: Option<bool>,
    pub mentionable: Option<bool>,
    /// `Some(None)` clears the setting (inherit).
    pub upload_categories: Option<Option<u64>>,
}

pub async fn update_role(db: &Pool, room_id: &str, role_id: &str, u: RoleUpdate<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    if let Some(v) = u.name {
        sqlx::query("UPDATE roles SET name = $1 WHERE room_id = $2 AND id = $3")
            .bind(v)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.color {
        sqlx::query("UPDATE roles SET color = $1 WHERE room_id = $2 AND id = $3")
            .bind(v)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.position {
        sqlx::query("UPDATE roles SET position = $1 WHERE room_id = $2 AND id = $3")
            .bind(v)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.permissions {
        sqlx::query("UPDATE roles SET permissions = $1 WHERE room_id = $2 AND id = $3")
            .bind(v as i64)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.hoist {
        sqlx::query("UPDATE roles SET hoist = $1 WHERE room_id = $2 AND id = $3")
            .bind(v as i64)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.mentionable {
        sqlx::query("UPDATE roles SET mentionable = $1 WHERE room_id = $2 AND id = $3")
            .bind(v as i64)
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(v) = u.upload_categories {
        sqlx::query("UPDATE roles SET upload_categories = $1 WHERE room_id = $2 AND id = $3")
            .bind(v.map(|c| c as i64))
            .bind(room_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn delete_role(db: &Pool, room_id: &str, role_id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM roles WHERE room_id = $1 AND id = $2 AND is_everyone = 0")
        .bind(room_id)
        .bind(role_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------- Categories and channels

pub async fn categories(db: &Pool, room_id: &str) -> Result<Vec<Category>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, room_id, name, position, system_name, no_bots FROM categories WHERE room_id = $1 ORDER BY position, id",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

pub async fn create_category(db: &Pool, room_id: &str, name: &str, position: i64) -> Result<String, ApiError> {
    let id = ulid();
    sqlx::query("INSERT INTO categories (id, room_id, name, position) VALUES ($1, $2, $3, $4)")
        .bind(&id)
        .bind(room_id)
        .bind(name)
        .bind(position)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn update_category(
    db: &Pool,
    room_id: &str,
    id: &str,
    name: Option<&str>,
    position: Option<i64>,
) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE categories SET name = COALESCE($1, name), position = COALESCE($2, position), system_name = CASE WHEN $1 IS NOT NULL AND $1 <> name THEN NULL ELSE system_name END WHERE room_id = $3 AND id = $4")
        .bind(name)
        .bind(position)
        .bind(room_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn delete_category(db: &Pool, room_id: &str, id: &str) -> Result<bool, ApiError> {
    let r =
        sqlx::query("DELETE FROM categories WHERE room_id = $1 AND id = $2").bind(room_id).bind(id).execute(db).await?;
    Ok(r.rows_affected() > 0)
}

pub async fn category_exists(db: &Pool, room_id: &str, id: &str) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT 1 AS x FROM categories WHERE room_id = $1 AND id = $2")
        .bind(room_id)
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

pub async fn channels(db: &Pool, room_id: &str) -> Result<Vec<ChannelRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLS} FROM channels c JOIN conversations v ON v.id = c.id WHERE c.room_id = $1 ORDER BY c.position, c.id"
    ))
    .bind(room_id)
    .fetch_all(db)
    .await?)
}

pub async fn channel_by_id(db: &Pool, channel_id: &str) -> Result<Option<ChannelRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CHANNEL_COLS} FROM channels c JOIN conversations v ON v.id = c.id WHERE c.id = $1"
    ))
    .bind(channel_id)
    .fetch_optional(db)
    .await?)
}

pub struct NewChannel<'a> {
    pub kind: &'a str,
    pub name: &'a str,
    pub topic: &'a str,
    pub category_id: Option<&'a str>,
    pub position: i64,
    pub encrypted: bool,
    pub bitrate_kbps: i64,
    pub user_limit: i64,
}

pub async fn create_channel(db: &Pool, room_id: &str, c: NewChannel<'_>) -> Result<String, ApiError> {
    let id = ulid();
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO conversations (id, kind, room_id, encrypted, created_at) VALUES ($1, 'channel', $2, $3, $4)",
    )
    .bind(&id)
    .bind(room_id)
    .bind(c.encrypted as i64)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO channels (id, room_id, category_id, kind, name, topic, position, bitrate_kbps, user_limit) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
        .bind(&id)
        .bind(room_id)
        .bind(c.category_id)
        .bind(c.kind)
        .bind(c.name)
        .bind(c.topic)
        .bind(c.position)
        .bind(c.bitrate_kbps)
        .bind(c.user_limit)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

pub struct ChannelUpdate<'a> {
    pub name: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub category_id: Option<Option<&'a str>>,
    pub position: Option<i64>,
    pub slowmode_secs: Option<i64>,
    pub bitrate_kbps: Option<i64>,
    pub user_limit: Option<i64>,
    pub encrypted: Option<bool>,
}

pub async fn update_channel(db: &Pool, channel_id: &str, u: ChannelUpdate<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE channels SET system_name = CASE WHEN $1 IS NOT NULL AND $1 <> name THEN NULL ELSE system_name END,
         name = COALESCE($1, name), topic = COALESCE($2, topic), position = COALESCE($3, position),
         slowmode_secs = COALESCE($4, slowmode_secs),
         bitrate_kbps = COALESCE($5, bitrate_kbps), user_limit = COALESCE($6, user_limit) WHERE id = $7",
    )
    .bind(u.name)
    .bind(u.topic)
    .bind(u.position)
    .bind(u.slowmode_secs)
    .bind(u.bitrate_kbps)
    .bind(u.user_limit)
    .bind(channel_id)
    .execute(&mut *tx)
    .await?;
    if let Some(cat) = u.category_id {
        sqlx::query("UPDATE channels SET category_id = $1 WHERE id = $2")
            .bind(cat)
            .bind(channel_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(enc) = u.encrypted {
        sqlx::query("UPDATE conversations SET encrypted = $1 WHERE id = $2")
            .bind(enc as i64)
            .bind(channel_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn delete_channel(db: &Pool, channel_id: &str) -> Result<bool, ApiError> {
    // Deleting the conversation is enough: channels, messages etc. hang off it via ON DELETE CASCADE.
    let r = sqlx::query("DELETE FROM conversations WHERE id = $1 AND kind = 'channel'")
        .bind(channel_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

// ---------------------------------------------------------------- Overrides

pub async fn overrides_for(db: &Pool, target_type: &str, target_id: &str) -> Result<Vec<OverrideRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {OVERRIDE_COLS} FROM permission_overrides WHERE target_type = $1 AND target_id = $2 ORDER BY id"
    ))
    .bind(target_type)
    .bind(target_id)
    .fetch_all(db)
    .await?)
}

pub struct SetOverride<'a> {
    pub room_id: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub allow: u64,
    pub deny: u64,
    /// Upload category masks (`None` keeps the current ones).
    pub upload_allow: Option<u64>,
    pub upload_deny: Option<u64>,
}

pub async fn set_override(db: &Pool, o: SetOverride<'_>) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    let current = sqlx::query("SELECT upload_allow, upload_deny FROM permission_overrides WHERE target_type = $1 AND target_id = $2 AND subject_type = $3 AND subject_id = $4")
        .bind(o.target_type)
        .bind(o.target_id)
        .bind(o.subject_type)
        .bind(o.subject_id)
        .fetch_optional(&mut *tx)
        .await?;
    let (cur_allow, cur_deny) = match current {
        Some(row) => (row.try_get::<i64, _>("upload_allow")? as u64, row.try_get::<i64, _>("upload_deny")? as u64),
        None => (0, 0),
    };
    let upload_allow = o.upload_allow.unwrap_or(cur_allow);
    let upload_deny = o.upload_deny.unwrap_or(cur_deny);
    sqlx::query("DELETE FROM permission_overrides WHERE target_type = $1 AND target_id = $2 AND subject_type = $3 AND subject_id = $4")
        .bind(o.target_type)
        .bind(o.target_id)
        .bind(o.subject_type)
        .bind(o.subject_id)
        .execute(&mut *tx)
        .await?;
    if o.allow != 0 || o.deny != 0 || upload_allow != 0 || upload_deny != 0 {
        sqlx::query("INSERT INTO permission_overrides (id, room_id, target_type, target_id, subject_type, subject_id, allow, deny, upload_allow, upload_deny) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
            .bind(ulid())
            .bind(o.room_id)
            .bind(o.target_type)
            .bind(o.target_id)
            .bind(o.subject_type)
            .bind(o.subject_id)
            .bind(o.allow as i64)
            .bind(o.deny as i64)
            .bind(upload_allow as i64)
            .bind(upload_deny as i64)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn overrides_of_room(db: &Pool, room_id: &str) -> Result<Vec<OverrideRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {OVERRIDE_COLS} FROM permission_overrides WHERE room_id = $1 ORDER BY id"))
        .bind(room_id)
        .fetch_all(db)
        .await?)
}

// ---------------------------------------------------------------- Invites and bans

pub async fn create_invite(
    db: &Pool,
    room_id: &str,
    creator_id: &str,
    max_uses: i64,
    expires_at: Option<&str>,
) -> Result<Invite, ApiError> {
    insert_invite(db, room_id, creator_id, max_uses, expires_at, None).await
}

/// A single-use invite bound to `address` (direct invite, FEDERATION.md §3.4).
pub async fn create_bound_invite(
    db: &Pool,
    room_id: &str,
    creator_id: &str,
    expires_at: &str,
    address: &str,
) -> Result<Invite, ApiError> {
    insert_invite(db, room_id, creator_id, 1, Some(expires_at), Some(address)).await
}

async fn insert_invite(
    db: &Pool,
    room_id: &str,
    creator_id: &str,
    max_uses: i64,
    expires_at: Option<&str>,
    bound_to: Option<&str>,
) -> Result<Invite, ApiError> {
    let code = crate::util::random_token(8);
    let ts = now();
    sqlx::query("INSERT INTO invites (code, room_id, creator_id, max_uses, uses, expires_at, created_at, bound_to) VALUES ($1, $2, $3, $4, 0, $5, $6, $7)")
        .bind(&code)
        .bind(room_id)
        .bind(creator_id)
        .bind(max_uses)
        .bind(expires_at)
        .bind(&ts)
        .bind(bound_to)
        .execute(db)
        .await?;
    Ok(Invite {
        code,
        room_id: room_id.into(),
        creator_id: creator_id.into(),
        max_uses,
        uses: 0,
        expires_at: expires_at.map(String::from),
        created_at: ts,
        user: bound_to.map(String::from),
        direct: bound_to.is_some(),
        creator: None,
    })
}

/// Members of a room whose home domain is `domain`, and bots whose owner's home domain is `domain`.
pub async fn members_of_domain(db: &Pool, room_id: &str, domain: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT m.user_id AS id FROM room_members m JOIN users u ON u.id = m.user_id
         LEFT JOIN users o ON o.id = u.owner_id
         WHERE m.room_id = $1 AND (u.domain = $2 OR o.domain = $2)",
    )
    .bind(room_id)
    .bind(domain)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

/// All members of a room with their role ids (without @everyone), in two queries (e.g. to compute who may
/// view a channel without one query per member).
pub async fn members_with_roles(db: &Pool, room_id: &str) -> Result<Vec<(MemberRow, Vec<String>)>, ApiError> {
    let members: Vec<MemberRow> = sqlx::query_as(&format!("SELECT {MEMBER_COLS} FROM room_members WHERE room_id = $1"))
        .bind(room_id)
        .fetch_all(db)
        .await?;
    let rows =
        sqlx::query("SELECT user_id, role_id FROM member_roles WHERE room_id = $1").bind(room_id).fetch_all(db).await?;
    let mut roles: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for r in &rows {
        roles.entry(r.try_get::<String, _>("user_id")?).or_default().push(r.try_get::<String, _>("role_id")?);
    }
    Ok(members
        .into_iter()
        .map(|m| {
            let r = roles.remove(&m.user_id).unwrap_or_default();
            (m, r)
        })
        .collect())
}

/// All members of a room (ids).
pub async fn member_ids(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT user_id FROM room_members WHERE room_id = $1").bind(room_id).fetch_all(db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}

/// Rooms both users are members of: `(id, name)`.
pub async fn shared_rooms(db: &Pool, a: &str, b: &str) -> Result<Vec<(String, String)>, ApiError> {
    let rows = sqlx::query(
        "SELECT r.id AS id, r.name AS name FROM rooms r
         JOIN room_members m1 ON m1.room_id = r.id AND m1.user_id = $1
         JOIN room_members m2 ON m2.room_id = r.id AND m2.user_id = $2
         ORDER BY r.name",
    )
    .bind(a)
    .bind(b)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("id")?, r.try_get("name")?))).collect()
}

/// Rooms a user is a member of (ids).
pub async fn room_ids_of_user(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT room_id FROM room_members WHERE user_id = $1").bind(user_id).fetch_all(db).await?;
    rows.iter().map(|r| r.try_get::<String, _>("room_id").map_err(Into::into)).collect()
}

pub async fn invite_by_code(db: &Pool, code: &str) -> Result<Option<Invite>, ApiError> {
    let invite: Option<Invite> = sqlx::query_as(
        "SELECT code, room_id, creator_id, max_uses, uses, expires_at, created_at, bound_to FROM invites WHERE code = $1",
    )
    .bind(code)
    .fetch_optional(db)
    .await?;
    Ok(invite.map(|i| Invite { direct: i.user.is_some(), ..i }))
}

/// Active invites of a room (not expired, uses left), newest first, with the creator's display name.
pub async fn invites_of_room(db: &Pool, room_id: &str) -> Result<Vec<Invite>, ApiError> {
    let rows: Vec<Invite> = sqlx::query_as(
        "SELECT i.code, i.room_id, i.creator_id, i.max_uses, i.uses, i.expires_at, i.created_at, i.bound_to, COALESCE(NULLIF(u.display_name, ''), u.username) AS creator \
         FROM invites i LEFT JOIN users u ON u.id = i.creator_id \
         WHERE i.room_id = $1 AND (i.expires_at IS NULL OR i.expires_at > $2) AND (i.max_uses = 0 OR i.uses < i.max_uses) \
         ORDER BY i.created_at DESC",
    )
    .bind(room_id)
    .bind(now())
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|i| Invite { direct: i.user.is_some(), ..i }).collect())
}

/// Claims one use of an invite atomically: `false` if it is used up or expired (also when several people redeem the
/// last use at the same moment, only one of them gets it).
pub async fn claim_invite(db: &Pool, code: &str, now: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE invites SET uses = uses + 1
         WHERE code = $1 AND (max_uses = 0 OR uses < max_uses) AND (expires_at IS NULL OR expires_at > $2)",
    )
    .bind(code)
    .bind(now)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Gives back a use claimed by [`claim_invite`] (the join failed after the claim).
pub async fn release_invite(db: &Pool, code: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE invites SET uses = uses - 1 WHERE code = $1 AND uses > 0").bind(code).execute(db).await?;
    Ok(())
}

pub async fn delete_invite(db: &Pool, room_id: &str, code: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM invites WHERE room_id = $1 AND code = $2")
        .bind(room_id)
        .bind(code)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Checks room bans (room_id) and node bans (NULL) for the user ID and its domain.
pub async fn is_banned(db: &Pool, room_id: Option<&str>, address: &str, domain: &str) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT 1 AS x FROM bans WHERE (room_id IS NULL OR room_id = $1) AND (subject = $2 OR subject = $3) LIMIT 1",
    )
    .bind(room_id)
    .bind(address)
    .bind(domain)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

pub async fn add_ban(
    db: &Pool,
    room_id: Option<&str>,
    subject: &str,
    reason: &str,
    actor_id: &str,
) -> Result<Ban, ApiError> {
    let id = ulid();
    let ts = now();
    remove_ban(db, room_id, subject).await?;
    sqlx::query(
        "INSERT INTO bans (id, room_id, subject, reason, actor_id, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(room_id)
    .bind(subject)
    .bind(reason)
    .bind(actor_id)
    .bind(&ts)
    .execute(db)
    .await?;
    Ok(Ban {
        id,
        room_id: room_id.map(String::from),
        subject: subject.into(),
        reason: reason.into(),
        actor_id: actor_id.into(),
        created_at: ts,
    })
}

pub async fn remove_ban(db: &Pool, room_id: Option<&str>, subject: &str) -> Result<bool, ApiError> {
    let r = match room_id {
        Some(r) => {
            sqlx::query("DELETE FROM bans WHERE room_id = $1 AND subject = $2")
                .bind(r)
                .bind(subject)
                .execute(db)
                .await?
        }
        None => {
            sqlx::query("DELETE FROM bans WHERE room_id IS NULL AND subject = $1").bind(subject).execute(db).await?
        }
    };
    Ok(r.rows_affected() > 0)
}

pub async fn bans(db: &Pool, room_id: Option<&str>) -> Result<Vec<Ban>, ApiError> {
    Ok(match room_id {
        Some(r) => sqlx::query_as("SELECT id, room_id, subject, reason, actor_id, created_at FROM bans WHERE room_id = $1 ORDER BY created_at DESC").bind(r).fetch_all(db).await?,
        None => sqlx::query_as("SELECT id, room_id, subject, reason, actor_id, created_at FROM bans WHERE room_id IS NULL ORDER BY created_at DESC").fetch_all(db).await?,
    })
}

// ---------------------------------------------------------------- Audit-Log

/// Sets a room's message retention (`None` = the node's value, PROTOCOL.md §7f).
pub async fn set_message_retention(db: &Pool, room_id: &str, days: Option<i64>) -> Result<(), ApiError> {
    sqlx::query("UPDATE rooms SET message_retention_days = $1 WHERE id = $2")
        .bind(days)
        .bind(room_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Rooms with an own message retention: (room id, days).
pub async fn message_retention_rooms(db: &Pool) -> Result<Vec<(String, i64)>, ApiError> {
    Ok(sqlx::query_as("SELECT id, message_retention_days FROM rooms WHERE message_retention_days > 0 ORDER BY id")
        .fetch_all(db)
        .await?)
}

pub async fn audit(
    db: &Pool,
    room_id: Option<&str>,
    actor_id: Option<&str>,
    action: &str,
    target: &str,
    reason: &str,
    mut meta: serde_json::Value,
) -> Result<(), ApiError> {
    // Action shortcuts of the moderation inbox record the report they act on (MODERATION.md §1.4).
    if let (Some(report_id), Some(obj)) = (crate::reports::acting_on(), meta.as_object_mut()) {
        obj.insert("report_id".into(), report_id.into());
    }
    sqlx::query("INSERT INTO audit_log (id, room_id, actor_id, action, target, reason, meta, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(ulid())
        .bind(room_id)
        .bind(actor_id)
        .bind(action)
        .bind(target)
        .bind(reason)
        .bind(meta.to_string())
        .bind(now())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn audit_entries(
    db: &Pool,
    room_id: Option<&str>,
    limit: i64,
    before: Option<&str>,
) -> Result<Vec<AuditRow>, ApiError> {
    let before = before.unwrap_or("~");
    Ok(match room_id {
        Some(r) => sqlx::query_as("SELECT id, room_id, actor_id, action, target, reason, meta, created_at FROM audit_log WHERE room_id = $1 AND id < $2 ORDER BY id DESC LIMIT $3")
            .bind(r).bind(before).bind(limit).fetch_all(db).await?,
        None => sqlx::query_as("SELECT id, room_id, actor_id, action, target, reason, meta, created_at FROM audit_log WHERE room_id IS NULL AND id < $1 ORDER BY id DESC LIMIT $2")
            .bind(before).bind(limit).fetch_all(db).await?,
    })
}

/// The owner plus every member with `MODERATE_MEMBERS` or `ADMINISTRATOR` (for auto-moderation notices).
pub async fn moderator_ids(db: &Pool, room_id: &str) -> Result<Vec<String>, ApiError> {
    let mask = (permissions::MODERATE_MEMBERS | permissions::ADMINISTRATOR) as i64;
    let rows = sqlx::query(
        "SELECT owner_id AS user_id FROM rooms WHERE id = $1
         UNION
         SELECT mr.user_id FROM member_roles mr JOIN roles r ON r.id = mr.role_id WHERE mr.room_id = $1 AND (r.permissions & $2) <> 0",
    )
    .bind(room_id)
    .bind(mask)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("user_id").map_err(Into::into)).collect()
}
