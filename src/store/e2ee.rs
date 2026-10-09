// SPDX-License-Identifier: AGPL-3.0-only
//! End-to-end encryption data: identity keys, device keys, KeyPackages, MLS delivery service
//! state and history backups (ENCRYPTION.md §2.3, §3, §4.4, §7).

use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    util::{now, ulid},
};

// ---------------------------------------------------------------- Identity and devices

/// Sets the identity key if none is set. `false` if a key already exists.
pub async fn set_identity_once(db: &Pool, user_id: &str, key: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE users SET identity_pubkey = $1 WHERE id = $2 AND identity_pubkey IS NULL")
        .bind(key)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Identity reset (§9): new key, reset time, attestations, KeyPackages, backups and whiteboard scenes gone.
pub async fn reset_identity(db: &Pool, user_id: &str, key: &str) -> Result<String, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET identity_pubkey = $1, identity_reset_at = $2 WHERE id = $3")
        .bind(key)
        .bind(&ts)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE devices SET identity_signature = NULL, attested_identity_key = NULL, attested_at = NULL WHERE user_id = $1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM key_packages WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM key_backups WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    // Whiteboard scenes are encrypted under the old backup key as well (WHITEBOARD.md §5).
    sqlx::query("DELETE FROM whiteboard_scenes WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    // The wrapped copies hold the old master secret (ENCRYPTION.md §2.4, §9).
    sqlx::query("DELETE FROM secret_storage WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    // A reset starts a new chain at generation 0 (the key derived from the new master secret, §9a).
    sqlx::query("DELETE FROM identity_continuity WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(ts)
}

// ---------------------------------------------------------------- Identity rotation (ENCRYPTION.md §9a)

/// One continuity statement of an account's chain with the wrapped key it introduced.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContinuityRow {
    pub generation: i64,
    pub old_key: String,
    pub new_key: String,
    pub at: String,
    pub sig_old: String,
    pub sig_new: String,
    pub identity_blob: String,
    pub created_at: String,
}

/// The continuity chain of a user, oldest first.
pub async fn continuity(db: &Pool, user_id: &str) -> Result<Vec<ContinuityRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT generation, old_key, new_key, at, sig_old, sig_new, identity_blob, created_at
         FROM identity_continuity WHERE user_id = $1 ORDER BY generation",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// The newest statement of a user's chain (the current generation), if the key was ever rotated.
pub async fn current_rotation(db: &Pool, user_id: &str) -> Result<Option<ContinuityRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT generation, old_key, new_key, at, sig_old, sig_new, identity_blob, created_at
         FROM identity_continuity WHERE user_id = $1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

/// A verified rotation to store.
pub struct Rotation<'a> {
    pub user_id: &'a str,
    pub old_key: &'a str,
    pub new_key: &'a str,
    pub at: &'a str,
    pub sig_old: &'a str,
    pub sig_new: &'a str,
    pub identity_blob: &'a str,
    /// `(device id, identity signature by the new key)` for every active device.
    pub attestations: &'a [(String, String)],
}

/// Rotates the identity key atomically (§9a): the new key (only if `old_key` is still current), the new
/// attestations of the listed devices, the statement and the blob. Retired devices keep their attestation.
/// Returns the new generation, `None` if the key changed in the meantime.
pub async fn rotate_identity(db: &Pool, r: &Rotation<'_>) -> Result<Option<i64>, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    let changed = sqlx::query("UPDATE users SET identity_pubkey = $1 WHERE id = $2 AND identity_pubkey = $3")
        .bind(r.new_key)
        .bind(r.user_id)
        .bind(r.old_key)
        .execute(&mut *tx)
        .await?;
    if changed.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(None);
    }
    for (device_id, signature) in r.attestations {
        sqlx::query(
            "UPDATE devices SET identity_signature = $1, attested_identity_key = $2, attested_at = $3
             WHERE id = $4 AND user_id = $5 AND attested_identity_key = $6",
        )
        .bind(signature)
        .bind(r.new_key)
        .bind(&ts)
        .bind(device_id)
        .bind(r.user_id)
        .bind(r.old_key)
        .execute(&mut *tx)
        .await?;
    }
    let row = sqlx::query(
        "SELECT CAST(COALESCE(MAX(generation), 0) AS BIGINT) AS g FROM identity_continuity WHERE user_id = $1",
    )
    .bind(r.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let generation: i64 = row.try_get::<i64, _>("g")? + 1;
    sqlx::query(
        "INSERT INTO identity_continuity (user_id, generation, old_key, new_key, at, sig_old, sig_new, identity_blob, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(r.user_id)
    .bind(generation)
    .bind(r.old_key)
    .bind(r.new_key)
    .bind(r.at)
    .bind(r.sig_old)
    .bind(r.sig_new)
    .bind(r.identity_blob)
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(generation))
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceKeyRow {
    pub id: String,
    pub user_id: String,
    pub public_key: Option<String>,
    pub identity_signature: Option<String>,
    pub attested_identity_key: Option<String>,
    pub created_at: String,
    /// Current identity key of the user (joined).
    pub identity_pubkey: Option<String>,
    /// The device's X25519 share key and the device key's signature over it (ENCRYPTION.md §3.1), base64url.
    pub share_public_key: Option<String>,
    pub share_key_signature: Option<String>,
}

impl DeviceKeyRow {
    /// Attested under the user's *current* identity key (§9).
    pub fn attested_key(&self) -> Option<&str> {
        match (&self.public_key, &self.identity_signature, &self.attested_identity_key, &self.identity_pubkey) {
            (Some(pk), Some(_), Some(att), Some(cur)) if att == cur => Some(pk),
            _ => None,
        }
    }
}

const DEVICE_KEY_COLS: &str = "d.id, d.user_id, d.public_key, d.identity_signature, d.attested_identity_key, d.created_at, \
     u.identity_pubkey, d.share_public_key, d.share_key_signature";

pub async fn device_key(db: &Pool, device_id: &str) -> Result<Option<DeviceKeyRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {DEVICE_KEY_COLS} FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1"
    ))
    .bind(device_id)
    .fetch_optional(db)
    .await?)
}

/// Devices of a user attested under the current identity key.
pub async fn attested_devices(db: &Pool, user_id: &str) -> Result<Vec<DeviceKeyRow>, ApiError> {
    let rows: Vec<DeviceKeyRow> = sqlx::query_as(&format!(
        "SELECT {DEVICE_KEY_COLS} FROM devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.identity_signature IS NOT NULL AND d.attested_identity_key = u.identity_pubkey
         ORDER BY d.created_at, d.id"
    ))
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Stores the device key and attestation. Allowed when the device has no key yet, or (after an
/// identity reset) has the same key without a valid attestation. The identity key the signature
/// was checked against is stored with it, so a concurrent reset cannot leave a stale attestation valid.
pub async fn set_device_key(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    public_key: &str,
    signature: &str,
    identity_key: &str,
) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE devices SET public_key = $1, identity_signature = $2, attested_identity_key = $3, attested_at = $4
         WHERE id = $5 AND user_id = $6
           AND (public_key IS NULL OR (public_key = $1 AND (attested_identity_key IS NULL OR attested_identity_key <> $3)))",
    )
    .bind(public_key)
    .bind(signature)
    .bind(identity_key)
    .bind(now())
    .bind(device_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// What [`set_share_key`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKeyOutcome {
    /// The device had no share key; this one is stored.
    Stored,
    /// The device already has exactly this share key.
    Unchanged,
    /// The device has another share key (share keys are immutable), or the device is not the user's.
    Conflict,
}

/// Stores the share key of a local device once (ENCRYPTION.md §3.1); the signature was checked by the caller.
pub async fn set_share_key(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    public_key: &str,
    signature: &str,
) -> Result<ShareKeyOutcome, ApiError> {
    let r = sqlx::query(
        "UPDATE devices SET share_public_key = $1, share_key_signature = $2
         WHERE id = $3 AND user_id = $4 AND share_public_key IS NULL",
    )
    .bind(public_key)
    .bind(signature)
    .bind(device_id)
    .bind(user_id)
    .execute(db)
    .await?;
    if r.rows_affected() > 0 {
        return Ok(ShareKeyOutcome::Stored);
    }
    let existing: Option<Option<String>> =
        sqlx::query_scalar("SELECT share_public_key FROM devices WHERE id = $1 AND user_id = $2")
            .bind(device_id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(match existing.flatten() {
        Some(k) if k == public_key => ShareKeyOutcome::Unchanged,
        _ => ShareKeyOutcome::Conflict,
    })
}

/// Public device ids (the id in the MLS identity: the home device id of a remote user's device) of `user_id`'s devices
/// that are attested under the current identity key and have a share key: the devices a v2 history share may carry
/// boxes for (ENCRYPTION.md §7b).
pub async fn share_key_devices(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(d.home_device_id, d.id) FROM devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.identity_signature IS NOT NULL AND d.attested_identity_key = u.identity_pubkey
           AND d.share_public_key IS NOT NULL",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

// ---------------------------------------------------------------- KeyPackages

pub async fn key_package_count(db: &Pool, device_id: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM key_packages WHERE device_id = $1")
        .bind(device_id)
        .fetch_one(db)
        .await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// Stores KeyPackages; exact duplicates (same hash) are skipped. Returns the new count.
pub async fn insert_key_packages(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    packages: &[(Vec<u8>, String)],
) -> Result<i64, ApiError> {
    for (kp, hash) in packages {
        let r = sqlx::query(
            "INSERT INTO key_packages (id, user_id, device_id, key_package, hash, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ulid())
        .bind(user_id)
        .bind(device_id)
        .bind(kp.clone())
        .bind(hash)
        .bind(now())
        .execute(db)
        .await;
        match r {
            Ok(_) => {}
            Err(e) if super::is_unique_violation(&e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    key_package_count(db, device_id).await
}

/// Takes (and deletes) the oldest KeyPackage of a device. Concurrent claims never get the same one.
pub async fn claim_key_package(db: &Pool, device_id: &str) -> Result<Option<Vec<u8>>, ApiError> {
    for _ in 0..5 {
        let row = sqlx::query("SELECT id, key_package FROM key_packages WHERE device_id = $1 ORDER BY id LIMIT 1")
            .bind(device_id)
            .fetch_optional(db)
            .await?;
        let Some(row) = row else { return Ok(None) };
        let id: String = row.try_get("id")?;
        let kp: Vec<u8> = row.try_get("key_package")?;
        let r = sqlx::query("DELETE FROM key_packages WHERE id = $1").bind(&id).execute(db).await?;
        if r.rows_affected() == 1 {
            return Ok(Some(kp));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------- MLS delivery service

pub struct GroupRow {
    pub epoch: i64,
    pub group_info: Vec<u8>,
    pub ds_state: Vec<u8>,
}

pub async fn group(db: &Pool, conversation_id: &str) -> Result<Option<GroupRow>, ApiError> {
    let row = sqlx::query("SELECT epoch, group_info, ds_state FROM mls_groups WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_optional(db)
        .await?;
    row.map(|r| {
        Ok(GroupRow {
            epoch: r.try_get("epoch")?,
            group_info: r.try_get("group_info")?,
            ds_state: r.try_get("ds_state")?,
        })
    })
    .transpose()
}

pub async fn group_epoch(db: &Pool, conversation_id: &str) -> Result<Option<i64>, ApiError> {
    let row = sqlx::query("SELECT epoch FROM mls_groups WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get::<i64, _>("epoch")).transpose()?)
}

/// The group's current epoch and when it began (the time of the commit that started it, or of the group's creation).
pub async fn group_epoch_since(db: &Pool, conversation_id: &str) -> Result<Option<(i64, String)>, ApiError> {
    let row = sqlx::query("SELECT epoch, updated_at FROM mls_groups WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_optional(db)
        .await?;
    Ok(row
        .map(|r| Ok::<_, sqlx::Error>((r.try_get::<i64, _>("epoch")?, r.try_get::<String, _>("updated_at")?)))
        .transpose()?)
}

/// Creates the group state (epoch 0). `false` if a group already exists (first wins).
pub async fn create_group(
    db: &Pool,
    conversation_id: &str,
    group_info: &[u8],
    ds_state: &[u8],
) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "INSERT INTO mls_groups (conversation_id, epoch, group_info, ds_state, updated_at) VALUES ($1, 0, $2, $3, $4)",
    )
    .bind(conversation_id)
    .bind(group_info.to_vec())
    .bind(ds_state.to_vec())
    .bind(now())
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub struct AcceptedCommit<'a> {
    pub conversation_id: &'a str,
    pub epoch: i64,
    pub commit: &'a [u8],
    pub group_info: &'a [u8],
    pub ds_state: &'a [u8],
    pub committer_device_id: &'a str,
    /// Added local devices that receive the Welcome.
    pub welcome_devices: &'a [String],
    pub welcome: Option<&'a [u8]>,
}

/// Stores an accepted commit atomically: log entry (unique per epoch), group state (only if it
/// is still at `epoch`) and Welcomes. `false` if another commit won the epoch.
pub async fn apply_commit(db: &Pool, c: AcceptedCommit<'_>) -> Result<bool, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO mls_commits (conversation_id, epoch, message, committer_device_id, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(c.conversation_id)
    .bind(c.epoch)
    .bind(c.commit.to_vec())
    .bind(c.committer_device_id)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    let updated = sqlx::query(
        "UPDATE mls_groups SET epoch = $1, group_info = $2, ds_state = $3, updated_at = $4 WHERE conversation_id = $5 AND epoch = $6",
    )
    .bind(c.epoch + 1)
    .bind(c.group_info.to_vec())
    .bind(c.ds_state.to_vec())
    .bind(&ts)
    .bind(c.conversation_id)
    .bind(c.epoch)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Ok(false);
    }
    if let Some(welcome) = c.welcome {
        for device_id in c.welcome_devices {
            sqlx::query(
                "INSERT INTO mls_welcomes (id, conversation_id, device_id, epoch, welcome, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(ulid())
            .bind(c.conversation_id)
            .bind(device_id)
            .bind(c.epoch + 1)
            .bind(welcome.to_vec())
            .bind(&ts)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}

/// Handshake log from `since_epoch` (ascending).
pub async fn commits(
    db: &Pool,
    conversation_id: &str,
    since_epoch: i64,
    limit: i64,
) -> Result<Vec<(i64, Vec<u8>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT epoch, message FROM mls_commits WHERE conversation_id = $1 AND epoch >= $2 ORDER BY epoch ASC LIMIT $3",
    )
    .bind(conversation_id)
    .bind(since_epoch)
    .bind(limit)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("epoch")?, r.try_get("message")?))).collect()
}

pub struct WelcomeRow {
    pub id: String,
    pub conversation_id: String,
    pub epoch: i64,
    pub welcome: Vec<u8>,
    pub created_at: String,
}

pub async fn welcomes_for(db: &Pool, device_id: &str) -> Result<Vec<WelcomeRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, conversation_id, epoch, welcome, created_at FROM mls_welcomes WHERE device_id = $1 ORDER BY id LIMIT 100",
    )
    .bind(device_id)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(WelcomeRow {
                id: r.try_get("id")?,
                conversation_id: r.try_get("conversation_id")?,
                epoch: r.try_get("epoch")?,
                welcome: r.try_get("welcome")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

pub async fn delete_welcome(db: &Pool, device_id: &str, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM mls_welcomes WHERE id = $1 AND device_id = $2")
        .bind(id)
        .bind(device_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// MLS groups of a room's channels: (conversation id, DS state).
pub async fn groups_in_room(db: &Pool, room_id: &str) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT g.conversation_id, g.ds_state FROM mls_groups g JOIN conversations c ON c.id = g.conversation_id WHERE c.room_id = $1",
    )
    .bind(room_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("conversation_id")?, r.try_get("ds_state")?))).collect()
}

/// MLS groups of all conversations a user may be in (channels of their rooms, DMs, group DMs).
pub async fn groups_of_user(db: &Pool, user_id: &str) -> Result<Vec<(String, Vec<u8>)>, ApiError> {
    let rows = sqlx::query(
        "SELECT g.conversation_id, g.ds_state FROM mls_groups g JOIN conversations c ON c.id = g.conversation_id
         WHERE c.room_id IN (SELECT room_id FROM room_members WHERE user_id = $1)
            OR c.id IN (SELECT conversation_id FROM conversation_members WHERE user_id = $1)",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| Ok((r.try_get("conversation_id")?, r.try_get("ds_state")?))).collect()
}

pub async fn group_state(db: &Pool, conversation_id: &str) -> Result<Option<Vec<u8>>, ApiError> {
    Ok(group(db, conversation_id).await?.map(|g| g.ds_state))
}

// ---------------------------------------------------------------- Backups

pub struct BackupRow {
    pub conversation: String,
    pub size: i64,
    pub etag: String,
    pub updated_at: String,
}

pub async fn backup(db: &Pool, user_id: &str, conversation: &str) -> Result<Option<(Vec<u8>, String)>, ApiError> {
    let row = sqlx::query("SELECT blob, etag FROM key_backups WHERE user_id = $1 AND conversation = $2")
        .bind(user_id)
        .bind(conversation)
        .fetch_optional(db)
        .await?;
    row.map(|r| Ok((r.try_get("blob")?, r.try_get("etag")?))).transpose()
}

pub async fn backups(db: &Pool, user_id: &str) -> Result<Vec<BackupRow>, ApiError> {
    let rows = sqlx::query(
        "SELECT conversation, CAST(LENGTH(blob) AS BIGINT) AS size, etag, updated_at FROM key_backups WHERE user_id = $1 ORDER BY conversation",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(BackupRow {
                conversation: r.try_get("conversation")?,
                size: r.try_get("size")?,
                etag: r.try_get("etag")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect()
}

pub async fn backup_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let row =
        sqlx::query("SELECT COUNT(*) AS n FROM key_backups WHERE user_id = $1").bind(user_id).fetch_one(db).await?;
    Ok(row.try_get::<i64, _>("n")?)
}

/// Writes a backup. `expected` = the `If-Match` ETag (`None`: create only). `false` on mismatch.
pub async fn put_backup(
    db: &Pool,
    user_id: &str,
    conversation: &str,
    blob: &[u8],
    etag: &str,
    expected: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let ts = now();
    match expected {
        Some(old) => {
            let r = sqlx::query(
                "UPDATE key_backups SET blob = $1, etag = $2, updated_at = $3 WHERE user_id = $4 AND conversation = $5 AND etag = $6",
            )
            .bind(blob.to_vec())
            .bind(etag)
            .bind(&ts)
            .bind(user_id)
            .bind(conversation)
            .bind(old)
            .execute(db)
            .await?;
            Ok((r.rows_affected() == 1).then_some(ts))
        }
        None => {
            let r = sqlx::query(
                "INSERT INTO key_backups (user_id, conversation, blob, etag, updated_at) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(user_id)
            .bind(conversation)
            .bind(blob.to_vec())
            .bind(etag)
            .bind(&ts)
            .execute(db)
            .await;
            match r {
                Ok(_) => Ok(Some(ts)),
                Err(e) if super::is_unique_violation(&e) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
    }
}
