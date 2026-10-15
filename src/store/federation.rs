// SPDX-License-Identifier: AGPL-3.0-only
//! Federation tables (migration 0010): peers and their keys, replay store, federation targets, remote
//! users and devices, federated sessions, inbox dedupe and outbox.

use sqlx::{FromRow, Row};

use crate::{
    db::Pool,
    error::ApiError,
    models::UserRow,
    util::{now, ulid},
};

use super::{is_unique_violation, users::USER_COLS};

// ---------------------------------------------------------------- domain policy

/// The ban subjects that cover `domain` (FEDERATION.md §1.5, §3.3): the domain itself and its parent domains with
/// at least two labels (`a.evil.example` → `a.evil.example`, `evil.example`), at most 10.
pub fn covering_domains(domain: &str) -> Vec<String> {
    let mut out = vec![domain.to_string()];
    let mut rest = domain;
    while let Some((_, parent)) = rest.split_once('.') {
        if !parent.contains('.') || out.len() >= 10 {
            break;
        }
        out.push(parent.to_string());
        rest = parent;
    }
    out
}

/// The registrable domain of a node domain, approximated by its last two labels (`a.evil.example` →
/// `evil.example`): per-domain budgets that must not multiply with wildcard subdomains are counted on it.
pub fn parent_domain(domain: &str) -> &str {
    match domain.rmatch_indices('.').nth(1) {
        Some((i, _)) => &domain[i + 1..],
        None => domain,
    }
}

/// Is `domain` the domain `subject` or one of its subdomains?
pub fn within_domain(domain: &str, subject: &str) -> bool {
    domain == subject || domain.strip_suffix(subject).is_some_and(|head| head.ends_with('.'))
}

/// Node-wide ban of a whole domain or a parent domain (`POST /admin/bans` with a domain subject).
pub async fn domain_banned(db: &Pool, domain: &str) -> Result<bool, ApiError> {
    let subjects = covering_domains(domain);
    let list = (1..=subjects.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(", ");
    let sql = format!("SELECT 1 AS x FROM bans WHERE room_id IS NULL AND subject IN ({list}) LIMIT 1");
    let mut q = sqlx::query(&sql);
    for subject in &subjects {
        q = q.bind(subject);
    }
    Ok(q.fetch_optional(db).await?.is_some())
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    #[test]
    fn bans_cover_subdomains_only() {
        assert_eq!(covering_domains("a.evil.example"), vec!["a.evil.example", "evil.example"]);
        assert_eq!(covering_domains("evil.example"), vec!["evil.example"]);
        assert_eq!(covering_domains(&format!("{}x.example", "a.".repeat(20))).len(), 10);
        assert!(within_domain("a.evil.example", "evil.example"));
        assert!(within_domain("evil.example", "evil.example"));
        assert!(!within_domain("notevil.example", "evil.example"));
        assert!(!within_domain("example", "evil.example"));
        assert_eq!(parent_domain("a.b.evil.example"), "evil.example");
        assert_eq!(parent_domain("evil.example"), "evil.example");
    }
}

// ---------------------------------------------------------------- peers

#[derive(Debug, Clone, FromRow)]
pub struct PeerRow {
    pub domain: String,
    pub document: String,
    pub fetched_at: String,
    pub expires_at: String,
    pub status: String,
    pub kid_refresh_at: Option<String>,
}

pub async fn peer(db: &Pool, domain: &str) -> Result<Option<PeerRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT domain, document, fetched_at, expires_at, status, kid_refresh_at FROM federation_peers WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(db)
    .await?)
}

pub async fn peer_status(db: &Pool, domain: &str) -> Result<Option<String>, ApiError> {
    let row =
        sqlx::query("SELECT status FROM federation_peers WHERE domain = $1").bind(domain).fetch_optional(db).await?;
    Ok(row.map(|r| r.try_get::<String, _>("status")).transpose()?)
}

/// Stores a freshly fetched, valid document and where it came from (`well_known` or `srv`); the status stays as
/// it is. `origin` (`request`: created to check an unverified request) is set only when the row is created.
pub async fn upsert_peer(
    db: &Pool,
    domain: &str,
    document: &str,
    fetched_at: &str,
    expires_at: &str,
    source: &str,
    origin: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO federation_peers (domain, document, fetched_at, expires_at, source, origin)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (domain) DO UPDATE SET document = $2, fetched_at = $3, expires_at = $4, source = $5",
    )
    .bind(domain)
    .bind(document)
    .bind(fetched_at)
    .bind(expires_at)
    .bind(source)
    .bind(origin)
    .execute(db)
    .await?;
    Ok(())
}

/// Where the cached document of a peer came from (`None`: no row, or cached before the source was recorded).
pub async fn peer_source(db: &Pool, domain: &str) -> Result<Option<String>, ApiError> {
    let row =
        sqlx::query("SELECT source FROM federation_peers WHERE domain = $1").bind(domain).fetch_optional(db).await?;
    Ok(row.map(|r| r.try_get::<Option<String>, _>("source")).transpose()?.flatten())
}

/// Records that a signed request of the peer verified with its keys (at most one write per peer and day).
pub async fn mark_peer_verified(db: &Pool, domain: &str, now: &str, cutoff: &str) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE federation_peers SET verified_at = $1 WHERE domain = $2 AND (verified_at IS NULL OR verified_at < $3)",
    )
    .bind(now)
    .bind(domain)
    .bind(cutoff)
    .execute(db)
    .await?;
    Ok(())
}

/// Cached peers known only from requests whose signature never verified (FEDERATION.md §1.4): created to check such
/// a request, never verified since, and with no users, sign-ins or directory entry here. Peers this node looked up
/// itself (directory, relays, its users' actions) never count.
pub async fn count_unverified_peers(db: &Pool) -> Result<i64, ApiError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM federation_peers p WHERE p.origin = 'request' AND p.verified_at IS NULL
         AND NOT EXISTS (SELECT 1 FROM users u WHERE u.domain = p.domain)
         AND NOT EXISTS (SELECT 1 FROM federation_targets t WHERE t.target = p.domain)
         AND NOT EXISTS (SELECT 1 FROM directory_nodes d WHERE d.domain = p.domain)",
    )
    .fetch_one(db)
    .await?;
    Ok(n)
}

/// Marks a peer (creating a row if needed, with an empty, expired document).
pub async fn set_peer_status(db: &Pool, domain: &str, status: &str) -> Result<(), ApiError> {
    let ts = now();
    sqlx::query(
        "INSERT INTO federation_peers (domain, document, fetched_at, expires_at, status) VALUES ($1, '{}', $2, $2, $3)
         ON CONFLICT (domain) DO UPDATE SET status = $3",
    )
    .bind(domain)
    .bind(&ts)
    .bind(status)
    .execute(db)
    .await?;
    Ok(())
}

/// Claims the unknown-`kid` refetch of a peer: `true` if none happened since `cutoff`.
pub async fn claim_kid_refresh(db: &Pool, domain: &str, now: &str, cutoff: &str) -> Result<bool, ApiError> {
    let r = sqlx::query(
        "UPDATE federation_peers SET kid_refresh_at = $1 WHERE domain = $2 AND (kid_refresh_at IS NULL OR kid_refresh_at < $3)",
    )
    .bind(now)
    .bind(domain)
    .bind(cutoff)
    .execute(db)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Every `(kid, x)` ever seen for a peer.
pub async fn peer_keys(db: &Pool, domain: &str) -> Result<Vec<(String, String)>, ApiError> {
    let rows =
        sqlx::query("SELECT kid, x FROM federation_peer_keys WHERE domain = $1").bind(domain).fetch_all(db).await?;
    rows.iter().map(|r| Ok((r.try_get("kid")?, r.try_get("x")?))).collect()
}

pub async fn add_peer_key(db: &Pool, domain: &str, kid: &str, x: &str) -> Result<(), ApiError> {
    let r = sqlx::query("INSERT INTO federation_peer_keys (domain, kid, x, first_seen_at) VALUES ($1, $2, $3, $4)")
        .bind(domain)
        .bind(kid)
        .bind(x)
        .bind(now())
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(()),
        Err(e) if is_unique_violation(&e) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------- replay store

/// Records a `jti` of `iss`; `false` if it was seen before (replay).
pub async fn spend_jti(db: &Pool, iss: &str, jti: &str, expires_at: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("INSERT INTO federation_replay (iss, jti, expires_at) VALUES ($1, $2, $3)")
        .bind(iss)
        .bind(jti)
        .bind(expires_at)
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------- federation targets (home node)

pub async fn touch_target(db: &Pool, user_id: &str, device_id: &str, target: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO federation_targets (user_id, device_id, target, last_issued_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, device_id, target) DO UPDATE SET last_issued_at = $4",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(target)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

/// Distinct target domains a user requested federation tokens for (any device).
pub async fn target_domains(db: &Pool, user_id: &str) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query("SELECT DISTINCT target FROM federation_targets WHERE user_id = $1 ORDER BY target")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|r| Ok(r.try_get("target")?)).collect()
}

/// Does this node have federation history with `domain`: users of it known here since before `known_before` (a stub
/// the sender itself just caused, for example by a friend request, does not count), local users who signed in
/// there, or the node listed in this node's directory?
pub async fn has_history(db: &Pool, domain: &str, known_before: &str) -> Result<bool, ApiError> {
    let row = sqlx::query(
        "SELECT 1 AS x FROM users WHERE domain = $1 AND created_at < $2
         UNION ALL SELECT 1 AS x FROM federation_targets WHERE target = $1
         UNION ALL SELECT 1 AS x FROM directory_nodes WHERE domain = $1 LIMIT 1",
    )
    .bind(domain)
    .bind(known_before)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

// ---------------------------------------------------------------- profiles (home node)

/// `(profile_version, avatar_sha256, avatar media id, avatar mime)` of a user (the still image).
pub async fn profile_info(
    db: &Pool,
    user_id: &str,
) -> Result<(i64, Option<String>, Option<String>, Option<String>), ApiError> {
    let row = sqlx::query(
        "SELECT u.profile_version AS pv, m.still_sha256 AS sha, m.id AS blob_id, m.mime AS mime
         FROM users u LEFT JOIN media m ON m.id = u.avatar_blob_id WHERE u.id = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;
    Ok((row.try_get("pv")?, row.try_get("sha")?, row.try_get("blob_id")?, row.try_get("mime")?))
}

// ---------------------------------------------------------------- remote users (target node)

#[derive(Debug, Clone, FromRow)]
pub struct RemoteMeta {
    pub user_id: String,
    pub profile_version: i64,
    pub profile_fetched_at: Option<String>,
    pub avatar_sha256: Option<String>,
    pub avatar_mime: Option<String>,
    pub keys_fetched_at: Option<String>,
    pub last_login_at: Option<String>,
}

pub async fn remote_meta(db: &Pool, user_id: &str) -> Result<Option<RemoteMeta>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT user_id, profile_version, profile_fetched_at, avatar_sha256, avatar_mime, keys_fetched_at, last_login_at
         FROM remote_users WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

/// Number of remote users (all domains other than `local_domain`, or exactly `domain`).
pub async fn count_remote_users(db: &Pool, local_domain: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM users WHERE domain <> $1")
        .bind(local_domain)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}

pub async fn count_users_of_domain(db: &Pool, domain: &str) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM users WHERE domain = $1")
        .bind(domain)
        .fetch_one(db)
        .await?;
    Ok(row.try_get("n")?)
}

/// Sets the account kind and owner of a remote user from a verified federation token of its home node (a stub
/// created earlier, for example by a friend request, did not know them).
pub async fn set_remote_kind(db: &Pool, user_id: &str, kind: &str, owner_id: Option<&str>) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET kind = $1, owner_id = $2 WHERE id = $3")
        .bind(kind)
        .bind(owner_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Creates the users row of a remote user (no password, email or factors) and its mirror state.
/// Returns the existing row if another request created it concurrently.
pub async fn create_remote_user(
    db: &Pool,
    username: &str,
    domain: &str,
    display_name: &str,
    kind: &str,
    owner_id: Option<&str>,
) -> Result<UserRow, ApiError> {
    let id = ulid();
    let ts = now();
    let mut tx = db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, domain, display_name, kind, owner_id, is_node_admin, created_at, profile_version)
         VALUES ($1, $2, $3, $4, $5, $6, 0, $7, 0)",
    )
    .bind(&id)
    .bind(username)
    .bind(domain)
    .bind(display_name)
    .bind(kind)
    .bind(owner_id)
    .bind(&ts)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {
            sqlx::query("INSERT INTO remote_users (user_id, profile_version) VALUES ($1, 0)")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        }
        Err(e) if is_unique_violation(&e) => drop(tx),
        Err(e) => return Err(e.into()),
    }
    super::users::by_username(db, username, domain)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("remote user missing after insert")))
}

/// Mirrors a fetched profile: display name, version and fetch time.
pub async fn store_profile(db: &Pool, user_id: &str, display_name: &str, version: i64) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(display_name)
        .bind(user_id)
        .execute(db)
        .await?;
    sqlx::query(
        "INSERT INTO remote_users (user_id, profile_version, profile_fetched_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE SET profile_version = $2, profile_fetched_at = $3",
    )
    .bind(user_id)
    .bind(version)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

/// Mirrors bio, linked accounts (JSON) and the DM setting of a remote user.
pub async fn store_remote_profile_fields(
    db: &Pool,
    user_id: &str,
    bio: &str,
    links: &str,
    dm_policy: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET bio = $1, links = $2, dm_policy = $3 WHERE id = $4")
        .bind(bio)
        .bind(links)
        .bind(dm_policy)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Hashes of the mirrored images of a remote user (what the home node announced when they were copied).
#[derive(Debug, Default, Clone)]
pub struct RemoteImageHashes {
    pub avatar: Option<String>,
    pub avatar_animated: Option<String>,
    pub header: Option<String>,
    pub header_animated: Option<String>,
}

pub async fn remote_image_hashes(db: &Pool, user_id: &str) -> Result<RemoteImageHashes, ApiError> {
    let row = sqlx::query(
        "SELECT avatar_sha256, avatar_animated_sha256, header_sha256, header_animated_sha256 FROM remote_users WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(RemoteImageHashes::default()) };
    Ok(RemoteImageHashes {
        avatar: row.try_get("avatar_sha256")?,
        avatar_animated: row.try_get("avatar_animated_sha256")?,
        header: row.try_get("header_sha256")?,
        header_animated: row.try_get("header_animated_sha256")?,
    })
}

/// Records the hashes of a mirrored avatar or header (`kind`), NULL when it was removed.
pub async fn set_remote_image_hashes(
    db: &Pool,
    user_id: &str,
    kind: &str,
    still: Option<&str>,
    animated: Option<&str>,
    mime: Option<&str>,
) -> Result<(), ApiError> {
    let sql = if kind == "header" {
        "UPDATE remote_users SET header_sha256 = $1, header_animated_sha256 = $2 WHERE user_id = $3"
    } else {
        "UPDATE remote_users SET avatar_sha256 = $1, avatar_animated_sha256 = $2, avatar_mime = $4 WHERE user_id = $3"
    };
    let q = sqlx::query(sql).bind(still).bind(animated).bind(user_id);
    let q = if kind == "header" { q } else { q.bind(mime) };
    q.execute(db).await?;
    Ok(())
}

pub async fn touch_login(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE remote_users SET last_login_at = $1 WHERE user_id = $2")
        .bind(now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// An attested device of a remote user as published by the home node (signature verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDeviceKey {
    pub home_device_id: String,
    pub public_key: String,
    pub identity_signature: String,
    /// The device's share key and its device signature (ENCRYPTION.md §3.1), both or neither (signature verified).
    pub share_public_key: Option<String>,
    pub share_key_signature: Option<String>,
}

/// Stores the key view of a remote user's home node: identity key, attested devices (device rows
/// keyed by `(user, home device id)`, created when missing) and the fetch time. Devices that were
/// attested under the previous identity key and are no longer published lose their attestation.
/// Returns the home device ids of those vanished devices.
pub async fn store_remote_keys(
    db: &Pool,
    user_id: &str,
    home_domain: &str,
    identity: Option<&str>,
    identity_reset_at: Option<&str>,
    devices: &[RemoteDeviceKey],
) -> Result<Vec<String>, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    let before = sqlx::query(
        "SELECT d.home_device_id AS home FROM devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.home_device_id IS NOT NULL AND d.identity_signature IS NOT NULL
           AND d.attested_identity_key = u.identity_pubkey",
    )
    .bind(user_id)
    .fetch_all(&mut *tx)
    .await?;
    let before: Vec<String> = before.iter().map(|r| r.try_get("home")).collect::<Result<_, _>>()?;
    sqlx::query("UPDATE users SET identity_pubkey = $1, identity_reset_at = $2 WHERE id = $3")
        .bind(identity)
        .bind(identity_reset_at)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE devices SET identity_signature = NULL, attested_identity_key = NULL, attested_at = NULL
         WHERE user_id = $1 AND home_device_id IS NOT NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    for d in devices {
        let updated = sqlx::query(
            "UPDATE devices SET public_key = $1, identity_signature = $2, attested_identity_key = $3, attested_at = $4,
                                share_public_key = $7, share_key_signature = $8
             WHERE user_id = $5 AND home_device_id = $6",
        )
        .bind(&d.public_key)
        .bind(&d.identity_signature)
        .bind(identity)
        .bind(&ts)
        .bind(user_id)
        .bind(&d.home_device_id)
        .bind(&d.share_public_key)
        .bind(&d.share_key_signature)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                "INSERT INTO devices (id, user_id, name, client, created_at, last_seen_at, home_device_id, home_domain,
                                      public_key, identity_signature, attested_identity_key, attested_at,
                                      share_public_key, share_key_signature)
                 VALUES ($1, $2, '', '', $3, $3, $4, $5, $6, $7, $8, $3, $9, $10)",
            )
            .bind(ulid())
            .bind(user_id)
            .bind(&ts)
            .bind(&d.home_device_id)
            .bind(home_domain)
            .bind(&d.public_key)
            .bind(&d.identity_signature)
            .bind(identity)
            .bind(&d.share_public_key)
            .bind(&d.share_key_signature)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query(
        "INSERT INTO remote_users (user_id, profile_version, keys_fetched_at) VALUES ($1, 0, $2)
         ON CONFLICT (user_id) DO UPDATE SET keys_fetched_at = $2",
    )
    .bind(user_id)
    .bind(&ts)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let still: Vec<&str> = devices.iter().filter(|_| identity.is_some()).map(|d| d.home_device_id.as_str()).collect();
    Ok(before.into_iter().filter(|h| !still.contains(&h.as_str())).collect())
}

/// An attested device of a remote user from the key cache.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RemoteAttestedDevice {
    pub home_device_id: String,
    pub public_key: String,
    pub identity_signature: String,
    pub created_at: String,
    pub share_public_key: Option<String>,
    pub share_key_signature: Option<String>,
}

/// Attested devices of a remote user from the key cache.
pub async fn remote_attested_devices(db: &Pool, user_id: &str) -> Result<Vec<RemoteAttestedDevice>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT d.home_device_id, d.public_key, d.identity_signature, d.created_at, d.share_public_key,
                d.share_key_signature
         FROM devices d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.home_device_id IS NOT NULL AND d.public_key IS NOT NULL
           AND d.identity_signature IS NOT NULL AND d.attested_identity_key = u.identity_pubkey
         ORDER BY d.created_at, d.id",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// Local row id of a remote user's device by its home device id.
pub async fn remote_device_row(db: &Pool, user_id: &str, home_device_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query("SELECT id FROM devices WHERE user_id = $1 AND home_device_id = $2")
        .bind(user_id)
        .bind(home_device_id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|r| r.try_get::<String, _>("id")).transpose()?)
}

/// Marks the key cache of a remote user as stale (`identity.changed`, `devices.changed`).
pub async fn invalidate_keys(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE remote_users SET keys_fetched_at = NULL WHERE user_id = $1").bind(user_id).execute(db).await?;
    Ok(())
}

/// A remote user's identity changed (`identity.changed`, FEDERATION.md §5.2): the new key and reset time, and with
/// `reset_window_at` the start of the user's history window on every membership here (ENCRYPTION.md §7b), in one
/// transaction: the key change is never recorded without its window.
pub async fn reset_remote_identity(
    db: &Pool,
    user_id: &str,
    key: &str,
    reset_at: &str,
    reset_window_at: Option<&str>,
) -> Result<(), ApiError> {
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE users SET identity_pubkey = $1, identity_reset_at = $2 WHERE id = $3")
        .bind(key)
        .bind(reset_at)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if let Some(at) = reset_window_at {
        super::history::mark_key_reset_tx(&mut tx, user_id, at).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Replaces the cached identity key of a remote user if it is still `old` (compare and swap): `true` for the one
/// caller that observed the change (it writes the `system.key_changed` entries).
pub async fn swap_remote_identity(db: &Pool, user_id: &str, old: &str, new: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE users SET identity_pubkey = $1 WHERE id = $2 AND identity_pubkey = $3")
        .bind(new)
        .bind(user_id)
        .bind(old)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

// ---------------------------------------------------------------- remote devices and sessions

/// Local row id of a remote device, created if missing (keyed by `(user, home device id)`).
pub async fn ensure_remote_device(
    db: &Pool,
    user_id: &str,
    home_device_id: &str,
    home_domain: &str,
    name: &str,
    client: &str,
) -> Result<String, ApiError> {
    let find = || async {
        let row = sqlx::query("SELECT id FROM devices WHERE user_id = $1 AND home_device_id = $2")
            .bind(user_id)
            .bind(home_device_id)
            .fetch_optional(db)
            .await?;
        Ok::<_, ApiError>(row.map(|r| r.try_get::<String, _>("id")).transpose()?)
    };
    if let Some(id) = find().await? {
        sqlx::query("UPDATE devices SET name = $1, client = $2, last_seen_at = $3 WHERE id = $4")
            .bind(name)
            .bind(client)
            .bind(now())
            .bind(&id)
            .execute(db)
            .await?;
        return Ok(id);
    }
    let id = ulid();
    let ts = now();
    let r = sqlx::query(
        "INSERT INTO devices (id, user_id, name, client, created_at, last_seen_at, home_device_id, home_domain)
         VALUES ($1, $2, $3, $4, $5, $5, $6, $7)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(client)
    .bind(&ts)
    .bind(home_device_id)
    .bind(home_domain)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(id),
        Err(e) if is_unique_violation(&e) => {
            find().await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("remote device missing after conflict")))
        }
        Err(e) => Err(e.into()),
    }
}

/// Home device id of a device row (remote devices only).
pub async fn home_device_id(db: &Pool, device_id: &str) -> Result<Option<String>, ApiError> {
    let row =
        sqlx::query("SELECT home_device_id FROM devices WHERE id = $1").bind(device_id).fetch_optional(db).await?;
    Ok(row.and_then(|r| r.try_get::<Option<String>, _>("home_device_id").ok().flatten()))
}

/// Revokes every session of a device and creates the single federated session, ending at
/// `max_expires_at` whatever the refreshes.
pub async fn replace_federated_session(
    db: &Pool,
    user_id: &str,
    device_id: &str,
    refresh_hash: &str,
    max_expires_at: &str,
) -> Result<(), ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL")
        .bind(&ts)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO sessions (id, user_id, device_id, refresh_token_hash, created_at, expires_at, max_expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(ulid())
    .bind(user_id)
    .bind(device_id)
    .bind(refresh_hash)
    .bind(&ts)
    .bind(max_expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `Some(home device id)` if the remote device has a live (not revoked, not expired) session.
pub async fn live_remote_session(db: &Pool, user_id: &str, device_id: &str) -> Result<Option<String>, ApiError> {
    let row = sqlx::query(
        "SELECT d.home_device_id AS home FROM sessions s JOIN devices d ON d.id = s.device_id
         WHERE s.device_id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > $3 LIMIT 1",
    )
    .bind(device_id)
    .bind(user_id)
    .bind(now())
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|r| r.try_get::<Option<String>, _>("home").ok().flatten()))
}

/// Revokes the sessions of a remote user: of one home device, or all. Returns the affected device rows.
pub async fn revoke_remote_sessions(
    db: &Pool,
    user_id: &str,
    home_device_id: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    let rows = match home_device_id {
        Some(home) => {
            sqlx::query("SELECT id FROM devices WHERE user_id = $1 AND home_device_id = $2")
                .bind(user_id)
                .bind(home)
                .fetch_all(db)
                .await?
        }
        None => sqlx::query("SELECT id FROM devices WHERE user_id = $1").bind(user_id).fetch_all(db).await?,
    };
    let ids: Vec<String> = rows.iter().map(|r| r.try_get("id")).collect::<Result<_, _>>()?;
    let ts = now();
    for id in &ids {
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL")
            .bind(&ts)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(ids)
}

/// Users whose home domain is `domain`, and bots whose owner's home domain is `domain`.
/// Users of `domain` and of its subdomains (and bots whose owner is one), the users a domain ban covers.
pub async fn users_within_domain(db: &Pool, domain: &str) -> Result<Vec<UserRow>, ApiError> {
    let cols: Vec<String> = USER_COLS.split(',').map(|c| format!("u.{}", c.trim())).collect();
    let rows: Vec<UserRow> = sqlx::query_as(&format!(
        "SELECT {} FROM users u LEFT JOIN users o ON o.id = u.owner_id
         WHERE u.domain = $1 OR o.domain = $1 OR u.domain LIKE $2 OR o.domain LIKE $2",
        cols.join(", ")
    ))
    .bind(domain)
    .bind(format!("%.{domain}"))
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn users_of_domain(db: &Pool, domain: &str) -> Result<Vec<UserRow>, ApiError> {
    let cols: Vec<String> = USER_COLS.split(',').map(|c| format!("u.{}", c.trim())).collect();
    Ok(sqlx::query_as(&format!(
        "SELECT {} FROM users u LEFT JOIN users o ON o.id = u.owner_id WHERE u.domain = $1 OR o.domain = $1",
        cols.join(", ")
    ))
    .bind(domain)
    .fetch_all(db)
    .await?)
}

/// Remote user row by address parts.
pub async fn user_by_address(db: &Pool, username: &str, domain: &str) -> Result<Option<UserRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {USER_COLS} FROM users WHERE username = $1 AND domain = $2"))
        .bind(username)
        .bind(domain)
        .fetch_optional(db)
        .await?)
}

// ---------------------------------------------------------------- inbox

/// Records an inbox message id of `iss`; `false` if it was seen before (duplicate).
/// Forgets a seen inbox message whose handling failed on this node's side, so the sender's retry is handled again.
pub async fn unmark_seen(db: &Pool, iss: &str, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM federation_inbox_seen WHERE iss = $1 AND id = $2").bind(iss).bind(id).execute(db).await?;
    Ok(())
}

pub async fn mark_seen(db: &Pool, iss: &str, id: &str, kind: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("INSERT INTO federation_inbox_seen (iss, id, type, seen_at) VALUES ($1, $2, $3, $4)")
        .bind(iss)
        .bind(id)
        .bind(kind)
        .bind(now())
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------- outbox

#[derive(Debug, Clone, FromRow)]
pub struct OutboxRow {
    pub id: String,
    pub target: String,
    #[sqlx(rename = "type")]
    pub kind: String,
    pub body: String,
    pub attempts: i64,
    pub next_at: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_status: Option<i64>,
    pub last_error: Option<String>,
}

const OUTBOX_COLS: &str = "id, target, type, body, attempts, next_at, created_at, expires_at, last_status, last_error";

pub struct NewOutbox<'a> {
    pub id: &'a str,
    pub target: &'a str,
    pub kind: &'a str,
    pub body: &'a str,
    pub created_at: &'a str,
    pub expires_at: &'a str,
}

pub async fn enqueue(db: &Pool, e: NewOutbox<'_>) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO federation_outbox (id, target, type, body, attempts, next_at, created_at, expires_at)
         VALUES ($1, $2, $3, $4, 0, $5, $5, $6)",
    )
    .bind(e.id)
    .bind(e.target)
    .bind(e.kind)
    .bind(e.body)
    .bind(e.created_at)
    .bind(e.expires_at)
    .execute(db)
    .await?;
    Ok(())
}

/// [`enqueue`] for many entries: one multi-row `INSERT` per 500 (a message's `notify` hints to many members).
pub async fn enqueue_many(db: &Pool, entries: &[NewOutbox<'_>]) -> Result<(), ApiError> {
    for chunk in entries.chunks(500) {
        let rows: Vec<String> = (0..chunk.len())
            .map(|i| {
                let b = i * 6;
                format!("(${}, ${}, ${}, ${}, 0, ${}, ${}, ${})", b + 1, b + 2, b + 3, b + 4, b + 5, b + 5, b + 6)
            })
            .collect();
        let sql = format!(
            "INSERT INTO federation_outbox (id, target, type, body, attempts, next_at, created_at, expires_at) VALUES {}",
            rows.join(", ")
        );
        let mut q = sqlx::query(&sql);
        for e in chunk {
            q = q.bind(e.id).bind(e.target).bind(e.kind).bind(e.body).bind(e.created_at).bind(e.expires_at);
        }
        q.execute(db).await?;
    }
    Ok(())
}

/// Queues `e` in place of the entries of the same target and type that `from` sent and that are still queued
/// (coalescing, FEDERATION.md §5.2 `profile.changed`): at most one such entry stays. The new entry is due at the
/// earliest `next_at` of the replaced ones (a waiting or backed-off target keeps its schedule), else at `next_at`.
/// Returns the number of replaced entries. An entry that is being delivered while it is replaced may still
/// arrive; its successor follows with the newer content.
pub async fn enqueue_replacing(db: &Pool, e: NewOutbox<'_>, from: &str, next_at: &str) -> Result<u64, ApiError> {
    let mut tx = db.begin().await?;
    let queued: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, body, next_at FROM federation_outbox WHERE target = $1 AND type = $2")
            .bind(e.target)
            .bind(e.kind)
            .fetch_all(&mut *tx)
            .await?;
    let mut due = next_at.to_string();
    let mut replaced = 0;
    for (id, body, at) in queued {
        let sender = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|b| b.get("from").and_then(|f| f.as_str()).map(String::from));
        if sender.as_deref() != Some(from) {
            continue;
        }
        sqlx::query("DELETE FROM federation_outbox WHERE id = $1").bind(&id).execute(&mut *tx).await?;
        replaced += 1;
        if at < due {
            due = at;
        }
    }
    sqlx::query(
        "INSERT INTO federation_outbox (id, target, type, body, attempts, next_at, created_at, expires_at)
         VALUES ($1, $2, $3, $4, 0, $5, $6, $7)",
    )
    .bind(e.id)
    .bind(e.target)
    .bind(e.kind)
    .bind(e.body)
    .bind(&due)
    .bind(e.created_at)
    .bind(e.expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(replaced)
}

/// Entries due at `now`, oldest first.
pub async fn due(db: &Pool, now: &str, limit: i64) -> Result<Vec<OutboxRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {OUTBOX_COLS} FROM federation_outbox WHERE next_at <= $1 ORDER BY next_at, id LIMIT $2"
    ))
    .bind(now)
    .bind(limit)
    .fetch_all(db)
    .await?)
}

pub async fn outbox_entries(db: &Pool) -> Result<Vec<OutboxRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {OUTBOX_COLS} FROM federation_outbox ORDER BY id")).fetch_all(db).await?)
}

pub async fn delete_outbox(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM federation_outbox WHERE id = $1").bind(id).execute(db).await?;
    Ok(())
}

pub async fn reschedule(
    db: &Pool,
    id: &str,
    attempts: i64,
    next_at: &str,
    last_status: Option<i64>,
    last_error: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE federation_outbox SET attempts = $1, next_at = $2, last_status = $3, last_error = $4 WHERE id = $5",
    )
    .bind(attempts)
    .bind(next_at)
    .bind(last_status)
    .bind(last_error)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Delays every queued entry of a target that is due before `next_at` (a failed target is not hammered).
pub async fn delay_target(db: &Pool, target: &str, next_at: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE federation_outbox SET next_at = $1 WHERE target = $2 AND next_at < $1")
        .bind(next_at)
        .bind(target)
        .execute(db)
        .await?;
    Ok(())
}

const UNDELIVERABLE_KEY: &str = "federation.undeliverable";

/// Counts a given-up outbox entry (admin overview).
pub async fn count_undeliverable(db: &Pool) -> Result<(), ApiError> {
    let current = undeliverable_count(db).await?;
    sqlx::query(
        "INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = $3",
    )
    .bind(UNDELIVERABLE_KEY)
    .bind((current + 1).to_string())
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

/// Number of outbox entries given up so far.
pub async fn undeliverable_count(db: &Pool) -> Result<i64, ApiError> {
    let row = sqlx::query("SELECT value FROM node_settings WHERE key = $1")
        .bind(UNDELIVERABLE_KEY)
        .fetch_optional(db)
        .await?;
    Ok(row.and_then(|r| r.try_get::<String, _>("value").ok()).and_then(|v| v.parse().ok()).unwrap_or(0))
}

// ---------------------------------------------------------------- housekeeping

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FederationPrune {
    pub replay: u64,
    pub inbox_seen: u64,
    pub targets: u64,
    /// Push hints older than the inbox window and expired invitations.
    pub hints_and_invites: u64,
    /// Cached peers unused for 30 days that nothing ties to this node.
    pub peers: u64,
}

/// Drops spent `jti`s after their expiry, inbox ids and push hints after 7 days, expired invitations and
/// federation targets after 30 days, and cached peer documents (with their key history) not fetched for 30 days
/// when no user of the domain is known here, no local user signed in there, the directory does not list it and it
/// is not blocked (FEDERATION.md §1.4).
pub async fn prune(db: &Pool, now: &str, seen_cutoff: &str, targets_cutoff: &str) -> Result<FederationPrune, ApiError> {
    let replay =
        sqlx::query("DELETE FROM federation_replay WHERE expires_at < $1").bind(now).execute(db).await?.rows_affected();
    let inbox_seen = sqlx::query("DELETE FROM federation_inbox_seen WHERE seen_at < $1")
        .bind(seen_cutoff)
        .execute(db)
        .await?
        .rows_affected();
    let targets = sqlx::query("DELETE FROM federation_targets WHERE last_issued_at < $1")
        .bind(targets_cutoff)
        .execute(db)
        .await?
        .rows_affected();
    let hints = super::invites::prune_hints(db, seen_cutoff).await?;
    let invites =
        sqlx::query("DELETE FROM user_invites WHERE expires_at < $1").bind(now).execute(db).await?.rows_affected();
    let unused = "SELECT domain FROM federation_peers p WHERE p.fetched_at < $1 AND p.status = 'ok'
         AND NOT EXISTS (SELECT 1 FROM users u WHERE u.domain = p.domain)
         AND NOT EXISTS (SELECT 1 FROM federation_targets t WHERE t.target = p.domain)
         AND NOT EXISTS (SELECT 1 FROM directory_nodes d WHERE d.domain = p.domain)";
    sqlx::query(&format!("DELETE FROM federation_peer_keys WHERE domain IN ({unused})"))
        .bind(targets_cutoff)
        .execute(db)
        .await?;
    let peers = sqlx::query(&format!("DELETE FROM federation_peers WHERE domain IN ({unused})"))
        .bind(targets_cutoff)
        .execute(db)
        .await?
        .rows_affected();
    Ok(FederationPrune { replay, inbox_seen, targets, hints_and_invites: hints + invites, peers })
}
