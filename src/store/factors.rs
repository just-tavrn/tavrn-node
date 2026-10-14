// SPDX-License-Identifier: AGPL-3.0-only
//! Second factors (TOTP, recovery codes, WebAuthn), WebAuthn ceremony state and spent pre-auth
//! tokens.

use sqlx::Row;

use crate::{
    db::Pool,
    error::ApiError,
    util::{in_seconds, now, ulid},
};

// ---------------------------------------------------------------- TOTP

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TotpRow {
    pub secret: Vec<u8>,
    pub confirmed_at: Option<String>,
    pub last_step: i64,
}

pub async fn totp(db: &Pool, user_id: &str) -> Result<Option<TotpRow>, ApiError> {
    Ok(sqlx::query_as("SELECT secret, confirmed_at, last_step FROM totp_secrets WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await?)
}

/// Stores a new, unconfirmed secret (replaces an unconfirmed one). `false` if a confirmed secret exists.
pub async fn put_pending_totp(db: &Pool, user_id: &str, secret: &[u8]) -> Result<bool, ApiError> {
    let mut tx = db.begin().await?;
    let confirmed = sqlx::query("SELECT 1 AS x FROM totp_secrets WHERE user_id = $1 AND confirmed_at IS NOT NULL")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    if confirmed.is_some() {
        return Ok(false);
    }
    sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO totp_secrets (user_id, secret, last_step, created_at) VALUES ($1, $2, 0, $3)")
        .bind(user_id)
        .bind(secret.to_vec())
        .bind(now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Accepts the code of `step` once: succeeds only if `step` is newer than the last accepted one
/// (atomic, so two parallel requests with the same code cannot both pass).
pub async fn use_totp_step(db: &Pool, user_id: &str, step: i64) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE totp_secrets SET last_step = $1 WHERE user_id = $2 AND last_step < $1")
        .bind(step)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn confirm_totp(db: &Pool, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE totp_secrets SET confirmed_at = $1 WHERE user_id = $2 AND confirmed_at IS NULL")
        .bind(now())
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- Recovery codes

/// Replaces the user's recovery codes with a new set (`salt`, hashes).
pub async fn replace_recovery_codes(db: &Pool, user_id: &str, salt: &str, hashes: &[String]) -> Result<(), ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    for hash in hashes {
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, salt, code_hash, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(ulid())
        .bind(user_id)
        .bind(salt)
        .bind(hash)
        .bind(&ts)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn has_recovery_codes(db: &Pool, user_id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM recovery_codes WHERE user_id = $1 LIMIT 1")
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .is_some())
}

/// Unused codes: `(id, salt, hash)`.
pub async fn unused_recovery_codes(db: &Pool, user_id: &str) -> Result<Vec<(String, String, String)>, ApiError> {
    let rows = sqlx::query("SELECT id, salt, code_hash FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    rows.iter()
        .map(|r| Ok((r.try_get("id")?, r.try_get("salt")?, r.try_get("code_hash")?)))
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

/// Marks a code used; `false` if a parallel request was faster.
pub async fn use_recovery_code(db: &Pool, id: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("UPDATE recovery_codes SET used_at = $1 WHERE id = $2 AND used_at IS NULL")
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected() == 1)
}

// ---------------------------------------------------------------- WebAuthn credentials

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub credential_id: String,
    pub user_id: String,
    pub name: String,
    pub passkey: String,
    pub prf_supported: i64,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

const CRED_COLS: &str = "credential_id, user_id, name, passkey, prf_supported, created_at, last_used_at";

pub async fn credentials(db: &Pool, user_id: &str) -> Result<Vec<CredentialRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at, credential_id"
    ))
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// A credential of `user_id` (`None` if it does not exist or belongs to someone else).
pub async fn credential(db: &Pool, user_id: &str, credential_id: &str) -> Result<Option<CredentialRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {CRED_COLS} FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2"
    ))
    .bind(credential_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

pub enum InsertCredential {
    Inserted,
    LimitReached,
    Duplicate,
}

pub struct NewCredential<'a> {
    pub credential_id: &'a str,
    pub user_id: &'a str,
    pub name: &'a str,
    pub passkey: &'a str,
    pub prf_supported: bool,
}

/// Stores a credential unless the user already has `limit` (checked under a row lock on the user,
/// so parallel registrations cannot exceed it) or the credential id is taken.
pub async fn insert_credential(db: &Pool, c: NewCredential<'_>, limit: i64) -> Result<InsertCredential, ApiError> {
    let mut tx = db.begin().await?;
    lock_user(&mut tx, c.user_id).await?;
    let n: i64 = sqlx::query("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = $1")
        .bind(c.user_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    if n >= limit {
        return Ok(InsertCredential::LimitReached);
    }
    let r = sqlx::query(
        "INSERT INTO webauthn_credentials (credential_id, user_id, name, passkey, prf_supported, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(c.credential_id)
    .bind(c.user_id)
    .bind(c.name)
    .bind(c.passkey)
    .bind(c.prf_supported as i64)
    .bind(now())
    .execute(&mut *tx)
    .await;
    match r {
        Ok(_) => {}
        Err(e) if super::is_unique_violation(&e) => return Ok(InsertCredential::Duplicate),
        Err(e) => return Err(e.into()),
    }
    tx.commit().await?;
    Ok(InsertCredential::Inserted)
}

pub async fn count_credentials(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?
        .try_get("n")?)
}

/// Stores the updated `Passkey` (counter, backup flags) after a successful assertion.
pub async fn credential_used(db: &Pool, credential_id: &str, passkey: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE webauthn_credentials SET passkey = $1, last_used_at = $2 WHERE credential_id = $3")
        .bind(passkey)
        .bind(now())
        .bind(credential_id)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- Factors overall

pub async fn has_factor(db: &Pool, user_id: &str) -> Result<bool, ApiError> {
    let totp = sqlx::query("SELECT 1 AS x FROM totp_secrets WHERE user_id = $1 AND confirmed_at IS NOT NULL")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    Ok(totp.is_some() || count_credentials(db, user_id).await? > 0)
}

/// Serializes factor changes of one user: the no-op update takes the user's row lock in
/// PostgreSQL (a non-key column, so foreign key checks elsewhere are not blocked); SQLite
/// serializes write transactions anyway.
async fn lock_user(tx: &mut sqlx::Transaction<'_, sqlx::Any>, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE users SET display_name = display_name WHERE id = $1").bind(user_id).execute(&mut **tx).await?;
    Ok(())
}

pub enum Factor<'a> {
    Totp,
    Webauthn(&'a str),
}

pub enum RemoveFactor {
    Removed,
    NotFound,
    LastFactor,
}

/// Removes a factor unless it is the last one. Removing a credential also removes its secret
/// storage entry (`passkey:<credential id>`).
pub async fn remove_factor(db: &Pool, user_id: &str, factor: Factor<'_>) -> Result<RemoveFactor, ApiError> {
    let mut tx = db.begin().await?;
    lock_user(&mut tx, user_id).await?;
    let totp: i64 =
        sqlx::query("SELECT COUNT(*) AS n FROM totp_secrets WHERE user_id = $1 AND confirmed_at IS NOT NULL")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?
            .try_get("n")?;
    let creds: i64 = sqlx::query("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    let exists = match factor {
        Factor::Totp => totp > 0,
        Factor::Webauthn(id) => {
            sqlx::query("SELECT 1 AS x FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2")
                .bind(id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?
                .is_some()
        }
    };
    if !exists {
        return Ok(RemoveFactor::NotFound);
    }
    if totp + creds <= 1 {
        return Ok(RemoveFactor::LastFactor);
    }
    match factor {
        Factor::Totp => {
            sqlx::query("DELETE FROM totp_secrets WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
        }
        Factor::Webauthn(id) => {
            sqlx::query("DELETE FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2")
                .bind(id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM secret_storage WHERE user_id = $1 AND method = $2")
                .bind(user_id)
                .bind(format!("passkey:{id}"))
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(RemoveFactor::Removed)
}

/// Admin rescue: removes every second factor of a user (TOTP, WebAuthn credentials with their
/// passkey secret storage entries, recovery codes, open challenges) and revokes all sessions.
/// The `recovery` secret storage entry stays. Returns the number of removed credentials.
pub async fn reset_second_factor(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    let ts = now();
    let mut tx = db.begin().await?;
    lock_user(&mut tx, user_id).await?;
    let creds: i64 = sqlx::query("SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?
        .try_get("n")?;
    for sql in [
        "DELETE FROM totp_secrets WHERE user_id = $1",
        "DELETE FROM recovery_codes WHERE user_id = $1",
        "DELETE FROM webauthn_credentials WHERE user_id = $1",
        "DELETE FROM webauthn_challenges WHERE user_id = $1",
    ] {
        sqlx::query(sql).bind(user_id).execute(&mut *tx).await?;
    }
    sqlx::query("DELETE FROM secret_storage WHERE user_id = $1 AND method LIKE 'passkey:%'")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL")
        .bind(&ts)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(creds)
}

// ---------------------------------------------------------------- WebAuthn challenges

pub async fn insert_challenge(
    db: &Pool,
    user_id: Option<&str>,
    kind: &str,
    state: &str,
    ttl_secs: i64,
) -> Result<String, ApiError> {
    let id = ulid();
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < $1").bind(now()).execute(db).await?;
    sqlx::query("INSERT INTO webauthn_challenges (id, user_id, kind, state, expires_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(user_id)
        .bind(kind)
        .bind(state)
        .bind(in_seconds(ttl_secs))
        .execute(db)
        .await?;
    Ok(id)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChallengeRow {
    pub user_id: Option<String>,
    pub kind: String,
    pub state: String,
    pub expires_at: String,
}

/// Takes a challenge out of the store (single use): only the request that deletes it gets it.
pub async fn take_challenge(db: &Pool, id: &str) -> Result<Option<ChallengeRow>, ApiError> {
    let row: Option<ChallengeRow> =
        sqlx::query_as("SELECT user_id, kind, state, expires_at FROM webauthn_challenges WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await?;
    let Some(row) = row else { return Ok(None) };
    let r = sqlx::query("DELETE FROM webauthn_challenges WHERE id = $1").bind(id).execute(db).await?;
    if r.rows_affected() != 1 || row.expires_at <= now() {
        return Ok(None);
    }
    Ok(Some(row))
}

// ---------------------------------------------------------------- Pre-auth tokens

pub async fn preauth_used(db: &Pool, jti: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("SELECT 1 AS x FROM preauth_used WHERE jti = $1").bind(jti).fetch_optional(db).await?.is_some())
}

/// Marks a pre-auth token spent; `false` if it already was (parallel completion).
pub async fn spend_preauth(db: &Pool, jti: &str, expires_at: &str) -> Result<bool, ApiError> {
    sqlx::query("DELETE FROM preauth_used WHERE expires_at < $1").bind(now()).execute(db).await?;
    let r = sqlx::query("INSERT INTO preauth_used (jti, expires_at) VALUES ($1, $2)")
        .bind(jti)
        .bind(expires_at)
        .execute(db)
        .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

// ---------------------------------------------------------------- Secret storage

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecretStorageRow {
    pub method: String,
    pub wrapped: Vec<u8>,
    pub params: String,
    pub updated_at: String,
}

pub async fn secret_storage(db: &Pool, user_id: &str) -> Result<Vec<SecretStorageRow>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT method, wrapped, params, updated_at FROM secret_storage WHERE user_id = $1 ORDER BY method",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?)
}

/// Stores or replaces an entry. With `credential`, the entry is only stored while that credential
/// of the user exists (checked under the user lock, so it cannot race with the credential's
/// removal), and the credential is marked PRF-capable in the same transaction; `false` otherwise.
pub async fn put_secret_storage(
    db: &Pool,
    user_id: &str,
    method: &str,
    wrapped: &[u8],
    params: &str,
    credential: Option<&str>,
) -> Result<bool, ApiError> {
    let mut tx = db.begin().await?;
    lock_user(&mut tx, user_id).await?;
    if let Some(id) = credential {
        let marked = sqlx::query("UPDATE webauthn_credentials SET prf_supported = 1 WHERE credential_id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if marked == 0 {
            return Ok(false);
        }
    }
    sqlx::query("DELETE FROM secret_storage WHERE user_id = $1 AND method = $2")
        .bind(user_id)
        .bind(method)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO secret_storage (user_id, method, wrapped, params, updated_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(method)
    .bind(wrapped.to_vec())
    .bind(params)
    .bind(now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn delete_secret_storage(db: &Pool, user_id: &str, method: &str) -> Result<bool, ApiError> {
    let r = sqlx::query("DELETE FROM secret_storage WHERE user_id = $1 AND method = $2")
        .bind(user_id)
        .bind(method)
        .execute(db)
        .await?;
    Ok(r.rows_affected() > 0)
}
