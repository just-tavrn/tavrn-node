// SPDX-License-Identifier: AGPL-3.0-only
//! Entitlement plans and grants, admin API tokens and the room retention setting.

use sqlx::FromRow;

use crate::{
    db::Pool,
    entitlements::{self, ActiveGrant, Limits, SubjectKind},
    error::ApiError,
    util::{now, ulid},
};

// ---------------------------------------------------------------- Plans

#[derive(Debug, Clone, FromRow)]
pub struct PlanRow {
    pub id: String,
    pub name: String,
    pub limits: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

const PLAN_COLS: &str = "id, name, limits, created_by, created_at, updated_at";

/// Upper bound of plans per node (DoS guard; the admin UI lists them all).
pub const MAX_PLANS: i64 = 500;

pub async fn plans(db: &Pool) -> Result<Vec<PlanRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {PLAN_COLS} FROM entitlement_plans ORDER BY name LIMIT $1"))
        .bind(MAX_PLANS)
        .fetch_all(db)
        .await?)
}

pub async fn plan(db: &Pool, id: &str) -> Result<Option<PlanRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {PLAN_COLS} FROM entitlement_plans WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn plan_count(db: &Pool) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM entitlement_plans").fetch_one(db).await?)
}

/// `Ok(None)` when the name is taken.
pub async fn create_plan(db: &Pool, name: &str, limits: &Limits, by: &str) -> Result<Option<PlanRow>, ApiError> {
    let id = ulid();
    let ts = now();
    let r = sqlx::query(
        "INSERT INTO entitlement_plans (id, name, limits, created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(&id)
    .bind(name)
    .bind(serde_json::to_string(limits).unwrap_or_else(|_| "{}".into()))
    .bind(by)
    .bind(&ts)
    .execute(db)
    .await;
    match r {
        Ok(_) => plan(db, &id).await,
        Err(e) if super::is_unique_violation(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `Ok(false)` when the new name is taken.
pub async fn update_plan(db: &Pool, id: &str, name: Option<&str>, limits: Option<&Limits>) -> Result<bool, ApiError> {
    let limits = limits.map(|l| serde_json::to_string(l).unwrap_or_else(|_| "{}".into()));
    let r = sqlx::query(
        "UPDATE entitlement_plans SET name = COALESCE($1, name), limits = COALESCE($2, limits), updated_at = $3 WHERE id = $4",
    )
    .bind(name)
    .bind(limits)
    .bind(now())
    .bind(id)
    .execute(db)
    .await;
    match r {
        Ok(_) => Ok(true),
        Err(e) if super::is_unique_violation(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub async fn plan_in_use(db: &Pool, id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM entitlement_grants WHERE plan_id = $1").bind(id).fetch_one(db).await?)
}

pub async fn delete_plan(db: &Pool, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM entitlement_plans WHERE id = $1").bind(id).execute(db).await?.rows_affected() > 0)
}

// ---------------------------------------------------------------- Grants

#[derive(Debug, Clone, FromRow)]
pub struct GrantRow {
    pub id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub plan_id: Option<String>,
    pub plan_name: Option<String>,
    pub overrides: String,
    pub expires_at: Option<String>,
    pub note: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

const GRANT_COLS: &str = "g.id, g.subject_kind, g.subject_id, g.plan_id, p.name AS plan_name, g.overrides, g.expires_at, \
     g.note, g.created_by, g.created_at, g.updated_at";
const GRANT_FROM: &str = "entitlement_grants g LEFT JOIN entitlement_plans p ON p.id = g.plan_id";

/// Active grants per subject at most (DoS guard: every request of the subject evaluates them).
pub const MAX_ACTIVE_GRANTS_PER_SUBJECT: i64 = 50;

pub struct GrantFilter<'a> {
    pub subject: Option<(SubjectKind, &'a str)>,
    pub include_expired: bool,
    pub now: &'a str,
    pub after: Option<&'a str>,
    pub limit: i64,
}

/// Grants ordered by id (newest last), paged with `after`.
pub async fn grants(db: &Pool, f: &GrantFilter<'_>) -> Result<Vec<GrantRow>, ApiError> {
    let mut sql = format!("SELECT {GRANT_COLS} FROM {GRANT_FROM} WHERE g.id > $1");
    let mut n = 1;
    if f.subject.is_some() {
        sql.push_str(" AND g.subject_kind = $2 AND g.subject_id = $3");
        n = 3;
    }
    if !f.include_expired {
        n += 1;
        sql.push_str(&format!(" AND (g.expires_at IS NULL OR g.expires_at > ${n})"));
    }
    sql.push_str(&format!(" ORDER BY g.id LIMIT ${}", n + 1));
    let mut q = sqlx::query_as::<_, GrantRow>(&sql).bind(f.after.unwrap_or(""));
    if let Some((kind, id)) = f.subject {
        q = q.bind(kind.as_str()).bind(id);
    }
    if !f.include_expired {
        q = q.bind(f.now);
    }
    Ok(q.bind(f.limit).fetch_all(db).await?)
}

pub async fn grant(db: &Pool, id: &str) -> Result<Option<GrantRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {GRANT_COLS} FROM {GRANT_FROM} WHERE g.id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn active_grant_count(db: &Pool, kind: SubjectKind, subject_id: &str, now: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM entitlement_grants WHERE subject_kind = $1 AND subject_id = $2 AND (expires_at IS NULL OR expires_at > $3)",
    )
    .bind(kind.as_str())
    .bind(subject_id)
    .bind(now)
    .fetch_one(db)
    .await?)
}

pub struct NewGrant<'a> {
    pub kind: SubjectKind,
    pub subject_id: &'a str,
    pub plan_id: Option<&'a str>,
    pub overrides: &'a Limits,
    pub expires_at: Option<&'a str>,
    pub note: &'a str,
    pub created_by: &'a str,
}

pub async fn create_grant(db: &Pool, g: NewGrant<'_>) -> Result<GrantRow, ApiError> {
    let id = ulid();
    let ts = now();
    sqlx::query(
        "INSERT INTO entitlement_grants (id, subject_kind, subject_id, plan_id, overrides, expires_at, note, created_by, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)",
    )
    .bind(&id)
    .bind(g.kind.as_str())
    .bind(g.subject_id)
    .bind(g.plan_id)
    .bind(serde_json::to_string(g.overrides).unwrap_or_else(|_| "{}".into()))
    .bind(g.expires_at)
    .bind(g.note)
    .bind(g.created_by)
    .bind(&ts)
    .execute(db)
    .await?;
    grant(db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("grant missing after insert")))
}

/// Writes the full new state of a grant (the route merges the patch).
pub async fn update_grant(
    db: &Pool,
    id: &str,
    plan_id: Option<&str>,
    overrides: &Limits,
    expires_at: Option<&str>,
    note: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE entitlement_grants SET plan_id = $1, overrides = $2, expires_at = $3, note = $4, updated_at = $5 WHERE id = $6",
    )
    .bind(plan_id)
    .bind(serde_json::to_string(overrides).unwrap_or_else(|_| "{}".into()))
    .bind(expires_at)
    .bind(note)
    .bind(now())
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn delete_grant(db: &Pool, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM entitlement_grants WHERE id = $1").bind(id).execute(db).await?.rows_affected() > 0)
}

/// (subject kind, subject id, plan limits, overrides, expiry).
type GrantValuesRow = (String, String, Option<String>, String, Option<String>);

/// Active grants of the given users and room with their resolved values (plan limits + overrides).
pub async fn active_grants(
    db: &Pool,
    user_ids: &[&str],
    room_id: Option<&str>,
    now: &str,
) -> Result<Vec<ActiveGrant>, ApiError> {
    if user_ids.is_empty() && room_id.is_none() {
        return Ok(Vec::new());
    }
    // At most two users (actor and room owner) plus one room: a fixed shape with empty placeholders.
    let rows: Vec<GrantValuesRow> = sqlx::query_as(
        "SELECT g.subject_kind, g.subject_id, p.limits, g.overrides, g.expires_at
           FROM entitlement_grants g LEFT JOIN entitlement_plans p ON p.id = g.plan_id
          WHERE ((g.subject_kind = 'user' AND g.subject_id IN ($1, $2)) OR (g.subject_kind = 'room' AND g.subject_id = $3))
            AND (g.expires_at IS NULL OR g.expires_at > $4)
          ORDER BY g.id",
    )
    .bind(user_ids.first().copied().unwrap_or(""))
    .bind(user_ids.get(1).copied().unwrap_or(""))
    .bind(room_id.unwrap_or(""))
    .bind(now)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, subject_id, plan, overrides, expires_at)| {
            let kind = SubjectKind::parse(&kind)?;
            let plan = plan.as_deref().map(entitlements::limits_from_text).unwrap_or_default();
            let values = entitlements::merge(&plan, &entitlements::limits_from_text(&overrides));
            Some(ActiveGrant { kind, subject_id, values, expires_at })
        })
        .collect())
}

/// Deletes grants that expired before `cutoff` and grants whose subject no longer exists.
pub async fn prune_grants(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    let expired = sqlx::query("DELETE FROM entitlement_grants WHERE expires_at IS NOT NULL AND expires_at < $1")
        .bind(cutoff)
        .execute(db)
        .await?
        .rows_affected();
    let orphans = sqlx::query(
        "DELETE FROM entitlement_grants WHERE
           (subject_kind = 'user' AND subject_id NOT IN (SELECT id FROM users))
           OR (subject_kind = 'room' AND subject_id NOT IN (SELECT id FROM rooms))",
    )
    .execute(db)
    .await?
    .rows_affected();
    Ok(expired + orphans)
}

// ---------------------------------------------------------------- Rooms

/// Sets a room's attachment retention (`None` = the node's value).
pub async fn set_room_retention(db: &Pool, room_id: &str, days: Option<i64>) -> Result<(), ApiError> {
    sqlx::query("UPDATE rooms SET attachment_retention_days = $1 WHERE id = $2")
        .bind(days)
        .bind(room_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Rooms that may have a retention shorter than the node's: an own setting or an active room grant.
pub async fn retention_rooms(db: &Pool, now: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM rooms WHERE attachment_retention_days > 0
         UNION SELECT subject_id FROM entitlement_grants WHERE subject_kind = 'room' AND (expires_at IS NULL OR expires_at > $1)",
    )
    .bind(now)
    .fetch_all(db)
    .await?)
}

// ---------------------------------------------------------------- Admin API tokens

#[derive(Debug, Clone, FromRow)]
pub struct AdminTokenRow {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub scopes: String,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

const TOKEN_COLS: &str = "id, name, token_hash, scopes, created_by, expires_at, last_used_at, created_at";

/// Admin tokens per node at most.
pub const MAX_ADMIN_TOKENS: i64 = 100;

pub async fn admin_tokens(db: &Pool) -> Result<Vec<AdminTokenRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {TOKEN_COLS} FROM admin_tokens ORDER BY id LIMIT $1"))
        .bind(MAX_ADMIN_TOKENS)
        .fetch_all(db)
        .await?)
}

pub async fn admin_token(db: &Pool, id: &str) -> Result<Option<AdminTokenRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {TOKEN_COLS} FROM admin_tokens WHERE id = $1"))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn admin_token_count(db: &Pool) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM admin_tokens").fetch_one(db).await?)
}

pub async fn create_admin_token(
    db: &Pool,
    id: &str,
    name: &str,
    token_hash: &str,
    scopes: &[String],
    created_by: &str,
    expires_at: Option<&str>,
) -> Result<AdminTokenRow, ApiError> {
    sqlx::query(
        "INSERT INTO admin_tokens (id, name, token_hash, scopes, created_by, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(name)
    .bind(token_hash)
    .bind(serde_json::to_string(scopes).unwrap_or_else(|_| "[]".into()))
    .bind(created_by)
    .bind(expires_at)
    .bind(now())
    .execute(db)
    .await?;
    admin_token(db, id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("admin token missing after insert")))
}

pub async fn delete_admin_token(db: &Pool, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM admin_tokens WHERE id = $1").bind(id).execute(db).await?.rows_affected() > 0)
}

pub async fn touch_admin_token(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE admin_tokens SET last_used_at = $1 WHERE id = $2").bind(now()).bind(id).execute(db).await?;
    Ok(())
}
