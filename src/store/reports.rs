// SPDX-License-Identifier: AGPL-3.0-only
//! Reports and automod inbox entries (protocol MODERATION.md §1, §2.4): table `reports` of migration 0270, with the
//! forwarding columns of migration 0380 (§1.6).

use sqlx::{FromRow, Row};

use crate::{db::Pool, error::ApiError};

const COLS: &str = "id, source, scope, kind, reporter_id, room_id, conversation_id, node, message_id, target_user_id, \
                    target_address, category, detail, snapshot, evidence, status, assignee_id, note, actions, \
                    created_at, updated_at, resolved_at, forwarded_to, forwarded_at, forwarded_by, origin, \
                    origin_report_id, origin_reporter, origin_reported_at";

#[derive(Debug, Clone, FromRow, PartialEq, Eq)]
pub struct ReportRow {
    pub id: String,
    /// `user` or `automod`.
    pub source: String,
    /// `room` or `node`.
    pub scope: String,
    /// `message`, `user` or `room`.
    pub kind: String,
    pub reporter_id: Option<String>,
    pub room_id: Option<String>,
    pub conversation_id: Option<String>,
    /// The node hosting the conversation when it is not this one.
    pub node: Option<String>,
    pub message_id: Option<String>,
    pub target_user_id: Option<String>,
    pub target_address: String,
    pub category: String,
    pub detail: String,
    /// JSON snapshot of a plaintext message.
    pub snapshot: Option<String>,
    /// JSON list of reporter-provided evidence entries.
    pub evidence: Option<String>,
    pub status: String,
    pub assignee_id: Option<String>,
    pub note: String,
    /// JSON list of the action shortcuts taken.
    pub actions: String,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    /// The home node this report was forwarded to (MODERATION.md §1.6), when and by whom (the admin's address).
    pub forwarded_to: Option<String>,
    pub forwarded_at: Option<String>,
    pub forwarded_by: Option<String>,
    /// `source = 'forward'`: the sending node, the report's id there, the reporter's pseudonym and the original time.
    pub origin: Option<String>,
    pub origin_report_id: Option<String>,
    pub origin_reporter: Option<String>,
    pub origin_reported_at: Option<String>,
}

/// Where a forwarded report comes from (MODERATION.md §1.6).
pub struct NewOrigin<'a> {
    pub node: &'a str,
    pub report_id: &'a str,
    pub reporter: &'a str,
    pub reported_at: &'a str,
}

/// A new report (or automod entry).
pub struct NewReport<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub scope: &'a str,
    pub kind: &'a str,
    pub reporter_id: Option<&'a str>,
    pub room_id: Option<&'a str>,
    pub conversation_id: Option<&'a str>,
    pub node: Option<&'a str>,
    pub message_id: Option<&'a str>,
    pub target_user_id: Option<&'a str>,
    pub target_address: &'a str,
    pub category: &'a str,
    pub detail: &'a str,
    pub snapshot: Option<&'a str>,
    pub evidence: Option<&'a str>,
    pub created_at: &'a str,
}

pub async fn insert(db: &Pool, r: &NewReport<'_>) -> Result<(), ApiError> {
    insert_with_origin(db, r, None).await
}

/// Inserts a report; `origin` for one another node forwarded (`source = 'forward'`). A second report of the same
/// origin and original id violates the unique index `reports_origin`: [`by_origin`] is checked first.
pub async fn insert_with_origin(db: &Pool, r: &NewReport<'_>, origin: Option<&NewOrigin<'_>>) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO reports (id, source, scope, kind, reporter_id, room_id, conversation_id, node, message_id,
             target_user_id, target_address, category, detail, snapshot, evidence, status, created_at, updated_at,
             origin, origin_report_id, origin_reporter, origin_reported_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'open', $16, $16, $17, $18, $19, $20)",
    )
    .bind(r.id)
    .bind(r.source)
    .bind(r.scope)
    .bind(r.kind)
    .bind(r.reporter_id)
    .bind(r.room_id)
    .bind(r.conversation_id)
    .bind(r.node)
    .bind(r.message_id)
    .bind(r.target_user_id)
    .bind(r.target_address)
    .bind(r.category)
    .bind(r.detail)
    .bind(r.snapshot)
    .bind(r.evidence)
    .bind(r.created_at)
    .bind(origin.map(|o| o.node))
    .bind(origin.map(|o| o.report_id))
    .bind(origin.map(|o| o.reporter))
    .bind(origin.map(|o| o.reported_at))
    .execute(db)
    .await?;
    Ok(())
}

/// The report `origin` forwarded with its id `report_id` there, if it arrived before.
pub async fn by_origin(db: &Pool, origin: &str, report_id: &str) -> Result<Option<ReportRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM reports WHERE origin = $1 AND origin_report_id = $2"))
        .bind(origin)
        .bind(report_id)
        .fetch_optional(db)
        .await?)
}

/// Records that report `id` was forwarded to `node`, unless it was forwarded before; `true` if this call recorded it
/// (exactly one of several concurrent forwards sends the message).
pub async fn mark_forwarded(db: &Pool, id: &str, node: &str, by: &str, at: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query(
        "UPDATE reports SET forwarded_to = $1, forwarded_by = $2, forwarded_at = $3, updated_at = $3
         WHERE id = $4 AND forwarded_to IS NULL",
    )
    .bind(node)
    .bind(by)
    .bind(at)
    .bind(id)
    .execute(db)
    .await?
    .rows_affected()
        > 0)
}

/// Takes back a forwarding mark whose message could not be queued.
pub async fn clear_forwarded(db: &Pool, id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE reports SET forwarded_to = NULL, forwarded_by = NULL, forwarded_at = NULL WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<ReportRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM reports WHERE id = $1")).bind(id).fetch_optional(db).await?)
}

/// The open report of the same reporter about the same target (MODERATION.md §1.3), if any.
pub async fn open_duplicate(db: &Pool, r: &NewReport<'_>) -> Result<Option<ReportRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM reports
         WHERE status = 'open' AND source = $1 AND reporter_id = $2 AND kind = $3
           AND COALESCE(room_id, '') = $4 AND COALESCE(conversation_id, '') = $5 AND COALESCE(node, '') = $6
           AND COALESCE(message_id, '') = $7 AND target_address = $8
         ORDER BY id LIMIT 1"
    ))
    .bind(r.source)
    .bind(r.reporter_id.unwrap_or_default())
    .bind(r.kind)
    .bind(r.room_id.unwrap_or_default())
    .bind(r.conversation_id.unwrap_or_default())
    .bind(r.node.unwrap_or_default())
    .bind(r.message_id.unwrap_or_default())
    .bind(r.target_address)
    .fetch_optional(db)
    .await?)
}

/// The open automod entry of `target_user_id` in a scope (room: `room_id`; node: `room_id` may be empty).
pub async fn open_automod(
    db: &Pool,
    scope: &str,
    room_id: Option<&str>,
    target_user_id: &str,
) -> Result<Option<ReportRow>, ApiError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLS} FROM reports
         WHERE status = 'open' AND source = 'automod' AND scope = $1 AND COALESCE(room_id, '') = $2
           AND target_user_id = $3
         ORDER BY id LIMIT 1"
    ))
    .bind(scope)
    .bind(room_id.unwrap_or_default())
    .bind(target_user_id)
    .fetch_optional(db)
    .await?)
}

/// Replaces category, detail and evidence of a merged report (MODERATION.md §1.3).
pub async fn merge(
    db: &Pool,
    id: &str,
    category: &str,
    detail: &str,
    evidence: Option<&str>,
    now: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE reports SET category = $1, detail = $2, evidence = $3, updated_at = $4 WHERE id = $5")
        .bind(category)
        .bind(detail)
        .bind(evidence)
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Reports `reporter_id` sent since `since` and the oldest of them (the per-user limit).
pub async fn sent_since(db: &Pool, reporter_id: &str, since: &str) -> Result<(i64, Option<String>), ApiError> {
    let row = sqlx::query(
        "SELECT CAST(COUNT(*) AS BIGINT) AS n, MIN(created_at) AS oldest FROM reports
         WHERE reporter_id = $1 AND source = 'user' AND created_at >= $2",
    )
    .bind(reporter_id)
    .bind(since)
    .fetch_one(db)
    .await?;
    Ok((row.try_get::<i64, _>("n")?, row.try_get::<Option<String>, _>("oldest")?))
}

/// Which reports a list shows.
#[derive(Debug, Default, Clone)]
pub struct ListFilter {
    pub room_id: Option<String>,
    pub scope: Option<String>,
    pub status: Option<String>,
    /// Leaves out reports about this user (moderators never see reports about themselves).
    pub exclude_target: Option<String>,
    /// Reports with a smaller id (paging).
    pub before: Option<String>,
}

fn list_where(f: &ListFilter, with_status: bool, with_before: bool) -> (String, Vec<String>) {
    let mut clauses = vec!["1 = 1".to_string()];
    let mut binds = Vec::new();
    let mut push = |clause: &str, value: &str, binds: &mut Vec<String>| {
        binds.push(value.to_string());
        clauses.push(clause.replace('?', &format!("${}", binds.len())));
    };
    if let Some(v) = &f.room_id {
        push("room_id = ?", v, &mut binds);
    }
    if let Some(v) = &f.scope {
        push("scope = ?", v, &mut binds);
    }
    if with_status && let Some(v) = &f.status {
        push("status = ?", v, &mut binds);
    }
    if let Some(v) = &f.exclude_target {
        push("COALESCE(target_user_id, '') <> ?", v, &mut binds);
    }
    if with_before && let Some(v) = &f.before {
        push("id < ?", v, &mut binds);
    }
    (clauses.join(" AND "), binds)
}

/// Reports matching `f`, newest first.
pub async fn list(db: &Pool, f: &ListFilter, limit: i64) -> Result<Vec<ReportRow>, ApiError> {
    let (where_sql, binds) = list_where(f, true, true);
    let sql = format!("SELECT {COLS} FROM reports WHERE {where_sql} ORDER BY id DESC LIMIT {}", limit.clamp(1, 100));
    let mut q = sqlx::query_as(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.fetch_all(db).await?)
}

/// Open reports matching `f` (whatever its status filter and cursor say).
pub async fn count_open(db: &Pool, f: &ListFilter) -> Result<i64, ApiError> {
    let (where_sql, binds) = list_where(f, false, false);
    let sql = format!("SELECT CAST(COUNT(*) AS BIGINT) AS n FROM reports WHERE {where_sql} AND status = 'open'");
    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.fetch_one(db).await?.try_get::<i64, _>("n")?)
}

/// The inbox fields a moderator changes (`PATCH /reports/{id}`).
pub async fn update_triage(
    db: &Pool,
    id: &str,
    status: &str,
    assignee_id: Option<&str>,
    note: &str,
    resolved_at: Option<&str>,
    now: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE reports SET status = $1, assignee_id = $2, note = $3, resolved_at = $4, updated_at = $5 WHERE id = $6",
    )
    .bind(status)
    .bind(assignee_id)
    .bind(note)
    .bind(resolved_at)
    .bind(now)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Stores the list of actions taken (JSON) and touches the report.
pub async fn set_actions(db: &Pool, id: &str, actions: &str, now: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE reports SET actions = $1, updated_at = $2 WHERE id = $3")
        .bind(actions)
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Replaces the detail of an automod entry and touches it.
pub async fn set_detail(db: &Pool, id: &str, detail: &str, now: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE reports SET detail = $1, updated_at = $2 WHERE id = $3")
        .bind(detail)
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &Pool, id: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM reports WHERE id = $1").bind(id).execute(db).await?.rows_affected() > 0)
}

/// Deletes resolved and dismissed reports closed before `cutoff` (retention, MODERATION.md §1.5).
pub async fn prune(db: &Pool, cutoff: &str) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        "DELETE FROM reports WHERE status IN ('resolved', 'dismissed') AND COALESCE(resolved_at, updated_at) < $1",
    )
    .bind(cutoff)
    .execute(db)
    .await?
    .rows_affected())
}

/// Ids of the node admins (people, never bots, not disabled or deleted).
pub async fn node_admin_ids(db: &Pool) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT id FROM users WHERE is_node_admin = 1 AND kind = 'user' AND disabled_at IS NULL AND deleted_at IS NULL",
    )
    .fetch_all(db)
    .await?;
    rows.iter().map(|r| r.try_get::<String, _>("id").map_err(Into::into)).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    async fn db() -> Pool {
        let pool = crate::db::connect("sqlite::memory:").await.unwrap();
        for (id, admin) in [("u1", 0), ("u2", 0), ("a1", 1)] {
            sqlx::query(
                "INSERT INTO users (id, username, domain, display_name, is_node_admin, created_at)
                 VALUES ($1, $1, 'd', $1, $2, '2026-01-01T00:00:00Z')",
            )
            .bind(id)
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        }
        pool
    }

    fn report<'a>(id: &'a str, at: &'a str) -> NewReport<'a> {
        NewReport {
            id,
            source: "user",
            scope: "node",
            kind: "user",
            reporter_id: Some("u1"),
            room_id: None,
            conversation_id: None,
            node: None,
            message_id: None,
            target_user_id: Some("u2"),
            target_address: "u2@d",
            category: "spam",
            detail: "first",
            snapshot: None,
            evidence: None,
            created_at: at,
        }
    }

    #[tokio::test]
    async fn insert_find_merge_and_delete() {
        let db = db().await;
        let r = report("01A", "2026-01-01T00:00:00Z");
        assert_eq!(open_duplicate(&db, &r).await.unwrap(), None);
        insert(&db, &r).await.unwrap();
        let found = open_duplicate(&db, &r).await.unwrap().unwrap();
        assert_eq!((found.id.as_str(), found.status.as_str(), found.actions.as_str()), ("01A", "open", "[]"));
        let other_target = NewReport { target_address: "x@d", ..report("01B", "2026-01-01T00:00:00Z") };
        assert_eq!(open_duplicate(&db, &other_target).await.unwrap(), None);
        merge(&db, "01A", "harassment", "second", Some("[]"), "2026-01-02T00:00:00Z").await.unwrap();
        let merged = by_id(&db, "01A").await.unwrap().unwrap();
        assert_eq!((merged.category.as_str(), merged.detail.as_str()), ("harassment", "second"));
        assert_eq!(merged.evidence.as_deref(), Some("[]"));
        assert_eq!(merged.updated_at, "2026-01-02T00:00:00Z");
        // Closed reports are no duplicates.
        update_triage(&db, "01A", "resolved", Some("a1"), "done", Some("2026-01-03T00:00:00Z"), "2026-01-03T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(open_duplicate(&db, &r).await.unwrap(), None);
        let row = by_id(&db, "01A").await.unwrap().unwrap();
        assert_eq!((row.assignee_id.as_deref(), row.note.as_str()), (Some("a1"), "done"));
        set_actions(&db, "01A", r#"[{"action":"ban"}]"#, "2026-01-04T00:00:00Z").await.unwrap();
        set_detail(&db, "01A", "new", "2026-01-04T00:00:00Z").await.unwrap();
        let row = by_id(&db, "01A").await.unwrap().unwrap();
        assert_eq!((row.actions.as_str(), row.detail.as_str()), (r#"[{"action":"ban"}]"#, "new"));
        assert!(delete(&db, "01A").await.unwrap());
        assert!(!delete(&db, "01A").await.unwrap());
    }

    #[tokio::test]
    async fn lists_filter_count_and_page() {
        let db = db().await;
        for (id, scope, room) in [("01A", "room", Some("r1")), ("01B", "node", None), ("01C", "room", Some("r1"))] {
            sqlx::query("INSERT INTO rooms (id, name, owner_id, created_at) VALUES ('r1', 'R', 'u1', 'x') ON CONFLICT DO NOTHING")
                .execute(&db)
                .await
                .unwrap();
            insert(&db, &NewReport { scope, room_id: room, ..report(id, "2026-01-01T00:00:00Z") }).await.unwrap();
        }
        let ids = |rows: Vec<ReportRow>| rows.into_iter().map(|r| r.id).collect::<Vec<_>>();
        let room = ListFilter { room_id: Some("r1".into()), scope: Some("room".into()), ..Default::default() };
        assert_eq!(ids(list(&db, &room, 50).await.unwrap()), vec!["01C", "01A"]);
        assert_eq!(
            ids(list(&db, &ListFilter { before: Some("01C".into()), ..room.clone() }, 50).await.unwrap()),
            vec!["01A"]
        );
        assert_eq!(ids(list(&db, &ListFilter::default(), 2).await.unwrap()), vec!["01C", "01B"]);
        assert_eq!(count_open(&db, &ListFilter::default()).await.unwrap(), 3);
        update_triage(&db, "01C", "dismissed", None, "", Some("2026-01-02T00:00:00Z"), "2026-01-02T00:00:00Z")
            .await
            .unwrap();
        let open = ListFilter { status: Some("open".into()), ..room.clone() };
        assert_eq!(ids(list(&db, &open, 50).await.unwrap()), vec!["01A"]);
        assert_eq!(count_open(&db, &room).await.unwrap(), 1);
        let not_about_u2 = ListFilter { exclude_target: Some("u2".into()), ..Default::default() };
        assert!(list(&db, &not_about_u2, 50).await.unwrap().is_empty());
        // Retention: only closed reports, by their closing time.
        assert_eq!(prune(&db, "2026-01-01T00:00:00Z").await.unwrap(), 0);
        assert_eq!(prune(&db, "2026-02-01T00:00:00Z").await.unwrap(), 1);
        assert_eq!(ids(list(&db, &ListFilter::default(), 50).await.unwrap()), vec!["01B", "01A"]);
    }

    #[tokio::test]
    async fn forwarding_marks_and_origins() {
        let db = db().await;
        insert(&db, &report("01A", "2026-01-01T00:00:00Z")).await.unwrap();
        assert!(mark_forwarded(&db, "01A", "b.example", "u1@d", "2026-01-02T00:00:00Z").await.unwrap());
        assert!(!mark_forwarded(&db, "01A", "c.example", "u1@d", "2026-01-03T00:00:00Z").await.unwrap(), "once only");
        let row = by_id(&db, "01A").await.unwrap().unwrap();
        assert_eq!(
            (row.forwarded_to.as_deref(), row.forwarded_by.as_deref(), row.forwarded_at.as_deref()),
            (Some("b.example"), Some("u1@d"), Some("2026-01-02T00:00:00Z"))
        );
        clear_forwarded(&db, "01A").await.unwrap();
        assert_eq!(by_id(&db, "01A").await.unwrap().unwrap().forwarded_to, None);

        let origin =
            NewOrigin { node: "a.example", report_id: "01X", reporter: "anon-1", reported_at: "2026-01-01T00:00:00Z" };
        let forwarded = NewReport { source: "forward", reporter_id: None, ..report("01B", "2026-01-02T00:00:00Z") };
        assert_eq!(by_origin(&db, "a.example", "01X").await.unwrap(), None);
        insert_with_origin(&db, &forwarded, Some(&origin)).await.unwrap();
        let row = by_origin(&db, "a.example", "01X").await.unwrap().unwrap();
        assert_eq!((row.id.as_str(), row.source.as_str()), ("01B", "forward"));
        assert_eq!(
            (row.origin_reporter.as_deref(), row.origin_reported_at.as_deref()),
            (Some("anon-1"), Some("2026-01-01T00:00:00Z"))
        );
        assert_eq!(by_origin(&db, "c.example", "01X").await.unwrap(), None, "per origin");
        let again = NewReport { id: "01C", ..forwarded };
        assert!(insert_with_origin(&db, &again, Some(&origin)).await.is_err(), "unique per origin and report id");
        assert_eq!(sent_since(&db, "u1", "2026-01-01T00:00:00Z").await.unwrap().0, 1, "forwarded reports do not count");
    }

    #[tokio::test]
    async fn limits_automod_entries_and_admins() {
        let db = db().await;
        insert(&db, &report("01A", "2026-01-01T10:00:00Z")).await.unwrap();
        insert(&db, &NewReport { target_address: "x@d", ..report("01B", "2026-01-01T11:00:00Z") }).await.unwrap();
        assert_eq!(
            sent_since(&db, "u1", "2026-01-01T10:30:00Z").await.unwrap(),
            (1, Some("2026-01-01T11:00:00Z".into()))
        );
        assert_eq!(sent_since(&db, "u2", "2026-01-01T00:00:00Z").await.unwrap(), (0, None));
        let auto = NewReport { source: "automod", reporter_id: None, ..report("01C", "2026-01-01T12:00:00Z") };
        insert(&db, &auto).await.unwrap();
        assert_eq!(open_automod(&db, "node", None, "u2").await.unwrap().map(|r| r.id), Some("01C".into()));
        assert_eq!(open_automod(&db, "room", None, "u2").await.unwrap(), None);
        assert_eq!(sent_since(&db, "u1", "2026-01-01T00:00:00Z").await.unwrap().0, 2, "automod entries do not count");
        assert_eq!(node_admin_ids(&db).await.unwrap(), vec!["a1".to_string()]);
    }
}
