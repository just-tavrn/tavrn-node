// SPDX-License-Identifier: AGPL-3.0-only
//! The node's legal documents (protocol/LEGAL.md §2): imprint, privacy policy, terms of service
//! and an optional cookie/notice text, written in Markdown by node admins, published with a version, served as
//! sanitized HTML. Also the terms acceptances (registration, the dialog after a new version, SSO first login) and the
//! `require` mode that refuses the API until the current terms are accepted.

use serde::Serialize;
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::{app::AppState, config::TermsMode, db::Pool, error::ApiError, util};

/// The document kinds, in the order the pages list them.
pub const KINDS: &[&str] = &["imprint", "privacy", "terms", "cookies"];

pub fn valid_kind(kind: &str) -> bool {
    KINDS.contains(&kind)
}

#[derive(Debug, Clone, FromRow)]
pub struct DocumentRow {
    pub kind: String,
    pub markdown: String,
    pub html: String,
    pub lang: String,
    pub version: i64,
    pub published_at: String,
    pub updated_by: Option<String>,
}

/// A published document.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LegalDocument {
    /// imprint | privacy | terms | cookies
    pub kind: String,
    pub version: i64,
    pub published_at: String,
    /// Language of the text (BCP 47, e.g. `de`); empty = the node's default.
    pub lang: String,
    /// Path of the standalone HTML page on this node (`/legal/<kind>`).
    pub url: String,
    pub markdown: String,
    /// Sanitized HTML rendering of `markdown`.
    pub html: String,
}

impl DocumentRow {
    pub fn to_api(&self) -> LegalDocument {
        LegalDocument {
            kind: self.kind.clone(),
            version: self.version,
            published_at: self.published_at.clone(),
            lang: self.lang.clone(),
            url: format!("/legal/{}", self.kind),
            markdown: self.markdown.clone(),
            html: self.html.clone(),
        }
    }
}

const COLS: &str = "kind, markdown, html, lang, version, published_at, updated_by";

pub async fn all(db: &Pool) -> Result<Vec<DocumentRow>, ApiError> {
    let mut rows: Vec<DocumentRow> =
        sqlx::query_as(&format!("SELECT {COLS} FROM legal_documents")).fetch_all(db).await?;
    rows.sort_by_key(|r| KINDS.iter().position(|k| *k == r.kind).unwrap_or(usize::MAX));
    Ok(rows)
}

pub async fn get(db: &Pool, kind: &str) -> Result<Option<DocumentRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM legal_documents WHERE kind = $1"))
        .bind(kind)
        .fetch_optional(db)
        .await?)
}

/// Publishes a new version of `kind` (the first one is version 1).
pub async fn publish(db: &Pool, kind: &str, markdown: &str, lang: &str, by: &str) -> Result<DocumentRow, ApiError> {
    let html = super::markdown::render(markdown);
    let now = util::now();
    let version = get(db, kind).await?.map_or(1, |d| d.version + 1);
    // Versions only ever grow, also after an unpublish (acceptances refer to them).
    let last: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM legal_document_versions WHERE kind = $1")
        .bind(kind)
        .fetch_one(db)
        .await?;
    let version = version.max(last.unwrap_or(0) + 1);
    sqlx::query(
        "INSERT INTO legal_document_versions (kind, version, markdown, lang, published_at, published_by)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(kind)
    .bind(version)
    .bind(markdown)
    .bind(lang)
    .bind(&now)
    .bind(by)
    .execute(db)
    .await?;
    sqlx::query("DELETE FROM legal_documents WHERE kind = $1").bind(kind).execute(db).await?;
    sqlx::query(
        "INSERT INTO legal_documents (kind, markdown, html, lang, version, published_at, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(kind)
    .bind(markdown)
    .bind(&html)
    .bind(lang)
    .bind(version)
    .bind(&now)
    .bind(by)
    .execute(db)
    .await?;
    get(db, kind).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("published document missing")))
}

/// Removes the published document (its history stays).
pub async fn unpublish(db: &Pool, kind: &str) -> Result<bool, ApiError> {
    Ok(sqlx::query("DELETE FROM legal_documents WHERE kind = $1").bind(kind).execute(db).await?.rows_affected() > 0)
}

// ---------------------------------------------------------------- terms

/// The version of the published terms (`None` without terms).
pub async fn terms_version(db: &Pool) -> Result<Option<i64>, ApiError> {
    Ok(sqlx::query_scalar("SELECT version FROM legal_documents WHERE kind = 'terms'").fetch_optional(db).await?)
}

/// The newest terms version `user_id` accepted, with the time.
pub async fn accepted(db: &Pool, user_id: &str) -> Result<Option<(i64, String)>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT version, accepted_at FROM terms_acceptances WHERE user_id = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?)
}

pub async fn accept(db: &Pool, user_id: &str, version: i64) -> Result<String, ApiError> {
    let now = util::now();
    sqlx::query("DELETE FROM terms_acceptances WHERE user_id = $1 AND version = $2")
        .bind(user_id)
        .bind(version)
        .execute(db)
        .await?;
    sqlx::query("INSERT INTO terms_acceptances (user_id, version, accepted_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(version)
        .bind(&now)
        .execute(db)
        .await?;
    Ok(now)
}

/// The terms acceptance state of a user.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TermsStatus {
    /// Version of the published terms; null when the node has none.
    pub current_version: Option<i64>,
    /// Newest version the user accepted (null: none).
    pub accepted_version: Option<i64>,
    pub accepted_at: Option<String>,
    /// The current version still needs the user's acceptance.
    pub pending: bool,
    /// `notice` (the client shows the dialog once) or `require` (the API refuses everything else until accepted).
    pub mode: String,
}

pub async fn status(state: &AppState, user_id: &str) -> Result<TermsStatus, ApiError> {
    let current = terms_version(&state.db).await?;
    let accepted = accepted(&state.db, user_id).await?;
    let pending = current.is_some_and(|c| accepted.as_ref().is_none_or(|(v, _)| *v < c));
    Ok(TermsStatus {
        current_version: current,
        accepted_version: accepted.as_ref().map(|a| a.0),
        accepted_at: accepted.map(|a| a.1),
        pending,
        mode: match state.config.legal_terms_mode {
            TermsMode::Notice => "notice".into(),
            TermsMode::Require => "require".into(),
        },
    })
}

/// Routes a user with unaccepted terms may still call in `require` mode: the legal pages and the acceptance (under
/// `/api/v1/legal/`), the terms status, logout and the own account basics the client needs to show the dialog.
pub fn exempt_route(path: &str) -> bool {
    path.starts_with("/api/v1/legal/")
        || matches!(
            path,
            "/api/v1/auth/logout"
                | "/api/v1/users/me/terms"
                | "/api/v1/users/me/terms/accept"
                // The date of birth dialog may come first (PROTOCOL.md §5e).
                | "/api/v1/users/me/date-of-birth"
        )
}

/// `403 legal.terms_required` for a local person whose acceptance of the current terms is missing, when the node
/// runs `TAVRN_LEGAL_TERMS_MODE=require`. Remote users accept their home node's terms; bots have none.
pub async fn check_required(
    state: &AppState,
    user: &crate::models::UserRow,
    path: Option<&str>,
) -> Result<(), ApiError> {
    if state.config.legal_terms_mode != TermsMode::Require
        || user.domain != state.config.domain
        || user.is_bot()
        || path.is_some_and(exempt_route)
    {
        return Ok(());
    }
    let missing: Option<i64> = sqlx::query_scalar(
        "SELECT d.version FROM legal_documents d WHERE d.kind = 'terms' AND NOT EXISTS
           (SELECT 1 FROM terms_acceptances a WHERE a.user_id = $1 AND a.version >= d.version)",
    )
    .bind(&user.id)
    .fetch_optional(&state.db)
    .await?;
    match missing {
        None => Ok(()),
        Some(version) => Err(terms_required(version)),
    }
}

pub fn terms_required(version: i64) -> ApiError {
    ApiError::ForbiddenMeta {
        code: "legal.terms_required",
        detail: "Accept the current terms of service first".into(),
        meta: serde_json::json!({ "version": version }),
    }
}

// ---------------------------------------------------------------- templates

/// Non-binding templates operators can load into the editor (server/templates/legal/*.md).
pub fn template(kind: &str, locale: &str) -> Option<&'static str> {
    Some(match (kind, locale) {
        ("privacy", "de") => include_str!("../../templates/legal/privacy-template.de.md"),
        ("privacy", _) => include_str!("../../templates/legal/privacy-template.en.md"),
        ("imprint", _) => include_str!("../../templates/legal/imprint-template.de.md"),
        ("terms", _) => include_str!("../../templates/legal/terms-template.en.md"),
        _ => return None,
    })
}

/// Fills the `{{…}}` placeholders the node knows; `[[OPERATOR: …]]` notes stay for the operator.
pub fn fill_template(text: &str, values: &[(&str, &str)]) -> String {
    let mut out = text.to_string();
    for (key, value) in values {
        if !value.is_empty() {
            out = out.replace(&format!("{{{{{key}}}}}"), value);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exempt_routes_cover_only_the_legal_flow() {
        for p in
            ["/api/v1/legal/pages", "/api/v1/auth/logout", "/api/v1/users/me/terms", "/api/v1/users/me/terms/accept"]
        {
            assert!(exempt_route(p), "{p}");
        }
        for p in ["/api/v1/users/me", "/api/v1/rooms", "/api/v1/admin/overview", "/api/v1/ws", "/api/v1/legalx"] {
            assert!(!exempt_route(p), "{p}");
        }
    }

    #[test]
    fn templates_carry_the_disclaimer_and_fill_known_placeholders() {
        for (kind, locale) in [("privacy", "en"), ("privacy", "de"), ("imprint", "de"), ("terms", "en")] {
            let t = template(kind, locale).unwrap_or_default();
            assert!(t.contains("template") || t.contains("Vorlage"), "{kind}/{locale}");
        }
        assert!(template("cookies", "en").is_none());
        let filled = fill_template(
            "{{node_domain}} {{contact_email}} {{unknown}}",
            &[("node_domain", "x.example"), ("contact_email", "")],
        );
        assert_eq!(filled, "x.example {{contact_email}} {{unknown}}");
    }
}
