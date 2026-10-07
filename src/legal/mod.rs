// SPDX-License-Identifier: AGPL-3.0-only
//! Legal compliance (protocol/LEGAL.md): takedown notices, the legal pages with terms
//! acceptance, and the GDPR data rights (export, account deletion). Everything here is optional for operators: a node
//! without notices, documents or deletions behaves as before.

pub mod account;
pub mod documents;
pub mod export;
pub mod markdown;
pub mod notices;

use serde::Serialize;
use utoipa::ToSchema;

use crate::{app::AppState, error::ApiError, store};

/// `node_settings` key of the designated contact for notices (name, address, e-mail; set in the admin "Legal" tab).
pub const CONTACT_KEY: &str = "legal.contact";

/// The designated contact (DMCA §512(c)(2) agent, DSA Art. 11/12 point of contact).
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize, ToSchema, PartialEq, Eq)]
pub struct LegalContact {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub email: String,
}

/// `legal.notices` of `GET /node`.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoticesInfo {
    /// The public notice form `/legal/notice` accepts notices (`TAVRN_LEGAL_NOTICES=on`).
    pub enabled: bool,
    /// The designated contact; null when the admin has not set one.
    pub contact: Option<LegalContact>,
}

/// One published document in `GET /node`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PageInfo {
    pub version: i64,
    pub published_at: String,
    /// Path of the standalone HTML page (`/legal/<kind>`).
    pub url: String,
}

/// `legal.pages` of `GET /node`: the published documents by kind.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct PagesInfo {
    pub imprint: Option<PageInfo>,
    pub privacy: Option<PageInfo>,
    pub terms: Option<PageInfo>,
    pub cookies: Option<PageInfo>,
}

/// `legal` of `GET /node`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LegalInfo {
    pub notices: NoticesInfo,
    pub pages: PagesInfo,
    /// `notice` or `require` (`TAVRN_LEGAL_TERMS_MODE`).
    pub terms_mode: String,
}

pub async fn contact(state: &AppState) -> Result<Option<LegalContact>, ApiError> {
    let raw: Option<String> = sqlx::query_scalar("SELECT value FROM node_settings WHERE key = $1")
        .bind(CONTACT_KEY)
        .fetch_optional(&state.db)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str::<LegalContact>(&r).ok()).filter(|c| *c != LegalContact::default()))
}

pub async fn set_contact(state: &AppState, c: &LegalContact) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM node_settings WHERE key = $1").bind(CONTACT_KEY).execute(&state.db).await?;
    sqlx::query("INSERT INTO node_settings (key, value, updated_at) VALUES ($1, $2, $3)")
        .bind(CONTACT_KEY)
        .bind(serde_json::to_string(c).map_err(|e| ApiError::Internal(e.into()))?)
        .bind(crate::util::now())
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn info(state: &AppState) -> Result<LegalInfo, ApiError> {
    let mut pages = PagesInfo::default();
    for d in documents::all(&state.db).await? {
        let info = Some(PageInfo {
            version: d.version,
            published_at: d.published_at.clone(),
            url: format!("/legal/{}", d.kind),
        });
        match d.kind.as_str() {
            "imprint" => pages.imprint = info,
            "privacy" => pages.privacy = info,
            "terms" => pages.terms = info,
            "cookies" => pages.cookies = info,
            _ => {}
        }
    }
    Ok(LegalInfo {
        notices: NoticesInfo { enabled: state.config.legal_notices.on(), contact: contact(state).await? },
        pages,
        terms_mode: match state.config.legal_terms_mode {
            crate::config::TermsMode::Notice => "notice".into(),
            crate::config::TermsMode::Require => "require".into(),
        },
    })
}

/// Housekeeping of the legal module: expired notices, interrupted content deletions, accounts past their grace
/// period. Returns (notices pruned, deletions resumed, accounts erased).
pub async fn housekeeping(
    state: &AppState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(u64, usize, usize), ApiError> {
    let pruned = notices::prune(&state.db, now).await?;
    let (resumed, purged) = account::housekeeping(state, now).await?;
    Ok((pruned, resumed, purged))
}

/// The user a status link or an admin route names, local and not a bot.
pub async fn local_person(state: &AppState, user_id: &str) -> Result<crate::models::UserRow, ApiError> {
    store::users::by_id(&state.db, user_id)
        .await?
        .filter(|u| u.domain == state.config.domain && !u.is_bot())
        .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })
}
