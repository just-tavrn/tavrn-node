// SPDX-License-Identifier: AGPL-3.0-only
//! Routes of the legal module (protocol/LEGAL.md): legal pages and terms, takedown notices,
//! data export and account deletion. Node admin routes refuse admin API tokens (fail closed, `admin_tokens.rs`).

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::{
    app::AppState,
    auth::{AuthUser, ClientIp, NodeAdmin},
    error::{ApiError, ApiJson, ProblemDetails},
    legal::{
        self, LegalContact, LegalInfo,
        account::{self, AccountDeletion, DeleteAccountRequest, DeletionStarted},
        documents::{self, LegalDocument, TermsStatus},
        export::{self, DataApplication, DataCategory, DataSummary},
        notices::{
            self, ContentPreview, CounterDecision, CounterNotice, CounterNoticeRequest, Notice, NoticeAction,
            NoticeActionResult, NoticeCreated, NoticeDetail, NoticeEvent, NoticeFilter, NoticeLocation,
            NoticeLocationInput, NoticeRequest, NoticeStatus, UploaderNotice,
        },
    },
    validate::{self, bad},
};

pub fn routes() -> Router<AppState> {
    let small = || axum::extract::DefaultBodyLimit::max(16 * 1024);
    Router::new()
        .route("/legal/pages", get(pages))
        .route("/legal/pages/{kind}", get(page))
        .route(
            "/legal/notices",
            post(submit_notice).layer(axum::extract::DefaultBodyLimit::max(notices::MAX_BODY_BYTES)),
        )
        .route("/legal/notices/{case_id}", get(notice_status))
        .route("/account-deletions/{deletion_id}", get(deletion_status))
        .route("/users/me/terms", get(terms_status))
        .route("/users/me/terms/accept", post(accept_terms).layer(small()))
        .route("/users/me/legal-notices", get(my_notices))
        .route("/users/me/legal-notices/{case_id}/counter-notice", post(counter_notice).layer(small()))
        .route("/users/me/data", get(data_summary))
        .route("/users/me/export", get(export_me))
        .route("/admin/legal/notices", get(admin_notices))
        .route("/admin/legal/notices/export", get(admin_export_notices))
        .route("/admin/legal/notices/{case_id}", get(admin_notice))
        .route("/admin/legal/notices/{case_id}/actions", post(admin_act).layer(small()))
        .route("/admin/legal/notices/{case_id}/counter-notice/decision", post(admin_counter_decision).layer(small()))
        .route("/admin/legal/documents", get(admin_documents))
        .route(
            "/admin/legal/documents/{kind}",
            put(admin_publish)
                .delete(admin_unpublish)
                .layer(axum::extract::DefaultBodyLimit::max(legal::markdown::MAX_MARKDOWN_BYTES + 4096)),
        )
        .route("/admin/legal/templates/{kind}", get(admin_template))
        .route("/admin/legal/contact", get(admin_contact).put(admin_set_contact).layer(small()))
        .route("/admin/account-deletions", get(admin_deletions))
        .route("/admin/users/{user_id}/export", get(admin_export_user))
        .route("/admin/users/{user_id}/delete", post(admin_delete_user).layer(small()))
        .route("/admin/users/{user_id}/undelete", post(admin_undelete_user))
}

/// The standalone HTML pages `/legal/{imprint|privacy|terms|cookies}` (outside `/api/v1`, no JavaScript).
pub fn page_routes() -> Router<AppState> {
    Router::new().route("/legal/{kind}", get(page_html))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        pages,
        page,
        submit_notice,
        notice_status,
        deletion_status,
        terms_status,
        accept_terms,
        my_notices,
        counter_notice,
        data_summary,
        export_me,
        delete_me,
        admin_notices,
        admin_export_notices,
        admin_notice,
        admin_act,
        admin_counter_decision,
        admin_documents,
        admin_publish,
        admin_unpublish,
        admin_template,
        admin_contact,
        admin_set_contact,
        admin_deletions,
        admin_export_user,
        admin_delete_user,
        admin_undelete_user
    ),
    components(schemas(
        LegalInfo,
        legal::NoticesInfo,
        legal::PagesInfo,
        legal::PageInfo,
        LegalContact,
        LegalDocument,
        TermsStatus,
        AcceptTermsRequest,
        NoticeRequest,
        NoticeLocationInput,
        NoticeLocation,
        NoticeCreated,
        NoticeStatus,
        Notice,
        NoticeDetail,
        NoticeEvent,
        CounterNotice,
        ContentPreview,
        NoticeAction,
        NoticeActionResult,
        CounterNoticeRequest,
        CounterDecision,
        UploaderNotice,
        DataSummary,
        DataCategory,
        DataApplication,
        AccountDeletion,
        DeletionStarted,
        DeleteAccountRequest,
        PublishRequest,
        LegalTemplate,
        NoticeExport
    ))
)]
pub struct LegalApi;

fn kind_of(kind: &str) -> Result<&str, ApiError> {
    if documents::valid_kind(kind) {
        Ok(kind)
    } else {
        Err(ApiError::NotFound { code: "legal.page_not_found", what: "Page".into() })
    }
}

// ---------------------------------------------------------------- pages and terms

/// The published legal documents (public).
#[utoipa::path(get, path = "/api/v1/legal/pages", responses((status = 200, body = Vec<LegalDocument>)))]
pub async fn pages(State(state): State<AppState>) -> Result<Json<Vec<LegalDocument>>, ApiError> {
    Ok(Json(documents::all(&state.db).await?.iter().map(|d| d.to_api()).collect()))
}

/// One published document (public).
#[utoipa::path(get, path = "/api/v1/legal/pages/{kind}", params(("kind" = String, Path, description = "imprint | privacy | terms | cookies")),
    responses((status = 200, body = LegalDocument), (status = 404, body = ProblemDetails)))]
pub async fn page(State(state): State<AppState>, Path(kind): Path<String>) -> Result<Json<LegalDocument>, ApiError> {
    let kind = kind_of(&kind)?;
    documents::get(&state.db, kind)
        .await?
        .map(|d| Json(d.to_api()))
        .ok_or_else(|| ApiError::NotFound { code: "legal.page_not_found", what: "Page".into() })
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Page CSP: no scripts, no external resources.
const PAGE_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn title_of(kind: &str) -> &'static str {
    match kind {
        "imprint" => "Imprint",
        "privacy" => "Privacy policy",
        "terms" => "Terms of service",
        _ => "Cookies and notices",
    }
}

/// `/legal/{kind}`: the document as a standalone HTML page in the app's dark style (crawlers, other clients, links
/// in mails). Other paths below `/legal/` (the notice form) belong to the web client.
pub async fn page_html(State(state): State<AppState>, Path(kind): Path<String>, uri: axum::http::Uri) -> Response {
    if !documents::valid_kind(&kind) {
        return crate::webapp::handler(State(state), uri).await;
    }
    let doc = documents::get(&state.db, &kind).await.ok().flatten();
    let others: String = documents::all(&state.db)
        .await
        .unwrap_or_default()
        .iter()
        .map(|d| format!("<a href=\"/legal/{0}\">{1}</a>", d.kind, title_of(&d.kind)))
        .collect::<Vec<_>>()
        .join(" · ");
    let (status, lang, body, meta) = match &doc {
        Some(d) => (
            StatusCode::OK,
            if d.lang.is_empty() { "en".to_string() } else { d.lang.clone() },
            d.html.clone(),
            format!("Version {} · {}", d.version, escape(&d.published_at)),
        ),
        None => {
            (StatusCode::NOT_FOUND, "en".into(), "<p>This document has not been published.</p>".into(), String::new())
        }
    };
    let html = format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<meta name=\"color-scheme\" content=\"dark\"><title>{title} · {node}</title><style>\
body{{margin:0;background:#1d2129;color:#f3f4f6;font:16px/1.6 Inter,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}}\
main{{max-width:46rem;margin:0 auto;padding:2rem 1rem 4rem}}a{{color:#33aea6}}a:hover{{color:#40b9b1}}\
h1,h2,h3{{line-height:1.3}}code{{background:#0f1115;padding:0 .25rem;border-radius:.25rem}}\
table{{border-collapse:collapse}}td,th{{border:1px solid #2f3542;padding:.25rem .5rem}}blockquote{{border-left:3px solid #2f3542;margin:0;padding-left:1rem;color:#b4bac6}}\
nav,footer{{font-size:.875rem;color:#7c8494}}.brand{{height:2px;background:linear-gradient(90deg,#80ffef,#04cfc7 45%,#00427b);opacity:.7}}\
</style></head><body><div class=\"brand\"></div><main><nav><a href=\"/\">{node}</a> · {others}</nav><article>{body}</article>\
<footer>{meta}</footer></main></body></html>",
        title = title_of(&kind),
        node = escape(&state.config.domain),
    );
    let mut resp = (status, html).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PAGE_CSP));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

/// The signed-in user's terms state.
#[utoipa::path(get, path = "/api/v1/users/me/terms", security(("bearer" = [])), responses((status = 200, body = TermsStatus)))]
pub async fn terms_status(State(state): State<AppState>, auth: AuthUser) -> Result<Json<TermsStatus>, ApiError> {
    Ok(Json(documents::status(&state, &auth.user.id).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptTermsRequest {
    /// The version shown to the user (must be the current one).
    pub version: i64,
}

/// Accept the current terms (registration records it with the account; this is the dialog after a new version and
/// the first SSO login).
#[utoipa::path(post, path = "/api/v1/users/me/terms/accept", security(("bearer" = [])), request_body = AcceptTermsRequest,
    responses((status = 200, body = TermsStatus), (status = 409, body = ProblemDetails)))]
pub async fn accept_terms(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<AcceptTermsRequest>,
) -> Result<Json<TermsStatus>, ApiError> {
    let current = documents::terms_version(&state.db).await?;
    if current != Some(req.version) {
        return Err(ApiError::Conflict {
            code: "legal.terms_version_mismatch",
            detail: "The terms changed meanwhile: show the current version".into(),
            meta: serde_json::json!({ "version": current }),
        });
    }
    documents::accept(&state.db, &auth.user.id, req.version).await?;
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.terms_accept",
        &auth.user.address(),
        "",
        serde_json::json!({ "version": req.version }),
    )
    .await?;
    Ok(Json(documents::status(&state, &auth.user.id).await?))
}

// ---------------------------------------------------------------- notices (public)

/// Submit a takedown notice (no account needed; captcha when the node has one; 5 per hour and address).
#[utoipa::path(post, path = "/api/v1/legal/notices", request_body = NoticeRequest,
    responses((status = 201, body = NoticeCreated), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn submit_notice(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<NoticeRequest>,
) -> Result<(StatusCode, Json<NoticeCreated>), ApiError> {
    if !state.config.legal_notices.on() {
        return Err(ApiError::NotFound { code: "legal.notices_disabled", what: "Notice form".into() });
    }
    state.legal_notice_limiter.check_all(&[format!("notice-ip:{ip}")]).await?;
    let captcha = state.config.captcha_provider != crate::config::CaptchaProvider::None;
    state.captcha.check(captcha, req.captcha_token.as_deref(), &ip).await?;
    let valid = notices::validate(&req)?;
    // Reporters have no account: their browser's language picks the mails' language.
    let locale =
        crate::mail_templates::from_accept_language(headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()));
    let (row, mailed) = notices::create(&state, &valid, None, locale.as_deref()).await?;
    Ok((StatusCode::CREATED, Json(NoticeCreated { case_id: row.id, state: row.state, mailed })))
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct TokenQuery {
    /// The token of the confirmation mail.
    #[serde(default)]
    pub token: String,
}

/// The reporter's status page of a case (needs the token of the confirmation mail; unknown cases and wrong tokens
/// answer alike).
#[utoipa::path(get, path = "/api/v1/legal/notices/{case_id}", params(("case_id" = String, Path), TokenQuery),
    responses((status = 200, body = NoticeStatus), (status = 404, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn notice_status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(case_id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<NoticeStatus>, ApiError> {
    state.legal_lookup_limiter.check_all(&[format!("lookup-ip:{ip}")]).await?;
    Ok(Json(notices::status_for_reporter(&state, &case_id, &q.token).await?))
}

/// Progress of an account deletion (the token comes with the deletion's answer).
#[utoipa::path(get, path = "/api/v1/account-deletions/{deletion_id}", params(("deletion_id" = String, Path), TokenQuery),
    responses((status = 200, body = AccountDeletion), (status = 404, body = ProblemDetails)))]
pub async fn deletion_status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> Result<Json<AccountDeletion>, ApiError> {
    state.legal_lookup_limiter.check_all(&[format!("lookup-ip:{ip}")]).await?;
    Ok(Json(account::status_for_owner(&state.db, &id, &q.token).await?))
}

// ---------------------------------------------------------------- uploader

/// Cases about the signed-in user's content: statements of reasons and counter-notices.
#[utoipa::path(get, path = "/api/v1/users/me/legal-notices", security(("bearer" = [])), responses((status = 200, body = Vec<UploaderNotice>)))]
pub async fn my_notices(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<UploaderNotice>>, ApiError> {
    Ok(Json(notices::of_uploader(&state, &auth.user.id).await?))
}

/// Answer an actioned case with a counter-notice (within `TAVRN_LEGAL_COUNTER_NOTICE_DAYS`).
#[utoipa::path(post, path = "/api/v1/users/me/legal-notices/{case_id}/counter-notice", security(("bearer" = [])), params(("case_id" = String, Path)),
    request_body = CounterNoticeRequest,
    responses((status = 200, body = UploaderNotice), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn counter_notice(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(case_id): Path<String>,
    ApiJson(req): ApiJson<CounterNoticeRequest>,
) -> Result<Json<UploaderNotice>, ApiError> {
    Ok(Json(notices::submit_counter(&state, &auth.user, &case_id, req).await?))
}

// ---------------------------------------------------------------- data rights

/// What the node holds about the account, as a summary ("My data").
#[utoipa::path(get, path = "/api/v1/users/me/data", security(("bearer" = [])), responses((status = 200, body = DataSummary)))]
pub async fn data_summary(State(state): State<AppState>, auth: AuthUser) -> Result<Json<DataSummary>, ApiError> {
    Ok(Json(export::summary(&state, &auth.user).await?))
}

fn export_response(body: axum::body::Body, username: &str) -> Response {
    let date = crate::util::now().chars().take(10).collect::<String>();
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"tavrn-export-{username}-{date}.json\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// Download everything the node holds about the account (JSON, streamed). Needs a reauth token.
#[utoipa::path(get, path = "/api/v1/users/me/export", security(("bearer" = [])),
    responses((status = 200, description = "JSON archive (format tavrn.export.v1)", content_type = "application/json"), (status = 403, body = ProblemDetails)))]
pub async fn export_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    crate::reauth::require(&state, &auth, &headers).await?;
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&auth.user.id),
        "user.export",
        &auth.user.address(),
        "",
        serde_json::json!({}),
    )
    .await?;
    let username = auth.user.username.clone();
    Ok(export_response(export::stream(state, auth.user).await?, &username))
}

fn confirm(user: &crate::models::UserRow, phrase: &str) -> Result<(), ApiError> {
    if phrase.trim().to_lowercase() != user.username {
        return Err(bad("account.confirm_mismatch", "Type the account's username to confirm"));
    }
    Ok(())
}

/// Delete the own account (needs a reauth token and the username as confirmation). Answers with the deletion and
/// the token of its status link.
#[utoipa::path(delete, path = "/api/v1/users/me", security(("bearer" = [])), request_body = DeleteAccountRequest,
    responses((status = 202, body = DeletionStarted), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn delete_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthUser,
    ApiJson(req): ApiJson<DeleteAccountRequest>,
) -> Result<(StatusCode, Json<DeletionStarted>), ApiError> {
    if auth.is_remote() || auth.app.is_some() {
        return Err(crate::federation::guard::local_only());
    }
    crate::reauth::require(&state, &auth, &headers).await?;
    confirm(&auth.user, &req.confirm)?;
    let started = account::delete_local(&state, &auth.user, None, req.delete_messages).await?;
    Ok((StatusCode::ACCEPTED, Json(started)))
}

// ---------------------------------------------------------------- admin: notices

/// Cases, newest first, with filters.
#[utoipa::path(get, path = "/api/v1/admin/legal/notices", security(("bearer" = [])), params(NoticeFilter),
    responses((status = 200, body = Vec<Notice>), (status = 403, body = ProblemDetails)))]
pub async fn admin_notices(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Query(f): Query<NoticeFilter>,
) -> Result<Json<Vec<Notice>>, ApiError> {
    Ok(Json(notices::list(&state.db, &f).await?.iter().map(|r| r.to_api()).collect()))
}

/// One exported case.
#[derive(Serialize, ToSchema)]
pub struct NoticeExport {
    #[serde(flatten)]
    pub notice: Notice,
    pub events: Vec<NoticeEvent>,
    pub counter_notices: Vec<CounterNotice>,
}

/// Every kept case with its trail and counter-notices (JSON archive for the operator's records).
#[utoipa::path(get, path = "/api/v1/admin/legal/notices/export", security(("bearer" = [])),
    responses((status = 200, body = Vec<NoticeExport>), (status = 403, body = ProblemDetails)))]
pub async fn admin_export_notices(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
) -> Result<Response, ApiError> {
    let mut out = Vec::new();
    let mut before: Option<String> = None;
    loop {
        let page =
            notices::list(&state.db, &NoticeFilter { limit: Some(200), before: before.clone(), ..Default::default() })
                .await?;
        if page.is_empty() {
            break;
        }
        for r in &page {
            out.push(NoticeExport {
                notice: r.to_api(),
                events: notices::events(&state.db, &r.id).await?,
                counter_notices: notices::counter_notices(&state.db, &r.id).await?,
            });
        }
        before = page.last().map(|r| r.id.clone());
    }
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "legal.export",
        "",
        "",
        serde_json::json!({ "cases": out.len() }),
    )
    .await?;
    let body = serde_json::to_vec(&out).map_err(|e| ApiError::Internal(e.into()))?;
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"tavrn-legal-notices.json\""),
    );
    Ok(resp)
}

/// A case with its trail, counter-notices, the reported content (plaintext only) and the repeat counter.
#[utoipa::path(get, path = "/api/v1/admin/legal/notices/{case_id}", security(("bearer" = [])), params(("case_id" = String, Path)),
    responses((status = 200, body = NoticeDetail), (status = 404, body = ProblemDetails)))]
pub async fn admin_notice(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Path(case_id): Path<String>,
) -> Result<Json<NoticeDetail>, ApiError> {
    let row = notices::by_id(&state.db, &case_id)
        .await?
        .ok_or_else(|| ApiError::NotFound { code: "legal.notice_not_found", what: "Notice".into() })?;
    Ok(Json(notices::detail(&state, &row).await?))
}

/// Act on a case: remove content, disable the account, reject, forward to the content's node, or set the state.
#[utoipa::path(post, path = "/api/v1/admin/legal/notices/{case_id}/actions", security(("bearer" = [])), params(("case_id" = String, Path)),
    request_body = NoticeAction,
    responses((status = 200, body = NoticeActionResult), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn admin_act(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(case_id): Path<String>,
    ApiJson(a): ApiJson<NoticeAction>,
) -> Result<Json<NoticeActionResult>, ApiError> {
    Ok(Json(notices::act(&state, &admin.user, &case_id, a).await?))
}

/// Decide on the uploader's counter-notice.
#[utoipa::path(post, path = "/api/v1/admin/legal/notices/{case_id}/counter-notice/decision", security(("bearer" = [])), params(("case_id" = String, Path)),
    request_body = CounterDecision,
    responses((status = 200, body = Notice), (status = 400, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn admin_counter_decision(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(case_id): Path<String>,
    ApiJson(d): ApiJson<CounterDecision>,
) -> Result<Json<Notice>, ApiError> {
    Ok(Json(notices::decide_counter(&state, &admin.user, &case_id, d).await?))
}

// ---------------------------------------------------------------- admin: documents and contact

/// The published documents (with Markdown) for the editor.
#[utoipa::path(get, path = "/api/v1/admin/legal/documents", security(("bearer" = [])), responses((status = 200, body = Vec<LegalDocument>)))]
pub async fn admin_documents(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<LegalDocument>>, ApiError> {
    Ok(Json(documents::all(&state.db).await?.iter().map(|d| d.to_api()).collect()))
}

#[derive(Deserialize, ToSchema)]
pub struct PublishRequest {
    /// The document in Markdown (raw HTML is shown as text).
    pub markdown: String,
    /// Language of the text (BCP 47, e.g. `de`, `en`); empty = `en`.
    #[serde(default)]
    pub lang: String,
}

fn valid_lang(lang: &str) -> bool {
    lang.is_empty()
        || (lang.len() <= 35
            && lang.split('-').all(|p| !p.is_empty() && p.len() <= 8 && p.chars().all(|c| c.is_ascii_alphanumeric())))
}

/// Publish a new version of a document (every publish of the terms asks existing users again).
#[utoipa::path(put, path = "/api/v1/admin/legal/documents/{kind}", security(("bearer" = [])), params(("kind" = String, Path)),
    request_body = PublishRequest,
    responses((status = 200, body = LegalDocument), (status = 400, body = ProblemDetails), (status = 413, body = ProblemDetails)))]
pub async fn admin_publish(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(kind): Path<String>,
    ApiJson(req): ApiJson<PublishRequest>,
) -> Result<Json<LegalDocument>, ApiError> {
    let kind = kind_of(&kind)?;
    if req.markdown.len() > legal::markdown::MAX_MARKDOWN_BYTES {
        return Err(ApiError::PayloadTooLarge {
            code: "legal.document_too_large",
            detail: "The document is too large".into(),
            meta: serde_json::json!({ "max_bytes": legal::markdown::MAX_MARKDOWN_BYTES }),
        });
    }
    let markdown = validate::text("markdown", &req.markdown, 1, legal::markdown::MAX_MARKDOWN_BYTES)?;
    let lang = req.lang.trim().to_ascii_lowercase();
    if !valid_lang(&lang) {
        return Err(bad("legal.lang_invalid", "Language: a BCP 47 tag such as de or en-GB"));
    }
    let doc = documents::publish(&state.db, kind, &markdown, &lang, &admin.user.id).await?;
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "legal.document_publish",
        kind,
        "",
        serde_json::json!({ "version": doc.version }),
    )
    .await?;
    Ok(Json(doc.to_api()))
}

/// Unpublish a document (its versions stay in the history).
#[utoipa::path(delete, path = "/api/v1/admin/legal/documents/{kind}", security(("bearer" = [])), params(("kind" = String, Path)),
    responses((status = 204), (status = 404, body = ProblemDetails)))]
pub async fn admin_unpublish(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(kind): Path<String>,
) -> Result<StatusCode, ApiError> {
    let kind = kind_of(&kind)?;
    if !documents::unpublish(&state.db, kind).await? {
        return Err(ApiError::NotFound { code: "legal.page_not_found", what: "Page".into() });
    }
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "legal.document_unpublish",
        kind,
        "",
        serde_json::json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct TemplateQuery {
    /// `en` or `de` (privacy policy); the imprint template is German, the terms skeleton English.
    pub locale: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct LegalTemplate {
    pub kind: String,
    pub locale: String,
    /// The template with the placeholders the node knows filled in; `[[OPERATOR: …]]` notes remain.
    pub markdown: String,
}

/// A non-binding template for the editor ("Insert template"): not legal advice.
#[utoipa::path(get, path = "/api/v1/admin/legal/templates/{kind}", security(("bearer" = [])), params(("kind" = String, Path), TemplateQuery),
    responses((status = 200, body = LegalTemplate), (status = 404, body = ProblemDetails)))]
pub async fn admin_template(
    State(state): State<AppState>,
    _admin: NodeAdmin,
    Path(kind): Path<String>,
    Query(q): Query<TemplateQuery>,
) -> Result<Json<LegalTemplate>, ApiError> {
    let kind = kind_of(&kind)?;
    let locale = if q.locale.as_deref() == Some("de") { "de" } else { "en" };
    let text = documents::template(kind, locale)
        .ok_or_else(|| ApiError::NotFound { code: "legal.template_not_found", what: "Template".into() })?;
    let contact = legal::contact(&state).await?.unwrap_or_default();
    let domain = state.config.domain.clone();
    let date = crate::util::now().chars().take(10).collect::<String>();
    let minimum_age = state.config.minimum_age.to_string();
    let markdown = documents::fill_template(
        text,
        &[
            ("node_domain", &domain),
            ("node_name", &state.config.name),
            ("operator_name", &contact.name),
            ("operator_address", &contact.address),
            ("contact_email", &contact.email),
            ("effective_date", &date),
            ("minimum_age", &minimum_age),
        ],
    );
    Ok(Json(LegalTemplate { kind: kind.into(), locale: locale.into(), markdown }))
}

/// The designated contact for notices.
#[utoipa::path(get, path = "/api/v1/admin/legal/contact", security(("bearer" = [])), responses((status = 200, body = LegalContact)))]
pub async fn admin_contact(State(state): State<AppState>, _admin: NodeAdmin) -> Result<Json<LegalContact>, ApiError> {
    Ok(Json(legal::contact(&state).await?.unwrap_or_default()))
}

/// Set the designated contact (shown in `GET /node` and on the notice form).
#[utoipa::path(put, path = "/api/v1/admin/legal/contact", security(("bearer" = [])), request_body = LegalContact,
    responses((status = 200, body = LegalContact), (status = 400, body = ProblemDetails)))]
pub async fn admin_set_contact(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    ApiJson(c): ApiJson<LegalContact>,
) -> Result<Json<LegalContact>, ApiError> {
    let email = c.email.trim().to_lowercase();
    if !email.is_empty() && !notices::valid_email(&email) {
        return Err(bad("legal.email_invalid", "A valid e-mail address is required"));
    }
    let contact = LegalContact {
        name: validate::text("name", &c.name, 0, 200)?,
        address: validate::text("address", &c.address, 0, 500)?,
        email,
    };
    legal::set_contact(&state, &contact).await?;
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "legal.contact_update",
        "",
        "",
        serde_json::json!({}),
    )
    .await?;
    Ok(Json(contact))
}

// ---------------------------------------------------------------- admin: accounts

/// Account deletions (the undo is possible while `state` is processing or done and `purge_after` lies ahead).
#[utoipa::path(get, path = "/api/v1/admin/account-deletions", security(("bearer" = [])), responses((status = 200, body = Vec<AccountDeletion>)))]
pub async fn admin_deletions(
    State(state): State<AppState>,
    _admin: NodeAdmin,
) -> Result<Json<Vec<AccountDeletion>>, ApiError> {
    Ok(Json(account::list(&state.db, 200).await?.iter().map(|d| d.to_api(true)).collect()))
}

/// Export a user's data on the user's request (needs the admin's reauth token; audited).
#[utoipa::path(get, path = "/api/v1/admin/users/{user_id}/export", security(("bearer" = [])), params(("user_id" = String, Path)),
    responses((status = 200, description = "JSON archive", content_type = "application/json"), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn admin_export_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    crate::reauth::require(&state, &admin, &headers).await?;
    let user = legal::local_person(&state, &user_id).await?;
    crate::store::rooms::audit(
        &state.db,
        None,
        Some(&admin.user.id),
        "admin.user_export",
        &user.address(),
        "",
        serde_json::json!({ "user_id": user.id }),
    )
    .await?;
    let username = user.username.clone();
    Ok(export_response(export::stream(state, user).await?, &username))
}

/// Delete a user's account on the user's request (reauth token, the username as confirmation; audited).
#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/delete", security(("bearer" = [])), params(("user_id" = String, Path)),
    request_body = DeleteAccountRequest,
    responses((status = 202, body = DeletionStarted), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn admin_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
    ApiJson(req): ApiJson<DeleteAccountRequest>,
) -> Result<(StatusCode, Json<DeletionStarted>), ApiError> {
    crate::reauth::require(&state, &admin, &headers).await?;
    let user = legal::local_person(&state, &user_id).await?;
    if user.id == admin.user.id {
        return Err(bad("admin.self", "Delete your own account in your settings"));
    }
    confirm(&user, &req.confirm)?;
    let started = account::delete_local(&state, &user, Some(&admin.user), req.delete_messages).await?;
    Ok((StatusCode::ACCEPTED, Json(started)))
}

/// Undo a deletion within the grace period.
#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/undelete", security(("bearer" = [])), params(("user_id" = String, Path)),
    responses((status = 200, body = AccountDeletion), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails)))]
pub async fn admin_undelete_user(
    State(state): State<AppState>,
    NodeAdmin(admin): NodeAdmin,
    Path(user_id): Path<String>,
) -> Result<Json<AccountDeletion>, ApiError> {
    Ok(Json(account::undelete(&state, &admin.user, &user_id).await?))
}

#[cfg(test)]
mod tests {
    #[test]
    fn languages() {
        for ok in ["", "de", "en-gb", "zh-hant-tw"] {
            assert!(super::valid_lang(ok), "{ok}");
        }
        for bad in ["de_DE", "\"><script>", "x-", "a".repeat(40).as_str()] {
            assert!(!super::valid_lang(bad), "{bad}");
        }
    }
}
