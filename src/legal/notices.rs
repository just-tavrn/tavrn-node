// SPDX-License-Identifier: AGPL-3.0-only
//! Takedown notices (protocol/LEGAL.md §1): the public notice form (US DMCA §512(c)(3), EU DSA
//! Art. 16), the cases the node admin works on, the statement of reasons to the uploader (DSA Art. 17), the
//! counter-notice (DMCA §512(g), DSA Art. 20), forwarding to the content's home node (S2S `legal.notice`), retention
//! and the repeat-infringer counter.
//!
//! The node only ever sees what it holds in plaintext: encrypted messages and files are never decrypted for a case.
//! A notice can still name them (message id, attachment id) and the admin can remove them.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::{
    app::AppState,
    db::Pool,
    error::ApiError,
    models::UserRow,
    store, util,
    validate::{self, bad},
};

pub const STATES: &[&str] = &["received", "in_review", "actioned", "rejected", "counter_notice"];
pub const BASES: &[&str] = &["copyright", "illegal", "terms"];
pub const LOCATION_KINDS: &[&str] = &["message", "attachment", "room", "profile", "other"];
/// Largest notice body (the form and S2S payloads).
pub const MAX_BODY_BYTES: usize = 32 * 1024;
pub const MAX_LOCATIONS: usize = 20;

// ---------------------------------------------------------------- API types

/// One reported place as the reporter names it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NoticeLocationInput {
    /// message | attachment | room | profile | other
    pub kind: String,
    /// A message link (`…?message=<id>`) or id, an attachment id, a room link or id, a user address, or a
    /// description (`other`).
    pub value: String,
}

/// `POST /legal/notices`: the fields DMCA §512(c)(3) and DSA Art. 16 ask for.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct NoticeRequest {
    /// copyright | illegal | terms
    pub basis: String,
    pub reporter_name: String,
    pub reporter_email: String,
    #[serde(default)]
    pub reporter_address: String,
    #[serde(default)]
    pub reporter_phone: String,
    /// Identification of the copyrighted work or description of the illegal content.
    pub work: String,
    /// Why the content is illegal or breaks the terms (required for `illegal` and `terms`).
    #[serde(default)]
    pub explanation: String,
    pub locations: Vec<NoticeLocationInput>,
    /// "I believe in good faith that the use is not authorized / the content is illegal."
    pub good_faith: bool,
    /// "The information in this notice is accurate."
    pub accuracy: bool,
    /// Copyright only: "under penalty of perjury, I am authorized to act on behalf of the owner".
    #[serde(default)]
    pub perjury: bool,
    /// Electronic signature: the reporter's full name, typed.
    pub signature: String,
    pub captcha_token: Option<String>,
}

/// A reported place as the node resolved it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NoticeLocation {
    pub kind: String,
    /// The value as reported.
    pub value: String,
    /// The node that hosts the content (this node or the one to forward to).
    pub node: String,
    /// The content was found on this node.
    pub local: bool,
    /// Message id, attachment id, room id or user address.
    pub id: Option<String>,
    pub conversation_id: Option<String>,
    pub room_id: Option<String>,
    /// The uploader (local user id) when the content is on this node.
    pub author_id: Option<String>,
    /// The uploader's address.
    pub author: Option<String>,
    /// Removed by an action of this case.
    #[serde(default)]
    pub removed: bool,
}

/// Answer to a submitted notice.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoticeCreated {
    pub case_id: String,
    pub state: String,
    /// A confirmation with the status link was sent to the reporter.
    pub mailed: bool,
}

/// The reporter's view of a case (`GET /legal/notices/{case_id}?token=`).
#[derive(Debug, Serialize, ToSchema)]
pub struct NoticeStatus {
    pub case_id: String,
    pub state: String,
    pub basis: String,
    pub created_at: String,
    pub updated_at: String,
    /// The reason given with a rejection or the decision, if any.
    pub decision_reason: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct NoticeRow {
    pub id: String,
    pub state: String,
    pub basis: String,
    pub origin: Option<String>,
    pub origin_case: Option<String>,
    pub reporter_name: String,
    pub reporter_email: String,
    pub reporter_address: String,
    pub reporter_phone: String,
    pub reporter_token_hash: Option<String>,
    pub work: String,
    pub explanation: String,
    pub locations: String,
    pub target_user_id: Option<String>,
    pub target_address: Option<String>,
    pub good_faith: i64,
    pub accuracy: i64,
    pub perjury: i64,
    pub signature: String,
    pub decision_reason: String,
    pub statement: Option<String>,
    pub statement_at: Option<String>,
    pub forwarded_to: Option<String>,
    pub counter_deadline: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub decided_at: Option<String>,
    pub retain_until: String,
}

const COLS: &str = "id, state, basis, origin, origin_case, reporter_name, reporter_email, reporter_address, reporter_phone, reporter_token_hash, work, explanation, locations, target_user_id, target_address, good_faith, accuracy, perjury, signature, decision_reason, statement, statement_at, forwarded_to, counter_deadline, created_at, updated_at, decided_at, retain_until";

impl NoticeRow {
    pub fn locations(&self) -> Vec<NoticeLocation> {
        serde_json::from_str(&self.locations).unwrap_or_default()
    }

    pub fn to_api(&self) -> Notice {
        Notice {
            case_id: self.id.clone(),
            state: self.state.clone(),
            basis: self.basis.clone(),
            origin: self.origin.clone(),
            origin_case: self.origin_case.clone(),
            reporter_name: self.reporter_name.clone(),
            reporter_email: self.reporter_email.clone(),
            reporter_address: self.reporter_address.clone(),
            reporter_phone: self.reporter_phone.clone(),
            work: self.work.clone(),
            explanation: self.explanation.clone(),
            locations: self.locations(),
            target_user_id: self.target_user_id.clone(),
            target_address: self.target_address.clone(),
            good_faith: self.good_faith != 0,
            accuracy: self.accuracy != 0,
            perjury: self.perjury != 0,
            signature: self.signature.clone(),
            decision_reason: self.decision_reason.clone(),
            statement: self.statement.clone(),
            statement_at: self.statement_at.clone(),
            forwarded_to: self.forwarded_to.clone(),
            counter_deadline: self.counter_deadline.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            decided_at: self.decided_at.clone(),
            retain_until: self.retain_until.clone(),
        }
    }
}

/// A case as node admins see it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Notice {
    pub case_id: String,
    /// received | in_review | actioned | rejected | counter_notice
    pub state: String,
    /// copyright | illegal | terms
    pub basis: String,
    /// The forwarding node for a case opened by S2S `legal.notice` (null: submitted here).
    pub origin: Option<String>,
    pub origin_case: Option<String>,
    pub reporter_name: String,
    pub reporter_email: String,
    pub reporter_address: String,
    pub reporter_phone: String,
    pub work: String,
    pub explanation: String,
    pub locations: Vec<NoticeLocation>,
    pub target_user_id: Option<String>,
    pub target_address: Option<String>,
    pub good_faith: bool,
    pub accuracy: bool,
    pub perjury: bool,
    pub signature: String,
    pub decision_reason: String,
    /// The statement of reasons sent to the uploader.
    pub statement: Option<String>,
    pub statement_at: Option<String>,
    /// Domains the case was forwarded to (comma-separated).
    pub forwarded_to: Option<String>,
    /// The uploader may answer with a counter-notice until then.
    pub counter_deadline: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub decided_at: Option<String>,
    /// The case is deleted after this time (retention).
    pub retain_until: String,
}

#[derive(Debug, Clone, Serialize, ToSchema, FromRow)]
pub struct NoticeEvent {
    pub id: String,
    pub actor_id: Option<String>,
    /// received, mail.reporter, mail.uploader, remove_content, disable_account, reject, forward, set_state,
    /// counter_notice, counter_decision, statement, forwarded_in
    pub action: String,
    /// JSON object with the step's details.
    #[schema(value_type = Object)]
    #[sqlx(try_from = "String")]
    pub detail: JsonText,
    pub created_at: String,
}

/// JSON stored as text, served as a JSON value.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct JsonText(pub Value);

#[allow(clippy::infallible_try_from)] // sqlx's `try_from` attribute needs `TryFrom`
impl TryFrom<String> for JsonText {
    type Error = std::convert::Infallible;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Self(serde_json::from_str(&s).unwrap_or(Value::Null)))
    }
}

#[derive(Debug, Clone, Serialize, ToSchema, FromRow)]
pub struct CounterNotice {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub address: String,
    pub statement: String,
    #[serde(serialize_with = "int_bool")]
    #[schema(value_type = bool)]
    pub consent: i64,
    pub signature: String,
    /// restore | uphold (null while open)
    pub decision: Option<String>,
    pub reason: String,
    pub decided_at: Option<String>,
    pub created_at: String,
}

fn int_bool<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bool(*v != 0)
}

/// What the node shows of a reported place: plaintext content inline, only metadata for encrypted content.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ContentPreview {
    /// Index into `locations`.
    pub location: usize,
    pub kind: String,
    /// The content is end-to-end encrypted: the node cannot show it.
    pub encrypted: bool,
    /// Plaintext content (message body, profile text, room description, file name), null when encrypted or gone.
    pub text: Option<String>,
    /// Where it is (room / channel name, conversation kind).
    pub context: String,
    pub author: Option<String>,
    pub created_at: Option<String>,
    /// Attachments: MIME type and size.
    pub mime: Option<String>,
    pub size: Option<i64>,
    /// The content no longer exists on this node.
    pub gone: bool,
}

/// A case with its trail, counter-notices, the reported content and the repeat-infringer counter.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoticeDetail {
    #[serde(flatten)]
    pub notice: Notice,
    pub events: Vec<NoticeEvent>,
    pub counter_notices: Vec<CounterNotice>,
    pub content: Vec<ContentPreview>,
    /// Actioned cases against the target user (all cases kept, this one included).
    pub repeat_count: i64,
    pub repeat_threshold: u32,
    /// `repeat_count` reached the threshold: the admin page suggests disabling the account (never automatic).
    pub repeat_suggest_disable: bool,
}

/// A case of the signed-in uploader (`GET /users/me/legal-notices`): the statement of reasons and the counter-notice.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploaderNotice {
    pub case_id: String,
    pub state: String,
    pub basis: String,
    pub statement: Option<String>,
    pub statement_at: Option<String>,
    pub counter_deadline: Option<String>,
    /// A counter-notice can be sent now.
    pub can_counter: bool,
    /// The uploader already answered.
    pub countered: bool,
    pub locations: Vec<NoticeLocation>,
}

// ---------------------------------------------------------------- store

pub async fn by_id(db: &Pool, id: &str) -> Result<Option<NoticeRow>, ApiError> {
    if !util::is_ulid(id) {
        return Ok(None);
    }
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM legal_notices WHERE id = $1")).bind(id).fetch_optional(db).await?)
}

pub async fn by_origin(db: &Pool, origin: &str, origin_case: &str) -> Result<Option<NoticeRow>, ApiError> {
    Ok(sqlx::query_as(&format!("SELECT {COLS} FROM legal_notices WHERE origin = $1 AND origin_case = $2"))
        .bind(origin)
        .bind(origin_case)
        .fetch_optional(db)
        .await?)
}

/// Filters of the admin list.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct NoticeFilter {
    /// Only this state.
    pub state: Option<String>,
    /// Only this legal basis.
    pub basis: Option<String>,
    /// Text in the reporter's name or e-mail, the work, the target address or the case id.
    pub q: Option<String>,
    /// Page size (1–200, default 50).
    pub limit: Option<i64>,
    /// Cases older than this case id (pagination, newest first).
    pub before: Option<String>,
}

pub async fn list(db: &Pool, f: &NoticeFilter) -> Result<Vec<NoticeRow>, ApiError> {
    let mut sql = format!("SELECT {COLS} FROM legal_notices WHERE 1 = 1");
    let mut binds: Vec<String> = Vec::new();
    if let Some(s) = f.state.as_deref().filter(|s| !s.is_empty()) {
        validate::one_of("state", s, STATES)?;
        binds.push(s.to_string());
        sql.push_str(&format!(" AND state = ${}", binds.len()));
    }
    if let Some(b) = f.basis.as_deref().filter(|s| !s.is_empty()) {
        validate::one_of("basis", b, BASES)?;
        binds.push(b.to_string());
        sql.push_str(&format!(" AND basis = ${}", binds.len()));
    }
    if let Some(q) = f.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let q: String = q.chars().take(100).collect::<String>().to_lowercase();
        // LIKE wildcards in the input are matched literally.
        let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        binds.push(format!("%{escaped}%"));
        let n = binds.len();
        sql.push_str(&format!(
            " AND (LOWER(reporter_name) LIKE ${n} ESCAPE '\\' OR LOWER(reporter_email) LIKE ${n} ESCAPE '\\' OR LOWER(work) LIKE ${n} ESCAPE '\\' OR LOWER(COALESCE(target_address, '')) LIKE ${n} ESCAPE '\\' OR LOWER(id) LIKE ${n} ESCAPE '\\')"
        ));
    }
    if let Some(b) = f.before.as_deref().filter(|b| util::is_ulid(b)) {
        binds.push(b.to_string());
        sql.push_str(&format!(" AND id < ${}", binds.len()));
    }
    sql.push_str(&format!(" ORDER BY id DESC LIMIT {}", validate::limit(f.limit, 50, 200)));
    let mut q = sqlx::query_as::<_, NoticeRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(q.fetch_all(db).await?)
}

pub async fn events(db: &Pool, notice_id: &str) -> Result<Vec<NoticeEvent>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, actor_id, action, detail, created_at FROM legal_notice_events WHERE notice_id = $1 ORDER BY id",
    )
    .bind(notice_id)
    .fetch_all(db)
    .await?)
}

pub async fn counter_notices(db: &Pool, notice_id: &str) -> Result<Vec<CounterNotice>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, name, address, statement, consent, signature, decision, reason, decided_at, created_at
         FROM legal_counter_notices WHERE notice_id = $1 ORDER BY id",
    )
    .bind(notice_id)
    .fetch_all(db)
    .await?)
}

/// Appends a step to the case's trail.
pub async fn event(
    db: &Pool,
    notice_id: &str,
    actor: Option<&str>,
    action: &str,
    detail: Value,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO legal_notice_events (id, notice_id, actor_id, action, detail, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(util::ulid())
    .bind(notice_id)
    .bind(actor)
    .bind(action)
    .bind(detail.to_string())
    .bind(util::now())
    .execute(db)
    .await?;
    Ok(())
}

fn retain_until(state: &AppState) -> String {
    util::in_seconds(i64::from(state.config.legal_notice_retention_days) * 24 * 3600)
}

/// Updates state and decision fields; every change extends the retention.
async fn update(
    state: &AppState,
    id: &str,
    new_state: &str,
    decision_reason: Option<&str>,
    decided: bool,
) -> Result<(), ApiError> {
    let now = util::now();
    sqlx::query(
        "UPDATE legal_notices SET state = $1, decision_reason = COALESCE($2, decision_reason), updated_at = $3,
           decided_at = CASE WHEN $4 = 1 THEN $3 ELSE decided_at END, retain_until = $5 WHERE id = $6",
    )
    .bind(new_state)
    .bind(decision_reason)
    .bind(&now)
    .bind(decided as i64)
    .bind(retain_until(state))
    .bind(id)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Actioned cases against `user_id` (the repeat-infringer counter).
pub async fn repeat_count(db: &Pool, user_id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM legal_notices WHERE target_user_id = $1 AND state = 'actioned'")
        .bind(user_id)
        .fetch_one(db)
        .await?)
}

/// Deletes cases whose retention ended. Returns the number deleted.
pub async fn prune(db: &Pool, now: chrono::DateTime<chrono::Utc>) -> Result<u64, ApiError> {
    Ok(sqlx::query("DELETE FROM legal_notices WHERE retain_until < $1")
        .bind(util::format_time(now))
        .execute(db)
        .await?
        .rows_affected())
}

// ---------------------------------------------------------------- validation and resolution

/// A notice whose fields passed the checks.
#[derive(Debug, Clone)]
pub struct ValidNotice {
    pub basis: String,
    pub reporter_name: String,
    pub reporter_email: String,
    pub reporter_address: String,
    pub reporter_phone: String,
    pub work: String,
    pub explanation: String,
    pub locations: Vec<NoticeLocationInput>,
    pub good_faith: bool,
    pub accuracy: bool,
    pub perjury: bool,
    pub signature: String,
}

pub fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else { return false };
    !local.is_empty()
        && local.len() <= 64
        && e.len() <= 254
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !e.chars().any(|c| c.is_whitespace() || c.is_control() || c == '<' || c == '>' || c == ',')
}

/// Field checks of the form (and of forwarded notices).
pub fn validate(req: &NoticeRequest) -> Result<ValidNotice, ApiError> {
    let basis = validate::one_of("basis", req.basis.trim(), BASES)?;
    let reporter_name = validate::name("reporter_name", &req.reporter_name, 200)?;
    let reporter_email = req.reporter_email.trim().to_lowercase();
    if !valid_email(&reporter_email) {
        return Err(bad("legal.email_invalid", "A valid e-mail address is required"));
    }
    let reporter_address = validate::text("reporter_address", &req.reporter_address, 0, 500)?;
    let reporter_phone = validate::text("reporter_phone", &req.reporter_phone, 0, 50)?;
    let work = validate::text("work", &req.work, 1, 5000)?;
    let explanation = validate::text("explanation", &req.explanation, 0, 5000)?;
    if basis != "copyright" && explanation.is_empty() {
        return Err(bad("legal.explanation_required", "Explain why the content is illegal or breaks the terms"));
    }
    if req.locations.is_empty() || req.locations.len() > MAX_LOCATIONS {
        return Err(bad("legal.locations_invalid", format!("Name between 1 and {MAX_LOCATIONS} locations")));
    }
    let mut locations = Vec::with_capacity(req.locations.len());
    for l in &req.locations {
        let kind = validate::one_of("locations.kind", l.kind.trim(), LOCATION_KINDS)?;
        let value = validate::name("locations.value", &l.value, 500)?;
        locations.push(NoticeLocationInput { kind, value });
    }
    if !req.good_faith || !req.accuracy {
        return Err(bad("legal.statements_required", "The good-faith and accuracy statements are required"));
    }
    if basis == "copyright" && !req.perjury {
        return Err(bad("legal.perjury_required", "Copyright notices need the statement under penalty of perjury"));
    }
    let signature = validate::name("signature", &req.signature, 200)?;
    Ok(ValidNotice {
        basis,
        reporter_name,
        reporter_email,
        reporter_address,
        reporter_phone,
        work,
        explanation,
        locations,
        good_faith: req.good_faith,
        accuracy: req.accuracy,
        perjury: req.perjury && req.basis.trim() == "copyright",
        signature,
    })
}

/// The ULIDs in `s`, in order (case-insensitive, returned uppercase).
fn ulids_in(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric()).map(str::to_ascii_uppercase).filter(|t| util::is_ulid(t)).collect()
}

/// The node a reported link points at: `/n/<domain>/…` (a room or DM of another node in the web client), else the
/// link's host when it is not this node's, else this node.
fn node_of(state: &AppState, value: &str) -> String {
    let own = state.config.domain.clone();
    let public_host = url_host(&state.config.public_url());
    if let Some(rest) = value.split("/n/").nth(1) {
        let domain = rest.split('/').next().unwrap_or("").to_lowercase();
        if util::valid_domain(&domain) {
            return domain;
        }
    }
    match url_host(value) {
        Some(host) if host != own && Some(&host) != public_host.as_ref() && util::valid_domain(&host) => {
            // A web client origin of this node (e.g. `app.` before the domain) cannot be told apart from another
            // node by the host alone: only hosts that are a tavrn domain different from ours count as remote.
            if host.ends_with(&format!(".{own}")) { own } else { host }
        }
        _ => own,
    }
}

fn url_host(value: &str) -> Option<String> {
    let rest = value.trim().split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?.to_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Resolves the reported places against this node's data.
pub async fn resolve(state: &AppState, inputs: &[NoticeLocationInput]) -> Result<Vec<NoticeLocation>, ApiError> {
    let own = state.config.domain.clone();
    let mut out = Vec::with_capacity(inputs.len());
    for l in inputs {
        let mut loc = NoticeLocation {
            kind: l.kind.clone(),
            value: l.value.clone(),
            node: own.clone(),
            local: false,
            id: None,
            conversation_id: None,
            room_id: None,
            author_id: None,
            author: None,
            removed: false,
        };
        match l.kind.as_str() {
            "message" => {
                loc.node = node_of(state, &l.value);
                // `?message=<id>` names the message; otherwise the last id in the link is the message.
                let explicit = l.value.split("message=").nth(1).map(ulids_in).and_then(|v| v.into_iter().next());
                loc.id = explicit.or_else(|| ulids_in(&l.value).pop());
                if loc.node == own
                    && let Some(id) = &loc.id
                    && let Some(m) = store::messages::by_id(&state.db, id).await?
                {
                    loc.local = true;
                    loc.conversation_id = Some(m.conversation_id.clone());
                    loc.room_id =
                        store::social::conversation(&state.db, &m.conversation_id).await?.and_then(|c| c.room_id);
                    loc.author = Some(format!("{}@{}", m.author_username, m.author_domain));
                    loc.author_id = Some(m.author_id);
                }
            }
            "attachment" => {
                loc.node = node_of(state, &l.value);
                loc.id = ulids_in(&l.value).pop();
                if loc.node == own
                    && let Some(id) = &loc.id
                    && let Some(b) = store::blobs::by_id(&state.db, id).await?
                {
                    loc.local = true;
                    loc.conversation_id = Some(b.conversation_id.clone());
                    loc.room_id = b.room_id.clone();
                    if let Some(u) = store::users::by_id(&state.db, &b.uploader_id).await? {
                        loc.author = Some(u.address());
                    }
                    loc.author_id = Some(b.uploader_id);
                }
            }
            "room" => {
                loc.node = node_of(state, &l.value);
                // `/rooms/<room>/…`: the first id after `rooms/` is the room.
                loc.id = l
                    .value
                    .split("rooms/")
                    .nth(1)
                    .map(ulids_in)
                    .and_then(|v| v.into_iter().next())
                    .or_else(|| ulids_in(&l.value).pop());
                if loc.node == own
                    && let Some(id) = &loc.id
                    && let Some(r) = store::rooms::room_by_id(&state.db, id).await?
                {
                    loc.local = true;
                    loc.room_id = Some(r.id.clone());
                    if let Some(u) = store::users::by_id(&state.db, &r.owner_id).await? {
                        loc.author = Some(u.address());
                    }
                    loc.author_id = Some(r.owner_id);
                }
            }
            "profile" => {
                // A user address, also inside a link (`/u/alice@node`).
                let candidate = l
                    .value
                    .split(['/', ' ', '?', '#'])
                    .map(|s| s.trim().trim_start_matches('@').to_lowercase())
                    .find(|s| util::parse_address(s).is_some());
                if let Some(address) = candidate
                    && let Some((name, domain)) = util::parse_address(&address)
                {
                    loc.node = domain.to_string();
                    loc.id = Some(address.clone());
                    if domain == own
                        && let Some(u) = store::users::by_username(&state.db, name, domain).await?
                    {
                        loc.local = true;
                        loc.author = Some(u.address());
                        loc.author_id = Some(u.id);
                    } else if domain != own {
                        // Content of a remote profile lives on its home node.
                        loc.author = Some(address);
                    }
                }
            }
            _ => {}
        }
        out.push(loc);
    }
    Ok(out)
}

// ---------------------------------------------------------------- create

/// Stores a new case and sends the reporter's confirmation (with the status link for cases submitted here).
/// `origin` = (forwarding node, its case id) for S2S cases. Returns the case and whether a mail went out.
pub async fn create(
    state: &AppState,
    n: &ValidNotice,
    origin: Option<(&str, &str)>,
    locale: Option<&str>,
) -> Result<(NoticeRow, bool), ApiError> {
    let locations = resolve(state, &n.locations).await?;
    let target = locations.iter().find(|l| l.local && l.author_id.is_some());
    let id = util::ulid();
    let now = util::now();
    let token = util::random_token(32);
    let token_hash = origin.is_none().then(|| util::sha256_b64(&token));
    sqlx::query(
        "INSERT INTO legal_notices (id, state, basis, origin, origin_case, reporter_name, reporter_email, reporter_address,
           reporter_phone, reporter_token_hash, work, explanation, locations, target_user_id, target_address, good_faith,
           accuracy, perjury, signature, created_at, updated_at, retain_until)
         VALUES ($1, 'received', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19, $20)",
    )
    .bind(&id)
    .bind(&n.basis)
    .bind(origin.map(|o| o.0))
    .bind(origin.map(|o| o.1))
    .bind(&n.reporter_name)
    .bind(&n.reporter_email)
    .bind(&n.reporter_address)
    .bind(&n.reporter_phone)
    .bind(&token_hash)
    .bind(&n.work)
    .bind(&n.explanation)
    .bind(serde_json::to_string(&locations).map_err(|e| ApiError::Internal(e.into()))?)
    .bind(target.and_then(|t| t.author_id.clone()))
    .bind(target.and_then(|t| t.author.clone()))
    .bind(n.good_faith as i64)
    .bind(n.accuracy as i64)
    .bind(n.perjury as i64)
    .bind(&n.signature)
    .bind(&now)
    .bind(retain_until(state))
    .execute(&state.db)
    .await?;
    let detail = match origin {
        Some((node, case)) => json!({ "origin": node, "origin_case": case }),
        None => json!({}),
    };
    event(&state.db, &id, None, if origin.is_some() { "forwarded_in" } else { "received" }, detail).await?;
    if locale.is_some() {
        sqlx::query("UPDATE legal_notices SET reporter_locale = $1 WHERE id = $2")
            .bind(locale)
            .bind(&id)
            .execute(&state.db)
            .await?;
    }
    // The status link is only in the mail: the case id alone never opens the status page.
    let link = format!("{}/legal/notice/{id}?token={token}", state.mailer.public_url());
    let (template, vars) = match origin {
        None => ("notice_received", [("case", id.as_str()), ("link", link.as_str())]),
        Some((node, _)) => ("notice_forwarded_in", [("case", id.as_str()), ("origin", node)]),
    };
    state.mailer.send_template(&n.reporter_email, locale, template, &vars).await;
    event(&state.db, &id, None, "mail.reporter", json!({ "kind": "confirmation" })).await?;
    let row = by_id(&state.db, &id).await?.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("case missing")))?;
    Ok((row, true))
}

/// The reporter's status view: needs the token of the confirmation mail. Unknown case ids and wrong tokens answer
/// the same `404 legal.notice_not_found` in the same way (no oracle for case ids).
pub async fn status_for_reporter(state: &AppState, case_id: &str, token: &str) -> Result<NoticeStatus, ApiError> {
    use subtle::ConstantTimeEq;
    let not_found = || ApiError::NotFound { code: "legal.notice_not_found", what: "Notice".into() };
    let row = by_id(&state.db, case_id).await?;
    let presented = util::sha256_b64(token);
    let stored = row.as_ref().and_then(|r| r.reporter_token_hash.clone()).unwrap_or_else(|| util::sha256_b64("-"));
    let matches = bool::from(stored.as_bytes().ct_eq(presented.as_bytes()));
    let Some(row) = row.filter(|r| matches && !token.is_empty() && r.reporter_token_hash.is_some()) else {
        return Err(not_found());
    };
    Ok(NoticeStatus {
        case_id: row.id,
        state: row.state,
        basis: row.basis,
        created_at: row.created_at,
        updated_at: row.updated_at,
        decision_reason: row.decision_reason,
    })
}

// ---------------------------------------------------------------- admin view

pub async fn detail(state: &AppState, row: &NoticeRow) -> Result<NoticeDetail, ApiError> {
    let locations = row.locations();
    let mut content = Vec::with_capacity(locations.len());
    for (i, l) in locations.iter().enumerate() {
        content.push(preview(state, i, l).await?);
    }
    let repeat_count = match &row.target_user_id {
        Some(u) => repeat_count(&state.db, u).await?,
        None => 0,
    };
    let threshold = state.config.legal_repeat_threshold;
    Ok(NoticeDetail {
        notice: row.to_api(),
        events: events(&state.db, &row.id).await?,
        counter_notices: counter_notices(&state.db, &row.id).await?,
        content,
        repeat_count,
        repeat_threshold: threshold,
        repeat_suggest_disable: repeat_count >= i64::from(threshold),
    })
}

async fn context_of(state: &AppState, conversation_id: &str) -> Result<String, ApiError> {
    let Some(conv) = store::social::conversation(&state.db, conversation_id).await? else { return Ok(String::new()) };
    Ok(match &conv.room_id {
        Some(room_id) => {
            let room = store::rooms::room_by_id(&state.db, room_id).await?.map(|r| r.name).unwrap_or_default();
            let channel: Option<String> = sqlx::query_scalar("SELECT name FROM channels WHERE id = $1")
                .bind(conversation_id)
                .fetch_optional(&state.db)
                .await?;
            format!("{room} / #{}", channel.unwrap_or_default())
        }
        None => conv.kind.clone(),
    })
}

async fn preview(state: &AppState, index: usize, l: &NoticeLocation) -> Result<ContentPreview, ApiError> {
    let mut p = ContentPreview {
        location: index,
        kind: l.kind.clone(),
        encrypted: false,
        text: None,
        context: String::new(),
        author: l.author.clone(),
        created_at: None,
        mime: None,
        size: None,
        gone: true,
    };
    if !l.local {
        p.context = l.node.clone();
        return Ok(p);
    }
    let Some(id) = l.id.as_deref() else { return Ok(p) };
    match l.kind.as_str() {
        "message" => {
            if let Some(m) = store::messages::by_id(&state.db, id).await? {
                p.gone = false;
                p.encrypted = m.encrypted != 0;
                p.created_at = Some(m.created_at.clone());
                p.context = context_of(state, &m.conversation_id).await?;
                if m.encrypted == 0 {
                    let v: Value = serde_json::from_str(&m.content).unwrap_or(Value::Null);
                    p.text = Some(
                        v.get("body").and_then(Value::as_str).map(String::from).unwrap_or_else(|| m.content.clone()),
                    );
                }
            }
        }
        "attachment" => {
            if let Some(b) = store::blobs::by_id(&state.db, id).await? {
                let encrypted: i64 = sqlx::query_scalar("SELECT encrypted FROM conversations WHERE id = $1")
                    .bind(&b.conversation_id)
                    .fetch_optional(&state.db)
                    .await?
                    .unwrap_or(1);
                p.gone = b.expired_at.is_some();
                p.encrypted = encrypted != 0;
                p.created_at = Some(b.created_at.clone());
                p.mime = Some(b.mime.clone());
                p.size = Some(b.size);
                p.context = context_of(state, &b.conversation_id).await?;
                if encrypted == 0 {
                    p.text = Some(b.name.clone());
                }
            }
        }
        "room" => {
            if let Some(r) = store::rooms::room_by_id(&state.db, id).await? {
                p.gone = false;
                p.created_at = Some(r.created_at.clone());
                p.context = r.name.clone();
                p.text = Some(format!("{}\n\n{}", r.name, r.description).trim().to_string());
            }
        }
        "profile" => {
            if let Some((name, domain)) = util::parse_address(id)
                && let Some(u) = store::users::by_username(&state.db, name, domain).await?
            {
                let (bio, _, _) = store::users::profile_extra(&state.db, &u.id).await.unwrap_or_default();
                p.gone = u.deleted_at.is_some();
                p.created_at = Some(u.created_at.clone());
                p.context = u.address();
                p.text = Some(format!("{}\n\n{bio}", u.display_name).trim().to_string());
            }
        }
        _ => {}
    }
    Ok(p)
}

// ---------------------------------------------------------------- actions

/// Body of `POST /admin/legal/notices/{case_id}/actions`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NoticeAction {
    /// remove_content | disable_account | reject | forward | set_state
    pub action: String,
    /// Reason for the reporter (reject) or the decision; also stored in the trail.
    #[serde(default)]
    pub reason: String,
    /// remove_content / disable_account: the statement of reasons for the uploader (DSA Art. 17): the facts, the
    /// legal ground or the terms clause. The node adds the redress options.
    #[serde(default)]
    pub statement: String,
    /// remove_content: indices into `locations` (default: every local location).
    #[serde(default)]
    pub locations: Option<Vec<usize>>,
    /// disable_account: the local user id (default: the case's target user).
    pub user_id: Option<String>,
    /// forward: the node to forward to (default: every remote node the locations name).
    pub node: Option<String>,
    /// set_state: the new state.
    pub state: Option<String>,
}

/// Result of an action.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoticeActionResult {
    pub notice: Notice,
    /// remove_content: locations removed now; forward: the nodes notified.
    pub done: Vec<String>,
    /// Locations or nodes that could not be handled, with the reason.
    pub skipped: Vec<String>,
}

fn not_found() -> ApiError {
    ApiError::NotFound { code: "legal.notice_not_found", what: "Notice".into() }
}

/// Publishes an event to everyone who sees a conversation (room members or DM members).
pub async fn publish_to_conversation(state: &AppState, conversation_id: &str, kind: &str, data: Value) {
    let Ok(Some(conv)) = store::social::conversation(&state.db, conversation_id).await else { return };
    match conv.room_id {
        Some(room_id) => {
            let id = state.hub.room(&room_id, kind, &data);
            crate::subscriptions::record(state, &room_id, kind, &id, &data).await;
        }
        None => {
            if let Ok(members) = store::social::member_ids(&state.db, conversation_id).await {
                state.hub.users(members, kind, &data);
            }
        }
    }
}

/// Deletes a message with its files and tells the conversation (`message.delete`).
pub async fn delete_message(state: &AppState, message_id: &str) -> Result<bool, ApiError> {
    let Some(m) = store::messages::by_id(&state.db, message_id).await? else { return Ok(false) };
    let blobs = store::blobs::by_message(&state.db, message_id).await?;
    if !store::messages::delete(&state.db, message_id).await? {
        return Ok(false);
    }
    for b in &blobs {
        state.storage.delete(&b.id).await;
    }
    let room_id = store::social::conversation(&state.db, &m.conversation_id).await?.and_then(|c| c.room_id);
    publish_to_conversation(
        state,
        &m.conversation_id,
        "message.delete",
        json!({ "room_id": room_id, "conversation_id": m.conversation_id, "id": message_id }),
    )
    .await;
    Ok(true)
}

/// Removes the file of an attachment (the row stays as expired, like attachment retention).
async fn remove_attachment(state: &AppState, blob_id: &str) -> Result<bool, ApiError> {
    let Some(b) = store::blobs::by_id(&state.db, blob_id).await? else { return Ok(false) };
    if b.expired_at.is_some() {
        return Ok(false);
    }
    sqlx::query("UPDATE blobs SET expired_at = $1 WHERE id = $2")
        .bind(util::now())
        .bind(blob_id)
        .execute(&state.db)
        .await?;
    state.storage.delete(&b.id).await;
    if let Some(message_id) = &b.message_id
        && let Ok(m) = crate::routes::messages::enrich_one(state, "", message_id).await
    {
        publish_to_conversation(
            state,
            &b.conversation_id,
            "message.update",
            serde_json::to_value(&m).unwrap_or_default(),
        )
        .await;
    }
    Ok(true)
}

/// Clears a local user's public profile: avatar, header, bio, links and status; the display name becomes the username.
pub async fn clear_profile(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    use crate::media::MediaKind;
    crate::profile::set_user_media(state, &user.id, MediaKind::Avatar, None).await?;
    crate::profile::set_user_media(state, &user.id, MediaKind::Header, None).await?;
    sqlx::query(
        "UPDATE users SET bio = '', links = '[]', custom_status = NULL, display_name = username,
           profile_version = profile_version + 1 WHERE id = $1",
    )
    .bind(&user.id)
    .execute(&state.db)
    .await?;
    crate::profile::announce_user(state, &user.id).await
}

/// Sends the statement of reasons to an uploader: stored with the case, an in-app notification (`legal.statement`)
/// and an e-mail when the account has one.
/// The statement names the decision, the legal basis, the reasons and the redress (DSA Art. 17(3)(f)) in the uploader's
/// language (`statement_content_removed`, `statement_account_disabled`).
async fn send_statement(
    state: &AppState,
    row: &NoticeRow,
    uploader_id: &str,
    decision: &str,
    statement: &str,
    deadline: &str,
    actor: &str,
) -> Result<(), ApiError> {
    let template =
        if decision == "account disabled" { "statement_account_disabled" } else { "statement_content_removed" };
    let locale = store::users::locale(&state.db, uploader_id).await?;
    let vars =
        [("case", row.id.as_str()), ("basis", row.basis.as_str()), ("statement", statement), ("deadline", deadline)];
    let mail = state.mailer.render(locale.as_deref(), template, &vars);
    let text = mail.body.clone();
    sqlx::query("UPDATE legal_notices SET statement = $1, statement_at = $2 WHERE id = $3")
        .bind(&text)
        .bind(util::now())
        .bind(&row.id)
        .execute(&state.db)
        .await?;
    state.hub.users(
        vec![uploader_id.to_string()],
        "legal.statement",
        json!({ "case_id": row.id, "decision": decision, "counter_deadline": deadline }),
    );
    event(&state.db, &row.id, Some(actor), "statement", json!({ "user_id": uploader_id, "decision": decision }))
        .await?;
    if let Some(user) = store::users::by_id(&state.db, uploader_id).await?
        && let Some(email) = user.email.as_deref().filter(|_| user.domain == state.config.domain)
    {
        state.mailer.send_rendered(email, &mail).await;
        event(&state.db, &row.id, Some(actor), "mail.uploader", json!({ "user_id": uploader_id })).await?;
    }
    Ok(())
}

/// The language of a case's reporter (`None` = English).
async fn reporter_locale(state: &AppState, case_id: &str) -> Result<Option<String>, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<String>>("SELECT reporter_locale FROM legal_notices WHERE id = $1")
        .bind(case_id)
        .fetch_optional(&state.db)
        .await?
        .flatten())
}

/// Mails the reporter the template `template` (the case id is added as `case`) and records it on the case.
async fn mail_reporter(
    state: &AppState,
    row: &NoticeRow,
    actor: &str,
    template: &str,
    vars: &[(&str, &str)],
) -> Result<(), ApiError> {
    let locale = reporter_locale(state, &row.id).await?;
    let mut all = vec![("case", row.id.as_str())];
    all.extend_from_slice(vars);
    let mail = state.mailer.send_template(&row.reporter_email, locale.as_deref(), template, &all).await;
    event(&state.db, &row.id, Some(actor), "mail.reporter", json!({ "subject": mail.subject, "template": template }))
        .await
}

/// Runs an admin action on a case.
pub async fn act(
    state: &AppState,
    admin: &UserRow,
    case_id: &str,
    a: NoticeAction,
) -> Result<NoticeActionResult, ApiError> {
    let row = by_id(&state.db, case_id).await?.ok_or_else(not_found)?;
    let reason = validate::text("reason", &a.reason, 0, 2000)?;
    let statement = validate::text("statement", &a.statement, 0, 5000)?;
    let mut done = Vec::new();
    let mut skipped = Vec::new();
    let actor = admin.id.as_str();
    let deadline = util::in_seconds(i64::from(state.config.legal_counter_notice_days) * 24 * 3600);
    match a.action.as_str() {
        "remove_content" => {
            if statement.is_empty() {
                return Err(bad("legal.statement_required", "Write the statement of reasons for the uploader"));
            }
            let mut locations = row.locations();
            let wanted: Vec<usize> = match &a.locations {
                Some(list) => list.clone(),
                None => (0..locations.len()).filter(|i| locations[*i].local).collect(),
            };
            let mut uploaders: Vec<String> = Vec::new();
            for i in wanted {
                let Some(l) = locations.get_mut(i) else {
                    skipped.push(format!("{i}: no such location"));
                    continue;
                };
                if !l.local {
                    skipped.push(format!("{i}: hosted on {} (forward the notice)", l.node));
                    continue;
                }
                let id = l.id.clone().unwrap_or_default();
                let removed = match l.kind.as_str() {
                    "message" => delete_message(state, &id).await?,
                    "attachment" => remove_attachment(state, &id).await?,
                    "profile" => match l.author_id.as_deref() {
                        Some(uid) => match store::users::by_id(&state.db, uid).await? {
                            Some(u) => {
                                clear_profile(state, &u).await?;
                                true
                            }
                            None => false,
                        },
                        None => false,
                    },
                    _ => {
                        skipped.push(format!("{i}: {} cannot be removed by this action", l.kind));
                        continue;
                    }
                };
                if removed {
                    l.removed = true;
                    done.push(format!("{i}"));
                    store::rooms::audit(
                        &state.db,
                        None,
                        Some(actor),
                        "legal.remove_content",
                        &id,
                        &reason,
                        json!({ "case_id": row.id, "kind": l.kind, "author_id": l.author_id, "room_id": l.room_id }),
                    )
                    .await?;
                    if let Some(u) = &l.author_id
                        && !uploaders.contains(u)
                    {
                        uploaders.push(u.clone());
                    }
                } else {
                    skipped.push(format!("{i}: already gone"));
                }
            }
            sqlx::query("UPDATE legal_notices SET locations = $1 WHERE id = $2")
                .bind(serde_json::to_string(&locations).map_err(|e| ApiError::Internal(e.into()))?)
                .bind(&row.id)
                .execute(&state.db)
                .await?;
            if done.is_empty() {
                return Err(ApiError::conflict(
                    "legal.nothing_removed",
                    "No reported content of this node could be removed",
                ));
            }
            if row.target_user_id.is_none()
                && let Some(first) = uploaders.first()
            {
                let address = store::users::by_id(&state.db, first).await?.map(|u| u.address());
                sqlx::query("UPDATE legal_notices SET target_user_id = $1, target_address = $2 WHERE id = $3")
                    .bind(first)
                    .bind(address)
                    .bind(&row.id)
                    .execute(&state.db)
                    .await?;
            }
            sqlx::query("UPDATE legal_notices SET counter_deadline = $1 WHERE id = $2")
                .bind(&deadline)
                .bind(&row.id)
                .execute(&state.db)
                .await?;
            update(state, &row.id, "actioned", Some(&reason), true).await?;
            event(
                &state.db,
                &row.id,
                Some(actor),
                "remove_content",
                json!({ "locations": done, "skipped": skipped, "reason": reason }),
            )
            .await?;
            for u in &uploaders {
                send_statement(state, &row, u, "content removed", &statement, &deadline, actor).await?;
            }
            mail_reporter(state, &row, actor, "notice_content_removed", &[("reason", &reason)]).await?;
        }
        "disable_account" => {
            let user_id = a
                .user_id
                .clone()
                .or_else(|| row.target_user_id.clone())
                .ok_or_else(|| bad("legal.no_target", "The case names no local user: give user_id"))?;
            let target = store::users::by_id(&state.db, &user_id)
                .await?
                .filter(|u| u.domain == state.config.domain && u.deleted_at.is_none())
                .ok_or_else(|| ApiError::NotFound { code: "user.not_found", what: "User".into() })?;
            if target.id == admin.id {
                return Err(bad("admin.self", "You cannot disable your own account"));
            }
            if statement.is_empty() {
                return Err(bad("legal.statement_required", "Write the statement of reasons for the uploader"));
            }
            store::admin::set_disabled(&state.db, &target.id, true).await?;
            crate::federation::remote::revoke_sessions(state, &target, None).await?;
            crate::applications::owner_disabled(state, &target.id).await?;
            store::rooms::audit(
                &state.db,
                None,
                Some(actor),
                "admin.user_disable",
                &target.address(),
                &reason,
                json!({ "case_id": row.id }),
            )
            .await?;
            sqlx::query("UPDATE legal_notices SET target_user_id = $1, target_address = $2, counter_deadline = $3 WHERE id = $4")
                .bind(&target.id)
                .bind(target.address())
                .bind(&deadline)
                .bind(&row.id)
                .execute(&state.db)
                .await?;
            update(state, &row.id, "actioned", Some(&reason), true).await?;
            event(
                &state.db,
                &row.id,
                Some(actor),
                "disable_account",
                json!({ "user_id": target.id, "reason": reason }),
            )
            .await?;
            send_statement(state, &row, &target.id, "account disabled", &statement, &deadline, actor).await?;
            mail_reporter(state, &row, actor, "notice_account_disabled", &[("reason", &reason)]).await?;
            done.push(target.address());
        }
        "reject" => {
            if reason.is_empty() {
                return Err(bad("legal.reason_required", "Give the reporter a reason"));
            }
            update(state, &row.id, "rejected", Some(&reason), true).await?;
            event(&state.db, &row.id, Some(actor), "reject", json!({ "reason": reason })).await?;
            mail_reporter(state, &row, actor, "notice_rejected", &[("reason", &reason)]).await?;
        }
        "forward" => {
            if !state.config.federation_enabled {
                return Err(crate::federation::disabled());
            }
            let mut nodes: Vec<String> = row
                .locations()
                .iter()
                .filter(|l| !l.local && l.node != state.config.domain)
                .map(|l| l.node.clone())
                .collect();
            nodes.sort();
            nodes.dedup();
            if let Some(n) = a.node.as_deref().map(|n| n.trim().to_lowercase()) {
                if !nodes.contains(&n) {
                    return Err(bad("legal.forward_node_invalid", "The case names no content on that node"));
                }
                nodes = vec![n];
            }
            if nodes.is_empty() {
                return Err(ApiError::conflict("legal.nothing_to_forward", "All reported content is on this node"));
            }
            for node in &nodes {
                if let Err(e) = crate::federation::check_policy(state, node).await {
                    skipped.push(format!("{node}: {}", e.code()));
                    continue;
                }
                let locations: Vec<Value> = row
                    .locations()
                    .iter()
                    .filter(|l| &l.node == node)
                    .map(|l| json!({ "kind": l.kind, "value": l.value }))
                    .collect();
                let payload = json!({
                    "case_id": row.id,
                    "basis": row.basis,
                    "work": row.work,
                    "explanation": row.explanation,
                    "locations": locations,
                    "reporter": { "name": row.reporter_name, "email": row.reporter_email, "address": row.reporter_address, "phone": row.reporter_phone },
                    "good_faith": row.good_faith != 0,
                    "accuracy": row.accuracy != 0,
                    "perjury": row.perjury != 0,
                    "signature": row.signature,
                    "submitted_at": row.created_at,
                });
                crate::federation::outbox::enqueue(state, node, KIND, &state.config.domain, node, payload).await?;
                done.push(node.clone());
            }
            if !done.is_empty() {
                let mut all: Vec<String> = row
                    .forwarded_to
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                all.extend(done.iter().cloned());
                all.sort();
                all.dedup();
                sqlx::query("UPDATE legal_notices SET forwarded_to = $1 WHERE id = $2")
                    .bind(all.join(","))
                    .bind(&row.id)
                    .execute(&state.db)
                    .await?;
                let next = if row.state == "received" { "in_review" } else { row.state.as_str() };
                update(state, &row.id, next, None, false).await?;
                event(&state.db, &row.id, Some(actor), "forward", json!({ "nodes": done, "skipped": skipped })).await?;
                mail_reporter(state, &row, actor, "notice_forwarded", &[("nodes", &done.join(", "))]).await?;
            }
        }
        "set_state" => {
            let s = a.state.as_deref().ok_or_else(|| bad("legal.state_required", "Name the new state"))?;
            validate::one_of("state", s, STATES)?;
            update(
                state,
                &row.id,
                s,
                (!reason.is_empty()).then_some(reason.as_str()),
                matches!(s, "actioned" | "rejected"),
            )
            .await?;
            event(
                &state.db,
                &row.id,
                Some(actor),
                "set_state",
                json!({ "from": row.state, "to": s, "reason": reason }),
            )
            .await?;
            done.push(s.to_string());
        }
        _ => {
            return Err(bad(
                "validation.enum",
                "action: remove_content, disable_account, reject, forward or set_state",
            ));
        }
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(actor),
        &format!("legal.{}", a.action),
        &row.id,
        &reason,
        json!({ "case_id": row.id, "done": done }),
    )
    .await?;
    let notice = by_id(&state.db, &row.id).await?.ok_or_else(not_found)?.to_api();
    Ok(NoticeActionResult { notice, done, skipped })
}

// ---------------------------------------------------------------- counter-notices

/// Body of `POST /users/me/legal-notices/{case_id}/counter-notice` (DMCA §512(g)(3)).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CounterNoticeRequest {
    /// Full name.
    pub name: String,
    /// Postal address (DMCA) — optional for other bases.
    #[serde(default)]
    pub address: String,
    /// Why the removal was a mistake or the content is lawful.
    pub statement: String,
    /// Copyright: consent to the jurisdiction and to accept service of process (DMCA §512(g)(3)(D)).
    #[serde(default)]
    pub consent: bool,
    /// Typed signature.
    pub signature: String,
}

/// The cases of a user as the uploader (statement of reasons sent).
pub async fn of_uploader(state: &AppState, user_id: &str) -> Result<Vec<UploaderNotice>, ApiError> {
    let rows: Vec<NoticeRow> = sqlx::query_as(&format!(
        "SELECT {COLS} FROM legal_notices WHERE target_user_id = $1 AND statement IS NOT NULL ORDER BY id DESC LIMIT 100"
    ))
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;
    let now = util::now();
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let countered: bool =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM legal_counter_notices WHERE notice_id = $1")
                .bind(&r.id)
                .fetch_one(&state.db)
                .await?
                > 0;
        let open = r.state == "actioned" && r.counter_deadline.as_deref().is_some_and(|d| d > now.as_str());
        // Only what concerns the uploader: no reporter data.
        let locations = r.locations().into_iter().filter(|l| l.author_id.as_deref() == Some(user_id)).collect();
        out.push(UploaderNotice {
            case_id: r.id,
            state: r.state,
            basis: r.basis,
            statement: r.statement,
            statement_at: r.statement_at,
            counter_deadline: r.counter_deadline,
            can_counter: open && !countered,
            countered,
            locations,
        });
    }
    Ok(out)
}

pub async fn submit_counter(
    state: &AppState,
    user: &UserRow,
    case_id: &str,
    req: CounterNoticeRequest,
) -> Result<UploaderNotice, ApiError> {
    let row = by_id(&state.db, case_id)
        .await?
        .filter(|r| r.target_user_id.as_deref() == Some(user.id.as_str()) && r.statement.is_some())
        .ok_or_else(not_found)?;
    let now = util::now();
    if row.state != "actioned" || row.counter_deadline.as_deref().is_none_or(|d| d <= now.as_str()) {
        return Err(ApiError::conflict("legal.counter_closed", "The counter-notice window of this case is closed"));
    }
    if !counter_notices(&state.db, &row.id).await?.is_empty() {
        return Err(ApiError::conflict("legal.counter_exists", "You already answered this case"));
    }
    let name = validate::name("name", &req.name, 200)?;
    let address = validate::text("address", &req.address, 0, 500)?;
    let statement = validate::text("statement", &req.statement, 10, 5000)?;
    let signature = validate::name("signature", &req.signature, 200)?;
    if row.basis == "copyright" && (!req.consent || address.is_empty()) {
        return Err(bad(
            "legal.counter_incomplete",
            "Copyright counter-notices need your address and the consent to jurisdiction",
        ));
    }
    sqlx::query(
        "INSERT INTO legal_counter_notices (id, notice_id, user_id, name, address, statement, consent, signature, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(util::ulid())
    .bind(&row.id)
    .bind(&user.id)
    .bind(&name)
    .bind(&address)
    .bind(&statement)
    .bind(req.consent as i64)
    .bind(&signature)
    .bind(&now)
    .execute(&state.db)
    .await?;
    update(state, &row.id, "counter_notice", None, false).await?;
    event(&state.db, &row.id, Some(&user.id), "counter_notice", json!({ "user_id": user.id })).await?;
    // The reporter gets the counter-notice (DMCA §512(g)(2)(B)); the operator decides.
    mail_reporter(
        state,
        &row,
        &user.id,
        "counter_notice_received",
        &[("statement", statement.as_str()), ("signature", signature.as_str())],
    )
    .await?;
    of_uploader(state, &user.id).await?.into_iter().find(|n| n.case_id == row.id).ok_or_else(not_found)
}

/// Body of `POST /admin/legal/notices/{case_id}/counter-notice/decision`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CounterDecision {
    /// restore (the counter-notice is accepted: a disabled account is enabled again, the uploader may publish the
    /// content again) | uphold (the action stays).
    pub decision: String,
    #[serde(default)]
    pub reason: String,
}

pub async fn decide_counter(
    state: &AppState,
    admin: &UserRow,
    case_id: &str,
    d: CounterDecision,
) -> Result<Notice, ApiError> {
    let row = by_id(&state.db, case_id).await?.ok_or_else(not_found)?;
    let decision = validate::one_of("decision", d.decision.trim(), &["restore", "uphold"])?;
    let reason = validate::text("reason", &d.reason, 1, 2000)?;
    let counter = counter_notices(&state.db, &row.id)
        .await?
        .into_iter()
        .find(|c| c.decision.is_none())
        .filter(|_| row.state == "counter_notice")
        .ok_or_else(|| ApiError::conflict("legal.no_counter_notice", "The case has no open counter-notice"))?;
    let now = util::now();
    sqlx::query("UPDATE legal_counter_notices SET decision = $1, reason = $2, decided_at = $3 WHERE id = $4")
        .bind(&decision)
        .bind(&reason)
        .bind(&now)
        .bind(&counter.id)
        .execute(&state.db)
        .await?;
    if decision == "restore" {
        // A disabled account comes back; deleted content is gone for good (the uploader may post it again).
        let disabled_here = events(&state.db, &row.id).await?.iter().any(|e| e.action == "disable_account");
        if disabled_here && let Some(uid) = &row.target_user_id {
            store::admin::set_disabled(&state.db, uid, false).await?;
        }
        update(state, &row.id, "rejected", Some(&reason), true).await?;
    } else {
        update(state, &row.id, "actioned", Some(&reason), true).await?;
    }
    event(&state.db, &row.id, Some(&admin.id), "counter_decision", json!({ "decision": decision, "reason": reason }))
        .await?;
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.id),
        "legal.counter_decision",
        &row.id,
        &reason,
        json!({ "decision": decision }),
    )
    .await?;
    let template = if decision == "restore" { "counter_restored" } else { "counter_upheld" };
    mail_reporter(state, &row, &admin.id, template, &[("reason", &reason)]).await?;
    if let Some(user) = store::users::by_id(&state.db, &counter.user_id).await? {
        state.hub.users(vec![user.id.clone()], "legal.statement", json!({ "case_id": row.id, "decision": decision }));
        if let Some(email) = user.email.as_deref() {
            let locale = store::users::locale(&state.db, &user.id).await?;
            let vars = [("case", row.id.as_str()), ("reason", reason.as_str())];
            state.mailer.send_template(email, locale.as_deref(), template, &vars).await;
            event(&state.db, &row.id, Some(&admin.id), "mail.uploader", json!({ "user_id": user.id })).await?;
        }
    }
    Ok(by_id(&state.db, &row.id).await?.ok_or_else(not_found)?.to_api())
}

// ---------------------------------------------------------------- S2S

/// The S2S type of a forwarded notice (FEDERATION.md §5.2): from the forwarding node, to this node's domain.
pub const KIND: &str = "legal.notice";

/// A `legal.notice` from `iss`: opens a case here in state `received` with the origin recorded (idempotent per
/// origin case). Fields are checked like the form; the perjury statement is taken as sent.
pub async fn receive(state: &AppState, iss: &str, payload: &Value) -> Result<&'static str, ApiError> {
    let invalid = |d: &str| ApiError::BadRequest { code: "federation.payload_invalid", detail: d.into() };
    let s = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let reporter = payload.get("reporter").cloned().unwrap_or(Value::Null);
    let r = |k: &str| reporter.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let origin_case = s("case_id");
    if !util::is_ulid(&origin_case) {
        return Err(invalid("case_id"));
    }
    if by_origin(&state.db, iss, &origin_case).await?.is_some() {
        return Ok("duplicate");
    }
    let locations: Vec<NoticeLocationInput> = payload
        .get("locations")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(MAX_LOCATIONS + 1)
                .map(|l| NoticeLocationInput {
                    kind: l.get("kind").and_then(Value::as_str).unwrap_or("").to_string(),
                    value: l.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    let req = NoticeRequest {
        basis: s("basis"),
        reporter_name: r("name"),
        reporter_email: r("email"),
        reporter_address: r("address"),
        reporter_phone: r("phone"),
        work: s("work"),
        explanation: s("explanation"),
        locations,
        good_faith: payload.get("good_faith").and_then(Value::as_bool).unwrap_or(false),
        accuracy: payload.get("accuracy").and_then(Value::as_bool).unwrap_or(false),
        perjury: payload.get("perjury").and_then(Value::as_bool).unwrap_or(false),
        signature: s("signature"),
        captcha_token: None,
    };
    let valid = validate(&req).map_err(|e| invalid(&e.to_string()))?;
    let (row, _) = create(state, &valid, Some((iss, &origin_case)), None).await?;
    store::rooms::audit(
        &state.db,
        None,
        None,
        "legal.notice_forwarded_in",
        &row.id,
        "",
        json!({ "origin": iss, "origin_case": origin_case }),
    )
    .await?;
    Ok("handled")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn req() -> NoticeRequest {
        NoticeRequest {
            basis: "copyright".into(),
            reporter_name: "Rita Reporter".into(),
            reporter_email: "Rita@Example.org".into(),
            reporter_address: "Street 1".into(),
            reporter_phone: String::new(),
            work: "My photo".into(),
            explanation: String::new(),
            locations: vec![NoticeLocationInput { kind: "message".into(), value: "01JAAAAAAAAAAAAAAAAAAAAAAA".into() }],
            good_faith: true,
            accuracy: true,
            perjury: true,
            signature: "Rita Reporter".into(),
            captcha_token: None,
        }
    }

    fn code(r: NoticeRequest) -> String {
        validate(&r).map(|_| "ok".to_string()).unwrap_or_else(|e| e.code().to_string())
    }

    #[test]
    fn form_rules() {
        assert_eq!(code(req()), "ok");
        assert_eq!(validate(&req()).unwrap().reporter_email, "rita@example.org");
        assert_eq!(code(NoticeRequest { perjury: false, ..req() }), "legal.perjury_required");
        assert_eq!(
            code(NoticeRequest { basis: "illegal".into(), perjury: false, ..req() }),
            "legal.explanation_required"
        );
        assert_eq!(
            code(NoticeRequest { basis: "illegal".into(), perjury: false, explanation: "Insult".into(), ..req() }),
            "ok"
        );
        assert_eq!(code(NoticeRequest { basis: "other".into(), ..req() }), "validation.enum");
        assert_eq!(code(NoticeRequest { good_faith: false, ..req() }), "legal.statements_required");
        assert_eq!(code(NoticeRequest { accuracy: false, ..req() }), "legal.statements_required");
        assert_eq!(code(NoticeRequest { reporter_email: "nope".into(), ..req() }), "legal.email_invalid");
        assert_eq!(
            code(NoticeRequest { reporter_email: "a@b.c\r\nBcc: x@y.z".into(), ..req() }),
            "legal.email_invalid"
        );
        assert_eq!(code(NoticeRequest { signature: " ".into(), ..req() }), "validation.length");
        assert_eq!(code(NoticeRequest { locations: vec![], ..req() }), "legal.locations_invalid");
        let many = (0..21).map(|_| NoticeLocationInput { kind: "other".into(), value: "x".into() }).collect();
        assert_eq!(code(NoticeRequest { locations: many, ..req() }), "legal.locations_invalid");
        let bad_kind = vec![NoticeLocationInput { kind: "server".into(), value: "x".into() }];
        assert_eq!(code(NoticeRequest { locations: bad_kind, ..req() }), "validation.enum");
        assert_eq!(code(NoticeRequest { work: "x".repeat(5001), ..req() }), "validation.length");
        assert_eq!(code(NoticeRequest { reporter_name: "a\u{0}b".into(), ..req() }), "validation.control_chars");
        // The perjury flag is only stored for copyright notices.
        let v = validate(&NoticeRequest { basis: "terms".into(), explanation: "x".into(), ..req() }).unwrap();
        assert!(!v.perjury);
    }

    #[test]
    fn ulids_and_hosts_are_found_in_links() {
        let link = "https://app.example/rooms/01JAAAAAAAAAAAAAAAAAAAAAAA/channels/01JBBBBBBBBBBBBBBBBBBBBBBB?message=01jccccccccccccccccccccccc";
        assert_eq!(ulids_in(link).len(), 3);
        assert_eq!(ulids_in(link).pop().as_deref(), Some("01JCCCCCCCCCCCCCCCCCCCCCCC"));
        assert_eq!(url_host("https://User@Node.Example:8443/x").as_deref(), Some("node.example"));
        assert_eq!(url_host("01JAAAAAAAAAAAAAAAAAAAAAAA"), None);
    }
}
