// SPDX-License-Identifier: AGPL-3.0-only
//! Conformance checks against peers and their reputation record (FEDERATION.md §9).
//!
//! Behavior is checked, not code. A check run talks to the peer like any other node would:
//! its discovery document, `POST /auth/federated` with good and deliberately broken federation tokens of
//! the reserved **probe account** `tavrn-conformance@<this node>`, the normal client API in a throwaway
//! conformance room on the peer (`POST /federation/conformance/room`), and the peer's inbox with good and
//! broken node tokens. Every check yields `pass`, `warn`, `fail` (hard checks only) or `skip`, with a
//! short reason. Requests use the federation client (SSRF rules, timeouts, size caps) and the whole run
//! has a budget of 60 seconds.
//!
//! Consequences (§9.4): a hard failure blocks the peer automatically (`status = blocked_auto`); a later
//! run without hard failures lifts an automatic block. Live-traffic violations (a federation token with
//! `sub` of another domain, an inbox message with a `from` its sender may not use, three inbox messages
//! whose body does not match the signed hash within 10 minutes) block as well.
//! `TAVRN_FEDERATION_REQUIRE_CONFORMANCE` additionally refuses peers that are unchecked or failing.
//!
//! The other side: this node hosts conformance rooms for the probes of other nodes ([`create_room`]),
//! deleted after 15 minutes by the worker ([`housekeeping`]).

use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tavrn_crypto::{Client, CommitOutput, Device, MasterSecret};
use tokio::time::Instant as TokioInstant;
use utoipa::ToSchema;

use super::{
    client::ProbeResponse,
    discovery::{self, PATH as WELL_KNOWN},
    inbox::INBOX_PATH,
    tokens::{self, FederationClaims},
};
use crate::{
    app::AppState,
    error::ApiError,
    jwt::{self, StandardClaims},
    models::UserRow,
    store::{
        self,
        conformance::{STATUS_BLOCKED, STATUS_BLOCKED_AUTO, STATUS_OK},
    },
    util,
};

/// Reserved username of the probe account on every node (§9.1).
pub const PROBE_USERNAME: &str = "tavrn-conformance";
pub const PROBE_DISPLAY_NAME: &str = "tavrn conformance probe";
/// Inbox type of the probe's own messages (unknown to receivers, so accepted and ignored, §5.1).
pub const PROBE_KIND: &str = "conformance.probe";
pub const ROOM_PATH: &str = "/api/v1/federation/conformance/room";
/// A conformance room is deleted with everything this long after its creation.
pub const ROOM_LIFETIME_SECS: i64 = 15 * 60;
/// Conformance rooms per checking domain and day (development nodes: 1000).
pub const ROOMS_PER_DAY: i64 = 4;
/// Time budget of one run against one peer.
pub const RUN_BUDGET: Duration = Duration::from_secs(60);
/// Unforced runs against the same peer happen at most this often …
pub const MIN_INTERVAL_SECS: i64 = 3600;
/// … and are repeated after this time while this node federates with the peer.
pub const RECHECK_SECS: i64 = 24 * 3600;
/// Runs kept in the record's `history`.
pub const HISTORY: usize = 10;
/// Live violations are kept this long.
pub const VIOLATION_DAYS: i64 = 30;
/// Three body hash mismatches within ten minutes block the sender.
pub const BODY_HASH_LIMIT: i64 = 3;
pub const BODY_HASH_WINDOW_SECS: i64 = 600;
/// `rate.limits` sends at most this many invalid logins; peers that publish a higher limit are skipped.
pub const RATE_PROBE_CAP: u64 = 200;
/// No run within this time after a run that sent the `rate.limits` burst.
pub const RATE_COOLDOWN_SECS: i64 = 70;
/// `time.skew`: the peer's `Date` header must be within this many seconds.
pub const MAX_SKEW_SECS: i64 = 300;
/// How often the worker looks for due peers and expired conformance rooms.
pub const WORKER_INTERVAL: Duration = Duration::from_secs(60);
/// Peers checked per worker round.
pub const WORKER_BATCH: i64 = 4;

// ---------------------------------------------------------------- record

/// Result of one check.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    /// A soft failure, or a check that could not be evaluated.
    Warn,
    /// A hard failure (only hard checks fail).
    Fail,
    /// Not run (a precondition failed or it does not apply).
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CheckResult {
    /// Check id of FEDERATION.md §9.1, e.g. `token.replay`.
    pub id: String,
    pub result: Outcome,
    /// Hard checks block the peer when they fail.
    pub hard: bool,
    /// Short reason (English), null on success.
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HistoryEntry {
    pub checked_at: String,
    pub result: String,
}

/// The reputation record of a peer as stored after a run (§9.3).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Record {
    pub version: u32,
    /// `pass` (all checks pass), `warn` (warnings only) or `fail` (at least one hard failure).
    pub result: String,
    pub checked_at: String,
    /// `name/version` from the peer's discovery document (information, not proof).
    pub software: Option<String>,
    pub duration_ms: u64,
    pub checks: Vec<CheckResult>,
    /// The last 10 runs, newest first.
    pub history: Vec<HistoryEntry>,
}

/// `fail` if any check failed, `warn` if any warned, otherwise `pass`.
pub fn overall(checks: &[CheckResult]) -> &'static str {
    if checks.iter().any(|c| c.result == Outcome::Fail) {
        "fail"
    } else if checks.iter().any(|c| c.result == Outcome::Warn) {
        "warn"
    } else {
        "pass"
    }
}

/// The checks that failed hard, for the block reason.
fn failed_ids(checks: &[CheckResult]) -> Vec<String> {
    checks.iter().filter(|c| c.result == Outcome::Fail).map(|c| c.id.clone()).collect()
}

// ---------------------------------------------------------------- runner

/// Runs in progress (one per peer at a time).
#[derive(Default)]
pub struct Runner {
    running: Mutex<HashSet<String>>,
    /// The MLS part of runs against different peers must not overlap: each run replaces the probe's
    /// KeyPackage, whose private part only that run holds.
    mls: tokio::sync::Mutex<()>,
}

struct RunGuard<'a> {
    runner: &'a Runner,
    domain: String,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.runner.running.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.domain);
    }
}

impl Runner {
    fn claim(&self, domain: &str) -> Option<RunGuard<'_>> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        running.insert(domain.to_string()).then(|| RunGuard { runner: self, domain: domain.to_string() })
    }

    pub fn is_running(&self, domain: &str) -> bool {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).contains(domain)
    }
}

fn running() -> ApiError {
    ApiError::conflict("conformance.running", "A conformance check of this node is already running")
}

/// Checks `domain` and stores the result (§9.3) with its consequences (§9.4). Unforced runs return the
/// stored record when the peer was checked within the last hour.
pub async fn run(state: &AppState, domain: &str, force: bool) -> Result<Record, ApiError> {
    if !super::valid_node_domain(domain) {
        return Err(ApiError::BadRequest {
            code: "federation.domain_invalid",
            detail: "Not a valid node domain".into(),
        });
    }
    if domain == state.config.domain {
        return Err(ApiError::BadRequest {
            code: "federation.target_self",
            detail: "This node does not check itself".into(),
        });
    }
    state.federation.check_policy(domain).map_err(|e| e.to_api())?;
    let previous = store::conformance::peer_state(&state.db, domain).await?;
    let stored =
        previous.as_ref().and_then(|p| p.conformance.as_deref()).and_then(|r| serde_json::from_str::<Record>(r).ok());
    if !force
        && let (Some(record), Some(at)) = (&stored, previous.as_ref().and_then(|p| p.conformance_checked_at.as_deref()))
    {
        let cutoff = util::format_time(Utc::now() - chrono::Duration::seconds(MIN_INTERVAL_SECS));
        if at > cutoff.as_str() {
            return Ok(record.clone());
        }
    }
    // The `rate.limits` burst uses up this node's login allowance on the peer for a minute; a run in
    // that minute would only see `429`s.
    if let Some(record) = &stored
        && record.checks.iter().any(|c| c.id == "rate.limits" && c.result != Outcome::Skip)
        && let Some(at) = util::parse_time(&record.checked_at)
    {
        let wait = RATE_COOLDOWN_SECS - (Utc::now() - at).num_seconds();
        if wait > 0 {
            return Err(ApiError::RateLimited { retry_after_secs: wait as u32 });
        }
    }
    let Some(_guard) = state.conformance.claim(domain) else { return Err(running()) };

    let started = Instant::now();
    let (checks, software) = Checker::new(state, domain).run().await;
    let result = overall(&checks);
    let checked_at = util::now();
    let mut history = vec![HistoryEntry { checked_at: checked_at.clone(), result: result.to_string() }];
    history.extend(stored.map(|r| r.history).unwrap_or_default().into_iter().take(HISTORY - 1));
    let record = Record {
        version: 1,
        result: result.to_string(),
        checked_at: checked_at.clone(),
        software,
        duration_ms: started.elapsed().as_millis() as u64,
        checks,
        history,
    };
    let hard = record.checks.iter().filter(|c| c.result == Outcome::Fail).count() as i64;
    let soft = record.checks.iter().filter(|c| c.result == Outcome::Warn).count() as i64;
    let json = serde_json::to_string(&record).map_err(|e| ApiError::Internal(e.into()))?;
    store::conformance::record_run(
        &state.db,
        store::conformance::RunRecord { domain, record: &json, result, checked_at: &checked_at, hard, soft },
    )
    .await?;
    tracing::info!(domain, result, hard, soft, ms = record.duration_ms, "conformance check");
    if result == "fail" {
        let reason = format!("conformance check failed: {}", failed_ids(&record.checks).join(", "));
        block_auto(state, domain, &reason).await?;
    } else if store::conformance::transition(&state.db, domain, &[STATUS_BLOCKED_AUTO], STATUS_OK, None).await? {
        tracing::warn!(domain, "automatic block lifted after a conformance check without hard failures");
        store::rooms::audit(&state.db, None, None, "federation.unblock_auto", domain, "", json!({ "result": result }))
            .await?;
    }
    Ok(record)
}

/// Starts an unforced run in the background unless one is running (first contact under
/// `TAVRN_FEDERATION_REQUIRE_CONFORMANCE`).
pub fn trigger(state: &AppState, domain: &str) {
    if state.conformance.is_running(domain) {
        return;
    }
    let state = state.clone();
    let domain = domain.to_string();
    tokio::spawn(async move {
        if let Err(e) = run(&state, &domain, false).await {
            tracing::info!(domain, result = e.code(), "conformance check not run");
        }
    });
}

/// `TAVRN_FEDERATION_REQUIRE_CONFORMANCE` (§9.4): federated logins and inbox messages of peers whose
/// latest result is neither `pass` nor `warn` are refused; unchecked peers get `503
/// federation.conformance_pending` (and a check is started).
pub async fn require(state: &AppState, domain: &str) -> Result<(), ApiError> {
    if !state.config.federation_require_conformance {
        return Ok(());
    }
    let result = store::conformance::peer_state(&state.db, domain).await?.and_then(|p| p.conformance_result);
    match result.as_deref() {
        Some("pass" | "warn") => Ok(()),
        Some(_) => Err(super::peer_blocked(domain)),
        None => {
            trigger(state, domain);
            Err(ApiError::Pending {
                code: "federation.conformance_pending",
                detail: format!("{domain} has not passed a conformance check yet"),
                retry_after_secs: 60,
            })
        }
    }
}

// ---------------------------------------------------------------- consequences

/// Blocks a peer automatically (only from `ok`; operator blocks and key conflicts stay as they are),
/// ends the federated sessions of its users and writes an audit entry (the admin notice).
pub async fn block_auto(state: &AppState, domain: &str, reason: &str) -> Result<(), ApiError> {
    if !store::conformance::transition(&state.db, domain, &[STATUS_OK], STATUS_BLOCKED_AUTO, Some(reason)).await? {
        return Ok(());
    }
    tracing::error!(domain, reason, "peer blocked automatically");
    end_sessions(state, domain).await?;
    store::rooms::audit(&state.db, None, None, "federation.block_auto", domain, reason, json!({})).await?;
    Ok(())
}

/// Ends the federated sessions of every user of `domain` on this node (their WebSockets close). New
/// logins are refused by the domain policy while the peer is blocked.
pub async fn end_sessions(state: &AppState, domain: &str) -> Result<(), ApiError> {
    for user in store::federation::users_of_domain(&state.db, domain).await? {
        let devices = store::federation::revoke_remote_sessions(&state.db, &user.id, None).await?;
        if !devices.is_empty() {
            state.hub.devices(devices, super::inbox::SESSION_REVOKED_EVENT, json!({}));
        }
    }
    Ok(())
}

/// Kinds of live-traffic violations (§9.4).
pub const VIOLATION_ISSUER_MISMATCH: &str = "issuer_mismatch";
pub const VIOLATION_TYPE_FORBIDDEN: &str = "type_forbidden";
pub const VIOLATION_BODY_HASH: &str = "body_hash";
pub const VIOLATION_KEY_CONFLICT: &str = "key_conflict";

/// Records a live-traffic violation of an authenticated peer and blocks it when §9.4 says so. Only
/// called for evidence the peer signed (never for a bad signature: anyone can claim any `iss`).
/// Failures are logged, never passed to the request.
pub async fn violation(state: &AppState, domain: &str, kind: &str) {
    if let Err(e) = record_violation(state, domain, kind).await {
        tracing::warn!(domain, kind, error = %e, "recording a federation violation failed");
    }
}

async fn record_violation(state: &AppState, domain: &str, kind: &str) -> Result<(), ApiError> {
    store::conformance::ensure_peer(&state.db, domain).await?;
    store::conformance::add_violation(&state.db, domain, kind).await?;
    tracing::warn!(domain, kind, "federation violation observed");
    let block = match kind {
        VIOLATION_ISSUER_MISMATCH | VIOLATION_TYPE_FORBIDDEN => true,
        VIOLATION_BODY_HASH => {
            let since = util::format_time(Utc::now() - chrono::Duration::seconds(BODY_HASH_WINDOW_SECS));
            store::conformance::count_violations(&state.db, domain, kind, &since).await? >= BODY_HASH_LIMIT
        }
        _ => false,
    };
    if block {
        block_auto(state, domain, &format!("violation observed in live traffic: {kind}")).await?;
    }
    Ok(())
}

/// A federation token of `iss` with a valid signature named a `sub` of another domain (§9.4). The
/// probes of the `token.issuer_mismatch` check (`sub` = the reserved probe name) are not counted.
pub async fn observe_issuer_mismatch(state: &AppState, iss: &str, token: &str) {
    let sub = token
        .split('.')
        .nth(1)
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("sub").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    if util::parse_address(&sub).is_some_and(|(name, _)| name == PROBE_USERNAME) {
        return;
    }
    violation(state, iss, VIOLATION_ISSUER_MISMATCH).await;
}

/// An inbox message of `iss` with a valid node token whose body does not hash to the signed
/// `body_sha256` (§9.4). The probe of the `s2s.body_hash` check (an envelope of type
/// `conformance.probe`) is not counted.
pub async fn observe_body_hash(state: &AppState, iss: &str, body: &[u8]) {
    let probe = serde_json::from_slice::<Value>(body)
        .ok()
        .is_some_and(|v| v.get("type").and_then(Value::as_str) == Some(PROBE_KIND));
    if !probe {
        violation(state, iss, VIOLATION_BODY_HASH).await;
    }
}

// ---------------------------------------------------------------- probe account

/// The probe account with its derived keys: identity and two attested devices. Every secret is derived
/// from the node secret (`keys/secrets.key`), so the account keeps its keys across restarts and runs.
pub struct Probe {
    pub user: UserRow,
    pub master: MasterSecret,
    pub device_ids: Vec<String>,
    secret: std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>,
}

fn derive(secret: &[u8; 32], info: &str) -> Result<[u8; 32], ApiError> {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(None, secret)
        .expand(info.as_bytes(), &mut out)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("HKDF output length")))?;
    Ok(out)
}

impl Probe {
    pub fn address(&self) -> String {
        self.user.address()
    }

    /// Device `index` (0 or 1) as an MLS device.
    pub fn device(&self, index: usize) -> Result<Device, ApiError> {
        let id = &self.device_ids[index];
        let secret = derive(&self.secret, &format!("tavrn conformance device v1 {id}"))?;
        Device::from_secret(&self.address(), id, &secret).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))
    }
}

/// Creates the probe account if needed and (re)writes its derived identity and device keys. The
/// account has no password (it cannot log in), is hidden from user lists and counts, and its username
/// is reserved at registration.
pub async fn ensure_probe(state: &AppState) -> Result<Probe, ApiError> {
    let db = &state.db;
    let domain = &state.config.domain;
    store::conformance::create_probe_user(db, PROBE_USERNAME, domain, PROBE_DISPLAY_NAME).await?;
    let user = store::conformance::probe_user(db, PROBE_USERNAME, domain)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("probe account missing")))?;
    let mut device_ids = store::conformance::device_ids(db, &user.id).await?;
    while device_ids.len() < 2 {
        let name = format!("conformance probe {}", device_ids.len() + 1);
        device_ids.push(store::users::create_device(db, &user.id, &name, "tavrn-node").await?.id);
    }
    device_ids.truncate(2);
    let secret = state.secret_key.clone();
    let master = MasterSecret::from_bytes(derive(&secret, "tavrn conformance identity v1")?);
    let identity = tavrn_crypto::util::b64url_encode(&master.identity_public_key());
    store::conformance::set_identity(db, &user.id, &identity).await?;
    let probe = Probe { user, master, device_ids, secret };
    for index in 0..2 {
        let att = probe.device(index)?.attest(&probe.master).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
        store::conformance::set_device_key(
            db,
            &probe.device_ids[index],
            &tavrn_crypto::util::b64url_encode(&att.device_public_key),
            &tavrn_crypto::util::b64url_encode(&att.signature),
            &identity,
        )
        .await?;
    }
    let user = store::users::by_id(db, &probe.user.id).await?.unwrap_or(probe.user);
    Ok(Probe { user, ..probe })
}

/// A valid federation token of probe device `index` for `target` (also used by tests).
pub async fn probe_token(state: &AppState, probe: &Probe, index: usize, target: &str) -> Result<String, ApiError> {
    let (pv, ..) = store::federation::profile_info(&state.db, &probe.user.id).await?;
    tokens::issue_federation_token(state, probe.address(), "user", &probe.device_ids[index], target, pv, None, None)
}

// ---------------------------------------------------------------- the checks

fn b64(bytes: &[u8]) -> String {
    tavrn_crypto::util::b64url_encode(bytes)
}

fn unb64(v: &Value) -> Option<Vec<u8>> {
    v.as_str().and_then(|s| tavrn_crypto::util::b64url_decode(s).ok())
}

fn json_of(r: &ProbeResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn describe(r: &ProbeResponse) -> String {
    match &r.code {
        Some(code) => format!("status {} ({code})", r.status),
        None => format!("status {}", r.status),
    }
}

/// Outcome of a hard check whose request the peer must refuse: accepted = fail, refused with a client
/// error = pass, anything else (rate limit, server error, timeout) = warn.
fn must_refuse(r: &Result<ProbeResponse, String>) -> (Outcome, Option<String>) {
    match r {
        Ok(r) if (200..300).contains(&r.status) => (Outcome::Fail, Some(format!("accepted ({})", r.status))),
        Ok(r) if (400..500).contains(&r.status) && r.status != 408 && r.status != 429 => (Outcome::Pass, None),
        Ok(r) => (Outcome::Warn, Some(format!("not evaluated: {}", describe(r)))),
        Err(e) => (Outcome::Warn, Some(format!("not evaluated: {e}"))),
    }
}

/// A commit with one byte flipped in its middle: the signature no longer covers the content (the
/// middle lies in the signed framed content, never in the trailing MACs a delivery service cannot check).
pub fn tamper(commit: &[u8]) -> Vec<u8> {
    let mut out = commit.to_vec();
    if let Some(b) = out.get_mut(commit.len() / 2) {
        *b ^= 0x01;
    }
    out
}

/// The conformance room on the peer as answered by `POST /federation/conformance/room`.
struct PeerRoom {
    room_id: String,
    conversation_id: String,
    plaintext_channel_id: String,
}

/// The keys (`kid`, `x`) of a discovery document.
pub type KeySet = BTreeSet<(String, String)>;

/// Fetches the peer's discovery document from every address its domain resolves to and returns the
/// keys of each valid one. Addresses that do not answer, answer with an error or with an invalid
/// document are left out (they are `wk.fetch` matters, not key conflicts).
pub async fn keys_by_address(state: &AppState, domain: &str) -> Vec<(IpAddr, KeySet)> {
    let answers = match state.federation.get_each_address(domain, WELL_KNOWN, super::client::Kind::Discovery).await {
        Ok(a) => a,
        Err(e) => {
            tracing::info!(domain, result = e.label(), "per-address discovery fetch failed");
            return Vec::new();
        }
    };
    answers
        .into_iter()
        .filter_map(|(ip, fetched)| {
            let doc = discovery::validate(domain, &fetched.ok()?.body).ok()?;
            Some((ip, doc.keys.iter().map(|k| (k.kid.clone(), k.x.clone())).collect()))
        })
        .collect()
}

/// `keys.consistent` across addresses (§9.1): every address must serve exactly the same key set. A
/// different set on one address is a split view (or an interception on one path), also when it only
/// adds a key.
pub fn compare_address_keys(seen: &[(IpAddr, KeySet)]) -> Result<(), String> {
    let Some((first_ip, first)) = seen.first() else { return Ok(()) };
    for (ip, keys) in &seen[1..] {
        if keys != first {
            let differing: BTreeSet<&str> = first.symmetric_difference(keys).map(|(kid, _)| kid.as_str()).collect();
            return Err(format!(
                "{first_ip} and {ip} serve different keys (kid {})",
                differing.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    Ok(())
}

struct Checker<'a> {
    state: &'a AppState,
    domain: &'a str,
    deadline: TokioInstant,
    results: Vec<CheckResult>,
    date: Option<String>,
    doc: Option<Value>,
}

impl<'a> Checker<'a> {
    fn new(state: &'a AppState, domain: &'a str) -> Self {
        Self { state, domain, deadline: TokioInstant::now() + RUN_BUDGET, results: Vec::new(), date: None, doc: None }
    }

    fn push(&mut self, id: &str, hard: bool, (result, detail): (Outcome, Option<String>)) {
        self.results.push(CheckResult { id: id.into(), result, hard, detail });
    }

    fn pass(&mut self, id: &str, hard: bool) {
        self.push(id, hard, (Outcome::Pass, None));
    }

    fn warn(&mut self, id: &str, hard: bool, detail: impl Into<String>) {
        self.push(id, hard, (Outcome::Warn, Some(detail.into())));
    }

    fn skip(&mut self, id: &str, hard: bool, detail: impl Into<String>) {
        self.push(id, hard, (Outcome::Skip, Some(detail.into())));
    }

    /// One request to the peer within the run's budget.
    async fn call(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<ProbeResponse, String> {
        let request = self.state.federation.probe(self.domain, method, path, bearer, body);
        match tokio::time::timeout_at(self.deadline, request).await {
            Err(_) => Err("time budget exhausted".into()),
            Ok(Err(e)) => Err(e.label()),
            Ok(Ok(r)) => {
                if self.date.is_none() {
                    self.date = r.date.clone();
                }
                Ok(r)
            }
        }
    }

    async fn call_json(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Value,
    ) -> Result<ProbeResponse, String> {
        self.call(method, path, bearer, Some(body.to_string().into_bytes())).await
    }

    async fn login(&mut self, token: &str) -> Result<ProbeResponse, String> {
        self.call_json(
            Method::POST,
            "/api/v1/auth/federated",
            None,
            json!({ "token": token, "device_name": PROBE_DISPLAY_NAME }),
        )
        .await
    }

    /// Runs every check; returns the results and the peer's software.
    async fn run(mut self) -> (Vec<CheckResult>, Option<String>) {
        if !self.discovery().await {
            for (id, hard) in [
                ("token.accept", false),
                ("mls.sequence", false),
                ("mls.reject", true),
                ("msg.plaintext", true),
                ("msg.ciphertext", false),
                ("token.replay", true),
                ("token.bad_signature", true),
                ("token.alg", true),
                ("token.aud", true),
                ("token.expired", true),
                ("token.issuer_mismatch", true),
                ("s2s.unsigned", true),
                ("s2s.body_hash", true),
                ("s2s.replay", true),
                ("time.skew", false),
                ("rate.limits", false),
            ] {
                self.skip(id, hard, "the peer's discovery document is not usable");
            }
            return (self.results, None);
        }
        let software = self.doc.as_ref().and_then(|d| {
            let name = d.pointer("/software/name")?.as_str()?;
            let version = d.pointer("/software/version")?.as_str()?;
            Some(format!("{name}/{version}").chars().take(64).collect::<String>())
        });
        match ensure_probe(self.state).await {
            Ok(probe) => {
                self.with_probe(&probe).await;
            }
            Err(e) => {
                tracing::error!(error = %e, "conformance probe account unavailable");
                self.warn("token.accept", false, "the probe account of this node is unavailable");
            }
        }
        self.s2s().await;
        self.time_skew();
        self.rate_limits().await;
        (self.results, software)
    }

    /// `wk.fetch`, `wk.schema`, `keys.consistent`; `true` if the document is usable.
    async fn discovery(&mut self) -> bool {
        let fetched = tokio::time::timeout_at(
            self.deadline,
            self.state.federation.get(self.domain, WELL_KNOWN, super::client::Kind::Discovery),
        )
        .await;
        let fetched = match fetched {
            Err(_) => {
                self.warn("wk.fetch", false, "time budget exhausted");
                return false;
            }
            Ok(Err(e)) => {
                self.warn("wk.fetch", false, e.label());
                return false;
            }
            Ok(Ok(f)) => f,
        };
        self.pass("wk.fetch", false);
        let doc = match discovery::validate(self.domain, &fetched.body) {
            Ok(doc) => doc,
            Err(reason) => {
                self.warn("wk.schema", false, reason);
                return false;
            }
        };
        self.pass("wk.schema", false);
        self.doc = serde_json::from_slice(&fetched.body).ok();
        let known = match store::federation::peer_keys(&self.state.db, self.domain).await {
            Ok(k) => k,
            Err(_) => {
                self.warn("keys.consistent", true, "key history unavailable");
                return true;
            }
        };
        let conflict = doc.keys.iter().find(|k| known.iter().any(|(kid, x)| kid == &k.kid && x != &k.x));
        if let Some(key) = conflict {
            let detail = format!("kid {} now names another key", key.kid);
            self.push("keys.consistent", true, (Outcome::Fail, Some(detail)));
            if let Err(e) =
                store::federation::set_peer_status(&self.state.db, self.domain, discovery::STATUS_KEY_CONFLICT).await
            {
                tracing::warn!(error = %e, "storing the key conflict failed");
            }
            violation(self.state, self.domain, VIOLATION_KEY_CONFLICT).await;
            return true;
        }
        // The same keys on every address the domain resolves to (IPv4 and IPv6, several hosts).
        match tokio::time::timeout_at(self.deadline, keys_by_address(self.state, self.domain)).await {
            Err(_) => self.warn("keys.consistent", true, "time budget exhausted"),
            Ok(seen) => match compare_address_keys(&seen) {
                Ok(()) => self.pass("keys.consistent", true),
                Err(detail) => {
                    self.push("keys.consistent", true, (Outcome::Fail, Some(detail)));
                    return true;
                }
            },
        }
        // Refresh the cache and the key history the way every other use of the peer does.
        if let Err(e) = discovery::fetch(self.state, self.domain).await {
            tracing::info!(
                domain = self.domain,
                result = e.code(),
                "document refresh during the conformance check failed"
            );
        }
        true
    }

    async fn with_probe(&mut self, probe: &Probe) {
        let accepted = match probe_token(self.state, probe, 0, self.domain).await {
            Ok(t) => t,
            Err(_) => {
                self.warn("token.accept", false, "signing failed");
                return;
            }
        };
        let session = match self.login(&accepted).await {
            Ok(r) if r.status == 200 => {
                self.pass("token.accept", false);
                json_of(&r)["access_token"].as_str().map(String::from)
            }
            Ok(r) => {
                self.warn("token.accept", false, format!("refused: {}", describe(&r)));
                None
            }
            Err(e) => {
                self.warn("token.accept", false, e);
                None
            }
        };
        match &session {
            Some(s1) => self.mls(probe, s1).await,
            None => {
                for (id, hard) in
                    [("mls.sequence", false), ("mls.reject", true), ("msg.plaintext", true), ("msg.ciphertext", false)]
                {
                    self.skip(id, hard, "needs a federated session (token.accept)");
                }
            }
        }
        self.bad_tokens(probe, &accepted).await;
    }

    /// The token checks of §9.1 after `token.accept` (`token.replay` reuses its token).
    async fn bad_tokens(&mut self, probe: &Probe, accepted: &str) {
        let r = self.login(accepted).await;
        self.push("token.replay", true, must_refuse(&r));

        let now = jwt::now_unix();
        let (pv, ..) = store::federation::profile_info(&self.state.db, &probe.user.id).await.unwrap_or_default();
        let claims = |sub: String, aud: &str, iat: i64, exp: i64| FederationClaims {
            std: StandardClaims {
                iss: self.state.config.domain.clone(),
                sub,
                aud: aud.to_string(),
                exp,
                iat,
                jti: util::ulid(),
                typ: "federation".into(),
            },
            kind: "user".into(),
            owner: None,
            device: probe.device_ids[0].clone(),
            pv,
            app: None,
            scopes: None,
            age_over_18: None,
        };
        let key = self.state.signing_key();
        let sign = |c: &FederationClaims| jwt::sign(&key.signing, &key.kid, c).unwrap_or_default();
        let address = probe.address();

        // A key this node never published, under its current kid.
        let wrong = crate::keys::NodeKey::generate(&key.kid);
        let bad = jwt::sign(&wrong.signing, &key.kid, &claims(address.clone(), self.domain, now, now + 300))
            .unwrap_or_default();
        let r = self.login(&bad).await;
        self.push("token.bad_signature", true, must_refuse(&r));

        // `alg: none` and `HS256` headers over a valid claim set.
        let payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims(address.clone(), self.domain, now, now + 300)).unwrap_or_default());
        let mut outcome = (Outcome::Pass, None);
        for (alg, sig) in [("none", String::new()), ("HS256", URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()))] {
            let header = URL_SAFE_NO_PAD.encode(json!({ "alg": alg, "typ": "JWT", "kid": key.kid }).to_string());
            let r = self.login(&format!("{header}.{payload}.{sig}")).await;
            let (o, d) = must_refuse(&r);
            if o == Outcome::Fail || (o == Outcome::Warn && outcome.0 == Outcome::Pass) {
                outcome = (o, d.map(|d| format!("alg {alg}: {d}")));
            }
        }
        self.push("token.alg", true, outcome);

        let r = self.login(&sign(&claims(address.clone(), "audience.invalid", now, now + 300))).await;
        self.push("token.aud", true, must_refuse(&r));

        let r = self.login(&sign(&claims(address.clone(), self.domain, now - 900, now - 600))).await;
        self.push("token.expired", true, must_refuse(&r));

        // Validly signed, but for a user of another domain (receivers do not count the probe name as spoofing).
        let foreign = format!("{PROBE_USERNAME}@conformance.invalid");
        let r = self.login(&sign(&claims(foreign, self.domain, now, now + 300))).await;
        self.push("token.issuer_mismatch", true, must_refuse(&r));
    }

    /// Conformance room, `mls.sequence`, `mls.reject`, `msg.plaintext`, `msg.ciphertext`.
    async fn mls(&mut self, probe: &Probe, s1: &str) {
        let room = match self.call_json(Method::POST, ROOM_PATH, Some(s1), json!({})).await {
            Ok(r) if r.status == 201 => {
                let v = json_of(&r);
                match (v["room_id"].as_str(), v["conversation_id"].as_str(), v["plaintext_channel_id"].as_str()) {
                    (Some(room), Some(conv), Some(plain)) => Some(PeerRoom {
                        room_id: room.into(),
                        conversation_id: conv.into(),
                        plaintext_channel_id: plain.into(),
                    }),
                    _ => None,
                }
            }
            Ok(r) => {
                self.warn("mls.sequence", false, format!("no conformance room: {}", describe(&r)));
                None
            }
            Err(e) => {
                self.warn("mls.sequence", false, format!("no conformance room: {e}"));
                None
            }
        };
        let Some(room) = room else {
            if !self.results.iter().any(|c| c.id == "mls.sequence") {
                self.warn("mls.sequence", false, "no conformance room: malformed answer");
            }
            for (id, hard) in [("mls.reject", true), ("msg.plaintext", true), ("msg.ciphertext", false)] {
                self.skip(id, hard, "needs the conformance room");
            }
            return;
        };

        let mls_lock = self.state.conformance.mls.lock().await;
        let sequence = self.mls_sequence(probe, s1, &room).await;
        drop(mls_lock);
        match sequence {
            Ok((c1, stale, accepted)) => {
                self.pass("mls.sequence", false);
                self.mls_reject(s1, &room, c1, &stale, &accepted).await;
            }
            Err(step) => {
                self.warn("mls.sequence", false, step);
                self.skip("mls.reject", true, "needs mls.sequence");
            }
        }

        let path = format!("/api/v1/conversations/{}/messages", room.conversation_id);
        let r = self
            .call_json(Method::POST, &path, Some(s1), json!({ "content": { "type": "text", "body": "conformance" } }))
            .await;
        self.push("msg.plaintext", true, must_refuse(&r));

        let path = format!("/api/v1/conversations/{}/messages", room.plaintext_channel_id);
        let r =
            self.call_json(Method::POST, &path, Some(s1), json!({ "content": "Y29uZm9ybWFuY2U", "epoch": 1 })).await;
        let (outcome, detail) = must_refuse(&r);
        // Ciphertext in a plaintext channel weakens nothing: a soft failure.
        let outcome = if outcome == Outcome::Fail { Outcome::Warn } else { outcome };
        self.push("msg.ciphertext", false, (outcome, detail));

        let path = format!("{ROOM_PATH}/{}", room.room_id);
        if let Ok(r) = self.call(Method::DELETE, &path, Some(s1), None).await
            && r.status != 204
        {
            tracing::info!(domain = self.domain, status = r.status, "conformance room not deleted by the peer");
        }
    }

    /// The scripted MLS sequence: create the group, add the second probe device with a KeyPackage claimed
    /// through the peer (which claims it from this node), Welcome, external rejoin, self update and an
    /// encrypted message. Returns the first device's client, a commit of an older epoch and the last
    /// accepted commit for `mls.reject`, or the failed step.
    async fn mls_sequence(
        &mut self,
        probe: &Probe,
        s1: &str,
        room: &PeerRoom,
    ) -> Result<(Client, CommitOutput, CommitOutput), String> {
        let conv = &room.conversation_id;
        let q = format!("{}/{conv}", self.domain);
        let fail = |step: &str, detail: String| format!("{step}: {detail}");
        let crypto = |step: &str| {
            let step = step.to_string();
            move |e: tavrn_crypto::CryptoError| format!("{step}: {e}")
        };
        let ok = |step: &str, r: Result<ProbeResponse, String>, want: u16| match r {
            Ok(r) if r.status == want => Ok(r),
            Ok(r) => Err(fail(step, describe(&r))),
            Err(e) => Err(fail(step, e)),
        };

        // KeyPackages of the second device, stored here for the peer's claim (its secrets stay in `c2`).
        let mut c1 = Client::new(probe.device(0).map_err(|e| fail("device", e.to_string()))?);
        let mut c2 = Client::new(probe.device(1).map_err(|e| fail("device", e.to_string()))?);
        let kp = c2.create_key_package().map_err(crypto("key package"))?;
        let hash = b64(&<Sha256 as sha2::Digest>::digest(&kp));
        store::conformance::clear_key_packages(&self.state.db, &probe.user.id)
            .await
            .map_err(|e| fail("key package", e.to_string()))?;
        store::e2ee::insert_key_packages(&self.state.db, &probe.user.id, &probe.device_ids[1], &[(kp, hash)])
            .await
            .map_err(|e| fail("key package", e.to_string()))?;

        let gi = c1.create_group(&q).map_err(crypto("create group"))?;
        let path = format!("/api/v1/conversations/{conv}/mls/group");
        ok(
            "create group",
            self.call_json(Method::POST, &path, Some(s1), json!({ "group_info": b64(&gi) })).await,
            201,
        )?;

        let path = format!("/api/v1/users/{}/key-packages/claim", probe.address());
        let r = ok("claim", self.call_json(Method::POST, &path, Some(s1), json!({})).await, 200)?;
        let kps: Vec<Vec<u8>> = json_of(&r)["key_packages"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|k| unb64(&k["key_package"]))
            .collect();
        if kps.is_empty() {
            return Err(fail("claim", "no KeyPackage".into()));
        }
        let out = c1.add_members(&q, &kps).map_err(crypto("add"))?;
        self.commit("add", s1, conv, &out).await?;
        c1.merge_pending_commit(&q).map_err(crypto("add"))?;

        let token =
            probe_token(self.state, probe, 1, self.domain).await.map_err(|e| fail("second device", e.to_string()))?;
        let r = ok("second device", self.login(&token).await, 200)?;
        let s2 = json_of(&r)["access_token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| fail("second device", "no session".into()))?;

        let r = ok("welcome", self.call(Method::GET, "/api/v1/mls/welcomes", Some(&s2), None).await, 200)?;
        let welcomes = json_of(&r)["items"].as_array().cloned().unwrap_or_default();
        let welcome = welcomes
            .iter()
            .find(|w| w["conversation_id"].as_str() == Some(conv))
            .ok_or_else(|| fail("welcome", "missing".into()))?;
        c2.join_by_welcome(&unb64(&welcome["welcome"]).unwrap_or_default()).map_err(crypto("welcome"))?;
        if let Some(id) = welcome["id"].as_str() {
            let _ = self.call(Method::DELETE, &format!("/api/v1/mls/welcomes/{id}"), Some(&s2), None).await;
        }

        let path = format!("/api/v1/conversations/{conv}/mls/group-info");
        let r = ok("external rejoin", self.call(Method::GET, &path, Some(&s2), None).await, 200)?;
        let gi = unb64(&json_of(&r)["group_info"]).ok_or_else(|| fail("external rejoin", "no group info".into()))?;
        let out = c2.join_by_external_commit(&q, &gi).map_err(crypto("external rejoin"))?;
        self.commit("external rejoin", &s2, conv, &out).await?;
        c2.merge_pending_commit(&q).map_err(crypto("external rejoin"))?;

        let since = c1.current_epoch(&q).map_err(crypto("catch up"))?;
        let path = format!("/api/v1/conversations/{conv}/mls/messages?since_epoch={since}");
        let r = ok("catch up", self.call(Method::GET, &path, Some(s1), None).await, 200)?;
        for item in json_of(&r)["items"].as_array().cloned().unwrap_or_default() {
            let commit = unb64(&item["commit"]).ok_or_else(|| fail("catch up", "malformed log".into()))?;
            c1.process_handshake(&q, &commit).map_err(crypto("catch up"))?;
        }

        // A commit of this epoch that is never sent: after the next commit it is stale.
        let stale = c1.self_update(&q).map_err(crypto("self update"))?;
        c1.discard_pending_commit(&q).map_err(crypto("self update"))?;
        let accepted = c1.self_update(&q).map_err(crypto("self update"))?;
        self.commit("self update", s1, conv, &accepted).await?;
        c1.merge_pending_commit(&q).map_err(crypto("self update"))?;

        let content = c1
            .encrypt_content(&q, &json!({ "type": "text", "body": "conformance" }).to_string())
            .map_err(crypto("message"))?;
        let epoch = c1.current_epoch(&q).map_err(crypto("message"))?;
        let path = format!("/api/v1/conversations/{conv}/messages");
        ok(
            "message",
            self.call_json(Method::POST, &path, Some(s1), json!({ "content": content, "epoch": epoch })).await,
            201,
        )?;
        Ok((c1, stale, accepted))
    }

    async fn commit(&mut self, step: &str, session: &str, conv: &str, out: &CommitOutput) -> Result<(), String> {
        let path = format!("/api/v1/conversations/{conv}/mls/commits");
        let body = json!({
            "epoch": out.epoch,
            "commit": b64(&out.commit),
            "group_info": b64(&out.group_info),
            "welcome": out.welcome.as_ref().map(|w| b64(w)),
        });
        match self.call_json(Method::POST, &path, Some(session), body).await {
            Ok(r) if r.status == 201 => Ok(()),
            Ok(r) => Err(format!("{step}: {}", describe(&r))),
            Err(e) => Err(format!("{step}: {e}")),
        }
    }

    /// `mls.reject`: a commit of an older epoch, the replay of an accepted commit and a commit whose
    /// signature does not cover its content must all be refused.
    async fn mls_reject(
        &mut self,
        s1: &str,
        room: &PeerRoom,
        mut c1: Client,
        stale: &CommitOutput,
        accepted: &CommitOutput,
    ) {
        let conv = &room.conversation_id;
        let q = format!("{}/{conv}", self.domain);
        let epoch = c1.current_epoch(&q).unwrap_or(stale.epoch + 1);
        let path = format!("/api/v1/conversations/{conv}/mls/commits");
        let post = |commit: &[u8], gi: &[u8]| json!({ "epoch": epoch, "commit": b64(commit), "group_info": b64(gi), "welcome": null });
        let mut cases = vec![
            ("stale epoch", post(&stale.commit, &stale.group_info)),
            ("replay", post(&accepted.commit, &accepted.group_info)),
        ];
        if let Ok(fresh) = c1.self_update(&q) {
            cases.push(("invalid signature", post(&tamper(&fresh.commit), &fresh.group_info)));
        }
        let _ = c1.discard_pending_commit(&q);
        let mut outcome = (Outcome::Pass, None);
        for (case, body) in cases {
            let r = self.call_json(Method::POST, &path, Some(s1), body).await;
            let (o, d) = must_refuse(&r);
            if o == Outcome::Fail || (o == Outcome::Warn && outcome.0 == Outcome::Pass) {
                outcome = (o, d.map(|d| format!("{case}: {d}")));
            }
        }
        self.push("mls.reject", true, outcome);
    }

    /// `s2s.unsigned`, `s2s.body_hash`, `s2s.replay` against the peer's inbox.
    async fn s2s(&mut self) {
        let (state, domain) = (self.state, self.domain);
        let envelope = || {
            json!({
                "id": util::ulid(), "type": PROBE_KIND, "from": state.config.domain, "to": domain,
                "at": util::now(), "payload": {}
            })
            .to_string()
            .into_bytes()
        };
        let r = self.call(Method::POST, INBOX_PATH, None, Some(envelope())).await;
        self.push("s2s.unsigned", true, must_refuse(&r));

        let body = envelope();
        match tokens::issue_node_token(self.state, self.domain, "POST", INBOX_PATH, &envelope()) {
            Ok(token) => {
                let r = self.call(Method::POST, INBOX_PATH, Some(&token), Some(body)).await;
                self.push("s2s.body_hash", true, must_refuse(&r));
            }
            Err(_) => self.warn("s2s.body_hash", true, "signing failed"),
        }

        let body = envelope();
        let Ok(token) = tokens::issue_node_token(self.state, self.domain, "POST", INBOX_PATH, &body) else {
            self.warn("s2s.replay", true, "signing failed");
            return;
        };
        match self.call(Method::POST, INBOX_PATH, Some(&token), Some(body.clone())).await {
            Ok(r) if (200..300).contains(&r.status) => {
                let r = self.call(Method::POST, INBOX_PATH, Some(&token), Some(body)).await;
                self.push("s2s.replay", true, must_refuse(&r));
            }
            Ok(r) => self.warn("s2s.replay", true, format!("a valid message was refused: {}", describe(&r))),
            Err(e) => self.warn("s2s.replay", true, e),
        }
    }

    fn time_skew(&mut self) {
        let Some(date) = self.date.clone() else {
            self.warn("time.skew", false, "no Date header");
            return;
        };
        match chrono::DateTime::parse_from_rfc2822(&date) {
            Ok(t) if (t.timestamp() - Utc::now().timestamp()).abs() <= MAX_SKEW_SECS => self.pass("time.skew", false),
            Ok(t) => {
                self.warn("time.skew", false, format!("clock off by {} s", t.timestamp() - Utc::now().timestamp()))
            }
            Err(_) => self.warn("time.skew", false, "malformed Date header"),
        }
    }

    /// `rate.limits`: published `federated_logins_per_minute + 5` invalid logins must produce a `429`
    /// with `Retry-After`. Runs last: it uses up this node's login allowance on the peer for a minute.
    async fn rate_limits(&mut self) {
        let limit = self
            .doc
            .as_ref()
            .and_then(|d| d.pointer("/federation/limits/federated_logins_per_minute"))
            .and_then(Value::as_u64)
            .unwrap_or(60);
        if limit + 5 > RATE_PROBE_CAP {
            self.skip("rate.limits", false, format!("published limit {limit}/min is above what the check sends"));
            return;
        }
        let key = crate::keys::NodeKey::generate(&self.state.signing_key().kid);
        for _ in 0..limit + 5 {
            let now = jwt::now_unix();
            let claims = StandardClaims {
                iss: self.state.config.domain.clone(),
                sub: format!("{PROBE_USERNAME}@{}", self.state.config.domain),
                aud: self.domain.to_string(),
                exp: now + 60,
                iat: now,
                jti: util::ulid(),
                typ: "federation".into(),
            };
            let token = jwt::sign(&key.signing, &key.kid, &claims).unwrap_or_default();
            match self.login(&token).await {
                Ok(r) if r.status == 429 => {
                    if r.retry_after.is_some() {
                        self.pass("rate.limits", false);
                    } else {
                        self.warn("rate.limits", false, "429 without Retry-After");
                    }
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    self.warn("rate.limits", false, e);
                    return;
                }
            }
        }
        self.warn("rate.limits", false, format!("no 429 after {} invalid logins in a minute", limit + 5));
    }
}

// ---------------------------------------------------------------- doctor

/// The result table printed by `tavrn-node doctor --peer <domain>`.
pub fn format_table(domain: &str, record: &Record) -> String {
    let mut out = format!(
        "Conformance check of {domain}: {} ({} ms{})\n\n",
        record.result.to_uppercase(),
        record.duration_ms,
        record.software.as_deref().map(|s| format!(", {s}")).unwrap_or_default()
    );
    out.push_str(&format!("{:<22} {:<5} {:<5} {}\n", "CHECK", "KIND", "RESULT", "DETAIL"));
    for c in &record.checks {
        let result = serde_json::to_value(c.result).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        out.push_str(&format!(
            "{:<22} {:<5} {:<6} {}\n",
            c.id,
            if c.hard { "hard" } else { "soft" },
            result,
            c.detail.as_deref().unwrap_or("")
        ));
    }
    out
}

/// `doctor --peer`: a forced run whose result is stored like an admin's. Returns the report and the
/// exit code (0 pass or warn, 1 fail, 2 the check could not run).
pub async fn doctor(state: &AppState, domain: &str) -> (String, i32) {
    match run(state, domain, true).await {
        Ok(record) => {
            let code = i32::from(record.result == "fail");
            (format_table(domain, &record), code)
        }
        Err(e) => (format!("The conformance check of {domain} could not run: {} ({})\n", e, e.code()), 2),
    }
}

// ---------------------------------------------------------------- conformance rooms (the checked node)

#[derive(Debug, Serialize, ToSchema)]
pub struct ConformanceRoom {
    pub room_id: String,
    /// The encrypted text channel.
    pub channel_id: String,
    /// Conversation of the encrypted text channel (MLS group).
    pub conversation_id: String,
    /// An unencrypted text channel (the `msg.ciphertext` check).
    pub plaintext_channel_id: String,
    pub expires_at: String,
}

fn probe_only() -> ApiError {
    ApiError::Forbidden {
        code: "conformance.probe_only",
        detail: "Only the conformance probe of another node may use this route".into(),
    }
}

fn room_not_found() -> ApiError {
    ApiError::NotFound { code: "conformance.room_not_found", what: "Conformance room".into() }
}

/// `POST /federation/conformance/room` for the probe of another node: a throwaway, non-discoverable room
/// owned by the probe, with an encrypted and an unencrypted text channel, created regardless of
/// `TAVRN_ROOM_CREATION` and deleted after 15 minutes. One at a time per checking domain (an older one
/// is deleted), at most 4 per day.
pub async fn create_room(state: &AppState, user: &UserRow) -> Result<ConformanceRoom, ApiError> {
    if user.domain == state.config.domain || user.username != PROBE_USERNAME {
        return Err(probe_only());
    }
    let domain = user.domain.clone();
    let max = if state.config.dev { 1000 } else { ROOMS_PER_DAY };
    let since = util::format_time(Utc::now() - chrono::Duration::days(1));
    if store::conformance::rooms_created_since(&state.db, &domain, &since).await? >= max {
        return Err(ApiError::RateLimited { retry_after_secs: 3600 });
    }
    for old in store::conformance::live_rooms(&state.db, &domain).await? {
        delete_room(state, &old).await?;
    }
    let room = store::rooms::create_room(
        &state.db,
        store::rooms::NewRoom { name: "conformance check", description: "", join_mode: "invite", owner_id: &user.id },
    )
    .await?;
    let channel_id = store::conformance::text_channel(&state.db, &room.id)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("conformance room without text channel")))?;
    let now = Utc::now();
    let expires_at = util::format_time(now + chrono::Duration::seconds(ROOM_LIFETIME_SECS));
    let category = store::conformance::category_of(&state.db, &channel_id).await?;
    let added = store::conformance::add_room(
        &state.db,
        &room.id,
        category.as_deref(),
        &domain,
        &util::format_time(now),
        &expires_at,
    )
    .await?;
    tracing::info!(domain, room = room.id, "conformance room created");
    Ok(ConformanceRoom {
        room_id: room.id,
        conversation_id: channel_id.clone(),
        channel_id,
        plaintext_channel_id: added.plaintext_channel_id,
        expires_at,
    })
}

/// `DELETE /federation/conformance/room/{room_id}` by the probe that created it.
pub async fn delete_own_room(state: &AppState, user: &UserRow, room_id: &str) -> Result<(), ApiError> {
    if user.domain == state.config.domain || user.username != PROBE_USERNAME {
        return Err(probe_only());
    }
    match store::conformance::room_domain(&state.db, room_id).await? {
        Some(domain) if domain == user.domain => delete_room(state, room_id).await,
        _ => Err(room_not_found()),
    }
}

async fn delete_room(state: &AppState, room_id: &str) -> Result<(), ApiError> {
    state.hub.room(room_id, "room.delete", json!({ "id": room_id }));
    store::rooms::delete_room(&state.db, room_id).await?;
    store::conformance::mark_room_deleted(&state.db, room_id).await
}

/// Deletes expired conformance rooms and forgets old room records and violations. Returns the number of
/// rooms deleted.
pub async fn housekeeping(state: &AppState, now: chrono::DateTime<Utc>) -> Result<usize, ApiError> {
    let expired = store::conformance::expired_rooms(&state.db, &util::format_time(now)).await?;
    for room in &expired {
        delete_room(state, room).await?;
    }
    store::conformance::prune(
        &state.db,
        &util::format_time(now - chrono::Duration::days(1)),
        &util::format_time(now - chrono::Duration::days(VIOLATION_DAYS)),
    )
    .await?;
    Ok(expired.len())
}

/// The worker (started with the server): creates the probe account, then every minute deletes expired
/// conformance rooms and checks up to 4 peers that are due (first contact, then every 24 hours while
/// this node federates with them).
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut probe_ready = false;
        let mut tick = tokio::time::interval(WORKER_INTERVAL);
        loop {
            tick.tick().await;
            // Several instances: the leader checks peers and creates the probe account (`cache::leader`).
            if !state.cluster.is_leader() {
                continue;
            }
            if !probe_ready {
                match ensure_probe(&state).await {
                    Ok(_) => probe_ready = true,
                    Err(e) => tracing::error!(error = %e, "conformance probe account could not be created"),
                }
            }
            if let Err(e) = housekeeping(&state, Utc::now()).await {
                tracing::warn!(error = %e, "conformance housekeeping failed");
            }
            if !state.config.federation_enabled {
                continue;
            }
            let cutoff = util::format_time(Utc::now() - chrono::Duration::seconds(RECHECK_SECS));
            let due = match store::conformance::due_peers(&state.db, &cutoff, WORKER_BATCH).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, "conformance worker failed");
                    continue;
                }
            };
            for domain in due.into_iter().filter(|d| state.federation.check_policy(d).is_ok()) {
                if let Err(e) = run(&state, &domain, false).await {
                    tracing::info!(domain, result = e.code(), "conformance check not run");
                }
            }
        }
    })
}

/// Manual block or unblock by a node admin (`STATUS_BLOCKED` or back to `STATUS_OK`).
pub async fn set_manual_block(state: &AppState, domain: &str, block: bool, reason: &str) -> Result<bool, ApiError> {
    if block {
        let done = store::conformance::transition(
            &state.db,
            domain,
            &[STATUS_OK, STATUS_BLOCKED_AUTO, discovery::STATUS_KEY_CONFLICT],
            STATUS_BLOCKED,
            Some(reason),
        )
        .await?;
        if done {
            end_sessions(state, domain).await?;
        }
        Ok(done)
    } else {
        let previous = store::conformance::peer_state(&state.db, domain).await?.map(|p| p.status);
        let done = store::conformance::transition(
            &state.db,
            domain,
            &[STATUS_BLOCKED, STATUS_BLOCKED_AUTO, discovery::STATUS_KEY_CONFLICT],
            STATUS_OK,
            None,
        )
        .await?;
        if done && previous.as_deref() == Some(discovery::STATUS_KEY_CONFLICT) {
            store::conformance::forget_keys(&state.db, domain).await?;
        }
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn check(id: &str, result: Outcome, hard: bool) -> CheckResult {
        CheckResult { id: id.into(), result, hard, detail: None }
    }

    #[test]
    fn keys_must_be_the_same_on_every_address() {
        let set =
            |keys: &[(&str, &str)]| -> KeySet { keys.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect() };
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        assert_eq!(compare_address_keys(&[]), Ok(()));
        assert_eq!(compare_address_keys(&[(v4, set(&[("k1", "x1")]))]), Ok(()));
        let same = [(v4, set(&[("k1", "x1"), ("k2", "x2")])), (v6, set(&[("k2", "x2"), ("k1", "x1")]))];
        assert_eq!(compare_address_keys(&same), Ok(()));
        // Another key under the same kid on IPv6.
        let err = compare_address_keys(&[(v4, set(&[("k1", "x1")])), (v6, set(&[("k1", "evil")]))]).unwrap_err();
        assert!(err.contains("192.0.2.1 and 2001:db8::1") && err.contains("k1"), "{err}");
        // An extra key on one address is a split view too.
        let err = compare_address_keys(&[
            (v4, set(&[("k1", "x1")])),
            (other, set(&[("k1", "x1")])),
            (v6, set(&[("k1", "x1"), ("k9", "x9")])),
        ])
        .unwrap_err();
        assert!(err.contains("k9") && !err.contains("k1,"), "{err}");
    }

    #[test]
    fn overall_result() {
        assert_eq!(overall(&[]), "pass");
        assert_eq!(overall(&[check("a", Outcome::Pass, true), check("b", Outcome::Skip, false)]), "pass");
        assert_eq!(overall(&[check("a", Outcome::Pass, true), check("b", Outcome::Warn, false)]), "warn");
        assert_eq!(overall(&[check("a", Outcome::Warn, true), check("b", Outcome::Fail, true)]), "fail");
        assert_eq!(failed_ids(&[check("a", Outcome::Warn, true), check("b", Outcome::Fail, true)]), vec!["b"]);
    }

    fn response(status: u16) -> Result<ProbeResponse, String> {
        Ok(ProbeResponse { status, code: None, retry_after: None, date: None, body: Vec::new() })
    }

    #[test]
    fn refusals_are_classified() {
        assert_eq!(must_refuse(&response(200)).0, Outcome::Fail);
        assert_eq!(must_refuse(&response(202)).0, Outcome::Fail);
        for refused in [400, 401, 403, 404, 409] {
            assert_eq!(must_refuse(&response(refused)).0, Outcome::Pass, "{refused}");
        }
        for unclear in [408, 429, 500, 502, 503] {
            assert_eq!(must_refuse(&response(unclear)).0, Outcome::Warn, "{unclear}");
        }
        assert_eq!(must_refuse(&Err("timeout".into())).0, Outcome::Warn);
    }

    #[test]
    fn table_lists_every_check() {
        let record = Record {
            version: 1,
            result: "fail".into(),
            checked_at: util::now(),
            software: Some("tavrn-node/0.0.1".into()),
            duration_ms: 12,
            checks: vec![
                check("wk.fetch", Outcome::Pass, false),
                CheckResult {
                    id: "token.replay".into(),
                    result: Outcome::Fail,
                    hard: true,
                    detail: Some("accepted (200)".into()),
                },
            ],
            history: vec![],
        };
        let table = format_table("b.example", &record);
        assert!(table.starts_with("Conformance check of b.example: FAIL (12 ms, tavrn-node/0.0.1)"), "{table}");
        assert!(table.contains("wk.fetch"), "{table}");
        assert!(
            table.lines().any(|l| l.starts_with("token.replay")
                && l.contains("hard")
                && l.contains("fail")
                && l.contains("accepted (200)")),
            "{table}"
        );
    }

    /// The tampered commit of `mls.reject` is refused by a correct delivery service, the original is not.
    #[test]
    fn tampered_commit_is_refused_by_the_delivery_service() {
        let conv = "a.example/01J00000000000000000000000";
        let alice = Device::from_secret("alice@a.example", "01J00000000000000000000001", &[1u8; 32]).unwrap();
        let bob = Device::from_secret("bob@a.example", "01J00000000000000000000002", &[2u8; 32]).unwrap();
        let mut a = Client::new(alice);
        let b = Client::new(bob);
        let gi = a.create_group(conv).unwrap();
        let mut ds = tavrn_crypto::ds::DsGroup::create(conv, &gi).unwrap();
        let out = a.add_members(conv, &[b.create_key_package().unwrap()]).unwrap();
        assert!(ds.process_commit(&tamper(&out.commit), &out.group_info).is_err(), "tampered commit refused");
        assert!(ds.process_commit(&out.commit, &out.group_info).is_ok(), "original accepted");
        assert!(ds.process_commit(&out.commit, &out.group_info).is_err(), "replay refused");
    }

    #[test]
    fn derived_secrets_are_stable_and_distinct() {
        let s = [7u8; 32];
        assert_eq!(derive(&s, "x").unwrap(), derive(&s, "x").unwrap());
        assert_ne!(derive(&s, "x").unwrap(), derive(&s, "y").unwrap());
        assert_ne!(derive(&s, "x").unwrap(), derive(&[8u8; 32], "x").unwrap());
    }
}
