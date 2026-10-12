// SPDX-License-Identifier: AGPL-3.0-only
//! Forwarding reports about users of other nodes to their home node (protocol MODERATION.md §1.6, FEDERATION.md §5.2
//! `report.forward`, capability `reports.v2`).
//!
//! The admins of the node holding a report forward it once ([`forward`]): the node checks that the reported user's
//! home node announces `reports.v2` and queues `report.forward` in the federation outbox. The reporter stays
//! pseudonymous to the home node ([`pseudonym`]): the home node may be run by the reported user. The home node
//! ([`receive`]) checks the payload like a report, stores it in its admins' inbox with the origin, deduplicated per
//! origin report, within a budget per sending domain ([`admit_inbound`]). Nobody is told anything else.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::Sha256;

use super::{CATEGORIES, DETAIL_MAX, EVIDENCE_MAX_ATTACHMENTS, EVIDENCE_MAX_NAME, EVIDENCE_MAX_TEXT};
use super::{EvidenceEntry, MessageSnapshot, ModerationReport};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiError,
    models::UserRow,
    store::{
        self,
        reports::{NewOrigin, NewReport},
    },
    util,
    validate::{self, bad},
};

/// Announced while federation is enabled.
pub const CAPABILITY: &str = "reports.v2";
/// The inbox type: from the forwarding node's domain to the reported user.
pub const KIND: &str = "report.forward";
const PSEUDONYM_PREFIX: &str = "anon-";
/// Room for the envelope (id, type, from, to, at) around the payload within the inbox limit.
const ENVELOPE_RESERVE: usize = 1024;

/// A pseudonym of the forwarded format: 1–64 characters of `[A-Za-z0-9_-]` (never an address).
pub fn is_pseudonym(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The pseudonym of `address` towards `receiver`: a keyed hash with this node's secret, stable per address and
/// receiving node (the home node can tell repeated reports of one person from reports of many) and unlinkable between
/// receiving nodes.
pub fn pseudonym(state: &AppState, receiver: &str, address: &str) -> String {
    let mut out = [0u8; 16];
    let info = format!("tavrn report pseudonym v1\n{receiver}\n{}", address.to_lowercase());
    // 16 bytes are far below HKDF-SHA256's output limit: expanding cannot fail.
    let _ = hkdf::Hkdf::<Sha256>::new(None, &state.secret_key[..]).expand(info.as_bytes(), &mut out);
    format!("{PSEUDONYM_PREFIX}{}", tavrn_crypto::util::b64url_encode(&out))
}

fn forward_invalid() -> ApiError {
    bad("report.forward_invalid", "Only reports by users about a user can be forwarded")
}

/// The payload of `report.forward` for `report` (MODERATION.md §1.6): the reporter and every author other than the
/// reported user replaced by `pseudo`, their device ids left out; the oldest context entries of the evidence left out
/// while the message would exceed the inbox limit (never the reported message).
pub fn payload(report: &ModerationReport, reporter: &str, pseudo: impl Fn(&str) -> String) -> Value {
    let target = report.target_address.as_str();
    let mut evidence: Option<Vec<EvidenceEntry>> = report.evidence.clone().map(|entries| {
        entries
            .into_iter()
            .map(|mut e| {
                if !e.author.eq_ignore_ascii_case(target) {
                    e.author = pseudo(&e.author);
                    e.device_id = None;
                }
                e
            })
            .collect()
    });
    let snapshot: Option<MessageSnapshot> = report.snapshot.clone().map(|mut s| {
        if !s.author.eq_ignore_ascii_case(target) {
            s.author = pseudo(&s.author);
        }
        s
    });
    let reporter = pseudo(reporter);
    loop {
        let mut p = Map::new();
        p.insert("report_id".into(), json!(report.id));
        p.insert("kind".into(), json!(report.kind));
        p.insert("category".into(), json!(report.category));
        p.insert("detail".into(), json!(report.detail));
        p.insert("created_at".into(), json!(report.created_at));
        p.insert("reporter".into(), json!(reporter));
        if let Some(m) = &report.message_id {
            p.insert("message_id".into(), json!(m));
        }
        if let Some(s) = &snapshot {
            p.insert("snapshot".into(), json!(s));
        }
        if let Some(e) = &evidence {
            p.insert("evidence".into(), json!(e));
        }
        let p = Value::Object(p);
        let size = serde_json::to_vec(&p).map_or(usize::MAX, |b| b.len()) + ENVELOPE_RESERVE;
        if size <= crate::federation::inbox::MAX_BODY_BYTES {
            return p;
        }
        let Some(entries) = evidence.as_mut() else { return p };
        let reported = report.message_id.as_deref();
        let oldest = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.message_id.as_deref().zip(reported).is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)))
            .min_by_key(|(_, e)| util::parse_time(&e.created_at))
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                entries.remove(i);
            }
            None => return p,
        }
    }
}

/// `POST /reports/{id}/forward` (MODERATION.md §1.6): node admins, reports by users about a user of another node whose
/// home node announces `reports.v2`; idempotent.
pub async fn forward(state: &AppState, auth: &AuthUser, id: &str) -> Result<ModerationReport, ApiError> {
    super::require_admin(auth)?;
    let row = super::visible(state, &auth.user, id).await?;
    if row.source != "user" || !matches!(row.kind.as_str(), "message" | "user") || row.reporter_id.is_none() {
        return Err(forward_invalid());
    }
    if row.forwarded_to.is_some() {
        return super::one(state, row, true).await;
    }
    let home = util::parse_address(&row.target_address).map(|(_, d)| d.to_string()).ok_or_else(forward_invalid)?;
    if home == state.config.domain {
        return Err(ApiError::conflict("report.target_local", "The reported user is a user of this node"));
    }
    if !state.config.federation_enabled {
        return Err(crate::federation::disabled());
    }
    let doc = crate::federation::discovery::document(state, &home).await?;
    if !doc.capabilities.iter().any(|c| c == CAPABILITY) {
        return Err(ApiError::conflict(
            "report.forward_unsupported",
            format!("{home} does not accept forwarded reports ({CAPABILITY})"),
        ));
    }
    let report = super::one(state, row.clone(), true).await?;
    let reporter = report.reporter.as_ref().map(|u| u.address.clone()).ok_or_else(forward_invalid)?;
    let payload = payload(&report, &reporter, |a| pseudonym(state, &home, a));
    let now = util::now();
    let by = auth.user.address();
    if store::reports::mark_forwarded(&state.db, &row.id, &home, &by, &now).await? {
        let queued =
            crate::federation::outbox::enqueue(state, &home, KIND, &state.config.domain, &row.target_address, payload)
                .await;
        if let Err(e) = queued {
            store::reports::clear_forwarded(&state.db, &row.id).await?;
            return Err(e);
        }
        store::rooms::audit(
            &state.db,
            None,
            Some(&auth.user.id),
            "report.forward",
            &row.id,
            "",
            json!({ "node": home, "scope": row.scope }),
        )
        .await?;
        tracing::info!(report = row.id, node = home, "report forwarded to the reported user's home node");
    }
    let row = store::reports::by_id(&state.db, &row.id).await?.ok_or_else(super::not_found)?;
    super::changed(state, &row, &row.status).await;
    super::one(state, row, true).await
}

// ---------------------------------------------------------------- receiving

/// A checked `report.forward` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub report_id: String,
    pub kind: String,
    pub category: String,
    pub detail: String,
    pub created_at: String,
    pub reporter: String,
    pub message_id: Option<String>,
    /// JSON of the snapshot.
    pub snapshot: Option<String>,
    /// JSON of the evidence.
    pub evidence: Option<String>,
}

#[derive(Deserialize)]
struct Payload {
    report_id: String,
    kind: String,
    category: String,
    #[serde(default)]
    detail: String,
    created_at: String,
    reporter: String,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    snapshot: Option<MessageSnapshot>,
    #[serde(default)]
    evidence: Option<Vec<EvidenceEntry>>,
}

fn invalid(detail: impl Into<String>) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

/// Checks a `report.forward` payload like a report (MODERATION.md §1.6): `400 federation.envelope_invalid`.
pub fn parse(payload: &Value) -> Result<Incoming, ApiError> {
    let p: Payload =
        serde_json::from_value(payload.clone()).map_err(|_| invalid("report.forward: malformed payload"))?;
    if !util::is_ulid(&p.report_id) {
        return Err(invalid("report.forward: report_id"));
    }
    if !matches!(p.kind.as_str(), "message" | "user") {
        return Err(invalid("report.forward: kind is message or user"));
    }
    if !CATEGORIES.contains(&p.category.as_str()) {
        return Err(invalid("report.forward: category"));
    }
    let detail =
        validate::text("detail", &p.detail, 0, DETAIL_MAX).map_err(|e| invalid(format!("report.forward: {e}")))?;
    let created_at = util::parse_time(&p.created_at).ok_or_else(|| invalid("report.forward: created_at"))?;
    if !is_pseudonym(&p.reporter) {
        return Err(invalid("report.forward: reporter is a pseudonym"));
    }
    let message_id = match (p.kind.as_str(), p.message_id.as_deref()) {
        ("message", Some(m)) if util::is_ulid(m) => Some(m.to_ascii_uppercase()),
        ("message", _) => return Err(invalid("report.forward: message_id")),
        (_, None) if p.snapshot.is_none() && p.evidence.is_none() => None,
        _ => return Err(invalid("report.forward: user reports carry no message")),
    };
    if p.snapshot.is_some() && p.evidence.is_some() {
        return Err(invalid("report.forward: a snapshot or evidence, not both"));
    }
    let snapshot = match &p.snapshot {
        None => None,
        Some(s) => {
            let author_ok = util::parse_address(&s.author.to_lowercase()).is_some() || is_pseudonym(&s.author);
            if !author_ok
                || util::parse_time(&s.created_at).is_none()
                || s.text.chars().count() > EVIDENCE_MAX_TEXT
                || s.attachments.len() > EVIDENCE_MAX_ATTACHMENTS
                || s.attachments.iter().any(|a| a.is_empty() || a.chars().count() > EVIDENCE_MAX_NAME)
            {
                return Err(invalid("report.forward: snapshot"));
            }
            Some(serde_json::to_string(s).map_err(|e| ApiError::Internal(e.into()))?)
        }
    };
    let evidence = match (&p.evidence, &message_id) {
        (Some(entries), Some(m)) => Some(
            super::check_evidence(entries, m, true).map_err(|e| invalid(format!("report.forward: evidence: {e}")))?,
        ),
        _ => None,
    };
    Ok(Incoming {
        report_id: p.report_id.to_ascii_uppercase(),
        kind: p.kind,
        category: p.category,
        detail,
        created_at: util::format_time(created_at),
        reporter: p.reporter,
        message_id,
        snapshot,
        evidence,
    })
}

/// Admission of a `report.forward` from `iss`, before the message counts as received (so a refused one comes again
/// with the sender's retry): at most `TAVRN_REPORTS_INBOUND_PER_HOUR` per sending registrable domain (subdomains share
/// it) and five times as many from all domains per hour (`429`).
pub async fn admit_inbound(state: &AppState, iss: &str) -> Result<(), ApiError> {
    state.reports_inbound_limiter.check_all(&[store::federation::parent_domain(iss).to_string()]).await?;
    state.reports_inbound_total_limiter.check_all(&["all".to_string()]).await
}

/// Stores a forwarded report about the local user `user` in the node admins' inbox (idempotent per origin report).
pub async fn receive(
    state: &AppState,
    iss: &str,
    user: &UserRow,
    incoming: Incoming,
) -> Result<&'static str, ApiError> {
    if store::reports::by_origin(&state.db, iss, &incoming.report_id).await?.is_some() {
        return Ok("duplicate");
    }
    let id = util::ulid();
    let now = util::now();
    let address = user.address();
    store::reports::insert_with_origin(
        &state.db,
        &NewReport {
            id: &id,
            source: "forward",
            scope: "node",
            kind: &incoming.kind,
            reporter_id: None,
            room_id: None,
            conversation_id: None,
            // The content lives on the origin: content actions are not offered here.
            node: Some(iss),
            message_id: incoming.message_id.as_deref(),
            target_user_id: Some(&user.id),
            target_address: &address,
            category: &incoming.category,
            detail: &incoming.detail,
            snapshot: incoming.snapshot.as_deref(),
            evidence: incoming.evidence.as_deref(),
            created_at: &now,
        },
        Some(&NewOrigin {
            node: iss,
            report_id: &incoming.report_id,
            reporter: &incoming.reporter,
            reported_at: &incoming.created_at,
        }),
    )
    .await?;
    store::rooms::audit(
        &state.db,
        None,
        None,
        "report.forwarded_in",
        &id,
        "",
        json!({ "origin": iss, "origin_report_id": incoming.report_id }),
    )
    .await?;
    if let Some(row) = store::reports::by_id(&state.db, &id).await? {
        super::announce(state, &row).await;
    }
    tracing::info!(report = id, origin = iss, "forwarded report received");
    Ok("handled")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const REPORTED: &str = "01J00000000000000000000001";

    fn entry(id: &str, author: &str, minute: u32, text: &str) -> EvidenceEntry {
        EvidenceEntry {
            message_id: Some(id.into()),
            author: author.into(),
            device_id: Some("dev".into()),
            created_at: format!("2026-10-01T10:{minute:02}:00Z"),
            text: text.into(),
            attachments: vec![],
        }
    }

    fn report(evidence: Option<Vec<EvidenceEntry>>) -> ModerationReport {
        ModerationReport {
            id: "01J00000000000000000000009".into(),
            source: "user".into(),
            scope: "room".into(),
            kind: "message".into(),
            room_id: Some("01J0000000000000000000ROOM".into()),
            room_name: Some("Secret room".into()),
            conversation_id: Some("01J0000000000000000000CONV".into()),
            conversation_kind: Some("channel".into()),
            node: None,
            message_id: Some(REPORTED.into()),
            message_exists: true,
            target: None,
            target_address: "mallory@b.example".into(),
            reporter: None,
            category: "harassment".into(),
            detail: "threat".into(),
            snapshot: None,
            evidence_count: evidence.as_ref().map_or(0, Vec::len),
            evidence,
            evidence_source: Some("reporter".into()),
            status: "open".into(),
            assignee: None,
            note: "internal note".into(),
            actions: vec![],
            forwarded: None,
            origin: None,
            created_at: "2026-10-01T11:00:00Z".into(),
            updated_at: "2026-10-01T11:00:00Z".into(),
            resolved_at: None,
        }
    }

    fn pseudo(a: &str) -> String {
        format!("anon-{}", a.split('@').next().unwrap())
    }

    #[test]
    fn the_payload_names_no_one_but_the_reported_user() {
        let r = report(Some(vec![
            entry("01J00000000000000000000002", "alice@a.example", 1, "hi"),
            entry("01J00000000000000000000003", "dave@c.example", 2, "hello"),
            entry(REPORTED, "Mallory@b.example", 3, "I know where you live"),
        ]));
        let p = payload(&r, "alice@a.example", pseudo);
        assert_eq!(p["reporter"], "anon-alice");
        assert_eq!(p["evidence"][0]["author"], "anon-alice", "the reporter's own entries carry the pseudonym");
        assert_eq!(p["evidence"][0]["device_id"], Value::Null);
        assert_eq!(p["evidence"][1]["author"], "anon-dave");
        assert_eq!(p["evidence"][2]["author"], "Mallory@b.example");
        assert_eq!(p["evidence"][2]["device_id"], "dev", "the reported user's entries keep their device");
        assert_eq!((p["report_id"].as_str(), p["message_id"].as_str()), (Some(r.id.as_str()), Some(REPORTED)));
        let text = p.to_string();
        for private in ["alice@", "dave@", "Secret room", "ROOM", "CONV", "internal note"] {
            assert!(!text.contains(private), "{private} in {text}");
        }
        // The payload passes the receiver's checks.
        let parsed = parse(&p).unwrap();
        assert_eq!(parsed.message_id.as_deref(), Some(REPORTED));
        assert_eq!(parsed.reporter, "anon-alice");
    }

    #[test]
    fn oversized_evidence_loses_its_oldest_context_first() {
        let big = "é".repeat(EVIDENCE_MAX_TEXT);
        let id = |i: u32| format!("01J0000000000000000000010{i}");
        let mut entries: Vec<EvidenceEntry> = (0..10).map(|i| entry(&id(i), "alice@a.example", i, &big)).collect();
        entries.push(entry(REPORTED, "mallory@b.example", 30, &big));
        let mut r = report(Some(entries));
        r.detail = "x".repeat(DETAIL_MAX);
        let p = payload(&r, "alice@a.example", pseudo);
        let size = serde_json::to_vec(&p).unwrap().len() + ENVELOPE_RESERVE;
        assert!(size <= crate::federation::inbox::MAX_BODY_BYTES, "{size}");
        let kept: Vec<&str> =
            p["evidence"].as_array().unwrap().iter().map(|e| e["message_id"].as_str().unwrap()).collect();
        assert!(kept.contains(&REPORTED), "the reported message stays");
        assert!(!kept.contains(&id(0).as_str()), "the oldest went first: {kept:?}");
        assert!(kept.contains(&id(9).as_str()), "the newest context stays: {kept:?}");
        assert!(parse(&p).is_ok());
    }

    #[test]
    fn pseudonyms_have_their_own_format() {
        assert!(is_pseudonym("anon-AbC_12-x"));
        for not in ["", "alice@a.example", "a b", "ä", &"x".repeat(65)] {
            assert!(!is_pseudonym(not), "{not}");
        }
    }

    #[test]
    fn incoming_payloads_are_checked() {
        let ok = json!({ "report_id": REPORTED.to_lowercase(), "kind": "user", "category": "spam", "detail": "  x  ",
                         "created_at": "2026-10-01T10:00:00Z", "reporter": "anon-1", "unknown": true });
        let parsed = parse(&ok).unwrap();
        assert_eq!((parsed.report_id.as_str(), parsed.detail.as_str()), (REPORTED, "x"));
        let code = |f: &dyn Fn(&mut Value)| {
            let mut p = ok.clone();
            f(&mut p);
            parse(&p).map(|_| ()).map_err(|e| e.code().to_string())
        };
        let bad = Err("federation.envelope_invalid".to_string());
        assert_eq!(code(&|p| p["report_id"] = json!("nope")), bad);
        assert_eq!(code(&|p| p["kind"] = json!("room")), bad);
        assert_eq!(code(&|p| p["category"] = json!("rude")), bad);
        assert_eq!(code(&|p| p["detail"] = json!("x".repeat(DETAIL_MAX + 1))), bad);
        assert_eq!(code(&|p| p["created_at"] = json!("yesterday")), bad);
        assert_eq!(code(&|p| p["reporter"] = json!("alice@a.example")), bad);
        assert_eq!(code(&|p| p["message_id"] = json!(REPORTED)), bad, "user reports carry no message");
        assert_eq!(code(&|p| p["kind"] = json!("message")), bad, "message reports name it");
        let snapshot = json!({ "author": "mallory@b.example", "created_at": "2026-10-01T10:00:00Z", "text": "t",
                               "attachments": ["a.png"] });
        let message = |p: &mut Value| {
            p["kind"] = json!("message");
            p["message_id"] = json!(REPORTED);
        };
        assert_eq!(
            code(&|p| {
                message(p);
                p["snapshot"] = snapshot.clone();
            }),
            Ok(())
        );
        assert_eq!(
            code(&|p| {
                message(p);
                p["snapshot"] =
                    json!({ "author": "x y", "created_at": "2026-10-01T10:00:00Z", "text": "", "attachments": [] });
            }),
            bad
        );
        assert_eq!(
            code(&|p| {
                message(p);
                p["snapshot"] = snapshot.clone();
                p["evidence"] = json!([entry(REPORTED, "mallory@b.example", 0, "t")]);
            }),
            bad,
            "not both"
        );
        assert_eq!(
            code(&|p| {
                message(p);
                p["evidence"] = json!([entry("01J00000000000000000000002", "anon-1", 0, "t")]);
            }),
            bad,
            "the reported message is part of the evidence"
        );
    }
}
