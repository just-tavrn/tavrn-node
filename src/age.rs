// SPDX-License-Identifier: AGPL-3.0-only
//! Date of birth, the private age status and the age gates of rooms and channels (protocol PROTOCOL.md §5e,
//! capability `age.v1`; the federated claim of FEDERATION.md §2.2).
//!
//! The date of birth is self-declared and stays on the home node. The status (`adult`, `minor`, `unknown`) is derived
//! from it on every use, so nobody has to store a birthday transition; `unknown` counts as `minor` everywhere. Remote
//! users carry the `age_over_18` claim of their home node's latest federation token instead.

use chrono::{Datelike, NaiveDate, Utc};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{app::AppState, error::ApiError, models::UserRow, store};

pub const CAPABILITY: &str = "age.v1";
/// Age from which a user counts as an adult for the gates.
pub const ADULT_AGE: i32 = 18;
pub const GATE_NONE: &str = "none";
pub const GATE_ADULTS: &str = "adults_only";
/// The gates this node enforces (`age.gates` of `GET /node`).
pub const GATES: &[&str] = &[GATE_ADULTS];
/// Earliest plausible date of birth.
const EARLIEST: (i32, u32, u32) = (1900, 1, 1);

/// Today's date in UTC (the node's clock for ages).
pub fn today() -> NaiveDate {
    Utc::now().date_naive()
}

/// Whole years between `dob` and `today`: `n` from the `n`th birthday on; a birthday on 29 February counts on
/// 1 March in common years.
pub fn age_on(dob: NaiveDate, today: NaiveDate) -> i32 {
    let mut years = today.year() - dob.year();
    if (today.month(), today.day()) < (dob.month(), dob.day()) {
        years -= 1;
    }
    years
}

fn invalid_date() -> ApiError {
    ApiError::BadRequest {
        code: "validation.date_of_birth",
        detail: "date_of_birth: a date YYYY-MM-DD between 1900-01-01 and today".into(),
    }
}

/// A date of birth as sent by a client: exactly `YYYY-MM-DD`, a real calendar date, not before 1900-01-01 and not
/// after `today` (`400 validation.date_of_birth`).
pub fn parse(raw: &str, today: NaiveDate) -> Result<NaiveDate, ApiError> {
    let bytes = raw.as_bytes();
    let shape = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes.iter().enumerate().all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !shape {
        return Err(invalid_date());
    }
    let date = NaiveDate::parse_from_str(raw, "%Y-%m-%d").map_err(|_| invalid_date())?;
    let earliest = NaiveDate::from_ymd_opt(EARLIEST.0, EARLIEST.1, EARLIEST.2).ok_or_else(invalid_date)?;
    if date < earliest || date > today {
        return Err(invalid_date());
    }
    Ok(date)
}

/// `403 age.below_minimum` (naming the minimum) when someone born on `dob` is younger than `minimum` on `today`.
pub fn check_minimum(dob: NaiveDate, today: NaiveDate, minimum: u32) -> Result<(), ApiError> {
    let minimum = i32::try_from(minimum).unwrap_or(i32::MAX);
    if age_on(dob, today) >= minimum {
        return Ok(());
    }
    Err(ApiError::ForbiddenMeta {
        code: "age.below_minimum",
        detail: format!("You must be at least {minimum} years old to register on this node"),
        meta: serde_json::json!({ "minimum_age": minimum }),
    })
}

/// The derived age status (PROTOCOL.md §5e).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Unknown,
    Minor,
    Adult,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Unknown => "unknown",
            Tier::Minor => "minor",
            Tier::Adult => "adult",
        }
    }
}

/// The tier of a stored date of birth on `today` (an unreadable stored value counts as unknown).
pub fn tier(dob: Option<&str>, today: NaiveDate) -> Tier {
    match dob.and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()) {
        None => Tier::Unknown,
        Some(d) if age_on(d, today) >= ADULT_AGE => Tier::Adult,
        Some(_) => Tier::Minor,
    }
}

/// `age` of `GET /node` and `/.well-known/tavrn` (PROTOCOL.md §5e).
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct AgeInfo {
    /// The date of birth is the user's own statement (no verification).
    pub self_declared: bool,
    /// The room and channel gates this node enforces.
    pub gates: Vec<String>,
    /// Registration refuses younger people (`TAVRN_MINIMUM_AGE`).
    pub minimum_age: u32,
}

pub fn info(config: &crate::config::Config) -> AgeInfo {
    AgeInfo {
        self_declared: true,
        gates: GATES.iter().map(|g| (*g).to_string()).collect(),
        minimum_age: config.minimum_age,
    }
}

/// `age_status` of `GET /users/me` (the user's own account only).
#[derive(Debug, Clone, Serialize, ToSchema, PartialEq, Eq)]
pub struct AgeStatus {
    /// `adult` (18 or older), `minor` (younger) or `unknown` (no date of birth yet). `unknown` counts as `minor`.
    pub tier: String,
    /// `self` for a self-declared date of birth, `none` while the status is unknown.
    pub method: String,
}

pub fn status(user: &UserRow) -> AgeStatus {
    let tier = tier(user.date_of_birth.as_deref(), today());
    AgeStatus { tier: tier.as_str().into(), method: if tier == Tier::Unknown { "none".into() } else { "self".into() } }
}

/// `true` when the node's own user counts as an adult (local users only: the date of birth).
fn local_adult(user: &UserRow) -> bool {
    tier(user.date_of_birth.as_deref(), today()) == Tier::Adult
}

/// Does `user` pass an `adults_only` gate of this node? Local users by their date of birth, users of other nodes by
/// their home node's latest claim, bots by their owner (local owner's date of birth; remote bots carry their owner's
/// claim). Webhooks, deleted and unknown accounts never do.
pub async fn is_adult(state: &AppState, user: &UserRow) -> Result<bool, ApiError> {
    if user.deleted_at.is_some() {
        return Ok(false);
    }
    if user.domain != state.config.domain {
        return Ok(user.age_over_18 == Some(1));
    }
    match user.kind.as_str() {
        "user" => Ok(local_adult(user)),
        "bot" => match user.owner_id.as_deref() {
            Some(owner_id) => Ok(store::users::by_id(&state.db, owner_id)
                .await?
                .is_some_and(|owner| owner.deleted_at.is_none() && local_adult(&owner))),
            None => Ok(false),
        },
        _ => Ok(false),
    }
}

/// The `age_over_18` claim this node signs into a federation token for its own `user` (FEDERATION.md §2.2): `None`
/// = unknown. Bots carry their owner's value.
pub async fn claim(state: &AppState, user: &UserRow) -> Result<Option<bool>, ApiError> {
    let subject = match (user.kind.as_str(), user.owner_id.as_deref()) {
        ("bot", Some(owner_id)) => match store::users::by_id(&state.db, owner_id).await? {
            Some(owner) => owner,
            None => return Ok(None),
        },
        _ => user.clone(),
    };
    Ok(match tier(subject.date_of_birth.as_deref(), today()) {
        Tier::Unknown => None,
        Tier::Minor => Some(false),
        Tier::Adult => Some(true),
    })
}

// ---------------------------------------------------------------- gates

/// `400 validation.age_gate` unless `none` or `adults_only`.
pub fn validate_gate(value: &str) -> Result<String, ApiError> {
    match value {
        GATE_NONE | GATE_ADULTS => Ok(value.to_string()),
        _ => Err(ApiError::BadRequest { code: "validation.age_gate", detail: "age_gate: none or adults_only".into() }),
    }
}

/// The effective gate of a channel: the stricter of its own and its room's (the room's gate is the minimum).
pub fn effective(room_gate: &str, channel_gate: &str) -> &'static str {
    if room_gate == GATE_ADULTS || channel_gate == GATE_ADULTS { GATE_ADULTS } else { GATE_NONE }
}

/// `403 age.restricted`: the room or channel is for adults only. Names the gate, never the requester's status.
pub fn restricted(what: &str) -> ApiError {
    ApiError::ForbiddenMeta {
        code: "age.restricted",
        detail: format!("This {what} is for adults only"),
        meta: serde_json::json!({ "age_gate": GATE_ADULTS }),
    }
}

/// Only an adult switches a gate on (`403 age.restricted`), so nobody locks themselves out by accident.
pub async fn require_adult_to_gate(state: &AppState, actor: &UserRow, gate: &str, what: &str) -> Result<(), ApiError> {
    if gate == GATE_ADULTS && !is_adult(state, actor).await? {
        return Err(restricted(what));
    }
    Ok(())
}

/// Is the requester of a public route (optional `Authorization` header) an adult? Anonymous requests, invalid tokens
/// and everybody below 18 are not: Discover and the directory hide gated rooms from them (PROTOCOL.md §5e).
pub async fn requester_is_adult(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(token) = crate::auth::bearer(headers) else { return false };
    match crate::auth::authenticate(state, token).await {
        Ok(auth) => is_adult(state, &auth.user).await.unwrap_or(false),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------- accounts without a date of birth

/// Routes a local user without a date of birth may still call (PROTOCOL.md §5e): the own account, the date of
/// birth itself, sign-out, the terms and legal flow and the data rights with their re-authentication.
pub fn exempt_route(path: &str) -> bool {
    crate::legal::documents::exempt_route(path)
        || matches!(
            path,
            "/api/v1/users/me"
                | "/api/v1/users/me/date-of-birth"
                | "/api/v1/auth/logout"
                | "/api/v1/users/me/data"
                | "/api/v1/users/me/export"
                | "/api/v1/auth/reauth"
                | "/api/v1/auth/reauth/webauthn/start"
        )
}

pub fn status_required() -> ApiError {
    ApiError::Forbidden { code: "age.status_required", detail: "Add your date of birth to continue".into() }
}

/// `true` for a local person who still has to add the date of birth. Bots follow their owner, users of other nodes
/// their home node's claim; neither is ever asked.
pub fn needs_date_of_birth(state: &AppState, user: &UserRow) -> bool {
    user.domain == state.config.domain && user.kind == "user" && user.date_of_birth.is_none()
}

/// `403 age.status_required` for a local person without a date of birth, except on [`exempt_route`]s.
pub fn check_required(state: &AppState, user: &UserRow, path: Option<&str>) -> Result<(), ApiError> {
    if needs_date_of_birth(state, user) && !path.is_some_and(exempt_route) {
        return Err(status_required());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn ages_count_whole_years_from_the_birthday_on() {
        assert_eq!(age_on(d("2008-10-09"), d("2026-10-08")), 17);
        assert_eq!(age_on(d("2008-10-09"), d("2026-10-09")), 18);
        assert_eq!(age_on(d("2008-10-09"), d("2026-12-31")), 18);
        assert_eq!(age_on(d("2026-10-09"), d("2026-10-09")), 0);
    }

    #[test]
    fn a_29_february_birthday_counts_on_1_march_in_common_years() {
        assert_eq!(age_on(d("2008-02-29"), d("2026-02-28")), 17);
        assert_eq!(age_on(d("2008-02-29"), d("2026-03-01")), 18);
        assert_eq!(age_on(d("2008-02-29"), d("2028-02-29")), 20);
        assert_eq!(tier(Some("2008-02-29"), d("2026-02-28")), Tier::Minor);
        assert_eq!(tier(Some("2008-02-29"), d("2026-03-01")), Tier::Adult);
    }

    #[test]
    fn dates_are_strict_and_plausible() {
        let today = d("2026-10-09");
        assert_eq!(parse("1990-05-17", today).unwrap(), d("1990-05-17"));
        assert_eq!(parse("1900-01-01", today).unwrap(), d("1900-01-01"));
        assert_eq!(parse("2026-10-09", today).unwrap(), today);
        for bad in [
            "",
            "1990-5-17",
            "17.05.1990",
            "1990-02-30",
            "1990-13-01",
            "1899-12-31",
            "2026-10-10",
            "+1990-05-1",
            "1990-05-17T00:00:00Z",
            " 1990-05-17",
        ] {
            assert_eq!(parse(bad, today).unwrap_err().code(), "validation.date_of_birth", "{bad}");
        }
    }

    #[test]
    fn the_minimum_age_is_checked_on_the_birthday() {
        let today = d("2026-10-09");
        assert!(check_minimum(d("2010-10-09"), today, 16).is_ok());
        let err = check_minimum(d("2010-10-10"), today, 16).unwrap_err();
        assert_eq!(err.code(), "age.below_minimum");
        assert!(err.to_string().contains("16"));
    }

    #[test]
    fn tiers_and_gates() {
        let today = d("2026-10-09");
        assert_eq!(tier(None, today), Tier::Unknown);
        assert_eq!(tier(Some("garbage"), today), Tier::Unknown);
        assert_eq!(tier(Some("2008-10-10"), today), Tier::Minor);
        assert_eq!(tier(Some("2008-10-09"), today), Tier::Adult);
        assert_eq!(effective("none", "none"), GATE_NONE);
        assert_eq!(effective("adults_only", "none"), GATE_ADULTS);
        assert_eq!(effective("none", "adults_only"), GATE_ADULTS);
        assert!(validate_gate("adults_only").is_ok() && validate_gate("none").is_ok());
        assert_eq!(validate_gate("verified_only").unwrap_err().code(), "validation.age_gate");
        assert_eq!(restricted("room").code(), "age.restricted");
    }

    #[test]
    fn the_exempt_routes() {
        for path in [
            "/api/v1/users/me",
            "/api/v1/users/me/date-of-birth",
            "/api/v1/auth/logout",
            "/api/v1/users/me/terms",
            "/api/v1/legal/pages",
        ] {
            assert!(exempt_route(path), "{path}");
        }
        for path in ["/api/v1/rooms", "/api/v1/federation/token", "/api/v1/users/me/devices"] {
            assert!(!exempt_route(path), "{path}");
        }
    }
}
