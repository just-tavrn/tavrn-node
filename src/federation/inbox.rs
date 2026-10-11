// SPDX-License-Identifier: AGPL-3.0-only
//! `POST /api/v1/federation/inbox` (FEDERATION.md §5.1, §5.2): signed notifications of other nodes.
//!
//! Order of checks: federation enabled; `Content-Length` within 64 KiB; node token (§2.3: unverified
//! `iss`, domain policy, key from `iss`'s own document (a limit per address before, per domain after), §2.1 claims, `htm`/`htu`,
//! `TAVRN_FEDERATION_REQUIRE_CONFORMANCE` (§9.4));
//! body read with a hard cap of 64 KiB; body hash **before** parsing; `jti` spent; envelope; message age;
//! the authority rules of §5.2 (`federation.type_forbidden`); recipient; payload; dedupe by `(iss, id)`
//! for 7 days; then the handler runs and the answer is `202`.
//!
//! Handlers run inline before the `202` (short database updates, plus a refetch of the sender's key view
//! for key changes) and are idempotent through the dedupe. Implemented: `session.revoke`,
//! `identity.changed`, `devices.changed` (here) and `room.invite`, `conversation.invite`, `friend.*`,
//! `notify`, `ban.notify` (`federation::social`) and `node.announce` (`federation::announce`); unknown types
//! are accepted and ignored (forward compatibility).

use std::time::Instant;

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode, header},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{social, tokens};
use crate::{app::AppState, auth, error::ApiError, models::UserRow, store, util};

pub const INBOX_PATH: &str = "/api/v1/federation/inbox";
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Message ids older than this or further in the future are refused (§5.1).
pub const MAX_AGE_SECS: i64 = 7 * 24 * 3600;
pub const MAX_FUTURE_SECS: i64 = 300;
/// Internal hub event that closes the WebSockets of revoked devices (code 4001).
pub const SESSION_REVOKED_EVENT: &str = "session.revoked";

fn too_large() -> ApiError {
    ApiError::PayloadTooLarge {
        code: "federation.payload_too_large",
        detail: "Message larger than 64 KiB".into(),
        meta: json!({ "max_bytes": MAX_BODY_BYTES }),
    }
}

fn invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

fn type_forbidden() -> ApiError {
    ApiError::Forbidden {
        code: "federation.type_forbidden",
        detail: "Sender or recipient does not fit this message type".into(),
    }
}

fn recipient_unknown() -> ApiError {
    ApiError::NotFound { code: "federation.recipient_unknown", what: "Recipient".into() }
}

#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub from: String,
    pub to: String,
    pub at: String,
    #[serde(default)]
    pub payload: Value,
}

/// Who may appear as `from` of a type (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromRule {
    /// A user address of any domain (e.g. the inviter of a room on the sending node).
    AnyUser,
    /// A user address whose domain is the sender (`iss`).
    UserOfSender,
    /// The sending domain itself.
    Sender,
}

/// Who may appear as `to` of a type (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToRule {
    /// A user address of this node.
    User,
    /// This node's domain.
    Node,
}

/// The authority rules of §5.2; `None` for unknown types.
pub fn rule(kind: &str) -> Option<(FromRule, ToRule)> {
    Some(match kind {
        "room.invite" | "conversation.invite" => (FromRule::AnyUser, ToRule::User),
        "friend.request" | "friend.accept" | "friend.remove" => (FromRule::UserOfSender, ToRule::User),
        "identity.changed" | "devices.changed" | "session.revoke" => (FromRule::UserOfSender, ToRule::Node),
        "node.announce" => (FromRule::Sender, ToRule::Node),
        "ban.notify" | "notify" => (FromRule::Sender, ToRule::User),
        // Applications (APPLICATIONS.md §4.5): the room node tells the bot's home node; the home node tells
        // the room nodes about its bot.
        "app.install" | "app.uninstall" => (FromRule::Sender, ToRule::User),
        "app.changed" => (FromRule::UserOfSender, ToRule::Node),
        // Legal (protocol/LEGAL.md): a notice forwarded to the content's home node, and the deletion of
        // an account by its home node.
        "legal.notice" => (FromRule::Sender, ToRule::Node),
        "user.deleted" => (FromRule::UserOfSender, ToRule::Node),
        _ => return None,
    })
}

/// The local recipient named by `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Node,
    /// Username of a local user.
    User(String),
}

/// `false` if `from` is not a sender `iss` may use for a known type (§5.2): a spoofing attempt (§9.4).
pub fn from_allowed(iss: &str, kind: &str, from: &str) -> bool {
    match rule(kind) {
        None => true,
        Some((FromRule::AnyUser, _)) => util::parse_address(from).is_some(),
        Some((FromRule::UserOfSender, _)) => util::parse_address(from).is_some_and(|(_, d)| d == iss),
        Some((FromRule::Sender, _)) => from == iss,
    }
}

/// Checks `from` and `to` of a known type against the sender `iss` and this node's domain.
pub fn check_authority(own: &str, iss: &str, kind: &str, from: &str, to: &str) -> Result<Option<Recipient>, ApiError> {
    let Some((_, to_rule)) = rule(kind) else { return Ok(None) };
    if !from_allowed(iss, kind, from) {
        return Err(type_forbidden());
    }
    match to_rule {
        ToRule::Node if to == own => Ok(Some(Recipient::Node)),
        ToRule::User => match util::parse_address(to) {
            Some((user, domain)) if domain == own => Ok(Some(Recipient::User(user.to_string()))),
            Some(_) => Err(recipient_unknown()),
            None => Err(type_forbidden()),
        },
        ToRule::Node => Err(type_forbidden()),
    }
}

/// `400 federation.message_stale` unless the ULID time of `id` lies within the last 7 days and at most
/// 5 minutes in the future.
pub fn check_age(id: &str, now: DateTime<Utc>) -> Result<(), ApiError> {
    let ulid = ulid::Ulid::from_string(id).map_err(|_| invalid("id is not a ULID"))?;
    let created = DateTime::<Utc>::from(ulid.datetime());
    if created < now - chrono::Duration::seconds(MAX_AGE_SECS)
        || created > now + chrono::Duration::seconds(MAX_FUTURE_SECS)
    {
        return Err(ApiError::BadRequest {
            code: "federation.message_stale",
            detail: "Message is too old or lies in the future".into(),
        });
    }
    Ok(())
}

/// What a handled message does, parsed before the message is recorded as seen.
enum Action {
    Revoke { device: Option<String> },
    IdentityChanged { key: String, reset_at: String },
    DevicesChanged,
    Social(social::Incoming),
    App(crate::installations::Incoming),
    LegalNotice,
    UserDeleted,
    Ignore,
}

fn parse_action(kind: &str, iss: &str, payload: &Value) -> Result<Action, ApiError> {
    match kind {
        "session.revoke" => match payload.get("device") {
            None | Some(Value::Null) => Ok(Action::Revoke { device: None }),
            Some(Value::String(d)) if util::is_ulid(d) => Ok(Action::Revoke { device: Some(d.clone()) }),
            Some(_) => Err(invalid("invalid payload.device")),
        },
        "identity.changed" => {
            let key = payload.get("identity_public_key").and_then(Value::as_str).unwrap_or("");
            let key =
                crate::e2ee::decode_public_key(key).map_err(|_| invalid("invalid payload.identity_public_key"))?;
            let reset_at = payload
                .get("identity_reset_at")
                .and_then(Value::as_str)
                .and_then(util::parse_time)
                .ok_or_else(|| invalid("invalid payload.identity_reset_at"))?;
            Ok(Action::IdentityChanged {
                key: tavrn_crypto::util::b64url_encode(&key),
                reset_at: util::format_time(reset_at),
            })
        }
        "devices.changed" => Ok(Action::DevicesChanged),
        crate::legal::notices::KIND => Ok(Action::LegalNotice),
        crate::legal::account::KIND => Ok(Action::UserDeleted),
        _ => {
            if let Some(app) = crate::installations::parse(kind, iss, payload)? {
                return Ok(Action::App(app));
            }
            Ok(social::parse(kind, iss, payload)?.map_or(Action::Ignore, Action::Social))
        }
    }
}

/// Handles one inbox request. Returns `202` for stored, handled and duplicate messages.
pub async fn receive(state: &AppState, ip: &str, headers: &HeaderMap, body: Body) -> Result<StatusCode, ApiError> {
    let started = Instant::now();
    if !state.config.federation_enabled {
        return Err(super::disabled());
    }
    let length = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if length.is_some_and(|n| n > MAX_BODY_BYTES as u64) {
        return Err(too_large());
    }
    // Per address before the signature check (which may fetch the claimed sender's keys); per domain only after
    // it, so requests forged in a peer's name cannot use up its budget.
    state.federation_ip_limiter.check_all(&[format!("ip:{ip}")]).await?;
    let token = auth::bearer(headers).ok_or_else(tokens::token_invalid)?;
    let iss = tokens::peek_issuer(state, token)?;
    super::check_policy(state, &iss).await?;
    let claims = tokens::verify_node_token(state, token, &iss, "POST", INBOX_PATH).await?;
    state.federation_inbox_limiter.check_all(&[format!("domain:{iss}")]).await?;
    // After the signature check: only real peers can start a conformance run.
    super::conformance::require(state, &iss).await?;
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| too_large())?;
    if let Err(e) = tokens::check_body(&claims, &bytes) {
        // Signed by the sender, but not over this body: counts towards an automatic block (§9.4).
        super::conformance::observe_body_hash(state, &iss, &bytes).await;
        return Err(e);
    }
    tokens::spend_jti(state, &claims.std).await?;

    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| invalid("invalid envelope"))?;
    let result = process(state, &iss, &envelope).await;
    let ms = started.elapsed().as_millis() as u64;
    match &result {
        Ok(outcome) => tracing::info!(
            sender = iss,
            kind = envelope.kind,
            id = envelope.id,
            result = outcome,
            ms,
            "federation inbox"
        ),
        Err(e) => {
            if e.code() == "federation.type_forbidden" {
                tracing::warn!(
                    sender = iss,
                    kind = envelope.kind,
                    id = envelope.id,
                    "federation spoofing attempt: type_forbidden"
                );
                // Only a `from` the sender may not use is spoofing; a misaddressed `to` is not.
                if !from_allowed(&iss, &envelope.kind, &envelope.from) {
                    super::conformance::violation(state, &iss, super::conformance::VIOLATION_TYPE_FORBIDDEN).await;
                }
            }
            tracing::info!(
                sender = iss,
                kind = envelope.kind,
                id = envelope.id,
                result = e.code(),
                ms,
                "federation inbox refused"
            );
        }
    }
    result.map(|_| StatusCode::ACCEPTED)
}

async fn process(state: &AppState, iss: &str, envelope: &Envelope) -> Result<&'static str, ApiError> {
    if !util::is_ulid(&envelope.id) || envelope.kind.is_empty() || envelope.kind.len() > 64 {
        return Err(invalid("invalid id or type"));
    }
    check_age(&envelope.id, Utc::now())?;
    if util::parse_time(&envelope.at).is_none() {
        return Err(invalid("invalid at"));
    }
    let recipient = check_authority(&state.config.domain, iss, &envelope.kind, &envelope.from, &envelope.to)?;
    if let Some(Recipient::User(username)) = &recipient {
        let known = store::users::by_username(&state.db, username, &state.config.domain).await?;
        if known.filter(|u| u.disabled_at.is_none()).is_none() {
            return Err(recipient_unknown());
        }
    }
    // `node.announce` (§7.2) dedupes and records itself: its rate limit and verification run before the
    // message counts as seen, so a refused announce can be sent again.
    if envelope.kind == super::announce::KIND {
        return super::announce::receive(state, iss, &envelope.id, &envelope.payload).await;
    }
    let action = parse_action(&envelope.kind, iss, &envelope.payload)?;
    if let Action::LegalNotice = action {
        crate::legal::notices::admit_inbound(state, iss).await?;
    }
    if !store::federation::mark_seen(&state.db, iss, &envelope.id, &envelope.kind).await? {
        return Ok("duplicate");
    }
    if recipient.is_none() {
        return Ok("ignored");
    }
    if let Action::Social(incoming) = action {
        let Some(Recipient::User(username)) = &recipient else { return Ok("ignored") };
        let user = store::users::by_username(&state.db, username, &state.config.domain)
            .await?
            .ok_or_else(recipient_unknown)?;
        return social::handle(state, iss, &envelope.from, &user, &envelope.at, incoming).await;
    }
    if let Action::LegalNotice = action {
        return crate::legal::notices::receive(state, iss, &envelope.payload).await;
    }
    let action = match action {
        Action::App(incoming) => {
            return match &recipient {
                Some(Recipient::User(username)) => {
                    let bot = store::users::by_username(&state.db, username, &state.config.domain)
                        .await?
                        .ok_or_else(recipient_unknown)?;
                    crate::installations::handle_for_bot(state, iss, &bot, incoming).await
                }
                _ => {
                    let bot = match util::parse_address(&envelope.from) {
                        Some((name, domain)) => store::federation::user_by_address(&state.db, name, domain).await?,
                        None => None,
                    };
                    crate::installations::handle_changed(state, iss, bot, incoming).await
                }
            };
        }
        other => other,
    };
    // `from` of the handled types is a user of the sender (checked above).
    let sender_user = match util::parse_address(&envelope.from) {
        Some((name, domain)) => store::federation::user_by_address(&state.db, name, domain).await?,
        None => None,
    };
    match (action, sender_user) {
        (Action::Ignore | Action::Social(_) | Action::App(_) | Action::LegalNotice, _) => Ok("stored"),
        (_, None) => Ok("no_local_state"),
        (Action::Revoke { device }, Some(user)) => {
            revoke(state, &user, device.as_deref()).await?;
            Ok("handled")
        }
        (Action::IdentityChanged { key, reset_at }, Some(user)) => {
            identity_changed(state, &user, &key, &reset_at).await?;
            Ok("handled")
        }
        (Action::DevicesChanged, Some(user)) => {
            devices_changed(state, &user).await?;
            Ok("handled")
        }
        (Action::UserDeleted, Some(user)) => {
            crate::legal::account::receive_remote(state, iss, &user, &envelope.payload).await
        }
    }
}

/// `session.revoke` (§2.9): revokes the federated sessions and closes their WebSockets.
async fn revoke(state: &AppState, user: &UserRow, device: Option<&str>) -> Result<(), ApiError> {
    let devices = store::federation::revoke_remote_sessions(&state.db, &user.id, device).await?;
    if !devices.is_empty() {
        state.hub.devices(devices, SESSION_REVOKED_EVENT, json!({}));
    }
    Ok(())
}

/// `devices.changed` (§5.2): refetch the key view of the home node and ask MLS groups to remove the
/// leaves of devices that disappeared. A failed refetch leaves the cache invalidated (refetched on use).
async fn devices_changed(state: &AppState, user: &UserRow) -> Result<(), ApiError> {
    store::federation::invalidate_keys(&state.db, &user.id).await?;
    match super::keys::refresh(state, user).await {
        Ok(vanished) => {
            for device in vanished {
                crate::e2ee::device_removed(state, user, &device).await?;
            }
        }
        Err(e) => tracing::info!(domain = user.domain, result = e.code(), "key refetch after devices.changed failed"),
    }
    Ok(())
}

/// `identity.changed` (§5.2): mirror the new key, refetch the key cache, tell the local contacts and
/// the user's own sessions, and ask MLS groups to remove the now unattested leaves.
async fn identity_changed(state: &AppState, user: &UserRow, key: &str, reset_at: &str) -> Result<(), ApiError> {
    let previous = store::users::by_id(&state.db, &user.id).await?.and_then(|u| u.identity_pubkey);
    store::federation::set_remote_identity(&state.db, &user.id, key, reset_at).await?;
    // The security log of the rooms here: a reset is never a rotation. The entry also records the reset on the
    // user's memberships here (ENCRYPTION.md §7b); without a cached key there is no entry, but the reset still counts.
    match previous.as_deref() {
        Some(p) if p != key => crate::welcome::key_changed(state, user, false).await,
        None => crate::history::key_reset(state, user, &util::now()).await,
        Some(_) => {}
    }
    store::federation::invalidate_keys(&state.db, &user.id).await?;
    if let Err(e) = super::keys::refresh(state, user).await {
        tracing::info!(domain = user.domain, result = e.code(), "key refetch after identity.changed failed");
    }
    let mut recipients = store::social::contact_ids(&state.db, &user.id).await?;
    for (friend, _) in store::social::friends_of(&state.db, &user.id).await? {
        if !recipients.contains(&friend) {
            recipients.push(friend);
        }
    }
    recipients.push(user.id.clone());
    state.hub.users(
        recipients,
        "identity.changed",
        json!({ "user": user.address(), "user_id": user.id, "identity_reset_at": reset_at, "at": util::now() }),
    );
    crate::e2ee::identity_reset(state, user).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const OWN: &str = "b.example";
    const ISS: &str = "a.example";

    fn code(r: Result<Option<Recipient>, ApiError>) -> String {
        r.unwrap_err().code().to_string()
    }

    #[test]
    fn authority_rules_of_every_type() {
        let ok = |kind: &str, from: &str, to: &str| check_authority(OWN, ISS, kind, from, to).unwrap();
        let user = Some(Recipient::User("bob".into()));
        let node = Some(Recipient::Node);
        assert_eq!(ok("room.invite", "carol@c.example", "bob@b.example"), user, "inviter of any domain");
        assert_eq!(ok("conversation.invite", "alice@a.example", "bob@b.example"), user);
        // Legal: notices come from the forwarding node, deletions from the user's home node.
        assert_eq!(ok("legal.notice", ISS, OWN), node);
        assert_eq!(ok("user.deleted", "alice@a.example", OWN), node);
        for (kind, from, to) in [
            ("legal.notice", "alice@a.example", OWN),
            ("legal.notice", ISS, "bob@b.example"),
            ("user.deleted", "mallory@c.example", OWN),
            ("user.deleted", ISS, OWN),
        ] {
            assert_eq!(
                code(check_authority(OWN, ISS, kind, from, to)),
                "federation.type_forbidden",
                "{kind} {from} {to}"
            );
        }
        for kind in ["friend.request", "friend.accept", "friend.remove"] {
            assert_eq!(ok(kind, "alice@a.example", "bob@b.example"), user);
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "carol@c.example", "bob@b.example")),
                "federation.type_forbidden"
            );
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "a.example", "bob@b.example")),
                "federation.type_forbidden"
            );
        }
        for kind in ["identity.changed", "devices.changed", "session.revoke"] {
            assert_eq!(ok(kind, "alice@a.example", "b.example"), node);
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "alice@c.example", "b.example")),
                "federation.type_forbidden"
            );
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "alice@a.example", "bob@b.example")),
                "federation.type_forbidden"
            );
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "alice@a.example", "c.example")),
                "federation.type_forbidden"
            );
        }
        assert_eq!(ok("node.announce", "a.example", "b.example"), node);
        assert_eq!(
            code(check_authority(OWN, ISS, "node.announce", "c.example", "b.example")),
            "federation.type_forbidden"
        );
        assert_eq!(
            code(check_authority(OWN, ISS, "node.announce", "alice@a.example", "b.example")),
            "federation.type_forbidden"
        );
        for kind in ["ban.notify", "notify"] {
            assert_eq!(ok(kind, "a.example", "bob@b.example"), user);
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "alice@a.example", "bob@b.example")),
                "federation.type_forbidden"
            );
            assert_eq!(code(check_authority(OWN, ISS, kind, "a.example", "b.example")), "federation.type_forbidden");
        }
        assert_eq!(
            code(check_authority(OWN, ISS, "room.invite", "a.example", "bob@b.example")),
            "federation.type_forbidden"
        );
        assert_eq!(
            code(check_authority(OWN, ISS, "room.invite", "carol@c.example", "bob@c.example")),
            "federation.recipient_unknown",
            "a user of another node is not a recipient here"
        );
        // Applications (APPLICATIONS.md §4.5).
        for kind in ["app.install", "app.uninstall"] {
            assert_eq!(
                ok(kind, "a.example", "bot@b.example"),
                Some(Recipient::User("bot".into())),
                "the room node tells the bot's home node"
            );
            assert_eq!(
                code(check_authority(OWN, ISS, kind, "carol@a.example", "bot@b.example")),
                "federation.type_forbidden"
            );
            assert_eq!(code(check_authority(OWN, ISS, kind, "a.example", "b.example")), "federation.type_forbidden");
        }
        assert_eq!(ok("app.changed", "bot@a.example", "b.example"), node, "the home node tells about its bot");
        assert_eq!(
            code(check_authority(OWN, ISS, "app.changed", "bot@c.example", "b.example")),
            "federation.type_forbidden"
        );
        assert_eq!(
            code(check_authority(OWN, ISS, "app.changed", "a.example", "b.example")),
            "federation.type_forbidden"
        );
        assert_eq!(ok("future.type", "anything", "anyone"), None, "unknown types are not checked");
    }

    #[test]
    fn message_age_window() {
        let now = Utc::now();
        let id_at = |t: DateTime<Utc>| ulid::Ulid::from_datetime(std::time::SystemTime::from(t)).to_string();
        assert!(check_age(&id_at(now), now).is_ok());
        assert!(check_age(&id_at(now - chrono::Duration::days(6)), now).is_ok());
        assert!(check_age(&id_at(now + chrono::Duration::seconds(240)), now).is_ok());
        for t in [now - chrono::Duration::days(8), now + chrono::Duration::seconds(400)] {
            assert_eq!(check_age(&id_at(t), now).unwrap_err().code(), "federation.message_stale");
        }
        assert_eq!(check_age("not-a-ulid", now).unwrap_err().code(), "federation.envelope_invalid");
    }

    #[test]
    fn payloads_are_validated() {
        assert!(matches!(
            parse_action("session.revoke", ISS, &json!({ "device": null })),
            Ok(Action::Revoke { device: None })
        ));
        assert!(matches!(parse_action("session.revoke", ISS, &json!({})), Ok(Action::Revoke { device: None })));
        let id = util::ulid();
        assert!(matches!(
            parse_action("session.revoke", ISS, &json!({ "device": id })),
            Ok(Action::Revoke { device: Some(_) })
        ));
        assert!(parse_action("session.revoke", ISS, &json!({ "device": "../x" })).is_err());
        assert!(parse_action("session.revoke", ISS, &json!({ "device": 5 })).is_err());
        let key = tavrn_crypto::util::b64url_encode(crate::keys::NodeKey::generate("k").verifying().as_bytes());
        assert!(
            parse_action(
                "identity.changed",
                ISS,
                &json!({ "identity_public_key": key, "identity_reset_at": util::now() })
            )
            .is_ok()
        );
        assert!(
            parse_action(
                "identity.changed",
                ISS,
                &json!({ "identity_public_key": "AAAA", "identity_reset_at": util::now() })
            )
            .is_err()
        );
        assert!(
            parse_action(
                "identity.changed",
                ISS,
                &json!({ "identity_public_key": key, "identity_reset_at": "yesterday" })
            )
            .is_err()
        );
        assert!(matches!(parse_action("devices.changed", ISS, &json!({})), Ok(Action::DevicesChanged)));
        assert!(parse_action("friend.request", ISS, &json!({ "request_id": "x" })).is_err(), "request ids are ULIDs");
        assert!(matches!(
            parse_action("friend.request", ISS, &json!({ "request_id": util::ulid() })),
            Ok(Action::Social(social::Incoming::FriendRequest { .. }))
        ));
        assert!(matches!(parse_action("node.announce", ISS, &json!({})), Ok(Action::Ignore)));
    }
}
