// SPDX-License-Identifier: AGPL-3.0-only
//! Whiteboard sessions and the audience of ephemeral events (`protocol/WHITEBOARD.md`).
//!
//! Ephemeral events (`POST /conversations/{id}/ephemeral`) are fanned out and forgotten; the node never
//! stores them. The only state it keeps is, per conversation, the small **session** derived from the
//! `whiteboard.open`, `whiteboard.grant` and `whiteboard.close` events (their plaintext `session` field,
//! never the encrypted content): who owns the board, from which device, whether it is open for everyone
//! and which users were granted editing. It lives in memory only: a node restart ends every session (the
//! owner's client opens it again with its next keepalive), and a session whose owner has not sent anything
//! for [`SESSION_TTL`] ends by itself.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{app::AppState, error::ApiError, store};

/// Largest `content` of an ephemeral event (the ciphertext string or the serialized plaintext object).
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
/// Ephemeral events per sender (user) and second.
pub const EVENTS_PER_SECOND: u32 = 30;
/// A session ends when its owner sent nothing for this long (clients send `whiteboard.open` every 30 s).
pub const SESSION_TTL: Duration = Duration::from_secs(90);
/// How often expired sessions are swept.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(15);
/// The audience of a conversation is cached this long (permission changes apply after at most this).
pub const AUDIENCE_TTL: Duration = Duration::from_secs(2);
/// Granted users per session.
pub const MAX_GRANTS: usize = 100;

/// The whiteboard session of a conversation as the node knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct WhiteboardSession {
    pub conversation_id: String,
    /// Address of the owner (the user who opened the board).
    pub owner: String,
    /// Node-local user id of the owner.
    pub owner_id: String,
    /// The owner's device presenting the board (the device id other clients know).
    pub device_id: String,
    /// Everyone who can view the conversation may edit.
    pub open_for_all: bool,
    /// Addresses granted editing.
    pub grants: Vec<String>,
    pub started_at: String,
}

/// The plaintext part of `whiteboard.open` and `whiteboard.grant`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, ToSchema)]
pub struct SessionState {
    #[serde(default)]
    pub open_for_all: bool,
    /// User addresses (`name@domain`), at most 100.
    #[serde(default)]
    pub grants: Vec<String>,
}

impl SessionState {
    /// Lowercase, trimmed, without duplicates; invalid addresses and too many grants are refused.
    pub fn normalized(&self) -> Result<Self, ApiError> {
        if self.grants.len() > MAX_GRANTS {
            return Err(crate::validate::bad(
                "whiteboard.grants_invalid",
                format!("At most {MAX_GRANTS} users can be granted editing"),
            ));
        }
        let mut grants: Vec<String> = Vec::with_capacity(self.grants.len());
        for g in &self.grants {
            let g = g.trim().to_lowercase();
            if crate::util::parse_address(&g).is_none() {
                return Err(crate::validate::bad("whiteboard.grants_invalid", "grants must be user addresses"));
            }
            if !grants.contains(&g) {
                grants.push(g);
            }
        }
        Ok(Self { open_for_all: self.open_for_all, grants })
    }
}

/// Who acts on a session.
pub struct Actor<'a> {
    pub user_id: &'a str,
    pub address: &'a str,
    /// The device id other clients know.
    pub public_device: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    /// Another user's board is open in this conversation.
    Exists(Box<WhiteboardSession>),
    NoSession,
    NotOwner,
    CloseForbidden,
}

impl From<SessionError> for ApiError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Exists(session) => ApiError::Conflict {
                code: "whiteboard.session_exists",
                detail: format!("{} already presents a whiteboard here", session.owner),
                meta: serde_json::to_value(*session).unwrap_or_default(),
            },
            SessionError::NoSession => {
                ApiError::NotFound { code: "whiteboard.no_session", what: "Whiteboard session".into() }
            }
            SessionError::NotOwner => ApiError::Forbidden {
                code: "whiteboard.not_owner",
                detail:
                    "Only the owner of the whiteboard (or a moderator with manage_whiteboard) can change who may edit"
                        .into(),
            },
            SessionError::CloseForbidden => ApiError::Forbidden {
                code: "whiteboard.close_forbidden",
                detail: "Only the owner or a moderator with manage_whiteboard can close the whiteboard".into(),
            },
        }
    }
}

struct Entry {
    session: WhiteboardSession,
    last_seen: Instant,
}

/// A computed audience (user ids) and when it was computed.
type CachedAudience = (Instant, Arc<Vec<String>>);

/// Sessions and cached audiences of this node.
#[derive(Default)]
pub struct Whiteboards {
    sessions: Mutex<HashMap<String, Entry>>,
    audiences: Mutex<HashMap<String, CachedAudience>>,
    /// The checks of encrypted ephemeral content, each cached for [`AUDIENCE_TTL`]: the current MLS epoch per
    /// conversation and the user whose attested device sent (per device).
    epochs: Mutex<HashMap<String, (Instant, i64)>>,
    attested: Mutex<HashMap<String, (Instant, String)>>,
}

/// A small map of values that are valid for [`AUDIENCE_TTL`]: the current one, if any.
fn fresh<T: Clone>(map: &Mutex<HashMap<String, (Instant, T)>>, key: &str, now: Instant) -> Option<T> {
    let map = map.lock().unwrap_or_else(|e| e.into_inner());
    map.get(key).filter(|(at, _)| now.duration_since(*at) < AUDIENCE_TTL).map(|(_, v)| v.clone())
}

fn remember<T>(map: &Mutex<HashMap<String, (Instant, T)>>, key: &str, value: T, now: Instant) {
    let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() > 1000 {
        map.retain(|_, (at, _)| now.duration_since(*at) < AUDIENCE_TTL);
    }
    map.insert(key.to_string(), (now, value));
}

/// Does the node know the MLS epoch `epoch` of the conversation (at most its current one)? An epoch above the cached
/// one asks the database again (a commit may just have started it).
pub async fn epoch_known(state: &AppState, conversation_id: &str, epoch: i64) -> Result<bool, ApiError> {
    let now = Instant::now();
    if fresh(&state.whiteboards.epochs, conversation_id, now).is_some_and(|current| epoch <= current) {
        return Ok(true);
    }
    let Some(current) = store::e2ee::group_epoch(&state.db, conversation_id).await? else { return Ok(false) };
    remember(&state.whiteboards.epochs, conversation_id, current, now);
    Ok(epoch <= current)
}

/// Encrypted content needs an attested sending device (`e2ee::attested_session_key`); a success is cached per device.
pub async fn require_attested(state: &AppState, auth: &crate::auth::AuthUser) -> Result<(), ApiError> {
    let now = Instant::now();
    if fresh(&state.whiteboards.attested, &auth.device_id, now).is_some_and(|user| user == auth.user.id) {
        return Ok(());
    }
    crate::e2ee::attested_session_key(state, auth).await?;
    remember(&state.whiteboards.attested, &auth.device_id, auth.user.id.clone(), now);
    Ok(())
}

impl Whiteboards {
    fn sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The live session of a conversation.
    pub fn get(&self, conversation_id: &str, now: Instant) -> Option<WhiteboardSession> {
        self.sessions()
            .get(conversation_id)
            .filter(|e| now.duration_since(e.last_seen) < SESSION_TTL)
            .map(|e| e.session.clone())
    }

    /// `whiteboard.open`: starts a session, or refreshes (keepalive) and updates the actor's own one.
    /// Returns the session and whether anything visible changed.
    pub fn open(
        &self,
        conversation_id: &str,
        actor: &Actor<'_>,
        state: Option<&SessionState>,
        now: Instant,
    ) -> Result<(WhiteboardSession, bool), SessionError> {
        let mut sessions = self.sessions();
        if let Some(entry) = sessions.get_mut(conversation_id)
            && now.duration_since(entry.last_seen) < SESSION_TTL
        {
            if entry.session.owner_id != actor.user_id {
                return Err(SessionError::Exists(Box::new(entry.session.clone())));
            }
            entry.last_seen = now;
            let before = entry.session.clone();
            entry.session.device_id = actor.public_device.to_string();
            if let Some(s) = state {
                entry.session.open_for_all = s.open_for_all;
                entry.session.grants.clone_from(&s.grants);
            }
            return Ok((entry.session.clone(), entry.session != before));
        }
        let state = state.cloned().unwrap_or_default();
        let session = WhiteboardSession {
            conversation_id: conversation_id.to_string(),
            owner: actor.address.to_string(),
            owner_id: actor.user_id.to_string(),
            device_id: actor.public_device.to_string(),
            open_for_all: state.open_for_all,
            grants: state.grants,
            started_at: crate::util::now(),
        };
        sessions.insert(conversation_id.to_string(), Entry { session: session.clone(), last_seen: now });
        Ok((session, true))
    }

    /// `whiteboard.grant`: the owner (or a moderator, `may_moderate`) replaces "open for everyone" and the
    /// grants. Only the owner's events keep the session alive.
    pub fn grant(
        &self,
        conversation_id: &str,
        actor: &Actor<'_>,
        state: &SessionState,
        may_moderate: bool,
        now: Instant,
    ) -> Result<(WhiteboardSession, bool), SessionError> {
        let mut sessions = self.sessions();
        let entry = sessions
            .get_mut(conversation_id)
            .filter(|e| now.duration_since(e.last_seen) < SESSION_TTL)
            .ok_or(SessionError::NoSession)?;
        let owner = entry.session.owner_id == actor.user_id;
        if !owner && !may_moderate {
            return Err(SessionError::NotOwner);
        }
        if owner {
            entry.last_seen = now;
        }
        let before = entry.session.clone();
        entry.session.open_for_all = state.open_for_all;
        entry.session.grants.clone_from(&state.grants);
        Ok((entry.session.clone(), entry.session != before))
    }

    /// `whiteboard.close` by the owner or a moderator (`may_moderate`).
    pub fn close(
        &self,
        conversation_id: &str,
        actor: &Actor<'_>,
        may_moderate: bool,
        now: Instant,
    ) -> Result<WhiteboardSession, SessionError> {
        let mut sessions = self.sessions();
        let entry = sessions
            .get(conversation_id)
            .filter(|e| now.duration_since(e.last_seen) < SESSION_TTL)
            .ok_or(SessionError::NoSession)?;
        if entry.session.owner_id != actor.user_id && !may_moderate {
            return Err(SessionError::CloseForbidden);
        }
        let session = entry.session.clone();
        sessions.remove(conversation_id);
        Ok(session)
    }

    /// Any other event of the owner keeps the session alive.
    pub fn touch(&self, conversation_id: &str, user_id: &str, now: Instant) {
        if let Some(entry) = self.sessions().get_mut(conversation_id)
            && entry.session.owner_id == user_id
            && now.duration_since(entry.last_seen) < SESSION_TTL
        {
            entry.last_seen = now;
        }
    }

    /// Removes the sessions whose owner was silent for [`SESSION_TTL`]; returns their conversations.
    pub fn expire(&self, now: Instant) -> Vec<String> {
        let mut sessions = self.sessions();
        let gone: Vec<String> = sessions
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) >= SESSION_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &gone {
            sessions.remove(k);
        }
        gone
    }

    fn cached_audience(&self, conversation_id: &str, now: Instant) -> Option<Arc<Vec<String>>> {
        let audiences = self.audiences.lock().unwrap_or_else(|e| e.into_inner());
        audiences.get(conversation_id).filter(|(at, _)| now.duration_since(*at) < AUDIENCE_TTL).map(|(_, a)| a.clone())
    }

    fn cache_audience(&self, conversation_id: &str, audience: Arc<Vec<String>>, now: Instant) {
        let mut audiences = self.audiences.lock().unwrap_or_else(|e| e.into_inner());
        if audiences.len() > 1000 {
            audiences.retain(|_, (at, _)| now.duration_since(*at) < AUDIENCE_TTL);
        }
        audiences.insert(conversation_id.to_string(), (now, audience));
    }
}

/// Who receives the ephemeral events of a conversation: room members with read access to the channel,
/// or the accepted members of a DM or group DM. Cached for [`AUDIENCE_TTL`].
pub async fn audience(state: &AppState, conversation_id: &str) -> Result<Arc<Vec<String>>, ApiError> {
    let now = Instant::now();
    if let Some(a) = state.whiteboards.cached_audience(conversation_id, now) {
        return Ok(a);
    }
    let Some(row) = store::social::conversation(&state.db, conversation_id).await? else {
        return Ok(Arc::new(Vec::new()));
    };
    let users = match (row.kind.as_str(), &row.room_id) {
        // The members who may view the channel (`crate::visibility`, the check of every per-room fan-out).
        ("channel", Some(room_id)) => match crate::visibility::room(state, room_id).await? {
            Some(view) => view.viewers(conversation_id).iter().cloned().collect(),
            None => Vec::new(),
        },
        ("dm" | "group", _) => {
            let requested = store::social::requested_ids(&state.db, conversation_id).await?;
            store::social::member_ids(&state.db, conversation_id)
                .await?
                .into_iter()
                .filter(|m| !requested.contains(m))
                .collect()
        }
        _ => Vec::new(),
    };
    let audience = Arc::new(users);
    state.whiteboards.cache_audience(conversation_id, audience.clone(), now);
    Ok(audience)
}

/// `whiteboard.session` `{ conversation_id, session }` to the conversation's audience (all their devices).
pub async fn publish_session(state: &AppState, conversation_id: &str, session: Option<&WhiteboardSession>) {
    match audience(state, conversation_id).await {
        Ok(users) => {
            state.hub.users(
                users.as_ref().clone(),
                "whiteboard.session",
                serde_json::json!({ "conversation_id": conversation_id, "session": session }),
            );
        }
        Err(e) => tracing::warn!(error = %e, conversation_id, "whiteboard session change not announced"),
    }
}

/// Ends the sessions whose owner went silent and tells their audiences.
pub async fn sweep(state: &AppState, now: Instant) -> usize {
    let gone = state.whiteboards.expire(now);
    for conversation_id in &gone {
        publish_session(state, conversation_id, None).await;
    }
    gone.len()
}

/// Background task sweeping expired sessions every [`SWEEP_INTERVAL`].
pub fn spawn_sweeper(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            // The sessions live on the leader (several instances, `cache::relay`).
            if state.cluster.is_leader() {
                sweep(&state, Instant::now()).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn actor<'a>(user_id: &'a str, address: &'a str, device: &'a str) -> Actor<'a> {
        Actor { user_id, address, public_device: device }
    }

    #[test]
    fn open_grant_close_transitions() {
        let w = Whiteboards::default();
        let t0 = Instant::now();
        let alice = actor("ua", "alice@x.test", "da");
        let bob = actor("ub", "bob@x.test", "db");
        assert_eq!(w.get("c1", t0), None);
        let (s, changed) = w.open("c1", &alice, None, t0).unwrap();
        assert!(changed);
        assert_eq!((s.owner.as_str(), s.device_id.as_str(), s.open_for_all), ("alice@x.test", "da", false));
        assert!(s.grants.is_empty());
        // A keepalive without changes changes nothing visible.
        let (_, changed) = w.open("c1", &alice, None, t0 + Duration::from_secs(30)).unwrap();
        assert!(!changed);
        // Another user cannot take over a live board.
        assert!(matches!(w.open("c1", &bob, None, t0), Err(SessionError::Exists(s)) if s.owner == "alice@x.test"));
        // Only the owner grants.
        let state = SessionState { open_for_all: false, grants: vec!["bob@x.test".into()] };
        assert_eq!(w.grant("c1", &bob, &state, false, t0), Err(SessionError::NotOwner));
        let (s, changed) = w.grant("c1", &alice, &state, false, t0).unwrap();
        assert!(changed);
        assert_eq!(s.grants, vec!["bob@x.test".to_string()]);
        assert!(!w.grant("c1", &alice, &state, false, t0).unwrap().1, "same state: no change");
        // A moderator (manage_whiteboard) may change the grants of someone else's board.
        let none = SessionState { open_for_all: false, grants: vec![] };
        assert!(w.grant("c1", &bob, &none, true, t0).unwrap().0.grants.is_empty());
        w.grant("c1", &alice, &state, false, t0).unwrap();
        // The keepalive carries the state too; the owner may switch devices.
        let open = SessionState { open_for_all: true, grants: vec![] };
        let (s, changed) = w.open("c1", &actor("ua", "alice@x.test", "da2"), Some(&open), t0).unwrap();
        assert!(changed && s.open_for_all && s.device_id == "da2");
        // Closing: not by others without moderation rights, by a moderator, then nothing is left.
        assert_eq!(w.close("c1", &bob, false, t0), Err(SessionError::CloseForbidden));
        assert_eq!(w.close("c1", &bob, true, t0).unwrap().owner, "alice@x.test");
        assert_eq!(w.get("c1", t0), None);
        assert_eq!(w.close("c1", &alice, false, t0), Err(SessionError::NoSession));
        assert_eq!(w.grant("c1", &alice, &state, false, t0), Err(SessionError::NoSession));
        // After closing, someone else may open.
        assert!(w.open("c1", &bob, None, t0).is_ok());
    }

    #[test]
    fn sessions_expire_without_owner_activity() {
        let w = Whiteboards::default();
        let t0 = Instant::now();
        let alice = actor("ua", "alice@x.test", "da");
        w.open("c1", &alice, None, t0).unwrap();
        w.open("c2", &alice, None, t0).unwrap();
        // Other events of the owner keep c1 alive; events of others do not.
        w.touch("c1", "ua", t0 + Duration::from_secs(60));
        w.touch("c2", "ub", t0 + Duration::from_secs(60));
        let later = t0 + SESSION_TTL + Duration::from_secs(1);
        assert!(w.get("c1", later).is_some());
        assert_eq!(w.get("c2", later), None, "expired sessions are invisible before the sweep");
        assert_eq!(w.expire(later), vec!["c2".to_string()]);
        // An expired session can be taken over by someone else.
        let bob = actor("ub", "bob@x.test", "db");
        assert!(w.open("c1", &bob, None, t0 + Duration::from_secs(200)).is_ok());
    }

    #[test]
    fn grants_are_normalized_and_limited() {
        let s = SessionState { open_for_all: false, grants: vec![" Bob@X.test ".into(), "bob@x.test".into()] };
        assert_eq!(s.normalized().unwrap().grants, vec!["bob@x.test".to_string()]);
        let bad = SessionState { open_for_all: false, grants: vec!["no address".into()] };
        assert_eq!(bad.normalized().unwrap_err().code(), "whiteboard.grants_invalid");
        let many =
            SessionState { open_for_all: false, grants: (0..=MAX_GRANTS).map(|i| format!("u{i}@x.test")).collect() };
        assert_eq!(many.normalized().unwrap_err().code(), "whiteboard.grants_invalid");
    }
}
