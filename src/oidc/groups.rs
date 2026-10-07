// SPDX-License-Identifier: AGPL-3.0-only
//! Provider groups → node rights (APPLICATIONS.md §8.5).
//!
//! The map comes from `TAVRN_OIDC_GROUP_MAP` (fixed) or from the admin API (`node_settings`). It is applied
//! on every SSO login with the groups of the verified ID token or UserInfo. Every right a sync grants is
//! recorded in `sso_grants`; `TAVRN_OIDC_GROUP_SYNC=sync` revokes exactly those rights once no group grants
//! them any more. Rights granted by hand are never recorded and therefore never touched, and the accounts of
//! `TAVRN_ADMIN_USERS` keep the admin flag whatever the groups say.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    app::AppState,
    error::ApiError,
    models::UserRow,
    store,
    util::{self, now},
};

/// Groups per map and rooms per group at most.
pub const MAX_GROUPS: usize = 200;
pub const MAX_ROOMS_PER_GROUP: usize = 50;
pub const MAX_ROLES_PER_ROOM: usize = 25;
/// Groups read from one token (more are ignored).
pub const MAX_TOKEN_GROUPS: usize = 500;
/// `node_settings` key of a map edited in the admin API.
pub const SETTINGS_KEY: &str = "sso.group_map";

/// Rights one provider group grants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupRights {
    /// Node admin flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_admin: Option<bool>,
    /// Room creations granted for `TAVRN_ROOM_CREATION=invite` (0–1000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_creation: Option<i64>,
    /// Application creations for `TAVRN_APP_CREATION=invite` (0–1000); applied once applications exist on the node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_creation: Option<i64>,
    /// Memberships in local rooms with the listed roles (`@everyone` implied).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rooms: Vec<RoomGrant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomGrant {
    /// Room id (ULID).
    pub room: String,
    /// Role ids of that room.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Group name → rights.
pub type GroupMap = BTreeMap<String, GroupRights>;

/// Parses and validates a map (JSON). Errors name the offending entry.
pub fn parse(json: &str) -> Result<GroupMap, String> {
    let map: GroupMap = serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    validate(&map)?;
    Ok(map)
}

pub fn validate(map: &GroupMap) -> Result<(), String> {
    if map.len() > MAX_GROUPS {
        return Err(format!("at most {MAX_GROUPS} groups"));
    }
    for (group, rights) in map {
        if group.trim().is_empty() || group.len() > 256 {
            return Err(format!("group name '{group}': 1–256 characters"));
        }
        for (name, n) in [("room_creation", rights.room_creation), ("app_creation", rights.app_creation)] {
            if n.is_some_and(|n| !(0..=1000).contains(&n)) {
                return Err(format!("{group}.{name}: 0–1000"));
            }
        }
        if rights.rooms.len() > MAX_ROOMS_PER_GROUP {
            return Err(format!("{group}.rooms: at most {MAX_ROOMS_PER_GROUP}"));
        }
        for grant in &rights.rooms {
            if !util::is_ulid(&grant.room) {
                return Err(format!("{group}.rooms: '{}' is not a room id", grant.room));
            }
            if grant.roles.len() > MAX_ROLES_PER_ROOM {
                return Err(format!("{group}.rooms.{}: at most {MAX_ROLES_PER_ROOM} roles", grant.room));
            }
            if let Some(role) = grant.roles.iter().find(|r| !util::is_ulid(r)) {
                return Err(format!("{group}.rooms.{}: '{role}' is not a role id", grant.room));
            }
        }
    }
    Ok(())
}

/// The map in force: the fixed one of the environment, else the one stored by an admin, else empty.
pub async fn current(state: &AppState) -> Result<GroupMap, ApiError> {
    if let Some(fixed) = state.oidc.as_ref().and_then(|o| o.settings.group_map.clone()) {
        return Ok(fixed);
    }
    Ok(store::oidc::stored_group_map(&state.db).await?.and_then(|json| parse(&json).ok()).unwrap_or_default())
}

/// The rights the user's groups add up to; every right remembers the first group (alphabetically) granting it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Desired {
    pub node_admin: Option<String>,
    /// (count, group)
    pub room_creation: Option<(i64, String)>,
    /// room → (group, roles → group)
    pub rooms: BTreeMap<String, (String, BTreeMap<String, String>)>,
}

pub fn desired(map: &GroupMap, groups: &BTreeSet<String>) -> Desired {
    let mut d = Desired::default();
    for (group, rights) in map.iter().filter(|(g, _)| groups.contains(*g)) {
        if rights.node_admin == Some(true) && d.node_admin.is_none() {
            d.node_admin = Some(group.clone());
        }
        if let Some(n) = rights.room_creation.filter(|n| *n > 0)
            && d.room_creation.as_ref().is_none_or(|(have, _)| n > *have)
        {
            d.room_creation = Some((n, group.clone()));
        }
        for grant in &rights.rooms {
            let entry = d.rooms.entry(grant.room.clone()).or_insert_with(|| (group.clone(), BTreeMap::new()));
            for role in &grant.roles {
                entry.1.entry(role.clone()).or_insert_with(|| group.clone());
            }
        }
    }
    d
}

/// Kinds of `sso_grants` rows.
pub mod kind {
    pub const NODE_ADMIN: &str = "node_admin";
    pub const ROOM_CREATION: &str = "room_creation";
    pub const ROOM: &str = "room";
    pub const ROLE: &str = "role";
}

/// Applies the map for `user` with the token's `groups` (APPLICATIONS.md §8.5).
pub async fn sync(state: &AppState, user: &UserRow, groups: &BTreeSet<String>) -> Result<(), ApiError> {
    let Some(oidc) = state.oidc.as_ref() else { return Ok(()) };
    let map = current(state).await?;
    let want = desired(&map, groups);
    let revoke = oidc.settings.group_sync == crate::config::OidcGroupSync::Sync;
    let grants = store::oidc::grants_of(&state.db, &user.id).await?;
    let has_grant = |kind: &str, room: &str, role: &str| {
        grants.iter().any(|g| g.kind == kind && g.room_id == room && g.role_id == role)
    };
    let db = &state.db;

    // Node admin flag.
    match &want.node_admin {
        Some(group) if !user.is_node_admin() => {
            store::oidc::set_node_admin(db, &user.id, true).await?;
            store::oidc::record_grant(db, &user.id, kind::NODE_ADMIN, "", "", group).await?;
        }
        Some(_) => {}
        None if revoke && has_grant(kind::NODE_ADMIN, "", "") => {
            if !state.config.admin_users().contains(&user.username) {
                store::oidc::set_node_admin(db, &user.id, false).await?;
            }
            store::oidc::delete_grant(db, &user.id, kind::NODE_ADMIN, "", "").await?;
        }
        None => {}
    }

    // Room creation grant: created once (consumed per room); a grant by hand is never replaced.
    let existing = store::users::room_creation_grant(db, &user.id).await?;
    match &want.room_creation {
        Some((n, group)) if existing.is_none() => {
            store::users::upsert_room_creation_grant(db, &user.id, &user.id, *n).await?;
            store::oidc::record_grant(db, &user.id, kind::ROOM_CREATION, "", "", group).await?;
        }
        Some(_) => {}
        None if revoke && has_grant(kind::ROOM_CREATION, "", "") => {
            store::oidc::delete_room_creation_grant(db, &user.id).await?;
            store::oidc::delete_grant(db, &user.id, kind::ROOM_CREATION, "", "").await?;
        }
        None => {}
    }

    // Rooms and roles.
    for (room_id, (group, roles)) in &want.rooms {
        apply_room(state, user, room_id, group, roles).await?;
    }
    if revoke {
        for g in grants.iter().filter(|g| g.kind == kind::ROLE) {
            let still = want.rooms.get(&g.room_id).is_some_and(|(_, roles)| roles.contains_key(&g.role_id));
            if !still {
                revoke_role(state, user, &g.room_id, &g.role_id, &g.grp).await?;
            }
        }
        for g in grants.iter().filter(|g| g.kind == kind::ROOM) {
            if !want.rooms.contains_key(&g.room_id) {
                revoke_room(state, user, &g.room_id, &g.grp).await?;
            }
        }
    }
    Ok(())
}

/// Joins `room_id` (skipping join mode and rules gate) and adds the mapped roles; bans win.
async fn apply_room(
    state: &AppState,
    user: &UserRow,
    room_id: &str,
    group: &str,
    roles: &BTreeMap<String, String>,
) -> Result<(), ApiError> {
    let db = &state.db;
    let Some(room) = store::rooms::room_by_id(db, room_id).await? else {
        tracing::warn!(room_id, "SSO group map names a room that does not exist on this node");
        return Ok(());
    };
    if store::rooms::is_banned(db, Some(room_id), &user.address(), &user.domain).await?
        || store::rooms::is_banned(db, None, &user.address(), &user.domain).await?
    {
        return Ok(());
    }
    let meta = serde_json::json!({ "source": "sso", "group": group });
    if store::rooms::member(db, room_id, &user.id).await?.is_none() {
        // Rules not accepted: clients show them on first open (§8.5).
        store::rooms::add_member(db, room_id, &user.id, false).await?;
        store::oidc::record_grant(db, &user.id, kind::ROOM, room_id, "", group).await?;
        store::rooms::audit(db, Some(room_id), None, "member.join", &user.id, "", meta.clone()).await?;
        crate::subscriptions::room_event(
            state,
            room_id,
            "member.join",
            serde_json::json!({ "room_id": room_id, "user": user.to_public() }),
        )
        .await;
        crate::welcome::joined(state, &room, user).await;
    }
    let room_roles = store::rooms::roles(db, room_id).await?;
    let mut current = store::rooms::member_role_ids(db, room_id, &user.id).await?;
    let mut added = Vec::new();
    for (role_id, role_group) in roles {
        if !room_roles.iter().any(|r| &r.id == role_id && r.is_everyone == 0) {
            tracing::warn!(room_id, role_id, "SSO group map names a role that does not exist in the room");
            continue;
        }
        if !current.contains(role_id) {
            current.push(role_id.clone());
            added.push(role_id.clone());
            store::oidc::record_grant(db, &user.id, kind::ROLE, room_id, role_id, role_group).await?;
        }
    }
    if !added.is_empty() {
        // Mapped role assignments ignore the role hierarchy: the operator configured them.
        store::rooms::set_member_roles(db, room_id, &user.id, &current).await?;
        let meta = serde_json::json!({ "source": "sso", "group": group, "roles": current, "added": added });
        store::rooms::audit(db, Some(room_id), None, "member.roles", &user.id, "", meta).await?;
        member_updated(state, room_id, &user.id).await?;
    }
    Ok(())
}

async fn revoke_role(
    state: &AppState,
    user: &UserRow,
    room_id: &str,
    role_id: &str,
    group: &str,
) -> Result<(), ApiError> {
    let db = &state.db;
    store::oidc::delete_grant(db, &user.id, kind::ROLE, room_id, role_id).await?;
    if store::rooms::member(db, room_id, &user.id).await?.is_none() {
        return Ok(());
    }
    let mut current = store::rooms::member_role_ids(db, room_id, &user.id).await?;
    if !current.iter().any(|r| r == role_id) {
        return Ok(());
    }
    current.retain(|r| r != role_id);
    store::rooms::set_member_roles(db, room_id, &user.id, &current).await?;
    let meta = serde_json::json!({ "source": "sso", "group": group, "roles": current, "removed": [role_id] });
    store::rooms::audit(db, Some(room_id), None, "member.roles", &user.id, "", meta).await?;
    member_updated(state, room_id, &user.id).await
}

async fn revoke_room(state: &AppState, user: &UserRow, room_id: &str, group: &str) -> Result<(), ApiError> {
    let db = &state.db;
    store::oidc::delete_grant(db, &user.id, kind::ROOM, room_id, "").await?;
    let Some(room) = store::rooms::room_by_id(db, room_id).await? else { return Ok(()) };
    if room.owner_id == user.id {
        return Ok(());
    }
    let member = store::rooms::member(db, room_id, &user.id).await?;
    if member.is_none() || !store::rooms::remove_member(db, room_id, &user.id).await? {
        return Ok(());
    }
    let meta = serde_json::json!({ "source": "sso", "group": group });
    store::rooms::audit(db, Some(room_id), None, "member.leave", &user.id, "", meta).await?;
    crate::subscriptions::room_event(
        state,
        room_id,
        "member.leave",
        serde_json::json!({ "room_id": room_id, "user_id": user.id }),
    )
    .await;
    crate::welcome::membership_ended(state, &room, user, member.as_ref(), crate::welcome::LeaveKind::Leave).await;
    crate::e2ee::user_left_room(state, room_id, user).await
}

async fn member_updated(state: &AppState, room_id: &str, user_id: &str) -> Result<(), ApiError> {
    let Some(row) = store::rooms::member(&state.db, room_id, user_id).await? else { return Ok(()) };
    if let Some(member) = crate::routes::rooms::to_member(state, room_id, &row).await? {
        crate::subscriptions::room_event(
            state,
            room_id,
            "member.update",
            serde_json::json!({ "room_id": room_id, "member": member }),
        )
        .await;
    }
    Ok(())
}

/// Reads the groups claim: an array of strings (a single string counts as one group).
pub fn groups_from_claim(value: Option<&serde_json::Value>) -> BTreeSet<String> {
    match value {
        Some(serde_json::Value::Array(list)) => list
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter(|g| !g.is_empty() && g.len() <= 256)
            .take(MAX_TOKEN_GROUPS)
            .map(String::from)
            .collect(),
        Some(serde_json::Value::String(g)) if !g.is_empty() && g.len() <= 256 => BTreeSet::from([g.clone()]),
        _ => BTreeSet::new(),
    }
}

/// Stores a map edited in the admin API (validated by the caller).
pub async fn store_map(state: &AppState, map: &GroupMap) -> Result<(), ApiError> {
    let json = serde_json::to_string(map).map_err(|e| ApiError::Internal(e.into()))?;
    store::oidc::set_stored_group_map(&state.db, &json, &now()).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const ROOM: &str = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";
    const ROLE: &str = "01J9YYYYYYYYYYYYYYYYYYYYYY";

    #[test]
    fn parses_and_validates_the_example_of_the_spec() {
        let map = parse(&format!(
            r#"{{ "it-admins": {{ "node_admin": true }},
                 "staff": {{ "room_creation": 5, "app_creation": 3 }},
                 "devs": {{ "rooms": [ {{ "room": "{ROOM}", "roles": ["{ROLE}"] }} ] }} }}"#
        ))
        .unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["staff"].room_creation, Some(5));
        assert!(parse(r#"{ "x": { "nodeadmin": true } }"#).unwrap_err().contains("invalid JSON"));
        assert!(parse(r#"{ "x": { "room_creation": 5000 } }"#).unwrap_err().contains("0–1000"));
        assert!(parse(r#"{ "x": { "rooms": [ { "room": "nope" } ] } }"#).unwrap_err().contains("room id"));
        assert!(
            parse(&format!(r#"{{ "x": {{ "rooms": [ {{ "room": "{ROOM}", "roles": ["r"] }} ] }} }}"#))
                .unwrap_err()
                .contains("role id")
        );
        assert!(parse(r#"{ "": {} }"#).is_err());
        assert!(parse("[]").is_err());
    }

    #[test]
    fn desired_rights_merge_groups() {
        let map = parse(&format!(
            r#"{{ "a": {{ "room_creation": 2, "rooms": [ {{ "room": "{ROOM}" }} ] }},
                 "b": {{ "room_creation": 5, "node_admin": false, "rooms": [ {{ "room": "{ROOM}", "roles": ["{ROLE}"] }} ] }},
                 "c": {{ "node_admin": true }} }}"#
        ))
        .unwrap();
        let groups = |g: &[&str]| g.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        let d = desired(&map, &groups(&["a", "b", "unknown"]));
        assert_eq!(d.node_admin, None);
        assert_eq!(d.room_creation, Some((5, "b".into())));
        assert_eq!(d.rooms[ROOM].0, "a");
        assert_eq!(d.rooms[ROOM].1[ROLE], "b");
        assert_eq!(desired(&map, &groups(&["c"])).node_admin, Some("c".into()));
        assert_eq!(desired(&map, &groups(&[])), Desired::default());
    }

    #[test]
    fn groups_claim_shapes() {
        let v = serde_json::json!(["a", "b", "", 3]);
        assert_eq!(groups_from_claim(Some(&v)).len(), 2);
        assert_eq!(groups_from_claim(Some(&serde_json::json!("solo"))).len(), 1);
        assert!(groups_from_claim(Some(&serde_json::json!({ "a": 1 }))).is_empty());
        assert!(groups_from_claim(None).is_empty());
    }
}
