// SPDX-License-Identifier: AGPL-3.0-only
//! Installing applications in rooms (protocol/APPLICATIONS.md §1.8, §4): the public application document,
//! the add flow with its nine checks, uninstalling (removal, kick, ban, leave, "no bots", blocks), the
//! bot's notification (`application.install` / `application.uninstall` locally, `app.install` /
//! `app.uninstall` to the bot's home node), the install index of the home node and `app.changed`.
//!
//! A bot is in a room only through an installation (§0). The room node (T) keeps the installation row
//! and, for a bot of another node, a stub user created from the application's public document; the bot's
//! home node (H) keeps the install index so the bot finds its room nodes and `app.changed` reaches them.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    applications as apps,
    auth::AuthUser,
    error::ApiError,
    federation::client::Kind,
    models::{Room, User, UserRow},
    permissions as p, store,
    store::applications::ApplicationRow,
    util,
    validate::bad,
};

/// Announced by every node from step 2 on (applications, tokens, scopes, installations, `app.*` types).
pub const CAPABILITY: &str = "apps.v1";
/// S2S inbox types of §4.5.
pub const KIND_INSTALL: &str = "app.install";
pub const KIND_UNINSTALL: &str = "app.uninstall";
pub const KIND_CHANGED: &str = "app.changed";
/// The public document is cacheable this long (§1.8).
pub const DOCUMENT_MAX_AGE_SECS: u32 = 300;
/// Longest application or room name accepted from another node.
const NAME_MAX: usize = 100;
/// Install index entries per application (§4.5); further `app.install` messages are ignored.
pub const MAX_INDEX_ENTRIES: i64 = 10_000;
/// Reasons of an uninstall (`app.uninstall` audit entry and events).
pub const REASONS: &[&str] = &["removed", "kicked", "banned", "left", "no_bots", "owner_banned", "blocked", "deleted"];

// ---------------------------------------------------------------- errors

pub fn blocked() -> ApiError {
    ApiError::Forbidden { code: "app.blocked", detail: "This application is blocked on this node".into() }
}

fn not_installed() -> ApiError {
    ApiError::NotFound { code: "app.not_installed", what: "Installation".into() }
}

// ---------------------------------------------------------------- public document (§1.8)

/// Everything a node or client needs to show and install an application (no authentication, CORS-open).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicApplication {
    /// `<domain>/<id>`
    #[serde(rename = "ref")]
    pub reference: String,
    pub id: String,
    /// The bot's home node.
    pub node: String,
    pub name: String,
    pub description: String,
    /// Bot address.
    pub bot: String,
    /// Owner address.
    pub owner: String,
    /// `false`: only the owner may install it.
    pub public: bool,
    /// Path of the bot's avatar on its home node (null without avatar).
    pub avatar: Option<String>,
    /// base64url SHA-256 of the avatar's still image.
    pub avatar_sha256: Option<String>,
    /// Decimal permission mask the add flow proposes (never `administrator`).
    pub requested_permissions: String,
    /// Upper bound of the application's token scopes.
    pub scopes: Vec<String>,
    /// Origins allowed to use the local activity bridge (§7.3).
    pub rpc_origins: Vec<String>,
    pub commands_version: i64,
    /// Command definitions with their ids (§5.1).
    #[schema(value_type = Vec<Object>)]
    pub commands: Vec<Value>,
    pub created_at: String,
}

/// The public document of a local application; `None` (→ `404 app.not_found`) for disabled, blocked or
/// deleted applications.
pub async fn document(state: &AppState, id: &str) -> Result<Option<PublicApplication>, ApiError> {
    if !util::is_ulid(id) {
        return Ok(None);
    }
    let Some(app) = store::applications::by_id(&state.db, id).await? else { return Ok(None) };
    let Some(bot) = store::users::by_id(&state.db, &app.bot_user_id).await? else { return Ok(None) };
    if apps::disabled_reason(state, &app, &bot).await?.is_some() {
        return Ok(None);
    }
    let owner = store::users::by_id(&state.db, &app.owner_id).await?.map(|o| o.address()).unwrap_or_default();
    let avatar_sha256 = match bot.avatar_blob_id.as_deref() {
        Some(media) => store::media::by_id(&state.db, media).await?.map(|m| m.still_sha256),
        None => None,
    };
    Ok(Some(PublicApplication {
        reference: apps::app_ref(state, &app.id),
        id: app.id.clone(),
        node: state.config.domain.clone(),
        name: app.name.clone(),
        description: app.description.clone(),
        bot: bot.address(),
        owner,
        public: app.public != 0,
        avatar: crate::models::media_url(bot.avatar_blob_id.as_deref(), false),
        avatar_sha256,
        requested_permissions: (app.requested_permissions as u64).to_string(),
        scopes: app.scopes(),
        rpc_origins: app.rpc_origins(),
        commands_version: app.commands_version,
        commands: crate::commands::values_of(
            &store::commands::of_app(&state.db, &apps::app_ref(state, &app.id)).await?,
        ),
        created_at: app.created_at.clone(),
    }))
}

/// Validates a document fetched from `domain` for the application `id`. Only `public`, `owner`, `bot`,
/// `requested_permissions` and `scopes` are used for authorization (§1.8); they must belong to `domain`.
pub fn parse_document(domain: &str, id: &str, body: &[u8]) -> Result<PublicApplication, &'static str> {
    let mut doc: PublicApplication = serde_json::from_slice(body).map_err(|_| "not an application document")?;
    if doc.id != id || doc.node != domain || doc.reference != format!("{domain}/{id}") {
        return Err("reference mismatch");
    }
    let of_domain =
        |address: &str| util::parse_address(address).is_some_and(|(name, d)| d == domain && util::valid_username(name));
    if !of_domain(&doc.bot) || !of_domain(&doc.owner) {
        return Err("bot or owner of another domain");
    }
    let perms = p::parse(&doc.requested_permissions).ok_or("requested_permissions invalid")?;
    if p::has(perms, p::ADMINISTRATOR) {
        return Err("requested_permissions with administrator");
    }
    let name = doc.name.trim();
    if name.is_empty() || name.chars().count() > NAME_MAX || name.chars().any(char::is_control) {
        return Err("name invalid");
    }
    doc.name = name.to_string();
    doc.description = doc.description.chars().take(400).collect();
    // Unknown (future) scopes are ignored here; tokens are checked by their home node.
    doc.scopes.retain(|s| p::is_scope(s));
    // Definitions this node cannot parse (e.g. newer argument types) are ignored (§10.1).
    doc.commands = crate::commands::parse_remote(&doc.commands)
        .into_iter()
        .filter_map(|v| {
            let mut value: Value = serde_json::from_str(&v.canonical).ok()?;
            value["id"] = json!(v.id);
            Some(value)
        })
        .collect();
    Ok(doc)
}

/// Fetches the public document of an application of another node (128 KiB cap, vetted client).
pub async fn fetch_document(state: &AppState, domain: &str, id: &str) -> Result<PublicApplication, ApiError> {
    crate::federation::check_policy(state, domain).await?;
    let path = format!("/api/v1/applications/{id}/public");
    match state.federation.get(domain, &path, Kind::Application).await {
        Ok(f) => parse_document(domain, id, &f.body)
            .map_err(|reason| crate::federation::discovery::peer_invalid(domain, reason)),
        Err(e) if e.status() == Some(404) => Err(apps::not_found()),
        Err(e) => Err(e.to_api()),
    }
}

// ---------------------------------------------------------------- resolving an application

/// An application as the room node sees it.
pub struct Resolved {
    pub reference: String,
    pub name: String,
    pub bot: UserRow,
    /// Owner address.
    pub owner: String,
    pub public: bool,
    pub requested_permissions: u64,
    /// Local applications only.
    pub local: Option<ApplicationRow>,
    /// Remote applications: the command definitions of the public document.
    pub commands: Vec<Value>,
}

/// Splits `<domain>/<ULID>` (`404 app.not_found` for anything else).
pub fn parse_ref(reference: &str) -> Result<(String, String), ApiError> {
    let (domain, id) = reference.trim().rsplit_once('/').ok_or_else(apps::not_found)?;
    let domain = domain.to_lowercase();
    if !util::valid_domain(&domain) || !util::is_ulid(id) {
        return Err(apps::not_found());
    }
    Ok((domain, id.to_string()))
}

/// Step 3 and 4 of §4.2: the application from the database or its home node, not blocked, not disabled.
pub async fn resolve(state: &AppState, reference: &str) -> Result<Resolved, ApiError> {
    let (domain, id) = parse_ref(reference)?;
    if domain == state.config.domain {
        let app = store::applications::by_id(&state.db, &id).await?.ok_or_else(apps::not_found)?;
        let bot = store::users::by_id(&state.db, &app.bot_user_id).await?.ok_or_else(apps::not_found)?;
        if store::applications::is_blocked(&state.db, &bot.address()).await? {
            return Err(blocked());
        }
        if let Some(reason) = apps::disabled_reason(state, &app, &bot).await? {
            return Err(apps::disabled(reason));
        }
        let owner = store::users::by_id(&state.db, &app.owner_id).await?.map(|o| o.address()).unwrap_or_default();
        return Ok(Resolved {
            reference: apps::app_ref(state, &app.id),
            name: app.name.clone(),
            owner,
            public: app.public != 0,
            requested_permissions: app.requested_permissions as u64,
            bot,
            local: Some(app),
            commands: Vec::new(),
        });
    }
    if !state.config.federation_enabled {
        return Err(crate::federation::disabled());
    }
    crate::federation::check_policy(state, &domain).await?;
    if !state.config.federation_remote_bots {
        return Err(crate::federation::remote::bots_refused());
    }
    let doc = fetch_document(state, &domain, &id).await?;
    if store::applications::is_blocked(&state.db, &doc.bot).await? {
        return Err(blocked());
    }
    let bot = remote_bot(state, &doc).await?;
    if bot.disabled_at.is_some() {
        return Err(apps::disabled("disabled"));
    }
    Ok(Resolved {
        reference: doc.reference.clone(),
        name: doc.name.clone(),
        owner: doc.owner.clone(),
        public: doc.public,
        requested_permissions: p::parse(&doc.requested_permissions).unwrap_or(0),
        bot,
        local: None,
        commands: doc.commands.clone(),
    })
}

/// The stub user of a remote bot (FEDERATION.md §2.6, `kind = bot`) with its owner stub, profile mirror,
/// owner address and application reference.
async fn remote_bot(state: &AppState, doc: &PublicApplication) -> Result<UserRow, ApiError> {
    let (name, domain) = util::parse_address(&doc.bot).ok_or_else(apps::not_found)?;
    let (owner_name, owner_domain) = util::parse_address(&doc.owner).ok_or_else(apps::not_found)?;
    if let Some(existing) = store::federation::user_by_address(&state.db, name, domain).await?
        && existing.kind != "bot"
    {
        return Err(crate::federation::discovery::peer_invalid(domain, "the bot address is a user"));
    }
    let owner = crate::federation::remote::ensure_remote_user(state, owner_name, owner_domain, "user", None).await?;
    let bot = crate::federation::remote::ensure_remote_user(state, name, domain, "bot", Some(&owner.id)).await?;
    store::applications::set_owner_address(&state.db, &bot.id, &doc.owner).await?;
    store::installations::set_bot_application(&state.db, &bot.id, &doc.reference).await?;
    match crate::federation::profiles::fetch(state, name, domain).await {
        Ok(profile) => crate::federation::profiles::apply(state, &bot, &profile).await?,
        Err(e) => tracing::info!(domain, result = e.code(), "bot profile not mirrored at install"),
    }
    Ok(store::users::by_id(&state.db, &bot.id).await?.unwrap_or(bot))
}

/// The application reference of a bot user (`<domain>/<ULID>`), `None` for users.
pub fn bot_ref(bot: &UserRow) -> Option<String> {
    let id = bot.application_id.as_deref()?;
    Some(if id.contains('/') { id.to_string() } else { format!("{}/{id}", bot.domain) })
}

// ---------------------------------------------------------------- installing (§4.2)

#[derive(Deserialize, ToSchema)]
pub struct InstallRequest {
    /// Application reference `<domain>/<id>`.
    pub application: String,
    /// Decimal mask, ⊆ the application's `requested_permissions`, never `administrator` (default "0").
    #[serde(default)]
    pub permissions: Option<String>,
    /// Create the managed role with the granted permissions (default true; needs `manage_roles`).
    #[serde(default)]
    pub create_role: Option<bool>,
}

/// The application of an installation as clients show it.
#[derive(Serialize, ToSchema)]
pub struct InstalledApplication {
    #[serde(rename = "ref")]
    pub reference: String,
    pub name: String,
    /// Path of the bot's avatar on this node.
    pub avatar: Option<String>,
}

/// An application installed in a room.
#[derive(Serialize, ToSchema)]
pub struct Installation {
    pub application: InstalledApplication,
    pub bot: User,
    /// The managed role (null when none was created or it was deleted).
    pub role_id: Option<String>,
    /// Granted permissions (decimal mask).
    pub permissions: String,
    /// Requested permissions the installer could not grant (only in the answer to the installation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_permissions: Option<String>,
    /// Installer's address.
    pub installed_by: String,
    pub installed_at: String,
    /// Commands of the application offered in this room: enabled (§5.3) and approved (§5.2).
    pub enabled_commands: i64,
}

async fn to_installation(
    state: &AppState,
    row: &store::installations::InstallationRow,
    dropped: Option<u64>,
) -> Result<Option<Installation>, ApiError> {
    let Some(bot) = store::users::by_id(&state.db, &row.bot_user_id).await? else { return Ok(None) };
    let role_id = match &row.role_id {
        Some(id) => store::rooms::role_by_id(&state.db, &row.room_id, id).await?.map(|r| r.id),
        None => None,
    };
    Ok(Some(Installation {
        application: InstalledApplication {
            reference: row.application_ref.clone(),
            name: bot.display_name.clone(),
            avatar: crate::models::media_url(bot.avatar_blob_id.as_deref(), false),
        },
        bot: bot.to_public(),
        role_id,
        permissions: (row.permissions as u64).to_string(),
        dropped_permissions: dropped.map(|d| d.to_string()),
        installed_by: row.installed_by.clone(),
        installed_at: row.installed_at.clone(),
        enabled_commands: crate::commands::enabled_count(state, &row.room_id, &row.application_ref).await?,
    }))
}

/// Room or node ban of the address or its domain.
async fn banned(state: &AppState, room_id: &str, address: &str) -> Result<bool, ApiError> {
    let domain = address.rsplit_once('@').map_or("", |(_, d)| d);
    store::rooms::is_banned(&state.db, Some(room_id), address, domain).await
}

/// A free role name: the application's name, `Name (2)`, `Name (3)`, …
fn role_name(name: &str, taken: &[String]) -> String {
    let base: String = name.chars().take(90).collect();
    let free = |n: &str| !taken.iter().any(|t| t.eq_ignore_ascii_case(n));
    if free(&base) {
        return base;
    }
    (2..1000).map(|i| format!("{base} ({i})")).find(|n| free(n)).unwrap_or(base)
}

/// `POST /rooms/{room_id}/applications` (§4.2): the nine checks in order, then the effects.
pub async fn install(
    state: &AppState,
    auth: &AuthUser,
    room_id: &str,
    req: InstallRequest,
) -> Result<Installation, ApiError> {
    // 1. manage_applications; bots never install bots.
    if auth.user.is_bot() || auth.app.is_some() {
        return Err(apps::bot_forbidden());
    }
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_manage_applications()?;
    // 2. no "no bots" room.
    if access.room.no_bots != 0 {
        return Err(ApiError::Forbidden { code: "app.room_no_bots", detail: "This room does not allow bots".into() });
    }
    // 3. + 4. the application (local or from its home node), not blocked, not disabled.
    let app = resolve(state, &req.application).await?;
    // 5. private applications only by their owner.
    if !app.public && app.owner != auth.user.address() {
        return Err(ApiError::Forbidden {
            code: "app.private",
            detail: "Only its owner can install this application".into(),
        });
    }
    // 6. bot, owner and their domains not banned.
    if banned(state, room_id, &app.bot.address()).await? {
        return Err(ApiError::Forbidden { code: "room.banned", detail: "This bot is banned from this room".into() });
    }
    if banned(state, room_id, &app.owner).await? {
        return Err(ApiError::Forbidden {
            code: "app.owner_banned",
            detail: "The owner of this application is banned from this room".into(),
        });
    }
    // 7. not installed yet, room limit.
    if store::installations::by_ref(&state.db, room_id, &app.reference).await?.is_some()
        || store::rooms::member(&state.db, room_id, &app.bot.id).await?.is_some()
    {
        return Err(ApiError::conflict("app.already_installed", "This application is installed in this room"));
    }
    let max = state.config.apps_per_room;
    if store::installations::count_of_room(&state.db, room_id).await? >= i64::from(max) {
        return Err(ApiError::Conflict {
            code: "app.room_limit",
            detail: format!("At most {max} applications per room"),
            meta: json!({ "max": max }),
        });
    }
    // 8. permissions ⊆ requested, never administrator; granted = permissions ∩ the caller's.
    let invalid = || bad("app.permissions_invalid", "permissions: a subset of the requested permissions");
    let wanted = p::parse(req.permissions.as_deref().unwrap_or("0").trim()).ok_or_else(invalid)?;
    if p::has(wanted, p::ADMINISTRATOR) || wanted & !app.requested_permissions != 0 {
        return Err(invalid());
    }
    let caller = if access.is_owner || access.is_node_admin { p::ALL } else { access.room_perms };
    let granted = wanted & caller;
    let dropped = wanted & !granted;
    // 9. the managed role needs manage_roles.
    let create_role = req.create_role.unwrap_or(true) && granted != 0;
    if create_role && !(access.is_owner || access.is_node_admin || access.has(p::MANAGE_ROLES)) {
        return Err(ApiError::Forbidden {
            code: "role.manage_forbidden",
            detail: "Managing roles is needed for the role".into(),
        });
    }

    let roles = store::rooms::roles(&state.db, room_id).await?;
    let role = if create_role {
        let taken: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();
        let highest = roles.iter().filter(|r| r.is_everyone == 0).map(|r| r.position).max().unwrap_or(0);
        // Directly below the caller's highest role; owners and node admins: above every role.
        let position = if access.is_owner || access.is_node_admin {
            highest + 1
        } else {
            access.member_roles.iter().map(|r| r.position).max().unwrap_or(1).max(1)
        };
        Some((role_name(&app.name, &taken), position))
    } else {
        None
    };
    let installed_by = auth.user.address();
    let installed = store::installations::install(
        &state.db,
        store::installations::NewInstallation {
            room_id,
            application_ref: &app.reference,
            bot_user_id: &app.bot.id,
            permissions: granted,
            installed_by: &installed_by,
            role: role.as_ref().map(|(n, pos)| (n.as_str(), *pos)),
        },
    )
    .await?
    .ok_or_else(|| ApiError::conflict("app.already_installed", "This application is installed in this room"))?;
    let row = &installed.installation;

    for id in &installed.shifted_roles {
        if let Some(r) = store::rooms::role_by_id(&state.db, room_id, id).await? {
            state.hub.room(room_id, "role.update", r.to_api());
        }
    }
    if let Some(rid) = &row.role_id
        && let Some(r) = store::rooms::role_by_id(&state.db, room_id, rid).await?
    {
        state.hub.room(room_id, "role.create", r.to_api());
    }
    state.hub.room(room_id, "member.join", json!({ "room_id": room_id, "user": app.bot.to_public() }));
    crate::welcome::joined(state, &access.room, &app.bot).await;
    store::rooms::audit(
        &state.db,
        Some(room_id),
        Some(&auth.user.id),
        "app.install",
        &app.bot.address(),
        "",
        json!({
            "application": app.reference, "owner": app.owner, "granted": granted.to_string(),
            "dropped": dropped.to_string(), "role": row.role_id,
        }),
    )
    .await?;
    tell_installed(state, &access.room, &app.bot, app.local.as_ref(), &installed_by).await;
    // A remote application's commands come with its document (§5.1); the room's palettes change.
    if app.local.is_none()
        && let Err(e) = crate::commands::store_remote(state, &app.reference, &app.commands).await
    {
        tracing::warn!(error = %e, "commands of a remote application not stored");
    }
    crate::commands::announce_room(state, room_id).await;
    tracing::info!(room = room_id, application = app.reference, "application installed");
    to_installation(state, row, Some(dropped)).await?.ok_or_else(apps::not_found)
}

/// The bot hears about its installation: locally `application.install` (and the install index), remotely
/// `app.install` to its home node. Failures are logged; the installation stands.
async fn tell_installed(
    state: &AppState,
    room: &Room,
    bot: &UserRow,
    local: Option<&ApplicationRow>,
    installed_by: &str,
) {
    let domain = state.config.domain.clone();
    let data = json!({ "room_id": room.id, "room_name": room.name, "node": domain, "installed_by": installed_by });
    if let Some(app) = local {
        if let Err(e) = store::installations::index_add(&state.db, &app.id, &domain, &room.id, &room.name).await {
            tracing::warn!(error = %e, "install index not updated");
        }
        state.hub.users(vec![bot.id.clone()], "application.install", &data);
        crate::subscriptions::application_event(state, &app.id, &room.id, "application.install", &data).await;
        return;
    }
    let name: String = room.name.chars().take(NAME_MAX).collect();
    let payload = json!({ "room": { "node": domain, "id": room.id, "name": name }, "installed_by": installed_by });
    if let Err(e) =
        crate::federation::outbox::enqueue(state, &bot.domain, KIND_INSTALL, &domain, &bot.address(), payload).await
    {
        tracing::warn!(error = %e, "app.install could not be queued");
    }
}

// ---------------------------------------------------------------- listing and uninstalling (§4.3)

pub async fn list(state: &AppState, auth: &AuthUser, room_id: &str) -> Result<Vec<Installation>, ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_view_applications()?;
    let mut out = Vec::new();
    for row in store::installations::of_room(&state.db, room_id).await? {
        if let Some(i) = to_installation(state, &row, None).await? {
            out.push(i);
        }
    }
    Ok(out)
}

/// `DELETE /rooms/{room_id}/applications/{application_ref}` (`manage_applications`).
pub async fn remove(state: &AppState, auth: &AuthUser, room_id: &str, reference: &str) -> Result<(), ApiError> {
    let access = access::room_access(state, room_id, &auth.user).await?;
    access.require_manage_applications()?;
    let row = store::installations::by_ref(&state.db, room_id, reference.trim()).await?.ok_or_else(not_installed)?;
    let bot = store::users::by_id(&state.db, &row.bot_user_id).await?.ok_or_else(not_installed)?;
    if !remove_member(state, &access.room, &bot, "removed", Some(&auth.user.id)).await? {
        // Not a member any more (left in between): the installation goes anyway.
        uninstalled(state, &access.room, &bot, "removed", Some(&auth.user.id)).await?;
    }
    Ok(())
}

/// Removes a bot from a room (`member.leave`, `mls.remove_needed`, welcome entry) and uninstalls it.
/// `false` if it was not a member.
pub async fn remove_member(
    state: &AppState,
    room: &Room,
    bot: &UserRow,
    reason: &str,
    actor_id: Option<&str>,
) -> Result<bool, ApiError> {
    let member = store::rooms::member(&state.db, &room.id, &bot.id).await?;
    if !store::rooms::remove_member(&state.db, &room.id, &bot.id).await? {
        return Ok(false);
    }
    let kind = if matches!(reason, "owner_banned" | "banned" | "blocked") {
        crate::welcome::LeaveKind::Ban
    } else {
        crate::welcome::LeaveKind::Kick
    };
    crate::welcome::membership_ended(state, room, bot, member.as_ref(), kind).await;
    let data = json!({ "room_id": room.id, "user_id": bot.id, "kicked": true, "reason": reason });
    crate::subscriptions::room_event(state, &room.id, "member.leave", &data).await;
    state.hub.users(vec![bot.id.clone()], "member.leave", &data);
    crate::e2ee::user_left_room(state, &room.id, bot).await?;
    uninstalled(state, room, bot, reason, actor_id).await?;
    Ok(true)
}

/// After a bot left a room by any path (removal, kick, ban, leave, "no bots", block, deletion): the
/// managed role and the installation row go, `app.uninstall` is audited and the bot is told. No-op for
/// users.
pub async fn uninstalled(
    state: &AppState,
    room: &Room,
    bot: &UserRow,
    reason: &str,
    actor_id: Option<&str>,
) -> Result<(), ApiError> {
    if !bot.is_bot() {
        return Ok(());
    }
    let row = store::installations::by_bot(&state.db, &room.id, &bot.id).await?;
    let mut role = None;
    if let Some(row) = &row {
        if let Some(rid) = &row.role_id
            && store::rooms::delete_role(&state.db, &room.id, rid).await?
        {
            state.hub.room(&room.id, "role.delete", json!({ "room_id": room.id, "id": rid }));
            role = Some(rid.clone());
        }
        store::installations::delete(&state.db, &row.id).await?;
        // The room's command settings for the application go with it (§4.3); a remote application's cached
        // definitions go when it is installed nowhere on this node any more.
        store::commands::delete_settings_of_app(&state.db, &room.id, &row.application_ref).await?;
        if bot.domain != state.config.domain {
            store::commands::forget_unused(&state.db, &row.application_ref).await?;
        }
        crate::commands::announce_room(state, &room.id).await;
    }
    let reference = row.as_ref().map(|r| r.application_ref.clone()).or_else(|| bot_ref(bot));
    store::rooms::audit(
        &state.db,
        Some(&room.id),
        actor_id,
        "app.uninstall",
        &bot.address(),
        "",
        json!({ "reason": reason, "application": reference, "owner": bot.owner_address, "role": role }),
    )
    .await?;
    tell_uninstalled(state, room, bot, reason).await;
    Ok(())
}

async fn tell_uninstalled(state: &AppState, room: &Room, bot: &UserRow, reason: &str) {
    let domain = state.config.domain.clone();
    if bot.domain == domain {
        if let Some(app_id) = bot.application_id.as_deref()
            && let Err(e) = store::installations::index_remove(&state.db, app_id, &domain, &room.id).await
        {
            tracing::warn!(error = %e, "install index not updated");
        }
        let data = json!({ "room_id": room.id, "node": domain, "reason": reason });
        state.hub.users(vec![bot.id.clone()], "application.uninstall", &data);
        if let Some(app_id) = bot.application_id.as_deref() {
            crate::subscriptions::application_event(state, app_id, &room.id, "application.uninstall", &data).await;
        }
        return;
    }
    // A deleted application has nobody left to tell.
    if reason == "deleted" {
        return;
    }
    let payload = json!({ "room": { "node": domain, "id": room.id }, "reason": reason });
    if let Err(e) =
        crate::federation::outbox::enqueue(state, &bot.domain, KIND_UNINSTALL, &domain, &bot.address(), payload).await
    {
        tracing::warn!(error = %e, "app.uninstall could not be queued");
    }
}

/// Removes a bot from every room of this node (`reason`: `blocked`, `deleted`). Returns the number.
pub async fn remove_everywhere(
    state: &AppState,
    bot: &UserRow,
    reason: &str,
    actor_id: Option<&str>,
) -> Result<usize, ApiError> {
    let mut removed = 0;
    for room_id in store::rooms::room_ids_of_user(&state.db, &bot.id).await? {
        if let Some(room) = store::rooms::room_by_id(&state.db, &room_id).await?
            && remove_member(state, &room, bot, reason, actor_id).await?
        {
            removed += 1;
        }
    }
    // Installations without a membership (left in between) go as well.
    for room_id in store::installations::rooms_of_bot(&state.db, &bot.id).await? {
        if let Some(room) = store::rooms::room_by_id(&state.db, &room_id).await? {
            uninstalled(state, &room, bot, reason, actor_id).await?;
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------- home node: app.changed (§4.5)

/// `app.changed` to every other node in the install index (name, avatar, scopes, requested permissions or
/// commands changed, or `deleted`). Failures are logged.
pub async fn changed(state: &AppState, app: &ApplicationRow, deleted: bool) {
    let nodes = match store::installations::index_nodes(&state.db, &app.id, &state.config.domain).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "install index not readable");
            return;
        }
    };
    let Ok(Some(bot)) = store::users::by_id(&state.db, &app.bot_user_id).await else { return };
    let payload = json!({ "application_id": app.id, "commands_version": app.commands_version, "deleted": deleted });
    for node in nodes {
        if let Err(e) =
            crate::federation::outbox::enqueue(state, &node, KIND_CHANGED, &bot.address(), &node, payload.clone()).await
        {
            tracing::warn!(error = %e, node, "app.changed could not be queued");
        }
    }
}

// ---------------------------------------------------------------- inbox handlers (§4.5)

/// A parsed `app.*` inbox message.
pub enum Incoming {
    Install { room_id: String, room_name: String, installed_by: String },
    Uninstall { room_id: String, reason: String },
    Changed { application_id: String, deleted: bool },
}

fn envelope_invalid(detail: &str) -> ApiError {
    ApiError::BadRequest { code: "federation.envelope_invalid", detail: detail.into() }
}

/// Validates the payload of an `app.*` type sent by `iss`; `None` for other types.
pub fn parse(kind: &str, iss: &str, payload: &Value) -> Result<Option<Incoming>, ApiError> {
    let room = || -> Result<String, ApiError> {
        let node = payload.pointer("/room/node").and_then(Value::as_str).unwrap_or("");
        if node != iss {
            return Err(envelope_invalid("payload.room.node must be the sender"));
        }
        let id = payload.pointer("/room/id").and_then(Value::as_str).unwrap_or("");
        if !util::is_ulid(id) {
            return Err(envelope_invalid("payload.room.id invalid"));
        }
        Ok(id.to_string())
    };
    Ok(Some(match kind {
        KIND_INSTALL => {
            let room_id = room()?;
            let name = payload.pointer("/room/name").and_then(Value::as_str).unwrap_or("");
            let room_name: String = name.chars().filter(|c| !c.is_control()).take(NAME_MAX).collect();
            let installed_by = payload.get("installed_by").and_then(Value::as_str).unwrap_or("");
            if util::parse_address(installed_by).is_none() || installed_by.len() > 320 {
                return Err(envelope_invalid("payload.installed_by invalid"));
            }
            Incoming::Install { room_id, room_name, installed_by: installed_by.to_string() }
        }
        KIND_UNINSTALL => {
            let room_id = room()?;
            let reason = payload.get("reason").and_then(Value::as_str).unwrap_or("removed");
            let reason = if REASONS.contains(&reason) { reason } else { "removed" };
            Incoming::Uninstall { room_id, reason: reason.to_string() }
        }
        KIND_CHANGED => {
            let id = payload.get("application_id").and_then(Value::as_str).unwrap_or("");
            if !util::is_ulid(id) {
                return Err(envelope_invalid("payload.application_id invalid"));
            }
            let deleted = payload.get("deleted").and_then(Value::as_bool).unwrap_or(false);
            Incoming::Changed { application_id: id.to_string(), deleted }
        }
        _ => return Ok(None),
    }))
}

/// `app.install` / `app.uninstall` to a bot of this node (H): the bot must exist with an enabled
/// application (`404 federation.recipient_unknown`).
pub async fn handle_for_bot(
    state: &AppState,
    iss: &str,
    bot: &UserRow,
    incoming: Incoming,
) -> Result<&'static str, ApiError> {
    let unknown = || ApiError::NotFound { code: "federation.recipient_unknown", what: "Bot".into() };
    if !bot.is_bot() {
        return Err(unknown());
    }
    let app = store::applications::by_bot(&state.db, &bot.id).await?.ok_or_else(unknown)?;
    match incoming {
        Incoming::Install { room_id, room_name, installed_by } => {
            if apps::disabled_reason(state, &app, bot).await?.is_some() {
                return Err(unknown());
            }
            // Other nodes cannot grow the index without bound (DoS).
            if store::installations::index_count(&state.db, &app.id).await? >= MAX_INDEX_ENTRIES {
                tracing::warn!(sender = iss, application = app.id, "install index full, app.install ignored");
                return Ok("ignored");
            }
            store::installations::index_add(&state.db, &app.id, iss, &room_id, &room_name).await?;
            state.hub.users(
                vec![bot.id.clone()],
                "application.install",
                json!({ "room_id": room_id, "room_name": room_name, "node": iss, "installed_by": installed_by }),
            );
            Ok("handled")
        }
        Incoming::Uninstall { room_id, reason } => {
            store::installations::index_remove(&state.db, &app.id, iss, &room_id).await?;
            state.hub.users(
                vec![bot.id.clone()],
                "application.uninstall",
                json!({ "room_id": room_id, "node": iss, "reason": reason }),
            );
            Ok("handled")
        }
        Incoming::Changed { .. } => Ok("ignored"),
    }
}

/// `app.changed` from the bot's home node (`from` = the bot, a user of `iss`): refetch the profile, or on
/// deletion uninstall the bot from every room of this node and refuse it from now on.
pub async fn handle_changed(
    state: &AppState,
    iss: &str,
    bot: Option<UserRow>,
    incoming: Incoming,
) -> Result<&'static str, ApiError> {
    let Incoming::Changed { application_id, deleted } = incoming else { return Ok("ignored") };
    let Some(bot) = bot else { return Ok("no_local_state") };
    // Only a bot this node knows as the application named in the message.
    if !bot.is_bot() || bot_ref(&bot).as_deref() != Some(format!("{iss}/{application_id}").as_str()) {
        return Ok("no_local_state");
    }
    if deleted {
        remove_everywhere(state, &bot, "deleted", None).await?;
        store::commands::forget_unused(&state.db, &format!("{iss}/{application_id}")).await?;
        store::installations::disable_remote_bot(&state.db, &bot.id).await?;
        let devices = store::federation::revoke_remote_sessions(&state.db, &bot.id, None).await?;
        apps::close_devices(state, devices);
        return Ok("handled");
    }
    match crate::federation::profiles::fetch(state, &bot.username, &bot.domain).await {
        Ok(profile) => crate::federation::profiles::apply(state, &bot, &profile).await?,
        Err(e) => tracing::info!(domain = bot.domain, result = e.code(), "bot profile not refreshed after app.changed"),
    }
    // The commands (§5.1): only while the application is installed here.
    let reference = format!("{iss}/{application_id}");
    if !store::commands::rooms_of_app(&state.db, &reference).await?.is_empty() {
        match fetch_document(state, iss, &application_id).await {
            Ok(doc) => crate::commands::store_remote(state, &reference, &doc.commands).await?,
            Err(e) => tracing::info!(domain = iss, result = e.code(), "commands not refreshed after app.changed"),
        }
    }
    if let Some(updated) = store::users::by_id(&state.db, &bot.id).await? {
        let rooms = store::rooms::room_ids_of_user(&state.db, &bot.id).await?;
        for room_id in rooms {
            state.hub.room(&room_id, "user.update", serde_json::json!({ "user": updated.to_public() }));
        }
    }
    Ok("handled")
}

// ---------------------------------------------------------------- node-level controls (§4.4)

/// Blocks a bot address on this node: removes it from every room (`reason: blocked`), ends its sessions.
pub async fn block(state: &AppState, admin: &UserRow, address: &str, reason: &str) -> Result<usize, ApiError> {
    store::installations::add_block(&state.db, address, reason, &admin.id).await?;
    let mut removed = 0;
    if let Some((name, domain)) = util::parse_address(address)
        && let Some(bot) = store::federation::user_by_address(&state.db, name, domain).await?
        && bot.is_bot()
    {
        removed = remove_everywhere(state, &bot, "blocked", Some(&admin.id)).await?;
        if bot.domain == state.config.domain {
            apps::close_bot(state, &bot.id).await?;
            crate::federation::remote::revoke_sessions(state, &bot, None).await?;
        } else {
            let devices = store::federation::revoke_remote_sessions(&state.db, &bot.id, None).await?;
            apps::close_devices(state, devices);
        }
    }
    store::rooms::audit(
        &state.db,
        None,
        Some(&admin.id),
        "admin.app_block",
        address,
        reason,
        json!({ "bots_removed": removed }),
    )
    .await?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn doc(over: Value) -> Vec<u8> {
        let id = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";
        let mut v = json!({
            "ref": format!("h.test/{id}"), "id": id, "node": "h.test", "name": " Weather ", "description": "d",
            "bot": "weather@h.test", "owner": "alice@h.test", "public": true, "avatar": null, "avatar_sha256": null,
            "requested_permissions": "3", "scopes": ["messages:read", "future:scope"], "rpc_origins": [],
            "commands_version": 0, "commands": [{ "x": 1 }], "created_at": "2026-10-05T12:00:00Z",
        });
        if let (Some(m), Some(o)) = (v.as_object_mut(), over.as_object()) {
            m.extend(o.clone());
        }
        serde_json::to_vec(&v).unwrap()
    }

    const ID: &str = "01J9ZZZZZZZZZZZZZZZZZZZZZZ";

    #[test]
    fn documents_are_bound_to_their_domain() {
        let d = parse_document("h.test", ID, &doc(json!({}))).unwrap();
        assert_eq!(d.name, "Weather");
        let command = json!({ "id": ID, "name": "w", "description": "Weather", "args": [] });
        let with = parse_document("h.test", ID, &doc(json!({ "commands": [command, { "x": 1 }] }))).unwrap();
        assert_eq!(with.commands.len(), 1, "unparseable definitions are ignored");
        assert_eq!(with.commands[0]["id"], ID);
        assert_eq!(d.scopes, vec!["messages:read".to_string()], "unknown scopes are ignored");
        assert!(d.commands.is_empty());
        for (over, why) in [
            (json!({ "bot": "weather@evil.test" }), "bot of another domain"),
            (json!({ "owner": "mallory@evil.test" }), "owner of another domain"),
            (json!({ "node": "evil.test" }), "node"),
            (json!({ "ref": format!("evil.test/{ID}") }), "ref"),
            (json!({ "id": "01J9YYYYYYYYYYYYYYYYYYYYYY" }), "id"),
            (json!({ "requested_permissions": "4611686018427387904" }), "administrator"),
            (json!({ "requested_permissions": "x" }), "mask"),
            (json!({ "name": "" }), "empty name"),
            (json!({ "public": "yes" }), "type"),
        ] {
            assert!(parse_document("h.test", ID, &doc(over)).is_err(), "{why}");
        }
        assert!(parse_document("h.test", ID, b"not json").is_err());
    }

    #[test]
    fn references_and_role_names() {
        assert_eq!(parse_ref(&format!("H.test/{ID}")).unwrap(), ("h.test".into(), ID.into()));
        for bad in ["", ID, "h.test/", "h.test/x", "../x", &format!("h test/{ID}")] {
            assert_eq!(parse_ref(bad).unwrap_err().code(), "app.not_found", "{bad}");
        }
        let taken = vec!["Weather".to_string(), "weather (2)".to_string()];
        assert_eq!(role_name("Weather", &taken), "Weather (3)");
        assert_eq!(role_name("Other", &taken), "Other");
    }

    #[test]
    fn inbox_payloads_are_checked() {
        let room = json!({ "node": "t.test", "id": util::ulid(), "name": "Lobby" });
        let ok = json!({ "room": room, "installed_by": "carol@t.test" });
        assert!(matches!(parse(KIND_INSTALL, "t.test", &ok).unwrap(), Some(Incoming::Install { .. })));
        assert_eq!(parse(KIND_INSTALL, "evil.test", &ok).err().unwrap().code(), "federation.envelope_invalid");
        let bad_room = json!({ "room": { "node": "t.test", "id": "x" }, "installed_by": "carol@t.test" });
        assert!(parse(KIND_INSTALL, "t.test", &bad_room).is_err());
        let no_installer = json!({ "room": room });
        assert!(parse(KIND_INSTALL, "t.test", &no_installer).is_err());
        let un = json!({ "room": room, "reason": "<script>" });
        assert!(
            matches!(parse(KIND_UNINSTALL, "t.test", &un).unwrap(), Some(Incoming::Uninstall { reason, .. }) if reason == "removed")
        );
        assert!(parse(KIND_CHANGED, "h.test", &json!({ "application_id": "x" })).is_err());
        assert!(matches!(
            parse(KIND_CHANGED, "h.test", &json!({ "application_id": ID, "deleted": true })).unwrap(),
            Some(Incoming::Changed { deleted: true, .. })
        ));
        assert!(parse("friend.request", "h.test", &json!({})).unwrap().is_none());
    }
}
