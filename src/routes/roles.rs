// SPDX-License-Identifier: AGPL-3.0-only
//! A room's roles.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    access,
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    models::Role,
    permissions as p, store,
    validate::{self, bad},
};

#[derive(Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub color: Option<String>,
    pub position: Option<i64>,
    /// Bitmask as a decimal string
    pub permissions: Option<String>,
    /// Shown as its own group in the member list.
    pub hoist: Option<bool>,
    pub mentionable: Option<bool>,
    /// Upload categories (protocol/PROTOCOL.md §7a); absent or null = not set (inherit).
    pub allowed_upload_categories: Option<Vec<String>>,
}

/// Parses upload category names (`role.upload_categories_invalid`).
pub fn upload_categories(list: &[String]) -> Result<u64, ApiError> {
    if list.len() > crate::uploads::NAMES.len() * 2 {
        return Err(bad("role.upload_categories_invalid", "Too many upload categories"));
    }
    crate::uploads::parse_names(list).ok_or_else(|| {
        bad("role.upload_categories_invalid", "Upload categories: images, audio, video, documents, archives, other")
    })
}

/// `@everyone` can never hold management-class permissions (protocol/permissions.md).
pub fn check_everyone(permissions: u64) -> Result<(), ApiError> {
    let restricted = permissions & p::EVERYONE_RESTRICTED;
    if restricted == 0 {
        return Ok(());
    }
    Err(ApiError::BadRequest {
        code: "role.everyone_restricted",
        detail: format!("These permissions cannot be granted to @everyone: {}", p::names(restricted).join(", ")),
    })
}

/// Checks that granted permissions and position stay below the actor's (no privilege escalation).
fn check_grant(access: &access::RoomAccess, permissions: u64, position: i64) -> Result<(), ApiError> {
    if access.is_owner || access.is_node_admin {
        return Ok(());
    }
    if permissions & !access.room_perms != 0 {
        return Err(ApiError::Forbidden {
            code: "role.escalation",
            detail: "You can only grant permissions you have yourself".into(),
        });
    }
    if !access.outranks(position) {
        return Err(ApiError::Forbidden {
            code: "role.hierarchy",
            detail: "The position must be below your highest role".into(),
        });
    }
    Ok(())
}

/// Create a role (`manage_roles`).
#[utoipa::path(post, path = "/api/v1/rooms/{room_id}/roles", security(("bearer" = [])), params(("room_id" = String, Path)), request_body = CreateRoleRequest, responses((status = 201, body = Role), (status = 403, body = ProblemDetails)))]
pub async fn create_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(room_id): Path<String>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<Role>), ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
    let name = validate::name("name", &req.name, 100)?;
    if name == "@everyone" {
        return Err(bad("role.name_reserved", "This name is reserved"));
    }
    let color = req.color.as_deref().map(validate::color).transpose()?;
    let permissions =
        req.permissions.as_deref().map(|s| validate::permissions("permissions", s)).transpose()?.unwrap_or(0);
    let position = validate::range("position", req.position.unwrap_or(1), 1, 10_000)?;
    let upload = req.allowed_upload_categories.as_deref().map(upload_categories).transpose()?;
    check_grant(&access, permissions, position)?;
    let id = store::rooms::create_role(
        &state.db,
        &room_id,
        store::rooms::NewRole {
            name: &name,
            color: color.as_deref(),
            position,
            permissions,
            hoist: req.hoist.unwrap_or(false),
            mentionable: req.mentionable.unwrap_or(false),
            upload_categories: upload,
        },
    )
    .await?;
    let role = store::rooms::role_by_id(&state.db, &room_id, &id)
        .await?
        .ok_or_else(|| access::not_found("Role", "role.not_found"))?
        .to_api();
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "role.create",
        &id,
        "",
        serde_json::json!({ "name": name, "permissions": permissions.to_string() }),
    )
    .await?;
    state.hub.room(&room_id, "role.create", &role);
    Ok((StatusCode::CREATED, Json(role)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    #[serde(default, with = "crate::serde_with_double_option")]
    pub color: Option<Option<String>>,
    pub position: Option<i64>,
    pub permissions: Option<String>,
    pub hoist: Option<bool>,
    pub mentionable: Option<bool>,
    /// Upload categories; null clears the setting (inherit; not for `@everyone`).
    #[serde(default, with = "crate::serde_with_double_option")]
    pub allowed_upload_categories: Option<Option<Vec<String>>>,
}

/// Update a role (`manage_roles`). `@everyone` allows only permissions.
#[utoipa::path(patch, path = "/api/v1/rooms/{room_id}/roles/{role_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("role_id" = String, Path)), request_body = UpdateRoleRequest, responses((status = 200, body = Role)))]
pub async fn update_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, role_id)): Path<(String, String)>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<Role>, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
    let current = store::rooms::role_by_id(&state.db, &room_id, &role_id)
        .await?
        .ok_or_else(|| access::not_found("Role", "role.not_found"))?;
    if current.is_everyone == 0 && !access.outranks(current.position) {
        return Err(ApiError::Forbidden {
            code: "role.hierarchy",
            detail: "The role is above your highest role".into(),
        });
    }
    let everyone = current.is_everyone != 0;
    let name = if everyone { None } else { req.name.as_deref().map(|n| validate::name("name", n, 100)).transpose()? };
    if name.as_deref() == Some("@everyone") {
        return Err(bad("role.name_reserved", "This name is reserved"));
    }
    let color = if everyone {
        None
    } else {
        req.color.as_ref().map(|c| c.as_deref().map(validate::color).transpose()).transpose()?
    };
    let position =
        if everyone { None } else { req.position.map(|p| validate::range("position", p, 1, 10_000)).transpose()? };
    let permissions = req.permissions.as_deref().map(|s| validate::permissions("permissions", s)).transpose()?;
    check_grant(&access, permissions.unwrap_or(0), position.unwrap_or(current.position))?;
    if everyone && let Some(perms) = permissions {
        check_everyone(perms)?;
    }
    let upload = match &req.allowed_upload_categories {
        None => None,
        Some(None) if everyone => {
            return Err(bad("role.upload_categories_invalid", "@everyone always has upload categories"));
        }
        Some(None) => Some(None),
        Some(Some(list)) => Some(Some(upload_categories(list)?)),
    };
    store::rooms::update_role(
        &state.db,
        &room_id,
        &role_id,
        store::rooms::RoleUpdate {
            name: name.as_deref(),
            color: color.as_ref().map(|c| c.as_deref()),
            position,
            permissions,
            hoist: if everyone { None } else { req.hoist },
            mentionable: req.mentionable,
            upload_categories: upload,
        },
    )
    .await?;
    let role = store::rooms::role_by_id(&state.db, &room_id, &role_id)
        .await?
        .ok_or_else(|| access::not_found("Role", "role.not_found"))?
        .to_api();
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "role.update",
        &role_id,
        "",
        serde_json::json!({ "permissions": role.permissions, "hoist": role.hoist, "upload_categories": role.allowed_upload_categories }),
    )
    .await?;
    state.hub.room(&room_id, "role.update", &role);
    Ok(Json(role))
}

/// Delete a role (`manage_roles`), not `@everyone`.
#[utoipa::path(delete, path = "/api/v1/rooms/{room_id}/roles/{role_id}", security(("bearer" = [])), params(("room_id" = String, Path), ("role_id" = String, Path)), responses((status = 204)))]
pub async fn delete_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((room_id, role_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let access = access::room_access(&state, &room_id, &auth.user).await?;
    access.require(p::MANAGE_ROLES, "role.manage_forbidden", "Manage roles")?;
    let current = store::rooms::role_by_id(&state.db, &room_id, &role_id)
        .await?
        .ok_or_else(|| access::not_found("Role", "role.not_found"))?;
    if current.is_everyone != 0 {
        return Err(bad("role.everyone_protected", "@everyone cannot be deleted"));
    }
    if !access.outranks(current.position) {
        return Err(ApiError::Forbidden {
            code: "role.hierarchy",
            detail: "The role is above your highest role".into(),
        });
    }
    store::rooms::delete_role(&state.db, &room_id, &role_id).await?;
    store::rooms::audit(
        &state.db,
        Some(&room_id),
        Some(&auth.user.id),
        "role.delete",
        &role_id,
        "",
        serde_json::json!({ "name": current.name }),
    )
    .await?;
    state.hub.room(&room_id, "role.delete", serde_json::json!({ "room_id": room_id, "id": role_id }));
    Ok(StatusCode::NO_CONTENT)
}
