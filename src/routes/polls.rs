// SPDX-License-Identifier: AGPL-3.0-only
//! Poll vote records (protocol PROTOCOL.md §7g): one encrypted (or plaintext, signed) vote per member and poll on the
//! node hosting the conversation. Votes are no messages: they never count as unread, never notify and go with their
//! message.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::{
    access::{self, Conv, ConvKind},
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ProblemDetails},
    models::MessageRow,
    permissions as p, polls, store,
    store::polls::VoteRow,
    validate::bad,
};

/// A member's vote on a poll (PROTOCOL.md §7g).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PollVote {
    pub conversation_id: String,
    pub message_id: String,
    /// The voter, `username@domain`.
    pub user: String,
    pub user_id: String,
    /// The device that voted last (public device id).
    pub device_id: Option<String>,
    /// Encrypted conversations: the MLS epoch of `content`.
    pub epoch: Option<i64>,
    /// Encrypted: content format 1 (base64url, ENCRYPTION.md §5.2) of the `poll.vote` object. Plaintext: the
    /// `poll.vote` object.
    #[schema(value_type = Value)]
    pub content: Value,
    /// Plaintext only: the voting device's signature (FEDERATION.md §10.3), as sent.
    pub signature: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<VoteRow> for PollVote {
    fn from(r: VoteRow) -> Self {
        // Encrypted votes always carry their epoch; plaintext votes are stored as their JSON object.
        let content = if r.epoch.is_some() {
            Value::String(r.content)
        } else {
            serde_json::from_str(&r.content).unwrap_or(Value::Null)
        };
        PollVote {
            conversation_id: r.conversation_id,
            message_id: r.message_id,
            user: format!("{}@{}", r.username, r.domain),
            user_id: r.user_id,
            device_id: r.device_id,
            epoch: r.epoch,
            content,
            signature: r.signature,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PollVoteList {
    /// Every vote of the poll, oldest first (at most one per member).
    pub items: Vec<PollVote>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PollVoteRequest {
    /// Encrypted conversations: content format 1 (base64url) of the `poll.vote` object under the current epoch.
    /// Plaintext conversations: the `poll.vote` object. At most 4 KiB.
    #[schema(value_type = Value)]
    pub content: Value,
    /// MLS epoch of `content` (encrypted only).
    pub epoch: Option<i64>,
    /// Plaintext only: device signature `base64url(nonce(16) || Ed25519 signature(64))` (FEDERATION.md §10.3) with
    /// empty reply and thread, no mentions and no attachments.
    pub signature: Option<String>,
}

fn not_a_poll() -> ApiError {
    bad("poll.not_a_poll", "The message is not a poll")
}

/// The poll message: in this conversation and inside the requester's history window (ENCRYPTION.md §7b).
async fn poll_message(
    state: &AppState,
    auth: &AuthUser,
    conv: &Conv,
    message_id: &str,
) -> Result<MessageRow, ApiError> {
    conv.require(p::VIEW_CHANNEL, "channel.view_forbidden", "View channel")?;
    let message = store::messages::by_id(&state.db, message_id)
        .await?
        .filter(|m| m.conversation_id == conv.id)
        .ok_or_else(|| access::not_found("Message", "message.not_found"))?;
    if message.encrypted != 0
        && let Some(cut) = crate::history::list_cutoff(state, conv, &auth.user).await?
        && message.id.as_str() < cut.as_str()
    {
        return Err(access::not_found("Message", "message.not_found"));
    }
    Ok(message)
}

/// Checks for changing a vote: member (room channels), DM rules, no timeout, an open poll, the rate limit.
async fn check_change(state: &AppState, auth: &AuthUser, conv: &Conv, message: &MessageRow) -> Result<(), ApiError> {
    if let ConvKind::Channel { access, .. } = &conv.kind {
        if access.member.is_none() {
            return Err(ApiError::Forbidden { code: "room.not_member", detail: "Only members can vote".into() });
        }
        if !access.is_owner
            && !access.is_node_admin
            && access.member.as_ref().is_some_and(crate::models::MemberRow::is_timed_out)
        {
            return Err(ApiError::Forbidden {
                code: "member.timed_out",
                detail: "Members in timeout cannot vote".into(),
            });
        }
    }
    crate::routes::messages::check_direct_write(state, auth, conv).await?;
    // System and webhook messages (no device) are never polls.
    if message.device_id.is_none() {
        return Err(not_a_poll());
    }
    if polls::is_closed(message.poll_closes_at.as_deref(), chrono::Utc::now()) {
        return Err(polls::closed());
    }
    state.poll_vote_limiter.check_all(&[format!("poll-vote:{}", auth.user.id)]).await
}

fn too_large() -> ApiError {
    ApiError::PayloadTooLarge {
        code: "poll.vote_too_large",
        detail: format!("A vote is at most {} bytes", polls::MAX_VOTE_BYTES),
        meta: serde_json::json!({ "max_bytes": polls::MAX_VOTE_BYTES }),
    }
}

/// Cast or change a vote.
#[utoipa::path(put, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}/poll/vote", security(("bearer" = [])),
    params(("conversation_id" = String, Path), ("message_id" = String, Path)), request_body = PollVoteRequest,
    description = "Creates or replaces the caller's vote on a poll (PROTOCOL.md §7g): one record per user and poll, the last device to vote wins. Encrypted conversations take content format 1 under the current epoch (the checks of ENCRYPTION.md §5.3); plaintext conversations take the vote object, checked against the poll, and an optional device signature. Needs membership and `view_channel`; refused after the poll's close time (`409 poll.closed`); at most 10 vote changes per user and minute. Event `poll.vote`.",
    responses((status = 200, body = PollVote), (status = 400, body = ProblemDetails), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 413, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn put_poll_vote(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
    Json(req): Json<PollVoteRequest>,
) -> Result<Json<PollVote>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    let message = poll_message(&state, &auth, &conv, &message_id).await?;
    check_change(&state, &auth, &conv, &message).await?;
    let (content, epoch, signature) = if conv.encrypted {
        let Value::String(ciphertext) = &req.content else {
            return Err(bad(
                "message.encryption_mismatch",
                "This conversation is encrypted; plaintext is not accepted",
            ));
        };
        if ciphertext.len() > polls::MAX_VOTE_BYTES {
            return Err(too_large());
        }
        if req.signature.is_some() {
            return Err(bad(
                "message.signature_invalid",
                "Only plaintext votes carry a signature field (encrypted content is signed inside)",
            ));
        }
        let v = crate::routes::messages::validate_content(&[], true, &req.content, &[])?;
        let epoch = crate::routes::messages::check_ciphertext(&state, &auth, &conv.id, &v.content, req.epoch).await?;
        (v.content, Some(epoch), None)
    } else {
        if !req.content.is_object() {
            return Err(bad(
                "message.encryption_mismatch",
                "This conversation is unencrypted; ciphertext is not accepted",
            ));
        }
        let json = serde_json::to_string(&req.content).map_err(|e| ApiError::Internal(e.into()))?;
        if json.len() > polls::MAX_VOTE_BYTES {
            return Err(too_large());
        }
        // The poll must be a plaintext poll the node can read; the vote must fit it (PROTOCOL.md §7g).
        let poll: Value = if message.encrypted == 0 {
            serde_json::from_str(&message.content).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        if poll.get("type").and_then(Value::as_str) != Some(polls::POLL_TYPE) {
            return Err(not_a_poll());
        }
        polls::validate_vote(&req.content, &poll, &message.id)?;
        if let Some(s) = req.signature.as_deref()
            && tavrn_crypto::PlaintextSignature::parse(s).is_err()
        {
            return Err(bad("message.signature_invalid", "signature must be base64url (no padding) of 80 bytes"));
        }
        (json, None, req.signature.clone())
    };
    let row = store::polls::upsert(
        &state.db,
        store::polls::NewVote {
            message_id: &message.id,
            conversation_id: &conv.id,
            user_id: &auth.user.id,
            device_id: Some(auth.public_device_id()),
            epoch,
            content: &content,
            signature: signature.as_deref(),
        },
    )
    .await?;
    let vote = PollVote::from(row);
    conv.publish(&state.hub, "poll.vote", &vote);
    Ok(Json(vote))
}

/// Retract a vote.
#[utoipa::path(delete, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}/poll/vote", security(("bearer" = [])),
    params(("conversation_id" = String, Path), ("message_id" = String, Path)),
    description = "Retracts the caller's vote on a poll (PROTOCOL.md §7g), until the poll's close time (`409 poll.closed`); `404 poll.vote_not_found` without a vote. Counts towards the 10 vote changes per user and minute. Event `poll.vote.delete`.",
    responses((status = 204), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails), (status = 409, body = ProblemDetails), (status = 429, body = ProblemDetails)))]
pub async fn delete_poll_vote(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    let message = poll_message(&state, &auth, &conv, &message_id).await?;
    check_change(&state, &auth, &conv, &message).await?;
    if !store::polls::delete(&state.db, &message.id, &auth.user.id).await? {
        return Err(access::not_found("Vote", "poll.vote_not_found"));
    }
    conv.publish(
        &state.hub,
        "poll.vote.delete",
        serde_json::json!({ "room_id": conv.room_id(), "conversation_id": conv.id, "message_id": message.id,
                            "user": auth.user.address(), "user_id": auth.user.id }),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// The votes of a poll.
#[utoipa::path(get, path = "/api/v1/conversations/{conversation_id}/messages/{message_id}/poll/votes", security(("bearer" = [])),
    params(("conversation_id" = String, Path), ("message_id" = String, Path)),
    description = "Every vote record of a poll (PROTOCOL.md §7g), oldest first, at most one per member; no paging. Needs what reading the message needs (`view_channel`, the history window of ENCRYPTION.md §7b). Clients verify each record against the voter's device and the poll before counting it.",
    responses((status = 200, body = PollVoteList), (status = 403, body = ProblemDetails), (status = 404, body = ProblemDetails)))]
pub async fn list_poll_votes(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((conversation_id, message_id)): Path<(String, String)>,
) -> Result<Json<PollVoteList>, ApiError> {
    let conv = access::conversation(&state, &conversation_id, &auth.user).await?;
    let message = poll_message(&state, &auth, &conv, &message_id).await?;
    let items = store::polls::list(&state.db, &message.id).await?.into_iter().map(PollVote::from).collect();
    Ok(Json(PollVoteList { items }))
}
