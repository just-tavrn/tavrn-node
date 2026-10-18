// SPDX-License-Identifier: AGPL-3.0-only
//! OpenAPI specification, generated from the route annotations. `tavrn-node openapi` prints it.

use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};

use crate::routes::applications;
use crate::routes::calls;
use crate::routes::history;
use crate::routes::history_requests;
use crate::routes::identity;
use crate::routes::peer_resolve;
use crate::routes::polls;
use crate::routes::whiteboard;
use crate::routes::{
    admin, attachments, auth, backups, channels, conformance, connect, conversations, conversations_index, directory,
    emojis, federation, friends, health, invites, keys, messages, mls, node, read, roles, rooms, second_factor,
    secret_storage, voice, wellknown,
};
use crate::routes::{notifications, presence, profile, room_profiles, unfurl};

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("JWT").build()),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "tavrn Node API",
        description = "API of a tavrn node. Clients, bots and other nodes use the same routes. Errors follow RFC 9457 (Problem Details).",
        license(name = "Apache-2.0")
    ),
    modifiers(&BearerAuth),
    paths(
        node::get_node, wellknown::get_well_known, health::healthz, health::readyz,
        auth::device_nonce, mls::pending_removals, mls::own_pending_removals, second_factor::reauth, second_factor::reauth_webauthn_start, keys::put_retired_device,
        auth::register, auth::login, auth::refresh, auth::logout, auth::verify_email, auth::resend_verification, auth::me, auth::devices, auth::change_password, auth::delete_device, auth::forgot_password, auth::reset_password,
        second_factor::verify, second_factor::factors, second_factor::totp_enroll, second_factor::totp_confirm, second_factor::totp_remove, second_factor::regenerate_recovery_codes,
        second_factor::webauthn_register_start, second_factor::webauthn_register_finish, second_factor::webauthn_credentials, second_factor::webauthn_delete_credential,
        second_factor::webauthn_login_start, second_factor::webauthn_login_finish,
        secret_storage::list, secret_storage::put_recovery, secret_storage::put_passkey, secret_storage::delete_passkey,
        admin::overview, admin::list_users, admin::update_user, admin::purge_user, admin::reset_second_factor, admin::create_invite, admin::list_invites, admin::delete_invite, admin::check_account_invite, admin::ban, admin::unban, admin::list_bans, admin::audit_log,
        rooms::create_room, rooms::list_my_rooms, rooms::discover_rooms, rooms::get_room, rooms::update_room, rooms::delete_room,
        rooms::join_room, rooms::preview_room, rooms::get_invite, rooms::join_by_invite, rooms::leave_room, rooms::list_members, rooms::update_member,
        rooms::kick_member, rooms::timeout_member, rooms::ban, rooms::unban, rooms::list_bans, rooms::create_invite, rooms::list_invites,
        rooms::delete_invite, rooms::direct_invite, rooms::audit_log, rooms::purge, invites::list, invites::dismiss,
        channels::create_category, channels::update_category, channels::delete_category, channels::create_channel, channels::update_channel,
        channels::delete_channel, channels::set_override,
        roles::create_role, roles::update_role, roles::delete_role,
        messages::list_messages, messages::create_message, messages::edit_message, messages::delete_message,
        attachments::upload, attachments::download, attachments::add_reaction, attachments::remove_reaction, attachments::pin, attachments::unpin, attachments::list_pins,
        emojis::list, emojis::create, emojis::delete, emojis::image, emojis::gifs, unfurl::unfurl,
        emojis::public_image, emojis::purge_cache, emojis::list_personal, emojis::create_personal, emojis::rename_personal, emojis::delete_personal,
        keys::put_identity, keys::get_keys, keys::put_device_key, keys::put_share_key, keys::upload_key_packages, keys::count_key_packages, keys::claim_key_packages, keys::reset_identity,
        identity::rotate, identity::blob,
        mls::create_group, mls::group_info, mls::post_commit, mls::log, mls::welcomes, mls::delete_welcome,
        history::create_share, history::list_shares, history::ack_share, history::list_pending,
        history_requests::create, history_requests::mine, history_requests::cancel, history_requests::list, history_requests::approve, history_requests::deny,
        backups::put_backup, backups::get_backup, backups::list_backups,
        friends::list, friends::send_request, friends::accept, friends::delete_request, friends::remove, friends::block, friends::unblock, friends::blocks,
        conversations::create, conversations::list, conversations::get, conversations::update, conversations::add_member, conversations::remove_member, read::mark_read,
        conversations::requests, conversations::accept, conversations::decline,
        messages::list_conversation_messages, messages::create_conversation_message, messages::edit_conversation_message, messages::delete_conversation_message,
        polls::put_poll_vote, polls::delete_poll_vote, polls::list_poll_votes,
        attachments::upload_to_conversation, attachments::add_conversation_reaction, attachments::remove_conversation_reaction, attachments::list_reactors, attachments::pin_in_conversation, attachments::unpin_in_conversation, attachments::list_conversation_pins,
        federation::issue_token, federation::federated_login, federation::inbox, federation::claim, federation::avatar,
        connect::connect_code, connect::connect_token, connect::create_session, connect::poll_session, connect::peer_document, peer_resolve::resolve_peer, conversations_index::get_index, conversations_index::put_index,
        directory::nodes, directory::node, directory::rooms, directory::delisted, directory::delist_node, directory::delist_room, directory::relist,
        directory::report, directory::report_summary, directory::reports_of, directory::dismiss_reports,
        conformance::create_room, conformance::delete_room, conformance::peer_state, conformance::list_peers, conformance::check_peer,
        conformance::block_peer, conformance::unblock_peer,
        voice::whisper_start, voice::whisper_receive, voice::whisper_end,
        voice::join, voice::leave, voice::update_state, voice::room_states, voice::my_states, voice::mute_member, voice::disconnect_member, voice::move_member,
        voice::webhook, voice::list_sounds, voice::create_sound, voice::delete_sound, voice::sound_audio,
        voice::update_sound, voice::public_sound_audio, voice::list_personal_sounds, voice::create_personal_sound, voice::update_personal_sound,
        voice::delete_personal_sound, voice::play_sound,
        voice::move_all, voice::connection_test,
        calls::start, calls::join, calls::leave, calls::decline, calls::get_call, calls::update_state,
        profile::update_me, profile::get_profile, profile::put_avatar, profile::delete_avatar, profile::put_header, profile::delete_header,
        profile::put_background, profile::get_background, profile::delete_background, profile::background_image,
        profile::get_media, profile::get_media_animated, profile::put_room_icon, profile::delete_room_icon,
        presence::get_mine, presence::put_mine, presence::put_activity, presence::delete_activity, presence::list,
        presence::get_room_setting, presence::put_room_setting,
        whiteboard::post_ephemeral, whiteboard::get_session, whiteboard::list_scenes, whiteboard::put_scene, whiteboard::get_scene,
        whiteboard::rename_scene, whiteboard::delete_scene, whiteboard::put_thumbnail, whiteboard::get_thumbnail, whiteboard::convert_background,
        notifications::get, notifications::put, attachments::upload_policy,
        room_profiles::put_own, room_profiles::delete_own, room_profiles::put_avatar, room_profiles::delete_avatar, room_profiles::moderate,
        applications::create, applications::list, applications::incoming_transfers, applications::get, applications::update,
        applications::put_avatar, applications::delete_avatar, applications::delete, applications::start_transfer,
        applications::cancel_transfer, applications::accept_transfer, applications::decline_transfer, applications::identity_reset,
        applications::create_token, applications::list_tokens, applications::reset_token, applications::revoke_token,
        applications::me, applications::rotate,
    ),
    components(schemas(
        applications::Application, applications::PendingTransfer, applications::AppToken, applications::TokenSecret,
        applications::RotatedToken, applications::IncomingTransfer, applications::CreateApplicationRequest,
        applications::UpdateApplicationRequest, applications::DeleteApplicationRequest, applications::TransferRequest,
        applications::CreateTokenRequest, applications::ResetTokenRequest,
        node::NodeInfo, node::CaptchaInfo, wellknown::WellKnown, wellknown::Policies, wellknown::ScreensharePolicy, health::Readiness,
        crate::keys::PublicKeyInfo, crate::error::ProblemDetails,
        crate::models::User, crate::models::UserPrivate, crate::models::Room, crate::models::Role, crate::models::Category,
        crate::models::Channel, crate::models::PermissionOverride, crate::models::Member, crate::models::Invite, crate::models::Ban,
        crate::models::AuditEntry, crate::models::Message, crate::models::Attachment, crate::models::Reaction, crate::models::ReactionChange, crate::models::MessageUpdate, attachments::Reactor, attachments::ReactorList, attachments::PinList, crate::models::Emoji, crate::gifs::Gif, crate::unfurl::UnfurlResponse, emojis::GifResults,
        emojis::PersonalEmojis, emojis::CachePurged, emojis::RenameEmoji, crate::store::emojis::UserEmoji, voice::PersonalSounds, voice::UpdateSound, voice::PlaySound, voice::PlayAllowed, crate::store::voice::UserSound, crate::auth::TokenPair,
        auth::RegisterRequest, auth::LoginRequest, auth::RefreshRequest, auth::VerifyEmailRequest, auth::AuthResponse, auth::DeviceInfo, auth::ChangePasswordRequest, auth::ForgotPasswordRequest, auth::ResetPasswordRequest,
        auth::SessionStatus, auth::PreAuthStatus, auth::PreAuthResponse,
        crate::device_proof::DeviceProof, crate::device_proof::DeviceNonce, mls::PendingRemoval, mls::PendingRemovalList,
        second_factor::ReauthRequest, crate::reauth::ReauthToken, keys::RetiredDeviceKey, keys::RetiredDeviceRequest,
        second_factor::VerifyRequest, second_factor::WebauthnCredential, second_factor::Factors, second_factor::TotpEnrollment, second_factor::TotpConfirmRequest,
        second_factor::EnrollmentResult, second_factor::RemoveTotpRequest, second_factor::PasswordConfirmation, second_factor::RecoveryCodes,
        second_factor::WebauthnChallenge, second_factor::WebauthnRegisterFinish, second_factor::WebauthnRegistered, second_factor::WebauthnLoginStart, second_factor::WebauthnLoginFinish,
        secret_storage::SecretStorageEntry, secret_storage::SecretStorageList, secret_storage::PutSecretStorage,
        crate::models::AccountInvite, admin::AdminOverview, admin::AdminUser, admin::UpdateUserRequest, admin::PurgeUserRequest, admin::PurgeUserResponse, admin::CreateAccountInviteRequest, admin::NodeBanRequest,
        rooms::CreateRoomRequest, rooms::RoomDetail, rooms::PublicRoom, rooms::UpdateRoomRequest, rooms::JoinRequest, rooms::InvitePreview, rooms::RoomPreview,
        rooms::UpdateMemberRequest, rooms::ReasonRequest, rooms::TimeoutRequest, rooms::BanRequest, rooms::CreateInviteRequest, rooms::PurgeRequest, rooms::PurgeResponse,
        rooms::DirectInviteRequest, rooms::DirectInviteResponse, invites::UserInvite, invites::UserInviteList,
        channels::CreateCategoryRequest, channels::UpdateCategoryRequest, channels::CreateChannelRequest, channels::UpdateChannelRequest, channels::SetOverrideRequest,
        roles::CreateRoleRequest, roles::UpdateRoleRequest,
        messages::CreateMessageRequest, messages::EditMessageRequest,
        polls::PollVote, polls::PollVoteList, polls::PollVoteRequest,
        keys::IdentityKeyRequest, keys::DeviceKey, keys::UserKeys, keys::DeviceKeyRequest, keys::ShareKeyRequest, keys::KeyPackagesRequest, keys::KeyPackageCount, keys::ClaimedKeyPackage, keys::ClaimedKeyPackages, keys::IdentityResetRequest,
        history::CreateHistoryShareRequest, history::HistoryShareCreated, history::HistoryShare, history::HistoryShareList, history::HistoryPendingMember, history::HistoryPendingList,
        history_requests::HistoryRequest, history_requests::HistoryRequestChannel, history_requests::HistoryRequestList, history_requests::MyHistoryState, history_requests::CreateHistoryRequest, history_requests::ApproveHistoryRequest, history_requests::DenyHistoryRequest,
        mls::CreateGroupRequest, mls::EpochResponse, mls::GroupInfoResponse, mls::CommitRequest, mls::LogEntry, mls::LogPage, mls::WelcomeItem, mls::WelcomeList,
        backups::BackupInfo, backups::BackupList,
        friends::Friend, friends::FriendRequest, friends::FriendList, friends::UserRef, friends::FriendRequestResult, friends::FriendRequestBody, friends::BlockRequest, friends::BlockedUser,
        conversations::Conversation, conversations::CreateConversationRequest, conversations::UpdateConversationRequest,
        conversations::ConversationRequest, conversations::SharedRoom, conversations::DeclineRequest,
        read::ReadRequest, crate::store::messages::ReadState,
        wellknown::FederationInfo, wellknown::FederationLimits,
        federation::FederationTokenRequest, federation::FederationTokenResponse, federation::FederatedLoginRequest, federation::FederatedSessionResponse,
        peer_resolve::PeerResolution, crate::federation::client::DelegationSource,
        connect::ConnectCodeRequest, connect::ConnectCodeResponse, connect::ConnectTokenRequest, connect::ConnectSessionRequest, connect::ConnectSessionResponse, connect::ConnectSessionStatus,
        conversations_index::IndexEntry, conversations_index::ConversationIndex, conversations_index::PutConversationIndex,
        directory::DirectorySoftware, directory::DirectoryNode, directory::DirectoryNodeList, directory::KeyFingerprint, directory::DirectoryNodeDetail,
        directory::DirectoryRoom, directory::DirectoryRoomList, directory::DelistedEntry, directory::RelistRequest,
        directory::ReportRequest, directory::ReportSubject, directory::DirectoryReport, directory::ReportSummary,
        crate::federation::conformance::ConformanceRoom, crate::federation::conformance::Record, crate::federation::conformance::CheckResult,
        crate::federation::conformance::Outcome, crate::federation::conformance::HistoryEntry,
        conformance::PeerPublicState, conformance::FederationPeer, conformance::ViolationCount, conformance::BlockPeerRequest,
        health::Health, crate::voice::livekit::LiveKitStatus, node::VoiceInfo, crate::voice::VoiceChannelState, crate::voice::state::VoiceParticipant,
        voice::WhisperRequest, crate::voice::whisper::WhisperSession, crate::voice::whisper::WhisperReceipt,
        voice::VoiceJoin, voice::VoiceLimits, voice::VideoLimits, voice::VoiceStatePatch, voice::VoiceRole, voice::VoiceRoleRequest, voice::RoomVoiceStates, voice::MyVoiceRoom, voice::MyVoiceStates, voice::MuteRequest, voice::MoveRequest,
        voice::MoveAllRequest, voice::MoveAllResult, voice::MoveSkipped, voice::ConnectionTest, voice::RtcInfo,
        calls::CallJoin, crate::calls::CallState,
        crate::store::voice::Sound,
        profile::Profile, profile::UpdateMeRequest, profile::Background, crate::profile::ProfileLink, crate::profile::ProfileLinkInput,
        presence::PresenceRequest, presence::RoomPresenceSetting, crate::presence::Presence, crate::presence::MyPresence,
        crate::presence::CustomStatus, crate::presence::Activity, crate::presence::ActivityApplication,
        whiteboard::EphemeralRequest, whiteboard::EphemeralAccepted, whiteboard::EphemeralEvent, whiteboard::EphemeralSender,
        whiteboard::SessionResponse, whiteboard::SceneInfo, whiteboard::SceneList, whiteboard::RenameSceneRequest,
        crate::whiteboard::WhiteboardSession, crate::whiteboard::SessionState,
        crate::notifications::NotificationSettings, crate::notifications::GlobalSettings, crate::notifications::RoomSettings,
        crate::notifications::ChannelSettings, crate::notifications::Mode, attachments::UploadPolicy,
        room_profiles::RoomProfileRequest, room_profiles::ModerateProfileRequest, crate::models::RoomProfile,
    ))
)]
pub struct ApiDoc;

pub fn spec() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    // Single sign-on (APPLICATIONS.md §8) documents its routes in its own module.
    doc.merge(crate::routes::oidc::OidcApi::openapi());
    // Entitlements and admin API tokens (ENTITLEMENTS.md).
    doc.merge(crate::routes::entitlements::EntitlementsApi::openapi());
    // Files channels (FILES.md).
    doc.merge(crate::routes::files::FilesApi::openapi());
    // Incoming webhooks and event subscriptions (APPLICATIONS.md §6).
    doc.merge(crate::routes::webhooks::WebhooksApi::openapi());
    doc.merge(crate::routes::subscriptions::SubscriptionsApi::openapi());
    doc.merge(crate::routes::installations::InstallationsApi::openapi());
    // Message search (PROTOCOL.md §7d).
    doc.merge(crate::routes::search::SearchApi::openapi());
    doc.merge(crate::routes::commands::CommandsApi::openapi());
    // Threads, forum and announcement channels (PROTOCOL.md §7e).
    doc.merge(crate::routes::threads::ThreadsApi::openapi());
    // Legal pages, notices, data export and account deletion (protocol/LEGAL.md).
    doc.merge(crate::routes::legal::LegalApi::openapi());
    // Web push (PROTOCOL.md §6d).
    doc.merge(crate::routes::push::PushApi::openapi());
    // Reports, auto-moderation and ownership transfer (protocol/MODERATION.md).
    doc.merge(crate::routes::moderation::ModerationApi::openapi());
    // Date of birth and age status (PROTOCOL.md §5e).
    doc.merge(crate::routes::age::AgeApi::openapi());
    doc
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    /// The generated specification must equal `protocol/openapi.json` of the pinned tavrn-protocol submodule
    /// (`tavrn-node openapi` prints it with a trailing newline). The protocol repository is the source of truth:
    /// an API change lands there first, then the submodule is moved to the new tag. `info.version` is left out
    /// of the comparison: it carries the version of the node that generated the file, not the protocol's.
    #[test]
    fn spec_matches_the_protocol_submodule() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("protocol/openapi.json");
        let published = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("{} not readable ({e}): run `git submodule update --init protocol`", path.display())
        });
        let mut spec = super::spec();
        let published_json: serde_json::Value = serde_json::from_str(&published).unwrap();
        spec.info.version = published_json["info"]["version"].as_str().unwrap_or_default().to_string();
        let generated = format!("{}\n", spec.to_pretty_json().unwrap());
        if generated != published {
            let line = generated
                .lines()
                .zip(published.lines())
                .position(|(a, b)| a != b)
                .map_or_else(|| generated.lines().count().min(published.lines().count()) + 1, |i| i + 1);
            panic!(
                "the generated OpenAPI specification differs from protocol/openapi.json (first difference at line \
                 {line}). Change the specification in tavrn-protocol first, tag it and move the submodule \
                 (`just openapi` shows the diff)."
            );
        }
    }

    #[test]
    fn spec_is_valid_json_and_lists_routes() {
        let json = super::spec().to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["paths"]["/api/v1/node"].is_object());
        assert!(v["paths"]["/.well-known/tavrn"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/channels/{channel_id}/messages"]["post"].is_object());
        assert!(v["components"]["schemas"]["ProblemDetails"].is_object());
        assert!(v["components"]["securitySchemes"]["bearer"].is_object());
        assert!(v["paths"].as_object().unwrap().len() >= 30);
        assert!(v["paths"]["/api/v1/rooms/{room_id}/invites/direct"]["post"].is_object());
        assert!(v["paths"]["/api/v1/users/me/invites"]["get"].is_object());
        assert!(v["paths"]["/api/v1/federation/key-packages/claim"]["post"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/channels/{channel_id}/voice/join"]["post"].is_object());
        assert!(v["components"]["schemas"]["VoiceChannelState"].is_object());
        assert!(v["paths"]["/api/v1/users/me/avatar"]["put"].is_object());
        assert!(v["paths"]["/api/v1/users/me/presence"]["put"].is_object());
        assert!(v["components"]["schemas"]["Profile"].is_object());
        assert!(v["paths"]["/api/v1/users/me/notification-settings"]["put"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/members/me/profile"]["put"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/members/{user_id}/profile"]["patch"].is_object());
        assert!(v["paths"]["/api/v1/conversations/{conversation_id}/upload-policy"]["get"].is_object());
        assert!(v["paths"]["/api/v1/auth/oidc/start"]["post"].is_object());
        assert!(v["paths"]["/api/v1/admin/sso/group-map"]["put"].is_object());
        assert!(v["components"]["schemas"]["OidcTokenResponse"].is_object());
        assert!(v["paths"]["/api/v1/admin/entitlements/grants"]["post"].is_object());
        assert!(v["paths"]["/api/v1/admin/tokens"]["post"].is_object());
        assert!(v["paths"]["/api/v1/users/me/entitlements"]["get"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/channels/{channel_id}/files/upload"]["post"].is_object());
        assert!(v["paths"]["/api/v1/rooms/{room_id}/channels/{channel_id}/files/backend"]["put"].is_object());
        assert!(v["components"]["schemas"]["FileEntry"].is_object());
    }
}
