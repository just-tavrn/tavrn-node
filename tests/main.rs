// SPDX-License-Identifier: AGPL-3.0-only
//! The node's integration tests as ONE test binary (each `tests/*.rs` file would be its own binary that links
//! the whole node and every dependency). One former file is one module under `suite/`; run it alone with
//! `cargo test -p tavrn-node --test main suite::<file>::` (a single test: `suite::<file>::<test>`).
//! Tests share one process and run in parallel threads: never rely on process-wide state (environment
//! variables, current directory, globals) in a test.

mod common;

mod suite {
    mod account_deletion_flow;
    mod admin_flow;
    mod age_flow;
    mod api_basics;
    mod app_install_flow;
    mod applications_flow;
    mod attachment_retention_flow;
    mod attachments_flow;
    mod auth_flow;
    mod authz_audit;
    mod automod_content_flow;
    mod backups_flow;
    mod blob_deletion_flow;
    mod bots_encrypted_flow;
    mod calls_flow;
    mod channel_visibility_flow;
    mod cluster_flow;
    mod cluster_outage_flow;
    mod commands_flow;
    mod components_flow;
    mod conformance_flow;
    mod connect_flow;
    mod conversation_index_flow;
    mod delegation_flow;
    mod directory_flow;
    mod dm_flow;
    mod dm_requests_flow;
    mod e2ee_flow;
    mod emoji_cache_flow;
    mod emojis_flow;
    mod emojis_sounds_flow;
    mod entitlements_flow;
    mod everyone_safety_flow;
    mod federation_flow;
    mod federation_rooms_flow;
    mod federation_social_flow;
    mod files_backends_flow;
    mod files_e2ee_flow;
    mod files_flow;
    mod friends_flow;
    mod history_flow;
    mod history_restore_flow;
    mod history_shares_v2_flow;
    mod history_since_join_flow;
    mod housekeeping_flow;
    mod identity_rotation_flow;
    mod legal_flow;
    mod mail_locale_flow;
    mod message_retention_flow;
    mod messages_flow;
    mod metrics_flow;
    mod mls_flow;
    mod notifications_flow;
    mod pending_removals_flow;
    mod permissions_flow;
    mod permissions_layered_flow;
    mod polls_flow;
    mod presence_flow;
    mod profiles_flow;
    mod push_flow;
    mod rate_limits_flow;
    mod reactions_flow;
    mod reauth_flow;
    mod report_push_flow;
    mod reports_flow;
    mod reports_forward_flow;
    mod room_invites_flow;
    mod room_profiles_flow;
    mod room_transfer_flow;
    mod rooms_flow;
    mod sealed_webhooks_flow;
    mod search_flow;
    mod second_factor_flow;
    mod secret_storage_flow;
    mod security_log_flow;
    mod sessions_flow;
    mod signatures_flow;
    mod sso_flow;
    mod storage_encryption_flow;
    mod subscriptions_flow;
    mod test_databases_flow;
    mod threads_flow;
    mod unfurl_flow;
    mod unread_flow;
    mod upload_categories_flow;
    mod voice_flow;
    mod voice_move_flow;
    mod voice_screen_flow;
    mod voice_status_flow;
    mod webhook_logs_flow;
    mod webhooks_flow;
    mod welcome_flow;
    mod whiteboard_flow;
    mod ws_flow;
}
