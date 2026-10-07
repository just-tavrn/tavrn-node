-- Phase 4E track S (PLAN.md 4.11): whiteboard permissions, upload categories, per-room profiles, the welcome
-- channel and notification settings. Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT booleans and masks.
-- Data fixes that need fresh ULIDs (welcome channels of existing rooms, the audited removal of restricted
-- permissions from @everyone) run in Rust at startup (server/src/fixups.rs).

-- New permission `use_whiteboard` (bit 27) is a default of @everyone: existing rooms keep their behaviour.
UPDATE roles SET permissions = permissions | 134217728 WHERE is_everyone = 1;

-- Upload categories (protocol/PROTOCOL.md §7a) as a bit mask: images 1, audio 2, video 4, documents 8,
-- archives 16, other 32. NULL on a role = not set (the highest role with a value wins, else @everyone).
ALTER TABLE roles ADD COLUMN upload_categories BIGINT;
UPDATE roles SET upload_categories = 63 WHERE is_everyone = 1;
-- Channel and category overrides allow or deny categories on top, evaluated like permission overrides.
ALTER TABLE permission_overrides ADD COLUMN upload_allow BIGINT NOT NULL DEFAULT 0;
ALTER TABLE permission_overrides ADD COLUMN upload_deny BIGINT NOT NULL DEFAULT 0;

-- Per-room profiles ("server profiles"): avatar (a `media` row of kind `room_avatar`) and bio per membership;
-- the nickname column exists since phase 1.
ALTER TABLE room_members ADD COLUMN avatar_media_id TEXT;
ALTER TABLE room_members ADD COLUMN avatar_animated BIGINT NOT NULL DEFAULT 0;
ALTER TABLE room_members ADD COLUMN bio TEXT NOT NULL DEFAULT '';

-- Welcome channel (a fixed system channel per room, `channels.kind = 'system'`, `system_name = 'welcome'`).
-- Switching it off hides it; its history stays.
ALTER TABLE rooms ADD COLUMN welcome_channel_enabled BIGINT NOT NULL DEFAULT 1;

-- Notification settings of local users (JSON, validated and size-limited by the node).
CREATE TABLE notification_settings (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings   TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX blobs_conversation ON blobs(conversation_id);
CREATE INDEX room_members_avatar ON room_members(avatar_media_id);
