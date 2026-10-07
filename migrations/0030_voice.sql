-- Voice (phase 4, protocol/VOICE.md).
-- Server mute by a moderator (`mute_members`): room-wide, survives reconnects and node restarts.
ALTER TABLE room_members ADD COLUMN voice_muted BIGINT NOT NULL DEFAULT 0;

-- Soundboard clips per room. The audio file lives in the blob storage under the clip id.
CREATE TABLE soundboard_sounds (
    id          TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    uploader_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    UNIQUE (room_id, name)
);
CREATE INDEX soundboard_sounds_room ON soundboard_sounds(room_id);
