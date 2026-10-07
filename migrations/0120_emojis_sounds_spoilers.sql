-- Feature round 3 (PLAN.md 4.13 items 4 and 5): animated custom emojis, personal emojis and sounds,
-- emojis on soundboard clips, attachment spoilers. Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT booleans.

-- Room emojis are converted by the media pipeline (WebP, 128 px). `id` is the storage id of the file shown in
-- chat (the animated WebP for animated emojis), `still_id` the storage id of the still variant (first frame)
-- of an animated emoji, NULL for stills (the still is `id` itself). Emojis uploaded before 0120 keep their file.
ALTER TABLE emojis ADD COLUMN animated BIGINT NOT NULL DEFAULT 0;
ALTER TABLE emojis ADD COLUMN still_id TEXT;

-- Personal emojis of local users (home node): usable in every room that grants `use_external_emojis`
-- and in DMs. Same file layout as `emojis`.
CREATE TABLE user_emojis (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        BIGINT NOT NULL,
    animated    BIGINT NOT NULL DEFAULT 0,
    still_id    TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE (user_id, name)
);

-- Personal soundboard clips of local users (home node), usable in voice channels that grant
-- `use_external_sounds`. The audio file lives in the blob storage under the clip id.
CREATE TABLE user_sounds (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        BIGINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    -- Unicode emoji or custom emoji token shown on the player's tile while the clip plays.
    emoji       TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE (user_id, name)
);

ALTER TABLE soundboard_sounds ADD COLUMN emoji TEXT;

-- Attachment spoilers of plaintext messages (the flag of encrypted attachments is inside the encrypted content).
ALTER TABLE blobs ADD COLUMN spoiler BIGINT NOT NULL DEFAULT 0;

-- Cached copies of emojis and clips of other nodes (PLAN.md 4.13): readers never load bytes from foreign
-- nodes; the node they talk to fetches them once (`GET /emojis/{id}/image?host=`, `GET /sounds/{id}/audio?host=`)
-- and serves the copy. `id` is the local storage id; housekeeping evicts copies unused for 30 days.
CREATE TABLE remote_emoji_cache (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,              -- emoji | emoji_still | sound
    origin_host TEXT NOT NULL,
    origin_id   TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        BIGINT NOT NULL,
    fetched_at  TEXT NOT NULL,
    used_at     TEXT NOT NULL,
    UNIQUE (kind, origin_host, origin_id)
);
CREATE INDEX remote_emoji_cache_used ON remote_emoji_cache(used_at);
