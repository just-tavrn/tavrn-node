-- Phase 4C (PLAN.md 4.9): profiles, media pipeline, presence, direct-message requests, friend request
-- messages and block reasons. Portable SQL: TEXT ids and RFC 3339 timestamps, BIGINT booleans.

-- Images produced by the media pipeline (server/src/media.rs) and mirrored from other nodes. `id` is the
-- storage id of the still image (the first frame of an animated input), `animated_id` the storage id of
-- the animated WebP (NULL for stills). `owner_id` is a user or room id (no foreign key: two tables);
-- rows are deleted together with their files when they are replaced or their owner goes away.
CREATE TABLE media (
    id              TEXT PRIMARY KEY,
    animated_id     TEXT,
    kind            TEXT NOT NULL,              -- avatar | header | icon | background
    owner_id        TEXT NOT NULL,
    mime            TEXT NOT NULL,              -- of the still; the animated variant is always image/webp
    still_size      BIGINT NOT NULL,
    animated_size   BIGINT NOT NULL DEFAULT 0,
    still_sha256    TEXT NOT NULL,              -- base64url
    animated_sha256 TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX media_owner ON media(owner_id);
CREATE INDEX media_animated ON media(animated_id);

-- Mirrored avatars of remote users (FEDERATION.md §2.7) were stored without a row; give them one.
INSERT INTO media (id, kind, owner_id, mime, still_size, still_sha256, created_at)
SELECT u.avatar_blob_id, 'avatar', u.id, r.avatar_mime, 0, r.avatar_sha256, u.created_at
FROM users u JOIN remote_users r ON r.user_id = u.id
WHERE u.avatar_blob_id IS NOT NULL AND r.avatar_sha256 IS NOT NULL AND r.avatar_mime IS NOT NULL;
UPDATE users SET avatar_blob_id = NULL
WHERE avatar_blob_id IS NOT NULL AND avatar_blob_id NOT IN (SELECT id FROM media);

-- Profile (users.avatar_blob_id now names a media row).
ALTER TABLE users ADD COLUMN avatar_animated BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN header_blob_id TEXT;
ALTER TABLE users ADD COLUMN header_animated BIGINT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN background_blob_id TEXT;
ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT '';
-- JSON array of { service, value, url }.
ALTER TABLE users ADD COLUMN links TEXT NOT NULL DEFAULT '[]';
-- Who may start a DM: friends | everyone_shared | everyone (the node's TAVRN_DM_POLICY is the upper bound).
ALTER TABLE users ADD COLUMN dm_policy TEXT NOT NULL DEFAULT 'everyone_shared';
-- Presence (kept by every node the user has a session on): the chosen status (online | dnd | invisible),
-- the custom status as JSON { text, emoji, expires_at } and the switch hiding the activity from others.
ALTER TABLE users ADD COLUMN presence_status TEXT NOT NULL DEFAULT 'online';
ALTER TABLE users ADD COLUMN custom_status TEXT;
ALTER TABLE users ADD COLUMN hide_activity BIGINT NOT NULL DEFAULT 0;

-- Mirror state of the other profile images of remote users.
ALTER TABLE remote_users ADD COLUMN avatar_animated_sha256 TEXT;
ALTER TABLE remote_users ADD COLUMN header_sha256 TEXT;
ALTER TABLE remote_users ADD COLUMN header_animated_sha256 TEXT;

-- Room icons (rooms.icon_blob_id names a media row).
ALTER TABLE rooms ADD COLUMN icon_animated BIGINT NOT NULL DEFAULT 0;

-- Hide my presence from the members of one room.
ALTER TABLE room_members ADD COLUMN hide_presence BIGINT NOT NULL DEFAULT 0;

-- Message requests: `requested` members see the conversation under "Message requests" until they
-- accept it; they get no message events, unread counts or push hints before.
ALTER TABLE conversation_members ADD COLUMN state TEXT NOT NULL DEFAULT 'active';

-- Optional message of a friend request (≤ 256 characters).
ALTER TABLE friend_requests ADD COLUMN message TEXT;

-- Private note of the blocking user (≤ 256 characters), only shown to them.
ALTER TABLE user_blocks ADD COLUMN reason TEXT NOT NULL DEFAULT '';
