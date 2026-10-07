-- Phase 1: Nutzer, Geräte, Sitzungen, Räume, Rollen, Channels, Nachrichten, Moderation.
-- Portables SQL (PostgreSQL in Produktion, SQLite nur in Entwicklung): TEXT-IDs (ULID),
-- Zeitstempel als RFC-3339-TEXT, Booleans als BIGINT 0/1, JSON als TEXT.

CREATE TABLE users (
    id                TEXT PRIMARY KEY,
    username          TEXT NOT NULL,
    domain            TEXT NOT NULL,              -- Heimatknoten; lokale Nutzer = eigene Domain
    display_name      TEXT NOT NULL,
    kind              TEXT NOT NULL DEFAULT 'user', -- user | bot
    owner_id          TEXT REFERENCES users(id) ON DELETE CASCADE,
    password_hash     TEXT,                       -- NULL bei Remote-Nutzern und Bots
    email             TEXT,
    email_verified_at TEXT,
    identity_pubkey   TEXT,                       -- Base64url, Phase 2
    identity_reset_at TEXT,
    is_node_admin     BIGINT NOT NULL DEFAULT 0,
    avatar_blob_id    TEXT,
    created_at        TEXT NOT NULL,
    disabled_at       TEXT,
    UNIQUE (username, domain)
);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    client       TEXT NOT NULL DEFAULT '',         -- "name/version (caps)"
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id          TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    prev_refresh_token_hash TEXT,          -- Erkennung wiederverwendeter Refresh-Tokens
    created_at         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    revoked_at         TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE email_verifications (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL
);

CREATE TABLE room_creation_grants (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    granted_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remaining  BIGINT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE rooms (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    rules          TEXT NOT NULL DEFAULT '',
    join_mode      TEXT NOT NULL DEFAULT 'invite', -- public | invite
    owner_id       TEXT NOT NULL REFERENCES users(id),
    icon_blob_id   TEXT,
    banner_blob_id TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    color       TEXT,
    position    BIGINT NOT NULL DEFAULT 0,       -- höher = mächtiger; everyone = 0
    permissions BIGINT NOT NULL DEFAULT 0,       -- u64-Bitmaske (als i64 gespeichert)
    hoist       BIGINT NOT NULL DEFAULT 0,
    mentionable BIGINT NOT NULL DEFAULT 0,
    is_everyone BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX roles_room ON roles(room_id);

CREATE TABLE room_members (
    room_id           TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nickname          TEXT,
    joined_at         TEXT NOT NULL,
    rules_accepted_at TEXT,
    timeout_until     TEXT,
    PRIMARY KEY (room_id, user_id)
);
CREATE INDEX room_members_user ON room_members(user_id);

CREATE TABLE member_roles (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (room_id, user_id, role_id),
    FOREIGN KEY (room_id, user_id) REFERENCES room_members(room_id, user_id) ON DELETE CASCADE
);

CREATE TABLE categories (
    id       TEXT PRIMARY KEY,
    room_id  TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    position BIGINT NOT NULL DEFAULT 0
);

-- Jede Konversation (Channel, DM, Gruppen-DM) hat genau eine Zeile; Channels teilen sich die ID.
CREATE TABLE conversations (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,                     -- channel | dm | group
    room_id    TEXT REFERENCES rooms(id) ON DELETE CASCADE,
    encrypted  BIGINT NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE channels (
    id                 TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    room_id            TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    category_id        TEXT REFERENCES categories(id) ON DELETE SET NULL,
    kind               TEXT NOT NULL,             -- text | voice | announcement | forum
    name               TEXT NOT NULL,
    topic              TEXT NOT NULL DEFAULT '',
    position           BIGINT NOT NULL DEFAULT 0,
    sync_with_category BIGINT NOT NULL DEFAULT 1,
    slowmode_secs      BIGINT NOT NULL DEFAULT 0,
    bitrate_kbps       BIGINT NOT NULL DEFAULT 64,
    user_limit         BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX channels_room ON channels(room_id);

CREATE TABLE permission_overrides (
    id           TEXT PRIMARY KEY,
    room_id      TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    target_type  TEXT NOT NULL,                   -- category | channel
    target_id    TEXT NOT NULL,
    subject_type TEXT NOT NULL,                   -- role | member
    subject_id   TEXT NOT NULL,
    allow        BIGINT NOT NULL DEFAULT 0,
    deny         BIGINT NOT NULL DEFAULT 0,
    UNIQUE (target_type, target_id, subject_type, subject_id)
);
CREATE INDEX permission_overrides_target ON permission_overrides(target_type, target_id);

CREATE TABLE invites (
    code       TEXT PRIMARY KEY,
    room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    creator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    max_uses   BIGINT NOT NULL DEFAULT 0,        -- 0 = unbegrenzt
    uses       BIGINT NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE bans (
    id         TEXT PRIMARY KEY,
    room_id    TEXT REFERENCES rooms(id) ON DELETE CASCADE, -- NULL = knotenweit
    subject    TEXT NOT NULL,                     -- "alice@domain" oder "domain"
    reason     TEXT NOT NULL DEFAULT '',
    actor_id   TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE (room_id, subject)
);
CREATE INDEX bans_subject ON bans(subject);

CREATE TABLE messages (
    id                TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    author_id         TEXT NOT NULL REFERENCES users(id),
    device_id         TEXT,
    encrypted         BIGINT NOT NULL,
    format            BIGINT NOT NULL DEFAULT 1,
    epoch             BIGINT,
    content           TEXT NOT NULL,              -- JSON (Klartext) oder Base64url (Chiffretext)
    content_size      BIGINT NOT NULL,
    reply_to_id       TEXT,
    thread_id         TEXT,
    mentions          TEXT NOT NULL DEFAULT '[]', -- JSON-Liste von Nutzerkennungen
    mentions_everyone BIGINT NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    edited_at         TEXT
);
CREATE INDEX messages_conversation ON messages(conversation_id, id);
CREATE INDEX messages_author ON messages(author_id, created_at);

CREATE TABLE reactions (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (message_id, user_id, emoji)
);

CREATE TABLE read_markers (
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message_id      TEXT NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,
    room_id    TEXT REFERENCES rooms(id) ON DELETE CASCADE,
    actor_id   TEXT,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX audit_log_room ON audit_log(room_id, id);
