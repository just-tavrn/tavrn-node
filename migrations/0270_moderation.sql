-- Reports with evidence and content auto-moderation (protocol/MODERATION.md). Portable SQL: TEXT ids, RFC 3339
-- timestamps, BIGINT booleans, JSON in TEXT columns.

-- The moderation inbox. `scope`: `room` (the room's moderators and node admins) or `node` (node admins only).
-- `source`: `user` (a report) or `automod` (an auto-moderation match, reporter NULL). A message report links the
-- message (`message_id`, no foreign key: the message may be deleted) and keeps either a `snapshot` of plaintext
-- content or the `evidence` the reporter released for encrypted content (MODERATION.md §1.2). `node` names the node
-- hosting the conversation when it is not this one.
CREATE TABLE reports (
    id               TEXT PRIMARY KEY,
    source           TEXT NOT NULL DEFAULT 'user',
    scope            TEXT NOT NULL,
    kind             TEXT NOT NULL,
    reporter_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
    room_id          TEXT REFERENCES rooms(id) ON DELETE CASCADE,
    conversation_id  TEXT,
    node             TEXT,
    message_id       TEXT,
    target_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
    target_address   TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL,
    detail           TEXT NOT NULL DEFAULT '',
    snapshot         TEXT,
    evidence         TEXT,
    status           TEXT NOT NULL DEFAULT 'open',
    assignee_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
    note             TEXT NOT NULL DEFAULT '',
    actions          TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    resolved_at      TEXT
);
CREATE INDEX reports_room ON reports(room_id, id);
CREATE INDEX reports_scope ON reports(scope, id);
CREATE INDEX reports_reporter ON reports(reporter_id, created_at);
CREATE INDEX reports_resolved ON reports(resolved_at);

-- Content rules of a room (MODERATION.md §2.2): the whole list as one JSON document, replaced at once.
CREATE TABLE automod_rules (
    room_id    TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
    rules      TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);
