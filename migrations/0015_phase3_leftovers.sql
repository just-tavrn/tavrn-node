-- Phase 3 leftovers (FEDERATION.md §9.2, §2.6, §13.1). Portable SQL: TEXT ids and RFC 3339 timestamps.

-- Reports of local users about other nodes (or one of their rooms), `POST /directory/reports`.
-- `kind` is the reported check or reason (the `check` of the request; `check` is an SQL keyword).
-- `room_id` is '' for the node as a whole. Reports never block anything on their own: they are shown in
-- the admin's Federation tab, and three distinct reporters of one domain within 7 days leave an admin
-- notice in the audit log.
CREATE TABLE directory_reports (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    room_id     TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX directory_reports_domain ON directory_reports(domain, created_at);
CREATE INDEX directory_reports_reporter ON directory_reports(reporter_id, created_at);

-- The remote user cleanup (housekeeping) looks up every tie of a user to this node; these lookups by
-- user had no index yet.
CREATE INDEX reactions_user ON reactions(user_id);
CREATE INDEX friends_friend ON friends(friend_id);
CREATE INDEX user_blocks_blocked ON user_blocks(blocked_id);
