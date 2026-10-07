-- Phase 5 step 2 (protocol/APPLICATIONS.md §4): installations of applications in rooms, the install index of
-- the bot's home node, managed roles, application reports and the token expiry notices (§2.2). Portable SQL:
-- TEXT ids, RFC 3339 timestamps, BIGINT masks.

-- On the room node: the membership of a bot created through the add flow (§4.2). `application_ref` is
-- `<home domain>/<application ULID>`; `role_id` is the managed role (NULL when none was created or it was
-- deleted by a room admin); `permissions` the granted mask; `installed_by` the installer's address.
CREATE TABLE application_installations (
    id              TEXT PRIMARY KEY,
    room_id         TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    application_ref TEXT NOT NULL,
    bot_user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         TEXT REFERENCES roles(id) ON DELETE SET NULL,
    permissions     BIGINT NOT NULL DEFAULT 0,
    installed_by    TEXT NOT NULL,
    installed_at    TEXT NOT NULL,
    UNIQUE (room_id, application_ref)
);
CREATE INDEX application_installations_bot ON application_installations(bot_user_id);

-- On the bot's home node: every room the bot is installed in, local and on other nodes (§4.5), so the
-- SDK finds its room nodes and `app.changed` reaches them.
CREATE TABLE application_install_index (
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    node           TEXT NOT NULL,
    room_id        TEXT NOT NULL,
    room_name      TEXT NOT NULL DEFAULT '',
    installed_at   TEXT NOT NULL,
    PRIMARY KEY (application_id, node, room_id)
);

-- A role created by an installation is marked with the application reference ("managed by …" in the role
-- editor); it stays editable and deletable like any role.
ALTER TABLE roles ADD COLUMN application_id TEXT;

-- `application.token_expiring` (§2.2): the smallest notice threshold (days before expiry) already sent for
-- the token's current secret; reset when the secret changes.
ALTER TABLE application_tokens ADD COLUMN expiry_notified_days BIGINT;

-- Reports about applications (§4.4, `subject: { kind: "application", ref }`) go through the report route of
-- FEDERATION.md §9.2; the reference of the reported application.
ALTER TABLE directory_reports ADD COLUMN application_ref TEXT;
