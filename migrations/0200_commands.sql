-- Phase 5 step 3 (protocol/APPLICATIONS.md §5): command definitions of applications, the node approval of
-- definitions, per-room command settings and the envelope field `interaction` of messages that answer a command.
-- Portable SQL: TEXT ids, RFC 3339 timestamps, BIGINT booleans and masks, JSON as TEXT.

-- Command definitions per application reference (`<home domain>/<application ULID>`). The bot's home node writes
-- them (`PUT …/commands`); a room node keeps a copy of a remote application's set from its public document,
-- refreshed at installation and on `app.changed`. `definition` is the JSON of the definition without `id`,
-- `definition_hash` the base64url SHA-256 of its JCS form (§5.1). Ids stay stable per name.
CREATE TABLE application_commands (
    id              TEXT PRIMARY KEY,
    application_ref TEXT NOT NULL,
    name            TEXT NOT NULL,
    definition      TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    position        BIGINT NOT NULL DEFAULT 0,
    UNIQUE (application_ref, name)
);
CREATE INDEX application_commands_ref ON application_commands(application_ref, position);

-- Node approval of definitions (§5.2, `TAVRN_APP_COMMANDS_REQUIRE_APPROVAL`): a definition is approved by its hash,
-- so any change of a definition makes it pending again. `state`: approved | rejected; no row = pending.
CREATE TABLE application_command_approvals (
    application_ref TEXT NOT NULL,
    definition_hash TEXT NOT NULL,
    state           TEXT NOT NULL,
    decided_by      TEXT REFERENCES users(id) ON DELETE SET NULL,
    decided_at      TEXT NOT NULL,
    PRIMARY KEY (application_ref, definition_hash)
);

-- Per-room settings of a command (§5.3); no row = the defaults (enabled, `default_permissions`, no role
-- restriction, every channel). `permissions` NULL = the definition's `default_permissions`.
CREATE TABLE room_command_settings (
    room_id           TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    command_id        TEXT NOT NULL,
    application_ref   TEXT NOT NULL,
    enabled           BIGINT NOT NULL DEFAULT 1,
    permissions       BIGINT,
    allowed_roles     TEXT NOT NULL DEFAULT '[]',
    disabled_channels TEXT NOT NULL DEFAULT '[]',
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (room_id, command_id)
);
CREATE INDEX room_command_settings_command ON room_command_settings(command_id);

-- Envelope field `interaction: { id, command, application, user }` of a message an application posted as the
-- answer to a command (§5.7), as JSON; NULL for every other message.
ALTER TABLE messages ADD COLUMN interaction TEXT;
