-- Message retention (TAVRN_RETENTION_DAYS, protocol PROTOCOL.md §7f): the hourly housekeeping deletes
-- messages older than the retention of their conversation. Portable SQL: TEXT ids (ULID), RFC 3339 timestamps.

-- A room's own message retention in days (NULL = the node's value). A room can only shorten the node value.
ALTER TABLE rooms ADD COLUMN message_retention_days BIGINT;

-- The retention pass looks messages up by age.
CREATE INDEX messages_created ON messages(created_at);
