-- Room privacy notice and legal notice (protocol PROTOCOL.md §6b "Room privacy notice and legal notice"): optional
-- Markdown documents a room publishes for its members and for people about to join ('' = off), each with the time
-- of its last change (null while off) so clients can say "updated on …". Information only: joining never needs an
-- acknowledgement of them (unlike `rules`).
ALTER TABLE rooms ADD COLUMN privacy_notice TEXT NOT NULL DEFAULT '';
ALTER TABLE rooms ADD COLUMN privacy_notice_updated_at TEXT;
ALTER TABLE rooms ADD COLUMN legal_notice TEXT NOT NULL DEFAULT '';
ALTER TABLE rooms ADD COLUMN legal_notice_updated_at TEXT;
