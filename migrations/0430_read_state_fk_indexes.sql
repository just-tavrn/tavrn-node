-- Indexes for read states and for deletions as tables grow. Portable SQL: PostgreSQL and SQLite both accept
-- `IF NOT EXISTS` and partial indexes.
--
-- The newest message of a conversation outside threads and the unread messages after a read marker
-- (`store::messages::read_states`, every room open, DM list and read marker update) are range lookups in this
-- index instead of reads of the whole history.
CREATE INDEX IF NOT EXISTS messages_conversation_main ON messages(conversation_id, id) WHERE thread_id IS NULL;
-- A user's read markers (account deletion, the remote user prune).
CREATE INDEX IF NOT EXISTS read_markers_user ON read_markers(user_id);
-- Columns referencing users or roles: PostgreSQL does not index foreign keys, so a cascading delete of a user or a
-- role and the hourly prune of unused remote users (`housekeeping.rs`) scanned these tables once per row.
CREATE INDEX IF NOT EXISTS blobs_uploader ON blobs(uploader_id);
CREATE INDEX IF NOT EXISTS pins_pinned_by ON pins(pinned_by);
CREATE INDEX IF NOT EXISTS bans_actor ON bans(actor_id);
CREATE INDEX IF NOT EXISTS emojis_uploader ON emojis(uploader_id);
CREATE INDEX IF NOT EXISTS users_owner ON users(owner_id);
CREATE INDEX IF NOT EXISTS invites_creator ON invites(creator_id);
CREATE INDEX IF NOT EXISTS threads_created_by ON threads(created_by);
CREATE INDEX IF NOT EXISTS threads_title_author ON threads(title_author_id);
CREATE INDEX IF NOT EXISTS member_roles_role ON member_roles(role_id);
-- The prunes of old Welcomes and commits of the MLS handshake log (`housekeeping.rs`) by age.
CREATE INDEX IF NOT EXISTS mls_welcomes_created ON mls_welcomes(created_at);
CREATE INDEX IF NOT EXISTS mls_commits_created ON mls_commits(created_at);
