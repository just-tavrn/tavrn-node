-- Security notices inside a channel (protocol APPLICATIONS.md §3.6). Portable SQL.
-- `notice` = 1 marks a system message the node wrote into a channel instead of the room's welcome channel because the
-- channel is not visible to `@everyone` (`system.bot_added` / `system.bot_removed`). Such a message never counts
-- towards unread or mention counts, cannot be deleted (`403 message.system_protected`) and is skipped by purges and
-- message retention, like the welcome channel's entries; it goes with its channel and with its author's account.
ALTER TABLE messages ADD COLUMN notice BIGINT NOT NULL DEFAULT 0;
