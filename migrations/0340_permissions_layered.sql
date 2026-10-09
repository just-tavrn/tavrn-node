-- Layered permission overrides (protocol permissions.md "Evaluation", 2026-10-09): a category's overrides always
-- apply to its channels, the channel's own on top. The either/or switch `sync_with_category` is gone; a channel
-- without own overrides behaves exactly as a synced one did. (Bits outside CHANNEL_SCOPED are stripped from
-- existing overrides by the start-up fixup, fixups.rs, which writes audit entries.)
ALTER TABLE channels DROP COLUMN sync_with_category;
