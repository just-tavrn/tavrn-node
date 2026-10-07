-- Bots and end-to-end encryption (PLAN.md 4.7, decided 2026-10-06; protocol/APPLICATIONS.md §3.5).
-- Portable SQL: TEXT values, BIGINT booleans.
--
-- `rooms.bots_in_encrypted_channels`: `per_channel` (every encrypted channel is "no bots" unless the channel sets
-- `bots_allowed`) or `allowed` (encrypted channels follow the `no_bots` flags only). Rooms that exist now keep
-- `allowed` through this column default, so nothing changes for them; the node creates new rooms with
-- `per_channel`. The startup fixup `fixup.bots_in_encrypted_channels` records the kept value once in the audit log
-- of each existing room.
ALTER TABLE rooms ADD COLUMN bots_in_encrypted_channels TEXT NOT NULL DEFAULT 'allowed';

-- `channels.bots_allowed`: the channel explicitly admits bots although it is encrypted (only meaningful in a
-- `per_channel` room; the `no_bots` flags still win).
ALTER TABLE channels ADD COLUMN bots_allowed BIGINT NOT NULL DEFAULT 0;

-- The `manage_applications` permission (bit 35) needs no schema change: the startup fixup
-- `fixup.manage_applications` grants it once to every role holding `manage_room`.
