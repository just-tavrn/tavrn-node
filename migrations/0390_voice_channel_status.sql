-- Voice channel status (protocol VOICE.md §2a): one line of plain text (at most 128 characters, '' = none) that
-- members with `voice_status` (permissions.md bit 38) change at any time. A field of its own next to `topic`, which
-- keeps its meaning (a description under `manage_channels`). Empty on every other channel kind.
ALTER TABLE channels ADD COLUMN status TEXT NOT NULL DEFAULT '';
