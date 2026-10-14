-- Indexes for growing rooms. The room snapshot (visibility, channel list) reads a room's categories ordered by
-- position and all of its permission overrides by `room_id`; both were full table scans (the overrides' index is by
-- target). Portable SQL: PostgreSQL and SQLite both accept `IF NOT EXISTS`.
CREATE INDEX IF NOT EXISTS categories_room ON categories(room_id, position);
CREATE INDEX IF NOT EXISTS permission_overrides_room ON permission_overrides(room_id);
