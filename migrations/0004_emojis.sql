-- Eigene Emojis je Raum. Die Bilddatei liegt im Blobspeicher unter der Emoji-ID.
CREATE TABLE emojis (
    id          TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    mime        TEXT NOT NULL,
    size        BIGINT NOT NULL,
    uploader_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    UNIQUE (room_id, name)
);
