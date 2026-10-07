-- Lazy history (PLAN.md 4.4): read markers carry the API name of the column. The primary key
-- (conversation_id, user_id) serves the join in the grouped unread query; messages are counted over
-- the existing index messages_conversation (conversation_id, id).
ALTER TABLE read_markers RENAME COLUMN message_id TO last_read_message_id;
