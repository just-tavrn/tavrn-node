-- Cached copies of other nodes' emojis and clips are capped per origin node (TAVRN_MEDIA_CACHE_MAX_BYTES_PER_HOST):
-- the size per host and its least recently used copies are looked up by host.
CREATE INDEX remote_emoji_cache_host ON remote_emoji_cache(origin_host, used_at);
