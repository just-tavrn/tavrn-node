// SPDX-License-Identifier: AGPL-3.0-only
//! [`Valkey`]: the cache shared by every instance of one node (`TAVRN_CACHE_URL`, Valkey or Redis ≥ 7).
//!
//! Commands go through redis-rs' connection manager, which reconnects with backoff by itself; a command during
//! an outage fails fast (response timeout) and the caller falls back or reports `503`. The bus uses a separate
//! pub/sub connection per subscription; when it breaks the stream ends and [`super::Cluster`] subscribes again
//! (and tells its clients to resync).

use std::{collections::HashMap, time::Duration};

use futures::{FutureExt, StreamExt, future::BoxFuture, stream::BoxStream};
use redis::{AsyncCommands, aio::ConnectionManager};

use super::{Cache, CacheError, CacheResult};

/// Connecting (and the first PING at startup) gives up after this.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A single command gives up after this (the request then falls back or fails, it never hangs).
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Acquire a free lease or renew the own one (`KEYS[1]` lease, `ARGV[1]` holder, `ARGV[2]` milliseconds).
const LEASE: &str = r#"
local v = redis.call('GET', KEYS[1])
if v == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return 1
end
if not v then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return 1
end
return 0
"#;

/// Delete the lease only if `ARGV[1]` holds it.
const RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;

pub struct Valkey {
    client: redis::Client,
    conn: ConnectionManager,
    lease: redis::Script,
    release: redis::Script,
}

fn err(e: impl std::fmt::Display) -> CacheError {
    CacheError(e.to_string())
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
}

impl Valkey {
    /// Connects and checks the server with a PING; fails within [`CONNECT_TIMEOUT`].
    pub async fn connect(url: &str) -> CacheResult<Self> {
        let client = redis::Client::open(url).map_err(err)?;
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_number_of_retries(2)
            .set_max_delay(Duration::from_secs(5));
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection_manager_with_config(config))
            .await
            .map_err(|_| CacheError("connection timed out".into()))?
            .map_err(err)?;
        let this = Self { client, conn, lease: redis::Script::new(LEASE), release: redis::Script::new(RELEASE) };
        this.ping().await?;
        Ok(this)
    }

    fn conn(&self) -> ConnectionManager {
        // A cheap handle onto the one multiplexed connection.
        self.conn.clone()
    }
}

impl Cache for Valkey {
    fn ping(&self) -> BoxFuture<'_, CacheResult<()>> {
        let mut c = self.conn();
        async move {
            let pong: String = redis::cmd("PING").query_async(&mut c).await.map_err(err)?;
            if pong == "PONG" { Ok(()) } else { Err(CacheError(format!("unexpected PING answer {pong}"))) }
        }
        .boxed()
    }

    fn hit(&self, key: &str, window: Duration) -> BoxFuture<'_, CacheResult<(u64, Duration)>> {
        let (mut c, key) = (self.conn(), key.to_string());
        async move {
            // One atomic transaction: count, start the window on the first hit (NX keeps a running one), remaining time.
            let (count, ttl): (u64, i64) = redis::pipe()
                .atomic()
                .incr(&key, 1)
                .cmd("PEXPIRE")
                .arg(&key)
                .arg(millis(window))
                .arg("NX")
                .ignore()
                .pttl(&key)
                .query_async(&mut c)
                .await
                .map_err(err)?;
            let left = u64::try_from(ttl).map(Duration::from_millis).unwrap_or(window);
            Ok((count, left))
        }
        .boxed()
    }

    fn put(&self, key: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, key) = (self.conn(), key.to_string());
        async move {
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(value)
                .arg("PX")
                .arg(millis(ttl))
                .query_async(&mut c)
                .await
                .map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn get(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        let (mut c, key) = (self.conn(), key.to_string());
        async move { c.get(&key).await.map_err(err) }.boxed()
    }

    fn take(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        let (mut c, key) = (self.conn(), key.to_string());
        // GETDEL: read and delete in one step, so exactly one instance gets a single-use value.
        async move { redis::cmd("GETDEL").arg(&key).query_async(&mut c).await.map_err(err) }.boxed()
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, key) = (self.conn(), key.to_string());
        async move {
            let _: i64 = c.del(&key).await.map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn lease(&self, key: &str, holder: &str, ttl: Duration) -> BoxFuture<'_, CacheResult<bool>> {
        let (mut c, key, holder) = (self.conn(), key.to_string(), holder.to_string());
        async move {
            let held: i64 =
                self.lease.key(&key).arg(&holder).arg(millis(ttl)).invoke_async(&mut c).await.map_err(err)?;
            Ok(held == 1)
        }
        .boxed()
    }

    fn release(&self, key: &str, holder: &str) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, key, holder) = (self.conn(), key.to_string(), holder.to_string());
        async move {
            let _: i64 = self.release.key(&key).arg(&holder).invoke_async(&mut c).await.map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn hash_put(&self, key: &str, field: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, key, field) = (self.conn(), key.to_string(), field.to_string());
        async move {
            let _: () = redis::pipe()
                .atomic()
                .hset(&key, &field, value)
                .ignore()
                .pexpire(&key, i64::try_from(millis(ttl)).unwrap_or(i64::MAX))
                .ignore()
                .query_async(&mut c)
                .await
                .map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn hash_remove(&self, key: &str, field: &str) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, key, field) = (self.conn(), key.to_string(), field.to_string());
        async move {
            let _: i64 = c.hdel(&key, &field).await.map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn hash_all(&self, key: &str) -> BoxFuture<'_, CacheResult<HashMap<String, String>>> {
        let (mut c, key) = (self.conn(), key.to_string());
        async move { c.hgetall(&key).await.map_err(err) }.boxed()
    }

    fn publish(&self, channel: &str, payload: String) -> BoxFuture<'_, CacheResult<()>> {
        let (mut c, channel) = (self.conn(), channel.to_string());
        async move {
            let _: i64 = c.publish(&channel, payload).await.map_err(err)?;
            Ok(())
        }
        .boxed()
    }

    fn subscribe(&self, channel: &str) -> BoxFuture<'_, CacheResult<BoxStream<'static, String>>> {
        let channel = channel.to_string();
        async move {
            let mut pubsub = tokio::time::timeout(CONNECT_TIMEOUT, self.client.get_async_pubsub())
                .await
                .map_err(|_| CacheError("pub/sub connection timed out".into()))?
                .map_err(err)?;
            tokio::time::timeout(CONNECT_TIMEOUT, pubsub.subscribe(&channel))
                .await
                .map_err(|_| CacheError("SUBSCRIBE timed out".into()))?
                .map_err(err)?;
            // The stream ends when the connection breaks.
            Ok(pubsub.into_on_message().filter_map(|m| async move { m.get_payload::<String>().ok() }).boxed())
        }
        .boxed()
    }
}
