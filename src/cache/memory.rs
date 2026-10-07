// SPDX-License-Identifier: AGPL-3.0-only
//! [`InProcess`]: the cache in this process's memory. Without `TAVRN_CACHE_URL` every node uses one of its own (one
//! instance, nobody else to share with); tests hand one `InProcess` to two `AppState`s to play two instances of one
//! node without Valkey.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use futures::{StreamExt, future::BoxFuture, stream::BoxStream};
use tokio::sync::broadcast;

use super::{Cache, CacheResult};

/// Entries are pruned when the map grows beyond this (expired ones only; live ones are never dropped).
const PRUNE_ABOVE: usize = 10_000;
/// Undelivered bus messages per subscriber before it counts as disrupted (like a dropped Valkey connection).
const BUS_CAPACITY: usize = 4096;

enum Value {
    Text(String),
    Count(u64),
    Hash(HashMap<String, String>),
}

struct Slot {
    value: Value,
    expires: Option<Instant>,
}

impl Slot {
    fn live(&self, now: Instant) -> bool {
        self.expires.is_none_or(|e| e > now)
    }
}

pub struct InProcess {
    map: Mutex<HashMap<String, Slot>>,
    bus: Mutex<HashMap<String, broadcast::Sender<String>>>,
}

impl Default for InProcess {
    fn default() -> Self {
        Self { map: Mutex::new(HashMap::new()), bus: Mutex::new(HashMap::new()) }
    }
}

impl InProcess {
    fn with_map<T>(&self, f: impl FnOnce(&mut HashMap<String, Slot>, Instant) -> T) -> T {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if map.len() > PRUNE_ABOVE {
            map.retain(|_, s| s.live(now));
        }
        f(&mut map, now)
    }

    /// The live slot of `key` (an expired one is removed).
    fn live<'a>(map: &'a mut HashMap<String, Slot>, key: &str, now: Instant) -> Option<&'a mut Slot> {
        if map.get(key).is_some_and(|s| !s.live(now)) {
            map.remove(key);
        }
        map.get_mut(key)
    }

    /// Ends every subscription (they see a broken connection and subscribe again): tests of the outage handling.
    pub fn interrupt(&self) {
        self.bus.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn sender(&self, channel: &str) -> broadcast::Sender<String> {
        self.bus
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(BUS_CAPACITY).0)
            .clone()
    }
}

fn ready<T: Send + 'static>(v: T) -> BoxFuture<'static, CacheResult<T>> {
    Box::pin(std::future::ready(Ok(v)))
}

impl Cache for InProcess {
    fn ping(&self) -> BoxFuture<'_, CacheResult<()>> {
        ready(())
    }

    fn hit(&self, key: &str, window: Duration) -> BoxFuture<'_, CacheResult<(u64, Duration)>> {
        let out = self.with_map(|map, now| {
            if let Some(slot) = Self::live(map, key, now)
                && let Value::Count(n) = &mut slot.value
            {
                *n += 1;
                let left = slot.expires.map(|e| e.saturating_duration_since(now)).unwrap_or(window);
                return (*n, left);
            }
            map.insert(key.to_string(), Slot { value: Value::Count(1), expires: Some(now + window) });
            (1, window)
        });
        ready(out)
    }

    fn put(&self, key: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        self.with_map(|map, now| {
            map.insert(key.to_string(), Slot { value: Value::Text(value), expires: Some(now + ttl) });
        });
        ready(())
    }

    fn get(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        let out = self.with_map(|map, now| match Self::live(map, key, now).map(|s| &s.value) {
            Some(Value::Text(t)) => Some(t.clone()),
            _ => None,
        });
        ready(out)
    }

    fn take(&self, key: &str) -> BoxFuture<'_, CacheResult<Option<String>>> {
        let out = self.with_map(|map, now| {
            Self::live(map, key, now)?;
            match map.remove(key).map(|s| s.value) {
                Some(Value::Text(t)) => Some(t),
                _ => None,
            }
        });
        ready(out)
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.with_map(|map, _| map.remove(key));
        ready(())
    }

    fn lease(&self, key: &str, holder: &str, ttl: Duration) -> BoxFuture<'_, CacheResult<bool>> {
        let out = self.with_map(|map, now| match Self::live(map, key, now) {
            Some(slot) => match &slot.value {
                Value::Text(h) if h == holder => {
                    slot.expires = Some(now + ttl);
                    true
                }
                _ => false,
            },
            None => {
                map.insert(key.to_string(), Slot { value: Value::Text(holder.to_string()), expires: Some(now + ttl) });
                true
            }
        });
        ready(out)
    }

    fn release(&self, key: &str, holder: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.with_map(|map, now| {
            if Self::live(map, key, now).is_some_and(|s| matches!(&s.value, Value::Text(h) if h == holder)) {
                map.remove(key);
            }
        });
        ready(())
    }

    fn hash_put(&self, key: &str, field: &str, value: String, ttl: Duration) -> BoxFuture<'_, CacheResult<()>> {
        self.with_map(|map, now| {
            if !Self::live(map, key, now).is_some_and(|s| matches!(s.value, Value::Hash(_))) {
                map.insert(key.to_string(), Slot { value: Value::Hash(HashMap::new()), expires: None });
            }
            if let Some(slot) = map.get_mut(key) {
                slot.expires = Some(now + ttl);
                if let Value::Hash(h) = &mut slot.value {
                    h.insert(field.to_string(), value);
                }
            }
        });
        ready(())
    }

    fn hash_remove(&self, key: &str, field: &str) -> BoxFuture<'_, CacheResult<()>> {
        self.with_map(|map, now| {
            if let Some(slot) = Self::live(map, key, now)
                && let Value::Hash(h) = &mut slot.value
            {
                h.remove(field);
                if h.is_empty() {
                    map.remove(key);
                }
            }
        });
        ready(())
    }

    fn hash_all(&self, key: &str) -> BoxFuture<'_, CacheResult<HashMap<String, String>>> {
        let out = self.with_map(|map, now| match Self::live(map, key, now).map(|s| &s.value) {
            Some(Value::Hash(h)) => h.clone(),
            _ => HashMap::new(),
        });
        ready(out)
    }

    fn publish(&self, channel: &str, payload: String) -> BoxFuture<'_, CacheResult<()>> {
        // No subscriber is no error (like PUBLISH answering 0).
        let _ = self.sender(channel).send(payload);
        ready(())
    }

    fn subscribe(&self, channel: &str) -> BoxFuture<'_, CacheResult<BoxStream<'static, String>>> {
        let rx = self.sender(channel).subscribe();
        // A lagging subscriber lost messages: the stream ends, exactly like a broken Valkey subscription.
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(m) => Some((m, rx)),
                Err(_) => None,
            }
        });
        ready(stream.boxed())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn counters_count_within_the_window_and_restart_after_it() {
        let c = InProcess::default();
        let w = Duration::from_millis(80);
        assert_eq!(c.hit("k", w).await.unwrap().0, 1);
        let (n, left) = c.hit("k", w).await.unwrap();
        assert_eq!(n, 2);
        assert!(left <= w);
        assert_eq!(c.hit("other", w).await.unwrap().0, 1, "keys are independent");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(c.hit("k", w).await.unwrap().0, 1, "a new window");
    }

    #[tokio::test]
    async fn take_is_single_use_and_values_expire() {
        let c = InProcess::default();
        c.put("n", "v".into(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(c.get("n").await.unwrap().as_deref(), Some("v"));
        assert_eq!(c.take("n").await.unwrap().as_deref(), Some("v"));
        assert_eq!(c.take("n").await.unwrap(), None, "spent");
        c.put("short", "v".into(), Duration::from_millis(20)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(c.take("short").await.unwrap(), None, "expired");
        c.put("d", "v".into(), Duration::from_secs(5)).await.unwrap();
        c.delete("d").await.unwrap();
        assert_eq!(c.get("d").await.unwrap(), None);
    }

    #[tokio::test]
    async fn leases_have_one_holder_until_released_or_expired() {
        let c = InProcess::default();
        let ttl = Duration::from_millis(60);
        assert!(c.lease("leader", "a", ttl).await.unwrap());
        assert!(!c.lease("leader", "b", ttl).await.unwrap(), "held by a");
        assert!(c.lease("leader", "a", ttl).await.unwrap(), "a renews");
        c.release("leader", "b").await.unwrap();
        assert!(!c.lease("leader", "b", ttl).await.unwrap(), "only the holder releases");
        c.release("leader", "a").await.unwrap();
        assert!(c.lease("leader", "b", ttl).await.unwrap(), "free after the release");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(c.lease("leader", "a", ttl).await.unwrap(), "free after the expiry");
    }

    #[tokio::test]
    async fn hashes_and_the_bus() {
        let c = InProcess::default();
        c.hash_put("h", "f1", "1".into(), Duration::from_secs(5)).await.unwrap();
        c.hash_put("h", "f2", "2".into(), Duration::from_secs(5)).await.unwrap();
        c.hash_remove("h", "f1").await.unwrap();
        let all = c.hash_all("h").await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all["f2"], "2");

        let mut a = c.subscribe("bus").await.unwrap();
        let mut b = c.subscribe("bus").await.unwrap();
        c.publish("bus", "hello".into()).await.unwrap();
        c.publish("other", "not here".into()).await.unwrap();
        assert_eq!(a.next().await.as_deref(), Some("hello"));
        assert_eq!(b.next().await.as_deref(), Some("hello"));
    }
}
