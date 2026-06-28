//! Blob storage **tiering** — a hot local cache over a cold durable backing tier
//! (DESIGN §4.1/D31, stack.md §2.4, api.md §9).
//!
//! The deployment shape is a 50–100 GB server-local LRU cache in front of a
//! large cold backing tier (Dropbox in prod, an abstract [`ColdTier`] here so the
//! tier is a swappable adapter — mirrors [`crate::blob::BlobStore`]). This module
//! ships two pieces:
//!
//! * [`CacheIndex`] — the **pure** recency/capacity bookkeeping that decides what
//!   to evict. It holds no bytes; it tracks `(blob_ref, index)` residency, size,
//!   and last-access order, and on each insert returns the keys the caller must
//!   drop from the hot cache to stay within the byte budget. Policy is **LRU**
//!   (evict least-recently-used) — the "cache eviction respects access recency"
//!   Phase-4b exit gate. (LFU is the documented future variant; not built.)
//! * [`ColdTier`] — the durable backing-tier seam, with in-memory / filesystem
//!   fakes for tests. The real Dropbox adapter is a deferred plug-in behind this
//!   trait; no HTTP/cloud dependency is pulled in this run.
//!
//! [`TieredBlobStore`] (next increment) composes a hot [`BlobStore`] cache, a
//! [`ColdTier`], and a [`CacheIndex`] into a single `BlobStore`.

use crate::blob::{BlobError, BlobStore, FsBlobStore, MemoryBlobStore};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Identifies one resident ciphertext chunk in the cache: its stream `blob_ref`
/// (`server::files`, of the form `hex/version/stream_type`) and chunk `index`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkKey {
    pub blob_ref: String,
    pub index: u64,
}

impl ChunkKey {
    pub fn new(blob_ref: impl Into<String>, index: u64) -> Self {
        ChunkKey {
            blob_ref: blob_ref.into(),
            index,
        }
    }
}

/// Pure recency/capacity bookkeeping for the hot cache. Holds **no chunk bytes** —
/// only residency metadata — so it is fully unit-testable and the eviction policy
/// is decided in one place, independent of the async I/O that actually stores
/// bytes. The caller records inserts/accesses/removals and physically evicts the
/// keys [`record_insert`](Self::record_insert) hands back.
pub struct CacheIndex {
    capacity_bytes: u64,
    total_bytes: u64,
    tick: u64,
    entries: HashMap<ChunkKey, Entry>,
}

struct Entry {
    size: u64,
    last_tick: u64,
}

impl CacheIndex {
    /// New, empty cache index holding at most `capacity_bytes` of resident chunks.
    pub fn new(capacity_bytes: u64) -> Self {
        CacheIndex {
            capacity_bytes,
            total_bytes: 0,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    /// Record that `key` (now `size` bytes) is resident — after a fresh PUT or a
    /// cold-tier fetch populated the hot cache. The inserted chunk becomes the
    /// most-recently-used. Returns the keys the caller must **evict from the hot
    /// cache** (LRU first) to bring residency back within `capacity_bytes`. The
    /// just-inserted key is never returned (a single over-capacity chunk is kept).
    pub fn record_insert(&mut self, key: ChunkKey, size: u64) -> Vec<ChunkKey> {
        self.tick += 1;
        let now = self.tick;
        // Overwrite of a resident key replaces its size (no double-counting).
        if let Some(prev) = self.entries.insert(
            key,
            Entry {
                size,
                last_tick: now,
            },
        ) {
            self.total_bytes -= prev.size;
        }
        self.total_bytes += size;

        // Evict least-recently-used until within budget. The just-inserted key
        // has the newest tick, so it is never the victim; the `len() > 1` guard
        // keeps a single over-capacity chunk resident.
        let mut evicted = Vec::new();
        while self.total_bytes > self.capacity_bytes && self.entries.len() > 1 {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_tick)
                .map(|(k, _)| k.clone())
                .expect("non-empty: len > 1");
            let e = self.entries.remove(&victim).expect("just located");
            self.total_bytes -= e.size;
            evicted.push(victim);
        }
        evicted
    }

    /// Record a cache **hit** on `key` — bumps its recency so it is no longer a
    /// near-term eviction victim. No-op if `key` is not resident.
    pub fn record_access(&mut self, key: &ChunkKey) {
        self.tick += 1;
        let now = self.tick;
        if let Some(e) = self.entries.get_mut(key) {
            e.last_tick = now;
        }
    }

    /// Drop **every** resident chunk of `blob_ref` from the index (stream
    /// teardown), freeing their bytes. Returns how many entries were removed.
    pub fn remove_stream(&mut self, blob_ref: &str) -> usize {
        let victims: Vec<ChunkKey> = self
            .entries
            .keys()
            .filter(|k| k.blob_ref == blob_ref)
            .cloned()
            .collect();
        for k in &victims {
            if let Some(e) = self.entries.remove(k) {
                self.total_bytes -= e.size;
            }
        }
        victims.len()
    }

    /// Drop `key` from the index (explicit teardown / overwrite), freeing its
    /// bytes. Returns whether it was resident.
    pub fn remove(&mut self, key: &ChunkKey) -> bool {
        match self.entries.remove(key) {
            Some(e) => {
                self.total_bytes -= e.size;
                true
            }
            None => false,
        }
    }

    pub fn contains(&self, key: &ChunkKey) -> bool {
        self.entries.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// The durable cold backing tier (DESIGN D31): inert ciphertext only, keyed by
/// `(blob_ref, index)` exactly like [`BlobStore`]. Kept a **distinct** trait from
/// the hot cache because (a) the tiering layer talks to the backing tier
/// distinctly, (b) the real Dropbox adapter implements *this* (not `BlobStore`),
/// and (c) direct-link brokering (api §9.4) lands here in a later increment. The
/// fakes delegate to the [`blob`](crate::blob) storage primitives to avoid
/// duplicating the filesystem containment guard.
#[async_trait]
pub trait ColdTier: Send + Sync {
    async fn put_chunk(&self, blob_ref: &str, index: u64, bytes: Vec<u8>)
        -> Result<(), BlobError>;
    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError>;
    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError>;
    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError>;
    /// Delete a single chunk by index (idempotent — absent is success). Lets the
    /// tiering layer honor a per-chunk delete on the durable tier too.
    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError>;
}

/// In-memory [`ColdTier`] fake for tests, backed by a [`MemoryBlobStore`].
#[derive(Default)]
pub struct MemoryColdTier {
    inner: MemoryBlobStore,
}

impl MemoryColdTier {
    pub fn new() -> Self {
        MemoryColdTier {
            inner: MemoryBlobStore::new(),
        }
    }
}

#[async_trait]
impl ColdTier for MemoryColdTier {
    async fn put_chunk(
        &self,
        blob_ref: &str,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<(), BlobError> {
        self.inner.put_chunk(blob_ref, index, bytes).await
    }
    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        self.inner.get_chunk(blob_ref, index).await
    }
    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        self.inner.chunk_count(blob_ref).await
    }
    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        self.inner.delete_stream(blob_ref).await
    }
    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError> {
        self.inner.delete_chunk(blob_ref, index).await
    }
}

/// Filesystem-backed [`ColdTier`] fake (models a durable cold store on disk),
/// backed by an [`FsBlobStore`].
pub struct FsColdTier {
    inner: FsBlobStore,
}

impl FsColdTier {
    pub fn new(base: impl Into<std::path::PathBuf>) -> Self {
        FsColdTier {
            inner: FsBlobStore::new(base),
        }
    }
}

#[async_trait]
impl ColdTier for FsColdTier {
    async fn put_chunk(
        &self,
        blob_ref: &str,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<(), BlobError> {
        self.inner.put_chunk(blob_ref, index, bytes).await
    }
    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        self.inner.get_chunk(blob_ref, index).await
    }
    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        self.inner.chunk_count(blob_ref).await
    }
    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        self.inner.delete_stream(blob_ref).await
    }
    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError> {
        self.inner.delete_chunk(blob_ref, index).await
    }
}

/// A hot [`BlobStore`] cache in front of a durable [`ColdTier`], presented as a
/// single [`BlobStore`] so it drops into `AppState` transparently (DESIGN D31,
/// stack.md §2.4). Reads are served from the cache; a miss fetches from the cold
/// tier and populates the cache (evicting the LRU per [`CacheIndex`]). Writes are
/// **write-through**: the cold tier is the durable record (written first), the
/// cache a populated copy. `chunk_count` reports the **cold** (authoritative)
/// count so the finalize completeness check (api §8.4) sees durable truth, not
/// cache residency.
pub struct TieredBlobStore {
    cache: Arc<dyn BlobStore>,
    cold: Arc<dyn ColdTier>,
    index: Mutex<CacheIndex>,
}

impl TieredBlobStore {
    /// New tier: `cache` is the hot local store, `cold` the durable backing,
    /// `capacity_bytes` the cache byte budget enforced by the [`CacheIndex`].
    pub fn new(cache: Arc<dyn BlobStore>, cold: Arc<dyn ColdTier>, capacity_bytes: u64) -> Self {
        TieredBlobStore {
            cache,
            cold,
            index: Mutex::new(CacheIndex::new(capacity_bytes)),
        }
    }

    /// Record `key` (size bytes) as freshly cached and physically evict whatever
    /// the index says no longer fits. The index lock is never held across an
    /// `await`.
    async fn cache_and_evict(&self, blob_ref: &str, index: u64, size: u64) -> Result<(), BlobError> {
        let evicted = {
            let mut idx = self.index.lock().unwrap();
            idx.record_insert(ChunkKey::new(blob_ref, index), size)
        };
        for k in evicted {
            self.cache.delete_chunk(&k.blob_ref, k.index).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl BlobStore for TieredBlobStore {
    async fn put_chunk(
        &self,
        blob_ref: &str,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<(), BlobError> {
        // Write-through: the cold tier is the durable record (written first), the
        // cache a populated hot copy.
        let size = bytes.len() as u64;
        self.cold.put_chunk(blob_ref, index, bytes.clone()).await?;
        self.cache.put_chunk(blob_ref, index, bytes).await?;
        self.cache_and_evict(blob_ref, index, size).await
    }

    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        // Cache hit: serve and bump recency.
        if let Some(bytes) = self.cache.get_chunk(blob_ref, index).await? {
            self.index
                .lock()
                .unwrap()
                .record_access(&ChunkKey::new(blob_ref, index));
            return Ok(Some(bytes));
        }
        // Miss: fetch from the durable cold tier and warm the cache.
        match self.cold.get_chunk(blob_ref, index).await? {
            Some(bytes) => {
                let size = bytes.len() as u64;
                self.cache.put_chunk(blob_ref, index, bytes.clone()).await?;
                self.cache_and_evict(blob_ref, index, size).await?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        // The cold tier is authoritative — the cache may hold only a subset.
        self.cold.chunk_count(blob_ref).await
    }

    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        self.cold.delete_stream(blob_ref).await?;
        self.cache.delete_stream(blob_ref).await?;
        self.index.lock().unwrap().remove_stream(blob_ref);
        Ok(())
    }

    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError> {
        self.cold.delete_chunk(blob_ref, index).await?;
        self.cache.delete_chunk(blob_ref, index).await?;
        self.index
            .lock()
            .unwrap()
            .remove(&ChunkKey::new(blob_ref, index));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(r: &str, i: u64) -> ChunkKey {
        ChunkKey::new(r, i)
    }

    #[test]
    fn evicts_least_recently_used_when_over_capacity() {
        // Capacity holds exactly two 10-byte chunks.
        let mut idx = CacheIndex::new(20);
        assert!(idx.record_insert(key("a", 0), 10).is_empty());
        assert!(idx.record_insert(key("b", 0), 10).is_empty());
        assert_eq!(idx.total_bytes(), 20);

        // Third insert overflows → the least-recently-used (a) is evicted.
        let evicted = idx.record_insert(key("c", 0), 10);
        assert_eq!(evicted, vec![key("a", 0)]);
        assert!(!idx.contains(&key("a", 0)));
        assert!(idx.contains(&key("b", 0)));
        assert!(idx.contains(&key("c", 0)));
        assert_eq!(idx.total_bytes(), 20);
    }

    #[test]
    fn access_bumps_recency_so_a_survives() {
        let mut idx = CacheIndex::new(20);
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("b", 0), 10);

        // A cache hit on `a` makes `b` the least-recently-used.
        idx.record_access(&key("a", 0));

        let evicted = idx.record_insert(key("c", 0), 10);
        assert_eq!(evicted, vec![key("b", 0)]);
        assert!(idx.contains(&key("a", 0)));
        assert!(!idx.contains(&key("b", 0)));
        assert!(idx.contains(&key("c", 0)));
    }

    #[test]
    fn remove_frees_capacity() {
        let mut idx = CacheIndex::new(20);
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("b", 0), 10);
        assert!(idx.remove(&key("a", 0)));
        assert!(!idx.remove(&key("a", 0))); // idempotent: already gone
        assert_eq!(idx.total_bytes(), 10);

        // Now `c` fits without evicting `b`.
        assert!(idx.record_insert(key("c", 0), 10).is_empty());
        assert!(idx.contains(&key("b", 0)));
        assert!(idx.contains(&key("c", 0)));
    }

    #[test]
    fn reinsert_same_key_updates_size_without_double_counting() {
        let mut idx = CacheIndex::new(100);
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("a", 0), 30); // overwrite with a larger chunk
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.total_bytes(), 30);
    }

    #[test]
    fn never_evicts_the_just_inserted_chunk_even_if_over_capacity() {
        let mut idx = CacheIndex::new(20);
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("b", 0), 10);
        // A single chunk larger than the whole capacity: everything else is
        // evicted, but the just-inserted chunk is kept (it was just requested).
        let evicted = idx.record_insert(key("big", 0), 50);
        assert_eq!(evicted.len(), 2);
        assert!(evicted.contains(&key("a", 0)));
        assert!(evicted.contains(&key("b", 0)));
        assert!(idx.contains(&key("big", 0)));
        assert_eq!(idx.total_bytes(), 50);
    }

    #[test]
    fn eviction_order_is_strict_lru_across_several_evictions() {
        let mut idx = CacheIndex::new(30); // three 10-byte slots
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("b", 0), 10);
        idx.record_insert(key("c", 0), 10);
        // Inserting two 10-byte chunks evicts the two oldest, in LRU order.
        let mut evicted = idx.record_insert(key("d", 0), 10);
        evicted.extend(idx.record_insert(key("e", 0), 10));
        assert_eq!(evicted, vec![key("a", 0), key("b", 0)]);
        assert!(idx.contains(&key("c", 0)));
        assert!(idx.contains(&key("d", 0)));
        assert!(idx.contains(&key("e", 0)));
    }

    #[test]
    fn remove_stream_drops_all_indices_of_one_blob_ref() {
        let mut idx = CacheIndex::new(100);
        idx.record_insert(key("a", 0), 10);
        idx.record_insert(key("a", 1), 10);
        idx.record_insert(key("b", 0), 10);
        assert_eq!(idx.remove_stream("a"), 2);
        assert!(!idx.contains(&key("a", 0)));
        assert!(!idx.contains(&key("a", 1)));
        assert!(idx.contains(&key("b", 0)));
        assert_eq!(idx.total_bytes(), 10);
        assert_eq!(idx.remove_stream("a"), 0); // idempotent
    }

    // ---- ColdTier fakes ----

    const REF: &str = "aabbccddeeff00112233445566778899/1/1";

    async fn cold_roundtrip(tier: &dyn ColdTier) {
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 0);
        assert!(tier.get_chunk(REF, 0).await.unwrap().is_none());

        tier.put_chunk(REF, 0, vec![0xAA; 16]).await.unwrap();
        tier.put_chunk(REF, 1, vec![0xBB; 16]).await.unwrap();
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 2);
        assert_eq!(tier.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xAA; 16]);

        // Per-chunk delete removes only that index.
        tier.delete_chunk(REF, 0).await.unwrap();
        assert!(tier.get_chunk(REF, 0).await.unwrap().is_none());
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 1);
        tier.delete_chunk(REF, 0).await.unwrap(); // idempotent
        tier.put_chunk(REF, 0, vec![0xAA; 16]).await.unwrap();

        tier.delete_stream(REF).await.unwrap();
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 0);
        tier.delete_stream(REF).await.unwrap(); // idempotent
    }

    #[tokio::test]
    async fn memory_cold_tier_roundtrip() {
        cold_roundtrip(&MemoryColdTier::new()).await;
    }

    #[tokio::test]
    async fn fs_cold_tier_roundtrip() {
        let r = maxsecu_crypto::random_array::<8>();
        let mut hex = String::new();
        for b in r {
            hex.push_str(&format!("{b:02x}"));
        }
        let dir = std::env::temp_dir().join(format!("mxcold_{hex}"));
        cold_roundtrip(&FsColdTier::new(&dir)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fs_cold_tier_rejects_unsafe_blob_ref() {
        let tier = FsColdTier::new(std::env::temp_dir().join("mxcold_guard"));
        assert!(tier.put_chunk("../escape", 0, vec![1]).await.is_err());
    }

    // ---- TieredBlobStore (cache over cold) ----

    fn tier_with_capacity(cap: u64) -> (TieredBlobStore, Arc<MemoryBlobStore>, Arc<MemoryColdTier>) {
        let cache = Arc::new(MemoryBlobStore::new());
        let cold = Arc::new(MemoryColdTier::new());
        let tier = TieredBlobStore::new(cache.clone(), cold.clone(), cap);
        (tier, cache, cold)
    }

    #[tokio::test]
    async fn tiered_put_is_write_through_to_cold_and_cache() {
        let (tier, cache, cold) = tier_with_capacity(1000);
        tier.put_chunk(REF, 0, vec![0x11; 10]).await.unwrap();
        // Durable record landed in cold AND a hot copy in the cache.
        assert_eq!(cold.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0x11; 10]);
        assert_eq!(cache.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0x11; 10]);
    }

    #[tokio::test]
    async fn tiered_get_miss_fetches_from_cold_and_populates_cache() {
        let (tier, cache, cold) = tier_with_capacity(1000);
        // Pre-load only the cold tier (as if this server never cached it yet).
        cold.put_chunk(REF, 0, vec![0x22; 10]).await.unwrap();
        assert!(cache.get_chunk(REF, 0).await.unwrap().is_none());

        let got = tier.get_chunk(REF, 0).await.unwrap().unwrap();
        assert_eq!(got, vec![0x22; 10]);
        // The cache is now warm for the next read.
        assert_eq!(cache.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0x22; 10]);
    }

    #[tokio::test]
    async fn tiered_get_hit_serves_from_cache_without_cold() {
        let (tier, _cache, cold) = tier_with_capacity(1000);
        tier.put_chunk(REF, 0, vec![0x33; 10]).await.unwrap();
        // Even if the cold tier loses the chunk, a cache hit still serves it.
        cold.delete_stream(REF).await.unwrap();
        assert_eq!(tier.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0x33; 10]);
    }

    #[tokio::test]
    async fn tiered_get_absent_everywhere_is_none() {
        let (tier, _cache, _cold) = tier_with_capacity(1000);
        assert!(tier.get_chunk(REF, 7).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tiered_eviction_drops_lru_from_cache_but_keeps_it_durable() {
        // Capacity for two 10-byte chunks.
        let (tier, cache, cold) = tier_with_capacity(20);
        tier.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        tier.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        tier.put_chunk(REF, 2, vec![0xA2; 10]).await.unwrap(); // overflow → evict index 0

        // Index 0 left the hot cache but remains durable in cold.
        assert!(cache.get_chunk(REF, 0).await.unwrap().is_none());
        assert_eq!(cold.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xA0; 10]);
        assert!(cache.get_chunk(REF, 2).await.unwrap().is_some());

        // A read of the evicted chunk transparently re-fetches from cold.
        assert_eq!(tier.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xA0; 10]);
    }

    #[tokio::test]
    async fn tiered_chunk_count_reflects_durable_cold_not_cache() {
        let (tier, _cache, _cold) = tier_with_capacity(20); // cache holds 2 of 3
        tier.put_chunk(REF, 0, vec![0xB0; 10]).await.unwrap();
        tier.put_chunk(REF, 1, vec![0xB1; 10]).await.unwrap();
        tier.put_chunk(REF, 2, vec![0xB2; 10]).await.unwrap();
        // All three are durable even though the cache only holds two.
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn tiered_delete_stream_clears_both_tiers_and_index() {
        let (tier, cache, cold) = tier_with_capacity(1000);
        tier.put_chunk(REF, 0, vec![0xC0; 10]).await.unwrap();
        tier.put_chunk(REF, 1, vec![0xC1; 10]).await.unwrap();

        tier.delete_stream(REF).await.unwrap();
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(cache.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(tier.chunk_count(REF).await.unwrap(), 0);
        // Index freed too: a later fill is unaffected by stale bookkeeping.
        assert!(tier.index.lock().unwrap().is_empty());
    }
}
