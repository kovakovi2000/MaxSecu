//! Write-back cold-tier offload (DESIGN §4.1/D31, api.md §9).
//!
//! A [`BlobStore`] that keeps freshly-uploaded ciphertext on a **local** store and
//! **lazily offloads** it to a durable [`ColdTier`] (Dropbox in prod) when the file
//! goes cold — either because it has not been requested for a configured idle span
//! (default 30 days) or because the local store is at its byte capacity and space
//! is needed for a new put/fetch. This is the **write-back** tiering model: unlike
//! the write-through [`crate::tier::TieredBlobStore`], a new upload is NOT copied to
//! the cold tier up front — it lands locally and only migrates on demand. That
//! minimizes what ever touches the untrusted cold store (and the egress it costs),
//! at the cost of a redundancy window: a chunk that has never been offloaded exists
//! only on local disk until its first offload.
//!
//! # local-XOR-cold invariant
//! Every stored chunk lives in **exactly one** tier at rest:
//! * `put_chunk` writes it **local-only**.
//! * offload (idle sweep or capacity eviction) **moves** it to cold — `cold.put`
//!   then `local.delete` — leaving it **cold-only**.
//! * a read miss **rehydrates** it — `cold.get` then `local.put` then `cold.delete`
//!   — moving it back to **local-only** (so a re-popular file is fast again, and the
//!   cold copy isn't left dangling).
//!
//! Because a chunk is never in both tiers at rest, `chunk_count` is simply
//! `local.chunk_count + cold.chunk_count` with no double-counting — and that holds
//! even across a process restart with an empty in-memory index (the index only
//! drives eviction/idle *bookkeeping*, never correctness of what is stored).
//!
//! All offload/rehydrate steps are **fail-safe**: a cold-tier I/O error leaves the
//! chunk exactly where it was (never deletes a copy it failed to write elsewhere),
//! so a flaky cold tier degrades to "stays local / served from cold" — never data
//! loss. The chunks are inert ciphertext throughout (the client verifies every byte
//! against the signed manifest regardless of which tier served it, `crate::blob`).

use crate::blob::{BlobError, BlobStore, ChunkStatus, DirectLink, FetchSource};
use crate::tier::{ChunkKey, ColdTier};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Injectable now-source so idle-offload tests can advance time deterministically
/// without sleeping.
#[derive(Clone)]
pub enum Clock {
    /// Real wall clock (production).
    System,
    /// A test clock that returns a fixed, manually-advanced instant.
    Fixed(Arc<Mutex<SystemTime>>),
}

impl Clock {
    pub fn now(&self) -> SystemTime {
        match self {
            Clock::System => SystemTime::now(),
            Clock::Fixed(t) => *t.lock().unwrap(),
        }
    }
    /// Advance a [`Clock::Fixed`] by `d` (no-op on [`Clock::System`]). Test helper.
    pub fn advance(&self, d: Duration) {
        if let Clock::Fixed(t) = self {
            let mut g = t.lock().unwrap();
            *g += d;
        }
    }
}

struct Entry {
    size: u64,
    /// Monotonic per-index operation counter — the LRU ordering key. Strictly
    /// increasing per put/access so eviction order is total and tie-free even when
    /// several operations land in the same wall-clock instant (which a coarse
    /// `SystemTime` or a fixed test clock readily does).
    last_tick: u64,
    /// Wall-clock last-access — drives ONLY the idle-offload age decision, never the
    /// LRU order (see `last_tick`).
    last_access: SystemTime,
}

/// Purely-local residency bookkeeping: what the local tier currently holds, each
/// chunk's size + last-access time, and the running local byte total. Decides the
/// eviction victims (LRU) and the idle-offload victims (older than a threshold). It
/// holds **no bytes** and is not authoritative for what is *stored* — only for what
/// to migrate and when.
struct LocalIndex {
    capacity_bytes: u64,
    total_bytes: u64,
    tick: u64,
    entries: HashMap<ChunkKey, Entry>,
}

impl LocalIndex {
    fn new(capacity_bytes: u64) -> Self {
        LocalIndex {
            capacity_bytes,
            total_bytes: 0,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    /// Record that `key` (now `size` bytes) is resident locally as of `now`, and
    /// return the keys to **offload** (LRU first) to bring the local total back
    /// within `capacity_bytes`. The just-recorded key is never a victim (newest
    /// access), and a single over-capacity chunk is kept (`len > 1` guard) — it has
    /// nowhere cheaper to go and was just requested.
    fn record_put(&mut self, key: ChunkKey, size: u64, now: SystemTime) -> Vec<ChunkKey> {
        self.tick += 1;
        let t = self.tick;
        if let Some(prev) = self.entries.insert(
            key,
            Entry {
                size,
                last_tick: t,
                last_access: now,
            },
        ) {
            self.total_bytes -= prev.size;
        }
        self.total_bytes += size;

        let mut victims = Vec::new();
        while self.total_bytes > self.capacity_bytes && self.entries.len() > 1 {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_tick)
                .map(|(k, _)| k.clone())
                .expect("non-empty: len > 1");
            let e = self.entries.remove(&victim).expect("just located");
            self.total_bytes -= e.size;
            victims.push(victim);
        }
        victims
    }

    /// Bump `key`'s recency (a local cache hit): both the LRU tick and the
    /// wall-clock access time. No-op if not resident.
    fn record_access(&mut self, key: &ChunkKey, now: SystemTime) {
        self.tick += 1;
        let t = self.tick;
        if let Some(e) = self.entries.get_mut(key) {
            e.last_tick = t;
            e.last_access = now;
        }
    }

    fn remove(&mut self, key: &ChunkKey) {
        if let Some(e) = self.entries.remove(key) {
            self.total_bytes -= e.size;
        }
    }

    fn remove_stream(&mut self, blob_ref: &str) {
        let victims: Vec<ChunkKey> = self
            .entries
            .keys()
            .filter(|k| k.blob_ref == blob_ref)
            .cloned()
            .collect();
        for k in &victims {
            self.remove(k);
        }
    }

    fn contains(&self, key: &ChunkKey) -> bool {
        self.entries.contains_key(key)
    }

    fn size_of(&self, key: &ChunkKey) -> Option<u64> {
        self.entries.get(key).map(|e| e.size)
    }

    /// The keys whose last access is older than `now - idle` — the idle-offload
    /// victims for a background sweep.
    fn idle_victims(&self, now: SystemTime, idle: Duration) -> Vec<ChunkKey> {
        let cutoff = now.checked_sub(idle);
        let Some(cutoff) = cutoff else {
            return Vec::new(); // now < idle since the epoch — nothing is that old
        };
        self.entries
            .iter()
            .filter(|(_, e)| e.last_access <= cutoff)
            .map(|(k, _)| k.clone())
            .collect()
    }
}

/// A write-back tier: a local hot [`BlobStore`] that lazily offloads cold chunks to
/// a durable [`ColdTier`]. Drops into `AppState` as a single `BlobStore`. See the
/// module doc for the local-XOR-cold invariant and the offload/rehydrate/fail-safe
/// contract.
pub struct WriteBackTier {
    local: Arc<dyn BlobStore>,
    cold: Arc<dyn ColdTier>,
    index: Mutex<LocalIndex>,
    idle: Duration,
    clock: Clock,
    /// Keys with a cold fetch in flight — drives the `cold-fetching` status.
    fetching: Mutex<HashSet<(String, u64)>>,
}

impl WriteBackTier {
    /// New write-back tier: `local` is the hot on-disk store, `cold` the durable
    /// backing tier, `capacity_bytes` the local byte budget, `idle` the
    /// not-requested-for span after which a chunk is offloaded by the background
    /// sweep. Uses the real system clock.
    pub fn new(
        local: Arc<dyn BlobStore>,
        cold: Arc<dyn ColdTier>,
        capacity_bytes: u64,
        idle: Duration,
    ) -> Self {
        Self::with_clock(local, cold, capacity_bytes, idle, Clock::System)
    }

    /// As [`new`](Self::new) but with an injectable [`Clock`] (idle-sweep tests).
    pub fn with_clock(
        local: Arc<dyn BlobStore>,
        cold: Arc<dyn ColdTier>,
        capacity_bytes: u64,
        idle: Duration,
        clock: Clock,
    ) -> Self {
        WriteBackTier {
            local,
            cold,
            index: Mutex::new(LocalIndex::new(capacity_bytes)),
            idle,
            clock,
            fetching: Mutex::new(HashSet::new()),
        }
    }

    /// Offload one local chunk to the cold tier and delete the local copy (the
    /// local→cold **move**). Fail-safe: if the cold write fails the local copy is
    /// kept and the chunk stays indexed (re-inserted by the caller), so nothing is
    /// ever lost. A local chunk that has already vanished is a no-op.
    async fn offload(&self, key: &ChunkKey) -> Result<(), BlobError> {
        let bytes = match self.local.get_chunk(&key.blob_ref, key.index).await? {
            Some(b) => b,
            None => return Ok(()), // already gone — nothing to move
        };
        // cold.put FIRST; only delete the local copy once the durable write landed.
        self.cold
            .put_chunk(&key.blob_ref, key.index, bytes)
            .await?;
        self.local.delete_chunk(&key.blob_ref, key.index).await?;
        Ok(())
    }

    /// Offload each victim best-effort. `record_put` already removed every victim
    /// from the index (they are the returned eviction set); a successful offload just
    /// completes the local→cold move. On the FIRST cold failure we re-adopt that
    /// victim AND every not-yet-processed one back into the index (they stay local,
    /// retried on the next trigger) and stop — never thrashing a down cold tier, and
    /// never dropping accounting for a chunk still on local disk.
    async fn offload_victims(&self, victims: Vec<ChunkKey>) {
        let mut iter = victims.into_iter();
        for key in iter.by_ref() {
            if self.offload(&key).await.is_err() {
                self.readopt(&key).await;
                let rest: Vec<ChunkKey> = iter.collect();
                for k in rest {
                    self.readopt(&k).await;
                }
                break;
            }
        }
    }

    /// Re-index a chunk that is still on the local store (its offload failed or was
    /// skipped), restoring its byte accounting so a later trigger reconsiders it.
    async fn readopt(&self, key: &ChunkKey) {
        if let Ok(Some(bytes)) = self.local.get_chunk(&key.blob_ref, key.index).await {
            let now = self.clock.now();
            let _ = self
                .index
                .lock()
                .unwrap()
                .record_put(key.clone(), bytes.len() as u64, now);
        }
    }

    /// Offload every chunk idle longer than the configured span. Meant to be called
    /// periodically by a background task. Never holds the index lock across `.await`.
    pub async fn run_idle_sweep(&self) {
        let now = self.clock.now();
        let victims = self.index.lock().unwrap().idle_victims(now, self.idle);
        self.offload_victims(victims).await;
    }
}

#[async_trait]
impl BlobStore for WriteBackTier {
    async fn put_chunk(&self, blob_ref: &str, index: u64, bytes: Vec<u8>) -> Result<(), BlobError> {
        // Write-back: the local store is the only landing spot for a fresh upload.
        let size = bytes.len() as u64;
        self.local.put_chunk(blob_ref, index, bytes).await?;
        let now = self.clock.now();
        let victims = self
            .index
            .lock()
            .unwrap()
            .record_put(ChunkKey::new(blob_ref, index), size, now);
        // Making room for the new chunk may push older ones to cold (capacity-driven
        // offload happens on upload too, per the design).
        self.offload_victims(victims).await;
        Ok(())
    }

    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        let key = ChunkKey::new(blob_ref, index);
        // Local hit: serve and bump recency.
        if let Some(bytes) = self.local.get_chunk(blob_ref, index).await? {
            let now = self.clock.now();
            let mut idx = self.index.lock().unwrap();
            if idx.contains(&key) {
                idx.record_access(&key, now);
            } else {
                // Post-restart (or first sight): adopt it into the index so it is
                // subject to eviction/idle bookkeeping from now on.
                let _ = idx.record_put(key, bytes.len() as u64, now);
            }
            return Ok(Some(bytes));
        }
        // Local miss: the chunk is either offloaded (in cold) or truly absent.
        let fkey = (blob_ref.to_owned(), index);
        self.fetching.lock().unwrap().insert(fkey.clone());
        let fetched = self.cold.get_chunk(blob_ref, index).await;
        self.fetching.lock().unwrap().remove(&fkey);
        match fetched? {
            Some(bytes) => {
                // Rehydrate = move back to local: write local, then drop the cold
                // copy (keeps the XOR invariant). If the cold delete fails the chunk
                // is briefly in both tiers — harmless (a later offload overwrites +
                // re-deletes); never data loss.
                let size = bytes.len() as u64;
                self.local.put_chunk(blob_ref, index, bytes.clone()).await?;
                let _ = self.cold.delete_chunk(blob_ref, index).await;
                let now = self.clock.now();
                let victims = self
                    .index
                    .lock()
                    .unwrap()
                    .record_put(ChunkKey::new(blob_ref, index), size, now);
                self.offload_victims(victims).await;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        // local-XOR-cold ⇒ the two counts are disjoint; their sum is the true total,
        // correct even with an empty in-memory index (e.g. right after a restart).
        let local = self.local.chunk_count(blob_ref).await?;
        let cold = self.cold.chunk_count(blob_ref).await?;
        Ok(local + cold)
    }

    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        self.local.delete_stream(blob_ref).await?;
        self.cold.delete_stream(blob_ref).await?;
        self.index.lock().unwrap().remove_stream(blob_ref);
        Ok(())
    }

    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError> {
        self.local.delete_chunk(blob_ref, index).await?;
        self.cold.delete_chunk(blob_ref, index).await?;
        self.index
            .lock()
            .unwrap()
            .remove(&ChunkKey::new(blob_ref, index));
        Ok(())
    }

    async fn chunk_status(
        &self,
        blob_ref: &str,
        index: u64,
    ) -> Result<Option<ChunkStatus>, BlobError> {
        let key = ChunkKey::new(blob_ref, index);
        // 1) Resident locally (hot).
        if let Some(size) = self.index.lock().unwrap().size_of(&key) {
            return Ok(Some(ChunkStatus {
                source: FetchSource::Cache,
                fetched_bytes: size,
                total_bytes: size,
            }));
        }
        // 2) A rehydrate fetch is in flight.
        if self
            .fetching
            .lock()
            .unwrap()
            .contains(&(blob_ref.to_owned(), index))
        {
            return Ok(Some(ChunkStatus {
                source: FetchSource::ColdFetching,
                fetched_bytes: 0,
                total_bytes: 0,
            }));
        }
        // 3) Offloaded, idle — a GET will rehydrate it.
        if self.cold.has_chunk(blob_ref, index).await? {
            return Ok(Some(ChunkStatus {
                source: FetchSource::ColdReady,
                fetched_bytes: 0,
                total_bytes: 0,
            }));
        }
        Ok(None)
    }

    async fn broker_direct_link(
        &self,
        blob_ref: &str,
        index: u64,
        ttl_secs: u64,
    ) -> Result<Option<DirectLink>, BlobError> {
        // A direct link only exists for an offloaded (cold-resident) chunk; a
        // still-local chunk has no cold URL, so the server proxies it (None → the
        // handler falls back to a proxied fetch).
        if self
            .index
            .lock()
            .unwrap()
            .contains(&ChunkKey::new(blob_ref, index))
        {
            return Ok(None);
        }
        self.cold.broker_direct_link(blob_ref, index, ttl_secs).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{MemoryBlobStore};
    use crate::tier::MemoryColdTier;

    const REF: &str = "aabbccddeeff00112233445566778899/1/1";

    fn tier(cap: u64) -> (Arc<WriteBackTier>, Arc<MemoryBlobStore>, Arc<MemoryColdTier>, Clock) {
        let local = Arc::new(MemoryBlobStore::new());
        let cold = Arc::new(MemoryColdTier::new());
        let clock = Clock::Fixed(Arc::new(Mutex::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000))));
        let t = Arc::new(WriteBackTier::with_clock(
            local.clone(),
            cold.clone(),
            cap,
            Duration::from_secs(30 * 24 * 3600),
            clock.clone(),
        ));
        (t, local, cold, clock)
    }

    #[tokio::test]
    async fn put_is_write_back_local_only_cold_stays_empty() {
        let (t, local, cold, _) = tier(1_000);
        t.put_chunk(REF, 0, vec![0xAA; 10]).await.unwrap();
        // Landed locally; the cold tier was NOT touched (unlike write-through).
        assert_eq!(local.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xAA; 10]);
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn capacity_pressure_moves_lru_to_cold_and_deletes_local() {
        // Room for two 10-byte chunks.
        let (t, local, cold, _) = tier(20);
        t.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xA2; 10]).await.unwrap(); // overflow → offload idx 0

        // Index 0 was MOVED to cold: gone from local, present in cold.
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());
        assert_eq!(cold.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xA0; 10]);
        // 1 and 2 are still local.
        assert!(local.get_chunk(REF, 1).await.unwrap().is_some());
        assert!(local.get_chunk(REF, 2).await.unwrap().is_some());
        // Union count is still 3 (1 cold + 2 local) — nothing lost, no double count.
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn access_bumps_recency_so_that_chunk_survives_eviction() {
        let (t, local, _cold, _) = tier(20);
        t.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        // Touch 0 so 1 becomes the LRU.
        assert!(t.get_chunk(REF, 0).await.unwrap().is_some());
        t.put_chunk(REF, 2, vec![0xA2; 10]).await.unwrap(); // evicts 1, not 0
        assert!(local.get_chunk(REF, 0).await.unwrap().is_some());
        assert!(local.get_chunk(REF, 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_miss_rehydrates_from_cold_moving_it_back_to_local() {
        let (t, local, cold, _) = tier(1_000);
        // Simulate an already-offloaded chunk: present only in cold.
        cold.put_chunk(REF, 0, vec![0xBB; 10]).await.unwrap();
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());

        let got = t.get_chunk(REF, 0).await.unwrap().unwrap();
        assert_eq!(got, vec![0xBB; 10]);
        // Rehydrated: now local, and REMOVED from cold (XOR invariant preserved).
        assert_eq!(local.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xBB; 10]);
        assert!(cold.get_chunk(REF, 0).await.unwrap().is_none());
        assert_eq!(t.chunk_count(REF).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn get_absent_everywhere_is_none() {
        let (t, _l, _c, _) = tier(1_000);
        assert!(t.get_chunk(REF, 7).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn idle_sweep_offloads_only_chunks_past_the_threshold() {
        let (t, local, cold, clock) = tier(1_000_000); // capacity never bites here
        t.put_chunk(REF, 0, vec![0xC0; 10]).await.unwrap();
        // Advance 20 days, then touch 0 and add 1 — both now "recent".
        clock.advance(Duration::from_secs(20 * 24 * 3600));
        assert!(t.get_chunk(REF, 0).await.unwrap().is_some());
        t.put_chunk(REF, 1, vec![0xC1; 10]).await.unwrap();
        // Advance to 31 days after 0/1's last touch: both are now idle > 30d.
        clock.advance(Duration::from_secs(31 * 24 * 3600));
        // A brand-new chunk stays hot.
        t.put_chunk(REF, 2, vec![0xC2; 10]).await.unwrap();

        t.run_idle_sweep().await;

        // 0 and 1 were offloaded (idle); 2 stays local (fresh).
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());
        assert!(local.get_chunk(REF, 1).await.unwrap().is_none());
        assert!(local.get_chunk(REF, 2).await.unwrap().is_some());
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 2);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn offload_is_fail_safe_when_cold_write_errors() {
        // A cold tier whose put_chunk always fails.
        struct FailingCold;
        #[async_trait]
        impl ColdTier for FailingCold {
            async fn put_chunk(&self, _r: &str, _i: u64, _b: Vec<u8>) -> Result<(), BlobError> {
                Err(BlobError::new("test", "cold down"))
            }
            async fn get_chunk(&self, _r: &str, _i: u64) -> Result<Option<Vec<u8>>, BlobError> {
                Ok(None)
            }
            async fn chunk_count(&self, _r: &str) -> Result<u64, BlobError> {
                Ok(0)
            }
            async fn delete_stream(&self, _r: &str) -> Result<(), BlobError> {
                Ok(())
            }
            async fn delete_chunk(&self, _r: &str, _i: u64) -> Result<(), BlobError> {
                Ok(())
            }
            async fn has_chunk(&self, _r: &str, _i: u64) -> Result<bool, BlobError> {
                Ok(false)
            }
        }
        let local = Arc::new(MemoryBlobStore::new());
        let t = WriteBackTier::new(local.clone(), Arc::new(FailingCold), 20, Duration::from_secs(1));
        t.put_chunk(REF, 0, vec![0xD0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xD1; 10]).await.unwrap();
        // This put overflows capacity → tries to offload idx 0, but cold is down.
        t.put_chunk(REF, 2, vec![0xD2; 10]).await.unwrap();
        // Nothing was lost: idx 0 is still local (offload failed → kept).
        assert!(local.get_chunk(REF, 0).await.unwrap().is_some());
        assert_eq!(local.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn delete_clears_both_tiers_and_index() {
        let (t, local, cold, _) = tier(20);
        t.put_chunk(REF, 0, vec![0xE0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xE1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xE2; 10]).await.unwrap(); // 0 offloaded to cold
        t.delete_stream(REF).await.unwrap();
        assert_eq!(local.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn direct_link_none_for_local_some_for_offloaded() {
        let (t, _local, _cold, _) = tier(10); // capacity for ONE 10-byte chunk
        t.put_chunk(REF, 0, vec![0x01; 10]).await.unwrap();
        // idx 0 is local → no cold URL, server must proxy.
        assert!(t.broker_direct_link(REF, 0, 900).await.unwrap().is_none());
        // A second put evicts idx 0 to cold → now a direct link is brokerable.
        t.put_chunk(REF, 1, vec![0x02; 10]).await.unwrap();
        let link = t.broker_direct_link(REF, 0, 900).await.unwrap();
        assert!(link.is_some(), "an offloaded chunk should have a cold direct link");
    }

    #[tokio::test]
    async fn status_transitions_cache_then_cold_ready() {
        let (t, _local, _cold, _) = tier(10);
        t.put_chunk(REF, 0, vec![0x11; 10]).await.unwrap();
        assert_eq!(
            t.chunk_status(REF, 0).await.unwrap().unwrap().source,
            FetchSource::Cache
        );
        // Evict 0 to cold; it should now report ColdReady.
        t.put_chunk(REF, 1, vec![0x22; 10]).await.unwrap();
        assert_eq!(
            t.chunk_status(REF, 0).await.unwrap().unwrap().source,
            FetchSource::ColdReady
        );
        // A never-stored chunk is absent everywhere.
        assert!(t.chunk_status(REF, 9).await.unwrap().is_none());
    }
}
