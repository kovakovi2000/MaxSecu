//! Write-back cold-tier offload (DESIGN §4.1/D31, api.md §9).
//!
//! A [`BlobStore`] that keeps freshly-uploaded ciphertext on a **local** store and
//! **lazily offloads** it to a durable [`ColdTier`] (Dropbox in prod) when the file
//! goes cold — either because it has not been requested for a configured idle span
//! (default 30 days) or because the local store is at its byte capacity and space
//! is needed for a new put/fetch. This is the **write-back** tiering model: unlike
//! the write-through [`crate::tier::TieredBlobStore`], a new upload is NOT copied to
//! the cold tier up front — it lands locally and only migrates on demand.
//!
//! # The cold tier is permanent
//! Once a chunk has been offloaded, the cold copy **stays** — a re-request pulls a
//! *copy* back into the local cache (for fast repeat access) but never deletes the
//! cold original, and a later eviction of that re-cached chunk just drops the local
//! copy (no re-upload — the durable cold copy is already there). A chunk leaves the
//! cold tier only when its whole stream is torn down through `delete_stream`, which
//! an owner delete reaches — and so does every version rotation, since
//! `http::finalize` purges the superseded version's streams the same way. So a
//! chunk is durably backed from its first offload until its version stops being
//! current; the redundancy gap is a chunk that has *never* been offloaded (fresh
//! upload, still local-only).
//!
//! # Chunk residency
//! Every stored chunk is in one of three states:
//! * **local-only** — freshly put, not yet offloaded (indexed, `in_cold=false`).
//! * **cold-only** — offloaded and evicted from local (not indexed).
//! * **both** — offloaded then re-cached on a read (indexed, `in_cold=true`); the
//!   cold copy is retained.
//!
//! `chunk_count` is `local + cold − overlap`, where `overlap` is the count of
//! this stream's chunks currently resident in *both* (the `in_cold=true` index
//! entries) — so a re-cached chunk is never double-counted. The sole production
//! caller (the finalize completeness check, `http::finalize`) runs right after
//! upload, before any read can re-cache, so `overlap` is zero there; tracking it
//! keeps the count correct in the rarer re-finalize-after-rehydrate case too.
//!
//! # Thumbnails & previews are pinned local
//! Thumbnail and Preview streams (the small artifacts the feed/browse UI needs
//! instantly) are **never offloaded** — they always stay on local disk — yet they
//! **do count** toward the local byte capacity. So a machine full of thumbnails
//! can sit at/over the cap with nothing evictable, which is the intended trade:
//! previews stay instant. Detected by the `stream_type` component of `blob_ref`.
//!
//! # Operator backup
//! [`WriteBackTier::backup_copy_refs`] is the one path that puts a chunk in cold
//! WITHOUT the offload protocol: it copies and KEEPS the local copy, closing the
//! never-offloaded redundancy gap on demand — thumbnails included. It is driven
//! by a caller-supplied ref list (from the DB) rather than the index, and only
//! finalized streams may be passed to it; its doc explains why each of those is
//! load-bearing rather than incidental.
//!
//! # Fail-safe
//! Every offload/rehydrate is **fail-safe**: a cold-tier I/O error leaves the chunk
//! exactly where it was (an offload never deletes a local copy it failed to durably
//! store), so a flaky cold tier degrades to "stays local / served from cold" — never
//! data loss. Chunks are inert ciphertext throughout (the client verifies every
//! byte against the signed manifest regardless of which tier served it,
//! `crate::blob`).

use crate::blob::{BlobError, BlobStore, ChunkStatus, DirectLink, FetchSource};
use crate::tier::{ChunkKey, ColdTier};
use async_trait::async_trait;
use maxsecu_encoding::types::StreamType;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Whether a `blob_ref`'s stream is a Thumbnail/Preview that must stay pinned to
/// local storage. `blob_ref` is `{hex}/{version}/{stream_type}` (`files::blob_ref`)
/// with `stream_type` the decimal [`StreamType`] discriminant.
fn is_pinned_stream(blob_ref: &str) -> bool {
    blob_ref
        .rsplit('/')
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|st| st == StreamType::Thumbnail as u8 || st == StreamType::Preview as u8)
}

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
            *t.lock().unwrap() += d;
        }
    }
}

/// One chunk to offload, with the residency fact the offload needs: an already-cold
/// (`in_cold`) chunk is dropped from local without re-uploading; a local-only one is
/// uploaded to cold first.
struct Victim {
    key: ChunkKey,
    in_cold: bool,
}

struct Entry {
    size: u64,
    /// Monotonic per-op counter — the LRU ordering key (tie-free even when several
    /// ops share one wall-clock instant, which a coarse/fixed clock readily does).
    last_tick: u64,
    /// Wall-clock last access — drives ONLY the idle-offload age decision.
    last_access: SystemTime,
    /// The chunk is also durably present in the cold tier (offloaded then re-cached).
    in_cold: bool,
    /// A Thumbnail/Preview stream: counts toward capacity but is never offloaded.
    pinned: bool,
}

/// Local residency bookkeeping: what the local tier holds, each chunk's size,
/// recency, cold-backing, and pin state, plus the running local byte total. Decides
/// eviction victims (LRU among non-pinned) and idle-offload victims. Holds no bytes.
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

    /// Record that `key` (`size` bytes, `in_cold`/`pinned` as given) is resident
    /// locally as of `now`, and return the chunks to **offload** (LRU first, never
    /// pinned, never the just-recorded key) to bring the local total back within
    /// `capacity_bytes`. If nothing is evictable (all remaining are pinned), the
    /// store stays over budget — pinned thumbnails/previews are kept regardless.
    fn record_put(
        &mut self,
        key: ChunkKey,
        size: u64,
        now: SystemTime,
        in_cold: bool,
        pinned: bool,
    ) -> Vec<Victim> {
        self.tick += 1;
        let t = self.tick;
        if let Some(prev) = self.entries.insert(
            key.clone(),
            Entry {
                size,
                last_tick: t,
                last_access: now,
                in_cold,
                pinned,
            },
        ) {
            self.total_bytes -= prev.size;
        }
        self.total_bytes += size;

        let mut victims = Vec::new();
        while self.total_bytes > self.capacity_bytes {
            let victim = self
                .entries
                .iter()
                .filter(|(k, e)| !e.pinned && **k != key)
                .min_by_key(|(_, e)| e.last_tick)
                .map(|(k, _)| k.clone());
            let Some(vk) = victim else {
                break; // nothing evictable — all remaining are pinned / just-inserted
            };
            let e = self.entries.remove(&vk).expect("just located");
            self.total_bytes -= e.size;
            victims.push(Victim {
                key: vk,
                in_cold: e.in_cold,
            });
        }
        victims
    }

    /// Bump `key`'s recency (a local cache hit). No-op if not resident.
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

    /// `Some(in_cold)` if `key` is resident locally, else `None` (cold-only/absent).
    fn in_cold_of(&self, key: &ChunkKey) -> Option<bool> {
        self.entries.get(key).map(|e| e.in_cold)
    }

    /// How many of `blob_ref`'s chunks are resident in BOTH tiers (indexed with
    /// `in_cold`) — the overlap to subtract from `local + cold` in `chunk_count`.
    fn overlap_count(&self, blob_ref: &str) -> u64 {
        self.entries
            .iter()
            .filter(|(k, e)| k.blob_ref == blob_ref && e.in_cold)
            .count() as u64
    }

    /// Non-pinned chunks whose last access is older than `now - idle` — the
    /// idle-offload victims for a background sweep.
    fn idle_victims(&self, now: SystemTime, idle: Duration) -> Vec<Victim> {
        let Some(cutoff) = now.checked_sub(idle) else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter(|(_, e)| !e.pinned && e.last_access <= cutoff)
            .map(|(k, e)| Victim {
                key: k.clone(),
                in_cold: e.in_cold,
            })
            .collect()
    }
}

/// A write-back tier: a local hot [`BlobStore`] that lazily offloads cold chunks to
/// a durable [`ColdTier`], keeping the cold copy permanent. See the module doc for
/// the residency states, the pin rule for thumbnails/previews, and the fail-safe
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

/// What one [`WriteBackTier::backup_copy_refs`] run actually managed to copy.
///
/// The counters and [`missing`](Self::missing) exist so an INCOMPLETE copy is
/// visible: a backup you wrongly believe is complete is worse than no backup, so
/// a caller must consult [`is_complete`](Self::is_complete) rather than read
/// `Ok(_)` as success.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Chunks this run uploaded to the cold tier.
    pub copied: u64,
    /// Chunks the cold tier already held — offloaded earlier, or copied by a
    /// previous run. Already backed up; nothing was done for these.
    pub already_cold: u64,
    /// `(blob_ref, index)` of every chunk found in NEITHER tier: the caller's
    /// records say the stream has it, `has_chunk` says cold does not, and the
    /// local store returned nothing. These are **not** in the backup.
    pub missing: Vec<(String, u64)>,
}

impl CopyReport {
    /// Whether every requested chunk is now durable in the cold tier.
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
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

    /// Offload one chunk from local, freeing its local bytes. An already-cold chunk
    /// (`in_cold`) is just dropped locally (its durable cold copy stays — no
    /// re-upload). A local-only chunk is uploaded to cold FIRST, then the local copy
    /// is deleted — fail-safe: a cold-write error leaves the local copy intact and
    /// is surfaced so the caller re-adopts it. A chunk already gone locally is a
    /// no-op.
    async fn offload(&self, key: &ChunkKey, in_cold: bool) -> Result<(), BlobError> {
        if in_cold {
            self.local.delete_chunk(&key.blob_ref, key.index).await?;
            return Ok(());
        }
        let bytes = match self.local.get_chunk(&key.blob_ref, key.index).await? {
            Some(b) => b,
            None => return Ok(()),
        };
        self.cold.put_chunk(&key.blob_ref, key.index, bytes).await?;
        self.local.delete_chunk(&key.blob_ref, key.index).await?;
        Ok(())
    }

    /// Offload each victim best-effort. `record_put`/`idle_victims` already dropped
    /// them from the index; a successful offload completes the local move. On the
    /// FIRST cold failure, re-adopt that victim AND every not-yet-processed one back
    /// into the index (they stay local, retried next trigger) and stop — never
    /// thrashing a down cold tier, never losing accounting for a chunk still local.
    async fn offload_victims(&self, victims: Vec<Victim>) {
        let mut iter = victims.into_iter();
        while let Some(v) = iter.next() {
            if self.offload(&v.key, v.in_cold).await.is_err() {
                self.readopt(&v.key, v.in_cold).await;
                for rest in iter {
                    self.readopt(&rest.key, rest.in_cold).await;
                }
                break;
            }
        }
    }

    /// Re-index a non-pinned chunk still on the local store (its offload failed or
    /// was skipped), restoring its byte accounting. Victims are never pinned.
    async fn readopt(&self, key: &ChunkKey, in_cold: bool) {
        if let Ok(Some(bytes)) = self.local.get_chunk(&key.blob_ref, key.index).await {
            let now = self.clock.now();
            let _ = self.index.lock().unwrap().record_put(
                key.clone(),
                bytes.len() as u64,
                now,
                in_cold,
                false,
            );
        }
    }

    /// Offload every non-pinned chunk idle longer than the configured span. Meant to
    /// be called periodically by a background task. Never holds the lock across
    /// `.await`.
    pub async fn run_idle_sweep(&self) {
        let now = self.clock.now();
        let victims = self.index.lock().unwrap().idle_victims(now, self.idle);
        self.offload_victims(victims).await;
    }

    /// Copy every chunk of every `(blob_ref, chunk_count)` in `refs` to the cold
    /// tier, **keeping the local copy** — the blob half of an operator backup.
    /// Idempotent and resumable (`has_chunk` short-circuits what is already
    /// durable), so a run interrupted by a network fault is simply re-run.
    ///
    /// `refs` is supplied by the caller from the DB (`file_streams`) because this
    /// method deliberately consults neither `LocalIndex` nor the pin rule. The
    /// index is in-memory and lazily populated, so on a freshly restarted server
    /// it is EMPTY — an index-driven backup (the shape of
    /// [`run_idle_sweep`](Self::run_idle_sweep)) would copy nothing and report
    /// success. The pin rule excludes every Thumbnail/Preview, which are never
    /// offloaded and so have no cold copy to fall back on: skipping them would
    /// silently omit them from the bundle. The DB is the only complete,
    /// restart-proof record of what exists.
    ///
    /// # Only finalized streams
    /// `refs` must name streams whose upload is **finalized**. Both the finalize
    /// check and the offload protocol assume a chunk reaches cold ONLY via
    /// `offload`, which deletes the local copy; a backup breaks that assumption on
    /// purpose, and on an in-flight stream it costs the user their upload:
    /// * [`chunk_count`](BlobStore::chunk_count) is `local + cold − overlap`, and
    ///   `overlap` is read from the index — which knows nothing of a copy made
    ///   here. A backed-up staged stream counts DOUBLE, so `http::finalize`'s
    ///   `chunk_count == expected` check rejects the client's finalize, and keeps
    ///   rejecting it on every retry.
    /// * A chunk re-PUT after being copied (a resumable upload re-sending a
    ///   missing index) leaves cold holding the SUPERSEDED bytes until some later
    ///   offload overwrites them — so a bundle taken now can carry ciphertext the
    ///   manifest will not verify.
    ///
    /// Marking the index from here is not the fix: a re-PUT racing the copy would
    /// leave the index claiming a cold copy that holds stale bytes, and the next
    /// offload would then drop the good local one. Filtering `refs` to finalized
    /// streams closes all of it — chunks of a finalized version are immutable
    /// (`http::put_chunk` 409s once `finalized`), which is what makes copying them
    /// behind the offload protocol's back safe.
    ///
    /// Fail-closed: any tier I/O error aborts and surfaces, unlike the best-effort
    /// idle sweep which swallows them. A chunk in neither tier is recorded in
    /// [`CopyReport::missing`] instead — one unreadable chunk must not cost the
    /// operator the rest of the corpus — but it makes the report incomplete, and
    /// the caller must treat that as a failed backup.
    pub async fn backup_copy_refs(&self, refs: &[(String, u64)]) -> Result<CopyReport, BlobError> {
        let mut report = CopyReport::default();
        for (blob_ref, chunk_count) in refs {
            for index in 0..*chunk_count {
                if self.cold.has_chunk(blob_ref, index).await? {
                    report.already_cold += 1;
                    continue;
                }
                let Some(bytes) = self.local.get_chunk(blob_ref, index).await? else {
                    // Re-probe before declaring a hole. `offload` puts to cold and
                    // THEN deletes the local copy, so a capacity-driven or idle
                    // offload landing between the probe above and this read leaves
                    // the chunk durable in cold yet absent locally — a local miss
                    // alone does not prove it is in neither tier. The server is
                    // live for the whole (multi-hour) copy, so that window is
                    // wide, and a false `missing` costs the operator the entire
                    // upgrade: the caller reads an incomplete report as a failed
                    // backup and aborts.
                    if self.cold.has_chunk(blob_ref, index).await? {
                        report.already_cold += 1;
                    } else {
                        report.missing.push((blob_ref.clone(), index));
                    }
                    continue;
                };
                self.cold.put_chunk(blob_ref, index, bytes).await?;
                report.copied += 1;
            }
        }
        Ok(report)
    }
}

#[async_trait]
impl BlobStore for WriteBackTier {
    async fn put_chunk(&self, blob_ref: &str, index: u64, bytes: Vec<u8>) -> Result<(), BlobError> {
        // Write-back: the local store is the only landing spot for a fresh upload.
        let size = bytes.len() as u64;
        self.local.put_chunk(blob_ref, index, bytes).await?;
        let now = self.clock.now();
        let pinned = is_pinned_stream(blob_ref);
        let victims = self.index.lock().unwrap().record_put(
            ChunkKey::new(blob_ref, index),
            size,
            now,
            false,
            pinned,
        );
        // Making room for the new chunk may push older ones to cold (capacity-driven
        // offload happens on upload too).
        self.offload_victims(victims).await;
        Ok(())
    }

    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        let key = ChunkKey::new(blob_ref, index);
        // Local hit: serve and bump recency (adopting it if unseen, e.g. post-restart).
        if let Some(bytes) = self.local.get_chunk(blob_ref, index).await? {
            let now = self.clock.now();
            let mut idx = self.index.lock().unwrap();
            if idx.contains(&key) {
                idx.record_access(&key, now);
            } else {
                let _ = idx.record_put(
                    key,
                    bytes.len() as u64,
                    now,
                    false,
                    is_pinned_stream(blob_ref),
                );
            }
            return Ok(Some(bytes));
        }
        // Local miss: the chunk is offloaded (cold) or truly absent.
        let fkey = (blob_ref.to_owned(), index);
        self.fetching.lock().unwrap().insert(fkey.clone());
        let fetched = self.cold.get_chunk(blob_ref, index).await;
        self.fetching.lock().unwrap().remove(&fkey);
        match fetched? {
            Some(bytes) => {
                // Rehydrate = COPY back to local; the cold copy is PERMANENT (kept),
                // so this chunk is now resident in both tiers (in_cold = true).
                let size = bytes.len() as u64;
                self.local.put_chunk(blob_ref, index, bytes.clone()).await?;
                let now = self.clock.now();
                let victims = self.index.lock().unwrap().record_put(
                    ChunkKey::new(blob_ref, index),
                    size,
                    now,
                    true,
                    is_pinned_stream(blob_ref),
                );
                self.offload_victims(victims).await;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        // A chunk in both tiers (re-cached) is counted once: local + cold − overlap.
        let local = self.local.chunk_count(blob_ref).await?;
        // Fail-safe: a cold-tier count error (e.g. Dropbox transiently 400/500ing on
        // list_folder) must NOT fail the finalize completeness check. Fall back to
        // the LOCAL count only. This can only ever UNDER-count (it never sees
        // cold-only chunks), so finalize stays fail-closed — it requires an EXACT
        // match with the expected chunk total, so an under-count can never falsely
        // report "complete"; it just leaves the upload retryable. For a fresh upload
        // every chunk is still local, so the local count is exact and the upload
        // finalizes even while the cold tier is entirely down. On this path there is
        // NO cold count, so overlap must not be subtracted (overlap only corrects a
        // double-count when BOTH tiers contributed) — we return the bare local count.
        let cold = match self.cold.chunk_count(blob_ref).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "maxsecu: cold-tier chunk_count failed for {blob_ref}; \
                     falling back to local count only: {e}"
                );
                return Ok(local);
            }
        };
        let overlap = self.index.lock().unwrap().overlap_count(blob_ref);
        Ok((local + cold).saturating_sub(overlap))
    }

    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        // Drop from BOTH tiers. TWO callers reach here, not one: an owner delete
        // (`http::discard_file` → `discard_unfinalized`/`delete_file`,
        // http.rs:1913/1927) and every version rotation — after a successful
        // `finalize_version`, `http::finalize` purges the PRIOR version's streams
        // through this method (http.rs:1453-1455). So a cold copy can disappear
        // with nobody having deleted anything, and "once offloaded, durably backed
        // for good" is only true for as long as the version stays current — the
        // premise an operator backup must not lean on. `delete_chunk` below is a
        // second cold-removal path, currently reached by no caller.
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
        // 1) Resident locally (hot) — includes re-cached (in-both) chunks.
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
        // A direct link is only valid for a chunk the cold tier actually holds. A
        // local-only chunk (offloaded==false) has no cold URL → None → server
        // proxies it. A chunk in both tiers CAN be brokered (cold has it).
        match self
            .index
            .lock()
            .unwrap()
            .in_cold_of(&ChunkKey::new(blob_ref, index))
        {
            Some(true) => {}                // re-cached: also in cold → brokerable
            Some(false) => return Ok(None), // local-only → proxy
            None => {}                      // cold-only or absent → let the cold tier decide
        }
        self.cold
            .broker_direct_link(blob_ref, index, ttl_secs)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::MemoryBlobStore;
    use crate::tier::MemoryColdTier;

    // A Content stream (stream_type 1) — offloadable.
    const REF: &str = "aabbccddeeff00112233445566778899/1/1";
    // A Thumbnail stream (stream_type 3) — pinned local, never offloaded.
    const THUMB: &str = "aabbccddeeff00112233445566778899/1/3";

    fn tier(
        cap: u64,
    ) -> (
        Arc<WriteBackTier>,
        Arc<MemoryBlobStore>,
        Arc<MemoryColdTier>,
        Clock,
    ) {
        let local = Arc::new(MemoryBlobStore::new());
        let cold = Arc::new(MemoryColdTier::new());
        let clock = Clock::Fixed(Arc::new(Mutex::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000),
        )));
        let t = Arc::new(WriteBackTier::with_clock(
            local.clone(),
            cold.clone(),
            cap,
            Duration::from_secs(30 * 24 * 3600),
            clock.clone(),
        ));
        (t, local, cold, clock)
    }

    #[test]
    fn pin_detection_matches_stream_type() {
        assert!(!is_pinned_stream(REF)); // content
        assert!(!is_pinned_stream("aa/1/2")); // metadata
        assert!(is_pinned_stream("aa/1/3")); // thumbnail
        assert!(is_pinned_stream("aa/1/4")); // preview
        assert!(!is_pinned_stream("garbage"));
    }

    #[tokio::test]
    async fn put_is_write_back_local_only_cold_stays_empty() {
        let (t, local, cold, _) = tier(1_000);
        t.put_chunk(REF, 0, vec![0xAA; 10]).await.unwrap();
        assert_eq!(
            local.get_chunk(REF, 0).await.unwrap().unwrap(),
            vec![0xAA; 10]
        );
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn capacity_pressure_offloads_lru_to_cold_and_deletes_local() {
        let (t, local, cold, _) = tier(20); // room for two 10-byte chunks
        t.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xA2; 10]).await.unwrap(); // overflow → offload idx 0

        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());
        assert_eq!(
            cold.get_chunk(REF, 0).await.unwrap().unwrap(),
            vec![0xA0; 10]
        );
        assert!(local.get_chunk(REF, 1).await.unwrap().is_some());
        assert!(local.get_chunk(REF, 2).await.unwrap().is_some());
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3); // 1 cold + 2 local, no loss
    }

    #[tokio::test]
    async fn access_bumps_recency_so_that_chunk_survives_eviction() {
        let (t, local, _cold, _) = tier(20);
        t.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        assert!(t.get_chunk(REF, 0).await.unwrap().is_some()); // touch 0 → 1 is LRU
        t.put_chunk(REF, 2, vec![0xA2; 10]).await.unwrap(); // evicts 1, not 0
        assert!(local.get_chunk(REF, 0).await.unwrap().is_some());
        assert!(local.get_chunk(REF, 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn get_miss_rehydrates_as_a_copy_keeping_the_permanent_cold_original() {
        let (t, local, cold, _) = tier(1_000);
        cold.put_chunk(REF, 0, vec![0xBB; 10]).await.unwrap(); // already offloaded
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());

        let got = t.get_chunk(REF, 0).await.unwrap().unwrap();
        assert_eq!(got, vec![0xBB; 10]);
        // Now resident in BOTH: local re-cached AND the cold original retained.
        assert_eq!(
            local.get_chunk(REF, 0).await.unwrap().unwrap(),
            vec![0xBB; 10]
        );
        assert_eq!(
            cold.get_chunk(REF, 0).await.unwrap().unwrap(),
            vec![0xBB; 10]
        );
        // Counted once, not twice.
        assert_eq!(t.chunk_count(REF).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn re_evicting_a_recached_chunk_drops_local_without_reupload() {
        // cap for ONE chunk; pre-offload idx 0 into cold, rehydrate it, then evict.
        let (t, local, cold, _) = tier(10);
        cold.put_chunk(REF, 0, vec![0xC0; 10]).await.unwrap();
        // Rehydrate idx 0 (now local+cold).
        assert!(t.get_chunk(REF, 0).await.unwrap().is_some());
        // A new put evicts idx 0 again — it is already in cold, so just drop local.
        t.put_chunk(REF, 1, vec![0xC1; 10]).await.unwrap();
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());
        // The permanent cold copy is still there (never deleted on eviction).
        assert_eq!(
            cold.get_chunk(REF, 0).await.unwrap().unwrap(),
            vec![0xC0; 10]
        );
        assert_eq!(t.chunk_count(REF).await.unwrap(), 2);
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
        clock.advance(Duration::from_secs(20 * 24 * 3600));
        assert!(t.get_chunk(REF, 0).await.unwrap().is_some()); // 0 touched → recent
        t.put_chunk(REF, 1, vec![0xC1; 10]).await.unwrap();
        clock.advance(Duration::from_secs(31 * 24 * 3600)); // 0 & 1 now idle > 30d
        t.put_chunk(REF, 2, vec![0xC2; 10]).await.unwrap(); // fresh → stays hot

        t.run_idle_sweep().await;

        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());
        assert!(local.get_chunk(REF, 1).await.unwrap().is_none());
        assert!(local.get_chunk(REF, 2).await.unwrap().is_some());
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 2);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn thumbnails_are_pinned_local_never_offloaded_but_counted() {
        // cap = 20 (two 10-byte chunks). Put a thumbnail + a content chunk (full),
        // then two more content chunks. The thumbnail must never be offloaded.
        let (t, local, cold, clock) = tier(20);
        t.put_chunk(THUMB, 0, vec![0x01; 10]).await.unwrap(); // pinned
        t.put_chunk(REF, 0, vec![0x02; 10]).await.unwrap(); // content (now at cap)
        t.put_chunk(REF, 1, vec![0x03; 10]).await.unwrap(); // evicts content idx 0, NOT the thumb
        t.put_chunk(REF, 2, vec![0x04; 10]).await.unwrap(); // evicts content idx 1

        // The thumbnail stayed local through every eviction; only content was offloaded.
        assert_eq!(
            local.get_chunk(THUMB, 0).await.unwrap().unwrap(),
            vec![0x01; 10]
        );
        assert_eq!(cold.chunk_count(THUMB).await.unwrap(), 0);
        assert!(cold.chunk_count(REF).await.unwrap() >= 1);

        // Idle sweep also never offloads the pinned thumbnail.
        clock.advance(Duration::from_secs(60 * 24 * 3600));
        t.run_idle_sweep().await;
        assert_eq!(
            local.get_chunk(THUMB, 0).await.unwrap().unwrap(),
            vec![0x01; 10]
        );
        assert_eq!(cold.chunk_count(THUMB).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn offload_is_fail_safe_when_cold_write_errors() {
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
        let t = WriteBackTier::new(
            local.clone(),
            Arc::new(FailingCold),
            20,
            Duration::from_secs(1),
        );
        t.put_chunk(REF, 0, vec![0xD0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xD1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xD2; 10]).await.unwrap(); // offload of idx 0 fails
        assert!(local.get_chunk(REF, 0).await.unwrap().is_some()); // kept — no loss
        assert_eq!(local.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn fresh_upload_succeeds_when_cold_chunk_count_errors() {
        // A cold tier whose chunk_count ALWAYS errors (models Dropbox transiently
        // 400ing on list_folder). A fresh multi-chunk upload is entirely local, so
        // WriteBackTier::chunk_count must fall back to the EXACT local count and let
        // finalize's `chunk_count == expected` completeness check pass — an upload
        // must not be blocked just because the cold tier's count is unavailable.
        struct CountErrCold;
        #[async_trait]
        impl ColdTier for CountErrCold {
            async fn put_chunk(&self, _r: &str, _i: u64, _b: Vec<u8>) -> Result<(), BlobError> {
                Ok(())
            }
            async fn get_chunk(&self, _r: &str, _i: u64) -> Result<Option<Vec<u8>>, BlobError> {
                Ok(None)
            }
            async fn chunk_count(&self, _r: &str) -> Result<u64, BlobError> {
                Err(BlobError::new(
                    "dropbox_chunk_count",
                    "dropbox http 400: path/malformed",
                ))
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
        let t = WriteBackTier::new(
            local.clone(),
            Arc::new(CountErrCold),
            1_000_000, // capacity never bites — all three chunks stay local
            Duration::from_secs(30 * 24 * 3600),
        );
        t.put_chunk(REF, 0, vec![0xF0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xF1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xF2; 10]).await.unwrap();
        // Cold count errors → fall back to the exact local count (3), so finalize's
        // completeness check passes and the upload finalizes even while cold is down.
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn delete_clears_both_tiers_and_index() {
        let (t, local, cold, _) = tier(20);
        t.put_chunk(REF, 0, vec![0xE0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xE1; 10]).await.unwrap();
        t.put_chunk(REF, 2, vec![0xE2; 10]).await.unwrap(); // idx 0 offloaded to cold
        t.delete_stream(REF).await.unwrap();
        assert_eq!(local.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn direct_link_none_for_local_some_for_cold_backed() {
        let (t, _local, _cold, _) = tier(10); // cap for ONE chunk
        t.put_chunk(REF, 0, vec![0x01; 10]).await.unwrap();
        // idx 0 local-only → no cold URL, proxy.
        assert!(t.broker_direct_link(REF, 0, 900).await.unwrap().is_none());
        // A second put evicts idx 0 to cold → now brokerable (cold-only).
        t.put_chunk(REF, 1, vec![0x02; 10]).await.unwrap();
        assert!(t.broker_direct_link(REF, 0, 900).await.unwrap().is_some());
    }

    // ---- backup_copy_refs (operator backup: copy to cold, keep local) ----

    /// A [`ColdTier`] that counts uploads, so a test can prove `backup_copy_refs`
    /// puts each chunk at most once across repeated runs.
    struct CountingCold {
        inner: MemoryColdTier,
        puts: std::sync::atomic::AtomicUsize,
    }
    impl CountingCold {
        fn new() -> Self {
            CountingCold {
                inner: MemoryColdTier::new(),
                puts: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn puts(&self) -> usize {
            self.puts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl ColdTier for CountingCold {
        async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.put_chunk(r, i, b).await
        }
        async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
            self.inner.get_chunk(r, i).await
        }
        async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
            self.inner.chunk_count(r).await
        }
        async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
            self.inner.delete_stream(r).await
        }
        async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
            self.inner.delete_chunk(r, i).await
        }
        async fn has_chunk(&self, r: &str, i: u64) -> Result<bool, BlobError> {
            self.inner.has_chunk(r, i).await
        }
    }

    #[tokio::test]
    async fn backup_copy_refs_copies_every_chunk_of_every_ref_to_cold() {
        let (t, local, cold, _) = tier(1_000_000);
        t.put_chunk(REF, 0, vec![0xA0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xA1; 10]).await.unwrap();
        t.put_chunk(THUMB, 0, vec![0xA2; 10]).await.unwrap();

        let report = t
            .backup_copy_refs(&[(REF.to_owned(), 2), (THUMB.to_owned(), 1)])
            .await
            .unwrap();
        assert_eq!(report.copied, 3);
        assert_eq!(report.already_cold, 0);
        assert!(report.is_complete());

        // Every chunk is durable in cold AND still local — a backup is a copy.
        for (r, i, b) in [(REF, 0, 0xA0), (REF, 1, 0xA1), (THUMB, 0, 0xA2)] {
            assert_eq!(cold.get_chunk(r, i).await.unwrap().unwrap(), vec![b; 10]);
            assert_eq!(local.get_chunk(r, i).await.unwrap().unwrap(), vec![b; 10]);
        }
    }

    /// The pin filter that keeps Thumbnail/Preview off the cold tier is an OFFLOAD
    /// rule, not a durability rule: a backup that skipped them would silently omit
    /// every thumbnail on the box. Regression test for modelling the copy on
    /// `idle_victims`, which filters `!e.pinned`.
    #[tokio::test]
    async fn backup_copy_refs_copies_pinned_streams_too() {
        let (t, local, cold, clock) = tier(1_000_000);
        t.put_chunk(THUMB, 0, vec![0x01; 10]).await.unwrap();

        // Neither trigger for offload will ever move a pinned chunk to cold.
        clock.advance(Duration::from_secs(60 * 24 * 3600));
        t.run_idle_sweep().await;
        assert_eq!(cold.chunk_count(THUMB).await.unwrap(), 0);

        let report = t.backup_copy_refs(&[(THUMB.to_owned(), 1)]).await.unwrap();
        assert_eq!(report.copied, 1);
        assert_eq!(
            cold.get_chunk(THUMB, 0).await.unwrap().unwrap(),
            vec![0x01; 10]
        );
        // Still pinned local: the backup did not turn it into an offload.
        assert!(local.get_chunk(THUMB, 0).await.unwrap().is_some());
    }

    /// `LocalIndex` is in-memory and lazily populated, so a freshly restarted
    /// server has an EMPTY index while every chunk is still on local disk. A
    /// backup driven off the index (the shape of `run_idle_sweep`) would copy
    /// nothing here and report success — the "backup you wrongly believe is
    /// complete" the design calls worse than no backup. `backup_copy_refs` is
    /// driven off the DB's `file_streams` instead and must not care.
    #[tokio::test]
    async fn backup_copy_refs_works_with_an_empty_local_index() {
        let (t, local, cold, clock) = tier(1_000_000);
        // Post-restart: bytes are on the local store, the index has never seen them.
        for i in 0..3u64 {
            local
                .put_chunk(REF, i, vec![0xB0 + i as u8; 10])
                .await
                .unwrap();
        }

        // The index-driven path is a no-op precisely because the index is empty.
        clock.advance(Duration::from_secs(60 * 24 * 3600));
        t.run_idle_sweep().await;
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 0);

        let report = t.backup_copy_refs(&[(REF.to_owned(), 3)]).await.unwrap();
        assert_eq!(report.copied, 3);
        assert!(report.is_complete());
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 3);
        for i in 0..3u64 {
            assert_eq!(
                cold.get_chunk(REF, i).await.unwrap().unwrap(),
                vec![0xB0 + i as u8; 10]
            );
        }
    }

    /// A backup uploads; it never evicts. The local store is left byte-identical
    /// even when it is already over its capacity budget — an operator backup must
    /// not double as a cache purge.
    #[tokio::test]
    async fn backup_copy_refs_evicts_nothing_even_when_local_is_over_capacity() {
        // Capacity for two chunks; four are already on disk (post-restart, so the
        // index has not accounted for them and cannot trim them either).
        let (t, local, _cold, _) = tier(20);
        for i in 0..4u64 {
            local.put_chunk(REF, i, vec![0xC0; 10]).await.unwrap();
        }
        t.backup_copy_refs(&[(REF.to_owned(), 4)]).await.unwrap();
        assert_eq!(local.chunk_count(REF).await.unwrap(), 4);
        for i in 0..4u64 {
            assert!(local.get_chunk(REF, i).await.unwrap().is_some());
        }
    }

    /// Resumable: a run interrupted by a cold-tier failure is re-run wholesale, so
    /// `has_chunk` must short-circuit everything already durable rather than
    /// re-uploading the corpus.
    #[tokio::test]
    async fn backup_copy_refs_is_idempotent_across_runs() {
        let local = Arc::new(MemoryBlobStore::new());
        let cold = Arc::new(CountingCold::new());
        let t = WriteBackTier::new(
            local.clone(),
            cold.clone(),
            1_000_000,
            Duration::from_secs(30 * 24 * 3600),
        );
        t.put_chunk(REF, 0, vec![0xD0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xD1; 10]).await.unwrap();

        let first = t.backup_copy_refs(&[(REF.to_owned(), 2)]).await.unwrap();
        assert_eq!((first.copied, first.already_cold), (2, 0));
        assert_eq!(cold.puts(), 2);

        let second = t.backup_copy_refs(&[(REF.to_owned(), 2)]).await.unwrap();
        assert_eq!((second.copied, second.already_cold), (0, 2));
        assert!(second.is_complete());
        assert_eq!(cold.puts(), 2); // no re-upload
    }

    /// A chunk that was offloaded and evicted lives ONLY in cold. It is already
    /// backed up — that is what `has_chunk` running first is for — so it must be
    /// counted, not read locally, and never treated as a fault.
    #[tokio::test]
    async fn backup_copy_refs_counts_a_cold_only_chunk_without_error() {
        let (t, local, cold, _) = tier(10); // capacity for ONE chunk
        t.put_chunk(REF, 0, vec![0xE0; 10]).await.unwrap();
        t.put_chunk(REF, 1, vec![0xE1; 10]).await.unwrap(); // evicts idx 0 to cold
        assert!(local.get_chunk(REF, 0).await.unwrap().is_none());

        let report = t.backup_copy_refs(&[(REF.to_owned(), 2)]).await.unwrap();
        assert_eq!(report.already_cold, 1); // idx 0: cold-only, already durable
        assert_eq!(report.copied, 1); // idx 1: local-only, uploaded now
        assert!(report.is_complete()); // nothing is missing
        assert!(report.missing.is_empty());
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 2);
    }

    /// The server stays live for the whole backup, so an offload can land between
    /// the cold probe and the local read — `offload` writes cold FIRST, then drops
    /// the local copy, which is exactly the interleaving that makes a local miss
    /// mean "already durable" rather than "gone". Reporting that as missing fails
    /// an otherwise-complete backup and aborts the operator's upgrade.
    #[tokio::test]
    async fn backup_copy_refs_re_probes_cold_before_calling_a_chunk_missing() {
        /// Answers `has_chunk` false the FIRST time it is asked about a key and
        /// truthfully thereafter — the racing offload completes in between.
        struct RacingCold {
            inner: MemoryColdTier,
            probed: Mutex<HashSet<(String, u64)>>,
        }
        #[async_trait]
        impl ColdTier for RacingCold {
            async fn put_chunk(&self, r: &str, i: u64, b: Vec<u8>) -> Result<(), BlobError> {
                self.inner.put_chunk(r, i, b).await
            }
            async fn get_chunk(&self, r: &str, i: u64) -> Result<Option<Vec<u8>>, BlobError> {
                self.inner.get_chunk(r, i).await
            }
            async fn chunk_count(&self, r: &str) -> Result<u64, BlobError> {
                self.inner.chunk_count(r).await
            }
            async fn delete_stream(&self, r: &str) -> Result<(), BlobError> {
                self.inner.delete_stream(r).await
            }
            async fn delete_chunk(&self, r: &str, i: u64) -> Result<(), BlobError> {
                self.inner.delete_chunk(r, i).await
            }
            async fn has_chunk(&self, r: &str, i: u64) -> Result<bool, BlobError> {
                if self.probed.lock().unwrap().insert((r.to_owned(), i)) {
                    return Ok(false);
                }
                self.inner.has_chunk(r, i).await
            }
        }

        let local = Arc::new(MemoryBlobStore::new());
        let cold = Arc::new(RacingCold {
            inner: MemoryColdTier::new(),
            probed: Mutex::new(HashSet::new()),
        });
        // The state the race leaves behind: the offload's put to cold has landed
        // and its local delete has run, so the chunk is durable but not local.
        cold.inner.put_chunk(REF, 0, vec![0x77; 10]).await.unwrap();

        let t = WriteBackTier::new(
            local.clone(),
            cold.clone(),
            1_000_000,
            Duration::from_secs(30 * 24 * 3600),
        );
        let report = t.backup_copy_refs(&[(REF.to_owned(), 1)]).await.unwrap();
        assert_eq!(report.already_cold, 1);
        assert_eq!(report.copied, 0);
        assert!(
            report.is_complete(),
            "a chunk durable in cold was reported missing: {:?}",
            report.missing
        );
    }

    /// A chunk in NEITHER tier is a hole in the backup. It must not abort the run
    /// — one unreadable chunk cannot cost the operator the other 200 GB — but it
    /// must be named in the report, and the report must stop claiming completeness.
    #[tokio::test]
    async fn backup_copy_refs_reports_a_chunk_missing_from_both_tiers() {
        let (t, _local, cold, _) = tier(1_000_000);
        t.put_chunk(REF, 0, vec![0xF0; 10]).await.unwrap();
        // The DB says this stream has three chunks; only index 0 exists anywhere.
        let report = t.backup_copy_refs(&[(REF.to_owned(), 3)]).await.unwrap();
        assert_eq!(report.copied, 1);
        assert_eq!(
            report.missing,
            vec![(REF.to_owned(), 1), (REF.to_owned(), 2)]
        );
        assert!(!report.is_complete());
        // The chunks that DO exist were still copied — a hole is not an abort.
        assert_eq!(cold.chunk_count(REF).await.unwrap(), 1);
    }

    /// Unlike the best-effort idle sweep (which swallows errors so a down cold tier
    /// never thrashes), a backup fails closed: a cold-tier fault surfaces instead
    /// of returning a report that under-reports what it copied.
    #[tokio::test]
    async fn backup_copy_refs_fails_closed_on_a_cold_tier_error() {
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
        let t = WriteBackTier::new(
            local.clone(),
            Arc::new(FailingCold),
            1_000_000,
            Duration::from_secs(30 * 24 * 3600),
        );
        t.put_chunk(REF, 0, vec![0x01; 10]).await.unwrap();
        assert!(t.backup_copy_refs(&[(REF.to_owned(), 1)]).await.is_err());
        // Fail-safe as ever: the local copy is untouched by the failed backup.
        assert!(local.get_chunk(REF, 0).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn status_transitions_cache_then_cold_ready() {
        let (t, _local, _cold, _) = tier(10);
        t.put_chunk(REF, 0, vec![0x11; 10]).await.unwrap();
        assert_eq!(
            t.chunk_status(REF, 0).await.unwrap().unwrap().source,
            FetchSource::Cache
        );
        t.put_chunk(REF, 1, vec![0x22; 10]).await.unwrap(); // evict 0 to cold
        assert_eq!(
            t.chunk_status(REF, 0).await.unwrap().unwrap().source,
            FetchSource::ColdReady
        );
        assert!(t.chunk_status(REF, 9).await.unwrap().is_none());
    }
}
