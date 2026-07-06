//! Sealed feed-card cache (the "Thumbnails" cache). One BlobCache under Ns::Card
//! holding CachedMeta serialized + SessionSeal-sealed (so an OS page-out spills
//! only ciphertext). Replaces the old plaintext ContentCache's card side; full
//! content payloads live in MediaCache Ns::Content.

use std::io;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::blob_cache::{BlobCache, Ns};
use crate::commands::feed::hex;
use crate::config::FragmentCacheLocation;
use crate::dto::CardDto;
use crate::session_seal::SessionSeal;

/// The cache key: a content id is unique per (file, version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub file_id: [u8; 16],
    pub version: u64,
}

/// Small, render-ready metadata shared by the card + the content DTOs. No key
/// material; this is exactly what already crosses to the UI. Serialized (JSON) and
/// sealed under the process [`SessionSeal`] before it rests in the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedMeta {
    pub file_type: String,
    pub title: String,
    pub tags: Vec<String>,
    pub thumbnail_b64: Option<String>,
    pub author_fp: String,
    pub recovery_ok: bool,
    pub mine: bool,
    /// Bundle member tally (order-private counts). Zeros for a non-bundle card.
    pub member_counts: crate::dto::MemberCounts,
}

/// The Thumbnails cache: sealed card meta in a `BlobCache` under `Ns::Card`, own
/// (256 MB default) budget. The `seal` is the process-global ephemeral key shared
/// with the Media cache's `Content` payloads, so a page-out spills only ciphertext.
///
/// Seal-ownership asymmetry (by design): everything ThumbCache stores is sealed, so
/// it OWNS an `Arc<SessionSeal>` clone. [`MediaCache`](crate::media_cache::MediaCache)
/// instead takes the seal as a per-call PARAMETER and stores no key material — it
/// also holds raw, UNSEALED `Ns::Frag` video ciphertext, so it stays key-less. Both
/// ultimately share the one process seal generated in `main.rs`.
pub struct ThumbCache {
    cache: Arc<Mutex<BlobCache>>,
    seal: Arc<SessionSeal>,
}

impl ThumbCache {
    /// Open the Thumbnails cache. Memory → `Some(cap)` enforced LRU; Disk → `None`
    /// (uncapped). On-disk blobs live under `cache/thumb/`. Fallible: opened ONCE at
    /// startup, so a bad/unwritable dir in Disk mode surfaces a clean fatal-init
    /// error rather than a panic.
    pub fn new(
        app_dir: &Path,
        cap_mb: u32,
        loc: FragmentCacheLocation,
        seal: Arc<SessionSeal>,
    ) -> io::Result<Self> {
        let cap = match loc {
            FragmentCacheLocation::Memory => Some(cap_mb as u64 * 1024 * 1024),
            FragmentCacheLocation::Disk => None,
        };
        let bc = BlobCache::open_located(app_dir, cap, loc, "thumb")?;
        Ok(ThumbCache {
            cache: Arc::new(Mutex::new(bc)),
            seal,
        })
    }

    /// The `(id_hex, sub)` backend key for a `CacheKey`. `version as u32` is safe:
    /// file versions are small monotonic counters that never approach `u32::MAX`
    /// (BlobCache's `sub` is a `u32`), so the truncation can never collide.
    fn key_parts(key: CacheKey) -> (String, u32) {
        (hex(&key.file_id), key.version as u32)
    }

    /// Insert/update a card's sealed meta. ENRICHMENT: if `meta.thumbnail_b64` is
    /// absent, carry forward any thumbnail already sealed under this key (so a
    /// later thumbnail-less card-put — e.g. the viewer's content-put path — does
    /// not clobber the feed thumbnail). "Content survives a card-put" is now
    /// automatic: content lives in MediaCache, untouched here.
    pub async fn put_card(&self, key: CacheKey, mut meta: CachedMeta) {
        let (id_hex, sub) = Self::key_parts(key);
        let mut cache = self.cache.lock().await;
        if meta.thumbnail_b64.is_none() {
            if let Some(sealed) = cache.get(Ns::Card, &id_hex, sub) {
                if let Some(pt) = self.seal.open(&sealed) {
                    if let Ok(old) = serde_json::from_slice::<CachedMeta>(&pt) {
                        if old.thumbnail_b64.is_some() {
                            meta.thumbnail_b64 = old.thumbnail_b64;
                        }
                    }
                }
            }
        }
        if let Ok(json) = serde_json::to_vec(&meta) {
            let sealed = self.seal.seal(&json);
            let _ = cache.put(Ns::Card, &id_hex, sub, &sealed);
        }
    }

    /// Reconstruct a verified card DTO from the sealed meta, or `None` on a miss /
    /// tamper / wrong-key unseal (fail-closed).
    pub async fn get_card(&self, key: CacheKey, file_id_hex: &str) -> Option<CardDto> {
        let meta = self.get_meta(key).await?;
        Some(CardDto {
            file_id: file_id_hex.to_owned(),
            file_type: meta.file_type,
            version: key.version,
            title: meta.title,
            tags: meta.tags,
            thumbnail_b64: meta.thumbnail_b64,
            mine: meta.mine,
            author_fp: meta.author_fp,
            recovery_ok: meta.recovery_ok,
            member_counts: meta.member_counts,
        })
    }

    /// Read + unseal the raw [`CachedMeta`] (used by the viewer's content-hit to
    /// shape the `OpenedContentDto`). `None` on miss / tamper.
    pub async fn get_meta(&self, key: CacheKey) -> Option<CachedMeta> {
        let (id_hex, sub) = Self::key_parts(key);
        let sealed = self.cache.lock().await.get(Ns::Card, &id_hex, sub)?;
        let pt = self.seal.open(&sealed)?;
        serde_json::from_slice(&pt).ok()
    }

    /// Drop one `(file, version)` card entry (a newer version supersedes it).
    pub async fn invalidate(&self, key: CacheKey) {
        let (id_hex, sub) = Self::key_parts(key);
        self.cache.lock().await.evict(Ns::Card, &id_hex, sub);
    }

    /// Drop EVERY version's card entry for a file id (post/bundle deletion).
    pub async fn invalidate_file(&self, file_id: [u8; 16]) {
        self.cache
            .lock()
            .await
            .evict_prefix(Ns::Card, &hex(&file_id));
    }

    /// Live cap change (Settings). MiB → bytes; a smaller cap evicts now. Gated on
    /// Memory mode: a `Disk` cache is uncapped (`None`), and a bare `set_cap` would
    /// wrongly turn it capped, so it is a no-op there. (The live Settings path now
    /// goes through [`apply_location_and_cap`](Self::apply_location_and_cap), which
    /// also handles the location toggle; this stays for the unit tests + any direct
    /// caller.)
    pub async fn set_cap_mb(&self, cap_mb: u32) {
        let mut c = self.cache.lock().await;
        if !c.is_disk() {
            c.set_cap(cap_mb as u64 * 1024 * 1024);
        }
    }

    /// The header gauge's fill + denominator selector (mirror of
    /// [`MediaCache::gauge_fill`](crate::media_cache::MediaCache::gauge_fill)). In
    /// `Memory` mode reconcile to the live `cap_bytes` and report the in-RAM fill
    /// + `false`; in `Disk` mode report the on-disk fill + `true`, never capping.
    pub async fn gauge_fill(&self, cap_bytes: u64) -> (u64, bool) {
        let mut c = self.cache.lock().await;
        if c.is_disk() {
            (c.disk_bytes(), true)
        } else {
            c.set_cap(cap_bytes);
            (c.memory_bytes(), false)
        }
    }

    /// Apply the Disk/Memory location toggle AND the live cap for the Thumbnails
    /// cache (mirror of
    /// [`MediaCache::apply_location_and_cap`](crate::media_cache::MediaCache::apply_location_and_cap),
    /// under the `cache/thumb` subdir). Rebuilds on a backend change (a Disk open
    /// wipes+recreates the subdir); otherwise applies the cap live in Memory mode.
    pub async fn apply_location_and_cap(
        &self,
        app_dir: &Path,
        loc: FragmentCacheLocation,
        cap_mb: u32,
    ) -> io::Result<()> {
        let mut c = self.cache.lock().await;
        let want_disk = loc == FragmentCacheLocation::Disk;
        if c.is_disk() != want_disk {
            let cap = if want_disk {
                None
            } else {
                Some(cap_mb as u64 * 1024 * 1024)
            };
            *c = BlobCache::open_located(app_dir, cap, loc, "thumb")?;
        } else if !want_disk {
            c.set_cap(cap_mb as u64 * 1024 * 1024);
        }
        Ok(())
    }

    /// Wipe everything (app close / explicit Clear). `Memory` zeroizes the sealed
    /// blobs; `Disk` removes the backing files.
    pub async fn clear_and_zeroize(&self) {
        self.cache.lock().await.clear_and_zeroize();
    }

    /// Sync-context (SYNC `RunEvent::Exit`) variant of
    /// [`clear_and_zeroize`](Self::clear_and_zeroize): `try_lock` (NOT
    /// `blocking_lock`) so it can never panic on the missing runtime context nor
    /// block shutdown — at shutdown nothing else holds the lock, so it succeeds. A
    /// contended miss (essentially never real at Exit) is a best-effort skip: in
    /// Memory mode the dying process reclaims the RAM; in Disk mode it leaves only
    /// ciphertext under `cache/thumb/*`, which the next Disk-mode open wipes+recreates
    /// and which a fresh per-process seal makes undecryptable anyway (not plaintext).
    pub fn clear_and_zeroize_sync(&self) {
        if let Ok(mut c) = self.cache.try_lock() {
            c.clear_and_zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxthumb-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn meta(title: &str) -> CachedMeta {
        CachedMeta {
            file_type: "blog".into(),
            title: title.into(),
            tags: vec!["t1".into(), "t2".into()],
            thumbnail_b64: None,
            author_fp: "abcd1234".into(),
            recovery_ok: true,
            mine: false,
            member_counts: crate::dto::MemberCounts::default(),
        }
    }

    fn key(b: u8, v: u64) -> CacheKey {
        CacheKey {
            file_id: [b; 16],
            version: v,
        }
    }

    fn mem_cache(dir: &Path, cap_mb: u32) -> ThumbCache {
        let seal = Arc::new(SessionSeal::generate());
        ThumbCache::new(dir, cap_mb, FragmentCacheLocation::Memory, seal).unwrap()
    }

    fn disk_cache(dir: &Path) -> ThumbCache {
        let seal = Arc::new(SessionSeal::generate());
        ThumbCache::new(dir, 0, FragmentCacheLocation::Disk, seal).unwrap()
    }

    #[tokio::test]
    async fn sealed_card_round_trips_and_blob_is_ciphertext() {
        let dir = tmp_dir("rt");
        let tc = mem_cache(&dir, 64);
        let k = key(1, 3);
        let mut m = meta("Secret Title");
        m.thumbnail_b64 = Some("THUMBDATA".into());
        tc.put_card(k, m).await;

        let card = tc.get_card(k, &hex(&k.file_id)).await.unwrap();
        assert_eq!(card.title, "Secret Title");
        assert_eq!(card.tags, vec!["t1".to_owned(), "t2".to_owned()]);
        assert_eq!(card.thumbnail_b64, Some("THUMBDATA".into()));
        assert_eq!(card.version, 3);
        assert_eq!(card.author_fp, "abcd1234");
        assert!(card.recovery_ok);
        assert!(!card.mine);

        // The stored blob is SEALED — it must not contain the plaintext title.
        let (id_hex, sub) = ThumbCache::key_parts(k);
        let sealed = tc.cache.lock().await.get(Ns::Card, &id_hex, sub).unwrap();
        let needle = b"Secret Title";
        assert!(
            !sealed.windows(needle.len()).any(|w| w == needle),
            "sealed card must not leak the plaintext title"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn thumbnail_carries_forward_on_a_later_thumbless_put() {
        let dir = tmp_dir("carry");
        let tc = mem_cache(&dir, 64);
        let k = key(2, 1);
        // 1) card WITH a thumbnail.
        let mut m = meta("t");
        m.thumbnail_b64 = Some("THUMB".into());
        tc.put_card(k, m).await;
        // 2) a later put WITHOUT a thumbnail must NOT drop the carried one.
        tc.put_card(k, meta("t")).await;
        assert_eq!(
            tc.get_card(k, "x").await.unwrap().thumbnail_b64,
            Some("THUMB".into()),
            "thumbnail survives a later thumbless card-put"
        );
        // 3) a put with a NEW thumbnail replaces it.
        let mut m3 = meta("t");
        m3.thumbnail_b64 = Some("THUMB2".into());
        tc.put_card(k, m3).await;
        assert_eq!(
            tc.get_card(k, "x").await.unwrap().thumbnail_b64,
            Some("THUMB2".into())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalidate_and_invalidate_file() {
        let dir = tmp_dir("inv");
        let tc = mem_cache(&dir, 64);
        tc.put_card(key(1, 1), meta("a")).await;
        tc.put_card(key(1, 2), meta("b")).await;
        tc.put_card(key(9, 1), meta("c")).await;
        // invalidate drops exactly one (file, version)…
        tc.invalidate(key(1, 1)).await;
        assert!(tc.get_card(key(1, 1), "x").await.is_none());
        assert!(tc.get_card(key(1, 2), "x").await.is_some());
        // invalidate_file drops EVERY version of a file id…
        tc.invalidate_file([1u8; 16]).await;
        assert!(tc.get_card(key(1, 2), "x").await.is_none());
        // …leaving the unrelated file id.
        assert!(tc.get_card(key(9, 1), "x").await.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_cap_mb_shrink_evicts_and_clear_empties() {
        let dir = tmp_dir("cap");
        let tc = mem_cache(&dir, 64);
        tc.put_card(key(1, 1), meta("a")).await;
        assert!(tc.get_card(key(1, 1), "x").await.is_some());
        // A 0 MB cap = 0-byte budget → the entry evicts immediately.
        tc.set_cap_mb(0).await;
        assert!(tc.get_card(key(1, 1), "x").await.is_none(), "cap 0 evicts");
        // Raise the cap, re-populate, then clear.
        tc.set_cap_mb(64).await;
        tc.put_card(key(2, 1), meta("b")).await;
        assert!(tc.get_card(key(2, 1), "x").await.is_some());
        tc.clear_and_zeroize().await;
        assert!(tc.get_card(key(2, 1), "x").await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wrong_key_unseal_is_a_miss() {
        // A blob sealed under one process key must not open under another (fail-closed).
        let dir = tmp_dir("wrongkey");
        let tc = mem_cache(&dir, 64);
        let k = key(4, 1);
        tc.put_card(k, meta("x")).await;
        assert!(tc.get_meta(k).await.is_some());
        // Swap in a fresh seal → the existing sealed blob no longer opens.
        let stranger = ThumbCache {
            cache: tc.cache.clone(),
            seal: Arc::new(SessionSeal::generate()),
        };
        assert!(stranger.get_meta(k).await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn gauge_fill_memory_reconciles_and_disk_never_caps() {
        // Memory: a lowered cap evicts and the fill is reported with RAM denominator.
        let dir = tmp_dir("gauge-mem");
        let tc = mem_cache(&dir, 64);
        for v in 0..4u64 {
            tc.put_card(key(1, v), meta("some-title")).await;
        }
        let (fill, disk_mode) = tc.gauge_fill(0).await; // 0-byte cap evicts everything
        assert!(!disk_mode);
        assert_eq!(fill, 0, "reconciled to the 0-byte cap");
        let _ = std::fs::remove_dir_all(&dir);

        // Disk: never caps; reports the on-disk fill with the disk denominator.
        let dir2 = tmp_dir("gauge-disk");
        let tc2 = disk_cache(&dir2);
        tc2.put_card(key(1, 0), meta("t")).await;
        let before = tc2.cache.lock().await.total_bytes();
        assert!(before > 0);
        let (fill2, disk_mode2) = tc2.gauge_fill(1).await; // tiny would-be cap must not evict
        assert!(disk_mode2);
        assert_eq!(fill2, before, "disk fill unchanged (uncapped)");
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[tokio::test]
    async fn apply_location_rebuilds_both_directions() {
        let dir = tmp_dir("loc");
        let tc = mem_cache(&dir, 64);
        tc.put_card(key(1, 0), meta("t")).await;
        assert!(!tc.cache.lock().await.is_disk());
        // Memory → Disk rebuilds (prior blob gone, backend flips, uncapped).
        tc.apply_location_and_cap(&dir, FragmentCacheLocation::Disk, 64)
            .await
            .unwrap();
        assert!(tc.cache.lock().await.is_disk());
        assert!(tc.get_card(key(1, 0), "x").await.is_none(), "rebuild wiped it");
        // Disk → Memory rebuilds back.
        tc.apply_location_and_cap(&dir, FragmentCacheLocation::Memory, 64)
            .await
            .unwrap();
        assert!(!tc.cache.lock().await.is_disk());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn apply_location_same_memory_lowers_cap_evicts() {
        let dir = tmp_dir("loc-cap");
        let tc = mem_cache(&dir, 64);
        tc.put_card(key(1, 0), meta("t")).await;
        assert!(tc.get_card(key(1, 0), "x").await.is_some());
        tc.apply_location_and_cap(&dir, FragmentCacheLocation::Memory, 0)
            .await
            .unwrap();
        assert!(tc.get_card(key(1, 0), "x").await.is_none(), "cap 0 evicts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn clear_and_zeroize_sync_empties() {
        let dir = tmp_dir("clr-sync");
        let tc = mem_cache(&dir, 64);
        tc.put_card(key(1, 0), meta("t")).await;
        assert!(tc.get_card(key(1, 0), "x").await.is_some());
        tc.clear_and_zeroize_sync();
        assert!(tc.get_card(key(1, 0), "x").await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
