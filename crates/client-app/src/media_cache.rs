//! App-global shared video+content cache. One `BlobCache` behind an async mutex,
//! holding `Frag` (content-DEK ciphertext) video fragments and (from Task 5)
//! `Content` (SessionSeal-sealed image/blog) blobs under one budget. Persistent
//! across `cancel_video` (the job drops its decryptor, never the shared cache).
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::blob_cache::{BlobCache, Ns};
use crate::commands::feed::hex;
use crate::config::FragmentCacheLocation;
use crate::session_seal::SessionSeal;
use crate::thumb_cache::CacheKey;

/// The app-global Media cache: `Ns::Frag` (raw DEK-ciphertext video fragments,
/// UNSEALED) + `Ns::Content` (SessionSeal-sealed image/blog payloads) under one
/// budget. Because it holds raw unsealed frag ciphertext, MediaCache stores NO key
/// material of its own — the seal is passed as a per-call PARAMETER to
/// `put_content`/`get_content`. (Contrast [`ThumbCache`](crate::thumb_cache::ThumbCache),
/// which seals everything it stores and so OWNS an `Arc<SessionSeal>` clone.) Both
/// share the one process seal from `main.rs`.
pub struct MediaCache(pub Arc<Mutex<BlobCache>>);

impl MediaCache {
    /// Memory → `Some(cap)` enforced LRU; Disk → `None` (uncapped, D5a). On-disk
    /// blobs live under `cache/media/`. Fallible: opened ONCE at startup, so a
    /// bad/unwritable dir in Disk mode surfaces a clean fatal-init error to the
    /// caller (Task 7's `main.rs`) rather than a panic-unwind.
    pub fn open(app_dir: &Path, cap_mb: u32, loc: FragmentCacheLocation) -> io::Result<Self> {
        let cap = match loc {
            FragmentCacheLocation::Memory => Some(cap_mb as u64 * 1024 * 1024),
            FragmentCacheLocation::Disk => None,
        };
        let bc = BlobCache::open_located(app_dir, cap, loc, "media")?;
        Ok(MediaCache(Arc::new(Mutex::new(bc))))
    }

    /// Seal + store a full display-final content payload (image PNG / blog UTF-8)
    /// under `Ns::Content`, sharing the media budget with video fragments. The
    /// `seal` is a PARAMETER (the process-global [`SessionSeal`]) — MediaCache keeps
    /// no key material of its own. An oversize-vs-cap sealed blob is silently
    /// skipped by [`BlobCache::put`] (preserving the old "oversize content not
    /// stored" behavior).
    pub async fn put_content(&self, seal: &SessionSeal, key: CacheKey, display_bytes: &[u8]) {
        let sealed = seal.seal(display_bytes);
        let _ = self
            .0
            .lock()
            .await
            .put(Ns::Content, &hex(&key.file_id), key.version as u32, &sealed);
    }

    /// Read + unseal a stored content payload. `None` on miss / tamper / wrong-key
    /// (fail-closed). The returned buffer is `Zeroizing` — wiped on drop.
    pub async fn get_content(
        &self,
        seal: &SessionSeal,
        key: CacheKey,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let sealed =
            self.0
                .lock()
                .await
                .get(Ns::Content, &hex(&key.file_id), key.version as u32)?;
        seal.open(&sealed)
    }

    /// Drop EVERY version's `Frag` + `Content` entry for a file id (post/bundle
    /// deletion). One lock covers both namespaces.
    pub async fn invalidate_file(&self, file_id: [u8; 16]) {
        let id_hex = hex(&file_id);
        let mut cache = self.0.lock().await;
        cache.evict_prefix(Ns::Frag, &id_hex);
        cache.evict_prefix(Ns::Content, &id_hex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::Ns;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxmedia-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn open_memory_starts_empty_and_round_trips_under_frag() {
        let dir = tmp_dir("mem");
        let media = MediaCache::open(&dir, 1, FragmentCacheLocation::Memory).unwrap();
        let ct = b"\x00opaque-ciphertext\xff".to_vec();
        {
            let mut cache = media.0.lock().await;
            assert_eq!(cache.memory_bytes(), 0, "fresh cache holds nothing in RAM");
            cache.put(Ns::Frag, "aa", 0, &ct).unwrap();
            assert_eq!(cache.get(Ns::Frag, "aa", 0).as_deref(), Some(ct.as_slice()));
            assert_eq!(cache.memory_bytes(), ct.len() as u64);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `Disk` branch opens with a `None` (uncapped) budget (D5a), so blobs that
    /// would exceed a would-be small cap are all retained — `disk_bytes()` tracks
    /// them and nothing is evicted. Mirrors `BlobCache::disk_backend_is_uncapped`
    /// but exercises it through `MediaCache::open`'s cap-selection logic (which
    /// discards `cap_mb` entirely in Disk mode).
    #[tokio::test]
    async fn open_disk_is_uncapped() {
        let dir = tmp_dir("disk-uncap");
        // cap_mb = 0 would be a 0-byte cap IF Disk mode honored it — but Disk maps to
        // `None`, so three blobs all survive with no eviction.
        let media = MediaCache::open(&dir, 0, FragmentCacheLocation::Disk).unwrap();
        {
            let mut cache = media.0.lock().await;
            for s in 0..3u32 {
                cache.put(Ns::Frag, "aa", s, &[0u8; 10]).unwrap();
            }
            assert_eq!(cache.total_bytes(), 30, "nothing evicted (uncapped)");
            assert_eq!(cache.disk_bytes(), 30);
            assert_eq!(cache.memory_bytes(), 0);
            assert!(cache.contains(Ns::Frag, "aa", 0), "oldest blob retained");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn content_seals_and_round_trips_through_media_cache() {
        let dir = tmp_dir("content");
        let media = MediaCache::open(&dir, 1, FragmentCacheLocation::Memory).unwrap();
        let seal = SessionSeal::generate();
        let key = CacheKey {
            file_id: [7u8; 16],
            version: 2,
        };
        let plaintext = b"blog-body-display-final-plaintext".to_vec();
        media.put_content(&seal, key, &plaintext).await;
        // get_content returns the display bytes verbatim…
        let got = media.get_content(&seal, key).await.unwrap();
        assert_eq!(&*got, &plaintext[..]);
        // …but the STORED blob is ciphertext, not the plaintext.
        let stored = media
            .0
            .lock()
            .await
            .get(Ns::Content, &hex(&key.file_id), 2)
            .unwrap();
        assert!(
            !stored.windows(plaintext.len()).any(|w| w == &plaintext[..]),
            "stored content must be sealed, not plaintext"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn oversize_content_is_not_stored() {
        let dir = tmp_dir("oversize");
        // 1 MB cap; a >1 MB sealed blob is un-cacheable (mirrors the old ContentCache).
        let media = MediaCache::open(&dir, 1, FragmentCacheLocation::Memory).unwrap();
        let seal = SessionSeal::generate();
        let key = CacheKey {
            file_id: [3u8; 16],
            version: 1,
        };
        media.put_content(&seal, key, &vec![0u8; 2 * 1024 * 1024]).await;
        assert!(media.get_content(&seal, key).await.is_none());
        assert_eq!(media.0.lock().await.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalidate_file_drops_frag_and_content_for_an_id_only() {
        let dir = tmp_dir("inv-file");
        let media = MediaCache::open(&dir, 4, FragmentCacheLocation::Memory).unwrap();
        let seal = SessionSeal::generate();
        let a = CacheKey {
            file_id: [1u8; 16],
            version: 1,
        };
        let b = CacheKey {
            file_id: [2u8; 16],
            version: 1,
        };
        media.put_content(&seal, a, b"a-content").await;
        media.put_content(&seal, b, b"b-content").await;
        // A raw DEK-ciphertext fragment for id `a` too (not re-sealed — Frag stays raw).
        media
            .0
            .lock()
            .await
            .put(Ns::Frag, &hex(&a.file_id), 0, b"a-frag-ciphertext")
            .unwrap();

        media.invalidate_file(a.file_id).await;
        // Both Frag and Content for id `a` are gone…
        assert!(media.get_content(&seal, a).await.is_none());
        assert!(!media.0.lock().await.contains(Ns::Frag, &hex(&a.file_id), 0));
        // …the unrelated id survives.
        assert!(media.get_content(&seal, b).await.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
