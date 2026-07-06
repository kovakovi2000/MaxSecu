//! App-global shared video+content cache. One `BlobCache` behind an async mutex,
//! holding `Frag` (content-DEK ciphertext) video fragments and (from Task 5)
//! `Content` (SessionSeal-sealed image/blog) blobs under one budget. Persistent
//! across `cancel_video` (the job drops its decryptor, never the shared cache).
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::blob_cache::BlobCache;
use crate::config::FragmentCacheLocation;

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
}
