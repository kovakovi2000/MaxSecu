//! Bounded on-disk **ciphertext** fragment cache (Phase-7 video, Gate 4 / spec
//! §5). Jumping **back** to an already-watched part of a video must re-fetch
//! nothing: the cache re-reads the stored **ciphertext** (which the TCB then
//! re-decrypts + re-decodes). The blobs live under `<dir>/cache/frag/` as files
//! keyed by `(file_id_hex, seq)`, capped by a configurable byte budget with
//! least-recently-used eviction.
//!
//! # Security invariant — CIPHERTEXT ONLY, never plaintext
//! This cache sits on the data-at-rest boundary. It stores **exactly the opaque
//! bytes it is handed** (the encrypted chunks the caller fetched from the
//! server) and never decrypts, transforms, or even inspects them. The public
//! API speaks only in opaque `&[u8]` / `Vec<u8>`; there is no path by which a
//! decoded/plaintext frame can reach disk through this type. The caller (the
//! fragment feeder, Task 4.2) is contractually required to pass the *fetched
//! ciphertext*, never a decrypted frame. What goes in is byte-for-byte what
//! lands on disk — the round-trip tests pin this.
//!
//! # No path traversal
//! The on-disk filename is `<file_id_hex>_<seq>.frag`. `file_id_hex` is
//! validated to be hex-only (so it cannot contain `/`, `\`, `.`, or `:`), and
//! `seq` is a `u32` rendered as decimal digits — so a hostile key can never
//! escape `cache/frag/`.
//!
//! # Windows search indexing
//! On Windows the `cache/frag/` directory is marked
//! `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` so the at-rest ciphertext is not
//! search-indexed. Because this crate `forbid`s `unsafe_code`, the raw Win32
//! `SetFileAttributesW` FFI (which needs `unsafe`) is unavailable here; the
//! attribute is therefore set **best-effort** via the system `attrib +I`
//! command. Any failure is ignored — it never fails the cache. On non-Windows
//! platforms this is a no-op.

use crate::config::FragmentCacheLocation;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// One tracked blob: its byte size and a monotonic last-used stamp driving LRU
/// eviction. The backing bytes live in the [`Backend`] (on disk keyed by
/// [`blob_filename`], or in-process in the `Memory` map); the on-disk filename is
/// derived deterministically from the index key, so it is not stored here.
#[derive(Debug, Clone)]
struct Entry {
    size_bytes: u64,
    last_used: u64,
}

/// Where the tracked ciphertext blobs actually live. Both variants store ONLY
/// the opaque bytes handed to [`FragmentCache::put`] — the CIPHERTEXT-ONLY
/// invariant holds identically for each.
#[derive(Debug)]
enum Backend {
    /// On disk under `<app_dir>/cache/frag/`, one `<key>_<seq>.frag` file per
    /// entry (today's behavior).
    Disk { root: PathBuf },
    /// In-process: `(file_id_hex, seq)` -> ciphertext, never touching disk.
    Memory {
        blobs: BTreeMap<(String, u32), Vec<u8>>,
    },
}

/// A bounded LRU of **ciphertext** fragment blobs, backed either on disk or fully
/// in RAM (see [`Backend`]).
#[derive(Debug)]
pub struct FragmentCache {
    /// Where the blobs live (disk files or an in-process map).
    backend: Backend,
    /// Hard byte budget; `total_bytes` is held `<= cap_bytes` after every `put`.
    cap_bytes: u64,
    /// Sum of `size_bytes` across `index`.
    total_bytes: u64,
    /// Monotonic clock for LRU; bumped on every `put` and successful `get`.
    tick: u64,
    /// `(file_id_hex, seq)` -> tracked blob.
    index: BTreeMap<(String, u32), Entry>,
}

impl FragmentCache {
    /// Open (and create) the cache under `<app_dir>/cache/frag`, capped at
    /// `cap_bytes`. Callers build the cap from the Phase-5 performance setting:
    /// `ram_cache_cap_mb as u64 * 1024 * 1024`.
    ///
    /// The directory is created idempotently and, on Windows, marked
    /// not-content-indexed (best-effort). Any ciphertext left by a prior run is
    /// dropped so the byte budget is accounted exactly (the cache is rebuilt on
    /// demand).
    pub fn open(app_dir: &Path, cap_bytes: u64) -> io::Result<Self> {
        let root = app_dir.join("cache").join("frag");
        std::fs::create_dir_all(&root)?;
        if let Ok(rd) = std::fs::read_dir(&root) {
            for ent in rd.flatten() {
                let _ = std::fs::remove_file(ent.path());
            }
        }
        mark_not_content_indexed(&root);
        Ok(Self {
            backend: Backend::Disk { root },
            cap_bytes,
            total_bytes: 0,
            tick: 0,
            index: BTreeMap::new(),
        })
    }

    /// Open the cache with the configured backend. `Disk` behaves exactly like
    /// [`open`]; `Memory` holds ciphertext in-process and never touches disk.
    pub fn open_located(
        app_dir: &Path,
        cap_bytes: u64,
        location: FragmentCacheLocation,
    ) -> io::Result<Self> {
        match location {
            FragmentCacheLocation::Disk => Self::open(app_dir, cap_bytes),
            FragmentCacheLocation::Memory => Ok(Self {
                backend: Backend::Memory {
                    blobs: BTreeMap::new(),
                },
                cap_bytes,
                total_bytes: 0,
                tick: 0,
                index: BTreeMap::new(),
            }),
        }
    }

    /// Store `ciphertext` (opaque bytes) under `(file_id_hex, seq)`, evicting
    /// least-recently-used entries first so the cap is honored. Re-`put`ting an
    /// existing key replaces it. A blob larger than the whole cap is
    /// **un-cacheable** and silently skipped (the caller still holds the bytes;
    /// a later `get` is simply a miss) — this keeps the cap strictly honored.
    pub fn put(&mut self, file_id_hex: &str, seq: u32, ciphertext: &[u8]) -> io::Result<()> {
        let key = validated_key(file_id_hex)?;
        let map_key = (key, seq);
        let size = ciphertext.len() as u64;

        // Replacing or skipping: drop any prior bytes for this key first.
        self.remove_entry(&map_key);

        // Larger-than-cap blobs are not cached (cap stays honored).
        if size > self.cap_bytes {
            return Ok(());
        }

        while self.total_bytes + size > self.cap_bytes && self.evict_one() {}

        match &mut self.backend {
            Backend::Disk { root } => {
                std::fs::write(root.join(blob_filename(&map_key.0, map_key.1)), ciphertext)?;
            }
            Backend::Memory { blobs } => {
                blobs.insert(map_key.clone(), ciphertext.to_vec());
            }
        }
        self.tick += 1;
        self.total_bytes += size;
        self.index.insert(
            map_key,
            Entry {
                size_bytes: size,
                last_used: self.tick,
            },
        );
        Ok(())
    }

    /// Return the cached ciphertext for `(file_id_hex, seq)`, refreshing its
    /// LRU position. A miss — including a corrupt/missing backing file — returns
    /// `None`; a stale index entry is dropped (fail-closed).
    pub fn get(&mut self, file_id_hex: &str, seq: u32) -> Option<Vec<u8>> {
        let key = validated_key(file_id_hex).ok()?;
        let map_key = (key, seq);
        // Only tracked keys can hit (guards both backends against stray reads).
        self.index.get(&map_key)?;
        let bytes = match &self.backend {
            Backend::Disk { root } => {
                match std::fs::read(root.join(blob_filename(&map_key.0, map_key.1))) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Corrupt/missing backing file: drop the stale entry (fail-closed).
                        self.remove_entry(&map_key);
                        return None;
                    }
                }
            }
            // Present iff indexed (the index gate above already ensured that).
            Backend::Memory { blobs } => blobs.get(&map_key).cloned()?,
        };
        self.tick += 1;
        if let Some(e) = self.index.get_mut(&map_key) {
            e.last_used = self.tick;
        }
        Some(bytes)
    }

    /// Total tracked ciphertext bytes currently on disk.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Whether `(file_id_hex, seq)` is currently tracked.
    pub fn contains(&self, file_id_hex: &str, seq: u32) -> bool {
        match validated_key(file_id_hex) {
            Ok(key) => self.index.contains_key(&(key, seq)),
            Err(_) => false,
        }
    }

    /// Explicitly drop `(file_id_hex, seq)` if present (no-op otherwise, never an
    /// error). Used by the direct-link download route: `feed_fragment` writes a
    /// fragment's ciphertext to the cache BEFORE the AEAD check that would catch a
    /// tampered direct-sourced chunk, so a caller that retries a failed range via
    /// the server proxy must evict the (possibly poisoned) cache entry first —
    /// otherwise the retry would read the same bad bytes back as a cache "hit"
    /// and never actually re-fetch.
    pub fn evict(&mut self, file_id_hex: &str, seq: u32) {
        if let Ok(key) = validated_key(file_id_hex) {
            self.remove_entry(&(key, seq));
        }
    }

    /// Evict the single least-recently-used entry. Returns `false` if empty.
    fn evict_one(&mut self) -> bool {
        let victim = self
            .index
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                self.remove_entry(&k);
                true
            }
            None => false,
        }
    }

    /// Drop an entry: delete its backing bytes (best-effort) and adjust totals.
    fn remove_entry(&mut self, key: &(String, u32)) {
        if let Some(e) = self.index.remove(key) {
            match &mut self.backend {
                Backend::Disk { root } => {
                    let _ = std::fs::remove_file(root.join(blob_filename(&key.0, key.1)));
                }
                Backend::Memory { blobs } => {
                    blobs.remove(key);
                }
            }
            self.total_bytes = self.total_bytes.saturating_sub(e.size_bytes);
        }
    }
}

/// Validate `file_id_hex` is non-empty, hex-only, and bounded in length, then
/// return it **lowercased** as the canonical key. Rejecting anything non-hex is
/// what guarantees the derived filename cannot traverse out of `cache/frag/`.
///
/// The lowercase normalization keeps the in-memory index namespace and the
/// on-disk filename namespace in agreement: on case-insensitive NTFS,
/// `AA_0.frag` and `aa_0.frag` are the *same* file, so case-distinct `String`
/// keys for the same seq would otherwise clobber each other's blob while
/// `total_bytes` double-counted. Canonicalizing both sides to lowercase makes
/// that impossible. (The Task-4.2 feeder already passes canonical lowercase
/// `hex16`; this just makes it airtight.)
fn validated_key(file_id_hex: &str) -> io::Result<String> {
    let ok = !file_id_hex.is_empty()
        && file_id_hex.len() <= 64
        && file_id_hex.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(file_id_hex.to_ascii_lowercase())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fragment cache key must be hex-only",
        ))
    }
}

/// Deterministic, path-safe filename for a validated key.
fn blob_filename(file_id_hex: &str, seq: u32) -> String {
    format!("{file_id_hex}_{seq}.frag")
}

/// Best-effort `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on the cache dir so the
/// at-rest ciphertext is not search-indexed. Uses the system `attrib +I`
/// command (no `unsafe`, which this crate forbids); failures are ignored.
///
/// Only the **absolute** `%SystemRoot%\System32\attrib.exe` is ever invoked —
/// if `SystemRoot` is unset we skip the call entirely rather than spawn a
/// PATH-resolved binary (no PATH-hijack surface).
#[cfg(windows)]
fn mark_not_content_indexed(path: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let Ok(system_root) = std::env::var("SystemRoot") else {
        return;
    };
    let attrib = format!("{system_root}\\System32\\attrib.exe");
    let _ = std::process::Command::new(attrib)
        .arg("+I")
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

#[cfg(not(windows))]
fn mark_not_content_indexed(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique throwaway cache root (no external tempdir crate; mirrors the
    /// pattern used by `index.rs`).
    fn tmp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mxfrag-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn put_then_get_roundtrips() {
        let dir = tmp_dir("rt");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        let ct = b"\x00\x01opaque-ciphertext\xff".to_vec();
        c.put("aa", 0, &ct).unwrap();
        assert_eq!(c.get("aa", 0).as_deref(), Some(ct.as_slice()));
        // A never-stored key is a miss.
        assert_eq!(c.get("aa", 1), None);
        assert_eq!(c.get("bb", 0), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_is_case_normalized_to_one_namespace() {
        let dir = tmp_dir("case");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        let ct = b"opaque".to_vec();
        // Stored under an upper-case key...
        c.put("AA", 0, &ct).unwrap();
        // ...is retrievable under the lower-case form (same canonical key).
        assert_eq!(c.get("aa", 0).as_deref(), Some(ct.as_slice()));
        assert!(c.contains("Aa", 0));
        // Exactly one tracked blob, on disk under the lower-case filename.
        assert_eq!(c.total_bytes(), ct.len() as u64);
        assert!(dir.join("cache").join("frag").join("aa_0.frag").is_file());
        // Re-putting the same id in a different case replaces (does not clobber
        // a second file or double-count).
        c.put("aA", 0, b"opaque2").unwrap();
        assert_eq!(c.total_bytes(), b"opaque2".len() as u64);
        assert_eq!(c.get("AA", 0).as_deref(), Some(b"opaque2".as_slice()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frag_dir_is_created() {
        let dir = tmp_dir("mkdir");
        assert!(!dir.join("cache").join("frag").exists());
        let _c = FragmentCache::open(&dir, 1024).unwrap();
        assert!(dir.join("cache").join("frag").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exceeding_cap_evicts_lru_and_get_refreshes() {
        let dir = tmp_dir("lru");
        // Cap holds exactly three 10-byte blobs.
        let mut c = FragmentCache::open(&dir, 30).unwrap();
        let blob = |b: u8| vec![b; 10];
        c.put("aa", 0, &blob(0xA0)).unwrap(); // tick 1
        c.put("aa", 1, &blob(0xA1)).unwrap(); // tick 2
        c.put("aa", 2, &blob(0xA2)).unwrap(); // tick 3
        assert_eq!(c.total_bytes(), 30);
        // Touch (aa,0) so the LRU victim becomes (aa,1).
        assert!(c.get("aa", 0).is_some()); // tick 4
                                           // Fourth blob forces one eviction.
        c.put("aa", 3, &blob(0xA3)).unwrap(); // evicts (aa,1)
        assert_eq!(c.total_bytes(), 30);
        assert_eq!(c.get("aa", 1), None, "LRU victim evicted");
        assert!(c.get("aa", 0).is_some(), "recently used survives");
        assert!(c.get("aa", 2).is_some());
        assert!(c.get("aa", 3).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_disk_bytes_are_exactly_the_ciphertext_never_plaintext() {
        let dir = tmp_dir("ct");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        // The caller hands opaque ciphertext; the cache must store it verbatim.
        let ciphertext = b"\x9f\x3c\x00OPAQUE-ENCRYPTED-CHUNK\x11\xff".to_vec();
        // A plaintext marker that we deliberately NEVER hand the cache.
        const PLAINTEXT: &[u8] = b"DECODED_FRAME_PLAINTEXT_MARKER";
        c.put("dead", 7, &ciphertext).unwrap();
        let on_disk = std::fs::read(dir.join("cache").join("frag").join("dead_7.frag")).unwrap();
        // What we put is exactly what is on disk (no transform/encrypt/decrypt).
        assert_eq!(on_disk, ciphertext);
        // The cache never received and never wrote the plaintext.
        assert!(!on_disk.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_keys_are_rejected() {
        let dir = tmp_dir("trav");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        for bad in ["../evil", "a/b", "a\\b", "zz", "..", "", "g0"] {
            assert!(c.put(bad, 0, b"x").is_err(), "{bad} must be rejected");
            assert!(c.get(bad, 0).is_none());
        }
        // Nothing escaped the cache dir.
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_backing_file_is_a_miss() {
        let dir = tmp_dir("corrupt");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        c.put("ab", 0, b"ciphertext").unwrap();
        // Simulate external corruption: delete the backing file out from under us.
        std::fs::remove_file(dir.join("cache").join("frag").join("ab_0.frag")).unwrap();
        assert_eq!(c.get("ab", 0), None);
        // The stale index entry was dropped (fail-closed).
        assert!(!c.contains("ab", 0));
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_drops_a_present_entry_and_is_a_noop_otherwise() {
        let dir = tmp_dir("evict");
        let mut c = FragmentCache::open(&dir, 1024).unwrap();
        c.put("aa", 0, b"ciphertext").unwrap();
        assert!(c.contains("aa", 0));
        c.evict("aa", 0);
        assert!(!c.contains("aa", 0));
        assert_eq!(c.get("aa", 0), None);
        assert_eq!(c.total_bytes(), 0);
        // Evicting an absent key, or a malformed/traversal key, never panics/errors.
        c.evict("aa", 0);
        c.evict("../evil", 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_backend_roundtrips_and_writes_nothing_to_disk() {
        let dir = tmp_dir("mem");
        let mut c =
            FragmentCache::open_located(&dir, 1024, crate::config::FragmentCacheLocation::Memory)
                .unwrap();
        let ct = b"\x00opaque\xff".to_vec();
        c.put("aa", 0, &ct).unwrap();
        assert_eq!(c.get("aa", 0).as_deref(), Some(ct.as_slice()));
        assert!(!dir.join("cache").join("frag").join("aa_0.frag").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn memory_backend_evicts_lru_like_disk() {
        let dir = tmp_dir("mem-lru");
        let mut c =
            FragmentCache::open_located(&dir, 30, crate::config::FragmentCacheLocation::Memory)
                .unwrap();
        let blob = |b: u8| vec![b; 10];
        c.put("aa", 0, &blob(0)).unwrap();
        c.put("aa", 1, &blob(1)).unwrap();
        c.put("aa", 2, &blob(2)).unwrap();
        assert!(c.get("aa", 0).is_some());
        c.put("aa", 3, &blob(3)).unwrap();
        assert_eq!(c.total_bytes(), 30);
        assert_eq!(c.get("aa", 1), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_blob_is_not_cached() {
        let dir = tmp_dir("oversize");
        let mut c = FragmentCache::open(&dir, 8).unwrap();
        c.put("cc", 0, &[0u8; 100]).unwrap(); // bigger than the whole cap
        assert!(!c.contains("cc", 0));
        assert_eq!(c.get("cc", 0), None);
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
