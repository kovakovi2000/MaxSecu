//! Bounded **ciphertext** blob cache (Phase-7 video, Gate 4 / spec §5),
//! generalized into a small set of logical namespaces (video fragments, whole
//! content, feed-card meta). Jumping **back** to an already-watched part of a
//! video must re-fetch nothing: the cache re-reads the stored **ciphertext**
//! (which the TCB then re-decrypts + re-decodes). The blobs live under a
//! caller-named `<dir>/cache/<subdir>/` (so several app-global caches can coexist
//! under one `app_dir` — e.g. `cache/media/` and `cache/thumb/`) as files keyed
//! by `(Ns, id_hex, sub)`, optionally capped by a byte budget with
//! least-recently-used eviction (`Memory` enforces the cap; a `None` cap — the
//! `Disk` app default — is unlimited).
//!
//! # Security invariant — CIPHERTEXT ONLY, never plaintext
//! This cache sits on the data-at-rest boundary. It stores **exactly the opaque
//! bytes it is handed** (the encrypted chunks the caller fetched from the
//! server) and never decrypts, transforms, or even inspects them. The public
//! API speaks only in opaque `&[u8]` / `Vec<u8>`; there is no path by which a
//! decoded/plaintext frame can reach disk through this type. The caller (the
//! fragment feeder, Task 4.2) is contractually required to pass the *fetched
//! ciphertext*, never a decrypted frame. What goes in is byte-for-byte what
//! lands on disk — the round-trip tests pin this. For defense-in-depth the
//! in-RAM (`Memory`) blobs are held in `Zeroizing` buffers, so eviction /
//! replace / clear wipes them even though they are already only ciphertext.
//!
//! # No path traversal
//! The on-disk filename is `<ns>_<id_hex>_<sub>.blob`. `id_hex` is validated to
//! be hex-only (so it cannot contain `/`, `\`, `.`, or `:`), the namespace tag is
//! a fixed path-safe string, and `sub` is a `u32` rendered as decimal digits — so
//! a hostile key can never escape the cache's own `cache/<subdir>/` directory.
//!
//! # Windows search indexing
//! On Windows the cache directory is marked
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
use zeroize::Zeroizing;

/// Which logical stream a blob belongs to. Kept as a small fixed set of
/// path-safe tags so the on-disk filename can embed it without traversal risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ns {
    Frag,
    Content,
    Card,
}

impl Ns {
    fn tag(self) -> &'static str {
        match self {
            Ns::Frag => "frag",
            Ns::Content => "content",
            Ns::Card => "card",
        }
    }
}

/// The composite index/backend key: `(namespace, id_hex, sub)`.
type Key = (Ns, String, u32);

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
/// the opaque bytes handed to [`BlobCache::put`] — the CIPHERTEXT-ONLY
/// invariant holds identically for each.
#[derive(Debug)]
enum Backend {
    /// On disk under `<app_dir>/cache/<subdir>/`, one `<ns>_<id_hex>_<sub>.blob`
    /// file per entry. The concrete directory is fixed at open time (`root`).
    Disk { root: PathBuf },
    /// In-process: `(Ns, id_hex, sub)` -> ciphertext, never touching disk.
    /// The value is `Zeroizing` so it is wiped on drop/eviction/clear.
    Memory {
        blobs: BTreeMap<Key, Zeroizing<Vec<u8>>>,
    },
}

/// A namespaced LRU of **ciphertext** blobs, backed either on disk or fully in
/// RAM (see [`Backend`]). The byte budget is optional: `Some(cap)` enforces LRU
/// eviction (the `Memory` app default); `None` is unlimited (the `Disk` app
/// default — disk is not RAM-pressure-bounded).
#[derive(Debug)]
pub struct BlobCache {
    /// Where the blobs live (disk files or an in-process map).
    backend: Backend,
    /// Optional byte budget. When `Some(c)`, `total_bytes` is held `<= c` after
    /// every `put`; when `None`, the cache never evicts on capacity.
    cap: Option<u64>,
    /// Sum of `size_bytes` across `index`.
    total_bytes: u64,
    /// Monotonic clock for LRU; bumped on every `put` and successful `get`.
    tick: u64,
    /// `(Ns, id_hex, sub)` -> tracked blob.
    index: BTreeMap<Key, Entry>,
}

impl BlobCache {
    /// Open (and create) a **disk** cache under `<app_dir>/cache/frag`, capped at
    /// `cap_bytes`. This is the capped-disk convenience constructor used by tests
    /// and legacy callers (fixed to the `"frag"` subdir); the app opens its
    /// several named caches via [`open_located`](Self::open_located) with an
    /// explicit `subdir` and (for RAM caches) a `None` cap.
    ///
    /// The directory is created idempotently and, on Windows, marked
    /// not-content-indexed (best-effort). Any ciphertext left by a prior run is
    /// dropped so the byte budget is accounted exactly (the cache is rebuilt on
    /// demand).
    pub fn open(app_dir: &Path, cap_bytes: u64) -> io::Result<Self> {
        Self::open_disk(app_dir, Some(cap_bytes), "frag")
    }

    /// Open the cache with the configured backend, an optional cap, and (for
    /// `Disk`) a named on-disk subdirectory. `Disk` creates/prepares
    /// `<app_dir>/cache/<subdir>`; `Memory` holds ciphertext in-process, never
    /// touches disk, and **ignores `subdir`**. `cap` = `None` means unlimited (no
    /// capacity eviction), `Some(c)` enforces the LRU budget on both backends.
    ///
    /// The `subdir` lets several app-global Disk caches coexist under one
    /// `app_dir` (e.g. Media `"media"` + Thumbnails `"thumb"`). Because a Disk
    /// open **wipes its own subdir** (see [`open_disk`](Self::open_disk)), two
    /// Disk caches sharing one `app_dir` MUST use distinct subdirs, or the second
    /// open would erase the first's ciphertext.
    pub fn open_located(
        app_dir: &Path,
        cap: Option<u64>,
        location: FragmentCacheLocation,
        subdir: &str,
    ) -> io::Result<Self> {
        match location {
            FragmentCacheLocation::Disk => Self::open_disk(app_dir, cap, subdir),
            FragmentCacheLocation::Memory => Ok(Self {
                backend: Backend::Memory {
                    blobs: BTreeMap::new(),
                },
                cap,
                total_bytes: 0,
                tick: 0,
                index: BTreeMap::new(),
            }),
        }
    }

    /// Shared disk-backend setup: create+clean `<app_dir>/cache/<subdir>`, mark it
    /// not-content-indexed, and return a fresh (empty-accounting) cache. This
    /// **wipes the subdir on open**, so each Disk cache under a shared `app_dir`
    /// must own a distinct `subdir`.
    fn open_disk(app_dir: &Path, cap: Option<u64>, subdir: &str) -> io::Result<Self> {
        let root = app_dir.join("cache").join(subdir);
        std::fs::create_dir_all(&root)?;
        if let Ok(rd) = std::fs::read_dir(&root) {
            for ent in rd.flatten() {
                let _ = std::fs::remove_file(ent.path());
            }
        }
        mark_not_content_indexed(&root);
        Ok(Self {
            backend: Backend::Disk { root },
            cap,
            total_bytes: 0,
            tick: 0,
            index: BTreeMap::new(),
        })
    }

    /// Store `ciphertext` (opaque bytes) under `(ns, id_hex, sub)`, evicting
    /// least-recently-used entries first so any cap is honored. Re-`put`ting an
    /// existing key replaces it. With a `Some` cap, a blob larger than the whole
    /// cap is **un-cacheable** and silently skipped (the caller still holds the
    /// bytes; a later `get` is simply a miss) — this keeps the cap strictly
    /// honored. With a `None` (unlimited) cap nothing is ever evicted or skipped.
    pub fn put(&mut self, ns: Ns, id_hex: &str, sub: u32, ciphertext: &[u8]) -> io::Result<()> {
        let id = validated_key(id_hex)?;
        let map_key: Key = (ns, id, sub);
        let size = ciphertext.len() as u64;

        // Replacing or skipping: drop any prior bytes for this key first.
        self.remove_entry(&map_key);

        // Larger-than-cap blobs are not cached (cap stays honored). Uncapped
        // (`None`) caches never skip.
        if self.cap.is_some_and(|c| size > c) {
            return Ok(());
        }

        while self.cap.is_some_and(|c| self.total_bytes + size > c) && self.evict_one() {}

        match &mut self.backend {
            Backend::Disk { root } => {
                std::fs::write(
                    root.join(blob_filename(map_key.0, &map_key.1, map_key.2)),
                    ciphertext,
                )?;
            }
            Backend::Memory { blobs } => {
                blobs.insert(map_key.clone(), Zeroizing::new(ciphertext.to_vec()));
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

    /// Return the cached ciphertext for `(ns, id_hex, sub)`, refreshing its LRU
    /// position. A miss — including a corrupt/missing backing file — returns
    /// `None`; a stale index entry is dropped (fail-closed).
    pub fn get(&mut self, ns: Ns, id_hex: &str, sub: u32) -> Option<Vec<u8>> {
        let id = validated_key(id_hex).ok()?;
        let map_key: Key = (ns, id, sub);
        // Only tracked keys can hit (guards both backends against stray reads).
        self.index.get(&map_key)?;
        let bytes = match &self.backend {
            Backend::Disk { root } => {
                match std::fs::read(root.join(blob_filename(map_key.0, &map_key.1, map_key.2))) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Corrupt/missing backing file: drop the stale entry (fail-closed).
                        self.remove_entry(&map_key);
                        return None;
                    }
                }
            }
            // Present iff indexed (the index gate above already ensured that).
            Backend::Memory { blobs } => blobs.get(&map_key).map(|z| z.to_vec())?,
        };
        self.tick += 1;
        if let Some(e) = self.index.get_mut(&map_key) {
            e.last_used = self.tick;
        }
        Some(bytes)
    }

    /// Total tracked ciphertext bytes currently held (on disk or in RAM).
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Bytes held in RAM (`Memory` backend) — `0` for `Disk` (whose blobs live on
    /// the filesystem, not in the process's rolling memory frame). Drives the
    /// header RAM-mode gauge, which reports only the in-RAM footprint against the
    /// configured cap.
    pub fn memory_bytes(&self) -> u64 {
        match &self.backend {
            Backend::Memory { .. } => self.total_bytes,
            Backend::Disk { .. } => 0,
        }
    }

    /// Bytes held on disk (`Disk` backend) — `0` for `Memory`. Drives the
    /// Disk-mode gauge.
    pub fn disk_bytes(&self) -> u64 {
        match &self.backend {
            Backend::Disk { .. } => self.total_bytes,
            Backend::Memory { .. } => 0,
        }
    }

    /// Update the byte budget to `Some(new_cap)`, immediately LRU-evicting down to
    /// it. This lets a **live** lowering of the RAM-cache setting shrink an
    /// already-open session's cache (the case the header gauge surfaces —
    /// otherwise the gauge divides the live cap into a cache still holding up to
    /// its larger open-time cap, reading over 100%). Raising the cap just permits
    /// more before the next eviction. Idempotent when unchanged.
    pub fn set_cap(&mut self, new_cap: u64) {
        self.cap = Some(new_cap);
        while self.total_bytes > new_cap && self.evict_one() {}
    }

    /// Whether `(ns, id_hex, sub)` is currently tracked.
    pub fn contains(&self, ns: Ns, id_hex: &str, sub: u32) -> bool {
        match validated_key(id_hex) {
            Ok(id) => self.index.contains_key(&(ns, id, sub)),
            Err(_) => false,
        }
    }

    /// Explicitly drop `(ns, id_hex, sub)` if present (no-op otherwise, never an
    /// error). Used by the direct-link download route: `feed_fragment` writes a
    /// fragment's ciphertext to the cache BEFORE the AEAD check that would catch a
    /// tampered direct-sourced chunk, so a caller that retries a failed range via
    /// the server proxy must evict the (possibly poisoned) cache entry first —
    /// otherwise the retry would read the same bad bytes back as a cache "hit"
    /// and never actually re-fetch.
    pub fn evict(&mut self, ns: Ns, id_hex: &str, sub: u32) {
        if let Ok(id) = validated_key(id_hex) {
            self.remove_entry(&(ns, id, sub));
        }
    }

    /// Drop every entry: `Memory` wipes the (`Zeroizing`) blobs; `Disk` removes
    /// the backing files. Resets the byte accounting to zero. Used on app close
    /// and by the explicit per-cache "Clear" control.
    pub fn clear_and_zeroize(&mut self) {
        let keys: Vec<Key> = self.index.keys().cloned().collect();
        for k in keys {
            self.remove_entry(&k);
        }
        self.total_bytes = 0;
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
    fn remove_entry(&mut self, key: &Key) {
        if let Some(e) = self.index.remove(key) {
            match &mut self.backend {
                Backend::Disk { root } => {
                    let _ = std::fs::remove_file(root.join(blob_filename(key.0, &key.1, key.2)));
                }
                Backend::Memory { blobs } => {
                    blobs.remove(key);
                }
            }
            self.total_bytes = self.total_bytes.saturating_sub(e.size_bytes);
        }
    }
}

/// Back-compat shim (removed in Task 4/5): the old `FragmentCache` name with its
/// 2-component (no-namespace) API, forwarding every call to a wrapped
/// [`BlobCache`] with a hard-coded [`Ns::Frag`]. This keeps the existing
/// `commands/video.rs` / `stream.rs` / `jobs.rs` / `video.rs` call sites
/// compiling unchanged until the RAM-cache-model migration moves them onto the
/// namespaced API. It preserves the pre-rework semantics exactly: both backends
/// are opened with a `Some` cap (disk was capped before this rework).
#[derive(Debug)]
pub struct FragmentCache(BlobCache);

impl FragmentCache {
    pub fn open(app_dir: &Path, cap_bytes: u64) -> io::Result<Self> {
        Ok(Self(BlobCache::open(app_dir, cap_bytes)?))
    }

    pub fn open_located(
        app_dir: &Path,
        cap_bytes: u64,
        location: FragmentCacheLocation,
    ) -> io::Result<Self> {
        Ok(Self(BlobCache::open_located(
            app_dir,
            Some(cap_bytes),
            location,
            "frag",
        )?))
    }

    pub fn put(&mut self, file_id_hex: &str, seq: u32, ciphertext: &[u8]) -> io::Result<()> {
        self.0.put(Ns::Frag, file_id_hex, seq, ciphertext)
    }

    pub fn get(&mut self, file_id_hex: &str, seq: u32) -> Option<Vec<u8>> {
        self.0.get(Ns::Frag, file_id_hex, seq)
    }

    pub fn total_bytes(&self) -> u64 {
        self.0.total_bytes()
    }

    pub fn memory_bytes(&self) -> u64 {
        self.0.memory_bytes()
    }

    pub fn set_cap(&mut self, new_cap: u64) {
        self.0.set_cap(new_cap)
    }

    pub fn contains(&self, file_id_hex: &str, seq: u32) -> bool {
        self.0.contains(Ns::Frag, file_id_hex, seq)
    }

    pub fn evict(&mut self, file_id_hex: &str, seq: u32) {
        self.0.evict(Ns::Frag, file_id_hex, seq)
    }
}

/// Validate `id_hex` is non-empty, hex-only, and bounded in length, then return
/// it **lowercased** as the canonical key component. Rejecting anything non-hex
/// is what guarantees the derived filename cannot traverse out of the cache's
/// `cache/<subdir>/` directory.
///
/// The lowercase normalization keeps the in-memory index namespace and the
/// on-disk filename namespace in agreement: on case-insensitive NTFS,
/// `frag_AA_0.blob` and `frag_aa_0.blob` are the *same* file, so case-distinct
/// `String` keys for the same `sub` would otherwise clobber each other's blob
/// while `total_bytes` double-counted. Canonicalizing both sides to lowercase
/// makes that impossible. (The Task-4.2 feeder already passes canonical lowercase
/// `hex16`; this just makes it airtight.)
fn validated_key(id_hex: &str) -> io::Result<String> {
    let ok = !id_hex.is_empty()
        && id_hex.len() <= 64
        && id_hex.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(id_hex.to_ascii_lowercase())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "blob cache key must be hex-only",
        ))
    }
}

/// Deterministic, path-safe filename for a validated key: `<ns>_<id>_<sub>.blob`.
/// The `ns` tag is a fixed path-safe string and `sub` is decimal digits, so only
/// the (already hex-validated) `id` component could carry hostile characters.
fn blob_filename(ns: Ns, id_hex: &str, sub: u32) -> String {
    format!("{}_{}_{}.blob", ns.tag(), id_hex, sub)
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
        let dir = std::env::temp_dir().join(format!("mxblob-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn put_then_get_roundtrips() {
        let dir = tmp_dir("rt");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        let ct = b"\x00\x01opaque-ciphertext\xff".to_vec();
        c.put(Ns::Frag, "aa", 0, &ct).unwrap();
        assert_eq!(c.get(Ns::Frag, "aa", 0).as_deref(), Some(ct.as_slice()));
        // A never-stored key is a miss.
        assert_eq!(c.get(Ns::Frag, "aa", 1), None);
        assert_eq!(c.get(Ns::Frag, "bb", 0), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_is_case_normalized_to_one_namespace() {
        let dir = tmp_dir("case");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        let ct = b"opaque".to_vec();
        // Stored under an upper-case key...
        c.put(Ns::Frag, "AA", 0, &ct).unwrap();
        // ...is retrievable under the lower-case form (same canonical key).
        assert_eq!(c.get(Ns::Frag, "aa", 0).as_deref(), Some(ct.as_slice()));
        assert!(c.contains(Ns::Frag, "Aa", 0));
        // Exactly one tracked blob, on disk under the lower-case filename.
        assert_eq!(c.total_bytes(), ct.len() as u64);
        assert!(dir
            .join("cache")
            .join("frag")
            .join("frag_aa_0.blob")
            .is_file());
        // Re-putting the same id in a different case replaces (does not clobber
        // a second file or double-count).
        c.put(Ns::Frag, "aA", 0, b"opaque2").unwrap();
        assert_eq!(c.total_bytes(), b"opaque2".len() as u64);
        assert_eq!(
            c.get(Ns::Frag, "AA", 0).as_deref(),
            Some(b"opaque2".as_slice())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frag_dir_is_created() {
        let dir = tmp_dir("mkdir");
        assert!(!dir.join("cache").join("frag").exists());
        let _c = BlobCache::open(&dir, 1024).unwrap();
        assert!(dir.join("cache").join("frag").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exceeding_cap_evicts_lru_and_get_refreshes() {
        let dir = tmp_dir("lru");
        // Cap holds exactly three 10-byte blobs.
        let mut c = BlobCache::open(&dir, 30).unwrap();
        let blob = |b: u8| vec![b; 10];
        c.put(Ns::Frag, "aa", 0, &blob(0xA0)).unwrap(); // tick 1
        c.put(Ns::Frag, "aa", 1, &blob(0xA1)).unwrap(); // tick 2
        c.put(Ns::Frag, "aa", 2, &blob(0xA2)).unwrap(); // tick 3
        assert_eq!(c.total_bytes(), 30);
        // Touch (aa,0) so the LRU victim becomes (aa,1).
        assert!(c.get(Ns::Frag, "aa", 0).is_some()); // tick 4
                                                      // Fourth blob forces one eviction.
        c.put(Ns::Frag, "aa", 3, &blob(0xA3)).unwrap(); // evicts (aa,1)
        assert_eq!(c.total_bytes(), 30);
        assert_eq!(c.get(Ns::Frag, "aa", 1), None, "LRU victim evicted");
        assert!(
            c.get(Ns::Frag, "aa", 0).is_some(),
            "recently used survives"
        );
        assert!(c.get(Ns::Frag, "aa", 2).is_some());
        assert!(c.get(Ns::Frag, "aa", 3).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_disk_bytes_are_exactly_the_ciphertext_never_plaintext() {
        let dir = tmp_dir("ct");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        // The caller hands opaque ciphertext; the cache must store it verbatim.
        let ciphertext = b"\x9f\x3c\x00OPAQUE-ENCRYPTED-CHUNK\x11\xff".to_vec();
        // A plaintext marker that we deliberately NEVER hand the cache.
        const PLAINTEXT: &[u8] = b"DECODED_FRAME_PLAINTEXT_MARKER";
        c.put(Ns::Frag, "dead", 7, &ciphertext).unwrap();
        let on_disk =
            std::fs::read(dir.join("cache").join("frag").join("frag_dead_7.blob")).unwrap();
        // What we put is exactly what is on disk (no transform/encrypt/decrypt).
        assert_eq!(on_disk, ciphertext);
        // The cache never received and never wrote the plaintext.
        assert!(!on_disk.windows(PLAINTEXT.len()).any(|w| w == PLAINTEXT));
        // Same invariant for the Content namespace (its own filename, verbatim).
        c.put(Ns::Content, "dead", 7, &ciphertext).unwrap();
        let on_disk_content =
            std::fs::read(dir.join("cache").join("frag").join("content_dead_7.blob")).unwrap();
        assert_eq!(on_disk_content, ciphertext);
        assert!(!on_disk_content
            .windows(PLAINTEXT.len())
            .any(|w| w == PLAINTEXT));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_keys_are_rejected() {
        let dir = tmp_dir("trav");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        for bad in ["../evil", "a/b", "a\\b", "zz", "..", "", "g0"] {
            assert!(
                c.put(Ns::Frag, bad, 0, b"x").is_err(),
                "{bad} must be rejected"
            );
            assert!(c.get(Ns::Frag, bad, 0).is_none());
        }
        // Nothing escaped the cache dir.
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_backing_file_is_a_miss() {
        let dir = tmp_dir("corrupt");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        c.put(Ns::Frag, "ab", 0, b"ciphertext").unwrap();
        // Simulate external corruption: delete the backing file out from under us.
        std::fs::remove_file(dir.join("cache").join("frag").join("frag_ab_0.blob")).unwrap();
        assert_eq!(c.get(Ns::Frag, "ab", 0), None);
        // The stale index entry was dropped (fail-closed).
        assert!(!c.contains(Ns::Frag, "ab", 0));
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evict_drops_a_present_entry_and_is_a_noop_otherwise() {
        let dir = tmp_dir("evict");
        let mut c = BlobCache::open(&dir, 1024).unwrap();
        c.put(Ns::Frag, "aa", 0, b"ciphertext").unwrap();
        assert!(c.contains(Ns::Frag, "aa", 0));
        c.evict(Ns::Frag, "aa", 0);
        assert!(!c.contains(Ns::Frag, "aa", 0));
        assert_eq!(c.get(Ns::Frag, "aa", 0), None);
        assert_eq!(c.total_bytes(), 0);
        // Evicting an absent key, or a malformed/traversal key, never panics/errors.
        c.evict(Ns::Frag, "aa", 0);
        c.evict(Ns::Frag, "../evil", 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_backend_roundtrips_and_writes_nothing_to_disk() {
        let dir = tmp_dir("mem");
        let mut c =
            BlobCache::open_located(
                &dir,
                Some(1024),
                crate::config::FragmentCacheLocation::Memory,
                "frag",
            )
            .unwrap();
        let ct = b"\x00opaque\xff".to_vec();
        c.put(Ns::Frag, "aa", 0, &ct).unwrap();
        assert_eq!(c.get(Ns::Frag, "aa", 0).as_deref(), Some(ct.as_slice()));
        assert!(!dir
            .join("cache")
            .join("frag")
            .join("frag_aa_0.blob")
            .exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_backend_evicts_lru_like_disk() {
        let dir = tmp_dir("mem-lru");
        let mut c =
            BlobCache::open_located(
                &dir,
                Some(30),
                crate::config::FragmentCacheLocation::Memory,
                "frag",
            )
            .unwrap();
        let blob = |b: u8| vec![b; 10];
        c.put(Ns::Frag, "aa", 0, &blob(0)).unwrap();
        c.put(Ns::Frag, "aa", 1, &blob(1)).unwrap();
        c.put(Ns::Frag, "aa", 2, &blob(2)).unwrap();
        assert!(c.get(Ns::Frag, "aa", 0).is_some());
        c.put(Ns::Frag, "aa", 3, &blob(3)).unwrap();
        assert_eq!(c.total_bytes(), 30);
        assert_eq!(c.get(Ns::Frag, "aa", 1), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_bytes_counts_ram_backend_only() {
        // Memory backend: memory_bytes tracks the in-RAM fill and drops on evict.
        let dir = tmp_dir("mem-bytes");
        let mut mem =
            BlobCache::open_located(
                &dir,
                Some(1024),
                crate::config::FragmentCacheLocation::Memory,
                "frag",
            )
            .unwrap();
        assert_eq!(mem.memory_bytes(), 0);
        mem.put(Ns::Frag, "aa", 0, &[0u8; 100]).unwrap();
        assert_eq!(mem.memory_bytes(), 100);
        assert_eq!(mem.memory_bytes(), mem.total_bytes());
        // In-RAM backend holds no disk bytes.
        assert_eq!(mem.disk_bytes(), 0);
        mem.evict(Ns::Frag, "aa", 0);
        assert_eq!(mem.memory_bytes(), 0);
        // Disk backend: bytes are on the filesystem, so the RAM figure stays 0 even
        // though total_bytes counts them.
        let mut disk = BlobCache::open(&dir, 1024).unwrap();
        disk.put(Ns::Frag, "bb", 0, &[0u8; 100]).unwrap();
        assert_eq!(disk.total_bytes(), 100);
        assert_eq!(disk.memory_bytes(), 0);
        assert_eq!(disk.disk_bytes(), 100);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_cap_lowering_evicts_down_to_the_new_budget() {
        let dir = tmp_dir("setcap");
        let mut c = BlobCache::open(&dir, 100).unwrap();
        for s in 0..10u32 {
            c.put(Ns::Frag, "aa", s, &[0u8; 10]).unwrap(); // 10 × 10B = 100B, at cap
        }
        assert_eq!(c.total_bytes(), 100);
        // Lower the cap below the current fill → evicts LRU down to ≤ new cap.
        c.set_cap(45);
        assert!(c.total_bytes() <= 45, "got {}", c.total_bytes());
        // The most-recently-used survive; the oldest were evicted.
        assert!(c.contains(Ns::Frag, "aa", 9));
        assert!(!c.contains(Ns::Frag, "aa", 0));
        // Raising the cap keeps everything; a further put now fits.
        c.set_cap(1000);
        assert!(c.total_bytes() <= 45);
        c.put(Ns::Frag, "aa", 100, &[0u8; 500]).unwrap();
        assert!(c.contains(Ns::Frag, "aa", 100));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_blob_is_not_cached() {
        let dir = tmp_dir("oversize");
        let mut c = BlobCache::open(&dir, 8).unwrap();
        c.put(Ns::Frag, "cc", 0, &[0u8; 100]).unwrap(); // bigger than the whole cap
        assert!(!c.contains(Ns::Frag, "cc", 0));
        assert_eq!(c.get(Ns::Frag, "cc", 0), None);
        assert_eq!(c.total_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn namespaces_do_not_collide() {
        let dir = tmp_dir("ns");
        let mut c =
            BlobCache::open_located(&dir, Some(1 << 20), FragmentCacheLocation::Memory, "frag")
                .unwrap();
        c.put(Ns::Frag, "aa", 0, b"frag-bytes").unwrap();
        c.put(Ns::Content, "aa", 0, b"content-bytes").unwrap();
        assert_eq!(
            c.get(Ns::Frag, "aa", 0).as_deref(),
            Some(b"frag-bytes".as_slice())
        );
        assert_eq!(
            c.get(Ns::Content, "aa", 0).as_deref(),
            Some(b"content-bytes".as_slice())
        );
    }

    #[test]
    fn disk_backend_is_uncapped() {
        let dir = tmp_dir("uncap");
        // cap None on disk: three 10-byte blobs under a would-be 20-byte cap all survive.
        let mut c =
            BlobCache::open_located(&dir, None, FragmentCacheLocation::Disk, "frag").unwrap();
        for s in 0..3u32 {
            c.put(Ns::Frag, "aa", s, &[0u8; 10]).unwrap();
        }
        assert_eq!(c.total_bytes(), 30);
        assert_eq!(c.disk_bytes(), 30);
        assert_eq!(c.memory_bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_and_zeroize_empties_both_backends() {
        for loc in [FragmentCacheLocation::Memory, FragmentCacheLocation::Disk] {
            let dir = tmp_dir("clr");
            let cap = if loc == FragmentCacheLocation::Memory {
                Some(1 << 20)
            } else {
                None
            };
            let mut c = BlobCache::open_located(&dir, cap, loc, "frag").unwrap();
            c.put(Ns::Card, "aa", 0, b"x").unwrap();
            // For Disk, the backing file exists before the clear...
            let blob_path = dir.join("cache").join("frag").join("card_aa_0.blob");
            if loc == FragmentCacheLocation::Disk {
                assert!(blob_path.is_file());
            }
            c.clear_and_zeroize();
            assert_eq!(c.total_bytes(), 0);
            assert!(c.get(Ns::Card, "aa", 0).is_none());
            // ...and is actually removed from disk (not just dropped from the index).
            if loc == FragmentCacheLocation::Disk {
                assert!(!blob_path.is_file(), "Disk clear must delete the backing file");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The back-compat `FragmentCache` shim (removed in Task 4/5) forwards its
    /// 2-arg API onto the namespaced `BlobCache` with `Ns::Frag`, preserving the
    /// pre-rework disk-capped semantics.
    #[test]
    fn fragment_cache_shim_roundtrips_and_caps() {
        let dir = tmp_dir("shim");
        let mut c = FragmentCache::open(&dir, 20).unwrap();
        c.put("aa", 0, &[0u8; 10]).unwrap();
        c.put("aa", 1, &[0u8; 10]).unwrap();
        assert_eq!(c.get("aa", 0).as_deref(), Some([0u8; 10].as_slice()));
        assert!(c.contains("aa", 1));
        assert_eq!(c.total_bytes(), 20);
        assert_eq!(c.memory_bytes(), 0);
        // The shim writes under the frag namespace filename.
        assert!(dir
            .join("cache")
            .join("frag")
            .join("frag_aa_0.blob")
            .is_file());
        // Capped: a third blob over the 20B cap evicts the LRU.
        c.put("aa", 2, &[0u8; 10]).unwrap();
        assert_eq!(c.total_bytes(), 20);
        c.evict("aa", 2);
        assert!(!c.contains("aa", 2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
