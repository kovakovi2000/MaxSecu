//! Disk-backed staging record for resumable video uploads.
//!
//! # Security invariant
//!
//! `StagingRecord` holds **NO DEK and NO content-stream ciphertext**.  The
//! content ciphertext is large and is re-sealed on demand at resume time from
//! `out_mp4_path` using the DEK recovered in-process from the self-wrap.
//! Only the small-stream ciphertexts (metadata / thumbnail / preview) are
//! persisted — they are public-shape and small.  `StagedSmallStream::stream_type`
//! must never be `1` (content); the tests assert this invariant.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Small local hex helper (no new dep)
// ---------------------------------------------------------------------------

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One wrap (self or recovery) as it will be re-POSTed to `/v1/files`.  Stores
/// the already-serialised wire forms so no key material is derived at resume time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedWrap {
    pub recipient_id: [u8; 16],
    pub recipient_type: String, // "user" | "recovery"
    pub wrapped_dek: Vec<u8>,   // wire bytes (enc ‖ ct)
    pub granted_by: [u8; 16],
    pub grant: Vec<u8>,     // canonical encoded Grant
    pub grant_sig: Vec<u8>, // 64 bytes
}

/// One SMALL (non-content) sealed stream (metadata / thumbnail / preview).  Its
/// ciphertext IS persisted (small + public-shape).  The CONTENT stream is
/// deliberately absent — `stream_type == 1` is forbidden by invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedSmallStream {
    pub stream_type: u8, // 2=metadata, 3=thumbnail, 4=preview (NEVER 1=content)
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub total_bytes: u64,
    pub digest: Vec<u8>,      // 32 bytes
    pub chunks: Vec<Vec<u8>>, // ciphertext chunks
}

/// The on-disk staging record for one resumable video upload.
///
/// # No DEK, no content ciphertext
///
/// This struct has **no field** capable of holding a DEK or the content-stream
/// ciphertext.  The content DEK lives only in-memory (recovered from
/// `wraps[self_wrap]` at upload or resume time) and is never written to disk.
/// The content ciphertext is re-sealed on demand from `out_mp4_path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagingRecord {
    pub file_id: [u8; 16],
    pub file_type: String, // "video"
    pub title: String,
    pub manifest: Vec<u8>,     // canonical encoded Manifest
    pub manifest_sig: Vec<u8>, // 64 bytes
    pub genesis: Vec<u8>,      // canonical encoded Genesis
    pub genesis_sig: Vec<u8>,  // 64 bytes
    pub wraps: Vec<StagedWrap>,
    pub out_mp4_path: PathBuf, // the on-disk transcode (author plaintext)
    pub chunk_size: u32,          // content chunk size (6 MiB)
    pub content_chunk_count: u64, // number of content chunks to (re-)seal + PUT
    pub small_streams: Vec<StagedSmallStream>,
    pub progress: u64,        // last content chunk index successfully PUT (0 = none)
    pub created_ms: u64,
    pub last_progress_ms: u64,
    pub finalized: bool,
}

// ---------------------------------------------------------------------------
// StagingStore
// ---------------------------------------------------------------------------

/// Manages per-upload staging directories under a root path.
///
/// Layout: `<root>/<file_id_hex>/record.json`
pub struct StagingStore {
    root: PathBuf,
}

impl StagingStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The per-upload staging directory (callers may place `out.mp4` here).
    pub fn dir_for(&self, file_id: &[u8; 16]) -> PathBuf {
        self.root.join(hex16(file_id))
    }

    /// Persist `rec` to `<root>/<file_id_hex>/record.json` atomically (write to
    /// a temp file, then rename).  Creates directories as needed.
    pub fn persist(&self, rec: &StagingRecord) -> std::io::Result<()> {
        let dir = self.dir_for(&rec.file_id);
        std::fs::create_dir_all(&dir)?;

        let target = dir.join("record.json");
        let tmp = dir.join("record.json.tmp");

        let json = serde_json::to_vec(rec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &target)?;
        Ok(())
    }

    /// Load `<root>/<file_id_hex>/record.json`.  Fail-closed on missing or corrupt.
    pub fn load(&self, file_id: &[u8; 16]) -> std::io::Result<StagingRecord> {
        let path = self.dir_for(file_id).join("record.json");
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Every valid pending record under `<root>`.  Skips unreadable / corrupt
    /// entries rather than failing the whole scan.
    pub fn list_pending(&self) -> Vec<StagingRecord> {
        let read_dir = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for entry in read_dir.flatten() {
            let path = entry.path().join("record.json");
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(rec) = serde_json::from_slice::<StagingRecord>(&bytes) {
                    out.push(rec);
                }
            }
        }
        out
    }

    /// Remove `<root>/<file_id_hex>/` recursively.  Idempotent — Ok if absent.
    pub fn remove(&self, file_id: &[u8; 16]) -> std::io::Result<()> {
        let dir = self.dir_for(file_id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn nanos() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
    }

    fn tmp_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mxs-staging-{}-{}-{}",
            std::process::id(),
            tag,
            nanos()
        ))
    }

    fn make_wrap(n: u8) -> StagedWrap {
        StagedWrap {
            recipient_id: [n; 16],
            recipient_type: if n == 0 { "user".into() } else { "recovery".into() },
            wrapped_dek: vec![n, n + 1, n + 2], // encrypted wire bytes — NOT the raw DEK
            granted_by: [n + 10; 16],
            grant: vec![0xaa, 0xbb, n],
            grant_sig: vec![n; 64],
        }
    }

    fn make_small_stream(stream_type: u8) -> StagedSmallStream {
        assert_ne!(stream_type, 1, "content stream must never be staged");
        StagedSmallStream {
            stream_type,
            chunk_size: 65536,
            chunk_count: 2,
            total_bytes: 131072,
            digest: vec![0xde; 32],
            chunks: vec![vec![1u8; 8], vec![2u8; 8]],
        }
    }

    fn make_record() -> StagingRecord {
        StagingRecord {
            file_id: [0x42; 16],
            file_type: "video".into(),
            title: "test-video.mp4".into(),
            manifest: vec![0x01, 0x02, 0x03],
            manifest_sig: vec![0xAB; 64],
            genesis: vec![0x04, 0x05, 0x06],
            genesis_sig: vec![0xCD; 64],
            wraps: vec![make_wrap(0), make_wrap(1)],
            out_mp4_path: PathBuf::from("/tmp/out.mp4"),
            chunk_size: 6 * 1024 * 1024,
            content_chunk_count: 10,
            small_streams: vec![
                make_small_stream(2), // metadata
                make_small_stream(3), // thumbnail
            ],
            progress: 0,
            created_ms: 1_700_000_000_000,
            last_progress_ms: 1_700_000_000_000,
            finalized: false,
        }
    }

    #[test]
    fn round_trips_through_disk() {
        let root = tmp_root("rtrip");
        let store = StagingStore::new(&root);
        let rec = make_record();

        // persist + load round-trip
        store.persist(&rec).unwrap();
        let loaded = store.load(&rec.file_id).unwrap();
        assert_eq!(loaded, rec);

        // list_pending returns exactly this record
        let pending = store.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], rec);

        // remove then assert gone
        store.remove(&rec.file_id).unwrap();
        assert!(store.load(&rec.file_id).is_err());
        assert!(store.list_pending().is_empty());

        // cleanup
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn record_holds_no_dek_and_no_content_ciphertext() {
        let rec = make_record();

        // No small stream has stream_type == 1 (content).
        // The content ciphertext is never persisted to disk by design — there is
        // no field in StagingRecord that can hold it.
        for ss in &rec.small_streams {
            assert_ne!(
                ss.stream_type, 1,
                "stream_type=1 (content) must never appear in small_streams"
            );
        }

        // Cheap JSON-key guard: the serialised form must not contain a key named "dek".
        let json = serde_json::to_vec(&rec).unwrap();
        assert!(
            !String::from_utf8_lossy(&json).contains("\"dek\""),
            "JSON must not contain a field named dek"
        );
    }

    #[test]
    fn persist_is_atomic_no_partial_on_reload() {
        let root = tmp_root("atomic");
        let store = StagingStore::new(&root);
        let rec = make_record();

        // Initial persist
        store.persist(&rec).unwrap();

        // Persist an updated record (progress bumped)
        let mut updated = rec.clone();
        updated.progress = 7;
        updated.last_progress_ms = 1_700_000_001_000;
        store.persist(&updated).unwrap();

        // Load must equal the updated record
        let loaded = store.load(&rec.file_id).unwrap();
        assert_eq!(loaded, updated);
        assert_eq!(loaded.progress, 7);

        // cleanup
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let root = tmp_root("corrupt");
        let store = StagingStore::new(&root);
        let file_id = [0x42u8; 16];

        // Write garbage bytes into the expected record path
        let dir = store.dir_for(&file_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("record.json"), b"NOT VALID JSON {{{").unwrap();

        // load must return Err
        assert!(
            store.load(&file_id).is_err(),
            "corrupt record must fail closed"
        );

        // list_pending must skip it without panicking
        let pending = store.list_pending();
        assert!(
            pending.is_empty(),
            "list_pending must skip corrupt records"
        );

        // cleanup
        let _ = std::fs::remove_dir_all(&root);
    }
}
