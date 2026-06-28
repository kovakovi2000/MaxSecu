//! Ciphertext blob storage (api.md §9, DESIGN §12.10 / D31).
//!
//! Chunks are **inert ciphertext** — the client verifies every chunk against the
//! signed manifest's per-stream digest + per-chunk AEAD tag regardless of which
//! tier served it (cache, Dropbox, or a tampering server), so a bad byte from
//! any source is caught client-side (§12.10). The server therefore only has to
//! store and return bytes by `(blob_ref, index)`; it never interprets them.
//!
//! [`MemoryBlobStore`] backs the unit/e2e tests; [`FsBlobStore`] backs the
//! Postgres deployment path (blobs live on disk, out of Postgres — the schema is
//! unchanged). Phase 4b swaps a cache+Dropbox tier in behind this same trait
//! (D31). `blob_ref` is the server-assigned per-stream key from `file_streams`
//! (`server::files`), of the form `hex(file_id)/version/stream_type`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

/// A blob-tier backend fault (I/O / backend error). Inert detail, server-side
/// only — like [`crate::error::StoreError`], never sent to a client verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobError {
    pub op: &'static str,
    pub detail: String,
}

impl BlobError {
    pub fn new(op: &'static str, detail: impl Into<String>) -> Self {
        BlobError {
            op,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob {}: {}", self.op, self.detail)
    }
}

impl std::error::Error for BlobError {}

/// Inert ciphertext-chunk storage keyed by `(blob_ref, index)`. `Send + Sync`
/// for sharing across axum request tasks.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Store one chunk at `index`. **Idempotent by index** (api.md §9.1): a
    /// re-PUT overwrites the same slot, so an interrupted upload re-sends only the
    /// missing indices (resumable).
    async fn put_chunk(&self, blob_ref: &str, index: u64, bytes: Vec<u8>)
        -> Result<(), BlobError>;
    /// Fetch one chunk's bytes, or `None` if that index was never stored.
    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError>;
    /// How many distinct indices are currently stored for `blob_ref`. With the
    /// PUT-side `index < chunk_count` bound, this equals "all of `0..count`
    /// present" — the finalize completeness check (api.md §8.4).
    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError>;
    /// Delete every chunk of a stream (prior-version teardown on finalize, and
    /// staged-cleanup). Idempotent — absent is success.
    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError>;
}

/// In-memory [`BlobStore`] for tests/dev and the e2e path.
#[derive(Default)]
pub struct MemoryBlobStore {
    inner: Mutex<HashMap<String, HashMap<u64, Vec<u8>>>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        MemoryBlobStore {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BlobStore for MemoryBlobStore {
    async fn put_chunk(
        &self,
        blob_ref: &str,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<(), BlobError> {
        self.inner
            .lock()
            .unwrap()
            .entry(blob_ref.to_owned())
            .or_default()
            .insert(index, bytes); // overwrite = idempotent by index
        Ok(())
    }

    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(blob_ref)
            .and_then(|m| m.get(&index).cloned()))
    }

    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(blob_ref)
            .map(|m| m.len() as u64)
            .unwrap_or(0))
    }

    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        self.inner.lock().unwrap().remove(blob_ref);
        Ok(())
    }
}

/// Filesystem-backed [`BlobStore`] (the Postgres-path tier): each stream is a
/// directory `base/<blob_ref>/`, each chunk the file `<index>` inside it.
pub struct FsBlobStore {
    base: PathBuf,
}

impl FsBlobStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        FsBlobStore { base: base.into() }
    }

    /// Resolve `base/<blob_ref>` with a containment guard. `blob_ref` is
    /// server-generated (`hex/version/stream_type`), but we still reject any `..`
    /// / absolute / prefix component so a future caller-influenced ref cannot
    /// escape `base` (defense in depth, mirrors `client-core::sanitize`).
    fn stream_dir(&self, blob_ref: &str) -> Result<PathBuf, BlobError> {
        let rel = Path::new(blob_ref);
        for c in rel.components() {
            match c {
                Component::Normal(_) => {}
                _ => {
                    return Err(BlobError::new("stream_dir", "unsafe blob_ref component"));
                }
            }
        }
        Ok(self.base.join(rel))
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put_chunk(
        &self,
        blob_ref: &str,
        index: u64,
        bytes: Vec<u8>,
    ) -> Result<(), BlobError> {
        let dir = self.stream_dir(blob_ref)?;
        std::fs::create_dir_all(&dir).map_err(|e| BlobError::new("put_chunk", e.to_string()))?;
        let path = dir.join(index.to_string());
        // Write to a temp sibling then rename, so a concurrent re-PUT of the same
        // index never exposes a half-written chunk.
        let tmp = dir.join(format!("{index}.tmp"));
        std::fs::write(&tmp, &bytes).map_err(|e| BlobError::new("put_chunk", e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| BlobError::new("put_chunk", e.to_string()))?;
        Ok(())
    }

    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        let path = self.stream_dir(blob_ref)?.join(index.to_string());
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BlobError::new("get_chunk", e.to_string())),
        }
    }

    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        let dir = self.stream_dir(blob_ref)?;
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(BlobError::new("chunk_count", e.to_string())),
        };
        let mut count = 0u64;
        for entry in rd {
            let entry = entry.map_err(|e| BlobError::new("chunk_count", e.to_string()))?;
            // Count committed chunk files only — skip any `.tmp` in-flight writes.
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".tmp") {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        let dir = self.stream_dir(blob_ref)?;
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BlobError::new("delete_stream", e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REF: &str = "aabbccddeeff00112233445566778899/1/1";

    async fn roundtrip_and_idempotency(store: &dyn BlobStore) {
        assert_eq!(store.chunk_count(REF).await.unwrap(), 0);
        assert!(store.get_chunk(REF, 0).await.unwrap().is_none());

        store.put_chunk(REF, 0, vec![0xAA; 16]).await.unwrap();
        store.put_chunk(REF, 1, vec![0xBB; 16]).await.unwrap();
        assert_eq!(store.chunk_count(REF).await.unwrap(), 2);
        assert_eq!(store.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xAA; 16]);
        assert_eq!(store.get_chunk(REF, 1).await.unwrap().unwrap(), vec![0xBB; 16]);

        // Re-PUT the same index overwrites the slot (idempotent), not a duplicate.
        store.put_chunk(REF, 0, vec![0xCC; 16]).await.unwrap();
        assert_eq!(store.chunk_count(REF).await.unwrap(), 2);
        assert_eq!(store.get_chunk(REF, 0).await.unwrap().unwrap(), vec![0xCC; 16]);

        // Teardown removes the whole stream; idempotent on a second call.
        store.delete_stream(REF).await.unwrap();
        assert_eq!(store.chunk_count(REF).await.unwrap(), 0);
        store.delete_stream(REF).await.unwrap();
    }

    #[tokio::test]
    async fn memory_roundtrip_and_idempotency() {
        roundtrip_and_idempotency(&MemoryBlobStore::new()).await;
    }

    fn unique_dir(tag: &str) -> PathBuf {
        let r = maxsecu_crypto::random_array::<8>();
        let mut hex = String::new();
        for b in r {
            hex.push_str(&format!("{b:02x}"));
        }
        std::env::temp_dir().join(format!("mxblob_{tag}_{hex}"))
    }

    #[tokio::test]
    async fn fs_roundtrip_and_idempotency() {
        let dir = unique_dir("rt");
        let store = FsBlobStore::new(&dir);
        roundtrip_and_idempotency(&store).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fs_rejects_unsafe_blob_ref() {
        let store = FsBlobStore::new(unique_dir("guard"));
        assert!(store.put_chunk("../escape", 0, vec![1]).await.is_err());
        assert!(store.get_chunk("/etc/passwd", 0).await.is_err());
    }
}
