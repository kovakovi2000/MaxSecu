//! The local title+tag search index (D-F). In-RAM in the TCB; persisted to
//! `<dir>/index/search.idx` ENCRYPTED with a key derived from the unlocked
//! identity via HKDF-SHA256, sealed with the crypto AEAD (`seal`/`open`). Only
//! `SearchHit`s of matches ever leave the TCB — never the whole index.

use std::path::Path;

use serde::{Deserialize, Serialize};

use maxsecu_client_core::Identity;

use crate::dto::SearchHit;
use crate::error::UiError;

/// Domain-separation label for the index key + AEAD aad.
const INDEX_LABEL: &[u8] = b"MaxSecu-search-index-v1";

/// One indexed item: the searchable title + tags + the type, keyed by file id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub file_id: String,
    pub file_type: String,
    pub title: String,
    pub tags: Vec<String>,
}

/// The in-RAM index (also the on-disk plaintext-before-sealing shape).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchIndex {
    pub entries: Vec<IndexEntry>,
}

impl SearchIndex {
    /// Insert or replace the entry for `file_id`.
    pub fn upsert(&mut self, entry: IndexEntry) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.file_id == entry.file_id) {
            *e = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// Case-insensitive substring match over title + tags. Empty query ⇒ all.
    pub fn search(&self, query: &str) -> Vec<SearchHit> {
        let q = query.trim().to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .map(|e| SearchHit {
                file_id: e.file_id.clone(),
                title: e.title.clone(),
                file_type: e.file_type.clone(),
            })
            .collect()
    }
}

/// Derive the 32-byte index-sealing key from the unlocked identity (a stable TCB
/// secret), domain-separated so it is unrelated to any wrap key.
fn index_key(identity: &Identity) -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(maxsecu_crypto::hkdf_sha256_32(
        &identity.enc_secret().expose_bytes(),
        INDEX_LABEL,
    ))
}

/// Load + decrypt the index from `<dir>/index/search.idx`, or an empty index if
/// absent. A decryption/parse failure is a sanitized error (corrupt/foreign).
pub fn load(dir: &Path, identity: &Identity) -> Result<SearchIndex, UiError> {
    let path = dir.join("index").join("search.idx");
    let sealed = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SearchIndex::default()),
        Err(_) => {
            return Err(UiError::new(
                "index_failed",
                "The search index could not be read.",
            ))
        }
    };
    if sealed.len() < 12 {
        return Err(UiError::new("index_failed", "The search index is corrupt."));
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| UiError::new("index_failed", "The search index is corrupt."))?;
    let key = index_key(identity);
    let plain = maxsecu_crypto::open(&key, &nonce, INDEX_LABEL, ct)
        .map_err(|_| UiError::new("index_failed", "The search index could not be read."))?;
    serde_json::from_slice(&plain)
        .map_err(|_| UiError::new("index_failed", "Corrupt search index."))
}

/// Encrypt + persist the index to `<dir>/index/search.idx` (creates `index/`).
pub fn save(dir: &Path, identity: &Identity, index: &SearchIndex) -> Result<(), UiError> {
    let idx_dir = dir.join("index");
    std::fs::create_dir_all(&idx_dir)
        .map_err(|_| UiError::new("index_failed", "Could not write the index."))?;
    let plain = zeroize::Zeroizing::new(
        serde_json::to_vec(index)
            .map_err(|_| UiError::new("index_failed", "Could not encode the index."))?,
    );
    let key = index_key(identity);
    let nonce = maxsecu_crypto::random_array::<12>();
    let ct = maxsecu_crypto::seal(&key, &nonce, INDEX_LABEL, &plain[..]);
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    std::fs::write(idx_dir.join("search.idx"), out)
        .map_err(|_| UiError::new("index_failed", "Could not write the index."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx() -> SearchIndex {
        let mut i = SearchIndex::default();
        i.upsert(IndexEntry {
            file_id: "aa".into(),
            file_type: "image".into(),
            title: "Sunset Beach".into(),
            tags: vec!["beach".into(), "2026".into()],
        });
        i.upsert(IndexEntry {
            file_id: "bb".into(),
            file_type: "blog".into(),
            title: "My Notes".into(),
            tags: vec!["draft".into()],
        });
        i
    }

    #[test]
    fn searches_title_and_tags_case_insensitively() {
        let i = idx();
        assert_eq!(i.search("sunset").len(), 1);
        assert_eq!(i.search("BEACH")[0].file_id, "aa");
        assert_eq!(i.search("draft")[0].file_id, "bb");
        assert_eq!(i.search("").len(), 2); // empty ⇒ all
        assert!(i.search("nonexistent").is_empty());
    }

    #[test]
    fn upsert_replaces_by_file_id() {
        let mut i = idx();
        i.upsert(IndexEntry {
            file_id: "aa".into(),
            file_type: "image".into(),
            title: "Renamed".into(),
            tags: vec![],
        });
        assert_eq!(i.entries.len(), 2);
        assert_eq!(i.search("renamed")[0].file_id, "aa");
        assert!(i.search("sunset").is_empty());
    }

    #[test]
    fn sealed_index_round_trips_and_is_not_plaintext() {
        let id = Identity::generate();
        let tmp = std::env::temp_dir().join(format!(
            "mxidx_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<4>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let mut i = SearchIndex::default();
        i.upsert(IndexEntry {
            file_id: "aa".into(),
            file_type: "blog".into(),
            title: "SECRET_TITLE_MARKER".into(),
            tags: vec!["t".into()],
        });
        save(&tmp, &id, &i).unwrap();
        // On-disk bytes must not contain the plaintext title.
        let raw = std::fs::read(tmp.join("index").join("search.idx")).unwrap();
        assert!(!raw
            .windows(b"SECRET_TITLE_MARKER".len())
            .any(|w| w == b"SECRET_TITLE_MARKER"));
        // A fresh load with the same identity reproduces the index.
        let back = load(&tmp, &id).unwrap();
        assert_eq!(back, i);
        // A different identity cannot read it.
        let other = Identity::generate();
        assert!(load(&tmp, &other).is_err());
        // Absent file ⇒ empty index (not an error).
        let _ = std::fs::remove_dir_all(&tmp);
        assert_eq!(load(&tmp, &id).unwrap(), SearchIndex::default());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
