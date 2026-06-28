//! File-version trust-on-last-use memory (DESIGN §7.5 / D23, Phase 3).
//!
//! The clock-independent rollback anchor for file versions: the client durably
//! remembers, per `file_id`, the highest `version` it has accepted and that
//! version's content-stream digest. [`open_and_remember`] consults this memory
//! to supply `seen_max` to the download core, then advances it on success — so a
//! server that replays an older signed version (rollback), poisons the memory
//! with a near-maximal version (D23), or reuses a version number under different
//! content (fork) is rejected on any client that saw the newer state.
//!
//! Mirrors the directory `TrustStore` pattern (§7.5 key-version memory). At rest
//! the real client keeps this as authenticated ciphertext (§8.1); the core only
//! reads the prior record and writes an accepted one.

use std::collections::HashMap;

use crate::download::{verify_and_open, DownloadBundle, OpenedFile, VerifyContext};
use crate::error::DownloadError;

/// Trust-on-last-use record for one file (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersionRecord {
    pub version: u64,
    pub content_digest: [u8; 32],
}

/// Persistent per-`file_id` version memory (§7.5). `&mut self` on write makes the
/// single-writer discipline explicit, mirroring [`crate::directory::TrustStore`].
pub trait VersionStore {
    fn get(&self, file_id: &[u8; 16]) -> Option<FileVersionRecord>;
    fn put(&mut self, file_id: [u8; 16], record: FileVersionRecord);
}

/// In-memory [`VersionStore`] for tests/dev (the real client persists this).
#[derive(Default)]
pub struct MemoryVersionStore {
    records: HashMap<[u8; 16], FileVersionRecord>,
}

impl MemoryVersionStore {
    pub fn new() -> MemoryVersionStore {
        MemoryVersionStore::default()
    }
}

impl VersionStore for MemoryVersionStore {
    fn get(&self, file_id: &[u8; 16]) -> Option<FileVersionRecord> {
        self.records.get(file_id).copied()
    }
    fn put(&mut self, file_id: [u8; 16], record: FileVersionRecord) {
        self.records.insert(file_id, record);
    }
}

/// Verify & open a download against the file-version memory: read `seen_max` from
/// `store`, run the §12.5 ladder, reject a fork at a reused version, then advance
/// the high-water mark on success. The `seen_max_version` in `ctx` is ignored —
/// the store is authoritative.
pub fn open_and_remember(
    store: &mut dyn VersionStore,
    ctx: &VerifyContext,
    bundle: &DownloadBundle,
) -> Result<OpenedFile, DownloadError> {
    let file_id = ctx.file_id.0;
    let prior = store.get(&file_id);

    // The store is authoritative for freshness — override any seen_max in `ctx`.
    let mut c = ctx.clone();
    c.seen_max_version = prior.map(|r| r.version);

    let opened = verify_and_open(&c, bundle)?;

    // Fork guard: the rule already rejected a lower version, so an accepted open
    // is either the same version (must carry the same content) or version+1.
    if let Some(r) = &prior {
        if opened.version == r.version && opened.content_digest != r.content_digest {
            return Err(DownloadError::VersionForked {
                version: opened.version,
            });
        }
    }

    // Advance the high-water mark (accepted version ≥ prior, so this never lowers).
    store.put(
        file_id,
        FileVersionRecord {
            version: opened.version,
            content_digest: opened.content_digest,
        },
    );
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{StreamChunks, NO_GRANTERS};
    use crate::identity::Identity;
    use crate::upload::{build_upload, PlaintextStreams, UploadBundle, UploadParams};
    use maxsecu_crypto::generate_enc_keypair;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{FileType, Id, RecipientType, Timestamp};

    const OWNER_ID: Id = Id([0x11; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);

    struct Built {
        owner: Identity,
        bundle: UploadBundle,
    }

    fn build_v1() -> Built {
        let owner = Identity::generate();
        let (_rsk, recovery_pk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: recovery_pk,
            created_at: Timestamp(1_719_500_000_000),
        };
        let streams = PlaintextStreams {
            content: b"version one content".to_vec(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        Built { owner, bundle }
    }

    fn self_bundle(b: &UploadBundle) -> DownloadBundle {
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .unwrap();
        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .unwrap();
        DownloadBundle {
            manifest_bytes: encode(&b.manifest),
            manifest_sig: b.manifest_sig,
            genesis_bytes: encode(&b.genesis),
            genesis_sig: b.genesis_sig,
            wrapped_dek: sw.wrapped_dek.clone(),
            grant_bytes: encode(&sw.grant),
            grant_sig: sw.grant_sig,
            ancestor_grants: vec![],
            recovery_grant_bytes: encode(&rw.grant),
            recovery_grant_sig: rw.grant_sig,
            streams: b
                .streams
                .iter()
                .map(|s| StreamChunks {
                    stream_type: s.stream_type,
                    chunks: s.chunks.clone(),
                })
                .collect(),
        }
    }

    fn ctx(built: &Built) -> VerifyContext<'_> {
        let pk = built.owner.sig_pub_bytes();
        VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: OWNER_ID,
            recipient_type: RecipientType::User,
            recipient_secret: built.owner.enc_secret(),
            seen_max_version: Some(999), // deliberately wrong — the store overrides
            granter_sig_pub: &NO_GRANTERS,
        }
    }

    #[test]
    fn first_contact_opens_and_records_high_water_mark() {
        let built = build_v1();
        let db = self_bundle(&built.bundle);
        let mut store = MemoryVersionStore::new();

        let opened = open_and_remember(&mut store, &ctx(&built), &db).expect("opens");
        assert_eq!(opened.version, 1);
        let rec = store.get(&FILE_ID.0).expect("recorded");
        assert_eq!(rec.version, 1);
        assert_eq!(rec.content_digest, opened.content_digest);
    }

    #[test]
    fn rollback_against_memory_is_rejected() {
        let built = build_v1();
        let db = self_bundle(&built.bundle);
        let mut store = MemoryVersionStore::new();
        // Memory already at version 5; the server replays signed v1.
        store.put(
            FILE_ID.0,
            FileVersionRecord {
                version: 5,
                content_digest: [0xAB; 32],
            },
        );
        assert_eq!(
            open_and_remember(&mut store, &ctx(&built), &db),
            Err(DownloadError::VersionRollback {
                seen_max: 5,
                served: 1
            })
        );
        // Memory is unchanged by a rejected open.
        assert_eq!(store.get(&FILE_ID.0).unwrap().version, 5);
    }

    #[test]
    fn re_download_same_version_same_content_is_idempotent() {
        let built = build_v1();
        let db = self_bundle(&built.bundle);
        let mut store = MemoryVersionStore::new();

        open_and_remember(&mut store, &ctx(&built), &db).unwrap();
        // A second open of the very same version succeeds and leaves memory at 1.
        open_and_remember(&mut store, &ctx(&built), &db).unwrap();
        assert_eq!(store.get(&FILE_ID.0).unwrap().version, 1);
    }

    #[test]
    fn same_version_different_content_is_a_fork() {
        let built = build_v1();
        let db = self_bundle(&built.bundle);
        let mut store = MemoryVersionStore::new();
        // Memory says version 1 had a DIFFERENT content digest — a fork at v1.
        store.put(
            FILE_ID.0,
            FileVersionRecord {
                version: 1,
                content_digest: [0xCD; 32],
            },
        );
        assert_eq!(
            open_and_remember(&mut store, &ctx(&built), &db),
            Err(DownloadError::VersionForked { version: 1 })
        );
    }
}
