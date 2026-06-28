//! The download / verify / decrypt core (DESIGN §12.5, Phase 3).
//!
//! Pure and transport-agnostic: given the opaque records a server returns for a
//! file version (api.md §8.5) plus the directory-verified author/owner signing
//! keys (resolved by the caller), it runs the full §12.5 verification ladder and
//! returns the decrypted streams — or a fail-closed [`DownloadError`]. Nothing
//! here trusts the server's framing: every record is strictly decoded (the
//! re-encode guard), every signature checked, every framing field bound-checked
//! before allocation, and the DEK self-validated against the manifest commitment.
//!
//! Phase 3 is single-recipient (self or recovery) with owner-only write (D29),
//! so a grant chains directly to the author; the re-share ancestor chain
//! (§12.4b) and full tombstone-completeness evaluation are Phase 4/5.

use maxsecu_crypto::{open_stream, stream_digest, unwrap_dek, EncSecretKey, VerifyingKey, WrappedDek};
use maxsecu_encoding::structs::{Genesis, Grant, Manifest, WrapContext};
use maxsecu_encoding::types::{Compression, FileType, Id, RecipientType, StreamType};
use maxsecu_encoding::{decode, labels, Canonical, RECOVERY_ID};

use crate::error::DownloadError;
use crate::limits::{
    CHUNK_SIZE_MAX, CHUNK_SIZE_MIN, FIRST_CONTACT_VERSION_CEILING, MAX_ADDRESSABLE_BYTES,
};

/// One stream's ordered ciphertext chunks as served (api.md §9.2).
pub struct StreamChunks {
    pub stream_type: StreamType,
    pub chunks: Vec<Vec<u8>>,
}

/// The opaque record set a server returns for one file version (api.md §8.5).
/// All `_bytes` fields are exact `canonical(...)` bytes; the core decodes them.
pub struct DownloadBundle {
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    /// The caller's own wrap (never another user's, never the recovery wrap).
    pub wrapped_dek: WrappedDek,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    /// The recovery recipient's grant (grant only, for the presence check).
    pub recovery_grant_bytes: Vec<u8>,
    pub recovery_grant_sig: [u8; 64],
    pub streams: Vec<StreamChunks>,
}

/// What the caller has resolved out of band before opening: the requested
/// `file_id`, the author's and owner's directory-verified signing keys, who the
/// downloader is, its unwrap key, and its trust-on-last-use version memory.
#[derive(Clone)]
pub struct VerifyContext<'a> {
    pub file_id: Id,
    /// The version author's directory-verified Ed25519 `sig_pub` (verifies the
    /// manifest and the grants, whose `granted_by` is the author in Phase 3).
    pub author_sig_pub: [u8; 32],
    /// The owner's directory-verified `sig_pub` for `genesis.owner_key_version`
    /// (verifies `genesis_sig`). In Phase 3 the owner *is* the author.
    pub owner_sig_pub: [u8; 32],
    pub recipient_id: Id,
    pub recipient_type: RecipientType,
    pub recipient_secret: &'a EncSecretKey,
    /// Highest `version` accepted for this file (trust-on-last-use), or `None`
    /// at first contact (§7.5). Supplied/persisted by the version-memory store.
    pub seen_max_version: Option<u64>,
}

/// One decrypted (and, later, decompressed) stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedStream {
    pub stream_type: StreamType,
    pub plaintext: Vec<u8>,
}

/// A successfully verified and decrypted file version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFile {
    pub version: u64,
    pub file_type: FileType,
    /// The `content` stream's manifest digest — what the caller records in
    /// trust-on-last-use memory alongside `version` (§7.5).
    pub content_digest: [u8; 32],
    /// `false` if the manifest asserts `recovery_present` but no valid author
    /// recovery grant was served — an anomaly to report (§12.5 step 5), not a
    /// rejection of the downloader's own read.
    pub recovery_grant_ok: bool,
    pub streams: Vec<OpenedStream>,
}

/// The §7.5/D23 file-`version` freshness rule (clock-independent): reject a
/// served version older than the highest seen or more than +1 above it; at first
/// contact apply the absolute ceiling. Exposed for the version-memory store to
/// reuse.
pub fn version_acceptable(served: u64, seen_max: Option<u64>) -> Result<(), DownloadError> {
    match seen_max {
        None => {
            if served > FIRST_CONTACT_VERSION_CEILING {
                Err(DownloadError::FirstContactCeiling { served })
            } else {
                Ok(())
            }
        }
        Some(seen) => {
            if served < seen {
                Err(DownloadError::VersionRollback {
                    seen_max: seen,
                    served,
                })
            } else if served > seen + 1 {
                Err(DownloadError::VersionTooHigh {
                    seen_max: seen,
                    served,
                })
            } else {
                Ok(())
            }
        }
    }
}

/// Run the §12.5 download verification ladder and decrypt, fail-closed.
pub fn verify_and_open(
    ctx: &VerifyContext,
    bundle: &DownloadBundle,
) -> Result<OpenedFile, DownloadError> {
    use DownloadError::*;

    // (1) Manifest: strict decode (re-encode guard), file_id, framing bound,
    // then the author's signature.
    let manifest: Manifest = decode(&bundle.manifest_bytes).map_err(|_| BadManifest)?;
    if manifest.file_id != ctx.file_id {
        return Err(FileIdMismatch);
    }
    if manifest.chunk_size < CHUNK_SIZE_MIN || manifest.chunk_size > CHUNK_SIZE_MAX {
        return Err(FramingBoundsExceeded("chunk_size out of range"));
    }
    if !verify(&ctx.author_sig_pub, labels::MANIFEST, &manifest, &bundle.manifest_sig) {
        return Err(ManifestSignature);
    }

    // (2) Genesis: decode + the owner's signature (owner binding).
    let genesis: Genesis = decode(&bundle.genesis_bytes).map_err(|_| BadGenesis)?;
    if genesis.file_id != ctx.file_id {
        return Err(FileIdMismatch);
    }
    if !verify(&ctx.owner_sig_pub, labels::GENESIS, &genesis, &bundle.genesis_sig) {
        return Err(GenesisSignature);
    }

    // (3) Author-entitlement: owner-only write (D29).
    if manifest.author_id != genesis.owner_id {
        return Err(AuthorNotOwner);
    }

    // (4) Freshness / rollback (clock-independent, §7.5/D23).
    version_acceptable(manifest.version, ctx.seen_max_version)?;

    // (5) The caller's own read-grant: decode, verify, chain to the author.
    let grant: Grant = decode(&bundle.grant_bytes).map_err(|_| BadGrant)?;
    if !verify(&ctx.author_sig_pub, labels::GRANT, &grant, &bundle.grant_sig) {
        return Err(GrantSignature);
    }
    check_grant(&grant, &manifest, ctx, genesis.owner_id)?;

    // (6) Recovery-grant presence — an anomaly flag, never a hard rejection of
    // the downloader's own read (§12.5 step 5).
    let recovery_grant_ok = recovery_grant_valid(bundle, &manifest, &ctx.author_sig_pub, genesis.owner_id);

    // (7) Unwrap the DEK and self-validate against the manifest commitment.
    let wrap_ctx = WrapContext {
        file_id: ctx.file_id,
        version: manifest.version,
        recipient_id: ctx.recipient_id,
    };
    let dek = unwrap_dek(ctx.recipient_secret, &bundle.wrapped_dek, &wrap_ctx).map_err(|_| DekUnwrap)?;
    if dek.commit() != manifest.dek_commit.0 {
        return Err(DekCommitMismatch);
    }

    // (8) Per stream: bound-check framing before allocating, verify the manifest
    // digest, then decrypt (framing tags re-checked by open_stream).
    let mut streams = Vec::with_capacity(manifest.streams.len());
    let mut content_digest = [0u8; 32];
    for ms in &manifest.streams {
        if ms.compression != Compression::None {
            return Err(CompressionUnsupported);
        }
        let provided = bundle
            .streams
            .iter()
            .find(|s| s.stream_type == ms.stream_type)
            .ok_or(StreamMissing(ms.stream_type))?;
        if provided.chunks.len() as u64 != ms.chunk_count {
            return Err(FramingBoundsExceeded("chunk_count mismatch"));
        }
        match ms.chunk_count.checked_mul(manifest.chunk_size as u64) {
            Some(b) if b <= MAX_ADDRESSABLE_BYTES => {}
            _ => return Err(FramingBoundsExceeded("addressable size")),
        }
        if stream_digest(&provided.chunks) != ms.digest.0 {
            return Err(StreamDigestMismatch(ms.stream_type));
        }
        let ck = dek.stream_subkey(ms.stream_type);
        let plaintext = open_stream(&ck, ctx.file_id, manifest.version, ms.stream_type, &provided.chunks)
            .map_err(|_| StreamFraming(ms.stream_type))?;
        if ms.stream_type == StreamType::Content {
            content_digest = ms.digest.0;
        }
        streams.push(OpenedStream {
            stream_type: ms.stream_type,
            plaintext,
        });
    }

    Ok(OpenedFile {
        version: manifest.version,
        file_type: manifest.file_type,
        content_digest,
        recovery_grant_ok,
        streams,
    })
}

/// Strict Ed25519 verification of a canonical record under its domain label.
fn verify<T: Canonical>(pubkey: &[u8; 32], label: &str, v: &T, sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(pubkey)
        .and_then(|vk| vk.verify_canonical(label, v, sig))
        .is_ok()
}

/// Check the caller's grant binds this exact file/version/recipient/DEK and
/// chains to the author (owner, in Phase 3). A mismatch ⇒ the wrap is absent.
fn check_grant(
    g: &Grant,
    m: &Manifest,
    ctx: &VerifyContext,
    owner_id: Id,
) -> Result<(), DownloadError> {
    use DownloadError::GrantMismatch;
    if g.file_id != ctx.file_id {
        return Err(GrantMismatch("file_id"));
    }
    if g.file_version != m.version {
        return Err(GrantMismatch("file_version"));
    }
    if g.recipient_id != ctx.recipient_id {
        return Err(GrantMismatch("recipient_id"));
    }
    if g.recipient_type != ctx.recipient_type {
        return Err(GrantMismatch("recipient_type"));
    }
    if g.dek_commit != m.dek_commit {
        return Err(GrantMismatch("dek_commit"));
    }
    // Owner-only write (D29): the version author is the owner, and a Phase-3
    // grant is author-rooted, so `granted_by` must be the owner.
    if g.granted_by != owner_id {
        return Err(GrantMismatch("granted_by"));
    }
    Ok(())
}

/// Is a valid author recovery grant present for this version? (Presence check
/// only — the recovery *wrap* is never served to a downloader, §12.5 step 2.)
fn recovery_grant_valid(
    bundle: &DownloadBundle,
    m: &Manifest,
    author_pub: &[u8; 32],
    owner_id: Id,
) -> bool {
    let g: Grant = match decode(&bundle.recovery_grant_bytes) {
        Ok(g) => g,
        Err(_) => return false,
    };
    verify(author_pub, labels::GRANT, &g, &bundle.recovery_grant_sig)
        && g.recipient_type == RecipientType::Recovery
        && g.recipient_id == RECOVERY_ID
        && g.file_id == m.file_id
        && g.file_version == m.version
        && g.dek_commit == m.dek_commit
        && g.granted_by == owner_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::upload::{build_upload, PlaintextStreams, UploadBundle, UploadParams};
    use maxsecu_crypto::{generate_enc_keypair, wrap_dek, Dek, EncPublicKey};
    use maxsecu_encoding::encode;
    use maxsecu_encoding::types::{Bytes32, Suite, Timestamp};

    const OWNER_ID: Id = Id([0x11; 16]);
    const FILE_ID: Id = Id([0xF1; 16]);
    const NOW: Timestamp = Timestamp(1_719_500_000_000);

    struct Built {
        owner: Identity,
        recovery_sk: EncSecretKey,
        bundle: UploadBundle,
    }

    fn build() -> Built {
        let owner = Identity::generate();
        let (recovery_sk, recovery_pk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: recovery_pk,
            created_at: NOW,
        };
        let streams = PlaintextStreams {
            content: b"the quick brown fox jumps over the lazy dog".to_vec(),
            metadata: Some(b"title=fox".to_vec()),
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        Built {
            owner,
            recovery_sk,
            bundle,
        }
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

    fn ctx<'a>(built: &'a Built) -> VerifyContext<'a> {
        let pk = built.owner.sig_pub_bytes();
        VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: OWNER_ID,
            recipient_type: RecipientType::User,
            recipient_secret: built.owner.enc_secret(),
            seen_max_version: None,
        }
    }

    #[test]
    fn round_trips_self_recipient() {
        let built = build();
        let db = self_bundle(&built.bundle);
        let opened = verify_and_open(&ctx(&built), &db).expect("opens");

        assert_eq!(opened.version, 1);
        assert_eq!(opened.file_type, FileType::Blog);
        assert!(opened.recovery_grant_ok, "valid recovery grant present");
        let content = opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        assert_eq!(content.plaintext, b"the quick brown fox jumps over the lazy dog");
        let meta = opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .unwrap();
        assert_eq!(meta.plaintext, b"title=fox");
    }

    #[test]
    fn recovery_wrap_recipient_round_trips() {
        let built = build();
        let b = &built.bundle;
        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .unwrap();
        let mut db = self_bundle(b);
        db.wrapped_dek = rw.wrapped_dek.clone();
        db.grant_bytes = encode(&rw.grant);
        db.grant_sig = rw.grant_sig;

        let pk = built.owner.sig_pub_bytes();
        let c = VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: RECOVERY_ID,
            recipient_type: RecipientType::Recovery,
            recipient_secret: &built.recovery_sk,
            seen_max_version: None,
        };
        let opened = verify_and_open(&c, &db).expect("recovery opens");
        assert_eq!(opened.version, 1);
    }

    #[test]
    fn forged_manifest_signature_is_rejected() {
        let built = build();
        let mut db = self_bundle(&built.bundle);
        db.manifest_sig[0] ^= 0x01;
        assert_eq!(
            verify_and_open(&ctx(&built), &db),
            Err(DownloadError::ManifestSignature)
        );
    }

    #[test]
    fn tampered_content_chunk_body_is_rejected() {
        let built = build();
        let mut db = self_bundle(&built.bundle);
        let content = db
            .streams
            .iter_mut()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        content.chunks[0][0] ^= 0x01; // flip a ciphertext body byte
        assert_eq!(
            verify_and_open(&ctx(&built), &db),
            Err(DownloadError::StreamFraming(StreamType::Content))
        );
    }

    #[test]
    fn truncated_stream_is_rejected() {
        let built = build();
        // Use a large content so it spans multiple chunks, then drop the last.
        let owner = Identity::generate();
        let (rsk, rpk) = generate_enc_keypair();
        let params = UploadParams {
            owner: &owner,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            file_id: FILE_ID,
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub: rpk,
            created_at: NOW,
        };
        let big = vec![7u8; 4096 * 3 + 11];
        let streams = PlaintextStreams {
            content: big,
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let b = build_upload(&params, &streams).unwrap();
        let _ = (&built, &rsk);
        let mut db = self_bundle(&b);
        let content = db
            .streams
            .iter_mut()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        content.chunks.pop(); // truncate

        let pk = owner.sig_pub_bytes();
        let c = VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: OWNER_ID,
            recipient_type: RecipientType::User,
            recipient_secret: owner.enc_secret(),
            seen_max_version: None,
        };
        assert!(matches!(
            verify_and_open(&c, &db),
            Err(DownloadError::FramingBoundsExceeded(_))
        ));
    }

    #[test]
    fn author_not_owner_is_rejected() {
        // Normal upload (author == owner O), then swap in a genesis for a
        // DIFFERENT owner O2 (signed by O2). author_id (O) != owner_id (O2).
        let built = build();
        let o2 = Identity::generate();
        let o2_id = Id([0x22; 16]);
        let genesis = Genesis {
            file_id: FILE_ID,
            owner_id: o2_id,
            owner_key_version: 1,
            created_at: NOW,
        };
        let genesis_sig = o2.signing_key().sign_canonical(labels::GENESIS, &genesis);
        let mut db = self_bundle(&built.bundle);
        db.genesis_bytes = encode(&genesis);
        db.genesis_sig = genesis_sig;

        let mut c = ctx(&built);
        c.owner_sig_pub = o2.sig_pub_bytes(); // genesis verifies, but owner != author
        assert_eq!(verify_and_open(&c, &db), Err(DownloadError::AuthorNotOwner));
    }

    #[test]
    fn dek_commit_mismatch_is_rejected() {
        // A wrap that opens to a DIFFERENT DEK than the manifest commits — e.g.
        // a grant backed by a garbage wrap (§12.5 step 6 self-validating proof).
        let built = build();
        let mut db = self_bundle(&built.bundle);
        let other = Dek::generate();
        let ctx_wrap = WrapContext {
            file_id: FILE_ID,
            version: 1,
            recipient_id: OWNER_ID,
        };
        let owner_pub = EncPublicKey::from_bytes(built.owner.enc_pub_bytes());
        db.wrapped_dek = wrap_dek(&owner_pub, &other, &ctx_wrap).unwrap();
        assert_eq!(
            verify_and_open(&ctx(&built), &db),
            Err(DownloadError::DekCommitMismatch)
        );
    }

    #[test]
    fn forged_grant_signature_is_rejected() {
        let built = build();
        let mut db = self_bundle(&built.bundle);
        db.grant_sig[0] ^= 0x01;
        assert_eq!(
            verify_and_open(&ctx(&built), &db),
            Err(DownloadError::GrantSignature)
        );
    }

    #[test]
    fn grant_for_a_different_recipient_is_rejected() {
        let built = build();
        let db = self_bundle(&built.bundle);
        let mut c = ctx(&built);
        c.recipient_id = Id([0x99; 16]); // grant names OWNER_ID, context claims another
        assert!(matches!(
            verify_and_open(&c, &db),
            Err(DownloadError::GrantMismatch(_))
        ));
    }

    #[test]
    fn missing_recovery_grant_flags_anomaly_without_failing() {
        let built = build();
        let mut db = self_bundle(&built.bundle);
        db.recovery_grant_sig[0] ^= 0x01; // invalid recovery grant
        let opened = verify_and_open(&ctx(&built), &db).expect("own read still succeeds");
        assert!(!opened.recovery_grant_ok, "recovery anomaly flagged");
    }

    #[test]
    fn version_rollback_is_rejected() {
        let built = build();
        let db = self_bundle(&built.bundle);
        let mut c = ctx(&built);
        c.seen_max_version = Some(5); // served is version 1 — a rollback
        assert_eq!(
            verify_and_open(&c, &db),
            Err(DownloadError::VersionRollback {
                seen_max: 5,
                served: 1
            })
        );
    }

    #[test]
    fn chunk_size_below_floor_in_manifest_is_rejected() {
        // A (manually) signed manifest with an out-of-range chunk_size — the
        // downloader bound-checks framing even though the manifest is signed.
        let owner = Identity::generate();
        let dek = Dek::generate();
        let manifest = Manifest {
            file_id: FILE_ID,
            version: 1,
            file_type: FileType::Blog,
            alg: Suite::V1,
            chunk_size: 1024, // below 4 KiB
            dek_commit: Bytes32(dek.commit()),
            streams: vec![],
            recovery_present: true,
            author_id: OWNER_ID,
            created_at: NOW,
        };
        let manifest_sig = owner.signing_key().sign_canonical(labels::MANIFEST, &manifest);
        let genesis = Genesis {
            file_id: FILE_ID,
            owner_id: OWNER_ID,
            owner_key_version: 1,
            created_at: NOW,
        };
        let genesis_sig = owner.signing_key().sign_canonical(labels::GENESIS, &genesis);
        let db = DownloadBundle {
            manifest_bytes: encode(&manifest),
            manifest_sig,
            genesis_bytes: encode(&genesis),
            genesis_sig,
            wrapped_dek: WrappedDek {
                enc: [0; 32],
                ct: vec![0; 48],
            },
            grant_bytes: vec![],
            grant_sig: [0; 64],
            recovery_grant_bytes: vec![],
            recovery_grant_sig: [0; 64],
            streams: vec![],
        };
        let pk = owner.sig_pub_bytes();
        let c = VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: pk,
            owner_sig_pub: pk,
            recipient_id: OWNER_ID,
            recipient_type: RecipientType::User,
            recipient_secret: owner.enc_secret(),
            seen_max_version: None,
        };
        assert!(matches!(
            verify_and_open(&c, &db),
            Err(DownloadError::FramingBoundsExceeded(_))
        ));
    }

    #[test]
    fn version_rule_accepts_same_next_and_first_contact() {
        assert!(version_acceptable(1, None).is_ok());
        assert!(version_acceptable(7, Some(7)).is_ok()); // re-download current
        assert!(version_acceptable(8, Some(7)).is_ok()); // next version
    }

    #[test]
    fn version_rule_rejects_rollback_too_high_and_ceiling() {
        assert_eq!(
            version_acceptable(6, Some(7)),
            Err(DownloadError::VersionRollback {
                seen_max: 7,
                served: 6
            })
        );
        assert_eq!(
            version_acceptable(9, Some(7)),
            Err(DownloadError::VersionTooHigh {
                seen_max: 7,
                served: 9
            })
        );
        assert_eq!(
            version_acceptable(FIRST_CONTACT_VERSION_CEILING + 1, None),
            Err(DownloadError::FirstContactCeiling {
                served: FIRST_CONTACT_VERSION_CEILING + 1
            })
        );
    }
}
