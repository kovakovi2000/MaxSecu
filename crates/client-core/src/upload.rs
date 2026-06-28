//! The file-upload core (DESIGN §12.2, Phase 3 — single-recipient).
//!
//! Pure and transport-agnostic: given the owner's identity, the plaintext
//! streams, and the recovery recipient's `enc_pub`, it produces the complete
//! signed record set the client uploads (api.md §8.1) — an owner-signed
//! `genesis`, a signed multi-stream `manifest`, the chunked-AEAD ciphertext per
//! stream, and a wrap+signed-grant for **self and recovery** (the only two
//! recipients in Phase 3; multi-recipient sharing is Phase 4). It derives one
//! fresh DEK, never an AEAD key directly (L-5), commits to it via `dek_commit`,
//! and self-checks the wraps it holds the key for before returning.

use maxsecu_crypto::{
    seal_stream, unwrap_dek, wrap_dek, Dek, EncPublicKey, EncSecretKey, SigningKey, WrappedDek,
};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::structs::{Genesis, Grant, Manifest, Stream};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileType, Id, RecipientType, StreamType, Suite, Timestamp,
};
use maxsecu_encoding::RECOVERY_ID;

use crate::error::UploadError;
use crate::identity::Identity;

/// First-version number (DESIGN §12.2 step 2 — `version = 1`, monotonic-by-1).
const FIRST_VERSION: u64 = 1;

/// Accepted chunk-framing size range (parameters §1.2 / DESIGN §12.10).
const CHUNK_SIZE_MIN: u32 = 4 * 1024;
const CHUNK_SIZE_MAX: u32 = 8 * 1024 * 1024;

/// Plaintext per-stream inputs. `content` is mandatory (the manifest requires a
/// `content` stream, DESIGN §12.3); `metadata`/`thumbnail`/`preview` are present
/// per `file_type` (a blog is typically content+metadata; media adds the rest).
/// The struct shape structurally guarantees the at-most-one-per-`stream_type`,
/// ascending ordering the manifest demands (encoding-spec V-13).
pub struct PlaintextStreams {
    pub content: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
    pub thumbnail: Option<Vec<u8>>,
    pub preview: Option<Vec<u8>>,
}

/// Parameters identifying the owner, the file, and the framing for an upload.
pub struct UploadParams<'a> {
    /// The owner's unlocked identity — signs `genesis`, `manifest`, and grants,
    /// and is the sole writer (owner-only, D29) and a wrap recipient (self).
    pub owner: &'a Identity,
    /// The owner's server-assigned `user_id` (the `author_id`/`owner_id`).
    pub owner_id: Id,
    /// The owner's `key_version` — selects the binding that verifies `genesis_sig`.
    pub owner_key_version: u64,
    /// Client-generated random `file_id` (DESIGN §12.2 step 2).
    pub file_id: Id,
    /// Authenticated listing key (D35).
    pub file_type: FileType,
    /// Per-stream chunk size; bound-checked to [4 KiB, 8 MiB].
    pub chunk_size: u32,
    /// The recovery recipient's directory-verified `enc_pub` (standing recipient).
    pub recovery_pub: EncPublicKey,
    /// Caller-supplied creation time (the core takes no clock dependency).
    pub created_at: Timestamp,
}

/// One sealed stream ready for upload: the manifest-committed metadata plus the
/// ciphertext chunks the client PUTs (api.md §9.1).
pub struct SealedStreamOut {
    pub stream_type: StreamType,
    pub compression: Compression,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub digest: [u8; 32],
    /// Total ciphertext bytes across all chunks (server `file_streams.total_bytes`).
    pub total_bytes: u64,
    pub chunks: Vec<Vec<u8>>,
}

/// One recipient's wrap plus its signed read-grant (api.md §8.1 `wraps[]`).
pub struct WrapOut {
    pub recipient_id: Id,
    pub recipient_type: RecipientType,
    pub wrapped_dek: WrappedDek,
    pub granted_by: Id,
    pub grant: Grant,
    pub grant_sig: [u8; 64],
}

/// The complete record set for `POST /v1/files` (api.md §8.1).
pub struct UploadBundle {
    pub file_id: Id,
    pub file_type: FileType,
    pub genesis: Genesis,
    pub genesis_sig: [u8; 64],
    pub manifest: Manifest,
    pub manifest_sig: [u8; 64],
    pub streams: Vec<SealedStreamOut>,
    pub wraps: Vec<WrapOut>,
}

/// Build the complete signed, encrypted upload for version 1 of a new file
/// (DESIGN §12.2). Wraps to **self + recovery**; owner-only write (D29).
///
/// Phase 3 leaves every stream uncompressed (`Compression::None`); selective
/// compression (D32) is a later increment.
pub fn build_upload(
    params: &UploadParams,
    streams: &PlaintextStreams,
) -> Result<UploadBundle, UploadError> {
    if params.chunk_size < CHUNK_SIZE_MIN || params.chunk_size > CHUNK_SIZE_MAX {
        return Err(UploadError::ChunkSizeOutOfRange {
            chunk_size: params.chunk_size,
        });
    }

    // One fresh DEK per file; only ever a KDF root (L-5).
    let dek = Dek::generate();
    let dek_commit = dek.commit();
    let frame = params.chunk_size as usize;

    // Seal each present stream under its own subkey, in ascending `stream_type`
    // order (content < metadata < thumbnail < preview) — the manifest's required
    // ordering (encoding-spec V-13) holds by construction.
    let mut inputs: Vec<(StreamType, &[u8])> = vec![(StreamType::Content, &streams.content)];
    if let Some(m) = &streams.metadata {
        inputs.push((StreamType::Metadata, m));
    }
    if let Some(t) = &streams.thumbnail {
        inputs.push((StreamType::Thumbnail, t));
    }
    if let Some(p) = &streams.preview {
        inputs.push((StreamType::Preview, p));
    }

    let mut manifest_streams: Vec<Stream> = Vec::with_capacity(inputs.len());
    let mut sealed_out: Vec<SealedStreamOut> = Vec::with_capacity(inputs.len());
    for (st, plaintext) in inputs {
        let ck = dek.stream_subkey(st);
        let sealed = seal_stream(&ck, params.file_id, FIRST_VERSION, st, frame, plaintext);
        let total_bytes = sealed.chunks.iter().map(|c| c.len() as u64).sum();
        // Phase 3: every stream uncompressed (selective compression is later).
        manifest_streams.push(Stream {
            stream_type: st,
            compression: Compression::None,
            chunk_count: sealed.chunk_count,
            digest: Bytes32(sealed.digest),
        });
        sealed_out.push(SealedStreamOut {
            stream_type: st,
            compression: Compression::None,
            chunk_size: params.chunk_size,
            chunk_count: sealed.chunk_count,
            digest: sealed.digest,
            total_bytes,
            chunks: sealed.chunks,
        });
    }

    let signer = params.owner.signing_key();

    let manifest = Manifest {
        file_id: params.file_id,
        version: FIRST_VERSION,
        file_type: params.file_type,
        alg: Suite::V1,
        chunk_size: params.chunk_size,
        dek_commit: Bytes32(dek_commit),
        streams: manifest_streams,
        recovery_present: true,
        author_id: params.owner_id,
        created_at: params.created_at,
    };
    let manifest_sig = signer.sign_canonical(labels::MANIFEST, &manifest);

    let genesis = Genesis {
        file_id: params.file_id,
        owner_id: params.owner_id,
        owner_key_version: params.owner_key_version,
        created_at: params.created_at,
    };
    let genesis_sig = signer.sign_canonical(labels::GENESIS, &genesis);

    // Wrap to self (we hold the secret, so self-check the wrap) and to the
    // standing recovery recipient. Owner-only write ⇒ no other recipients (D29).
    let owner_enc_pub = EncPublicKey::from_bytes(params.owner.enc_pub_bytes());
    let wraps = vec![
        build_wrap(
            params,
            &dek,
            dek_commit,
            params.owner_id,
            RecipientType::User,
            &owner_enc_pub,
            Some(params.owner.enc_secret()),
            signer,
        )?,
        build_wrap(
            params,
            &dek,
            dek_commit,
            RECOVERY_ID,
            RecipientType::Recovery,
            &params.recovery_pub,
            None,
            signer,
        )?,
    ];

    Ok(UploadBundle {
        file_id: params.file_id,
        file_type: params.file_type,
        genesis,
        genesis_sig,
        manifest,
        manifest_sig,
        streams: sealed_out,
        wraps,
    })
}

/// Wrap the DEK to one recipient and sign its author read-grant. When the
/// caller holds the recipient's secret (the self wrap), the wrap is re-opened
/// and checked against `dek_commit` — the pre-upload self-check (§12.2 step 7).
#[allow(clippy::too_many_arguments)]
fn build_wrap(
    params: &UploadParams,
    dek: &Dek,
    dek_commit: [u8; 32],
    recipient_id: Id,
    recipient_type: RecipientType,
    recipient_pub: &EncPublicKey,
    self_secret: Option<&EncSecretKey>,
    signer: &SigningKey,
) -> Result<WrapOut, UploadError> {
    let ctx = WrapContext {
        file_id: params.file_id,
        version: FIRST_VERSION,
        recipient_id,
    };
    let wrapped_dek = wrap_dek(recipient_pub, dek, &ctx)?;
    if let Some(sk) = self_secret {
        let reopened = unwrap_dek(sk, &wrapped_dek, &ctx)?;
        if reopened.commit() != dek_commit {
            return Err(UploadError::WrapSelfCheckFailed);
        }
    }
    let grant = Grant {
        file_id: params.file_id,
        file_version: FIRST_VERSION,
        recipient_id,
        recipient_type,
        dek_commit: Bytes32(dek_commit),
        granted_by: params.owner_id,
        created_at: params.created_at,
    };
    let grant_sig = signer.sign_canonical(labels::GRANT, &grant);
    Ok(WrapOut {
        recipient_id,
        recipient_type,
        wrapped_dek,
        granted_by: params.owner_id,
        grant,
        grant_sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::{generate_enc_keypair, open_stream};
    use maxsecu_encoding::{decode, encode};

    fn params<'a>(owner: &'a Identity, recovery_pub: EncPublicKey) -> UploadParams<'a> {
        UploadParams {
            owner,
            owner_id: Id([0x11; 16]),
            owner_key_version: 1,
            file_id: Id([0xF1; 16]),
            file_type: FileType::Blog,
            chunk_size: 4096,
            recovery_pub,
            created_at: Timestamp(1_719_500_000_000),
        }
    }

    fn streams() -> PlaintextStreams {
        PlaintextStreams {
            content: b"hello world, this is the content stream".to_vec(),
            metadata: Some(b"title=greeting".to_vec()),
            thumbnail: None,
            preview: None,
        }
    }

    #[test]
    fn manifest_is_signed_and_well_formed() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let b = build_upload(&p, &streams()).expect("upload builds");

        assert_eq!(b.manifest.version, 1);
        assert_eq!(b.manifest.file_id, p.file_id);
        assert_eq!(b.manifest.file_type, FileType::Blog);
        assert_eq!(b.manifest.author_id, p.owner_id);
        assert!(b.manifest.recovery_present, "recovery_present must be true");
        assert!(matches!(b.manifest.alg, Suite::V1));

        // Streams ascending and unique by type: content then metadata.
        let types: Vec<u8> = b.manifest.streams.iter().map(|s| s.stream_type as u8).collect();
        assert_eq!(types, vec![StreamType::Content as u8, StreamType::Metadata as u8]);

        // manifest_sig verifies under the owner's signing key.
        owner
            .verifying_key()
            .verify_canonical(labels::MANIFEST, &b.manifest, &b.manifest_sig)
            .expect("manifest signature verifies");

        // The manifest decodes canonically (round-trips through the strict codec).
        assert_eq!(decode::<Manifest>(&encode(&b.manifest)).unwrap(), b.manifest);
    }

    #[test]
    fn genesis_is_signed_and_binds_owner() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let b = build_upload(&p, &streams()).expect("upload builds");

        assert_eq!(b.genesis.file_id, p.file_id);
        assert_eq!(b.genesis.owner_id, p.owner_id);
        assert_eq!(b.genesis.owner_key_version, p.owner_key_version);
        owner
            .verifying_key()
            .verify_canonical(labels::GENESIS, &b.genesis, &b.genesis_sig)
            .expect("genesis signature verifies");
    }

    #[test]
    fn self_wrap_opens_to_committed_dek_and_content_decrypts() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let s = streams();
        let b = build_upload(&p, &s).expect("upload builds");

        let w = b
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("a self wrap exists");

        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };
        let dek = unwrap_dek(owner.enc_secret(), &w.wrapped_dek, &ctx).expect("self wrap opens");
        assert_eq!(dek.commit(), b.manifest.dek_commit.0, "DEK matches commitment");

        // The content stream decrypts to the original plaintext.
        let content = b
            .streams
            .iter()
            .find(|st| st.stream_type == StreamType::Content)
            .unwrap();
        let ck = dek.stream_subkey(StreamType::Content);
        let pt = open_stream(&ck, p.file_id, 1, StreamType::Content, &content.chunks)
            .expect("content decrypts");
        assert_eq!(pt, s.content);
    }

    #[test]
    fn recovery_wrap_opens_to_committed_dek() {
        let owner = Identity::generate();
        let (rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let b = build_upload(&p, &streams()).expect("upload builds");

        let w = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .expect("a recovery wrap exists");
        assert_eq!(w.recipient_id, RECOVERY_ID, "recovery wrap uses RECOVERY_ID");

        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: RECOVERY_ID,
        };
        let dek = unwrap_dek(&rsk, &w.wrapped_dek, &ctx).expect("recovery wrap opens");
        assert_eq!(dek.commit(), b.manifest.dek_commit.0);
    }

    #[test]
    fn every_grant_is_signed_chains_to_owner_and_commits_to_dek() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let b = build_upload(&p, &streams()).expect("upload builds");

        assert_eq!(b.wraps.len(), 2, "exactly self + recovery in Phase 3");
        for w in &b.wraps {
            assert_eq!(w.granted_by, p.owner_id, "author-rooted grant");
            assert_eq!(w.grant.granted_by, p.owner_id);
            assert_eq!(w.grant.file_id, p.file_id);
            assert_eq!(w.grant.file_version, 1);
            assert_eq!(w.grant.recipient_id, w.recipient_id);
            assert_eq!(w.grant.recipient_type, w.recipient_type);
            assert_eq!(
                w.grant.dek_commit, b.manifest.dek_commit,
                "grant commits to the manifest DEK"
            );
            owner
                .verifying_key()
                .verify_canonical(labels::GRANT, &w.grant, &w.grant_sig)
                .expect("grant signature verifies");
        }
    }

    #[test]
    fn per_stream_digest_matches_sealed_chunks() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk);
        let b = build_upload(&p, &streams()).expect("upload builds");

        for sealed in &b.streams {
            let m = b
                .manifest
                .streams
                .iter()
                .find(|s| s.stream_type == sealed.stream_type)
                .expect("each sealed stream is in the manifest");
            assert_eq!(m.digest, Bytes32(sealed.digest), "manifest digest binds the stream");
            assert_eq!(m.chunk_count, sealed.chunk_count);
            assert_eq!(m.compression, Compression::None);
        }
    }

    #[test]
    fn chunk_size_below_floor_is_rejected() {
        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let mut p = params(&owner, rpk);
        p.chunk_size = 1024; // below 4 KiB
        let err = build_upload(&p, &streams()).err().expect("rejected");
        assert_eq!(err, UploadError::ChunkSizeOutOfRange { chunk_size: 1024 });
    }
}
