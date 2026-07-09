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
    deserialize_hybrid_wrap, seal_stream, seal_stream_streaming, serialize_hybrid_wrap, unwrap_dek,
    unwrap_dek_hybrid, wrap_dek, wrap_dek_hybrid, CryptoError, Dek, EncPublicKey, EncSecretKey,
    HybridEncPublicKey, HybridEncSecretKey, HybridWrappedDek, SigningKey, WrappedDek,
};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::structs::{ChunkAad, Genesis, Grant, Manifest, Stream};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileType, Id, RecipientType, StreamType, Suite, Timestamp,
};
use maxsecu_encoding::RECOVERY_ID;

use crate::error::UploadError;
use crate::identity::Identity;

use crate::limits::{CHUNK_SIZE_MAX, CHUNK_SIZE_MIN};

/// First-version number (DESIGN §12.2 step 2 — `version = 1`, monotonic-by-1).
const FIRST_VERSION: u64 = 1;

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
    /// The recovery recipient's directory-verified ML-KEM-768 encapsulation key
    /// (the PQ leg of its hybrid wrap), or `None` for a classical recovery key.
    /// Suite::V2 requires BOTH the uploader and the recovery recipient to be
    /// PQ-enrolled (recovery is mandatory, DESIGN §6.3); otherwise the upload
    /// falls back to Suite::V1 so a partially-enrolled fleet still uploads (P7.5).
    pub recovery_mlkem_pub: Option<[u8; 1184]>,
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

/// The non-content streams for a streaming-path upload (metadata, thumbnail,
/// preview). The content ciphertext is produced externally by
/// [`ContentStreamSealer`] and committed via `(content_digest,
/// content_chunk_count)` — it never enters the records builder.
pub struct SmallStreams {
    pub metadata: Option<Vec<u8>>,
    pub thumbnail: Option<Vec<u8>>,
    pub preview: Option<Vec<u8>>,
}

/// Holds the per-stream content subkey derived from a `Dek` and delegates to
/// [`seal_stream_streaming`] so client-app can stream-seal content from disk
/// chunk-by-chunk without the DEK or its subkey ever crossing the crate boundary
/// — the caller only receives ciphertext via the `emit` callback.
///
/// The raw `Dek` is **not** stored; only the `Zeroizing<[u8;32]>` subkey is
/// retained, and no getter exposes it.
pub struct ContentStreamSealer {
    subkey: zeroize::Zeroizing<[u8; 32]>,
    file_id: Id,
    version: u64,
    stream_type: StreamType,
    chunk_size: usize,
}

impl ContentStreamSealer {
    /// Derive and hold the per-stream subkey for `stream_type` from `dek`.
    /// The `Dek` is consumed by reference; only the subkey is stored.
    pub fn new(
        dek: &Dek,
        file_id: Id,
        version: u64,
        stream_type: StreamType,
        chunk_size: usize,
    ) -> Self {
        Self {
            subkey: dek.stream_subkey(stream_type),
            file_id,
            version,
            stream_type,
            chunk_size,
        }
    }

    /// Seal bytes from `reader` chunk-at-a-time, calling `emit(index, &ciphertext)`
    /// per chunk (O(one chunk) RAM). Returns `(chunk_count, digest)` byte-identical
    /// to `seal_stream` for the same input. Pure delegation to `seal_stream_streaming`.
    pub fn seal_from_reader<R, E>(
        &self,
        reader: &mut R,
        emit: E,
    ) -> Result<(u64, [u8; 32]), CryptoError>
    where
        R: std::io::Read,
        E: FnMut(u64, &[u8]) -> Result<(), CryptoError>,
    {
        seal_stream_streaming(
            &self.subkey,
            self.file_id,
            self.version,
            self.stream_type,
            self.chunk_size,
            reader,
            emit,
        )
    }

    /// Seal ONE content chunk at `index` (random access), for the streaming confirm/
    /// resume pass where the total `chunk_count` is already known so the caller supplies
    /// `is_last = (index == chunk_count - 1)`. Produces BYTE-IDENTICAL ciphertext to
    /// `seal_from_reader` / `seal_stream` for the same index. Does NOT touch the digest
    /// (already committed in the manifest from the pass-1 `seal_from_reader`).
    pub fn seal_chunk(&self, index: u64, plaintext: &[u8], is_last: bool) -> Vec<u8> {
        let aad = ChunkAad {
            file_id: self.file_id,
            version: self.version,
            stream_type: self.stream_type,
            chunk_index: index,
            is_last,
        };
        maxsecu_crypto::seal_chunk(&self.subkey, &aad, plaintext)
    }
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

/// The signed manifest/genesis/wraps plus the SMALL sealed streams (no content
/// chunks). Used by the streaming-path upload: the caller streams content
/// separately via [`ContentStreamSealer`] then calls [`build_records_inner`] /
/// [`StreamingUploadBuilder::finish`] to assemble this set.
pub struct UploadRecords {
    pub file_id: Id,
    pub file_type: FileType,
    pub genesis: Genesis,
    pub genesis_sig: [u8; 64],
    pub manifest: Manifest,
    pub manifest_sig: [u8; 64],
    pub wraps: Vec<WrapOut>,
    pub small_streams: Vec<SealedStreamOut>,
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
    build_upload_inner(&Dek::generate(), params, streams)
}

/// Inner sealing loop shared by [`seal_streams`] and [`build_records_inner`].
/// Seals each `(StreamType, &[u8])` pair under its own DEK subkey in the order
/// supplied (callers must maintain ascending `stream_type` order themselves).
fn seal_inputs(
    dek: &Dek,
    file_id: Id,
    version: u64,
    chunk_size: u32,
    inputs: &[(StreamType, &[u8])],
) -> (Vec<Stream>, Vec<SealedStreamOut>) {
    let frame = chunk_size as usize;
    let mut manifest_streams: Vec<Stream> = Vec::with_capacity(inputs.len());
    let mut sealed_out: Vec<SealedStreamOut> = Vec::with_capacity(inputs.len());
    for &(st, plaintext) in inputs {
        let ck = dek.stream_subkey(st);
        let sealed = seal_stream(&ck, file_id, version, st, frame, plaintext);
        let total_bytes = sealed.chunks.iter().map(|c| c.len() as u64).sum();
        manifest_streams.push(Stream {
            stream_type: st,
            compression: Compression::None,
            chunk_count: sealed.chunk_count,
            digest: Bytes32(sealed.digest),
        });
        sealed_out.push(SealedStreamOut {
            stream_type: st,
            compression: Compression::None,
            chunk_size,
            chunk_count: sealed.chunk_count,
            digest: sealed.digest,
            total_bytes,
            chunks: sealed.chunks,
        });
    }
    (manifest_streams, sealed_out)
}

/// Seal each present plaintext stream under its own DEK subkey, in ascending
/// `stream_type` order (content < metadata < thumbnail < preview) — the
/// manifest's required ordering (encoding-spec V-13) holds by construction.
/// Phase 3 leaves every stream uncompressed (`Compression::None`). Shared by
/// [`build_upload`] (version 1) and rotation (a new version under a fresh DEK).
pub(crate) fn seal_streams(
    dek: &Dek,
    file_id: Id,
    version: u64,
    chunk_size: u32,
    streams: &PlaintextStreams,
) -> (Vec<Stream>, Vec<SealedStreamOut>) {
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
    seal_inputs(dek, file_id, version, chunk_size, &inputs)
}

/// Wrap the DEK to one recipient and sign its read-grant rooted at `granted_by`
/// for `(file_id, version)`. When the caller holds the recipient's secret (the
/// self wrap), the wrap is re-opened and checked against `dek_commit` — the
/// pre-upload self-check (§12.2 step 7). Shared by upload and rotation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn wrap_and_grant(
    signer: &SigningKey,
    file_id: Id,
    version: u64,
    recipient_id: Id,
    recipient_type: RecipientType,
    recipient_pub: &EncPublicKey,
    dek: &Dek,
    dek_commit: [u8; 32],
    granted_by: Id,
    created_at: Timestamp,
    self_secret: Option<&EncSecretKey>,
) -> Result<WrapOut, UploadError> {
    let ctx = WrapContext {
        file_id,
        version,
        recipient_id,
    };
    let wrapped_dek = wrap_dek(recipient_pub, dek, &ctx)?;
    if let Some(sk) = self_secret {
        let reopened = unwrap_dek(sk, &wrapped_dek, &ctx)?;
        if reopened.commit() != dek_commit {
            return Err(UploadError::WrapSelfCheckFailed);
        }
    }
    let (grant, grant_sig) = build_grant(
        signer,
        file_id,
        version,
        recipient_id,
        recipient_type,
        dek_commit,
        granted_by,
        created_at,
    );
    Ok(WrapOut {
        recipient_id,
        recipient_type,
        wrapped_dek,
        granted_by,
        grant,
        grant_sig,
    })
}

/// Wrap the DEK to one recipient under the **Suite::V2 hybrid** KEM (X25519 +
/// ML-KEM-768) and sign its read-grant, mirroring [`wrap_and_grant`] but for the
/// PQ wire layout (P7.5). The grant is identical to the V1 path — it binds
/// `dek_commit`, not the wrap layout. The hybrid wrap is stored in the
/// [`WrappedDek`] byte-carrier (`enc ‖ ct` == `serialize_hybrid_wrap`, see
/// [`pack_hybrid_wrap`]). When the caller holds the recipient's hybrid secret
/// (the self wrap), the wrap is re-opened and checked against `dek_commit`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn wrap_and_grant_hybrid(
    signer: &SigningKey,
    file_id: Id,
    version: u64,
    recipient_id: Id,
    recipient_type: RecipientType,
    recipient_pub: &HybridEncPublicKey,
    dek: &Dek,
    dek_commit: [u8; 32],
    granted_by: Id,
    created_at: Timestamp,
    self_secret: Option<&HybridEncSecretKey>,
) -> Result<WrapOut, UploadError> {
    let ctx = WrapContext {
        file_id,
        version,
        recipient_id,
    };
    let hybrid = wrap_dek_hybrid(recipient_pub, dek, &ctx)?;
    if let Some(sk) = self_secret {
        let reopened = unwrap_dek_hybrid(sk, &hybrid, &ctx)?;
        if reopened.commit() != dek_commit {
            return Err(UploadError::WrapSelfCheckFailed);
        }
    }
    let wrapped_dek = pack_hybrid_wrap(&hybrid);
    let (grant, grant_sig) = build_grant(
        signer,
        file_id,
        version,
        recipient_id,
        recipient_type,
        dek_commit,
        granted_by,
        created_at,
    );
    Ok(WrapOut {
        recipient_id,
        recipient_type,
        wrapped_dek,
        granted_by,
        grant,
        grant_sig,
    })
}

/// Build and sign a possession-entailing read-grant for `(file_id, version,
/// recipient)` rooted at `granted_by`. Shared by the V1 and V2 wrap paths — the
/// grant binds `dek_commit`, never the wrap wire layout (P7.5), so it is suite-
/// independent.
#[allow(clippy::too_many_arguments)]
fn build_grant(
    signer: &SigningKey,
    file_id: Id,
    version: u64,
    recipient_id: Id,
    recipient_type: RecipientType,
    dek_commit: [u8; 32],
    granted_by: Id,
    created_at: Timestamp,
) -> (Grant, [u8; 64]) {
    let grant = Grant {
        file_id,
        file_version: version,
        recipient_id,
        recipient_type,
        dek_commit: Bytes32(dek_commit),
        granted_by,
        created_at,
    };
    let grant_sig = signer.sign_canonical(labels::GRANT, &grant);
    (grant, grant_sig)
}

/// Pack a Suite::V2 hybrid wrap into the [`WrappedDek`] byte-carrier. The stored
/// wire form is exactly `serialize_hybrid_wrap` = `eph_x_pub(32) ‖ ct_pq(1088) ‖
/// aead_ct(48)` (1168 bytes), split so `enc` = the 32-byte X25519 ephemeral and
/// `ct` = `ct_pq ‖ aead_ct`. The server stores these opaque bytes (`enc ‖ ct`)
/// identically to a V1 wrap; the layout is selected on read by `manifest.alg`.
pub(crate) fn pack_hybrid_wrap(h: &HybridWrappedDek) -> WrappedDek {
    let bytes = serialize_hybrid_wrap(h);
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&bytes[..32]);
    WrappedDek {
        enc,
        ct: bytes[32..].to_vec(),
    }
}

/// Reconstruct a Suite::V2 hybrid wrap from the [`WrappedDek`] byte-carrier (the
/// inverse of [`pack_hybrid_wrap`]). Fail-closed on a malformed length — the
/// stored `enc ‖ ct` must be the exact 1168-byte hybrid wire form.
pub(crate) fn unpack_hybrid_wrap(w: &WrappedDek) -> Result<HybridWrappedDek, CryptoError> {
    let mut bytes = Vec::with_capacity(32 + w.ct.len());
    bytes.extend_from_slice(&w.enc);
    bytes.extend_from_slice(&w.ct);
    deserialize_hybrid_wrap(&bytes)
}

/// Output of [`assemble_records`]: the manifest and its signature, the genesis
/// and its signature, and the per-recipient wraps (in that order).
type AssembledRecords = (Manifest, [u8; 64], Genesis, [u8; 64], Vec<WrapOut>);

/// Shared manifest+genesis+wraps assembly used by both [`build_upload_inner`]
/// and [`build_records_inner`]. Takes `manifest_streams` already in ascending
/// order (caller's responsibility) and the pre-computed `dek_commit`. Applies
/// the V1/V2 suite-selection policy (P7.5) and the self-check on the owner wrap.
fn assemble_records(
    dek: &Dek,
    dek_commit: [u8; 32],
    params: &UploadParams,
    manifest_streams: Vec<Stream>,
) -> Result<AssembledRecords, UploadError> {
    let signer = params.owner.signing_key();

    // Suite-selection policy (P7.5): V2 iff BOTH the uploader AND the recovery
    // recipient are PQ-enrolled; otherwise V1 (partially-enrolled fleet fallback).
    let pq = params
        .owner
        .mlkem_pub_bytes()
        .zip(params.recovery_mlkem_pub);
    let suite = if pq.is_some() { Suite::V2 } else { Suite::V1 };

    let manifest = Manifest {
        file_id: params.file_id,
        version: FIRST_VERSION,
        file_type: params.file_type,
        alg: suite,
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

    // Wrap to self (self-check) and to the standing recovery recipient.
    // Owner-only write ⇒ no other recipients (D29).
    let wraps = match pq {
        Some((owner_mlkem, recovery_mlkem)) => {
            // Suite::V2 — hybrid wraps to {x25519, ML-KEM} recipients.
            let owner_hybrid_pub = HybridEncPublicKey {
                x25519: params.owner.enc_pub_bytes(),
                mlkem: owner_mlkem,
            };
            let owner_hybrid_sec = HybridEncSecretKey::from_components(
                params.owner.enc_secret().expose_bytes(),
                params
                    .owner
                    .mlkem_seed()
                    .expect("owner ML-KEM pub implies its seed"),
            );
            let recovery_hybrid_pub = HybridEncPublicKey {
                x25519: params.recovery_pub.to_bytes(),
                mlkem: recovery_mlkem,
            };
            vec![
                wrap_and_grant_hybrid(
                    signer,
                    params.file_id,
                    FIRST_VERSION,
                    params.owner_id,
                    RecipientType::User,
                    &owner_hybrid_pub,
                    dek,
                    dek_commit,
                    params.owner_id,
                    params.created_at,
                    Some(&owner_hybrid_sec),
                )?,
                wrap_and_grant_hybrid(
                    signer,
                    params.file_id,
                    FIRST_VERSION,
                    RECOVERY_ID,
                    RecipientType::Recovery,
                    &recovery_hybrid_pub,
                    dek,
                    dek_commit,
                    params.owner_id,
                    params.created_at,
                    None,
                )?,
            ]
        }
        None => {
            // Suite::V1 — classical HPKE wraps (behavior unchanged from Phase 3).
            let owner_enc_pub = EncPublicKey::from_bytes(params.owner.enc_pub_bytes());
            vec![
                wrap_and_grant(
                    signer,
                    params.file_id,
                    FIRST_VERSION,
                    params.owner_id,
                    RecipientType::User,
                    &owner_enc_pub,
                    dek,
                    dek_commit,
                    params.owner_id,
                    params.created_at,
                    Some(params.owner.enc_secret()),
                )?,
                wrap_and_grant(
                    signer,
                    params.file_id,
                    FIRST_VERSION,
                    RECOVERY_ID,
                    RecipientType::Recovery,
                    &params.recovery_pub,
                    dek,
                    dek_commit,
                    params.owner_id,
                    params.created_at,
                    None,
                )?,
            ]
        }
    };

    Ok((manifest, manifest_sig, genesis, genesis_sig, wraps))
}

/// Build a complete [`UploadBundle`] from a caller-supplied DEK (which may be
/// freshly generated or recovered for a resume). Shared by [`build_upload`]
/// and the test-only streaming-path comparator.
pub(crate) fn build_upload_inner(
    dek: &Dek,
    params: &UploadParams,
    streams: &PlaintextStreams,
) -> Result<UploadBundle, UploadError> {
    if params.chunk_size < CHUNK_SIZE_MIN || params.chunk_size > CHUNK_SIZE_MAX {
        return Err(UploadError::ChunkSizeOutOfRange {
            chunk_size: params.chunk_size,
        });
    }
    let dek_commit = dek.commit();
    let (manifest_streams, sealed_out) = seal_streams(
        dek,
        params.file_id,
        FIRST_VERSION,
        params.chunk_size,
        streams,
    );
    let (manifest, manifest_sig, genesis, genesis_sig, wraps) =
        assemble_records(dek, dek_commit, params, manifest_streams)?;
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

/// Build the signed manifest/genesis/wraps and seal the SMALL (non-content)
/// streams from a caller-supplied DEK, using a pre-computed `content_digest`
/// and `content_chunk_count` from the streaming content sealer. The content
/// `Stream` is prepended so the manifest's ascending order holds.
pub(crate) fn build_records_inner(
    dek: &Dek,
    params: &UploadParams,
    small: &SmallStreams,
    content_digest: [u8; 32],
    content_chunk_count: u64,
) -> Result<UploadRecords, UploadError> {
    if params.chunk_size < CHUNK_SIZE_MIN || params.chunk_size > CHUNK_SIZE_MAX {
        return Err(UploadError::ChunkSizeOutOfRange {
            chunk_size: params.chunk_size,
        });
    }
    let dek_commit = dek.commit();

    // Seal the small (non-content) streams.
    let mut small_inputs: Vec<(StreamType, &[u8])> = Vec::new();
    if let Some(m) = &small.metadata {
        small_inputs.push((StreamType::Metadata, m));
    }
    if let Some(t) = &small.thumbnail {
        small_inputs.push((StreamType::Thumbnail, t));
    }
    if let Some(p) = &small.preview {
        small_inputs.push((StreamType::Preview, p));
    }
    let (small_manifest, small_sealed) = seal_inputs(
        dek,
        params.file_id,
        FIRST_VERSION,
        params.chunk_size,
        &small_inputs,
    );

    // Content sorts lowest (encoding-spec V-13); prepend it then extend.
    let mut manifest_streams = vec![Stream {
        stream_type: StreamType::Content,
        compression: Compression::None,
        chunk_count: content_chunk_count,
        digest: Bytes32(content_digest),
    }];
    manifest_streams.extend(small_manifest);

    let (manifest, manifest_sig, genesis, genesis_sig, wraps) =
        assemble_records(dek, dek_commit, params, manifest_streams)?;
    Ok(UploadRecords {
        file_id: params.file_id,
        file_type: params.file_type,
        genesis,
        genesis_sig,
        manifest,
        manifest_sig,
        wraps,
        small_streams: small_sealed,
    })
}

/// Drives the streaming-path upload. The caller generates a builder, streams
/// content through [`content_sealer`][StreamingUploadBuilder::content_sealer],
/// then calls [`finish`][StreamingUploadBuilder::finish] with the content digest
/// and the small streams to assemble the complete [`UploadRecords`]. The DEK is
/// owned privately and never exposed outside this crate.
pub struct StreamingUploadBuilder {
    dek: Dek,
}

impl StreamingUploadBuilder {
    /// Generate a fresh DEK for this upload.
    pub fn new() -> Self {
        Self {
            dek: Dek::generate(),
        }
    }

    /// Derive a [`ContentStreamSealer`] for the content stream. The sealer holds
    /// only the content subkey — the raw DEK never leaves this builder.
    pub fn content_sealer(&self, params: &UploadParams) -> ContentStreamSealer {
        ContentStreamSealer::new(
            &self.dek,
            params.file_id,
            FIRST_VERSION,
            StreamType::Content,
            params.chunk_size as usize,
        )
    }

    /// Consume the builder and assemble the [`UploadRecords`] from the small
    /// streams and the content digest/chunk-count reported by the sealer.
    pub fn finish(
        self,
        params: &UploadParams,
        small: &SmallStreams,
        content_digest: [u8; 32],
        content_chunk_count: u64,
    ) -> Result<UploadRecords, UploadError> {
        build_records_inner(
            &self.dek,
            params,
            small,
            content_digest,
            content_chunk_count,
        )
    }
}

impl Default for StreamingUploadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Recover the DEK from a classical (Suite::V1) self-wrap for a resumable
/// upload. The DEK stays in-crate; only the returned `Dek` is held by the
/// caller (who must immediately derive a subkey and let the `Dek` drop).
pub(crate) fn recover_dek(
    self_secret: &EncSecretKey,
    wrapped_dek: &WrappedDek,
    ctx: &WrapContext,
) -> Result<Dek, CryptoError> {
    unwrap_dek(self_secret, wrapped_dek, ctx)
}

/// Recover the DEK from a hybrid (Suite::V2) self-wrap for a resumable upload.
pub(crate) fn recover_dek_hybrid(
    self_secret: &HybridEncSecretKey,
    wrapped_dek: &WrappedDek,
    ctx: &WrapContext,
) -> Result<Dek, CryptoError> {
    let h = unpack_hybrid_wrap(wrapped_dek)?;
    unwrap_dek_hybrid(self_secret, &h, ctx)
}

/// Recover a [`ContentStreamSealer`] from the owner's self-wrapped DEK for a
/// resumable content upload. The DEK is recovered, a content subkey is derived,
/// and the DEK is immediately dropped (zeroized). The returned sealer produces
/// byte-identical ciphertext to the original upload for the same
/// `file_id`/`version`/`chunk_size`.
pub fn resume_content_sealer(
    owner: &Identity,
    self_wrapped_dek: &WrappedDek,
    ctx: &WrapContext,
    suite: Suite,
    file_id: Id,
    version: u64,
    chunk_size: u32,
) -> Result<ContentStreamSealer, UploadError> {
    let dek = match suite {
        Suite::V1 => recover_dek(owner.enc_secret(), self_wrapped_dek, ctx)?,
        Suite::V2 => {
            let seed = owner
                .mlkem_seed()
                .ok_or(UploadError::Crypto(CryptoError::WrapOpen))?;
            let sk = HybridEncSecretKey::from_components(owner.enc_secret().expose_bytes(), seed);
            recover_dek_hybrid(&sk, self_wrapped_dek, ctx)?
        }
    };
    // `dek` drops (zeroized) after the subkey is derived inside `new`.
    Ok(ContentStreamSealer::new(
        &dek,
        file_id,
        version,
        StreamType::Content,
        chunk_size as usize,
    ))
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
            recovery_mlkem_pub: None,
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
        let types: Vec<u8> = b
            .manifest
            .streams
            .iter()
            .map(|s| s.stream_type as u8)
            .collect();
        assert_eq!(
            types,
            vec![StreamType::Content as u8, StreamType::Metadata as u8]
        );

        // manifest_sig verifies under the owner's signing key.
        owner
            .verifying_key()
            .verify_canonical(labels::MANIFEST, &b.manifest, &b.manifest_sig)
            .expect("manifest signature verifies");

        // The manifest decodes canonically (round-trips through the strict codec).
        assert_eq!(
            decode::<Manifest>(&encode(&b.manifest)).unwrap(),
            b.manifest
        );
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
        assert_eq!(
            dek.commit(),
            b.manifest.dek_commit.0,
            "DEK matches commitment"
        );

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
        assert_eq!(
            w.recipient_id, RECOVERY_ID,
            "recovery wrap uses RECOVERY_ID"
        );

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
            assert_eq!(
                m.digest,
                Bytes32(sealed.digest),
                "manifest digest binds the stream"
            );
            assert_eq!(m.chunk_count, sealed.chunk_count);
            assert_eq!(m.compression, Compression::None);
        }
    }

    #[test]
    fn content_stream_sealer_matches_seal_stream() {
        use std::io::Cursor;

        let chunk_size = 4096usize;
        let file_id = Id([0x5A; 16]);
        let version = 1u64;
        let st = StreamType::Content;

        let lengths: &[usize] = &[1, 2 * chunk_size, 2 * chunk_size + 123, 0];
        for &len in lengths {
            let dek = Dek::generate();
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            // (a) expected — whole-buffer sealer via direct subkey derivation
            let ck = dek.stream_subkey(st);
            let expected = maxsecu_crypto::seal_stream(&ck, file_id, version, st, chunk_size, &pt);

            // (b) actual — via ContentStreamSealer
            let sealer = ContentStreamSealer::new(&dek, file_id, version, st, chunk_size);
            let mut got: Vec<Vec<u8>> = Vec::new();
            let (count, digest) = sealer
                .seal_from_reader(&mut Cursor::new(&pt), |_i, ct| {
                    got.push(ct.to_vec());
                    Ok(())
                })
                .expect("sealing succeeds");

            assert_eq!(got, expected.chunks, "chunks match for len={}", len);
            assert_eq!(
                count, expected.chunk_count,
                "chunk_count matches for len={}",
                len
            );
            assert_eq!(digest, expected.digest, "digest matches for len={}", len);
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

    /// Concatenate a wrap's byte-carrier back to its stored wire form
    /// (`enc ‖ ct`) — for a V2 wrap this is exactly `serialize_hybrid_wrap`.
    fn wrap_wire(w: &WrappedDek) -> Vec<u8> {
        let mut v = w.enc.to_vec();
        v.extend_from_slice(&w.ct);
        v
    }

    #[test]
    fn pq_upload_emits_v2_hybrid_wraps() {
        use maxsecu_crypto::generate_mlkem_keypair;
        // Both the uploader's identity and the recovery recipient are PQ-enrolled
        // ⇒ Suite::V2 hybrid wraps to self + recovery.
        let owner = Identity::generate();
        let (recovery_sk, recovery_pk) = generate_enc_keypair();
        let (recovery_seed, recovery_mlkem) = generate_mlkem_keypair();
        let mut p = params(&owner, recovery_pk);
        p.recovery_mlkem_pub = Some(recovery_mlkem);
        let b = build_upload(&p, &streams()).expect("v2 upload builds");

        assert!(matches!(b.manifest.alg, Suite::V2), "manifest.alg is V2");
        assert_eq!(b.wraps.len(), 2, "self + recovery");

        // The self wrap deserializes as the 1168-byte hybrid wire form and the
        // identity's reconstructed hybrid secret unwraps it to the committed DEK.
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("a self wrap");
        let self_wire = wrap_wire(&sw.wrapped_dek);
        assert_eq!(
            self_wire.len(),
            1168,
            "hybrid wrap is eph(32)+ct_pq(1088)+aead(48)"
        );
        let self_hybrid = deserialize_hybrid_wrap(&self_wire).expect("self wrap is hybrid wire");
        let owner_sec = HybridEncSecretKey::from_components(
            owner.enc_secret().expose_bytes(),
            owner.mlkem_seed().unwrap(),
        );
        let sctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };
        let dek = unwrap_dek_hybrid(&owner_sec, &self_hybrid, &sctx).expect("self hybrid opens");
        assert_eq!(
            dek.commit(),
            b.manifest.dek_commit.0,
            "self → committed DEK"
        );

        // The recovery wrap opens with a test recovery hybrid secret.
        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .expect("a recovery wrap");
        let rec_hybrid = deserialize_hybrid_wrap(&wrap_wire(&rw.wrapped_dek))
            .expect("recovery wrap is hybrid wire");
        let rec_sec =
            HybridEncSecretKey::from_components(recovery_sk.expose_bytes(), recovery_seed);
        let rctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: RECOVERY_ID,
        };
        let rdek = unwrap_dek_hybrid(&rec_sec, &rec_hybrid, &rctx).expect("recovery hybrid opens");
        assert_eq!(
            rdek.commit(),
            b.manifest.dek_commit.0,
            "recovery → committed DEK"
        );
    }

    #[test]
    fn non_pq_upload_stays_v1() {
        // Recovery lacks an ML-KEM key (owner is PQ-capable) ⇒ V1 fallback so a
        // partially-enrolled fleet still uploads. The classical path is unchanged.
        let owner = Identity::generate();
        let (_recovery_sk, recovery_pk) = generate_enc_keypair();
        let p = params(&owner, recovery_pk); // recovery_mlkem_pub == None
        let b = build_upload(&p, &streams()).expect("v1 upload builds");
        assert!(matches!(b.manifest.alg, Suite::V1), "recovery-missing ⇒ V1");
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .unwrap();
        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };
        let dek = unwrap_dek(owner.enc_secret(), &sw.wrapped_dek, &ctx).expect("v1 self opens");
        assert_eq!(dek.commit(), b.manifest.dek_commit.0);

        // Symmetric case: the uploader's identity lacks ML-KEM (a v1 blob) but the
        // recovery key is PQ ⇒ still V1 (V2 needs BOTH legs PQ).
        let (esk, epk, seed, _) = owner.secret_bytes();
        let v1_owner = Identity::from_secret_bytes(esk, epk, seed, None);
        assert!(v1_owner.mlkem_pub_bytes().is_none());
        let (_rsk, rpk) = generate_enc_keypair();
        let (_rseed, rmlkem) = maxsecu_crypto::generate_mlkem_keypair();
        let mut p2 = params(&v1_owner, rpk);
        p2.recovery_mlkem_pub = Some(rmlkem);
        let b2 = build_upload(&p2, &streams()).expect("v1 upload builds");
        assert!(
            matches!(b2.manifest.alg, Suite::V1),
            "identity-missing ⇒ V1"
        );
    }

    // ── Streaming-path tests ──────────────────────────────────────────────────

    /// The streaming path (build_records_inner + ContentStreamSealer) produces a
    /// byte-identical manifest/genesis/sigs to the monolithic path (build_upload_inner)
    /// when driven by the same DEK. The self-wrap opens to the committed DEK in
    /// both paths. The small sealed streams are byte-identical.
    #[test]
    fn streaming_records_match_monolithic_v1() {
        use std::io::Cursor;

        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        // V1: recovery_mlkem_pub = None ⇒ partially-enrolled fallback to V1.
        let p = params(&owner, rpk);

        let content: Vec<u8> = (0..(4096 * 2 + 123)).map(|i| (i % 251) as u8).collect();
        let meta: Option<Vec<u8>> = Some(b"title=x".to_vec());

        // ONE DEK drives both paths to ensure determinism.
        let dek = Dek::generate();

        // (a) monolithic path.
        let full_streams = PlaintextStreams {
            content: content.clone(),
            metadata: meta.clone(),
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload_inner(&dek, &p, &full_streams).expect("inner build");

        // (b) streaming path: seal content via ContentStreamSealer (discarding chunks),
        //     then build records from the digest + small streams.
        let sealer = ContentStreamSealer::new(
            &dek,
            p.file_id,
            FIRST_VERSION,
            StreamType::Content,
            p.chunk_size as usize,
        );
        let (count, digest) = sealer
            .seal_from_reader(&mut Cursor::new(&content), |_, _| Ok(()))
            .expect("sealing succeeds");
        let recs = build_records_inner(
            &dek,
            &p,
            &SmallStreams {
                metadata: meta.clone(),
                thumbnail: None,
                preview: None,
            },
            digest,
            count,
        )
        .expect("records build");

        // Manifests must be byte-identical (all fields deterministic for same DEK).
        assert_eq!(
            encode(&bundle.manifest),
            encode(&recs.manifest),
            "manifests are byte-identical"
        );
        assert_eq!(
            bundle.manifest_sig, recs.manifest_sig,
            "manifest sigs match"
        );
        assert_eq!(bundle.genesis, recs.genesis, "genesis matches");
        assert_eq!(bundle.genesis_sig, recs.genesis_sig, "genesis sigs match");

        // Wrap metadata matches; wrapped_dek bytes differ (HPKE randomizes the ephemeral).
        assert_eq!(bundle.wraps.len(), recs.wraps.len(), "wrap count matches");
        for (bw, rw) in bundle.wraps.iter().zip(recs.wraps.iter()) {
            assert_eq!(bw.recipient_id, rw.recipient_id, "recipient_id");
            assert_eq!(bw.recipient_type, rw.recipient_type, "recipient_type");
            assert_eq!(bw.granted_by, rw.granted_by, "granted_by");
            assert_eq!(bw.grant, rw.grant, "grant");
            assert_eq!(bw.grant_sig, rw.grant_sig, "grant_sig");
        }

        // Both self-wraps open to the committed DEK.
        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };
        let bundle_self = bundle
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("bundle self wrap");
        let recs_self = recs
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("recs self wrap");
        let dek_commit = bundle.manifest.dek_commit.0;
        assert_eq!(
            unwrap_dek(owner.enc_secret(), &bundle_self.wrapped_dek, &ctx)
                .expect("bundle self opens")
                .commit(),
            dek_commit,
            "bundle self-wrap → committed DEK"
        );
        assert_eq!(
            unwrap_dek(owner.enc_secret(), &recs_self.wrapped_dek, &ctx)
                .expect("recs self opens")
                .commit(),
            dek_commit,
            "recs self-wrap → committed DEK"
        );

        // Metadata sealed stream matches in both paths.
        let bundle_meta = bundle
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .expect("bundle has metadata stream");
        let recs_meta = recs
            .small_streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .expect("recs has metadata stream");
        assert_eq!(
            bundle_meta.chunk_count, recs_meta.chunk_count,
            "meta chunk_count"
        );
        assert_eq!(bundle_meta.digest, recs_meta.digest, "meta digest");
        assert_eq!(
            bundle_meta.total_bytes, recs_meta.total_bytes,
            "meta total_bytes"
        );
        assert_eq!(bundle_meta.chunks, recs_meta.chunks, "meta chunks");
    }

    /// Recovering the DEK from a V1 self-wrap via `recover_dek` and
    /// `resume_content_sealer` reproduces the original content ciphertext.
    #[test]
    fn recover_dek_v1_reproduces_content() {
        use std::io::Cursor;

        let owner = Identity::generate();
        let (_rsk, rpk) = generate_enc_keypair();
        let p = params(&owner, rpk); // V1

        let content: Vec<u8> = (0..4096 * 3).map(|i| (i % 127) as u8).collect();
        let full_streams = PlaintextStreams {
            content: content.clone(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let dek = Dek::generate();
        let bundle = build_upload_inner(&dek, &p, &full_streams).expect("inner build");

        let self_wrap = bundle
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("self wrap");
        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };

        // recover_dek opens to the committed DEK.
        let dek2 = recover_dek(owner.enc_secret(), &self_wrap.wrapped_dek, &ctx)
            .expect("recover_dek succeeds");
        assert_eq!(
            dek2.commit(),
            bundle.manifest.dek_commit.0,
            "recovered DEK matches commitment"
        );

        // Sealing with the recovered DEK reproduces the original ciphertext.
        let sealer2 = ContentStreamSealer::new(&dek2, p.file_id, 1, StreamType::Content, 4096);
        let mut got: Vec<Vec<u8>> = Vec::new();
        let (count2, digest2) = sealer2
            .seal_from_reader(&mut Cursor::new(&content), |_, ct| {
                got.push(ct.to_vec());
                Ok(())
            })
            .expect("re-seal succeeds");
        let orig_content = bundle
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .expect("original content stream");
        assert_eq!(got, orig_content.chunks, "recovered DEK chunks match");
        assert_eq!(count2, orig_content.chunk_count, "chunk count matches");
        assert_eq!(digest2, orig_content.digest, "digest matches");

        // resume_content_sealer produces the same ciphertext.
        let sealer3 = resume_content_sealer(
            &owner,
            &self_wrap.wrapped_dek,
            &ctx,
            Suite::V1,
            p.file_id,
            1,
            4096,
        )
        .expect("resume_content_sealer succeeds");
        let mut got3: Vec<Vec<u8>> = Vec::new();
        let (count3, digest3) = sealer3
            .seal_from_reader(&mut Cursor::new(&content), |_, ct| {
                got3.push(ct.to_vec());
                Ok(())
            })
            .expect("resume re-seal succeeds");
        assert_eq!(got3, orig_content.chunks, "resume sealer chunks match");
        assert_eq!(count3, orig_content.chunk_count);
        assert_eq!(digest3, orig_content.digest);
    }

    /// Recovering the DEK from a V2 hybrid self-wrap via `recover_dek_hybrid` and
    /// `resume_content_sealer` reproduces the original content ciphertext.
    #[test]
    fn recover_dek_v2_reproduces_content() {
        use maxsecu_crypto::generate_mlkem_keypair;
        use std::io::Cursor;

        // Both owner and recovery are PQ-enrolled ⇒ Suite::V2.
        let owner = Identity::generate();
        let (_recovery_sk, recovery_pk) = generate_enc_keypair();
        let (_recovery_seed, recovery_mlkem) = generate_mlkem_keypair();
        let mut p = params(&owner, recovery_pk);
        p.recovery_mlkem_pub = Some(recovery_mlkem);

        let content: Vec<u8> = (0..4096 * 2 + 7).map(|i| (i % 199) as u8).collect();
        let full_streams = PlaintextStreams {
            content: content.clone(),
            metadata: None,
            thumbnail: None,
            preview: None,
        };
        let dek = Dek::generate();
        let bundle = build_upload_inner(&dek, &p, &full_streams).expect("v2 inner build");
        assert!(
            matches!(bundle.manifest.alg, Suite::V2),
            "manifest.alg is V2"
        );

        let self_wrap = bundle
            .wraps
            .iter()
            .find(|w| w.recipient_id == p.owner_id && w.recipient_type == RecipientType::User)
            .expect("v2 self wrap");
        let ctx = WrapContext {
            file_id: p.file_id,
            version: 1,
            recipient_id: p.owner_id,
        };

        // recover_dek_hybrid directly: reconstruct the owner's hybrid secret.
        let owner_sec = HybridEncSecretKey::from_components(
            owner.enc_secret().expose_bytes(),
            owner.mlkem_seed().expect("owner is PQ"),
        );
        let dek2 = recover_dek_hybrid(&owner_sec, &self_wrap.wrapped_dek, &ctx)
            .expect("recover_dek_hybrid succeeds");
        assert_eq!(
            dek2.commit(),
            bundle.manifest.dek_commit.0,
            "hybrid-recovered DEK matches commitment"
        );

        // resume_content_sealer with Suite::V2 reproduces the original ciphertext.
        let sealer = resume_content_sealer(
            &owner,
            &self_wrap.wrapped_dek,
            &ctx,
            Suite::V2,
            p.file_id,
            1,
            4096,
        )
        .expect("v2 resume_content_sealer succeeds");
        let mut got: Vec<Vec<u8>> = Vec::new();
        let (count, digest) = sealer
            .seal_from_reader(&mut Cursor::new(&content), |_, ct| {
                got.push(ct.to_vec());
                Ok(())
            })
            .expect("v2 resume re-seal succeeds");
        let orig_content = bundle
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .expect("original v2 content stream");
        assert_eq!(got, orig_content.chunks, "v2 resume sealer chunks match");
        assert_eq!(count, orig_content.chunk_count);
        assert_eq!(digest, orig_content.digest);
    }

    /// `ContentStreamSealer::seal_chunk` produces BYTE-IDENTICAL ciphertext to
    /// `seal_from_reader` for every chunk index, including the short final chunk.
    #[test]
    fn seal_chunk_matches_seal_from_reader() {
        use std::io::Cursor;

        let chunk_size = 4096usize;
        let file_id = Id([0xCC; 16]);
        let version = 1u64;

        // 3 full chunks + a short tail (exercises is_last on a short final chunk).
        let pt_len = chunk_size * 3 + 100;
        let plaintext: Vec<u8> = (0..pt_len).map(|i| (i % 251) as u8).collect();

        let dek = Dek::generate();
        let sealer =
            ContentStreamSealer::new(&dek, file_id, version, StreamType::Content, chunk_size);

        // (a) reference — drive seal_from_reader and collect each emitted chunk.
        let mut reference: Vec<Vec<u8>> = Vec::new();
        let (count, _digest) = sealer
            .seal_from_reader(&mut Cursor::new(&plaintext), |_i, ct| {
                reference.push(ct.to_vec());
                Ok(())
            })
            .expect("seal_from_reader succeeds");

        // (b) random-access — split the plaintext manually and call seal_chunk per index.
        let chunks_in: Vec<&[u8]> = plaintext.chunks(chunk_size).collect();
        assert_eq!(chunks_in.len() as u64, count, "chunk count matches");

        for i in 0..count {
            let is_last = i == count - 1;
            let ct = sealer.seal_chunk(i, chunks_in[i as usize], is_last);
            assert_eq!(
                ct, reference[i as usize],
                "seal_chunk({i}) bytes must match seal_from_reader chunk {i}"
            );
        }
    }
}
