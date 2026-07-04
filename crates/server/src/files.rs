//! File-record parsing & coarse validation (api.md §8, DESIGN §11.2/§11.7/§12.2).
//!
//! Pure and storage-agnostic: given the opaque record bytes a client posts to
//! `POST /v1/files` / `.../versions`, it strict-decodes the manifest (and, for
//! version 1, the genesis) — the re-encode guard rejecting any non-canonical
//! bytes — bound-checks the framing it will have to store (so a hostile
//! `chunk_count`/`chunk_size` cannot make the server over-allocate, api.md §8.1),
//! and runs the **coarse** owner/author and recovery-wrap mirror checks.
//!
//! It does **not** verify signatures or trust these fields for security: the
//! signed manifest is authoritative and **every** downloader re-verifies it
//! client-side (§8.5). The server is a transport for inert bytes; these checks
//! only bound its own resources and keep obviously-inconsistent records out. The
//! exact canonical bytes are stored verbatim — the server never re-encodes.

use maxsecu_encoding::structs::{Genesis, Manifest};
use maxsecu_encoding::{decode, RECOVERY_ID};

use crate::error::StoreError;

/// Minimum accepted chunk size, 4 KiB (parameters §1.2 / DESIGN §12.10). The
/// server keeps its own copy of the framing bounds the client also enforces
/// (`maxsecu_client_core::limits`) — independent so neither side can silently
/// widen the other's.
pub const CHUNK_SIZE_MIN: u32 = 4 * 1024;
/// Maximum accepted chunk size, 8 MiB (parameters §1.2).
pub const CHUNK_SIZE_MAX: u32 = 8 * 1024 * 1024;
/// Anti-DoS cap on the framing fields only (`chunk_count · chunk_size`), 256 GiB
/// (parameters §1.2) — not a product size limit (the server imposes none, D31).
pub const MAX_ADDRESSABLE_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// One recipient's key-wrap + signed read-grant as posted (api.md §8.1 `wraps[]`).
/// All inert: the server stores the bytes and never unwraps or verifies them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapInput {
    pub recipient_id: [u8; 16],
    pub recipient_type: i16, // 1=user 2=recovery (schema file_key_wraps)
    pub wrapped_dek: Vec<u8>,
    pub wrap_alg: i32,
    pub granted_by: [u8; 16],
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
}

/// The genesis half of a version-1 stage (immutable, §11.7); absent for vN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisInput {
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
}

/// The decoded staging request (`POST /v1/files` or `.../versions`).
#[derive(Clone, Debug)]
pub struct StageInput {
    pub file_id: [u8; 16],
    /// The authenticated session user (the coarse owner/author subject).
    pub caller_id: [u8; 16],
    /// Request `file_type` mirror (api.md §8.1) — cross-checked vs the manifest.
    pub file_type_advisory: i16,
    /// `Some` for version 1 (carries genesis), `None` for a rotation (vN).
    pub genesis: Option<GenesisInput>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub wraps: Vec<WrapInput>,
    /// Advisory ciphertext `total_bytes` per stream (api.md §8.1 request); keyed
    /// by `stream_type`. Not committed in the manifest — listing/quota only.
    pub stream_totals: Vec<(i16, u64)>,
    /// The version the client proposes (1 for create; N for rotation). Must equal
    /// the manifest's `version`; finalize enforces strict `+1` (§12).
    pub proposed_version: u64,
    /// File-level feed visibility, set once at v1 creation (Task 1.3). `false`
    /// marks a bundle member the server hides from the feed listing (Task 1.4).
    /// Ignored on rotations (vN) — the file's value is fixed at genesis.
    pub listed: bool,
    /// The owning bundle's `file_id` for a bundle member, else `None`. Set once at
    /// v1 creation; ignored on rotations.
    pub bundle_id: Option<[u8; 16]>,
}

/// One `file_streams` row projected from the manifest (authoritative) plus the
/// advisory `total_bytes` and the server-assigned `blob_ref` (api.md §8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamRow {
    pub stream_type: i16,
    pub compression: i16,
    pub chunk_size: u32, // file-wide (the manifest commits one chunk_size)
    pub chunk_count: u64,
    pub total_bytes: u64,
    pub digest: [u8; 32],
    pub blob_ref: String,
}

/// The immutable genesis row (schema `file_genesis`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisRow {
    pub owner_id: [u8; 16],
    pub owner_key_version: u64,
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
}

/// A fully decoded, bound-checked stage ready to persist (input to
/// [`crate::store::Store::stage_version`]). Carries the verbatim canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedStage {
    pub file_id: [u8; 16],
    pub file_type: i16, // authoritative (from the manifest)
    pub version: u64,
    pub author_id: [u8; 16],
    pub alg: i32,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    /// `Some` only on version 1; the owner identity comes from here (and the
    /// store records it as the file's owner). `None` ⇒ rotation of an existing
    /// file whose owner the store already knows.
    pub genesis: Option<GenesisRow>,
    pub streams: Vec<StreamRow>,
    pub wraps: Vec<WrapInput>,
    pub recovery_present: bool,
    /// File-level feed visibility, recorded once at v1 creation (Task 1.3).
    /// `false` = a bundle member hidden from the feed listing (Task 1.4). The
    /// store only applies this on the genesis (v1) path; rotations ignore it.
    pub listed: bool,
    /// The owning bundle's `file_id` for a bundle member, else `None` (Task 1.3).
    pub bundle_id: Option<[u8; 16]>,
}

/// Why a stage/finalize was rejected. The pure [`parse_stage`] yields the
/// decode/bound/coarse variants; the lifecycle ones (`NoSuchFile`, …) come from
/// the store. Fail-closed; none reveals key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    /// Manifest bytes failed strict canonical decode (the re-encode guard).
    BadManifest,
    /// Genesis bytes failed strict canonical decode.
    BadGenesis,
    /// A record's `file_id` did not match the request / each other.
    FileIdMismatch,
    /// Coarse owner/author check failed (caller is not the owner/author, D29).
    NotOwner,
    /// `chunk_size` outside [4 KiB, 8 MiB] (→ 400).
    ChunkSizeOutOfRange,
    /// `chunk_count · chunk_size` over the 256 GiB framing cap (→ 413).
    SizeBoundExceeded,
    /// No recovery wrap present (Phase 3 requires self + recovery, §12.2).
    MissingRecoveryWrap,
    /// `proposed_version` ≠ the manifest's `version`.
    VersionMismatch,
    /// Version 1 stage without a genesis, or a `version == 1` manifest with none.
    GenesisRequired,
    /// A rotation (vN) stage that carried a genesis (immutable, one per file).
    GenesisUnexpected,
    /// Rotation named a file the store has never seen.
    NoSuchFile,
    /// The named version is already finalized (immutable) — cannot re-stage.
    AlreadyFinalized,
    /// A backend fault (→ 500, logged) — distinct from a business rejection.
    Store(StoreError),
}

impl From<StoreError> for StageError {
    fn from(e: StoreError) -> Self {
        StageError::Store(e)
    }
}

/// Why a finalize (the atomic version commit, api.md §8.4 / §12) was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeError {
    /// Coarse owner check failed (caller is not the file owner, D29).
    NotOwner,
    /// No staged version `v` exists for the file (nothing to commit).
    NoSuchVersion,
    /// Lost the serialize-on-`(file_id, version)` race / stale proposal: `v` is
    /// not `current_version + 1` (→ 409; the client rebases, §12.9).
    VersionConflict { expected: u64, got: u64 },
    /// Version `v` is already finalized (immutable) — idempotent no-op guard.
    AlreadyFinalized,
    /// A backend fault (→ 500, logged).
    Store(StoreError),
}

impl From<StoreError> for FinalizeError {
    fn from(e: StoreError) -> Self {
        FinalizeError::Store(e)
    }
}

/// Why a read re-share (`POST /v1/files/{id}/wraps`, api.md §10.1) was rejected.
/// Coarse-only — the wrap bytes are inert and the client re-verifies the grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddWrapError {
    /// The file is absent, not yet finalized, or the caller holds no wrap for the
    /// current version — all indistinguishable (no access oracle, → 404).
    NoAccess,
    /// The posted wrap is not a valid re-share: `granted_by` is not the caller
    /// (the re-sharer signs as themselves), or the recipient is the recovery
    /// sentinel / not a user (→ 400). Re-share never targets recovery (§12.9).
    BadRequest,
    /// A backend fault (→ 500, logged).
    Store(StoreError),
}

impl From<StoreError> for AddWrapError {
    fn from(e: StoreError) -> Self {
        AddWrapError::Store(e)
    }
}

/// Why a soft-revoke (`DELETE /v1/files/{id}/wraps/{recipient}`, api.md §10.2)
/// was rejected. Soft-revoke is a server-side denial, not a cryptographic
/// boundary (§12.8) — for a guarantee against a malicious server, tombstone +
/// rotate (§12.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteWrapError {
    /// No such file, finalized version, or wrap row for that recipient (→ 404).
    NotFound,
    /// The caller is neither the file owner nor the wrap's `granted_by` — the
    /// coarse owner-or-granter gate (→ 403).
    NotAuthorized,
    /// A backend fault (→ 500, logged).
    Store(StoreError),
}

impl From<StoreError> for DeleteWrapError {
    fn from(e: StoreError) -> Self {
        DeleteWrapError::Store(e)
    }
}

/// Why a staged-but-never-finalized file discard (`DELETE /v1/files/{id}`)
/// was rejected. Fail-closed; missing-vs-not-owner collapses to the same
/// outcome (no oracle, §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscardError {
    /// The file is absent or the caller is not the owner — same code, no oracle.
    NotFound,
    /// A finalized version exists, so this is NOT a staged-discard. Internal
    /// routing signal only: the `DELETE /v1/files/{id}` handler catches it and
    /// dispatches to the owner-only permanent-delete path ([`DeleteError`] /
    /// [`crate::store::Store::delete_file`]). The endpoint no longer returns 409.
    HasFinalizedVersion,
    /// A backend fault (→ 500, logged).
    Store(StoreError),
}

impl From<StoreError> for DiscardError {
    fn from(e: StoreError) -> Self {
        DiscardError::Store(e)
    }
}

/// Why an **owner-only permanent delete** of a *finalized* file (`DELETE
/// /v1/files/{id}`) was rejected. Unlike [`DiscardError`] this path removes
/// finalized content (via the transaction-local carve-out over the append-only
/// triggers), so there is deliberately **no** `HasFinalizedVersion` variant.
/// Fail-closed: a missing file and a non-owner collapse to the same `NotFound`
/// (no oracle, §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteError {
    /// The file is absent or the caller is not its owner — same code, no oracle.
    NotFound,
    /// A backend fault (→ 500, logged) — distinct from a business rejection.
    Store(StoreError),
}

impl From<StoreError> for DeleteError {
    fn from(e: StoreError) -> Self {
        DeleteError::Store(e)
    }
}

/// Which version of a file `GET /v1/files/{id}` should return (api.md §8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSelector {
    /// The current finalized version (`?version=latest`).
    Latest,
    /// A specific version number (`?version=<v>`).
    Specific(u64),
}

/// Filter/limit for `GET /v1/files` listing (api.md §8.6 / D35).
#[derive(Debug, Clone)]
pub struct ListFilter {
    /// Restrict to one `file_type` (1=video 2=image 3=blog), or all if `None`.
    pub file_type: Option<i16>,
    /// Max entries to return.
    pub limit: usize,
}

/// Decode and coarse-validate a staging request (api.md §8.1/§8.2). Pure: no DB,
/// no crypto. Existence / strict-`+1` / owner-of-an-existing-file checks that
/// need stored state are the store's job (`stage_version`/`finalize_version`).
pub fn parse_stage(input: StageInput) -> Result<ParsedStage, StageError> {
    // Strict canonical decode — the re-encode guard rejects non-canonical bytes.
    let manifest: Manifest = decode(&input.manifest_bytes).map_err(|_| StageError::BadManifest)?;

    if manifest.file_id.0 != input.file_id {
        return Err(StageError::FileIdMismatch);
    }
    // Bound the framing the server will have to store (api.md §8.1) — manifest is
    // authoritative for the values, but its sizes still cap the server's own
    // allocation. chunk_size first (→ 400), then per-stream product (→ 413).
    if manifest.chunk_size < CHUNK_SIZE_MIN || manifest.chunk_size > CHUNK_SIZE_MAX {
        return Err(StageError::ChunkSizeOutOfRange);
    }
    for s in &manifest.streams {
        let product = s
            .chunk_count
            .checked_mul(manifest.chunk_size as u64)
            .ok_or(StageError::SizeBoundExceeded)?;
        if product > MAX_ADDRESSABLE_BYTES {
            return Err(StageError::SizeBoundExceeded);
        }
    }
    // Coarse owner-only-write mirror (D29): the caller must be the version author.
    // Combined with the store's caller==owner check this gives author==owner; the
    // downloader re-verifies authoritatively (§8.5).
    if manifest.author_id.0 != input.caller_id {
        return Err(StageError::NotOwner);
    }
    // Recovery wrap must be present (Phase 3 wraps to self + recovery, §12.2); the
    // client also asserts `recovery_present` in the signed manifest — coarse mirror.
    let has_recovery = input.wraps.iter().any(|w| {
        w.recipient_type == 2 || w.recipient_id == RECOVERY_ID.0
    });
    if !has_recovery {
        return Err(StageError::MissingRecoveryWrap);
    }
    if input.proposed_version != manifest.version {
        return Err(StageError::VersionMismatch);
    }

    // Genesis is present iff this is version 1 (immutable, one per file, §11.7).
    let genesis = match (&input.genesis, manifest.version) {
        (Some(g), 1) => {
            let decoded: Genesis =
                decode(&g.genesis_bytes).map_err(|_| StageError::BadGenesis)?;
            if decoded.file_id.0 != input.file_id {
                return Err(StageError::FileIdMismatch);
            }
            if decoded.owner_id.0 != input.caller_id {
                return Err(StageError::NotOwner);
            }
            Some(GenesisRow {
                owner_id: decoded.owner_id.0,
                owner_key_version: decoded.owner_key_version,
                genesis_bytes: g.genesis_bytes.clone(),
                genesis_sig: g.genesis_sig,
            })
        }
        (Some(_), _) => return Err(StageError::GenesisUnexpected), // vN must not carry genesis
        (None, 1) => return Err(StageError::GenesisRequired),      // v1 must carry genesis
        (None, _) => None,                                          // valid rotation
    };

    let streams = manifest
        .streams
        .iter()
        .map(|s| {
            let st = s.stream_type as u8;
            let total_bytes = input
                .stream_totals
                .iter()
                .find(|(t, _)| *t == st as i16)
                .map(|(_, b)| *b)
                .unwrap_or(0);
            StreamRow {
                stream_type: st as i16,
                compression: s.compression as u8 as i16,
                chunk_size: manifest.chunk_size,
                chunk_count: s.chunk_count,
                total_bytes,
                digest: s.digest.0,
                blob_ref: blob_ref(&input.file_id, manifest.version, st),
            }
        })
        .collect();

    Ok(ParsedStage {
        file_id: input.file_id,
        file_type: manifest.file_type as u8 as i16,
        version: manifest.version,
        author_id: manifest.author_id.0,
        alg: 1, // Suite::V1 (encoding-spec §3)
        manifest_bytes: input.manifest_bytes,
        manifest_sig: input.manifest_sig,
        genesis,
        streams,
        wraps: input.wraps,
        recovery_present: manifest.recovery_present,
        listed: input.listed,
        bundle_id: input.bundle_id,
    })
}

/// A logical blob id keying one stream's chunks across the storage tiers
/// (schema `file_streams.blob_ref`, D31). Server-assigned and deterministic in
/// `(file_id, version, stream_type)` so a re-stage targets the same slot.
fn blob_ref(file_id: &[u8; 16], version: u64, stream_type: u8) -> String {
    let mut hex = String::with_capacity(32);
    for b in file_id {
        hex.push_str(&format!("{b:02x}"));
    }
    format!("{hex}/{version}/{stream_type}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::structs::{Manifest, Stream};
    use maxsecu_encoding::types::{
        Bytes32, Compression, FileType, Id, StreamType, Suite, Timestamp,
    };

    const OWNER: [u8; 16] = [0x11; 16];
    const FILE: [u8; 16] = [0xF1; 16];

    fn stream(st: StreamType, count: u64) -> Stream {
        Stream {
            stream_type: st,
            compression: Compression::None,
            chunk_count: count,
            digest: Bytes32([st as u8; 32]),
        }
    }

    fn manifest_bytes(file: [u8; 16], version: u64, author: [u8; 16], chunk_size: u32) -> Vec<u8> {
        let m = Manifest {
            file_id: Id(file),
            version,
            file_type: FileType::Blog,
            alg: Suite::V1,
            chunk_size,
            dek_commit: Bytes32([0xDC; 32]),
            streams: vec![stream(StreamType::Content, 2), stream(StreamType::Metadata, 1)],
            recovery_present: true,
            author_id: Id(author),
            created_at: Timestamp(1_719_500_000_000),
        };
        encode(&m)
    }

    fn genesis_bytes(file: [u8; 16], owner: [u8; 16]) -> Vec<u8> {
        encode(&Genesis {
            file_id: Id(file),
            owner_id: Id(owner),
            owner_key_version: 1,
            created_at: Timestamp(1_719_500_000_000),
        })
    }

    fn recovery_wrap() -> WrapInput {
        WrapInput {
            recipient_id: RECOVERY_ID.0,
            recipient_type: 2,
            wrapped_dek: vec![0xAA; 48],
            wrap_alg: 1,
            granted_by: OWNER,
            grant_bytes: vec![0xBB; 8],
            grant_sig: [0xCC; 64],
        }
    }

    fn self_wrap() -> WrapInput {
        WrapInput {
            recipient_id: OWNER,
            recipient_type: 1,
            wrapped_dek: vec![0xAA; 48],
            wrap_alg: 1,
            granted_by: OWNER,
            grant_bytes: vec![0xBB; 8],
            grant_sig: [0xCC; 64],
        }
    }

    fn v1_input(chunk_size: u32) -> StageInput {
        StageInput {
            file_id: FILE,
            caller_id: OWNER,
            file_type_advisory: 3,
            genesis: Some(GenesisInput {
                genesis_bytes: genesis_bytes(FILE, OWNER),
                genesis_sig: [0x9A; 64],
            }),
            manifest_bytes: manifest_bytes(FILE, 1, OWNER, chunk_size),
            manifest_sig: [0x9B; 64],
            wraps: vec![self_wrap(), recovery_wrap()],
            stream_totals: vec![(1, 4096), (2, 100)],
            proposed_version: 1,
            listed: true,
            bundle_id: None,
        }
    }

    #[test]
    fn version1_stage_parses_into_rows() {
        let parsed = parse_stage(v1_input(1 << 20)).expect("valid v1 parses");
        assert_eq!(parsed.file_id, FILE);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.author_id, OWNER);
        assert_eq!(parsed.file_type, 3); // Blog
        assert!(parsed.recovery_present);
        let g = parsed.genesis.expect("genesis row present");
        assert_eq!(g.owner_id, OWNER);
        assert_eq!(g.owner_key_version, 1);
        // Two streams, framing projected from the manifest, totals from request.
        assert_eq!(parsed.streams.len(), 2);
        let content = &parsed.streams[0];
        assert_eq!(content.stream_type, 1);
        assert_eq!(content.chunk_count, 2);
        assert_eq!(content.chunk_size, 1 << 20);
        assert_eq!(content.total_bytes, 4096);
        // blob_ref is deterministic and distinguishes (file, version, stream).
        assert!(content.blob_ref.contains(&format!("{}", 1)));
        assert_ne!(content.blob_ref, parsed.streams[1].blob_ref);
    }

    #[test]
    fn rotation_stage_without_genesis_parses() {
        let mut input = v1_input(1 << 20);
        input.genesis = None;
        input.manifest_bytes = manifest_bytes(FILE, 7, OWNER, 1 << 20);
        input.proposed_version = 7;
        let parsed = parse_stage(input).expect("valid vN parses");
        assert_eq!(parsed.version, 7);
        assert!(parsed.genesis.is_none());
    }

    #[test]
    fn malformed_manifest_is_rejected() {
        let mut input = v1_input(1 << 20);
        input.manifest_bytes = vec![0x00, 0x02, 0xFF]; // truncated garbage
        assert_eq!(parse_stage(input), Err(StageError::BadManifest));
    }

    #[test]
    fn manifest_file_id_must_match_request() {
        let mut input = v1_input(1 << 20);
        input.manifest_bytes = manifest_bytes([0xEE; 16], 1, OWNER, 1 << 20);
        assert_eq!(parse_stage(input), Err(StageError::FileIdMismatch));
    }

    #[test]
    fn genesis_file_id_must_match_request() {
        let mut input = v1_input(1 << 20);
        input.genesis = Some(GenesisInput {
            genesis_bytes: genesis_bytes([0xEE; 16], OWNER),
            genesis_sig: [0x9A; 64],
        });
        assert_eq!(parse_stage(input), Err(StageError::FileIdMismatch));
    }

    #[test]
    fn non_owner_author_is_rejected() {
        // Manifest author != caller (owner-only write, D29 coarse mirror).
        let mut input = v1_input(1 << 20);
        input.manifest_bytes = manifest_bytes(FILE, 1, [0x22; 16], 1 << 20);
        assert_eq!(parse_stage(input), Err(StageError::NotOwner));
    }

    #[test]
    fn genesis_owner_must_be_caller() {
        let mut input = v1_input(1 << 20);
        input.genesis = Some(GenesisInput {
            genesis_bytes: genesis_bytes(FILE, [0x22; 16]),
            genesis_sig: [0x9A; 64],
        });
        assert_eq!(parse_stage(input), Err(StageError::NotOwner));
    }

    #[test]
    fn chunk_size_below_floor_is_rejected() {
        assert_eq!(
            parse_stage(v1_input(2048)),
            Err(StageError::ChunkSizeOutOfRange)
        );
    }

    #[test]
    fn chunk_size_above_ceiling_is_rejected() {
        assert_eq!(
            parse_stage(v1_input(16 * 1024 * 1024)),
            Err(StageError::ChunkSizeOutOfRange)
        );
    }

    #[test]
    fn framing_over_256gib_is_rejected() {
        // chunk_count · chunk_size > 256 GiB on the content stream.
        let huge = Manifest {
            file_id: Id(FILE),
            version: 1,
            file_type: FileType::Blog,
            alg: Suite::V1,
            chunk_size: 8 * 1024 * 1024,
            dek_commit: Bytes32([0xDC; 32]),
            streams: vec![stream(StreamType::Content, 40_000)], // 40000·8MiB ≈ 305 GiB
            recovery_present: true,
            author_id: Id(OWNER),
            created_at: Timestamp(1),
        };
        let mut input = v1_input(8 * 1024 * 1024);
        input.manifest_bytes = encode(&huge);
        assert_eq!(parse_stage(input), Err(StageError::SizeBoundExceeded));
    }

    #[test]
    fn missing_recovery_wrap_is_rejected() {
        let mut input = v1_input(1 << 20);
        input.wraps = vec![self_wrap()]; // no recovery recipient
        assert_eq!(parse_stage(input), Err(StageError::MissingRecoveryWrap));
    }

    #[test]
    fn proposed_version_must_match_manifest() {
        let mut input = v1_input(1 << 20);
        input.proposed_version = 2; // manifest says version 1
        assert_eq!(parse_stage(input), Err(StageError::VersionMismatch));
    }

    #[test]
    fn version1_manifest_without_genesis_is_rejected() {
        let mut input = v1_input(1 << 20);
        input.genesis = None; // version stays 1 but no genesis
        assert_eq!(parse_stage(input), Err(StageError::GenesisRequired));
    }

    #[test]
    fn rotation_carrying_a_genesis_is_rejected() {
        let mut input = v1_input(1 << 20);
        input.manifest_bytes = manifest_bytes(FILE, 4, OWNER, 1 << 20);
        input.proposed_version = 4;
        // genesis still Some ⇒ a vN stage must not carry one
        assert_eq!(parse_stage(input), Err(StageError::GenesisUnexpected));
    }
}
