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
//! A leaf wrap-grant either chains directly to the version author (owner-only
//! write, D29) or via re-share ancestor grants (§12.4b/§12.5), each intermediate
//! granter's key directory-resolved (§7.2) — see [`verify_grant_chain`], bounded
//! by [`MAX_GRANT_CHAIN_DEPTH`] and cycle-guarded. Full tombstone-completeness
//! evaluation against the sink-anchored head is Phase 5.

use maxsecu_crypto::{
    open_stream, open_stream_streaming, stream_digest, unwrap_dek, Dek, EncSecretKey, VerifyingKey,
    WrappedDek,
};
use maxsecu_encoding::structs::{Genesis, Grant, Manifest, WrapContext};
use maxsecu_encoding::types::{Compression, FileType, Id, RecipientType, StreamType};
use maxsecu_encoding::{decode, labels, Canonical, RECOVERY_ID};

use std::collections::{HashMap, HashSet};

use crate::error::DownloadError;
use crate::limits::{
    CHUNK_SIZE_MAX, CHUNK_SIZE_MIN, FIRST_CONTACT_VERSION_CEILING, MAX_ADDRESSABLE_BYTES,
    MAX_GRANT_CHAIN_DEPTH,
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
    /// The re-share ancestor grants (each `canonical(grant)` + sig) needed to
    /// chain the caller's leaf grant up to the version author (api.md §8.5
    /// `ancestor_grants`). Empty for an author-rooted (non-re-shared) wrap.
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
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
    /// Resolves an intermediate re-share granter's **directory-verified** Ed25519
    /// `sig_pub` (§7.2), or `None` if it cannot be authenticated. Consulted only
    /// when a leaf/ancestor grant's `granted_by` is *not* the version author; an
    /// author-rooted wrap never calls it. Pass [`NO_GRANTERS`] when no re-share
    /// chain is expected.
    pub granter_sig_pub: &'a dyn Fn(Id) -> Option<[u8; 32]>,
    /// The authenticated, sink-anchored tombstone set for the completeness gate
    /// (§12.5 step 4): the version is **rejected** if its `author_id` is account-
    /// revoked (a tombstoned author cannot mint, §12.9) or if the downloader is
    /// revoked from this file at this version. `None` skips the gate — used only
    /// at first contact / for already-verified reads where no completeness proof
    /// is required (§7.6); any served version supplies a set proven contiguous to
    /// the sink head ([`TombstoneSet::verify_authenticated`]).
    pub tombstones: Option<&'a crate::revocation::TombstoneSet>,
    /// The R27 signing-compromise cutoff for the immutable `genesis` (§11.7/D28).
    /// `None` skips the check (no compromise relevant). When present, a genesis
    /// signed under a compromised `(owner_id, owner_key_version)` is honored only
    /// if its **sink-anchoring position predates** the compromise — defeating a
    /// backdated forgery regardless of its attacker-chosen `created_at`.
    pub compromise: Option<CompromiseCheck<'a>>,
}

/// Inputs for the R27 key-compromise cutoff on the durable `genesis` (§11.7/D28).
/// Both positions are **sink** positions (append order), never timestamps — a
/// forgery cannot retroactively acquire an earlier sink position.
#[derive(Clone, Copy)]
pub struct CompromiseCheck<'a> {
    /// The genesis record's own sink-anchoring position, or `None` if unknown
    /// (then a genesis under any compromise fails closed).
    pub genesis_sink_pos: Option<u64>,
    /// Resolves `(owner_id, owner_key_version)` to the sink position of an active
    /// `key_compromise` cutoff for that key, or `None` if the key is uncompromised.
    pub cutoff: &'a dyn Fn(Id, u64) -> Option<u64>,
}

/// A granter resolver that authenticates no one — for callers with no re-share
/// ancestor chain (every grant is author-rooted). `'static`, so it can back a
/// [`VerifyContext`] returned from a helper.
pub static NO_GRANTERS: fn(Id) -> Option<[u8; 32]> = no_granters;

fn no_granters(_: Id) -> Option<[u8; 32]> {
    None
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

/// Verify the §12.5 header ladder (steps 1–7): strict-decode + signatures of the
/// manifest/genesis/grant, author-entitlement (D29), freshness/rollback, and the
/// DEK unwrap + self-validation against the manifest commitment. Returns the
/// verified manifest, the unwrapped DEK, and whether a valid recovery grant was
/// present. Shared by the whole-buffer [`verify_and_open`] and the streaming
/// [`verify_and_stream_content`] paths so the access proof is identical.
#[allow(clippy::too_many_arguments)]
fn verify_header(
    ctx: &VerifyContext,
    manifest_bytes: &[u8],
    manifest_sig: &[u8; 64],
    genesis_bytes: &[u8],
    genesis_sig: &[u8; 64],
    grant_bytes: &[u8],
    grant_sig: &[u8; 64],
    ancestor_grants: &[(Vec<u8>, [u8; 64])],
    recovery_grant_bytes: &[u8],
    recovery_grant_sig: &[u8; 64],
    wrapped_dek: &WrappedDek,
) -> Result<(Manifest, Dek, bool), DownloadError> {
    use DownloadError::*;

    // (1) Manifest: strict decode (re-encode guard), file_id, framing bound, sig.
    let manifest: Manifest = decode(manifest_bytes).map_err(|_| BadManifest)?;
    if manifest.file_id != ctx.file_id {
        return Err(FileIdMismatch);
    }
    if manifest.chunk_size < CHUNK_SIZE_MIN || manifest.chunk_size > CHUNK_SIZE_MAX {
        return Err(FramingBoundsExceeded("chunk_size out of range"));
    }
    if !verify(&ctx.author_sig_pub, labels::MANIFEST, &manifest, manifest_sig) {
        return Err(ManifestSignature);
    }

    // (2) Genesis: decode + the owner's signature (owner binding).
    let genesis: Genesis = decode(genesis_bytes).map_err(|_| BadGenesis)?;
    if genesis.file_id != ctx.file_id {
        return Err(FileIdMismatch);
    }
    if !verify(&ctx.owner_sig_pub, labels::GENESIS, &genesis, genesis_sig) {
        return Err(GenesisSignature);
    }

    // (2b) R27 signing-compromise cutoff for the durable genesis (§11.7/D28). If
    // the owner's signing key for this genesis is under a key_compromise, the
    // genesis is honored only if its sink-anchoring position **predates** the
    // compromise — a backdated forgery cannot acquire an earlier sink position.
    if let Some(chk) = &ctx.compromise {
        if let Some(cutoff_pos) = (chk.cutoff)(genesis.owner_id, genesis.owner_key_version) {
            let predates = chk.genesis_sink_pos.is_some_and(|g| g < cutoff_pos);
            if !predates {
                return Err(GenesisAfterCompromise);
            }
        }
    }

    // (3) Author-entitlement: owner-only write (D29).
    if manifest.author_id != genesis.owner_id {
        return Err(AuthorNotOwner);
    }

    // (3b) Tombstone completeness (§12.5 step 4, Phase 5). When the caller supplies
    // an authenticated, sink-anchored tombstone set, a version whose author is
    // account-revoked is rejected (a tombstoned author cannot mint, §12.9), as is
    // one served to a downloader revoked from this file at this version (§11.5).
    if let Some(ts) = ctx.tombstones {
        if ts.is_account_revoked(&manifest.author_id.0) {
            return Err(AuthorRevoked);
        }
        if ts.is_revoked(&ctx.recipient_id.0, &ctx.file_id.0, manifest.version) {
            return Err(RecipientRevoked);
        }
    }

    // (4) Freshness / rollback (clock-independent, §7.5/D23).
    version_acceptable(manifest.version, ctx.seen_max_version)?;

    // (5) The caller's own read-grant: decode, field-bind to this exact
    // file/version/recipient/DEK, then verify it chains to the version author —
    // directly (author edge) or via re-share edges (§12.3a/§12.5).
    let grant: Grant = decode(grant_bytes).map_err(|_| BadGrant)?;
    check_grant_fields(&grant, &manifest, ctx)?;
    verify_grant_chain(
        &grant,
        grant_sig,
        ancestor_grants,
        manifest.file_id,
        manifest.version,
        manifest.dek_commit,
        manifest.author_id,
        &ctx.author_sig_pub,
        ctx.granter_sig_pub,
    )?;

    // (6) Recovery-grant presence — an anomaly flag, never a hard rejection.
    let recovery_grant_ok = recovery_grant_valid(
        recovery_grant_bytes,
        recovery_grant_sig,
        &manifest,
        &ctx.author_sig_pub,
        genesis.owner_id,
    );

    // (7) Unwrap the DEK and self-validate against the manifest commitment.
    let wrap_ctx = WrapContext {
        file_id: ctx.file_id,
        version: manifest.version,
        recipient_id: ctx.recipient_id,
    };
    let dek = unwrap_dek(ctx.recipient_secret, wrapped_dek, &wrap_ctx).map_err(|_| DekUnwrap)?;
    if dek.commit() != manifest.dek_commit.0 {
        return Err(DekCommitMismatch);
    }
    Ok((manifest, dek, recovery_grant_ok))
}

/// Run the §12.5 download verification ladder and decrypt **whole-buffer**,
/// fail-closed. For large content that should not be materialized, use
/// [`verify_and_stream_content`] instead.
pub fn verify_and_open(
    ctx: &VerifyContext,
    bundle: &DownloadBundle,
) -> Result<OpenedFile, DownloadError> {
    use DownloadError::*;

    let (manifest, dek, recovery_grant_ok) = verify_header(
        ctx,
        &bundle.manifest_bytes,
        &bundle.manifest_sig,
        &bundle.genesis_bytes,
        &bundle.genesis_sig,
        &bundle.grant_bytes,
        &bundle.grant_sig,
        &bundle.ancestor_grants,
        &bundle.recovery_grant_bytes,
        &bundle.recovery_grant_sig,
        &bundle.wrapped_dek,
    )?;

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

/// Check the caller's leaf grant binds this exact file/version/recipient/DEK
/// (its `granted_by` chain is verified separately by [`verify_grant_chain`]). A
/// mismatch ⇒ the wrap is treated as absent (§12.3a).
fn check_grant_fields(g: &Grant, m: &Manifest, ctx: &VerifyContext) -> Result<(), DownloadError> {
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
    Ok(())
}

/// An ancestor (re-share) grant must bind this exact file/version/DEK and grant
/// to a `user` recipient (a re-sharer held a real wrap, §12.3a).
fn check_ancestor_fields(
    g: &Grant,
    file_id: Id,
    version: u64,
    dek_commit: maxsecu_encoding::types::Hash,
) -> Result<(), DownloadError> {
    use DownloadError::GrantMismatch;
    if g.file_id != file_id {
        return Err(GrantMismatch("ancestor file_id"));
    }
    if g.file_version != version {
        return Err(GrantMismatch("ancestor file_version"));
    }
    if g.dek_commit != dek_commit {
        return Err(GrantMismatch("ancestor dek_commit"));
    }
    if g.recipient_type != RecipientType::User {
        return Err(GrantMismatch("ancestor recipient_type"));
    }
    Ok(())
}

/// Verify a leaf grant chains to the version author (§12.5 step 5 / §12.9 step 2
/// carry-forward): directly when `granted_by == author_id` (author edge,
/// verified under the author's directory key), or via a re-share chain where
/// each intermediate granter's grant is verified under that granter's
/// **directory-verified** `sig_pub` (§7.2, resolved by `granter_sig_pub`) and
/// the granter must itself hold a grant for this version. Both author and
/// re-share edges entail the granter actually held the DEK, so any verified
/// chain is possession-entailing (carry-forward-eligible, §12.9). Fail closed on
/// a broken chain, an unknown granter key, a cycle, or a chain past the depth
/// cap. Shared by the download ladder and the rotation carry-forward selection
/// (so the two cannot drift). The leaf's own `file_id`/`version`/`dek_commit`/
/// `recipient` are checked by the caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_grant_chain(
    leaf: &Grant,
    leaf_sig: &[u8; 64],
    ancestors: &[(Vec<u8>, [u8; 64])],
    file_id: Id,
    version: u64,
    dek_commit: maxsecu_encoding::types::Hash,
    author_id: Id,
    author_sig_pub: &[u8; 32],
    granter_sig_pub: &dyn Fn(Id) -> Option<[u8; 32]>,
) -> Result<(), DownloadError> {
    use DownloadError::*;

    // Decode each ancestor once, field-bind it, and index by the recipient it
    // grants to (so a granter's own grant is found by id during the walk).
    let mut by_recipient: HashMap<Id, (Grant, [u8; 64])> = HashMap::new();
    for (bytes, sig) in ancestors {
        let g: Grant = decode(bytes).map_err(|_| BadGrant)?;
        check_ancestor_fields(&g, file_id, version, dek_commit)?;
        by_recipient.insert(g.recipient_id, (g, *sig));
    }

    let mut visited: HashSet<Id> = HashSet::new();
    let mut current: &Grant = leaf;
    let mut current_sig: &[u8; 64] = leaf_sig;
    let mut depth = 0usize;
    loop {
        let granter = current.granted_by;
        if granter == author_id {
            // Author edge: the root, verified under the author's directory key.
            if !verify(author_sig_pub, labels::GRANT, current, current_sig) {
                return Err(GrantSignature);
            }
            return Ok(());
        }
        // Re-share edge: bounded depth, directory-resolved granter key.
        if depth >= MAX_GRANT_CHAIN_DEPTH {
            return Err(GrantChainTooDeep);
        }
        let granter_pub = granter_sig_pub(granter).ok_or(GranterKeyUnknown)?;
        if !verify(&granter_pub, labels::GRANT, current, current_sig) {
            return Err(GrantSignature);
        }
        if !visited.insert(granter) {
            return Err(GrantChainCycle);
        }
        let (next, next_sig) = by_recipient.get(&granter).ok_or(GrantChainBroken)?;
        current = next;
        current_sig = next_sig;
        depth += 1;
    }
}

/// Is a valid author recovery grant present for this version? (Presence check
/// only — the recovery *wrap* is never served to a downloader, §12.5 step 2.)
fn recovery_grant_valid(
    recovery_grant_bytes: &[u8],
    recovery_grant_sig: &[u8; 64],
    m: &Manifest,
    author_pub: &[u8; 32],
    owner_id: Id,
) -> bool {
    let g: Grant = match decode(recovery_grant_bytes) {
        Ok(g) => g,
        Err(_) => return false,
    };
    verify(author_pub, labels::GRANT, &g, recovery_grant_sig)
        && g.recipient_type == RecipientType::Recovery
        && g.recipient_id == RECOVERY_ID
        && g.file_id == m.file_id
        && g.file_version == m.version
        && g.dek_commit == m.dek_commit
        && g.granted_by == owner_id
}

/// The verification records + the **non-content** (small) streams a streaming
/// open needs up front (api.md §8.5). The `content` stream is *not* here — it is
/// fetched chunk-by-chunk by [`verify_and_stream_content`]'s `fetch` closure so
/// it is never materialized whole (DESIGN §8.1).
pub struct StreamHeader {
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: [u8; 64],
    pub genesis_bytes: Vec<u8>,
    pub genesis_sig: [u8; 64],
    pub wrapped_dek: WrappedDek,
    pub grant_bytes: Vec<u8>,
    pub grant_sig: [u8; 64],
    /// The re-share ancestor grants chaining the leaf grant to the author
    /// (api.md §8.5); empty for an author-rooted wrap.
    pub ancestor_grants: Vec<(Vec<u8>, [u8; 64])>,
    pub recovery_grant_bytes: Vec<u8>,
    pub recovery_grant_sig: [u8; 64],
    /// Every manifest stream except `content`, served whole (these are small —
    /// `metadata`/`thumbnail`/`preview`, D35).
    pub small_streams: Vec<StreamChunks>,
}

/// The result of a streaming open: the verified header facts plus the decoded
/// small streams. The `content` bytes were delivered to the caller's sink, not
/// returned (they are never held whole).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedHeader {
    pub version: u64,
    pub file_type: FileType,
    /// The `content` stream's manifest digest (committed) — recorded in
    /// trust-on-last-use memory alongside `version` (§7.5).
    pub content_digest: [u8; 32],
    pub recovery_grant_ok: bool,
    /// Number of `content` chunks (the manifest framing the caller fetched).
    pub content_chunk_count: u64,
    pub small_streams: Vec<OpenedStream>,
}

/// Run the §12.5 ladder, then **stream** the `content` stream chunk-at-a-time to
/// `sink` while decoding the small streams whole (DESIGN §8.1 line 360–361).
///
/// `fetch(i)` supplies content ciphertext chunk `i` (a lazy network GET); each
/// chunk's AEAD tag is verified **before** its plaintext reaches `sink`, and only
/// one content chunk of plaintext is ever in memory — so an arbitrarily large
/// `content` round-trips within an O(chunk_size) budget with no whole plaintext
/// in RAM. Streaming relies on per-chunk AEAD under the committed DEK + the
/// signed `chunk_count`/`is_last` (truncation/extension), not the whole-stream
/// digest (which cannot be checked before release); the small streams keep the
/// full digest check. Fail-closed throughout.
pub fn verify_and_stream_content<Fetch, Sink>(
    ctx: &VerifyContext,
    header: &StreamHeader,
    mut fetch: Fetch,
    mut sink: Sink,
) -> Result<OpenedHeader, DownloadError>
where
    Fetch: FnMut(u64) -> Result<Vec<u8>, DownloadError>,
    Sink: FnMut(&[u8]) -> Result<(), DownloadError>,
{
    use DownloadError::*;

    let (manifest, dek, recovery_grant_ok) = verify_header(
        ctx,
        &header.manifest_bytes,
        &header.manifest_sig,
        &header.genesis_bytes,
        &header.genesis_sig,
        &header.grant_bytes,
        &header.grant_sig,
        &header.ancestor_grants,
        &header.recovery_grant_bytes,
        &header.recovery_grant_sig,
        &header.wrapped_dek,
    )?;

    // Small streams (everything except content) decode whole, fully digest-checked.
    let mut small = Vec::new();
    let mut content_ms: Option<&maxsecu_encoding::structs::Stream> = None;
    for ms in &manifest.streams {
        if ms.compression != Compression::None {
            return Err(CompressionUnsupported);
        }
        if ms.stream_type == StreamType::Content {
            content_ms = Some(ms);
            continue;
        }
        let provided = header
            .small_streams
            .iter()
            .find(|s| s.stream_type == ms.stream_type)
            .ok_or(StreamMissing(ms.stream_type))?;
        if provided.chunks.len() as u64 != ms.chunk_count {
            return Err(FramingBoundsExceeded("chunk_count mismatch"));
        }
        if stream_digest(&provided.chunks) != ms.digest.0 {
            return Err(StreamDigestMismatch(ms.stream_type));
        }
        let ck = dek.stream_subkey(ms.stream_type);
        let plaintext = open_stream(&ck, ctx.file_id, manifest.version, ms.stream_type, &provided.chunks)
            .map_err(|_| StreamFraming(ms.stream_type))?;
        small.push(OpenedStream {
            stream_type: ms.stream_type,
            plaintext,
        });
    }

    // The content stream must be declared in the manifest (DESIGN §12.3).
    let content_ms = content_ms.ok_or(StreamMissing(StreamType::Content))?;
    match content_ms.chunk_count.checked_mul(manifest.chunk_size as u64) {
        Some(b) if b <= MAX_ADDRESSABLE_BYTES => {}
        _ => return Err(FramingBoundsExceeded("addressable size")),
    }
    let ck = dek.stream_subkey(StreamType::Content);
    // Bridge the caller's DownloadError fetch/sink into the crypto layer's
    // CryptoError closures: stash any caller error in a cell and surface a
    // sentinel, so a fetch/sink failure propagates faithfully (a genuine AEAD
    // failure, with no caller error stashed, becomes StreamFraming).
    let user_err: core::cell::RefCell<Option<DownloadError>> = core::cell::RefCell::new(None);
    let res = open_stream_streaming(
        &ck,
        ctx.file_id,
        manifest.version,
        StreamType::Content,
        content_ms.chunk_count,
        |i| {
            fetch(i).map_err(|e| {
                *user_err.borrow_mut() = Some(e);
                maxsecu_crypto::CryptoError::Framing("fetch")
            })
        },
        |frame| {
            sink(frame).map_err(|e| {
                *user_err.borrow_mut() = Some(e);
                maxsecu_crypto::CryptoError::Framing("sink")
            })
        },
    );
    if res.is_err() {
        return Err(user_err
            .into_inner()
            .unwrap_or(StreamFraming(StreamType::Content)));
    }

    Ok(OpenedHeader {
        version: manifest.version,
        file_type: manifest.file_type,
        content_digest: content_ms.digest.0,
        recovery_grant_ok,
        content_chunk_count: content_ms.chunk_count,
        small_streams: small,
    })
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
            granter_sig_pub: &NO_GRANTERS,
            tombstones: None,
            compromise: None,
        }
    }

    /// A multi-chunk build (content spans several 4 KiB chunks) for streaming.
    fn build_large() -> (Built, Vec<u8>) {
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
        let content: Vec<u8> = (0..(4096 * 3 + 123)).map(|i| (i % 251) as u8).collect();
        let streams = PlaintextStreams {
            content: content.clone(),
            metadata: Some(b"title=big".to_vec()),
            thumbnail: None,
            preview: None,
        };
        let bundle = build_upload(&params, &streams).unwrap();
        (Built { owner, recovery_sk, bundle }, content)
    }

    /// Split an UploadBundle into a streaming header (small streams) + the
    /// content stream's ciphertext chunks (fetched lazily by the test).
    fn stream_header(b: &UploadBundle) -> (StreamHeader, Vec<Vec<u8>>) {
        let sw = b.wraps.iter().find(|w| w.recipient_type == RecipientType::User).unwrap();
        let rw = b.wraps.iter().find(|w| w.recipient_type == RecipientType::Recovery).unwrap();
        let content = b.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap();
        let small = b
            .streams
            .iter()
            .filter(|s| s.stream_type != StreamType::Content)
            .map(|s| StreamChunks { stream_type: s.stream_type, chunks: s.chunks.clone() })
            .collect();
        let header = StreamHeader {
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
            small_streams: small,
        };
        (header, content.chunks.clone())
    }

    #[test]
    fn streaming_content_round_trips_without_a_whole_buffer() {
        let (built, content) = build_large();
        let (header, chunks) = stream_header(&built.bundle);
        assert!(chunks.len() >= 4, "content spans multiple chunks");

        let mut out = Vec::new();
        let mut max_frame = 0usize;
        let opened = verify_and_stream_content(
            &ctx(&built),
            &header,
            |i| Ok(chunks[i as usize].clone()),
            |frame| {
                max_frame = max_frame.max(frame.len());
                out.extend_from_slice(frame);
                Ok(())
            },
        )
        .expect("streams");

        assert_eq!(opened.version, 1);
        assert!(opened.recovery_grant_ok);
        assert_eq!(opened.content_chunk_count, chunks.len() as u64);
        assert!(max_frame <= 4096, "no frame exceeds the chunk size (O(chunk_size) RAM)");
        assert_eq!(out, content, "streamed content reconstructs the plaintext");
        // The small metadata stream is decoded whole and digest-checked.
        let meta = opened.small_streams.iter().find(|s| s.stream_type == StreamType::Metadata).unwrap();
        assert_eq!(meta.plaintext, b"title=big");
    }

    #[test]
    fn streaming_rejects_a_tampered_content_chunk() {
        let (built, _content) = build_large();
        let (header, mut chunks) = stream_header(&built.bundle);
        chunks[1][0] ^= 0x01; // tamper the second content chunk
        let mut released = 0usize;
        let err = verify_and_stream_content(
            &ctx(&built),
            &header,
            |i| Ok(chunks[i as usize].clone()),
            |_| {
                released += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err, DownloadError::StreamFraming(StreamType::Content));
        assert_eq!(released, 1, "only the first (valid) chunk was released");
    }

    #[test]
    fn streaming_propagates_a_fetch_error() {
        let (built, _content) = build_large();
        let (header, _chunks) = stream_header(&built.bundle);
        let err = verify_and_stream_content(
            &ctx(&built),
            &header,
            |_| Err(DownloadError::StreamMissing(StreamType::Content)),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(err, DownloadError::StreamMissing(StreamType::Content));
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
            granter_sig_pub: &NO_GRANTERS,
            tombstones: None,
            compromise: None,
        };
        let opened = verify_and_open(&c, &db).expect("recovery opens");
        assert_eq!(opened.version, 1);
    }

    /// Build an authenticated `TombstoneSet` account-wide-revoking `victim`
    /// (dual-controlled), plus the leak-free issuer resolver for its two admins.
    fn account_revoke_set(victim: Id) -> crate::revocation::TombstoneSet {
        use crate::revocation::{ControlRecordIn, IssuerInfo, TombstoneSet};
        use maxsecu_admin_core::{ControlChain, CoSign, RevokeParams};
        use maxsecu_crypto::SigningKey;
        use maxsecu_encoding::types::{FileScope, Role};

        let a1 = SigningKey::generate();
        let a2 = SigningKey::generate();
        let a1_id = Id([0xA1; 16]);
        let a2_id = Id([0xA2; 16]);
        let mut chain = ControlChain::new();
        let rev = chain
            .revoke(
                &a1,
                RevokeParams {
                    scope: FileScope::AccountWide,
                    revoked_user_id: victim,
                    revoked_capability: None,
                    from_version: 1,
                    issued_by: a1_id,
                    created_at: NOW,
                },
                Some(CoSign { admin_id: a2_id, key: &a2 }),
            )
            .unwrap();
        let (a1_pub, a2_pub) = (a1.verifying_key().to_bytes(), a2.verifying_key().to_bytes());
        let issuer = move |id: Id| match id {
            x if x == a1_id => Some(IssuerInfo { sig_pub: a1_pub, roles: vec![Role::Admin], key_version: 1 }),
            x if x == a2_id => Some(IssuerInfo { sig_pub: a2_pub, roles: vec![Role::Admin], key_version: 1 }),
            _ => None,
        };
        TombstoneSet::verify_authenticated(
            &[ControlRecordIn { bytes: rev.bytes.clone(), sig: rev.sig, co_sig: rev.co_sig }],
            chain.head(),
            &issuer,
        )
        .unwrap()
    }

    #[test]
    fn tombstoned_author_version_is_rejected() {
        let built = build();
        let db = self_bundle(&built.bundle);
        // The author/owner is under an account-wide tombstone — a tombstoned
        // author cannot mint an accepted version (§12.9/§12.5 step 4).
        let ts = account_revoke_set(OWNER_ID);
        let mut c = ctx(&built);
        c.tombstones = Some(&ts);
        assert_eq!(verify_and_open(&c, &db), Err(DownloadError::AuthorRevoked));
    }

    #[test]
    fn revoked_recipient_is_rejected() {
        let built = build();
        let (bundle, v, r) = reshare_chain(&built);
        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == R_ID).then_some(r_pub);
        // V (the downloader) is account-revoked; the owner/author is not — so the
        // recipient-revocation arm fires (not AuthorRevoked).
        let ts = account_revoke_set(V_ID);
        let mut c = reshare_ctx(&built, &v, &resolver);
        c.tombstones = Some(&ts);
        assert_eq!(verify_and_open(&c, &bundle), Err(DownloadError::RecipientRevoked));
    }

    #[test]
    fn unrelated_tombstone_still_opens() {
        let built = build();
        let db = self_bundle(&built.bundle);
        // A tombstone naming someone else does not block the owner's own read.
        let ts = account_revoke_set(Id([0xEE; 16]));
        let mut c = ctx(&built);
        c.tombstones = Some(&ts);
        assert!(verify_and_open(&c, &db).is_ok());
    }

    #[test]
    fn backdated_genesis_under_compromised_key_is_rejected() {
        let built = build(); // genesis owner_key_version == 1
        let db = self_bundle(&built.bundle);
        // (owner, kv=1) was compromised; the cutoff is anchored at sink pos 5. The
        // genesis was actually anchored at pos 9 (AFTER the compromise) — a forgery
        // backdated via created_at cannot acquire an earlier sink position (D28).
        let cutoff = |id: Id, kv: u64| (id == OWNER_ID && kv == 1).then_some(5u64);
        let mut c = ctx(&built);
        c.compromise = Some(CompromiseCheck { genesis_sink_pos: Some(9), cutoff: &cutoff });
        assert_eq!(verify_and_open(&c, &db), Err(DownloadError::GenesisAfterCompromise));
    }

    #[test]
    fn pre_compromise_genesis_still_opens() {
        let built = build();
        let db = self_bundle(&built.bundle);
        // Genesis anchored at pos 2, before the compromise at pos 5 — a legitimately
        // old file under a key that was only later compromised; still opens.
        let cutoff = |id: Id, kv: u64| (id == OWNER_ID && kv == 1).then_some(5u64);
        let mut c = ctx(&built);
        c.compromise = Some(CompromiseCheck { genesis_sink_pos: Some(2), cutoff: &cutoff });
        assert!(verify_and_open(&c, &db).is_ok());
    }

    #[test]
    fn unknown_genesis_position_under_compromise_fails_closed() {
        let built = build();
        let db = self_bundle(&built.bundle);
        let cutoff = |id: Id, kv: u64| (id == OWNER_ID && kv == 1).then_some(5u64);
        let mut c = ctx(&built);
        // Cannot establish the genesis's sink position while a compromise exists
        // for its key → fail closed rather than honor a possibly-forged genesis.
        c.compromise = Some(CompromiseCheck { genesis_sink_pos: None, cutoff: &cutoff });
        assert_eq!(verify_and_open(&c, &db), Err(DownloadError::GenesisAfterCompromise));
    }

    #[test]
    fn uncompromised_key_ignores_the_cutoff() {
        let built = build();
        let db = self_bundle(&built.bundle);
        // The resolver reports no compromise for this key → the genesis position is
        // irrelevant and the file opens.
        let cutoff = |_: Id, _: u64| None;
        let mut c = ctx(&built);
        c.compromise = Some(CompromiseCheck { genesis_sink_pos: None, cutoff: &cutoff });
        assert!(verify_and_open(&c, &db).is_ok());
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
            granter_sig_pub: &NO_GRANTERS,
            tombstones: None,
            compromise: None,
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

    /// Build R (author-rooted recipient) and V (re-shared by R), recovering the
    /// DEK from the owner self-wrap so the test can forge real wraps to both.
    /// Returns V's download bundle, V's identity, and R's signing pubkey.
    const R_ID: Id = Id([0x22; 16]);
    const V_ID: Id = Id([0x33; 16]);

    fn reshare_chain(built: &Built) -> (DownloadBundle, Identity, Identity) {
        let b = &built.bundle;
        let sw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::User)
            .unwrap();
        let owner_ctx = WrapContext {
            file_id: FILE_ID,
            version: 1,
            recipient_id: OWNER_ID,
        };
        let dek = unwrap_dek(built.owner.enc_secret(), &sw.wrapped_dek, &owner_ctx).unwrap();
        let dek_commit = Bytes32(dek.commit());

        // R: author granted R directly (granted_by = owner).
        let r = Identity::generate();
        let r_ctx = WrapContext {
            file_id: FILE_ID,
            version: 1,
            recipient_id: R_ID,
        };
        let _r_wrap = wrap_dek(&EncPublicKey::from_bytes(r.enc_pub_bytes()), &dek, &r_ctx).unwrap();
        let r_grant = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: R_ID,
            recipient_type: RecipientType::User,
            dek_commit,
            granted_by: OWNER_ID,
            created_at: NOW,
        };
        let r_grant_sig = built.owner.signing_key().sign_canonical(labels::GRANT, &r_grant);

        // V: re-shared by R (granted_by = R), signed with R's own key.
        let v = Identity::generate();
        let v_ctx = WrapContext {
            file_id: FILE_ID,
            version: 1,
            recipient_id: V_ID,
        };
        let v_wrap = wrap_dek(&EncPublicKey::from_bytes(v.enc_pub_bytes()), &dek, &v_ctx).unwrap();
        let v_grant = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: V_ID,
            recipient_type: RecipientType::User,
            dek_commit,
            granted_by: R_ID,
            created_at: NOW,
        };
        let v_grant_sig = r.signing_key().sign_canonical(labels::GRANT, &v_grant);

        let rw = b
            .wraps
            .iter()
            .find(|w| w.recipient_type == RecipientType::Recovery)
            .unwrap();
        let bundle = DownloadBundle {
            manifest_bytes: encode(&b.manifest),
            manifest_sig: b.manifest_sig,
            genesis_bytes: encode(&b.genesis),
            genesis_sig: b.genesis_sig,
            wrapped_dek: v_wrap,
            grant_bytes: encode(&v_grant),
            grant_sig: v_grant_sig,
            ancestor_grants: vec![(encode(&r_grant), r_grant_sig)],
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
        };
        (bundle, v, r)
    }

    #[test]
    fn reshared_recipient_chains_to_author_and_opens() {
        let built = build();
        let (bundle, v, r) = reshare_chain(&built);
        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == R_ID).then_some(r_pub);
        let owner_pub = built.owner.sig_pub_bytes();
        let vctx = VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: owner_pub,
            owner_sig_pub: owner_pub,
            recipient_id: V_ID,
            recipient_type: RecipientType::User,
            recipient_secret: v.enc_secret(),
            seen_max_version: None,
            granter_sig_pub: &resolver,
            tombstones: None,
            compromise: None,
        };
        let opened = verify_and_open(&vctx, &bundle).expect("re-shared read chains to author");
        let content = opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap();
        assert_eq!(
            content.plaintext,
            b"the quick brown fox jumps over the lazy dog"
        );
    }

    /// Build a V-recipient context whose resolver maps `R_ID` to `r`'s key.
    fn reshare_ctx<'a>(
        built: &'a Built,
        v: &'a Identity,
        resolver: &'a dyn Fn(Id) -> Option<[u8; 32]>,
    ) -> VerifyContext<'a> {
        let owner_pub = built.owner.sig_pub_bytes();
        VerifyContext {
            file_id: FILE_ID,
            author_sig_pub: owner_pub,
            owner_sig_pub: owner_pub,
            recipient_id: V_ID,
            recipient_type: RecipientType::User,
            recipient_secret: v.enc_secret(),
            seen_max_version: None,
            granter_sig_pub: resolver,
            tombstones: None,
            compromise: None,
        }
    }

    #[test]
    fn forged_ancestor_grant_signature_is_rejected() {
        let built = build();
        let (mut bundle, v, r) = reshare_chain(&built);
        bundle.ancestor_grants[0].1[0] ^= 0x01; // corrupt R's grant signature
        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == R_ID).then_some(r_pub);
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GrantSignature)
        );
    }

    #[test]
    fn broken_chain_with_missing_ancestor_is_rejected() {
        let built = build();
        let (mut bundle, v, r) = reshare_chain(&built);
        bundle.ancestor_grants.clear(); // R's grant withheld — chain cannot reach author
        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == R_ID).then_some(r_pub);
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GrantChainBroken)
        );
    }

    #[test]
    fn unresolvable_granter_key_is_rejected() {
        let built = build();
        let (bundle, v, _r) = reshare_chain(&built);
        let resolver = |_: Id| None; // R cannot be directory-verified
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GranterKeyUnknown)
        );
    }

    #[test]
    fn ancestor_grant_for_a_different_dek_is_rejected() {
        let built = build();
        let (mut bundle, v, r) = reshare_chain(&built);
        // Re-issue R's ancestor grant committing to the wrong DEK (a server
        // splicing a foreign grant into the chain) — caught before any sig use.
        let bad = Grant {
            file_id: FILE_ID,
            file_version: 1,
            recipient_id: R_ID,
            recipient_type: RecipientType::User,
            dek_commit: Bytes32([0xAB; 32]),
            granted_by: OWNER_ID,
            created_at: NOW,
        };
        bundle.ancestor_grants[0].0 = encode(&bad);
        let r_pub = r.sig_pub_bytes();
        let resolver = move |id: Id| (id == R_ID).then_some(r_pub);
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GrantMismatch("ancestor dek_commit"))
        );
    }

    #[test]
    fn cyclic_grant_chain_is_rejected() {
        let built = build();
        let dek_commit = built.bundle.manifest.dek_commit;
        let r = Identity::generate();
        let v = Identity::generate();
        let mk = |recipient: Id, granted_by: Id, signer: &Identity| {
            let g = Grant {
                file_id: FILE_ID,
                file_version: 1,
                recipient_id: recipient,
                recipient_type: RecipientType::User,
                dek_commit,
                granted_by,
                created_at: NOW,
            };
            let sig = signer.signing_key().sign_canonical(labels::GRANT, &g);
            (encode(&g), sig)
        };
        // leaf V←R, and ancestors R←V and V←R: granters cycle R→V→R.
        let (leaf_bytes, leaf_sig) = mk(V_ID, R_ID, &r);
        let a = mk(R_ID, V_ID, &v); // R's grant, signed by V
        let b = mk(V_ID, R_ID, &r); // V's grant, signed by R
        let bundle = DownloadBundle {
            manifest_bytes: encode(&built.bundle.manifest),
            manifest_sig: built.bundle.manifest_sig,
            genesis_bytes: encode(&built.bundle.genesis),
            genesis_sig: built.bundle.genesis_sig,
            wrapped_dek: WrappedDek { enc: [0; 32], ct: vec![0; 48] },
            grant_bytes: leaf_bytes,
            grant_sig: leaf_sig,
            ancestor_grants: vec![a, b],
            recovery_grant_bytes: vec![],
            recovery_grant_sig: [0; 64],
            streams: vec![],
        };
        let (r_pub, v_pub) = (r.sig_pub_bytes(), v.sig_pub_bytes());
        let resolver = move |id: Id| match id {
            x if x == R_ID => Some(r_pub),
            x if x == V_ID => Some(v_pub),
            _ => None,
        };
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GrantChainCycle)
        );
    }

    #[test]
    fn over_deep_grant_chain_is_rejected() {
        use std::collections::HashMap;
        let built = build();
        let dek_commit = built.bundle.manifest.dek_commit;
        // A chain of more re-share edges than the depth cap, none reaching the
        // author within the bound — must fail closed before exhausting it.
        let n = MAX_GRANT_CHAIN_DEPTH + 2;
        let nodes: Vec<Identity> = (0..=n).map(|_| Identity::generate()).collect();
        // Offset to avoid the all-zero RECOVERY_ID and the OWNER/R/V ids.
        let node_id = |i: usize| Id([(0x40 + i) as u8; 16]);
        let mk = |recipient: Id, granted_by: Id, signer: &Identity| {
            let g = Grant {
                file_id: FILE_ID,
                file_version: 1,
                recipient_id: recipient,
                recipient_type: RecipientType::User,
                dek_commit,
                granted_by,
                created_at: NOW,
            };
            let sig = signer.signing_key().sign_canonical(labels::GRANT, &g);
            (g, sig)
        };
        // leaf V←nodes[0]; ancestor i: nodes[i]←nodes[i+1].
        let (leaf_g, leaf_sig) = mk(V_ID, node_id(0), &nodes[0]);
        let mut ancestors = Vec::new();
        let mut keys: HashMap<Id, [u8; 32]> = HashMap::new();
        keys.insert(node_id(0), nodes[0].sig_pub_bytes());
        for i in 0..n {
            let (g, sig) = mk(node_id(i), node_id(i + 1), &nodes[i + 1]);
            ancestors.push((encode(&g), sig));
            keys.insert(node_id(i + 1), nodes[i + 1].sig_pub_bytes());
        }
        let bundle = DownloadBundle {
            manifest_bytes: encode(&built.bundle.manifest),
            manifest_sig: built.bundle.manifest_sig,
            genesis_bytes: encode(&built.bundle.genesis),
            genesis_sig: built.bundle.genesis_sig,
            wrapped_dek: WrappedDek { enc: [0; 32], ct: vec![0; 48] },
            grant_bytes: encode(&leaf_g),
            grant_sig: leaf_sig,
            ancestor_grants: ancestors,
            recovery_grant_bytes: vec![],
            recovery_grant_sig: [0; 64],
            streams: vec![],
        };
        let v = Identity::generate();
        let resolver = move |id: Id| keys.get(&id).copied();
        assert_eq!(
            verify_and_open(&reshare_ctx(&built, &v, &resolver), &bundle),
            Err(DownloadError::GrantChainTooDeep)
        );
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
            ancestor_grants: vec![],
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
            granter_sig_pub: &NO_GRANTERS,
            tombstones: None,
            compromise: None,
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
