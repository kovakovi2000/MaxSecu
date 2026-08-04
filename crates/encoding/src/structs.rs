//! The signed & hashed structures (encoding-spec §4). Each implements
//! [`Canonical`](crate::Canonical): a `u16 type_id` (§5 registry) followed by
//! its fields in the exact declared order.

use crate::error::DecodeError;
use crate::primitives::{Reader, Writer};
use crate::types::*;
use crate::{read_struct, Canonical};

/// ML-KEM-768 encapsulation (public) key size in bytes (Phase 7 / P7.3).
pub const MLKEM768_PUB_LEN: usize = 1184;

/// `dirbinding` — `0x0001` (DESIGN §7.1).
///
/// `mlkem_pub` (Phase 7, P7.3) is an **optional** ML-KEM-768 encapsulation key
/// carried after the v1 fields as a standard `option<MlKemPub>`: a 1-byte
/// presence flag (`0x00` absent / `0x01` present; any other byte →
/// [`DecodeError::InvalidPresenceByte`]) followed, when present, by the fixed
/// [`MLKEM768_PUB_LEN`]-byte key (no length prefix — the size is structural).
/// It is **not** part of the fingerprint (which stays
/// `SHA-256(canonical(enc_pub ‖ sig_pub))`, see [`FingerprintInput`]); the PQ
/// key is authenticated for free by the existing D5 Ed25519 signature over
/// `canonical(binding)`, which now covers the trailing field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirBinding {
    pub username: Text,
    pub user_id: Id,
    pub enc_pub: X25519Pub,
    pub sig_pub: Ed25519Pub,
    pub key_version: u64,
    pub roles: RoleSet,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
    /// Optional ML-KEM-768 encapsulation key (Suite::V2 enrollment, P7.4).
    pub mlkem_pub: Option<MlKemPub>,
}

impl Canonical for DirBinding {
    const TYPE_ID: u16 = 0x0001;
    fn encode_body(&self, w: &mut Writer) {
        self.username.put(w);
        self.user_id.put(w);
        self.enc_pub.put(w);
        self.sig_pub.put(w);
        self.key_version.put(w);
        self.roles.put(w);
        self.not_before.put(w);
        self.not_after.put(w);
        self.mlkem_pub.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(DirBinding {
            username: Text::get(r)?,
            user_id: Id::get(r)?,
            enc_pub: Bytes32::get(r)?,
            sig_pub: Bytes32::get(r)?,
            key_version: u64::get(r)?,
            roles: RoleSet::get(r)?,
            not_before: Timestamp::get(r)?,
            not_after: Timestamp::get(r)?,
            mlkem_pub: Option::<MlKemPub>::get(r)?,
        })
    }
}

/// `Stream` — `0x000D` (manifest sub-struct, DESIGN §13 / D33). Fixed 44 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub stream_type: StreamType,
    pub compression: Compression,
    pub chunk_count: u64,
    pub digest: Hash,
}

impl Canonical for Stream {
    const TYPE_ID: u16 = 0x000D;
    fn encode_body(&self, w: &mut Writer) {
        self.stream_type.put(w);
        self.compression.put(w);
        self.chunk_count.put(w);
        self.digest.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Stream {
            stream_type: StreamType::get(r)?,
            compression: Compression::get(r)?,
            chunk_count: u64::get(r)?,
            digest: Bytes32::get(r)?,
        })
    }
}

/// `manifest` — `0x0002` (DESIGN §12.3, multi-stream per D33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub file_id: Id,
    pub version: u64,
    pub file_type: FileType,
    pub alg: Suite,
    pub chunk_size: u32,
    pub dek_commit: Hash,
    /// Ascending and unique by `stream_type` (enforced on decode, V-13). Each
    /// element is emitted as a full `canonical(Stream)` (type_id ‖ body),
    /// count-prefixed by a `u8` (§4 / §2 `set`-style ordering).
    pub streams: Vec<Stream>,
    pub recovery_present: bool,
    pub author_id: Id,
    pub created_at: Timestamp,
}

impl Canonical for Manifest {
    const TYPE_ID: u16 = 0x0002;
    fn encode_body(&self, w: &mut Writer) {
        self.file_id.put(w);
        self.version.put(w);
        self.file_type.put(w);
        self.alg.put(w);
        self.chunk_size.put(w);
        self.dek_commit.put(w);
        w.u8(self.streams.len() as u8);
        for s in &self.streams {
            // Each element is canonical(Stream) = type_id ‖ body.
            w.u16(Stream::TYPE_ID);
            s.encode_body(w);
        }
        self.recovery_present.put(w);
        self.author_id.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        let file_id = Id::get(r)?;
        let version = u64::get(r)?;
        let file_type = FileType::get(r)?;
        let alg = Suite::get(r)?;
        let chunk_size = u32::get(r)?;
        let dek_commit = Bytes32::get(r)?;
        let count = r.u8()? as usize;
        let mut streams = Vec::with_capacity(count);
        let mut prev: Option<u8> = None;
        for _ in 0..count {
            let s = read_struct::<Stream>(r)?;
            let st = s.stream_type as u8;
            if let Some(p) = prev {
                if st <= p {
                    // Not strictly ascending ⇒ unsorted or duplicate (V-13).
                    return Err(DecodeError::StreamsNotAscending);
                }
            }
            prev = Some(st);
            streams.push(s);
        }
        // Canonicalize so the master re-encode guard (§7 rule 5) backstops the
        // strictly-ascending check above: a non-canonical (mis-ordered or
        // duplicate) stream list decodes to this sorted/deduped form, re-encodes
        // differently, and is rejected as NonCanonical even if the explicit
        // check regressed. No-op on valid input.
        streams.sort_by_key(|s| s.stream_type as u8);
        streams.dedup_by_key(|s| s.stream_type as u8);
        Ok(Manifest {
            file_id,
            version,
            file_type,
            alg,
            chunk_size,
            dek_commit,
            streams,
            recovery_present: bool::get(r)?,
            author_id: Id::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `grant` (read-grant) — `0x0003` (DESIGN §12.3a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub file_id: Id,
    pub file_version: u64,
    pub recipient_id: Id,
    pub recipient_type: RecipientType,
    pub dek_commit: Hash,
    pub granted_by: Id,
    pub created_at: Timestamp,
}

impl Canonical for Grant {
    const TYPE_ID: u16 = 0x0003;
    fn encode_body(&self, w: &mut Writer) {
        self.file_id.put(w);
        self.file_version.put(w);
        self.recipient_id.put(w);
        self.recipient_type.put(w);
        self.dek_commit.put(w);
        self.granted_by.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        let file_id = Id::get(r)?;
        let file_version = u64::get(r)?;
        let recipient_id = Id::get(r)?;
        let recipient_type = RecipientType::get(r)?;
        // §7 rule 4 / V-11: recovery recipient ⇒ recipient_id == RECOVERY_ID.
        if recipient_type == RecipientType::Recovery && recipient_id != crate::RECOVERY_ID {
            return Err(DecodeError::RecoveryIdMismatch);
        }
        Ok(Grant {
            file_id,
            file_version,
            recipient_id,
            recipient_type,
            dek_commit: Bytes32::get(r)?,
            granted_by: Id::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `genesis` — `0x0005` (DESIGN §11.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub file_id: Id,
    pub owner_id: Id,
    pub owner_key_version: u64,
    pub created_at: Timestamp,
}

impl Canonical for Genesis {
    const TYPE_ID: u16 = 0x0005;
    fn encode_body(&self, w: &mut Writer) {
        self.file_id.put(w);
        self.owner_id.put(w);
        self.owner_key_version.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Genesis {
            file_id: Id::get(r)?,
            owner_id: Id::get(r)?,
            owner_key_version: u64::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `revocation` (tombstone) — `0x0006` (DESIGN §11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub scope: FileScope,
    pub revoked_user_id: Id,
    /// Absent = full-access revoke; present = role-narrowing (DESIGN §7.6).
    pub revoked_capability: Option<Role>,
    pub from_version: u64,
    pub revocation_epoch: u64,
    pub prev_head: Hash,
    pub issued_by: Id,
    /// Absent for single-file; present for mass/`*` dual control.
    pub co_signed_by: Option<Id>,
    pub created_at: Timestamp,
}

impl Canonical for Revocation {
    const TYPE_ID: u16 = 0x0006;
    fn encode_body(&self, w: &mut Writer) {
        self.scope.put(w);
        self.revoked_user_id.put(w);
        self.revoked_capability.put(w);
        self.from_version.put(w);
        self.revocation_epoch.put(w);
        self.prev_head.put(w);
        self.issued_by.put(w);
        self.co_signed_by.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Revocation {
            scope: FileScope::get(r)?,
            revoked_user_id: Id::get(r)?,
            revoked_capability: Option::<Role>::get(r)?,
            from_version: u64::get(r)?,
            revocation_epoch: u64::get(r)?,
            prev_head: Bytes32::get(r)?,
            issued_by: Id::get(r)?,
            co_signed_by: Option::<Id>::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `reinstatement` — `0x0007` (DESIGN §11.5a). `co_signed_by` is required —
/// reinstatement is always dual-controlled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reinstatement {
    pub scope: FileScope,
    pub reinstated_user_id: Id,
    pub supersedes_epoch: u64,
    pub reinstatement_epoch: u64,
    pub prev_head: Hash,
    pub issued_by: Id,
    pub co_signed_by: Id,
    pub created_at: Timestamp,
}

impl Canonical for Reinstatement {
    const TYPE_ID: u16 = 0x0007;
    fn encode_body(&self, w: &mut Writer) {
        self.scope.put(w);
        self.reinstated_user_id.put(w);
        self.supersedes_epoch.put(w);
        self.reinstatement_epoch.put(w);
        self.prev_head.put(w);
        self.issued_by.put(w);
        self.co_signed_by.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Reinstatement {
            scope: FileScope::get(r)?,
            reinstated_user_id: Id::get(r)?,
            supersedes_epoch: u64::get(r)?,
            reinstatement_epoch: u64::get(r)?,
            prev_head: Bytes32::get(r)?,
            issued_by: Id::get(r)?,
            co_signed_by: Id::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `key_compromise` — `0x0008` (DESIGN §11.7 / D28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCompromise {
    pub user_id: Id,
    pub key_version: u64,
    pub effective_from: Timestamp,
    pub prev_head: Hash,
    pub issued_by: Id,
    pub co_signed_by: Id,
    pub created_at: Timestamp,
}

impl Canonical for KeyCompromise {
    const TYPE_ID: u16 = 0x0008;
    fn encode_body(&self, w: &mut Writer) {
        self.user_id.put(w);
        self.key_version.put(w);
        self.effective_from.put(w);
        self.prev_head.put(w);
        self.issued_by.put(w);
        self.co_signed_by.put(w);
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(KeyCompromise {
            user_id: Id::get(r)?,
            key_version: u64::get(r)?,
            effective_from: Timestamp::get(r)?,
            prev_head: Bytes32::get(r)?,
            issued_by: Id::get(r)?,
            co_signed_by: Id::get(r)?,
            created_at: Timestamp::get(r)?,
        })
    }
}

/// `auth_proof_context` — `0x0009` (DESIGN §9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProofContext {
    pub server_id: Text,
    pub tls_exporter: Bytes32,
    pub nonce: Bytes32,
    pub timestamp: Timestamp,
}

impl Canonical for AuthProofContext {
    const TYPE_ID: u16 = 0x0009;
    fn encode_body(&self, w: &mut Writer) {
        self.server_id.put(w);
        self.tls_exporter.put(w);
        self.nonce.put(w);
        self.timestamp.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(AuthProofContext {
            server_id: Text::get(r)?,
            tls_exporter: Bytes32::get(r)?,
            nonce: Bytes32::get(r)?,
            timestamp: Timestamp::get(r)?,
        })
    }
}

/// `wrap_context` (HPKE `info`) — `0x000A` (DESIGN §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapContext {
    pub file_id: Id,
    pub version: u64,
    pub recipient_id: Id,
}

impl Canonical for WrapContext {
    const TYPE_ID: u16 = 0x000A;
    fn encode_body(&self, w: &mut Writer) {
        self.file_id.put(w);
        self.version.put(w);
        self.recipient_id.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(WrapContext {
            file_id: Id::get(r)?,
            version: u64::get(r)?,
            recipient_id: Id::get(r)?,
        })
    }
}

/// `chunk_aad` — `0x000B` (DESIGN §12.10, per-stream per D33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAad {
    pub file_id: Id,
    pub version: u64,
    pub stream_type: StreamType,
    pub chunk_index: u64,
    pub is_last: bool,
}

impl Canonical for ChunkAad {
    const TYPE_ID: u16 = 0x000B;
    fn encode_body(&self, w: &mut Writer) {
        self.file_id.put(w);
        self.version.put(w);
        self.stream_type.put(w);
        self.chunk_index.put(w);
        self.is_last.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(ChunkAad {
            file_id: Id::get(r)?,
            version: u64::get(r)?,
            stream_type: StreamType::get(r)?,
            chunk_index: u64::get(r)?,
            is_last: bool::get(r)?,
        })
    }
}

/// `fingerprint_input` — `0x000C` (DESIGN §7.1).
/// `fingerprint = SHA-256(canonical(fingerprint_input))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintInput {
    pub enc_pub: X25519Pub,
    pub sig_pub: Ed25519Pub,
}

impl Canonical for FingerprintInput {
    const TYPE_ID: u16 = 0x000C;
    fn encode_body(&self, w: &mut Writer) {
        self.enc_pub.put(w);
        self.sig_pub.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(FingerprintInput {
            enc_pub: Bytes32::get(r)?,
            sig_pub: Bytes32::get(r)?,
        })
    }
}

/// `BundleMember` — one entry of a [`BundleBody`]: a referenced file's id and
/// its type. Not a top-level [`Canonical`] struct — it has no `type_id` of its
/// own and is only ever emitted inline as a fixed 17-byte field (16-byte
/// `file_id` ‖ 1-byte `file_type`) within the bundle body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMember {
    pub file_id: Id,
    pub file_type: FileType,
}

/// `bundle_body` — `0x000E`. The encrypted, author-signed **content** stream of
/// a bundle file: an ordered list of member files. Order is authoritative and
/// preserved verbatim (unlike a manifest's `set`-style streams) — the codec
/// neither sorts nor de-duplicates. The count is a `u16` length prefix so a
/// bundle may carry more than 255 members. Minimum-member and other policy
/// checks belong to higher layers, not this codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleBody {
    pub members: Vec<BundleMember>,
}

impl Canonical for BundleBody {
    const TYPE_ID: u16 = 0x000E;
    fn encode_body(&self, w: &mut Writer) {
        debug_assert!(self.members.len() <= u16::MAX as usize);
        w.u16(self.members.len() as u16);
        for m in &self.members {
            m.file_id.put(w);
            m.file_type.put(w);
        }
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        let count = r.u16()? as usize;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let file_id = Id::get(r)?;
            let file_type = FileType::get(r)?;
            members.push(BundleMember { file_id, file_type });
        }
        Ok(BundleBody { members })
    }
}

/// Smallest an encoded [`BackupEntry`] can be: an empty `path` (its 4-byte
/// length prefix still costs) ‖ `len` ‖ `digest`. The floor an untrusted entry
/// count is capped against before anything is reserved.
const BACKUP_ENTRY_MIN_LEN: usize = 4 + 8 + 32;

/// Encoded size of a [`BackupPart`] — fixed: `len` ‖ `digest`.
const BACKUP_PART_LEN: usize = 8 + 32;

/// `BackupEntry` — one file carried by a [`BackupIndex`]: its bundle-relative
/// path, plaintext length, and content digest. Not a top-level [`Canonical`]
/// struct — it has no `type_id` of its own and is only ever emitted inline
/// within the index body.
///
/// There is deliberately **no `offset`**: a bundle's payload is the
/// concatenation of its entries' bytes in `entries` order, so an entry's offset
/// is the running sum of the preceding `len`s. Storing it as well would be a
/// second source of truth that can disagree with the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEntry {
    /// Bundle-relative POSIX path, e.g. `tls/key.der`. Path *policy* — traversal,
    /// absolute roots, reserved names — belongs to the restorer that will create
    /// these files, not to this codec.
    pub path: Text,
    /// Plaintext byte length of the entry's content.
    pub len: u64,
    /// `SHA-256` over the entry's plaintext bytes.
    pub digest: Hash,
}

/// `BackupPart` — one sealed `MXBU` part of a backup bundle. Inline like
/// [`BackupEntry`]. A part's index is its **position** in [`BackupIndex::parts`],
/// which is exactly what the seal binds into each part's AEAD AAD; storing the
/// index here too would let the two disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPart {
    /// Byte length of the stored part blob (`MXBU` header ‖ ciphertext ‖ tag).
    pub len: u64,
    /// `SHA-256` over those same stored bytes — checkable straight off the cold
    /// tier, before a passphrase has been asked for or Argon2id has run.
    pub digest: Hash,
}

/// `backup_index` — `0x000F`. The authenticated table of contents of one sealed
/// server-backup bundle (`MXBU`, `crates/server/src/backup/format.rs`): what the
/// bundle holds and which parts carry it.
///
/// It exists because a bundle needs a tar and this repo has no archive crate —
/// and because `_backup/<stamp>/manifest.json` is a **plaintext hint** that
/// anyone holding the Dropbox account can rewrite. This is its authenticated
/// counterpart: it rides inside the sealed bytes, so the `git_sha`, the entry
/// table and the part digests are all covered by the bundle's AEAD tags. Restore
/// compares hint against index and aborts when they disagree.
///
/// **Metadata only — never a part's payload.** [`decode`](crate::decode) runs the
/// §7 rule-5 re-encode guard, which allocates a complete second copy of its
/// input; an embedded N-byte payload would therefore cost ~3N and destroy the
/// O(part size) RAM budget the part-at-a-time format exists to provide.
///
/// The `db` and `state` bundles share this one structure and carry **no
/// component tag**: they are sealed independently under fresh per-bundle salts,
/// so neither's parts can open under the other's key, and which one is in hand is
/// the cold-tier path it came from. A tag would mean a new frozen enum registry
/// for a distinction the key already makes.
///
/// Both counts are `u32`, not [`BundleBody`]'s `u16`: `part_index` is a `u32` in
/// the part AAD, so a `u16` ceiling here would cap a bundle at 65 535 parts
/// (~512 GiB at the 8 MiB part size) — a limit the sealed format does not have.
/// Order is authoritative and preserved verbatim; the codec neither sorts nor
/// de-duplicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupIndex {
    /// The commit the backed-up server was built from — what a `--only code`
    /// rollback checks out. Free-form `text` rather than 20 fixed bytes so a
    /// SHA-256 object id, or a `-dirty` marker, needs no format break.
    pub git_sha: Text,
    /// The bundle's files, in payload order.
    pub entries: Vec<BackupEntry>,
    /// The bundle's sealed parts, in `part_index` order.
    pub parts: Vec<BackupPart>,
    pub created_at: Timestamp,
}

impl Canonical for BackupIndex {
    const TYPE_ID: u16 = 0x000F;
    fn encode_body(&self, w: &mut Writer) {
        self.git_sha.put(w);
        debug_assert!(self.entries.len() <= u32::MAX as usize);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            e.path.put(w);
            e.len.put(w);
            e.digest.put(w);
        }
        debug_assert!(self.parts.len() <= u32::MAX as usize);
        w.u32(self.parts.len() as u32);
        for p in &self.parts {
            p.len.put(w);
            p.digest.put(w);
        }
        self.created_at.put(w);
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        let git_sha = Text::get(r)?;
        // Both counts are attacker-controlled and — unlike `BundleBody`'s u16 —
        // can claim 4 G elements. Cap each reservation at what the remaining
        // input could actually hold, so a lying count costs a bounded reserve and
        // then dies on the read it cannot satisfy, rather than reserving
        // gigabytes before the first byte of an element is looked at.
        let entry_count = r.u32()? as usize;
        let mut entries = Vec::with_capacity(entry_count.min(r.remaining() / BACKUP_ENTRY_MIN_LEN));
        for _ in 0..entry_count {
            entries.push(BackupEntry {
                path: Text::get(r)?,
                len: u64::get(r)?,
                digest: Bytes32::get(r)?,
            });
        }
        let part_count = r.u32()? as usize;
        let mut parts = Vec::with_capacity(part_count.min(r.remaining() / BACKUP_PART_LEN));
        for _ in 0..part_count {
            parts.push(BackupPart {
                len: u64::get(r)?,
                digest: Bytes32::get(r)?,
            });
        }
        Ok(BackupIndex {
            git_sha,
            entries,
            parts,
            created_at: Timestamp::get(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, encode};

    #[test]
    fn bundle_body_roundtrips_and_preserves_order() {
        let body = BundleBody {
            members: vec![
                BundleMember {
                    file_id: Id([0x01; 16]),
                    file_type: FileType::Video,
                },
                BundleMember {
                    file_id: Id([0x02; 16]),
                    file_type: FileType::Image,
                },
                BundleMember {
                    file_id: Id([0x03; 16]),
                    file_type: FileType::Generic,
                },
            ],
        };
        let bytes = encode(&body);
        let back: BundleBody = decode(&bytes).unwrap();
        assert_eq!(back.members.len(), 3);
        assert_eq!(back.members[0].file_type, FileType::Video);
        assert_eq!(back.members[2].file_id, Id([0x03; 16]));
        assert_eq!(back.members[1].file_id, Id([0x02; 16])); // order is authoritative
    }

    #[test]
    fn bundle_body_over_255_members_pins_u16_width_and_keeps_dups() {
        // 300 members forces the count past a u8 ceiling: a regression to a u8
        // length prefix would truncate/corrupt here. Two identical members lock
        // in the deliberate no-dedup behavior.
        let mut members: Vec<BundleMember> = (0..300)
            .map(|i| BundleMember {
                file_id: Id([i as u8; 16]),
                file_type: FileType::Video,
            })
            .collect();
        // Overwrite two entries to be byte-identical (same id + type).
        members[10] = BundleMember {
            file_id: Id([0xAB; 16]),
            file_type: FileType::Image,
        };
        members[11] = BundleMember {
            file_id: Id([0xAB; 16]),
            file_type: FileType::Image,
        };
        let body = BundleBody { members };
        let bytes = encode(&body);
        let back: BundleBody = decode(&bytes).unwrap();
        assert_eq!(back.members.len(), 300);
        // First/last survive in order.
        assert_eq!(back.members[0].file_id, Id([0x00; 16]));
        assert_eq!(back.members[299].file_id, Id([(299u16 as u8); 16]));
        // Both identical members survive (no dedup).
        assert_eq!(back.members[10], back.members[11]);
        assert_eq!(back.members[10].file_id, Id([0xAB; 16]));
        assert_eq!(back.members[10].file_type, FileType::Image);
    }

    #[test]
    fn bundle_body_empty_roundtrips() {
        let body = BundleBody { members: vec![] };
        let bytes = encode(&body);
        // type_id (2) + u16 count (2), no member bytes.
        assert_eq!(bytes.len(), 4);
        let back: BundleBody = decode(&bytes).unwrap();
        assert!(back.members.is_empty());
    }

    fn backup_index() -> BackupIndex {
        BackupIndex {
            git_sha: Text::new("37283fdd1c9e4a0b").unwrap(),
            entries: vec![
                BackupEntry {
                    path: Text::new("etc/maxsecu/dropbox.env").unwrap(),
                    len: 240,
                    digest: Bytes32([0xA1; 32]),
                },
                BackupEntry {
                    path: Text::new("tls/key.der").unwrap(),
                    len: 1218,
                    digest: Bytes32([0xA2; 32]),
                },
            ],
            parts: vec![
                BackupPart {
                    len: 8 * 1024 * 1024 + 61,
                    digest: Bytes32([0xB1; 32]),
                },
                BackupPart {
                    len: 4096,
                    digest: Bytes32([0xB2; 32]),
                },
            ],
            created_at: Timestamp(1_752_624_000_000),
        }
    }

    #[test]
    fn backup_index_roundtrips_and_preserves_order() {
        let idx = backup_index();
        let bytes = encode(&idx);
        let back: BackupIndex = decode(&bytes).unwrap();
        assert_eq!(back, idx);
        // Order is authoritative for both lists: an entry's offset is the running
        // sum of its predecessors' `len`, and a part's index is its position.
        assert_eq!(back.entries[0].path.as_str(), "etc/maxsecu/dropbox.env");
        assert_eq!(back.parts[1].len, 4096);
    }

    #[test]
    fn backup_index_empty_roundtrips() {
        let idx = BackupIndex {
            git_sha: Text::new("").unwrap(),
            entries: vec![],
            parts: vec![],
            created_at: Timestamp(0),
        };
        let bytes = encode(&idx);
        // type_id (2) + text len (4) + entry count (4) + part count (4) + created_at (8).
        assert_eq!(bytes.len(), 22);
        let back: BackupIndex = decode(&bytes).unwrap();
        assert_eq!(back, idx);
    }

    #[test]
    fn backup_index_over_65535_parts_pins_the_u32_count_width() {
        // A u16 part count would cap a bundle at 65_535 parts (~512 GiB at the
        // 8 MiB part size) while `part_index` in the AEAD's part AAD is a u32 —
        // a regression to u16 here would truncate the count and silently drop
        // every part past the ceiling.
        let n = 70_000u32;
        let idx = BackupIndex {
            git_sha: Text::new("wide").unwrap(),
            entries: vec![],
            parts: (0..n)
                .map(|i| BackupPart {
                    len: i as u64,
                    digest: Bytes32([i as u8; 32]),
                })
                .collect(),
            created_at: Timestamp(7),
        };
        let bytes = encode(&idx);
        let back: BackupIndex = decode(&bytes).unwrap();
        assert_eq!(back.parts.len(), n as usize);
        assert_eq!(back.parts[69_999].len, 69_999);
    }

    #[test]
    fn backup_index_lying_counts_fail_closed() {
        // A u32 count can claim 4 G elements. The decoder must reject on the
        // reads it cannot satisfy — and must not reserve on the claim first.
        let mut w = Writer::new();
        w.u16(BackupIndex::TYPE_ID);
        w.text("");
        w.u32(u32::MAX); // entry_count
        assert!(matches!(
            decode::<BackupIndex>(&w.into_bytes()),
            Err(DecodeError::ShortInput { .. })
        ));

        let mut w = Writer::new();
        w.u16(BackupIndex::TYPE_ID);
        w.text("");
        w.u32(0); // no entries
        w.u32(u32::MAX); // part_count
        assert!(matches!(
            decode::<BackupIndex>(&w.into_bytes()),
            Err(DecodeError::ShortInput { .. })
        ));
    }

    #[test]
    fn backup_index_type_id_is_registered() {
        // `is_registered` is a hand-maintained `matches!` list with no
        // exhaustiveness check, so nothing but this test notices a missed entry:
        // an unregistered 0x000F would report UnknownTypeId here instead.
        assert_eq!(
            decode::<BundleBody>(&[0x00, 0x0F]),
            Err(DecodeError::WrongTypeId {
                expected: 0x000E,
                got: 0x000F
            })
        );
    }
}
