//! The signed & hashed structures (encoding-spec §4). Each implements
//! [`Canonical`](crate::Canonical): a `u16 type_id` (§5 registry) followed by
//! its fields in the exact declared order.

use crate::error::DecodeError;
use crate::primitives::{Reader, Writer};
use crate::types::*;
use crate::{read_struct, Canonical};

/// ML-KEM-768 encapsulation (public) key size in bytes (Phase 7 / P7.2).
pub const MLKEM768_PUB_LEN: usize = 1184;

/// `dirbinding` — `0x0001` (DESIGN §7.1).
///
/// `mlkem_pub` (Phase 7, P7.3) is an **optional** ML-KEM-768 encapsulation key
/// carried after the v1 fields, wire-encoded as a 1-byte presence flag
/// (`0x00` absent / `0x01` present) followed, when present, by the fixed
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
    pub mlkem_pub: Option<[u8; MLKEM768_PUB_LEN]>,
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
        // Optional PQ key: presence flag then, if present, the fixed-width key.
        // Hand-rolled (not the generic `Option<T>` Field) because the payload is
        // a 1184-byte array emitted via `fixed` with no length prefix, mirroring
        // how `enc_pub`/`sig_pub` are written.
        match &self.mlkem_pub {
            None => w.u8(0x00),
            Some(key) => {
                w.u8(0x01);
                w.fixed(key);
            }
        }
    }
    fn decode_body(r: &mut Reader) -> Result<Self, DecodeError> {
        let username = Text::get(r)?;
        let user_id = Id::get(r)?;
        let enc_pub = Bytes32::get(r)?;
        let sig_pub = Bytes32::get(r)?;
        let key_version = u64::get(r)?;
        let roles = RoleSet::get(r)?;
        let not_before = Timestamp::get(r)?;
        let not_after = Timestamp::get(r)?;
        let mlkem_pub = match r.u8()? {
            0x00 => None,
            0x01 => Some(r.fixed::<MLKEM768_PUB_LEN>()?),
            other => {
                return Err(DecodeError::UnknownEnum {
                    kind: "PqPresence",
                    value: other as u32,
                })
            }
        };
        Ok(DirBinding {
            username,
            user_id,
            enc_pub,
            sig_pub,
            key_version,
            roles,
            not_before,
            not_after,
            mlkem_pub,
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
