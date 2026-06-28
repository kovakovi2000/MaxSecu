//! Domain / identifier types (encoding-spec §3) and the internal `Field` trait
//! that composes them into the signed/hashed structures of §4.
//!
//! Each `Field` is responsible for its own strict decode rules — unknown enum
//! codepoints, non-ascending sets, malformed `FileScope`, the recovery-id
//! binding, etc. — so the structures in `structs.rs` read as a flat field list.

use crate::error::DecodeError;
use crate::primitives::{to_nfc, Reader, Writer};
use crate::MAX_TEXT;

/// A field that has exactly one canonical byte form.
pub(crate) trait Field: Sized {
    fn put(&self, w: &mut Writer);
    fn get(r: &mut Reader) -> Result<Self, DecodeError>;
}

// ---- integers & bool ----

impl Field for u8 {
    fn put(&self, w: &mut Writer) {
        w.u8(*self);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        r.u8()
    }
}
impl Field for u16 {
    fn put(&self, w: &mut Writer) {
        w.u16(*self);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        r.u16()
    }
}
impl Field for u32 {
    fn put(&self, w: &mut Writer) {
        w.u32(*self);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        r.u32()
    }
}
impl Field for u64 {
    fn put(&self, w: &mut Writer) {
        w.u64(*self);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        r.u64()
    }
}
impl Field for bool {
    fn put(&self, w: &mut Writer) {
        w.bool(*self);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        r.bool()
    }
}

/// `option<T>` (encoding-spec §2): presence byte `0x00` (absent) or `0x01` ‖ T.
impl<T: Field> Field for Option<T> {
    fn put(&self, w: &mut Writer) {
        match self {
            None => w.u8(0x00),
            Some(v) => {
                w.u8(0x01);
                v.put(w);
            }
        }
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x00 => Ok(None),
            0x01 => Ok(Some(T::get(r)?)),
            other => Err(DecodeError::InvalidPresenceByte(other)),
        }
    }
}

// ---- identifiers & fixed byte strings ----

/// 128-bit identifier (`user_id`/`file_id`/`granted_by`/…), `bytes_fixed(16)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(pub [u8; 16]);

impl Field for Id {
    fn put(&self, w: &mut Writer) {
        w.fixed(&self.0);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Id(r.fixed::<16>()?))
    }
}

/// A raw 32-byte value: a public key (`X25519Pub`/`Ed25519Pub`), a SHA-256
/// `Hash`, or a fixed nonce/exporter. `bytes_fixed(32)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; 32]);

impl Field for Bytes32 {
    fn put(&self, w: &mut Writer) {
        w.fixed(&self.0);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Bytes32(r.fixed::<32>()?))
    }
}

/// Logical aliases — identical 32-byte wire form, distinguished only for
/// readability of the structure definitions (encoding-spec §3).
pub type X25519Pub = Bytes32;
pub type Ed25519Pub = Bytes32;
pub type Hash = Bytes32;

/// Milliseconds since the Unix epoch, UTC (`u64`). Informational except for the
/// coarse identity lifetime on `dirbinding`; never a freshness basis (§3 note).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub u64);

impl Field for Timestamp {
    fn put(&self, w: &mut Writer) {
        w.u64(self.0);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Timestamp(r.u64()?))
    }
}

/// NFC-normalized, length-bounded UTF-8 text (`text`, encoding-spec §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text(String);

impl Text {
    /// Build a `Text`, normalizing to NFC and enforcing `MAX_TEXT` so that
    /// `encode` always emits the one canonical form. Rejects over-long input.
    pub fn new(s: &str) -> Result<Text, DecodeError> {
        let n = to_nfc(s);
        if n.len() > MAX_TEXT {
            return Err(DecodeError::TextTooLong {
                len: n.len(),
                max: MAX_TEXT,
            });
        }
        Ok(Text(n))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Field for Text {
    fn put(&self, w: &mut Writer) {
        w.text(&self.0);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Text(r.text()?))
    }
}

// ---- enums (encoding-spec §3) ----

/// `FileScope` (§3): a specific file or the account-wide `*` sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileScope {
    Specific(Id),
    AccountWide,
}

impl Field for FileScope {
    fn put(&self, w: &mut Writer) {
        match self {
            FileScope::Specific(id) => {
                w.u8(0x01);
                id.put(w);
            }
            FileScope::AccountWide => w.u8(0x02),
        }
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x01 => Ok(FileScope::Specific(Id::get(r)?)),
            0x02 => Ok(FileScope::AccountWide),
            other => Err(DecodeError::UnknownEnum {
                kind: "FileScope",
                value: other as u32,
            }),
        }
    }
}

/// `Suite` (§3): the algorithm-agility identifier, `enum16`. `0x0001` is the v1
/// suite; `0x0002` adds the X25519+ML-KEM-768 hybrid KEM (Phase 7). Unknown /
/// below-floor suites are rejected (DESIGN §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// {AEAD AES-256-GCM, KDF HKDF-SHA256, KEM X25519, SIG Ed25519, PWKDF Argon2id}
    V1,
    /// {AEAD AES-256-GCM, KDF HKDF-SHA256, KEM X25519+ML-KEM-768 hybrid,
    /// SIG Ed25519, PWKDF Argon2id} — the PQ-hybrid wrap suite (Phase 7).
    V2,
}

impl Field for Suite {
    fn put(&self, w: &mut Writer) {
        match self {
            Suite::V1 => w.u16(0x0001),
            Suite::V2 => w.u16(0x0002),
        }
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u16()? {
            0x0001 => Ok(Suite::V1),
            0x0002 => Ok(Suite::V2),
            other => Err(DecodeError::UnknownEnum {
                kind: "Suite",
                value: other as u32,
            }),
        }
    }
}

/// `Role` (§3), `enum8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    User = 0x01,
    Admin = 0x02,
}

impl Field for Role {
    fn put(&self, w: &mut Writer) {
        w.u8(*self as u8);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x01 => Ok(Role::User),
            0x02 => Ok(Role::Admin),
            other => Err(DecodeError::UnknownEnum {
                kind: "Role",
                value: other as u32,
            }),
        }
    }
}

/// `set<Role>` (§2): `u8 count` ‖ codepoints in strictly ascending order. The
/// ascending rule rejects both unsorted sets and duplicates in one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleSet(Vec<Role>);

impl RoleSet {
    /// Build from any iterable, sorting + de-duplicating so the value has the
    /// one canonical form. (Construction-side convenience; the wire form is the
    /// authority and is re-checked on decode.)
    pub fn new(roles: impl IntoIterator<Item = Role>) -> RoleSet {
        let mut v: Vec<Role> = roles.into_iter().collect();
        v.sort();
        v.dedup();
        RoleSet(v)
    }

    pub fn roles(&self) -> &[Role] {
        &self.0
    }
}

impl Field for RoleSet {
    fn put(&self, w: &mut Writer) {
        w.u8(self.0.len() as u8);
        for r in &self.0 {
            r.put(w);
        }
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        const REGISTRY_SIZE: usize = 2; // |{User, Admin}|
        let count = r.u8()? as usize;
        if count > REGISTRY_SIZE {
            return Err(DecodeError::SetTooLong {
                count,
                max: REGISTRY_SIZE,
            });
        }
        let mut roles = Vec::with_capacity(count);
        let mut prev: Option<u8> = None;
        for _ in 0..count {
            let role = Role::get(r)?;
            let cp = role as u8;
            if let Some(p) = prev {
                if cp <= p {
                    return Err(DecodeError::SetNotAscending);
                }
            }
            prev = Some(cp);
            roles.push(role);
        }
        // Canonicalize the stored value so the master re-encode guard (§7 rule 5)
        // is a *real* backstop: if the strictly-ascending check above were ever
        // removed, a non-canonical input would decode to this sorted/deduped
        // value, re-encode to different bytes, and be rejected as NonCanonical.
        // On valid (already strictly-ascending) input this is a no-op.
        roles.sort();
        roles.dedup();
        Ok(RoleSet(roles))
    }
}

/// `RecipientType` (§3), `enum8`. When `recovery`, the paired `recipient_id`
/// MUST be `RECOVERY_ID` — enforced by the `grant` decoder (§4 / §7 rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecipientType {
    User = 0x01,
    Recovery = 0x02,
}

impl Field for RecipientType {
    fn put(&self, w: &mut Writer) {
        w.u8(*self as u8);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x01 => Ok(RecipientType::User),
            0x02 => Ok(RecipientType::Recovery),
            other => Err(DecodeError::UnknownEnum {
                kind: "RecipientType",
                value: other as u32,
            }),
        }
    }
}

/// `StreamType` (§3), `enum8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    Content = 0x01,
    Metadata = 0x02,
    Thumbnail = 0x03,
    Preview = 0x04,
}

impl Field for StreamType {
    fn put(&self, w: &mut Writer) {
        w.u8(*self as u8);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x01 => Ok(StreamType::Content),
            0x02 => Ok(StreamType::Metadata),
            0x03 => Ok(StreamType::Thumbnail),
            0x04 => Ok(StreamType::Preview),
            other => Err(DecodeError::UnknownEnum {
                kind: "StreamType",
                value: other as u32,
            }),
        }
    }
}

/// `Compression` (§3), `enum8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    None = 0x00,
    Zstd = 0x01,
}

impl Field for Compression {
    fn put(&self, w: &mut Writer) {
        w.u8(*self as u8);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x00 => Ok(Compression::None),
            0x01 => Ok(Compression::Zstd),
            other => Err(DecodeError::UnknownEnum {
                kind: "Compression",
                value: other as u32,
            }),
        }
    }
}

/// `FileType` (§3), `enum8`. Server-visible **and** authenticated listing key
/// (DESIGN §13 / D35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileType {
    Video = 0x01,
    Image = 0x02,
    Blog = 0x03,
}

impl Field for FileType {
    fn put(&self, w: &mut Writer) {
        w.u8(*self as u8);
    }
    fn get(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8()? {
            0x01 => Ok(FileType::Video),
            0x02 => Ok(FileType::Image),
            0x03 => Ok(FileType::Blog),
            other => Err(DecodeError::UnknownEnum {
                kind: "FileType",
                value: other as u32,
            }),
        }
    }
}
