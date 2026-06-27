//! Decode errors. Every variant is a *hard reject* — the decoder is fail-closed
//! (encoding-spec §1 invariant 5, §7). There is no best-effort parse.

use core::fmt;

/// Why a byte string was rejected by the strict decoder.
///
/// The decoder never returns a partially-parsed value; any deviation from the
/// one canonical form yields one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes remained than a fixed-width field required (§2).
    ShortInput { needed: usize, remaining: usize },
    /// Input was not fully consumed after the top-level struct (§7 rule 2).
    TrailingBytes { remaining: usize },
    /// A `bool` byte was neither `0x00` nor `0x01` (§2).
    InvalidBool(u8),
    /// A `bytes_var`/`text` length prefix exceeded the remaining input (§2).
    LengthOverrun { len: u64, remaining: usize },
    /// `text` was not valid UTF-8 (§2).
    InvalidUtf8,
    /// `text` bytes differed from their NFC-normalized form (§2).
    NonNfcText,
    /// `text` exceeded `MAX_TEXT` NFC bytes (§2).
    TextTooLong { len: usize, max: usize },
    /// An `enum8`/`enum16` codepoint was not in its registry (§2).
    UnknownEnum { kind: &'static str, value: u32 },
    /// A `set<enum8>` was not strictly ascending — unsorted or duplicate (§2).
    SetNotAscending,
    /// A `set` count exceeded the registry size (§2).
    SetTooLong { count: usize, max: usize },
    /// An `option` presence byte was neither `0x00` nor `0x01` (§2).
    InvalidPresenceByte(u8),
    /// The struct `type_id` was not in the registry (§5).
    UnknownTypeId(u16),
    /// The struct `type_id` did not match the type being decoded (§5, §7 rule).
    WrongTypeId { expected: u16, got: u16 },
    /// A `FileScope` placed an id after the account-wide `0x02` sentinel, or
    /// omitted the id after `0x01` (§3, §7 rule 4).
    FileScopeMalformed,
    /// `recipient_type == recovery` but `recipient_id != RECOVERY_ID` (§3, §7 rule 4).
    RecoveryIdMismatch,
    /// A `manifest.streams` list was not ascending/unique by `stream_type` (§4, V-13).
    StreamsNotAscending,
    /// The value decoded, but `encode(value) != input` — the master canonical
    /// guard caught a non-canonical-but-parseable form (§7 rule 5).
    NonCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeError::*;
        match self {
            ShortInput { needed, remaining } => {
                write!(f, "short input: needed {needed}, {remaining} remaining")
            }
            TrailingBytes { remaining } => write!(f, "{remaining} trailing byte(s)"),
            InvalidBool(b) => write!(f, "invalid bool byte 0x{b:02x}"),
            LengthOverrun { len, remaining } => {
                write!(f, "length {len} overruns {remaining} remaining byte(s)")
            }
            InvalidUtf8 => write!(f, "text is not valid UTF-8"),
            NonNfcText => write!(f, "text is not NFC-normalized"),
            TextTooLong { len, max } => write!(f, "text length {len} exceeds max {max}"),
            UnknownEnum { kind, value } => write!(f, "unknown {kind} codepoint {value}"),
            SetNotAscending => write!(f, "set not strictly ascending (unsorted or duplicate)"),
            SetTooLong { count, max } => write!(f, "set count {count} exceeds registry size {max}"),
            InvalidPresenceByte(b) => write!(f, "invalid option presence byte 0x{b:02x}"),
            UnknownTypeId(id) => write!(f, "unknown type_id 0x{id:04x}"),
            WrongTypeId { expected, got } => {
                write!(
                    f,
                    "wrong type_id: expected 0x{expected:04x}, got 0x{got:04x}"
                )
            }
            FileScopeMalformed => write!(f, "malformed FileScope"),
            RecoveryIdMismatch => write!(f, "recovery recipient_id != RECOVERY_ID"),
            StreamsNotAscending => write!(f, "streams not ascending/unique by stream_type"),
            NonCanonical => write!(f, "non-canonical encoding (re-encode guard)"),
        }
    }
}

impl std::error::Error for DecodeError {}
