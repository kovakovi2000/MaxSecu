//! `MSHARE1` share wire-encoding + integrity checksum (T6 spec §5).
//!
//! Pure, offline module — no network, no I/O (grep-checkable: no `hyper`/
//! `http_client` import here). Turns a `crypto::shamir::Share` into the
//! human-transcribable text form used for share distribution (typed, filed,
//! or fed back in at a later reconstruct ceremony):
//!
//! ```text
//! MSHARE1:<label-b64url>:<k>:<n>:<index>:<body-b64url>:<checksum-hex8>
//! ```
//!
//! - `MSHARE1` is a version tag; any other tag is rejected outright so a
//!   future format change can never be misinterpreted under this one.
//! - `label` (non-secret, operator-chosen) and `body` (`Share::body`, the
//!   sensitive share payload) are each base64url (`URL_SAFE_NO_PAD`) encoded
//!   so they can safely sit between `:` delimiters.
//! - `k`, `n`, `index` are carried as plain decimal integers.
//! - `checksum` is the first 8 hex characters of
//!   `sha256(label_bytes ‖ [k] ‖ [n] ‖ [index] ‖ body_bytes)` — i.e. the raw
//!   UTF-8 bytes of the (decoded) label, followed by the three single-byte
//!   fields `k`, `n`, `index` in that order, followed by the raw (decoded)
//!   body bytes. This exact concatenation is used by both `encode` and
//!   `parse_and_verify`; changing it is a wire-format break.
//!
//! **What the checksum is NOT (spec §5):** it is a UX corruption/transcription
//! check only — it catches a mistyped character or a truncated paste/file
//! *before* a `combine` attempt wastes effort on it. It is **not** a
//! cryptographic authenticity guarantee: it has no secret key, so a malicious
//! party can trivially forge a self-consistent `MSHARE1` string with a
//! matching checksum for fabricated bytes. Authenticity of a *reconstructed*
//! key comes only from the downstream real-wrap proof (§6), never from this
//! checksum passing. No code path anywhere may treat "checksum passed" as a
//! security property.
//!
//! `body` is sensitive: `ParsedShare`'s `Debug` deliberately elides it
//! (prints only its length), mirroring `crypto::shamir::Share`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use core::fmt;
use maxsecu_crypto::{sha256, Share};

/// The only version tag `parse_and_verify` accepts.
const TAG: &str = "MSHARE1";

/// A `MSHARE1` string, parsed and checksum-verified, ready to feed into
/// `crypto::shamir::combine` (after collecting `k` of these).
///
/// `Debug` deliberately elides `body` (prints only its length) — mirrors
/// `crypto::shamir::Share`'s own hygiene (shamir.rs) since this is the same
/// sensitive payload, just wire-decoded.
#[derive(Clone, PartialEq, Eq)]
pub struct ParsedShare {
    pub label: String,
    pub k: u8,
    pub n: u8,
    pub index: u8,
    pub body: Vec<u8>,
}

impl fmt::Debug for ParsedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedShare {{ label: {:?}, k: {}, n: {}, index: {}, body: <{} bytes> }}",
            self.label,
            self.k,
            self.n,
            self.index,
            self.body.len()
        )
    }
}

/// A fail-closed error parsing/verifying a `MSHARE1` string. Carries no
/// secret material — every variant is safe to show/log verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareParseError {
    /// The first field wasn't exactly `MSHARE1`.
    WrongVersion,
    /// The string didn't split into exactly 7 `:`-delimited fields
    /// (tag, label, k, n, index, body, checksum).
    WrongFieldCount,
    /// `label` or `body` was not valid `URL_SAFE_NO_PAD` base64 (or, for
    /// `label`, decoded bytes were not valid UTF-8).
    BadBase64,
    /// `k`, `n`, or `index` was not a valid decimal `u8`.
    BadInteger,
    /// `checksum` was not exactly 8 hex characters.
    BadChecksum,
    /// `checksum` was well-formed but did not match the recomputed value —
    /// the share text was mistyped, truncated, or otherwise corrupted.
    ChecksumMismatch,
}

impl fmt::Display for ShareParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ShareParseError::*;
        match self {
            WrongVersion => write!(f, "not a MaxSecu recovery share (wrong version tag)"),
            WrongFieldCount => write!(f, "not a MaxSecu recovery share (wrong field count)"),
            BadBase64 => write!(f, "share text is not validly encoded"),
            BadInteger => write!(f, "share text has an invalid k/n/index field"),
            BadChecksum => write!(f, "share text has a malformed checksum field"),
            ChecksumMismatch => write!(f, "share may be corrupted or mistyped"),
        }
    }
}

impl std::error::Error for ShareParseError {}

/// Encode a share for display, copy, QR, or file export (spec §5).
pub fn encode(share: &Share, label: &str, k: u8, n: u8) -> String {
    let label_b64 = URL_SAFE_NO_PAD.encode(label.as_bytes());
    let body_b64 = URL_SAFE_NO_PAD.encode(&share.body);
    let checksum = checksum_hex8(label.as_bytes(), k, n, share.index, &share.body);
    format!(
        "{TAG}:{label_b64}:{k}:{n}:{}:{body_b64}:{checksum}",
        share.index
    )
}

/// Parse a `MSHARE1` string and verify its checksum (spec §5).
///
/// Returns a specific [`ShareParseError`] variant on any failure — never a
/// raw parse-error dump. A passing checksum is a UX corruption check only,
/// **not** an authenticity guarantee (see module docs).
pub fn parse_and_verify(text: &str) -> Result<ParsedShare, ShareParseError> {
    let fields: Vec<&str> = text.split(':').collect();
    if fields.len() != 7 {
        return Err(ShareParseError::WrongFieldCount);
    }
    if fields[0] != TAG {
        return Err(ShareParseError::WrongVersion);
    }

    let label_bytes = URL_SAFE_NO_PAD
        .decode(fields[1])
        .map_err(|_| ShareParseError::BadBase64)?;
    let label = String::from_utf8(label_bytes).map_err(|_| ShareParseError::BadBase64)?;
    let k: u8 = fields[2].parse().map_err(|_| ShareParseError::BadInteger)?;
    let n: u8 = fields[3].parse().map_err(|_| ShareParseError::BadInteger)?;
    let index: u8 = fields[4].parse().map_err(|_| ShareParseError::BadInteger)?;
    let body = URL_SAFE_NO_PAD
        .decode(fields[5])
        .map_err(|_| ShareParseError::BadBase64)?;
    let checksum = fields[6];

    if checksum.len() != 8 || !checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ShareParseError::BadChecksum);
    }
    let expected = checksum_hex8(label.as_bytes(), k, n, index, &body);
    if checksum != expected {
        return Err(ShareParseError::ChecksumMismatch);
    }

    Ok(ParsedShare {
        label,
        k,
        n,
        index,
        body,
    })
}

/// The exact checksum byte-concatenation (module docs): raw label bytes,
/// then `k`, `n`, `index` as single bytes, then raw body bytes — first 8 hex
/// chars of `sha256` over that. Used identically by `encode` and
/// `parse_and_verify`.
fn checksum_hex8(label: &[u8], k: u8, n: u8, index: u8, body: &[u8]) -> String {
    let mut buf = Vec::with_capacity(label.len() + 3 + body.len());
    buf.extend_from_slice(label);
    buf.push(k);
    buf.push(n);
    buf.push(index);
    buf.extend_from_slice(body);
    let digest = sha256(&buf);
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_crypto::split;

    fn sample_share() -> Share {
        let secret = b"0123456789abcdef0123456789abcdef".to_vec();
        let shares = split(&secret, 3, 5).expect("split");
        shares[1].clone() // index == 2
    }

    #[test]
    fn debug_elides_body() {
        let parsed = ParsedShare {
            label: "l".into(),
            k: 3,
            n: 5,
            index: 2,
            body: vec![0xAA; 32],
        };
        let dbg = format!("{parsed:?}");
        assert!(!dbg.contains("170")); // 0xAA == 170 decimal; body bytes must not appear
        assert!(dbg.contains("<32 bytes>"));
    }

    #[test]
    fn encode_then_parse_round_trips() {
        let share = sample_share();
        let text = encode(&share, "MaxSecu recovery key, 2026-07", 3, 5);
        assert!(text.starts_with("MSHARE1:"));

        let parsed = parse_and_verify(&text).expect("parse_and_verify");
        assert_eq!(parsed.label, "MaxSecu recovery key, 2026-07");
        assert_eq!(parsed.k, 3);
        assert_eq!(parsed.n, 5);
        assert_eq!(parsed.index, share.index);
        assert_eq!(parsed.body, share.body);
    }

    #[test]
    fn empty_label_round_trips() {
        let share = sample_share();
        let text = encode(&share, "", 3, 5);
        let parsed = parse_and_verify(&text).expect("parse_and_verify");
        assert_eq!(parsed.label, "");
        assert_eq!(parsed.body, share.body);
    }

    // --- Mutation rejection: a single-character change in every field must
    // be caught by `parse_and_verify`, never silently accepted (spec §5's
    // "a transcription typo is caught before combine" acceptance bar).

    /// Split `text` on `:` and mutate exactly one character inside the field
    /// at `field_idx` (0=tag,1=label,2=k,3=n,4=index,5=body,6=checksum), then
    /// rejoin. The mutation always changes the field's value.
    fn mutate_field(text: &str, field_idx: usize) -> String {
        let mut fields: Vec<String> = text.split(':').map(|s| s.to_string()).collect();
        let field = &mut fields[field_idx];
        assert!(!field.is_empty(), "cannot mutate an empty field");
        let mut chars: Vec<char> = field.chars().collect();
        // Replace the first character with a different one, chosen to still
        // be a legal character for that field's alphabet where possible, so
        // the mutation is caught by checksum verification rather than by an
        // earlier structural error.
        let orig = chars[0];
        let replacement = if orig.is_ascii_digit() {
            // Numeric field (k/n/index): pick a different digit.
            if orig == '0' {
                '1'
            } else {
                '0'
            }
        } else {
            // base64url alphabet field (label/body) or hex (checksum).
            if orig == 'A' {
                'B'
            } else {
                'A'
            }
        };
        assert_ne!(orig, replacement);
        chars[0] = replacement;
        *field = chars.into_iter().collect();
        fields.join(":")
    }

    #[test]
    fn mutation_in_every_field_is_rejected() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        // Sanity: the unmutated text parses fine.
        assert!(parse_and_verify(&text).is_ok());

        // field indices: 1=label, 2=k, 3=n, 4=index, 5=body, 6=checksum
        for field_idx in 1..=6 {
            let mutated = mutate_field(&text, field_idx);
            let result = parse_and_verify(&mutated);
            assert!(
                result.is_err(),
                "field {field_idx} mutation must be rejected, text={mutated:?}"
            );
        }
    }

    #[test]
    fn checksum_field_mutation_is_checksum_mismatch() {
        // A single hex-digit flip in the checksum stays 8 valid hex chars,
        // so it must surface specifically as ChecksumMismatch, not BadChecksum.
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let mutated = mutate_field(&text, 6);
        assert_eq!(
            parse_and_verify(&mutated),
            Err(ShareParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn body_field_mutation_is_checksum_mismatch() {
        // A single base64 char flip still decodes (different bytes), so it
        // must reach and fail the checksum check specifically.
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let mutated = mutate_field(&text, 5);
        assert_eq!(
            parse_and_verify(&mutated),
            Err(ShareParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn wrong_version_tag_is_rejected_specifically() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let bad = text.replacen("MSHARE1", "MSHARE2", 1);
        assert_eq!(parse_and_verify(&bad), Err(ShareParseError::WrongVersion));
    }

    #[test]
    fn missing_tag_entirely_is_wrong_version() {
        assert_eq!(
            parse_and_verify("NOTASHARE:aaaa:3:5:2:bbbb:00000000"),
            Err(ShareParseError::WrongVersion)
        );
    }

    #[test]
    fn bad_base64_in_body_is_rejected_specifically() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let fields: Vec<&str> = text.split(':').collect();
        let bad = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            fields[0], fields[1], fields[2], fields[3], fields[4], "not!valid!base64!", fields[6]
        );
        assert_eq!(parse_and_verify(&bad), Err(ShareParseError::BadBase64));
    }

    #[test]
    fn bad_integer_in_k_is_rejected_specifically() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let fields: Vec<&str> = text.split(':').collect();
        let bad = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            fields[0], fields[1], "not-a-number", fields[3], fields[4], fields[5], fields[6]
        );
        assert_eq!(parse_and_verify(&bad), Err(ShareParseError::BadInteger));
    }

    #[test]
    fn wrong_field_count_is_rejected_specifically() {
        // Drop the checksum field entirely (6 fields instead of 7).
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let fields: Vec<&str> = text.split(':').collect();
        let short = fields[..6].join(":");
        assert_eq!(
            parse_and_verify(&short),
            Err(ShareParseError::WrongFieldCount)
        );
    }

    #[test]
    fn too_many_fields_is_wrong_field_count() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let extra = format!("{text}:extra");
        assert_eq!(
            parse_and_verify(&extra),
            Err(ShareParseError::WrongFieldCount)
        );
    }

    #[test]
    fn malformed_checksum_field_is_bad_checksum() {
        let share = sample_share();
        let text = encode(&share, "recovery-2026", 3, 5);
        let fields: Vec<&str> = text.split(':').collect();
        let bad = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], "zzzzzzzz"
        );
        assert_eq!(parse_and_verify(&bad), Err(ShareParseError::BadChecksum));
    }

    #[test]
    fn checksum_covers_label_k_n_index_not_just_body() {
        // Same share body, different k/n/label must produce a different
        // checksum, proving the checksum isn't computed from body alone.
        let share = sample_share();
        let t1 = encode(&share, "label-a", 3, 5);
        let t2 = encode(&share, "label-b", 3, 5);
        let cs1 = t1.rsplit(':').next().unwrap();
        let cs2 = t2.rsplit(':').next().unwrap();
        assert_ne!(cs1, cs2);
    }
}
