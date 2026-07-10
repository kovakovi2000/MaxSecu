//! In-band pin bootstrap fingerprint (design 2026-07-10).
//!
//! A single source of truth shared by BOTH the server (which prints the
//! "connection code") and the client (which verifies it), so the two can never
//! disagree on how the pins are hashed. The fingerprint commits to the exact
//! bytes of the two public trust anchors (`server_cert.der`, `directory_pub.der`)
//! via a domain-separated, length-framed SHA-256, truncated to 160 bits and
//! base32-encoded to a short, hand-copyable code.

use crate::hash::sha256;

/// Domain-separation tag mixed in front of the framed pins.
const DOMAIN_SEP: &[u8] = b"MAXSECU-PINS-v1";

/// RFC 4648 base32 alphabet (uppercase, no padding).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `base32(RFC4648, no pad)` of
/// `SHA-256("MAXSECU-PINS-v1" ‖ len32(cert) ‖ cert ‖ len32(dir) ‖ dir)`
/// truncated to the first 20 bytes. Uppercase, exactly 32 chars.
///
/// `len32(x)` is the byte length of `x` as a big-endian `u32`. The two inputs
/// are the raw DER bytes of the self-signed TLS cert and the Ed25519 directory
/// key — both public, so this provides *integrity* (second-preimage
/// resistance), not secrecy.
pub fn pin_fingerprint(cert_der: &[u8], dir_der: &[u8]) -> String {
    let mut preimage =
        Vec::with_capacity(DOMAIN_SEP.len() + 4 + cert_der.len() + 4 + dir_der.len());
    preimage.extend_from_slice(DOMAIN_SEP);
    preimage.extend_from_slice(&(cert_der.len() as u32).to_be_bytes());
    preimage.extend_from_slice(cert_der);
    preimage.extend_from_slice(&(dir_der.len() as u32).to_be_bytes());
    preimage.extend_from_slice(dir_der);

    let digest = sha256(&preimage);
    base32_no_pad(&digest[..20])
}

/// RFC 4648 base32 encode, uppercase, no padding. Inline (no crate dependency).
///
/// Emits one output char per 5 input bits (ceil(bits/5) chars). For the 20-byte
/// (160-bit) input this crate uses, that is exactly 32 chars with no leftover
/// bits, so no padding is ever needed.
fn base32_no_pad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        // Pad the remaining <5 bits on the right with zeros to form a final char.
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_vector() {
        // Cross-check vector derived INDEPENDENTLY of this implementation via:
        //   python:
        //     import hashlib, base64, struct
        //     pre = (b"MAXSECU-PINS-v1"
        //            + struct.pack(">I", 4) + b"cert"
        //            + struct.pack(">I", 3) + b"dir")
        //     base64.b32encode(hashlib.sha256(pre).digest()[:20]).decode().rstrip("=")
        //   => "7ZYAOZUV4NXUTL5YVLNFRVB5MNKBOSNN"
        let got = pin_fingerprint(b"cert", b"dir");
        assert_eq!(got, "7ZYAOZUV4NXUTL5YVLNFRVB5MNKBOSNN");
    }

    #[test]
    fn byte_flip_changes_output() {
        let cert = b"the-server-certificate-bytes".to_vec();
        let dir = b"the-directory-public-key-bytes".to_vec();
        let base = pin_fingerprint(&cert, &dir);

        // Flip every single byte position of cert, one at a time.
        for i in 0..cert.len() {
            let mut c = cert.clone();
            c[i] ^= 0x01;
            assert_ne!(
                pin_fingerprint(&c, &dir),
                base,
                "flipping cert byte {i} did not change the fingerprint"
            );
        }
        // Flip every single byte position of dir, one at a time.
        for i in 0..dir.len() {
            let mut d = dir.clone();
            d[i] ^= 0x01;
            assert_ne!(
                pin_fingerprint(&cert, &d),
                base,
                "flipping dir byte {i} did not change the fingerprint"
            );
        }
    }

    #[test]
    fn shape_is_32_chars_in_alphabet() {
        let fp = pin_fingerprint(b"anything", b"else");
        assert_eq!(fp.len(), 32, "fingerprint must be exactly 32 chars");
        for ch in fp.chars() {
            assert!(
                ('A'..='Z').contains(&ch) || ('2'..='7').contains(&ch),
                "char {ch:?} not in RFC4648 base32 alphabet [A-Z2-7]"
            );
        }
    }
}
