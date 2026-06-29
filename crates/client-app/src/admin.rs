//! Admin-side helpers: voucher-code generation and ceremony-request shaping. No
//! key material here — the D5 key is offline; "approve" emits a work-item, not a
//! signature (D-K).

use maxsecu_crypto::{random_array, sha256};

/// A freshly generated invite: the human-shareable `code` and the `hash` posted
/// to the server (the server never sees the code).
pub struct Voucher {
    pub code: String,
    pub hash: [u8; 32],
}

/// Generate a random invite code + its SHA-256.
pub fn generate_voucher() -> Voucher {
    let raw: [u8; 18] = random_array();
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let code = URL_SAFE_NO_PAD.encode(raw);
    let hash = sha256(code.as_bytes());
    Voucher { code, hash }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn voucher_hash_matches_code() {
        let v = generate_voucher();
        assert_eq!(v.hash, sha256(v.code.as_bytes()));
        assert_ne!(generate_voucher().code, generate_voucher().code);
    }
}
