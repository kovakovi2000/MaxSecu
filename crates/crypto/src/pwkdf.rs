//! Argon2id password KDF (DESIGN §5 / parameters §1.1).
//!
//! Derives the AES-256-GCM key that protects the on-device `local_key_blob`.
//! A client **rejects** any params below the mandatory floor — a stored blob
//! whose params fall below it is refused (parameters §1.1), fail closed.

use crate::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id cost parameters (`p = 1` throughout for v1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

/// Mandatory floor, all platforms: `m ≥ 19 MiB, t ≥ 2, p = 1` (OWASP/RFC 9106).
pub const ARGON2_FLOOR: Argon2Params = Argon2Params {
    m_kib: 19 * 1024,
    t: 2,
    p: 1,
};

/// Desktop v1 target: `m = 256 MiB, t = 3, p = 1` (calibrate to 0.5–1.0 s).
pub const ARGON2_DESKTOP_TARGET: Argon2Params = Argon2Params {
    m_kib: 256 * 1024,
    t: 3,
    p: 1,
};

impl Argon2Params {
    /// Does this meet the mandatory floor (parameters §1.1)?
    pub fn meets_floor(&self) -> bool {
        self.m_kib >= ARGON2_FLOOR.m_kib && self.t >= ARGON2_FLOOR.t && self.p >= 1
    }
}

/// Derive a 32-byte key from `password` and a 16-byte `salt` under `params`.
/// Rejects below-floor params before doing any work.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if !params.meets_floor() {
        return Err(CryptoError::BelowArgonFloor);
    }
    let p =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| CryptoError::Argon2)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|_| CryptoError::Argon2)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use the floor params in tests: memory-hard but the cheapest acceptable
    // profile, so the suite stays fast while exercising the real KDF.
    const SALT: [u8; 16] = [0x5a; 16];

    #[test]
    fn deterministic_for_same_inputs() {
        let a = derive_key(b"correct horse battery staple", &SALT, ARGON2_FLOOR).unwrap();
        let b = derive_key(b"correct horse battery staple", &SALT, ARGON2_FLOOR).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn different_password_differs() {
        let a = derive_key(b"password-one-xxxxxxx", &SALT, ARGON2_FLOOR).unwrap();
        let b = derive_key(b"password-two-xxxxxxx", &SALT, ARGON2_FLOOR).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn different_salt_differs() {
        let a = derive_key(b"same-password-yyyyyy", &SALT, ARGON2_FLOOR).unwrap();
        let b = derive_key(b"same-password-yyyyyy", &[0xa5; 16], ARGON2_FLOOR).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn below_floor_is_rejected() {
        let weak = Argon2Params {
            m_kib: 8 * 1024, // < 19 MiB
            t: 1,
            p: 1,
        };
        assert!(!weak.meets_floor());
        assert_eq!(
            derive_key(b"whatever-passphrase", &SALT, weak).map(|_| ()),
            Err(CryptoError::BelowArgonFloor)
        );
    }

    #[test]
    fn floor_and_target_meet_floor() {
        assert!(ARGON2_FLOOR.meets_floor());
        assert!(ARGON2_DESKTOP_TARGET.meets_floor());
    }
}
