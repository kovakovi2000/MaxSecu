//! Shamir secret-sharing over GF(2^8) (DESIGN §16.3 / §19).
//!
//! The cryptographic core of "recovery requires a threshold of custodians":
//! a secret is split into `n` shares such that any `k` of them reconstruct it
//! and any `k-1` reveal nothing. Each byte of the secret is the constant term
//! of an independent, freshly random degree-`(k-1)` polynomial over the AES
//! field GF(256) (reduction polynomial `0x11B`), evaluated at distinct non-zero
//! x-coordinates `x = 1..=n`. Reconstruction is Lagrange interpolation at `x = 0`.
//!
//! This is the *bare* primitive: it is **not** authenticated — a flipped share
//! byte yields a different (wrong) secret without error. Integrity comes from the
//! downstream X25519-key check that wires this into recovery custody (P7.7).
//!
//! Pure, offline ceremony code (no I/O, no async). Performance is irrelevant, so
//! GF(256) multiplication uses a carry-less (Russian-peasant) loop. It is
//! implemented branchlessly over a fixed 8-iteration count (mask arithmetic, no
//! data-dependent branches and no lookup tables) so that — even though one
//! operand in `combine` is a secret share byte — the work is independent of the
//! operand values. Random coefficients come from the OS CSPRNG (`crate::rng`),
//! and all transient secret-bearing buffers are zeroized.

use crate::rng::fill_random;
use core::fmt;
use zeroize::Zeroizing;

/// One Shamir share: a non-zero GF(256) x-coordinate and the per-byte y-values.
///
/// The `body` is itself a share (not the secret), but treat it carefully — never
/// log it. `index` is the evaluation x-coordinate and must be `!= 0`.
///
/// `Debug` deliberately elides `body` (prints only its length): in the `k == 1`
/// degenerate case `body == secret`, so an accidental `{:?}` must not dump it.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// The GF(256) x-coordinate this share was evaluated at (`1..=n`, non-zero).
    pub index: u8,
    /// The per-secret-byte y-values; `body.len() == secret.len()`.
    pub body: Vec<u8>,
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Elide the share bytes; only structure-safe metadata is printed.
        write!(
            f,
            "Share {{ index: {}, body: <{} bytes> }}",
            self.index,
            self.body.len()
        )
    }
}

/// A fail-closed Shamir error. Carries no secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Fewer than `k` shares were supplied to `combine`.
    InsufficientShares,
    /// Two supplied shares share an `index` (Lagrange basis would divide by zero).
    DuplicateIndex,
    /// `split` was given `k == 0`, `n == 0`, or `k > n`; or `combine` got `k == 0`.
    BadThreshold,
    /// Supplied shares had differing `body` lengths.
    LengthMismatch,
}

impl fmt::Display for ShamirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ShamirError::*;
        match self {
            InsufficientShares => write!(f, "fewer than k shares supplied"),
            DuplicateIndex => write!(f, "duplicate share index"),
            BadThreshold => write!(f, "invalid threshold (require 1 <= k <= n)"),
            LengthMismatch => write!(f, "shares have differing body lengths"),
        }
    }
}

impl std::error::Error for ShamirError {}

/// The GF(256) reduction polynomial `0x11B` with its `x^8` bit dropped: the value
/// XORed in when a left shift carries out of bit 7.
const GF256_REDUCTION: u8 = 0x1B;
/// The high bit (`x^7`) whose set state means the next left shift will overflow.
const GF256_HIGH_BIT: u8 = 0x80;
/// Exponent for the multiplicative inverse: `a^254 == a^-1` (since `a^255 == 1`).
const GF256_INV_EXP: u32 = 254;

/// GF(256) addition is XOR.
#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(256) multiplication via carry-less Russian-peasant with the `0x11B`
/// reduction. Branchless over a fixed 8-iteration loop: each step's contribution
/// is selected by mask arithmetic (`(bit).wrapping_neg()` is `0x00`/`0xFF`), so
/// control flow is independent of the operand values — important because in
/// `combine` one operand is a secret share byte.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product: u8 = 0;
    for _ in 0..8 {
        // Add `a` iff the low bit of `b` is set (mask = 0xFF when set, else 0x00).
        product ^= a & (b & 1).wrapping_neg();
        // 1 iff the high bit (`x^7`) is set, i.e. the next shift will overflow.
        let carry = (a & GF256_HIGH_BIT) >> 7;
        a <<= 1;
        // Reduce iff a carry shifted out of bit 7.
        a ^= GF256_REDUCTION & carry.wrapping_neg();
        b >>= 1;
    }
    product
}

/// `a^n` in GF(256) by square-and-multiply.
fn gf_pow(a: u8, mut n: u32) -> u8 {
    let mut result: u8 = 1;
    let mut base = a;
    while n > 0 {
        if n & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        n >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256): `a^254` (since `a^255 == 1` for `a != 0`).
/// `gf_inv(0) == 0`; callers must guarantee a non-zero argument.
#[inline]
fn gf_inv(a: u8) -> u8 {
    gf_pow(a, GF256_INV_EXP)
}

/// Evaluate the polynomial with the given `coeffs` (low-order first) at `x`,
/// via Horner's method over GF(256).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc
}

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
///
/// Requires `1 <= k <= n <= 255` (x-coordinates are non-zero bytes `1..=n`).
/// Coefficients are drawn from the OS CSPRNG and zeroized after use.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>, ShamirError> {
    if k == 0 || n == 0 || k > n {
        return Err(ShamirError::BadThreshold);
    }
    // `n <= 255` is enforced by the `u8` type; x = 1..=n are all non-zero/distinct.
    let mut shares: Vec<Share> = (1..=n)
        .map(|index| Share {
            index,
            body: vec![0u8; secret.len()],
        })
        .collect();

    for (pos, &secret_byte) in secret.iter().enumerate() {
        // coeffs[0] is the secret byte; coeffs[1..k] are fresh OS-random.
        let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
        coeffs[0] = secret_byte;
        if k > 1 {
            fill_random(&mut coeffs[1..]);
        }
        for share in shares.iter_mut() {
            share.body[pos] = eval_poly(&coeffs, share.index);
        }
        // `coeffs` (holding the secret byte + random coefficients) zeroized here.
    }

    Ok(shares)
}

/// Reconstruct the secret from exactly `k` of the supplied `shares` via Lagrange
/// interpolation at `x = 0`. Uses the first `k` shares.
///
/// Errors: `BadThreshold` (`k == 0`), `InsufficientShares` (`< k` supplied),
/// `LengthMismatch` (unequal body lengths among the used shares), `DuplicateIndex`
/// (two used shares share an index).
pub fn combine(k: u8, shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, ShamirError> {
    if k == 0 {
        return Err(ShamirError::BadThreshold);
    }
    let k = k as usize;
    if shares.len() < k {
        return Err(ShamirError::InsufficientShares);
    }
    let used = &shares[..k];

    let len = used[0].body.len();
    if used.iter().any(|s| s.body.len() != len) {
        return Err(ShamirError::LengthMismatch);
    }
    for i in 0..k {
        for j in (i + 1)..k {
            if used[i].index == used[j].index {
                return Err(ShamirError::DuplicateIndex);
            }
        }
    }

    let mut secret = Zeroizing::new(vec![0u8; len]);
    for (pos, out) in secret.iter_mut().enumerate() {
        let mut acc: u8 = 0;
        for i in 0..k {
            let xi = used[i].index;
            let yi = used[i].body[pos];
            // Lagrange basis evaluated at 0: prod_{j!=i} (0 - xj)/(xi - xj).
            // In GF(2^8), 0 - xj == xj and xi - xj == xi ^ xj.
            let mut num: u8 = 1;
            let mut den: u8 = 1;
            for (j, sj) in used.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = sj.index;
                num = gf_mul(num, xj);
                den = gf_mul(den, gf_add(xi, xj));
            }
            let basis = gf_mul(num, gf_inv(den));
            acc = gf_add(acc, gf_mul(yi, basis));
        }
        *out = acc;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret() -> Vec<u8> {
        // A non-trivial 32-byte secret (not all-equal, spans the byte range).
        (0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect()
    }

    #[test]
    fn gf_mul_known_answers() {
        // GF(256) AES-field spot checks.
        assert_eq!(gf_mul(0, 5), 0);
        assert_eq!(gf_mul(1, 5), 5);
        assert_eq!(gf_mul(0x53, 0xCA), 0x01); // 0x53 and 0xCA are inverses.
        assert_eq!(gf_mul(0x57, 0x83), 0xC1); // classic AES example.
    }

    #[test]
    fn gf_inv_round_trips() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn split_then_any_k_of_n_reconstructs() {
        let secret = sample_secret();
        let shares = split(&secret, 3, 5).expect("split");
        assert_eq!(shares.len(), 5);
        for (i, s) in shares.iter().enumerate() {
            assert_eq!(s.index as usize, i + 1);
            assert_eq!(s.body.len(), secret.len());
        }

        // Every 3-subset of the 5 shares reconstructs the exact secret.
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let subset = [
                        shares[a].clone(),
                        shares[b].clone(),
                        shares[c].clone(),
                    ];
                    let rec = combine(3, &subset).expect("combine 3");
                    assert_eq!(&*rec, &secret, "subset {a},{b},{c}");
                }
            }
        }

        // A 4-subset and the full 5-subset reconstruct too.
        let four = [
            shares[0].clone(),
            shares[1].clone(),
            shares[2].clone(),
            shares[3].clone(),
        ];
        assert_eq!(&*combine(4, &four).expect("combine 4"), &secret);
        assert_eq!(&*combine(5, &shares).expect("combine 5"), &secret);
    }

    #[test]
    fn fewer_than_k_cannot_reconstruct() {
        let secret = sample_secret();
        let shares = split(&secret, 3, 5).expect("split");
        // The API requires k shares; supplying only 2 is rejected by construction,
        // which is exactly the security property: < k shares are insufficient.
        let two = [shares[0].clone(), shares[1].clone()];
        assert_eq!(combine(3, &two), Err(ShamirError::InsufficientShares));
    }

    #[test]
    fn duplicate_index_rejected() {
        let secret = sample_secret();
        let shares = split(&secret, 3, 5).expect("split");
        let mut dup = shares[1].clone();
        dup.index = shares[0].index; // collide indices
        let supplied = [shares[0].clone(), dup, shares[2].clone()];
        assert_eq!(combine(3, &supplied), Err(ShamirError::DuplicateIndex));
    }

    #[test]
    fn length_mismatch_rejected() {
        let secret = sample_secret();
        let shares = split(&secret, 3, 5).expect("split");
        let mut short = shares[2].clone();
        short.body.pop(); // differing length
        let supplied = [shares[0].clone(), shares[1].clone(), short];
        assert_eq!(combine(3, &supplied), Err(ShamirError::LengthMismatch));
    }

    #[test]
    fn bad_threshold_rejected() {
        let s = sample_secret();
        assert_eq!(split(&s, 0, 5), Err(ShamirError::BadThreshold));
        assert_eq!(split(&s, 6, 5), Err(ShamirError::BadThreshold));
        assert_eq!(split(&s, 1, 0), Err(ShamirError::BadThreshold));
    }

    #[test]
    fn tampered_share_reconstructs_wrong_secret() {
        // Bare Shamir is NOT authenticated: a flipped share byte yields a wrong
        // secret without panicking. Integrity is enforced downstream in P7.7.
        let secret = sample_secret();
        let shares = split(&secret, 3, 5).expect("split");
        let mut tampered = shares[0].clone();
        tampered.body[0] ^= 0x01;
        let supplied = [tampered, shares[1].clone(), shares[2].clone()];
        let rec = combine(3, &supplied).expect("combine (no panic)");
        assert_ne!(&*rec, &secret, "tampered share must not reconstruct the secret");
    }

    #[test]
    fn per_byte_independence_32_bytes() {
        let secret = sample_secret();
        assert_eq!(secret.len(), 32);
        let shares = split(&secret, 2, 4).expect("split");
        let subset = [shares[1].clone(), shares[3].clone()];
        let rec = combine(2, &subset).expect("combine");
        assert_eq!(&*rec, &secret);
    }

    #[test]
    fn k_equals_1_is_trivial_sharing() {
        // k=1: the polynomial is the constant secret, so every share body == secret.
        let secret = sample_secret();
        let shares = split(&secret, 1, 3).expect("split");
        for s in &shares {
            assert_eq!(&s.body, &secret);
        }
        let one = [shares[2].clone()];
        assert_eq!(&*combine(1, &one).expect("combine"), &secret);
    }

    #[test]
    fn k_equals_n() {
        let secret = sample_secret();
        let shares = split(&secret, 5, 5).expect("split");
        assert_eq!(&*combine(5, &shares).expect("combine"), &secret);
    }

    #[test]
    fn empty_secret_round_trips() {
        let shares = split(&[], 2, 3).expect("split");
        for s in &shares {
            assert!(s.body.is_empty());
        }
        let subset = [shares[0].clone(), shares[2].clone()];
        assert!(combine(2, &subset).expect("combine").is_empty());
    }
}
