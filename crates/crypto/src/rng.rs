//! OS CSPRNG (DESIGN §5 / parameters §1.6): all key material, salts, and DEKs
//! come from the operating system RNG (`BCryptGenRandom` on Windows) — never a
//! userspace PRNG.

/// Fill `buf` with cryptographically secure random bytes from the OS.
///
/// Panics only if the OS RNG is unavailable, which on a supported platform is
/// not a recoverable condition for a security product (fail loud, not weak).
pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG must be available");
}

/// Return `N` fresh random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut a = [0u8; N];
    fill_random(&mut a);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_draws_differ() {
        // Two 32-byte draws colliding has probability 2^-256 — treat equality as
        // a broken RNG.
        assert_ne!(random_array::<32>(), random_array::<32>());
    }

    #[test]
    fn fill_writes_all_bytes() {
        let mut buf = [0u8; 16];
        fill_random(&mut buf);
        // Not all-zero with overwhelming probability.
        assert_ne!(buf, [0u8; 16]);
    }
}
