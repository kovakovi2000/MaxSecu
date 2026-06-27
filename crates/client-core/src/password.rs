//! Password policy (DESIGN §9.4, parameters §2): minimum length 15, generous
//! maximum 128, no forced composition, and a local known-breached/common
//! blocklist checked at set-time. The blocklist is intentionally small in v1
//! (a representative seed); it is meant to be replaced/extended with a real
//! breached-password corpus before production.

use crate::error::PasswordError;

/// Minimum password length in Unicode scalar values (parameters §2).
pub const MIN_LEN: usize = 15;
/// Maximum password length (parameters §2).
pub const MAX_LEN: usize = 128;

/// Seed blocklist of common/breached passwords (compared case-insensitively).
/// Entries are >= MIN_LEN so the length gate doesn't make them unreachable.
const BLOCKLIST: &[&str] = &[
    "passwordpassword",
    "password12345678",
    "123456789012345",
    "1234567890123456",
    "qwertyuiopasdfgh",
    "iloveyouiloveyou",
    "adminadminadmin1",
    "letmeinletmein12",
    "aaaaaaaaaaaaaaaa",
    "correcthorsebatterystaple",
];

/// Check a candidate password at set-time. Fail closed on the first violation.
pub fn check(password: &str) -> Result<(), PasswordError> {
    let len = password.chars().count();
    if len < MIN_LEN {
        return Err(PasswordError::TooShort { min: MIN_LEN });
    }
    if len > MAX_LEN {
        return Err(PasswordError::TooLong { max: MAX_LEN });
    }
    let lower = password.to_lowercase();
    if BLOCKLIST.iter().any(|b| *b == lower) {
        return Err(PasswordError::Breached);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_long_unique_passphrase() {
        assert!(check("a-perfectly-fine-unique-passphrase").is_ok());
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(
            check("short").unwrap_err(),
            PasswordError::TooShort { min: MIN_LEN }
        );
        // Exactly MIN_LEN - 1 still rejected; MIN_LEN accepted.
        assert!(check(&"x".repeat(MIN_LEN - 1)).is_err());
        assert!(check(&"xy9-z".repeat(3)).is_ok()); // 15 chars, not blocklisted
    }

    #[test]
    fn rejects_too_long() {
        assert_eq!(
            check(&"a".repeat(MAX_LEN + 1)).unwrap_err(),
            PasswordError::TooLong { max: MAX_LEN }
        );
    }

    #[test]
    fn rejects_blocklisted_case_insensitively() {
        assert_eq!(
            check("passwordpassword").unwrap_err(),
            PasswordError::Breached
        );
        assert_eq!(
            check("PasswordPassword").unwrap_err(),
            PasswordError::Breached
        );
        assert_eq!(
            check("CorrectHorseBatteryStaple").unwrap_err(),
            PasswordError::Breached
        );
    }

    #[test]
    fn counts_unicode_scalars_not_bytes() {
        // 15 multi-byte chars passes the length gate (counted as 15, not 30+).
        let pw = "é".repeat(15);
        assert!(check(&pw).is_ok());
    }
}
