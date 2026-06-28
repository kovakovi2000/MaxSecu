//! Portable keystore file: an Argon2id-wrapped local_key_blob beside the exe
//! (stack.md §5.2). The password derives the at-rest key, so the folder travels.

use maxsecu_client_core::keyblob;
use maxsecu_client_core::password;
use maxsecu_client_core::{Identity, ARGON2_DESKTOP_TARGET};
use std::path::{Path, PathBuf};

use crate::error::UiError;

pub fn keystore_path(dir: &Path) -> PathBuf {
    dir.join("keystore").join("local_key_blob")
}

// `exists`/`create` back the onboarding flow (first-run keystore creation) the
// UI adds in a later phase (Task 9/10); Phase-1 commands only `unlock` an
// already-provisioned keystore, so these are not yet called by the binary.
#[allow(dead_code)]
pub fn exists(dir: &Path) -> bool {
    keystore_path(dir).exists()
}

/// Create a fresh identity, seal it under `password`, and write the blob.
#[allow(dead_code)]
pub fn create(dir: &Path, password: &str) -> Result<Identity, UiError> {
    // Fail closed before doing anything: overwriting an existing blob would
    // destroy the prior identity (and access to everything sealed to it) with
    // no recovery. `exists()` is the contract; enforce it here.
    if exists(dir) {
        return Err(UiError::new(
            "keystore_exists",
            "A keystore already exists on this device.",
        ));
    }
    password::check(password)
        .map_err(|_| UiError::new("weak_password", "Password is too weak."))?;
    let id = Identity::generate();
    let blob = keyblob::seal(password, &id, ARGON2_DESKTOP_TARGET)
        .map_err(|_| UiError::new("keystore", "Could not create keystore."))?;
    let path = keystore_path(dir);
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    std::fs::write(&path, &blob)
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    Ok(id)
}

/// Unlock the existing blob with `password`.
pub fn unlock(dir: &Path, password: &str) -> Result<Identity, UiError> {
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    keyblob::unlock(password, &blob).map_err(|_| UiError::new("unauthorized", "Wrong password."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_unlock_roundtrips_identity() {
        let dir = tempdir();
        let pw = "correct horse battery staple 9!";
        let created = create(&dir, pw).unwrap();
        let unlocked = unlock(&dir, pw).unwrap();
        assert_eq!(created.sig_pub_bytes(), unlocked.sig_pub_bytes());
    }

    #[test]
    fn wrong_password_is_unauthorized() {
        let dir = tempdir();
        create(&dir, "correct horse battery staple 9!").unwrap();
        // `Identity` intentionally has no `Debug` (secret material), so
        // `unwrap_err` is unavailable; extract the error explicitly.
        let err = match unlock(&dir, "nope") {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "unauthorized");
    }

    #[test]
    fn missing_keystore_reports_no_keystore() {
        let dir = tempdir();
        let err = match unlock(&dir, "whatever") {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "no_keystore");
    }

    #[test]
    fn create_refuses_to_overwrite_existing_keystore() {
        let dir = tempdir();
        let pw = "correct horse battery staple 9!";
        create(&dir, pw).unwrap();
        let err = match create(&dir, pw) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "keystore_exists");
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("maxsecu-ks-{}", nanos()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
