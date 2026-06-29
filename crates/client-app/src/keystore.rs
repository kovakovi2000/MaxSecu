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

pub fn exists(dir: &Path) -> bool {
    keystore_path(dir).exists()
}

/// Fail-fast guard run BEFORE any network/account creation: refuse if a keystore
/// already exists (overwrite would destroy the prior identity) or the password is
/// too weak. `seal_identity` re-checks these (defense in depth).
pub fn precheck(dir: &Path, password: &str) -> Result<(), UiError> {
    if exists(dir) {
        return Err(UiError::new(
            "keystore_exists",
            "A keystore already exists on this device.",
        ));
    }
    password::check(password)
        .map_err(|_| UiError::new("weak_password", "Password is too weak."))?;
    Ok(())
}

/// Seal a GIVEN identity under `password` into `dir/keystore/local_key_blob`.
/// Fails closed if a keystore already exists (overwriting destroys the prior
/// identity irrecoverably) and enforces the password policy.
pub fn seal_identity(dir: &Path, password: &str, id: &Identity) -> Result<(), UiError> {
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
    let blob = keyblob::seal(password, id, ARGON2_DESKTOP_TARGET)
        .map_err(|_| UiError::new("keystore", "Could not create keystore."))?;
    let path = keystore_path(dir);
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    std::fs::write(&path, &blob)
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    Ok(())
}

/// Create a fresh identity, seal it under `password`, and write the blob.
pub fn create(dir: &Path, password: &str) -> Result<Identity, UiError> {
    let id = Identity::generate();
    seal_identity(dir, password, &id)?;
    Ok(id)
}

/// Unlock the existing blob with `password`.
pub fn unlock(dir: &Path, password: &str) -> Result<Identity, UiError> {
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    keyblob::unlock(password, &blob).map_err(|_| UiError::new("unauthorized", "Wrong password."))
}

/// Change the keystore password: verify `old`, re-seal under `new`, atomically
/// replace the blob. Weak `new` -> `weak_password` (BEFORE touching the blob);
/// wrong `old` -> `unauthorized`. The identity never leaves this function. On any
/// failure the original blob is left intact (atomic temp-then-rename).
///
/// Wired into a Tauri command in Phase-5 Task 4.
pub fn change_password(dir: &Path, old: &str, new: &str) -> Result<(), UiError> {
    // Fail closed on a weak new password before doing anything to the blob.
    password::check(new).map_err(|_| UiError::new("weak_password", "Password is too weak."))?;
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    // `keyblob::reseal` verifies `old` (it calls `unlock(old, ..)` internally and
    // propagates the error), then re-seals under `new` with a fresh salt. The
    // identity is created and dropped entirely inside `reseal` — it never leaves
    // this function. The new password is already known-strong (checked above), so
    // the only realistic failure here is a wrong `old` password, which must map to
    // `unauthorized` (NOT the generic `keystore` code).
    let new_blob = keyblob::reseal(&blob, old, new, ARGON2_DESKTOP_TARGET)
        .map_err(|_| UiError::new("unauthorized", "Wrong password."))?;
    // Atomic replace within the same directory: write to a sibling temp file and
    // rename over the original, so a mid-write crash leaves the old blob intact.
    let path = keystore_path(dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &new_blob)
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    std::fs::rename(&tmp, &path)
        .map_err(|_| UiError::new("keystore", "Could not write keystore."))?;
    Ok(())
}

/// Copy the already-sealed (Argon2id ciphertext) key blob to `dest` — the portable
/// backup. NEVER decrypts; writes ciphertext only.
///
/// Wired into a Tauri command in Phase-5 Task 4.
pub fn export_keystore(dir: &Path, dest: &str) -> Result<(), UiError> {
    let blob = std::fs::read(keystore_path(dir))
        .map_err(|_| UiError::new("no_keystore", "No keystore on this device."))?;
    std::fs::write(dest, &blob)
        .map_err(|_| UiError::new("export_failed", "Could not write the backup."))?;
    Ok(())
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
    fn seal_identity_then_unlock_roundtrips_specific_identity() {
        let dir = tempdir();
        let pw = "correct horse battery staple 9!";
        let id = Identity::generate();
        let want = id.sig_pub_bytes();
        seal_identity(&dir, pw, &id).unwrap();
        let unlocked = unlock(&dir, pw).unwrap();
        assert_eq!(unlocked.sig_pub_bytes(), want);
    }

    #[test]
    fn seal_identity_refuses_to_overwrite_existing_keystore() {
        let dir = tempdir();
        let pw = "correct horse battery staple 9!";
        seal_identity(&dir, pw, &Identity::generate()).unwrap();
        let err = match seal_identity(&dir, pw, &Identity::generate()) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "keystore_exists");
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
    fn change_password_reseals_blob() {
        let dir = tempdir();
        let old = "correct horse battery staple 9!";
        let id = create(&dir, old).unwrap();
        let want = id.sig_pub_bytes();
        change_password(&dir, old, "a different strong passphrase 7!").unwrap();
        // Old password no longer works; new one unlocks the SAME identity.
        // (`Identity` has no `Debug`, so extract the error code via a match
        // rather than `unwrap_err`.)
        let err = match unlock(&dir, old) {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        };
        assert_eq!(err.code, "unauthorized");
        assert_eq!(
            unlock(&dir, "a different strong passphrase 7!")
                .unwrap()
                .sig_pub_bytes(),
            want
        );
    }

    #[test]
    fn change_password_rejects_wrong_old_and_weak_new() {
        let dir = tempdir();
        create(&dir, "correct horse battery staple 9!").unwrap();
        assert_eq!(
            change_password(
                &dir,
                "wrong-old-password-xyz!",
                "another strong passphrase 7!"
            )
            .unwrap_err()
            .code,
            "unauthorized"
        );
        assert_eq!(
            change_password(&dir, "correct horse battery staple 9!", "weak")
                .unwrap_err()
                .code,
            "weak_password"
        );
        // After a rejected change, the ORIGINAL password still works (no corruption).
        assert!(unlock(&dir, "correct horse battery staple 9!").is_ok());
    }

    #[test]
    fn export_keystore_copies_ciphertext_blob() {
        let dir = tempdir();
        create(&dir, "correct horse battery staple 9!").unwrap();
        let dest = dir.join("backup.blob");
        export_keystore(&dir, dest.to_str().unwrap()).unwrap();
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            std::fs::read(keystore_path(&dir)).unwrap()
        );
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
