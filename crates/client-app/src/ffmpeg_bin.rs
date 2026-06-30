//! Embedded, integrity-pinned static ffmpeg (D-1 of universal video ingest).
//!
//! The vendored static `ffmpeg.exe` is baked into this binary via
//! `include_bytes!` and pinned to a SHA-256 ([`FFMPEG_SHA256`]). At runtime
//! [`ensure_ffmpeg`] materializes it to `<appdir>/bin/ffmpeg-<sha8>.exe` and
//! **hash-verifies the on-disk copy every run**, re-extracting the in-binary
//! copy on any mismatch (tamper / truncation / partial write). A crash during
//! extraction can never leave a half-written exe at the final path because the
//! bytes are written to a same-directory temp file and then atomically renamed
//! into place.
//!
//! # Feature gate: `embed-ffmpeg` (default-on)
//! `include_bytes!` requires `vendor/ffmpeg/ffmpeg.exe` to exist at build time.
//! To keep the workspace buildable for a contributor who has NOT run
//! `scripts/fetch-ffmpeg.ps1` (the binary is gitignored), the embed lives behind
//! the default-on `embed-ffmpeg` feature:
//!
//! * `--features embed-ffmpeg` (the default): the real `include_bytes!`,
//!   [`ensure_ffmpeg`], and the embed tests are compiled. This is the path
//!   exercised in CI / release builds where the binary is present.
//! * `--no-default-features` (binary absent): [`ensure_ffmpeg`] is a stub that
//!   fail-closes with `video_unavailable` and there is NO `include_bytes!`, so
//!   the crate still compiles with no vendored binary on disk.
//!
//! [`FFMPEG_SHA256`] is defined in both configurations (it is just a constant).

use std::path::{Path, PathBuf};

use crate::error::UiError;

/// SHA-256 of the vendored static ffmpeg, pinned at build time.
///
/// hex: `6ed7e5c931d3cbc72931ee7e97efc4b7d8a1287f03c60585fab81a6a293b2e0e`
pub const FFMPEG_SHA256: [u8; 32] = [
    0x6e, 0xd7, 0xe5, 0xc9, 0x31, 0xd3, 0xcb, 0xc7, 0x29, 0x31, 0xee, 0x7e, 0x97, 0xef, 0xc4, 0xb7,
    0xd8, 0xa1, 0x28, 0x7f, 0x03, 0xc6, 0x05, 0x85, 0xfa, 0xb8, 0x1a, 0x6a, 0x29, 0x3b, 0x2e, 0x0e,
];

/// The vendored static ffmpeg, baked into this binary. Present only when the
/// `embed-ffmpeg` feature is enabled (the default).
#[cfg(feature = "embed-ffmpeg")]
static FFMPEG_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/ffmpeg/ffmpeg.exe"
));

/// The single sanitized error this module surfaces. Mirrors the sanitized-error
/// posture of `error.rs`: no path / IO detail ever reaches the UI.
#[cfg(feature = "embed-ffmpeg")]
fn video_unavailable() -> UiError {
    UiError::new("video_unavailable", "Video support is unavailable.")
}

/// First 8 lowercase hex chars (the first 4 bytes) of the pinned digest,
/// derived from the constant so the on-disk filename can never drift from the
/// pin. For the current pin this is `6ed7e5c9`.
#[cfg(feature = "embed-ffmpeg")]
fn sha8() -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(8);
    for b in &FFMPEG_SHA256[..4] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The stable materialization path: `<appdir>/bin/ffmpeg-<sha8>.exe`.
#[cfg(feature = "embed-ffmpeg")]
fn target_path(appdir: &Path) -> PathBuf {
    appdir.join("bin").join(format!("ffmpeg-{}.exe", sha8()))
}

/// A process-unique suffix for the same-directory temp file. Avoids pulling in
/// an external temp-dir crate while keeping concurrent extractions distinct.
#[cfg(feature = "embed-ffmpeg")]
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), t, n)
}

/// Materialize the embedded ffmpeg to `<appdir>/bin/ffmpeg-<sha8>.exe`,
/// hash-verifying the on-disk copy and re-extracting on any mismatch.
///
/// Fast path: if the target exists and its SHA-256 already equals
/// [`FFMPEG_SHA256`], it is returned with zero writes (idempotent). Otherwise
/// the embedded bytes are defensively re-verified against the pin (guarding a
/// corrupt embed — fail closed if they ever disagree), written to a
/// same-directory temp file, and atomically renamed into place.
///
/// All IO failures collapse to a sanitized `video_unavailable` `UiError`.
#[cfg(feature = "embed-ffmpeg")]
pub fn ensure_ffmpeg(appdir: &Path) -> Result<PathBuf, UiError> {
    let target = target_path(appdir);

    // Fast path: an already-correct copy is returned untouched.
    if let Ok(bytes) = std::fs::read(&target) {
        if maxsecu_crypto::sha256(&bytes) == FFMPEG_SHA256 {
            return Ok(target);
        }
    }

    // Defensive: never extract a corrupt embed. Fail closed on mismatch.
    if maxsecu_crypto::sha256(FFMPEG_BYTES) != FFMPEG_SHA256 {
        return Err(video_unavailable());
    }

    let bin_dir = target.parent().ok_or_else(video_unavailable)?;
    std::fs::create_dir_all(bin_dir).map_err(|_| video_unavailable())?;

    // Write to a same-directory temp file, then atomically rename. A crash
    // mid-write leaves only the temp file, never a half-written final exe.
    let tmp = bin_dir.join(format!("ffmpeg-{}.exe.tmp-{}", sha8(), unique_suffix()));
    if std::fs::write(&tmp, FFMPEG_BYTES).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(video_unavailable());
    }

    // Windows refuses `rename` onto an existing path; clear any stale/tampered
    // target first so the re-extract (tamper-recovery) case succeeds.
    if target.exists() && std::fs::remove_file(&target).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(video_unavailable());
    }
    if std::fs::rename(&tmp, &target).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(video_unavailable());
    }

    Ok(target)
}

/// Stub used when the `embed-ffmpeg` feature is off and no binary is embedded.
/// Fail-closes with the same sanitized error so callers behave uniformly.
#[cfg(not(feature = "embed-ffmpeg"))]
pub fn ensure_ffmpeg(_appdir: &Path) -> Result<PathBuf, UiError> {
    Err(UiError::new(
        "video_unavailable",
        "Video support is unavailable.",
    ))
}

#[cfg(all(test, feature = "embed-ffmpeg"))]
mod tests {
    use super::*;

    /// A fresh, empty temp dir per test, with any prior remnant cleared.
    fn fresh_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("maxsecu-ffmpeg-test-{tag}-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // (a) The embedded bytes match the pin.
    #[test]
    fn embedded_bytes_match_pin() {
        assert_eq!(maxsecu_crypto::sha256(FFMPEG_BYTES), FFMPEG_SHA256);
    }

    // (b) ensure_ffmpeg materializes bin/ffmpeg-<sha8>.exe whose hash == pin.
    #[test]
    fn ensure_materializes_verified_exe() {
        let dir = fresh_dir("materialize");
        let path = ensure_ffmpeg(&dir).unwrap();
        assert_eq!(path, dir.join("bin").join("ffmpeg-6ed7e5c9.exe"));
        assert!(path.exists());
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(maxsecu_crypto::sha256(&on_disk), FFMPEG_SHA256);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (c) A tampered on-disk copy is re-extracted to the correct bytes.
    #[test]
    fn ensure_reextracts_after_tamper() {
        let dir = fresh_dir("tamper");
        let path = ensure_ffmpeg(&dir).unwrap();

        // Tamper: overwrite the materialized file with garbage.
        std::fs::write(&path, b"not a real ffmpeg binary").unwrap();
        assert_ne!(
            maxsecu_crypto::sha256(&std::fs::read(&path).unwrap()),
            FFMPEG_SHA256
        );

        let path2 = ensure_ffmpeg(&dir).unwrap();
        assert_eq!(path, path2);
        assert_eq!(
            maxsecu_crypto::sha256(&std::fs::read(&path2).unwrap()),
            FFMPEG_SHA256
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // (d) A second call over an already-correct file is a no-op: the fast path
    // performs zero writes, so the file's mtime is byte-identical (proving no
    // needless rewrite — robust on the target NTFS / 100ns-resolution FS).
    #[test]
    fn ensure_is_idempotent_no_rewrite() {
        let dir = fresh_dir("idempotent");
        let path = ensure_ffmpeg(&dir).unwrap();
        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();

        let path2 = ensure_ffmpeg(&dir).unwrap();
        let mtime2 = std::fs::metadata(&path2).unwrap().modified().unwrap();

        assert_eq!(path, path2);
        assert_eq!(mtime1, mtime2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
