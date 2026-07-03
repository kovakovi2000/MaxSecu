//! **Startup-mode precedence** (spec §5 / §0-D7). On launch the client picks its
//! initial screen from files present beside the exe, in a fixed precedence order:
//!
//!   1. a cold **recovery** keyblob (`<app-dir>/recovery/recovery_key_blob`, Task 11)
//!      → `recovery` — the operator is recovering an untrusted server; this WINS
//!      even if a registration key is ALSO present (recovery is the higher-trust
//!      break-glass path and must never be shadowed by a stray register file),
//!   2. else a single-use **registration** key (`<app-dir>/register.key`, Task 12)
//!      → `register` — a fresh enrollee turns the key into a real account,
//!   3. else → `normal` — the usual keystore-unlock + connect login.
//!
//! This command only ever returns the mode *string* — it reads no key material and
//! opens neither file (a bare `exists()` check), so nothing secret crosses the seam.
//! The UI (`app-shell.ts`) calls it once on boot and routes accordingly; the user
//! can still reach other screens afterwards, only the INITIAL screen follows this
//! precedence.

use std::path::Path;

use crate::dto::StartupMode;

use super::auth::AppDir;
use super::recovery_login::recovery_key_path;
use super::register::register_key_path;

/// Resolve the startup mode from the files present beside the exe (pure; testable).
/// Precedence: recovery-key file → `Recovery` (even if a register file also exists),
/// else register-key file → `Register`, else `Normal`. Only presence is checked; no
/// file is opened, so no secret is read.
pub fn resolve_startup_mode(dir: &Path) -> StartupMode {
    if recovery_key_path(dir).exists() {
        StartupMode::Recovery
    } else if register_key_path(dir).exists() {
        StartupMode::Register
    } else {
        StartupMode::Normal
    }
}

/// `startup_mode` — report the initial screen the UI should route to on launch.
/// Returns only the opaque mode string; reads no key material (spec §0-D7).
#[tauri::command]
pub fn startup_mode(dir: tauri::State<'_, AppDir>) -> StartupMode {
    resolve_startup_mode(&dir.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tempdir() -> PathBuf {
        // A per-call atomic counter (not the wall clock) guarantees uniqueness even
        // when tests run in parallel on a coarse-resolution clock.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "mxstartup-ut-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_recovery(dir: &Path) {
        let p = recovery_key_path(dir);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"sealed-recovery-blob").unwrap();
    }

    fn write_register(dir: &Path) {
        std::fs::write(register_key_path(dir), b"single-use-key").unwrap();
    }

    #[test]
    fn neither_file_present_is_normal() {
        let dir = tempdir();
        assert_eq!(resolve_startup_mode(&dir), StartupMode::Normal);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_register_file_is_register() {
        let dir = tempdir();
        write_register(&dir);
        assert_eq!(resolve_startup_mode(&dir), StartupMode::Register);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_recovery_file_is_recovery() {
        let dir = tempdir();
        write_recovery(&dir);
        assert_eq!(resolve_startup_mode(&dir), StartupMode::Recovery);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_wins_when_both_files_present() {
        // Precedence: a recovery keyblob shadows a registration key — the operator
        // is recovering an untrusted server, which must never be down-graded to a
        // fresh-enrollment flow by a stray register.key sitting beside it.
        let dir = tempdir();
        write_register(&dir);
        write_recovery(&dir);
        assert_eq!(resolve_startup_mode(&dir), StartupMode::Recovery);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_mode_serializes_to_bare_lowercase_string() {
        // Only the mode string crosses the seam (no wrapper object, no key material).
        assert_eq!(
            serde_json::to_string(&StartupMode::Recovery).unwrap(),
            "\"recovery\""
        );
        assert_eq!(
            serde_json::to_string(&StartupMode::Register).unwrap(),
            "\"register\""
        );
        assert_eq!(
            serde_json::to_string(&StartupMode::Normal).unwrap(),
            "\"normal\""
        );
    }
}
