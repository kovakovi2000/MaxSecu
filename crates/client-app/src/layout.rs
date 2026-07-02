//! The client's portable folder layout (spec §8.1). A single signed exe self-
//! extracts/uses a portable folder beside it; these sub-dirs hold the at-rest
//! ciphertext state (keystore), pinned trust + connection config, the encrypted
//! search index, the ciphertext blob cache, and sanitized logs. `ensure_portable_layout`
//! creates them on startup (idempotent) so first-run writes never fail on a missing dir.
//!
//! ```text
//! MaxSecuClient/
//!   MaxSecuClient.exe
//!   config/    connection.json, settings.json, server_cert.der, directory_pub.der, recovery_recipient.txt
//!   keystore/  local_key_blob (Argon2id-wrapped identity)
//!   index/     search.idx (encrypted title+tag index)
//!   cache/     ciphertext-only blob cache (rebuilt on demand)
//!   logs/      sanitized logs (no secrets/plaintext)
//! ```

use std::path::Path;

/// Create the portable sub-dirs beside the exe if absent (idempotent). Best-effort:
/// callers may log and continue on failure (the individual writers also create
/// their own parent dirs).
pub fn ensure_portable_layout(dir: &Path) -> std::io::Result<()> {
    for sub in ["config", "keystore", "index", "cache", "logs", "staging"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_creates_all_subdirs_idempotently() {
        let tmp = std::env::temp_dir().join(format!("mxcl-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        ensure_portable_layout(&tmp).unwrap();
        for sub in ["config", "keystore", "index", "cache", "logs", "staging"] {
            assert!(tmp.join(sub).is_dir(), "{sub} should exist");
        }
        // Idempotent.
        ensure_portable_layout(&tmp).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
