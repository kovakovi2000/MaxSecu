//! ConnectionConfig: where to connect and whether to auto-connect. The test
//! build ships an auto-connect config (spec §4.4); the "later" build leaves
//! `auto_connect=false` and the user types the server on the connect screen.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::UiError;

/// Load the pinned offline **directory-signing (D5) public key** (§7.3) from
/// `<dir>/config/directory_pub.der` (32 raw bytes). The trust root the client
/// verifies every served binding against; absent or malformed ⇒ fail closed with
/// a sanitized `untrusted` error (no browse/admin without a pinned root). Mirrors
/// the pinned server-cert source used by `commands::connection::open_conn`.
pub fn load_directory_pub(dir: &Path) -> Result<[u8; 32], UiError> {
    let path = dir.join("config").join("directory_pub.der");
    let bytes = std::fs::read(&path)
        .map_err(|_| UiError::new("untrusted", "This server's directory key is not pinned."))?;
    bytes
        .try_into()
        .map_err(|_| UiError::new("untrusted", "The pinned directory key is malformed."))
}

// Loaded by the UI in a later phase (Task 10) to prefill the connect form /
// drive auto-connect; Phase-1 `connect` takes its parameters straight from the
// ConnectRequest, so this type is not yet read by the binary.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConnectionConfig {
    pub server: String,
    pub use_tor: bool,
    pub auto_connect: bool,
}

#[allow(dead_code)] // load/save wired by the UI in Task 10 (see type comment).
impl ConnectionConfig {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("config").join("connection.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let p = dir.join("config");
        std::fs::create_dir_all(&p)?;
        std::fs::write(
            p.join("connection.json"),
            serde_json::to_vec_pretty(self).unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_directory_pub_reads_pinned_key() {
        let tmp = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(tmp.join("config")).unwrap();
        // Missing → a sanitized "untrusted" error (fail closed; no admin/browse
        // without a pinned root).
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        // Present (exactly 32 bytes) → returned verbatim.
        let key = [0x7Du8; 32];
        std::fs::write(tmp.join("config").join("directory_pub.der"), key).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap(), key);
        // Wrong length → fail closed.
        std::fs::write(tmp.join("config").join("directory_pub.der"), [0u8; 31]).unwrap();
        assert_eq!(load_directory_pub(&tmp).unwrap_err().code, "untrusted");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_config_defaults_to_manual() {
        let dir = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = ConnectionConfig::load(&dir);
        assert!(!cfg.auto_connect);
        assert_eq!(cfg.server, "");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("maxsecu-cfg-{}", n()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = ConnectionConfig {
            server: "localhost:8443".into(),
            use_tor: false,
            auto_connect: true,
        };
        cfg.save(&dir).unwrap();
        assert_eq!(ConnectionConfig::load(&dir), cfg);
    }

    fn n() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
