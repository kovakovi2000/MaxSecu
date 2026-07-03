//! DEV directory-signing artifacts for the portable launcher — SECURITY-DEGRADED,
//! dev-only. A DEV directory-signing (D5) key persisted as a 32-byte SEED so the
//! pinned public key is STABLE across restarts. In PRODUCTION the D5 private key
//! is offline (the air-gapped ceremony) and only its PUBLIC key is pinned — this
//! dev key is a convenience, never a production ceremony key.
//!
//! There is NO bootstrap secret: enrollment is registration-key-only (the server
//! signs bindings with the D5 key derived from this seed; the first registrant
//! becomes admin), and the recovery account is provisioned once by `maxsecu-setup`.
use maxsecu_admin_core::DirectorySigner;

use crate::layout::Layout;

/// Generate (first run) / load (restart) the DEV D5 key from a persisted 32-byte
/// seed; write its public key to `d5_pub_path`; return the public key. Stable
/// across restarts (so a client that pinned it stays valid).
pub fn ensure_dev_d5(layout: &Layout) -> std::io::Result<[u8; 32]> {
    let seed: [u8; 32] = match std::fs::read(layout.d5_secret_path()) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        Ok(_) => return Err(std::io::Error::other("d5 seed malformed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s: [u8; 32] = maxsecu_crypto::random_array();
            std::fs::write(layout.d5_secret_path(), s)?;
            s
        }
        Err(e) => return Err(e),
    };
    let pubkey = DirectorySigner::from_seed(&seed).public_key();
    std::fs::write(layout.d5_pub_path(), pubkey)?;
    Ok(pubkey)
}

/// Read the persisted 32-byte dev D5 seed (must exist — call after
/// [`ensure_dev_d5`]). The server signs enrollment bindings with the key derived
/// from this seed; its public half is the pinned `directory_pub`. DEV-only: in
/// production the signing key is the offline ceremony key, never on the server.
pub fn dev_d5_seed(layout: &Layout) -> std::io::Result<[u8; 32]> {
    match std::fs::read(layout.d5_secret_path()) {
        Ok(b) if b.len() == 32 => Ok(b.try_into().unwrap()),
        Ok(_) => Err(std::io::Error::other("d5 seed malformed")),
        Err(e) => Err(e),
    }
}

/// Copy the dev D5 public key to `<client_config_dir>/directory_pub.der` (where the
/// client pins it). Call after `ensure_dev_d5`.
pub fn export_client_pin_d5(
    layout: &Layout,
    client_config_dir: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::create_dir_all(client_config_dir)?;
    std::fs::copy(
        layout.d5_pub_path(),
        client_config_dir.join("directory_pub.der"),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxps-boot-{}-{}",
            std::process::id(),
            maxsecu_crypto::random_array::<4>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn dev_d5_is_stable_across_calls() {
        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        let p1 = ensure_dev_d5(&layout).unwrap();
        let p2 = ensure_dev_d5(&layout).unwrap(); // reloads the persisted seed
        assert_eq!(p1, p2, "pinned D5 pubkey must be stable across restarts");
        // Export to a client config dir.
        let client = dir.join("client-config");
        export_client_pin_d5(&layout, &client).unwrap();
        assert_eq!(
            std::fs::read(client.join("directory_pub.der")).unwrap(),
            p1.to_vec()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
