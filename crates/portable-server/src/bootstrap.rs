//! DEV bootstrap artifacts for the portable launcher — SECURITY-DEGRADED, dev-only.
//! - A one-time bootstrap secret: generated on first run, printed ONCE by the
//!   caller, stored only as sha256 (+ a marker so it isn't reprinted).
//! - A DEV directory-signing (D5) key: persisted as a 32-byte SEED so the pinned
//!   public key is STABLE across restarts. In PRODUCTION the D5 private key is
//!   offline (the air-gapped ceremony) and only its PUBLIC key is pinned — this
//!   dev key is a convenience, never a production ceremony key.
use maxsecu_admin_core::DirectorySigner;

use crate::layout::Layout;

/// First run (no marker) → generate a random bootstrap secret, store sha256(secret)
/// to the marker, return Some(secret) so the caller prints it ONCE. Subsequent runs
/// → None (already bootstrapped; the hash is unchanged).
pub fn ensure_bootstrap_secret(layout: &Layout) -> std::io::Result<Option<String>> {
    if layout.bootstrap_marker_path().exists() {
        return Ok(None);
    }
    // URL-safe base64 of 24 random bytes — copy-pasteable, high-entropy.
    let raw: [u8; 24] = maxsecu_crypto::random_array();
    let secret = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        URL_SAFE_NO_PAD.encode(raw)
    };
    let hash = maxsecu_crypto::sha256(secret.as_bytes());
    std::fs::write(layout.bootstrap_marker_path(), hash)?; // 32 raw bytes
    Ok(Some(secret))
}

/// Read the stored bootstrap-secret hash for `AuthConfig.with_bootstrap_secret_hash`,
/// or None if not yet bootstrapped.
pub fn bootstrap_secret_hash(layout: &Layout) -> std::io::Result<Option<[u8; 32]>> {
    match std::fs::read(layout.bootstrap_marker_path()) {
        Ok(b) if b.len() == 32 => Ok(Some(b.try_into().unwrap())),
        Ok(_) => Err(std::io::Error::other("bootstrap marker malformed")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

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
    fn bootstrap_secret_is_one_time_and_hash_persists() {
        let layout = Layout::ensure(&tmp()).unwrap();
        let secret = ensure_bootstrap_secret(&layout)
            .unwrap()
            .expect("first run returns the secret");
        let stored = bootstrap_secret_hash(&layout).unwrap().unwrap();
        assert_eq!(stored, maxsecu_crypto::sha256(secret.as_bytes()));
        // Second run: no secret returned, hash unchanged.
        assert!(ensure_bootstrap_secret(&layout).unwrap().is_none());
        assert_eq!(bootstrap_secret_hash(&layout).unwrap().unwrap(), stored);
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
