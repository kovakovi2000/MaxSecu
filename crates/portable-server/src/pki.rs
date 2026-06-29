//! DEV self-signed pinned TLS cert for the portable launcher. Generates a
//! `localhost` cert on first run, persists it (reused on restart), builds the
//! rustls ServerConfig (aws_lc_rs, TLS 1.3), and exports the DER cert to where a
//! client pins it. PROD injects a real cert (not this).
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;

use crate::layout::Layout;

/// Generate the dev cert if absent (idempotent); write DER cert + DER key.
pub fn ensure_dev_cert(layout: &Layout) -> std::io::Result<()> {
    if layout.cert_der_path().exists() && layout.cert_key_path().exists() {
        return Ok(());
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| std::io::Error::other(format!("cert gen: {e}")))?;
    std::fs::write(layout.cert_der_path(), cert.cert.der().as_ref())?;
    std::fs::write(layout.cert_key_path(), cert.key_pair.serialize_der())?;
    Ok(())
}

/// Build the rustls ServerConfig from the persisted dev cert/key.
pub fn load_server_config(layout: &Layout) -> std::io::Result<Arc<ServerConfig>> {
    let cert_bytes = std::fs::read(layout.cert_der_path())?;
    let key_bytes = std::fs::read(layout.cert_key_path())?;
    let cert = CertificateDer::from(cert_bytes);
    let key = PrivateKeyDer::try_from(key_bytes)
        .map_err(|e| std::io::Error::other(format!("key: {e}")))?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("tls: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| std::io::Error::other(format!("tls cert: {e}")))?;
    Ok(Arc::new(config))
}

/// Copy the DER cert to `<client_config_dir>/server_cert.der` (the client pins it).
pub fn export_client_pin(
    layout: &Layout,
    client_config_dir: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::create_dir_all(client_config_dir)?;
    std::fs::copy(
        layout.cert_der_path(),
        client_config_dir.join("server_cert.der"),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mxps-pki-{}-{}",
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
    fn cert_is_generated_idempotently_and_loads() {
        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        ensure_dev_cert(&layout).unwrap();
        let first = std::fs::read(layout.cert_der_path()).unwrap();
        // Idempotent: a second call does not regenerate (bytes stable).
        ensure_dev_cert(&layout).unwrap();
        assert_eq!(std::fs::read(layout.cert_der_path()).unwrap(), first);
        // The DER cert parses, and the ServerConfig builds.
        let _cert = CertificateDer::from(first);
        let _cfg = load_server_config(&layout).unwrap();
        // Export to a client config dir.
        let client = dir.join("client-config");
        export_client_pin(&layout, &client).unwrap();
        assert!(client.join("server_cert.der").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
