//! DEV self-signed pinned TLS cert for the portable launcher. Generates a
//! `localhost` cert on first run, persists it (reused on restart), builds the
//! rustls ServerConfig (aws_lc_rs, TLS 1.3), and exports the DER cert to where a
//! client pins it. PROD injects a real cert (not this).
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;

use crate::layout::Layout;

/// Generate the dev cert if absent (idempotent); write DER cert + DER key.
///
/// The cert always carries `localhost` (DNS SAN) + `127.0.0.1` (IP SAN). When
/// `public_addr` is set it is added too: an IPv4/IPv6 literal becomes an **IP
/// SAN**, a hostname a **DNS SAN**, so a client typing the bare public address
/// passes the pinned TLS handshake. Regenerating for a changed address is an
/// operator action (delete the cert files); this call skips generation if they
/// already exist.
pub fn ensure_dev_cert(layout: &Layout, public_addr: Option<&str>) -> std::io::Result<()> {
    if layout.cert_der_path().exists() && layout.cert_key_path().exists() {
        return Ok(());
    }
    let mut sans = vec![
        san_for("localhost"),
        // Loopback IP literal → IP SAN.
        rcgen::SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])),
    ];
    if let Some(addr) = public_addr.map(str::trim).filter(|s| !s.is_empty()) {
        sans.push(san_for(addr));
    }

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| std::io::Error::other(format!("cert params: {e}")))?;
    params.subject_alt_names = sans;
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| std::io::Error::other(format!("key gen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| std::io::Error::other(format!("cert gen: {e}")))?;

    std::fs::write(layout.cert_der_path(), cert.der().as_ref())?;
    std::fs::write(layout.cert_key_path(), key_pair.serialize_der())?;
    Ok(())
}

/// Classify a SAN string: an IP literal (v4/v6) → IP SAN, anything else → DNS SAN.
/// Hostnames flow through `Ia5String`, which accepts the ASCII host charset; a
/// non-ASCII value falls back to a lossy conversion (dev-only cert generation).
fn san_for(host: &str) -> rcgen::SanType {
    use std::str::FromStr;
    if let Ok(ip) = std::net::IpAddr::from_str(host) {
        rcgen::SanType::IpAddress(ip)
    } else {
        let ia5 = rcgen::Ia5String::try_from(host.to_owned())
            .unwrap_or_else(|_| rcgen::Ia5String::try_from("localhost".to_owned()).unwrap());
        rcgen::SanType::DnsName(ia5)
    }
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
        ensure_dev_cert(&layout, None).unwrap();
        let first = std::fs::read(layout.cert_der_path()).unwrap();
        // Idempotent: a second call does not regenerate (bytes stable).
        ensure_dev_cert(&layout, None).unwrap();
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

    /// Mirror of `client-app/src/transport.rs::pinned_client_config`: pin exactly
    /// the given cert as the sole root, TLS 1.3-only, aws-lc-rs provider, no client
    /// auth. Built the SAME way the real client builds it so this test validates
    /// the IP SAN through the exact verifier the client uses.
    fn pinned_client_config(
        server_cert: CertificateDer<'static>,
    ) -> Arc<tokio_rustls::rustls::ClientConfig> {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(server_cert).unwrap();
        let cfg = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    }

    /// End-to-end proof that an IP SAN validates through the client's pinned
    /// verifier: generate a cert for public_addr `1.2.3.4`, serve TLS with it, and
    /// complete a pinned TLS 1.3 handshake connecting by `ServerName::IpAddress`.
    #[tokio::test]
    async fn ip_san_validates_through_pinned_client_handshake() {
        use tokio_rustls::rustls::pki_types::ServerName;

        let dir = tmp();
        let layout = Layout::ensure(&dir).unwrap();
        // Cert with the public IP as an IP SAN.
        ensure_dev_cert(&layout, Some("1.2.3.4")).unwrap();
        let server_config = load_server_config(&layout).unwrap();
        let cert_der = CertificateDer::from(std::fs::read(layout.cert_der_path()).unwrap());

        // Bind a loopback listener; the SNI/SAN we validate is `1.2.3.4`, decoupled
        // from the transport address (which is loopback for the test).
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept one connection and drive its side of the TLS handshake.
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let (tcp, _) = listener.accept().await.unwrap();
            // Completing the accept means the client's certificate check passed.
            acceptor.accept(tcp).await.map(|_| ())
        });

        // Client: pin the cert, connect by IP-literal ServerName, handshake. The
        // handshake completing is the assertion — cert (incl. IP-SAN) validation
        // happens during it, through the exact verifier the real client uses.
        let client_config = pinned_client_config(cert_der);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        // rustls' pki-types `IpAddr` is built from a std `IpAddr` (mirrors how the
        // client turns a typed IP into a `ServerName`).
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let server_name = ServerName::IpAddress(ip.into());
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(server_name, tcp)
            .await
            .expect("pinned client handshake with IP SAN must succeed");

        server
            .await
            .unwrap()
            .expect("server handshake must succeed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
