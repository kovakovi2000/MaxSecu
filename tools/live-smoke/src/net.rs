//! Pinned-transport connection + raw JSON GET/POST helpers over a live server.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use std::path::Path;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};

use maxsecu_client_app::transport::{pinned_client_config, Transport};

pub struct Conn {
    pub sender: SendRequest<Full<Bytes>>,
    pub exporter: [u8; 32],
}

/// Read the pinned `server_cert.der` from `<client_dir>/config/` and build a
/// Transport that pins it and verifies the SAN against `host` (the public IP).
pub fn transport(client_dir: &Path, host: &str, server: &str) -> Result<Transport, String> {
    let cert_path = client_dir.join("config").join("server_cert.der");
    let der = std::fs::read(&cert_path)
        .map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    let cfg = pinned_client_config(CertificateDer::from(der))
        .map_err(|e| format!("pin cert: {}", e.message))?;
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| format!("invalid server_name '{host}'"))?;
    Ok(Transport::new(cfg, name, server.to_owned()))
}

/// Open one pinned-TLS connection and drive an http1 client over it.
pub async fn open(t: &Transport) -> Result<Conn, String> {
    let (tls, exporter) = t.connect().await.map_err(|e| format!("connect: {}", e.message))?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| format!("http handshake: {e}"))?;
    tokio::spawn(async move { let _ = conn.await; });
    Ok(Conn { sender, exporter })
}

#[allow(dead_code)]
pub async fn post(
    c: &mut Conn,
    uri: &str,
    host: &str,
    auth: Option<&str>,
    body: serde_json::Value,
) -> Result<(hyper::StatusCode, serde_json::Value), String> {
    maxsecu_client_app::http_client::post_json(&mut c.sender, uri, &body, auth, host)
        .await
        .map_err(|e| format!("POST {uri}: {}", e.message))
}

#[allow(dead_code)]
pub async fn get(
    c: &mut Conn,
    uri: &str,
    host: &str,
    auth: Option<&str>,
) -> Result<(hyper::StatusCode, serde_json::Value), String> {
    maxsecu_client_app::http_client::get_json(&mut c.sender, uri, auth, host)
        .await
        .map_err(|e| format!("GET {uri}: {}", e.message))
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{x:02x}")); }
    s
}

#[allow(dead_code)]
pub fn hex16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 { return Err(format!("bad user_id hex len: {}", s.len())); }
    if !s.is_ascii() { return Err("user_id hex is not ASCII".into()); }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

#[allow(dead_code)]
pub fn b64(bytes: &[u8]) -> String { B64.encode(bytes) }
