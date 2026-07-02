//! The pinned out-of-band **sink** client seam (T4 / spec §0 D-OQ1). A reshare's
//! revocation anchor MUST come from the independent, out-of-band sink — NOT the
//! untrusted app server's advisory `chain_head` — so a compromised operator can
//! neither forge a stale anchor nor withhold the real one. This module is the
//! thin client-app adapter over `client_core::sink::HttpSinkClient`: it dials the
//! sink over its OWN pinned TLS identity (independent of the app server), fetches
//! the anchored control-log head, and returns the head's 32 bytes ONLY after an
//! anchor proof validates against the offline-pinned allowlist
//! ([`crate::config::SinkPins`]). Any transport failure, a forged proof, or a
//! proof from an un-pinned signer fails closed to a sanitized [`UiError`] — never
//! a "best effort" head.
//!
//! Task 5 (`TombstoneSet`) consumes [`fetch_anchored_head`]'s validated head to
//! reject a server-served tombstone chain that is short (withheld tail), forked,
//! or rolled back relative to this independently-attested head.

use crate::config::SinkPins;
use crate::error::UiError;
use maxsecu_client_core::sink::{verify_anchor_proof, HttpSinkClient, SinkError};

/// Fetch the sink's current anchored control-log head over the pinned channel and
/// return its 32-byte head ONLY if at least one served anchor proof validates
/// against the pinned custodian / transparency-log allowlists (spec §0 D-OQ1).
///
/// Fail-closed on every unhappy path:
/// * transport/parse failure ([`SinkError::Unreachable`]) ⇒ `sink_unreachable`;
/// * NO pinned anchor-proof form validates the served head (a forged proof, a
///   tampered head, or a proof from an un-pinned signer) ⇒ `sink_unverified`.
///
/// The returned `UiError` carries only a stable machine code + short message; no
/// internal detail (addresses, crypto internals) crosses the command boundary.
pub fn fetch_anchored_head(pins: &SinkPins) -> Result<[u8; 32], UiError> {
    let client = HttpSinkClient::new(pins.addr, pins.server_name.clone(), pins.tls.clone());
    let (head, proofs) = client.fetch_head_all_proofs().map_err(map_sink_err)?;
    // The served bytes are UNTRUSTED until a pinned anchor-proof form validates
    // them (mirrors `client_core::sink::confirm_anchored`): accept iff ANY served
    // proof verifies under the pinned allowlists. An empty allowlist makes the
    // corresponding form unvalidatable, so an un-pinned signer can never pass.
    let trusted = proofs.iter().any(|p| {
        verify_anchor_proof(&head, p, &pins.custodian_pubs, &pins.transparency_log_pubs).is_ok()
    });
    if trusted {
        Ok(head.head)
    } else {
        Err(UiError::new(
            "sink_unverified",
            "The revocation anchor could not be verified.",
        ))
    }
}

/// Collapse a `client_core` [`SinkError`] to a sanitized [`UiError`]. A transport
/// failure is distinguished from an unverifiable head (both fail closed); neither
/// leaks internal detail.
fn map_sink_err(e: SinkError) -> UiError {
    match e {
        SinkError::Unreachable => UiError::new(
            "sink_unreachable",
            "The revocation anchor could not be fetched.",
        ),
        // `fetch_head_all_proofs` only ever yields `Unreachable`, but map the
        // remaining variants to the same fail-closed "unverified" shape so this
        // stays total if the caller graph widens (no internal detail leaks).
        SinkError::BadProof | SinkError::NotAnchored => UiError::new(
            "sink_unverified",
            "The revocation anchor could not be verified.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{client_config_for_pinned_root, SinkPins};
    use base64::Engine;
    use maxsecu_crypto::SigningKey;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::ServerConfig;

    const HEAD: [u8; 32] = [0xAB; 32];
    const CHAIN_SEQ: u64 = 7;

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// A self-signed `localhost` cert: the sink's server config + its DER (which
    /// the pinned client config trusts as its ONLY root).
    fn test_pki() -> (Arc<ServerConfig>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::try_from(key_der).unwrap(),
            )
            .unwrap();
        (Arc::new(server_config), cert_der)
    }

    /// The §3.1 head JSON: a custodian co-signature over the head's signing bytes
    /// plus a well-formed-but-inert transparency block (zeros — it PARSES so the
    /// caller gets both proof forms, but verifies against no pinned log key, so
    /// the custodian co-signature is the only path to trust).
    fn head_json(chain_seq: u64, head: [u8; 32], cosig: [u8; 64]) -> String {
        serde_json::json!({
            "chain_seq": chain_seq,
            "head_b64": b64(&head),
            "cosig_b64": b64(&cosig),
            "transparency": {
                "checkpoint_sig_b64": b64(&[0u8; 64]),
                "tree_size": 0,
                "root_b64": b64(&[0u8; 32]),
                "index": 0,
                "path_b64": [],
            }
        })
        .to_string()
    }

    /// Serve the given head JSON on `GET /v1/control-log/head` over loopback TLS.
    /// Runs on its OWN background thread + current-thread runtime so the test
    /// thread can call the (internally blocking) `fetch_anchored_head` without a
    /// nested-runtime panic. Returns the ephemeral socket address.
    fn spawn_head_sink(server_config: Arc<ServerConfig>, body: String) -> SocketAddr {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                tx.send(listener.local_addr().unwrap()).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                loop {
                    let (tcp, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let acceptor = acceptor.clone();
                    let body = body.clone();
                    tokio::spawn(async move {
                        use http_body_util::{BodyExt, Full};
                        use hyper::body::Bytes;
                        use hyper::service::service_fn;
                        use hyper_util::rt::TokioIo;
                        let tls = match acceptor.accept(tcp).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let body = body.clone();
                            async move {
                                let is_head = req.uri().path() == "/v1/control-log/head";
                                let _ = req.into_body().collect().await;
                                let resp = if is_head {
                                    hyper::Response::builder()
                                        .status(200)
                                        .body(Full::<Bytes>::from(body))
                                        .unwrap()
                                } else {
                                    hyper::Response::builder()
                                        .status(404)
                                        .body(Full::<Bytes>::new(Bytes::new()))
                                        .unwrap()
                                };
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), svc)
                            .await;
                    });
                }
            });
        });
        rx.recv().unwrap()
    }

    /// A validly-anchored head is returned ONLY after the pinned custodian's
    /// co-signature verifies (the D-OQ1 foundation: a cryptographically-validated
    /// head sourced from the sink, bypassing the app server).
    #[test]
    fn valid_anchor_yields_the_head() {
        let custodian = SigningKey::generate();
        let cosig = custodian.sign_raw(&maxsecu_encoding::sink_head_signing_input(CHAIN_SEQ, &HEAD));
        let (server_config, cert_der) = test_pki();
        let addr = spawn_head_sink(server_config, head_json(CHAIN_SEQ, HEAD, cosig));
        let pins = SinkPins {
            addr,
            server_name: "localhost".into(),
            tls: client_config_for_pinned_root(&cert_der).unwrap(),
            custodian_pubs: vec![custodian.verifying_key().to_bytes()],
            transparency_log_pubs: vec![],
        };
        assert_eq!(fetch_anchored_head(&pins).unwrap(), HEAD);
    }

    /// A head whose only proof is signed by an UN-pinned custodian fails closed —
    /// the server cannot substitute a self-attested head.
    #[test]
    fn unpinned_custodian_fails_closed() {
        let real = SigningKey::generate();
        let other = SigningKey::generate();
        let cosig = real.sign_raw(&maxsecu_encoding::sink_head_signing_input(CHAIN_SEQ, &HEAD));
        let (server_config, cert_der) = test_pki();
        let addr = spawn_head_sink(server_config, head_json(CHAIN_SEQ, HEAD, cosig));
        let pins = SinkPins {
            addr,
            server_name: "localhost".into(),
            tls: client_config_for_pinned_root(&cert_der).unwrap(),
            // Pin only `other` (and no transparency log) — the real signer is not trusted.
            custodian_pubs: vec![other.verifying_key().to_bytes()],
            transparency_log_pubs: vec![],
        };
        let err = fetch_anchored_head(&pins).unwrap_err();
        assert_eq!(err.code, "sink_unverified");
    }

    /// A head the server LIES about (replaying a real signature over a different
    /// head) breaks the proof and fails closed.
    #[test]
    fn tampered_head_fails_closed() {
        let custodian = SigningKey::generate();
        // Sign the true head, then serve a DIFFERENT head with that signature.
        let cosig = custodian.sign_raw(&maxsecu_encoding::sink_head_signing_input(CHAIN_SEQ, &HEAD));
        let mut lied = HEAD;
        lied[0] ^= 0x01;
        let (server_config, cert_der) = test_pki();
        let addr = spawn_head_sink(server_config, head_json(CHAIN_SEQ, lied, cosig));
        let pins = SinkPins {
            addr,
            server_name: "localhost".into(),
            tls: client_config_for_pinned_root(&cert_der).unwrap(),
            custodian_pubs: vec![custodian.verifying_key().to_bytes()],
            transparency_log_pubs: vec![],
        };
        assert_eq!(fetch_anchored_head(&pins).unwrap_err().code, "sink_unverified");
    }

    /// A withheld / unreachable sink fails closed with a distinct sanitized code —
    /// never a fabricated head.
    #[test]
    fn unreachable_sink_fails_closed() {
        // A bound-then-dropped port: nothing listens there.
        let dead: SocketAddr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let (_server_config, cert_der) = test_pki();
        let pins = SinkPins {
            addr: dead,
            server_name: "localhost".into(),
            tls: client_config_for_pinned_root(&cert_der).unwrap(),
            custodian_pubs: vec![SigningKey::generate().verifying_key().to_bytes()],
            transparency_log_pubs: vec![],
        };
        assert_eq!(fetch_anchored_head(&pins).unwrap_err().code, "sink_unreachable");
    }
}
