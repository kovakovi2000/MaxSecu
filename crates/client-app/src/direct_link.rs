//! The client-side "Prefer Dropbox offload" download route (Part B,
//! spec `2026-07-02-download-route-setting`): when [`RouteMode::PreferDropbox`]
//! is selected, fetch an offloaded chunk's ciphertext DIRECTLY from the
//! server-brokered short-lived cloud URL (`POST .../direct-link`,
//! `server::http::direct_link`) instead of the server proxying the bytes
//! (`GET .../chunks/{index}`, `server::http::get_chunk`) — then hand those bytes
//! to the SAME verification/decrypt path the proxied bytes go through. On any
//! problem this module falls back to the caller doing the ordinary proxied GET.
//!
//! # Zero-knowledge / fail-closed boundary
//! * **Only ciphertext ever crosses this seam.** [`fetch_chunk_routed`] returns
//!   the same opaque bytes `get_bytes` would have; no key, plaintext, manifest
//!   secret, or session token is ever sent to the brokered URL — [`HyperDirectLinkHttp::get`]
//!   issues a bare `GET` with only a `Host` header (mirrors
//!   `server::dropbox_tier::HyperDropboxHttp::execute`, this crate's exact
//!   pattern for egress to a public cloud host).
//! * **The link source is UNTRUSTED.** A brokered URL — or its response body — is
//!   attacker-reachable in principle (a compromised/rogue cloud host, a MITM of
//!   *that* connection, or a substituted link). This module never adds a trust
//!   shortcut: the caller is expected to run the SAME AEAD/manifest verification
//!   over direct-fetched bytes it runs over proxied ones (`client-core`), and to
//!   retry via [`fetch_chunk_proxy`] on a verification failure. Where an
//!   immediate per-chunk AEAD probe is available (the `content` stream, via
//!   `ContentDecryptor::open_range`) callers pass it as `accept` and get that
//!   retry for free within [`fetch_chunk_routed`] itself.
//! * **Fail-closed everywhere.** [`direct_allowed`] returns `false` for anything
//!   other than [`RouteMode::PreferDropbox`] — in particular
//!   [`RouteMode::TorOnly`] NEVER attempts a direct fetch (a public-cloud GET
//!   would leak the real IP / defeat Tor: no broker call is even made). A
//!   disabled server feature (403 `direct_disabled`), an absent/untiered chunk
//!   (404 ⇒ no link in the broker response), a malformed broker response, a
//!   transport error reaching the cloud host, a non-200 direct response, or the
//!   caller's `accept` check all fall back to the ordinary server-proxied GET —
//!   a direct-link problem never denies the user the content.
//!
//! # Transport seam
//! [`DirectLinkHttp`] is the ONLY I/O boundary the direct fetch uses to reach the
//! brokered host — mirrors `server::dropbox_tier::DropboxHttp` exactly, so unit
//! tests assert exactly what would have egressed (and that no secret is in it)
//! with no network, via `#[cfg(test)]` `MockDirectLinkHttp`. The real transport,
//! [`HyperDirectLinkHttp`], is hyper over tokio-rustls (`aws_lc_rs`), verifying
//! the brokered host's PUBLIC WebPKI identity via `webpki-roots` — NOT the
//! pinned self-signed app-server cert, since the brokered URL is a public cloud
//! host (e.g. Dropbox's `dl.dropboxusercontent.com`).

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use async_trait::async_trait;

use crate::config::RouteMode;
use crate::error::UiError;
use crate::http_client::{get_bytes, post_json};

/// Whether the effective route ever attempts a direct cloud fetch.
/// [`RouteMode::PreferDropbox`] only — [`RouteMode::PreferServer`] has no reason
/// to try (today's proxied behavior), and [`RouteMode::TorOnly`] MUST NEVER go
/// direct: a direct GET to a public cloud host would bypass Tor and leak the
/// client's real IP. Checked BEFORE any broker call is made, so under
/// `TorOnly`/`PreferServer` no cloud host is even named to the server.
pub fn direct_allowed(route_mode: RouteMode) -> bool {
    matches!(route_mode, RouteMode::PreferDropbox)
}

/// One outbound GET to a brokered public URL. `Err` is a transport-level failure
/// (connect/TLS/HTTP); any HTTP status the host actually returned is a
/// **successful** `get` carrying that status — the caller interprets it. Not a
/// supported external-implementation surface (mirrors
/// `server::dropbox_tier::DropboxHttp`) — the only two implementors are
/// `MockDirectLinkHttp` (test) and [`HyperDirectLinkHttp`] (real).
#[async_trait]
#[doc(hidden)]
pub trait DirectLinkHttp: Send + Sync {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), UiError>;
}

/// Split one of the server's brokered `https://host/path...` URLs into
/// `(host, path)`. Not a general URL parser — only ever fed a URL this process
/// received from the server's `/direct-link` response, itself sourced from the
/// cold tier's own `https://` link minting (`server::blob::DirectLink`).
fn split_https_url(url: &str) -> Result<(&str, &str), UiError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| UiError::new("fetch_failed", "The direct link was malformed."))?;
    if rest.is_empty() {
        return Err(UiError::new("fetch_failed", "The direct link was malformed."));
    }
    match rest.find('/') {
        Some(idx) => Ok((&rest[..idx], &rest[idx..])),
        None => Ok((rest, "/")),
    }
}

/// The real transport: hyper over tokio-rustls (`aws_lc_rs` provider), verifying
/// the brokered host's PUBLIC WebPKI identity via `webpki-roots` (mirrors
/// `server::dropbox_tier::HyperDropboxHttp`'s connect → TLS 1.3 → http1
/// handshake → send_request → drain dance, but a GET against whatever public
/// host the server brokered, not a fixed Dropbox host). Contains no other I/O.
pub struct HyperDirectLinkHttp {
    tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
}

impl HyperDirectLinkHttp {
    pub fn new() -> Result<Self, UiError> {
        let provider =
            std::sync::Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| UiError::new("internal", "Could not initialize the direct-link transport."))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(HyperDirectLinkHttp {
            tls: std::sync::Arc::new(tls),
        })
    }
}

#[async_trait]
impl DirectLinkHttp for HyperDirectLinkHttp {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), UiError> {
        use http_body_util::BodyExt;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let (host, path) = split_https_url(url)?;

        let tcp = tokio::net::TcpStream::connect((host, 443u16))
            .await
            .map_err(|_| UiError::new("offline", "Could not reach the direct-link host."))?;
        let connector = TlsConnector::from(self.tls.clone());
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| UiError::new("fetch_failed", "Invalid direct-link host."))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|_| UiError::new("offline", "TLS to the direct-link host failed."))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| UiError::new("offline", "The direct-link handshake failed."))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // No Authorization/token header, no body — a bare capability-scoped GET.
        let req = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", host)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|_| UiError::new("internal", "Could not build the direct-link request."))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|_| UiError::new("offline", "The direct-link host did not respond."))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| UiError::new("offline", "The direct-link response was interrupted."))?
            .to_bytes()
            .to_vec();
        Ok((status, body))
    }
}

/// Process-wide lazily-built [`HyperDirectLinkHttp`]: `rustls::ClientConfig`
/// construction (root-store population) is pure CPU with no I/O, but is wasted
/// work to repeat on every range request during video playback. Built once, on
/// first use, and reused for the life of the process. Returns `None` (never
/// panics) if the one-time construction fails — callers degrade to proxy-only,
/// same as `direct_http: None` anywhere else in this module.
pub fn shared_direct_http() -> Option<&'static dyn DirectLinkHttp> {
    static SHARED: std::sync::OnceLock<Option<HyperDirectLinkHttp>> = std::sync::OnceLock::new();
    SHARED
        .get_or_init(|| HyperDirectLinkHttp::new().ok())
        .as_ref()
        .map(|h| h as &dyn DirectLinkHttp)
}

/// `POST .../direct-link` over the caller's already-authenticated pinned-server
/// connection, and return the brokered URL. Returns `None` for ANY non-success
/// outcome — the operator toggle off (403 `direct_disabled`), an absent/never-
/// offloaded chunk (404), or a malformed JSON body — without distinguishing them
/// further (no oracle beyond what the endpoint itself already returns; the
/// caller's uniform reaction is "fall back to the proxy" either way).
pub async fn broker_direct_link(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    version: u64,
    stream_name: &str,
    index: u64,
) -> Option<String> {
    let uri = format!(
        "/v1/files/{file_id_hex}/versions/{version}/streams/{stream_name}/chunks/{index}/direct-link"
    );
    let (status, json) = post_json(sender, &uri, &serde_json::Value::Null, Some(token), host)
        .await
        .ok()?;
    if status != hyper::StatusCode::OK {
        return None;
    }
    json.get("url")?.as_str().map(str::to_owned)
}

/// The ordinary server-proxied GET of one ciphertext chunk (`server::http::get_chunk`).
/// Used both as the direct route's fallback and as a forced-proxy retry after a
/// direct-sourced verification failure.
pub async fn fetch_chunk_proxy(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    version: u64,
    stream_name: &str,
    index: u64,
) -> Result<Vec<u8>, UiError> {
    let uri = format!(
        "/v1/files/{file_id_hex}/versions/{version}/streams/{stream_name}/chunks/{index}"
    );
    let (status, bytes) = get_bytes(sender, &uri, Some(token), host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new(
            "fetch_failed",
            "A content chunk could not be fetched.",
        ));
    }
    Ok(bytes)
}

/// Fetch one chunk's ciphertext, preferring the direct-link cloud route under
/// [`RouteMode::PreferDropbox`] and falling back to the server-proxied GET on
/// ANY problem: link brokering failure/off/absent, a direct transport error, a
/// non-200 direct response, or `accept` rejecting the bytes. `accept` is the
/// caller's own per-chunk trust check — typically an immediate AEAD probe (e.g.
/// `ContentDecryptor::open_range` on the single fetched chunk) where one is
/// available; pass `|_| true` where it is not (the caller then relies on
/// whatever verification runs downstream, unconditionally, over these bytes —
/// see the module doc).
///
/// Returns `(bytes, used_direct)` so a caller whose OWN downstream verification
/// covers a wider span (e.g. a multi-chunk fragment/stream) can track which
/// indices were direct-sourced and retry precisely those via
/// [`fetch_chunk_proxy`] if that wider verification later fails.
pub async fn fetch_chunk_routed(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    version: u64,
    stream_name: &str,
    index: u64,
    route_mode: RouteMode,
    direct_http: Option<&dyn DirectLinkHttp>,
    accept: impl Fn(&[u8]) -> bool,
) -> Result<(Vec<u8>, bool), UiError> {
    if direct_allowed(route_mode) {
        if let Some(http) = direct_http {
            if let Some(url) =
                broker_direct_link(sender, host, token, file_id_hex, version, stream_name, index)
                    .await
            {
                if let Ok((status, body)) = http.get(&url).await {
                    if status == 200 && accept(&body) {
                        return Ok((body, true));
                    }
                }
            }
        }
    }
    let bytes =
        fetch_chunk_proxy(sender, host, token, file_id_hex, version, stream_name, index).await?;
    Ok((bytes, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[test]
    fn direct_allowed_only_under_prefer_dropbox() {
        assert!(!direct_allowed(RouteMode::TorOnly));
        assert!(!direct_allowed(RouteMode::PreferServer));
        assert!(direct_allowed(RouteMode::PreferDropbox));
    }

    #[test]
    fn split_https_url_splits_host_and_path() {
        assert_eq!(
            split_https_url("https://dl.dropboxusercontent.com/abc/123").unwrap(),
            ("dl.dropboxusercontent.com", "/abc/123")
        );
        // No path segment at all — defaults to "/".
        assert_eq!(
            split_https_url("https://example.com").unwrap(),
            ("example.com", "/")
        );
        assert!(split_https_url("http://insecure.example.com/x").is_err());
        assert!(split_https_url("https://").is_err());
    }

    /// Records every URL it was asked to GET (so a test can assert no secret ever
    /// appears in it) and returns canned `(status, body)` responses in order.
    struct MockDirectLinkHttp {
        urls: Mutex<Vec<String>>,
        responses: Mutex<VecDeque<Result<(u16, Vec<u8>), UiError>>>,
    }

    impl MockDirectLinkHttp {
        fn new(responses: Vec<Result<(u16, Vec<u8>), UiError>>) -> Self {
            MockDirectLinkHttp {
                urls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
        fn urls(&self) -> Vec<String> {
            self.urls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DirectLinkHttp for MockDirectLinkHttp {
        async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), UiError> {
            self.urls.lock().unwrap().push(url.to_owned());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(UiError::new("test", "no canned response queued")))
        }
    }

    // ---- fetch_chunk_routed over a real local loopback stub server ----
    //
    // These exercise the FULL seam — `broker_direct_link`'s POST + `fetch_chunk_proxy`'s
    // GET — over a real hyper HTTP/1.1 connection to an in-process stub, so the
    // wire shapes (headers, no-secret-in-URL) are genuinely round-tripped, not just
    // asserted against a hand-built request. `DirectLinkHttp` is mocked (no real
    // TLS/network to a cloud host) since that is the seam under test.

    use http_body_util::BodyExt;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    /// A tiny in-process HTTP/1.1 stub standing in for the pinned server
    /// connection: POST `/direct-link` returns a canned JSON body (or a 403 to
    /// model the feature toggle off / a 404-shaped empty body to model an
    /// untiered chunk), and any other path is the "proxy" GET, returning a fixed
    /// ciphertext payload. Records how many times each was hit.
    struct StubServer {
        direct_link_status: hyper::StatusCode,
        direct_link_body: serde_json::Value,
        proxy_body: Vec<u8>,
        direct_link_hits: std::sync::Arc<AtomicUsize>,
        proxy_hits: std::sync::Arc<AtomicUsize>,
    }

    async fn spawn_stub(stub: StubServer) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = std::sync::Arc::new(stub);
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let stub = stub.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let stub = stub.clone();
                        async move {
                            let is_direct_link = req.uri().path().ends_with("/direct-link");
                            // Drain the body (never inspected — proves nothing about the
                            // request depends on it beyond routing by path).
                            let _ = req.into_body().collect().await;
                            let resp = if is_direct_link {
                                stub.direct_link_hits.fetch_add(1, Ordering::SeqCst);
                                Response::builder()
                                    .status(stub.direct_link_status)
                                    .body(Full::<Bytes>::from(stub.direct_link_body.to_string()))
                                    .unwrap()
                            } else {
                                stub.proxy_hits.fetch_add(1, Ordering::SeqCst);
                                Response::builder()
                                    .status(200)
                                    .body(Full::<Bytes>::from(stub.proxy_body.clone()))
                                    .unwrap()
                            };
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = server_http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), svc)
                        .await;
                });
            }
        });
        format!("127.0.0.1:{}", addr.port())
    }

    async fn connect(addr: &str) -> SendRequest<Full<Bytes>> {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    #[tokio::test]
    async fn direct_fetch_succeeds_and_verifies_and_proxy_is_not_invoked() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/blob/1", "expires_in_s": 900 }),
            proxy_body: b"PROXY-BYTES-MUST-NOT-BE-USED".to_vec(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;

        let canned = b"CANNED-CIPHERTEXT".to_vec();
        let http = MockDirectLinkHttp::new(vec![Ok((200, canned.clone()))]);

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            Some(&http),
            |b| b == canned.as_slice(), // stand-in AEAD probe: "verifies" iff it's the canned bytes
        )
        .await
        .unwrap();

        assert!(used_direct, "route was PreferDropbox with a valid link");
        assert_eq!(bytes, canned, "the verified direct bytes are returned");
        assert_eq!(hits_direct.load(Ordering::SeqCst), 1, "the broker was called once");
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 0, "the proxy was NEVER invoked");
        // No secret (token/key/plaintext) ever reached the mock cloud transport —
        // only the opaque brokered URL.
        assert_eq!(http.urls(), vec!["https://cloud.example.com/blob/1".to_string()]);
        for u in http.urls() {
            assert!(!u.contains("tok"), "the session token must never reach the cloud URL");
        }
    }

    #[tokio::test]
    async fn tampered_direct_body_fails_verify_and_falls_back_to_proxy() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"GENUINE-PROXIED-CIPHERTEXT".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/blob/1", "expires_in_s": 900 }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;

        let genuine = b"GENUINE-CIPHERTEXT".to_vec();
        let tampered = b"TAMPERED-GARBAGE".to_vec();
        let http = MockDirectLinkHttp::new(vec![Ok((200, tampered))]);

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            Some(&http),
            |b| b == genuine.as_slice(), // rejects the tampered body
        )
        .await
        .unwrap();

        assert!(!used_direct, "verification of the direct bytes failed");
        assert_eq!(bytes, proxy_bytes, "fell back to the genuine proxied bytes");
        assert_eq!(hits_direct.load(Ordering::SeqCst), 1);
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1, "the proxy WAS invoked as fallback");
    }

    #[tokio::test]
    async fn absent_direct_link_falls_back_to_proxy() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        // The chunk was never offloaded — the server 404s the broker call.
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::NOT_FOUND,
            direct_link_body: serde_json::Value::Null,
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;
        let http = MockDirectLinkHttp::new(vec![]); // must not even be called

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            Some(&http),
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_direct.load(Ordering::SeqCst), 1);
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
        assert!(http.urls().is_empty(), "no cloud GET without a brokered link");
    }

    #[tokio::test]
    async fn disabled_feature_403_falls_back_to_proxy() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::FORBIDDEN,
            direct_link_body: serde_json::json!({ "code": "direct_disabled" }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;
        let http = MockDirectLinkHttp::new(vec![]);

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            Some(&http),
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_direct.load(Ordering::SeqCst), 1);
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tor_only_never_calls_the_broker_and_goes_straight_to_proxy() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/x", "expires_in_s": 900 }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;
        let http = MockDirectLinkHttp::new(vec![]); // must not be called either

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::TorOnly,
            Some(&http),
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_direct.load(Ordering::SeqCst), 0, "TorOnly must never even broker a link");
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
        assert!(http.urls().is_empty());
    }

    #[tokio::test]
    async fn prefer_server_never_calls_the_broker_either() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/x", "expires_in_s": 900 }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;
        let http = MockDirectLinkHttp::new(vec![]);

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferServer,
            Some(&http),
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_direct.load(Ordering::SeqCst), 0);
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_direct_http_injected_skips_straight_to_proxy() {
        // `direct_http: None` — e.g. HyperDirectLinkHttp::new() failed to init.
        // Must degrade to proxy-only, never panic, never block playback.
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/x", "expires_in_s": 900 }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            None,
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_direct.load(Ordering::SeqCst), 0, "no broker call without a transport");
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn transport_error_reaching_the_cloud_host_falls_back_to_proxy() {
        let hits_direct = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_proxy = std::sync::Arc::new(AtomicUsize::new(0));
        let proxy_bytes = b"PROXIED".to_vec();
        let addr = spawn_stub(StubServer {
            direct_link_status: hyper::StatusCode::OK,
            direct_link_body: serde_json::json!({ "url": "https://cloud.example.com/x", "expires_in_s": 900 }),
            proxy_body: proxy_bytes.clone(),
            direct_link_hits: hits_direct.clone(),
            proxy_hits: hits_proxy.clone(),
        })
        .await;
        let mut sender = connect(&addr).await;
        let http = MockDirectLinkHttp::new(vec![Err(UiError::new("offline", "no route"))]);

        let (bytes, used_direct) = fetch_chunk_routed(
            &mut sender,
            "localhost",
            "tok",
            "ff".repeat(16).as_str(),
            1,
            "content",
            0,
            RouteMode::PreferDropbox,
            Some(&http),
            |_| true,
        )
        .await
        .unwrap();

        assert!(!used_direct);
        assert_eq!(bytes, proxy_bytes);
        assert_eq!(hits_proxy.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn hyper_direct_link_http_constructs_without_network() {
        // Compile/runtime smoke: the TLS config (root store + provider) builds
        // with no I/O. Behavior is exercised by the mock-based tests above; a
        // real end-to-end fetch against a public host is not run in CI.
        assert!(HyperDirectLinkHttp::new().is_ok());
    }
}
