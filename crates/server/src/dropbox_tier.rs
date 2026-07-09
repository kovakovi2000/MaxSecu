//! The real Dropbox cold-tier adapter (DESIGN §4.1/D31, api.md §9) — a
//! production [`ColdTier`] that egresses to Dropbox's API v2 over HTTPS.
//!
//! # Zero-knowledge boundary
//! Every byte handed to [`DropboxTier::put_chunk`] is already client-encrypted
//! AEAD ciphertext (`server::blob` module doc) — this adapter passes it through
//! **verbatim**, and stores/returns nothing else. No key, manifest field, title,
//! or plaintext ever reaches this module, let alone Dropbox. The OAuth access
//! token is read from **runtime config/env only** (never hardcoded, never
//! committed) and is redacted from `Debug` + best-effort zeroized on drop
//! ([`DropboxToken`]). [`DropboxTier::broker_direct_link`] mints only a
//! Dropbox-scoped, short-lived read link (`get_temporary_link`) that carries no
//! master credential, and returns `Ok(None)` for an absent chunk (no oracle).
//! Every transport failure, non-2xx status, or malformed response maps to a
//! [`BlobError`] — never a panic, never a silent success (fail-closed).
//!
//! # Transport seam
//! [`DropboxHttp`] is the ONLY I/O boundary [`DropboxTier<H>`] uses to reach
//! Dropbox — it builds [`DropboxRequest`]s and interprets [`DropboxResponse`]s,
//! but never opens a socket itself. This makes the adapter's request-shaping /
//! response-parsing logic fully unit-testable without network: the `#[cfg(test)]`
//! `MockDropboxHttp` records exactly what would have egressed and returns canned
//! responses. The real transport, [`HyperDropboxHttp`], implements
//! [`DropboxHttp`] with hyper over tokio-rustls (`aws_lc_rs` provider, mirroring
//! `crate::audit::HttpSinkPublisher::post_json`) verifying Dropbox's PUBLIC
//! WebPKI identity via `webpki-roots` (pure-Rust Mozilla root bundle — Dropbox is
//! a public host, not a pinned self-signed cert like the app server's own
//! transports). These types are technically `pub` (a public trait bound on the
//! public [`DropboxTier<H>`] cannot name a private trait) but `#[doc(hidden)]`
//! and not a supported external-implementation surface — the only two
//! implementors are `MockDropboxHttp` (test) and [`HyperDropboxHttp`] (real).
//!
//! # Path mapping
//! One chunk is one Dropbox file at `{root}/{blob_ref}/{index}`; a stream's
//! chunks live under the folder `{root}/{blob_ref}/`. `blob_ref` is
//! server-generated (`hex/version/stream_type`, `crate::files`) but is still
//! guarded against path traversal here, defense in depth (mirrors
//! `FsBlobStore::stream_dir`).
//!
//! # Running the live test
//! `dropbox_live_round_trip` is `#[ignore]`d and gated on the `DROPBOX_TEST_TOKEN`
//! env var — it never runs in CI. To run it manually against a real Dropbox
//! account (an app-scoped OAuth2 access token with `files.content.write`,
//! `files.content.read`, and `sharing.write` scopes):
//! ```text
//! DROPBOX_TEST_TOKEN=<your-token> \
//!   cargo test -p maxsecu-server --lib -- --ignored dropbox_live_round_trip
//! ```
//! It uploads a small random ciphertext-shaped blob under a fresh random test
//! root, reads it back, brokers a temporary link, and deletes it.

use crate::blob::{BlobError, DirectLink};
use crate::tier::ColdTier;
use async_trait::async_trait;
use std::fmt;
use zeroize::Zeroize;

/// Default Dropbox API v2 hosts: `api.dropboxapi.com` for JSON RPC endpoints,
/// `content.dropboxapi.com` for the upload/download content endpoints.
const DEFAULT_API_HOST: &str = "https://api.dropboxapi.com";
const DEFAULT_CONTENT_HOST: &str = "https://content.dropboxapi.com";

/// A Dropbox OAuth access token that redacts itself from `Debug` and is
/// best-effort scrubbed on drop. Never logged, never embedded in a URL/body —
/// it is carried ONLY in the `Authorization` header of each request.
#[derive(Clone)]
struct DropboxToken(String);

impl DropboxToken {
    fn new(token: impl Into<String>) -> Self {
        DropboxToken(token.into())
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DropboxToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DropboxToken").field(&"<redacted>").finish()
    }
}

impl Drop for DropboxToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// HTTP method of a [`DropboxRequest`]. Only `POST` is ever issued — every
/// Dropbox API v2 endpoint this adapter calls (upload/download/RPC) is POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum DropboxMethod {
    Post,
}

/// One outbound request to a Dropbox API host, decoupled from any concrete
/// transport so unit tests can assert exactly what would have egressed without
/// opening a socket. `headers` INCLUDES `Authorization` explicitly, so a test
/// can assert the bearer token appears ONLY there (never in `url`/`body`).
///
/// Not a supported external-implementation surface — see the module doc.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct DropboxRequest {
    method: DropboxMethod,
    /// Full `https://` URL, e.g. `https://api.dropboxapi.com/2/files/get_metadata`.
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// A Dropbox HTTP response: status code + raw body bytes. Not a supported
/// external-implementation surface — see the module doc.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct DropboxResponse {
    status: u16,
    body: Vec<u8>,
}

/// The transport seam: [`DropboxTier<H>`] builds [`DropboxRequest`]s and
/// interprets [`DropboxResponse`]s; only an implementor of this trait ever
/// touches a socket. `Err` means a transport-level failure (connect/TLS/HTTP);
/// any HTTP status Dropbox actually returned (2xx, 409, 500, ...) is a
/// **successful** `execute` carrying that status in [`DropboxResponse`] — the
/// caller in `dropbox_tier` interprets status codes. Not a supported
/// external-implementation surface (`#[doc(hidden)]`) — see the module doc.
#[async_trait]
#[doc(hidden)]
pub trait DropboxHttp: Send + Sync {
    async fn execute(&self, req: DropboxRequest) -> Result<DropboxResponse, BlobError>;
}

/// Reject any `blob_ref` component that isn't a plain path segment (no `..`,
/// no absolute prefix, no root) before it is spliced into a Dropbox path.
/// `blob_ref` is server-generated (`hex/version/stream_type`), but this is
/// defense in depth, mirroring `FsBlobStore::stream_dir`.
fn guard_blob_ref(blob_ref: &str) -> Result<(), BlobError> {
    use std::path::{Component, Path};
    if blob_ref.is_empty() {
        return Err(BlobError::new("dropbox_path", "empty blob_ref"));
    }
    for c in Path::new(blob_ref).components() {
        match c {
            Component::Normal(_) => {}
            _ => return Err(BlobError::new("dropbox_path", "unsafe blob_ref component")),
        }
    }
    Ok(())
}

/// The Dropbox path of one chunk: `{root}/{blob_ref}/{index}`.
fn chunk_path(root: &str, blob_ref: &str, index: u64) -> Result<String, BlobError> {
    guard_blob_ref(blob_ref)?;
    Ok(format!("{root}/{blob_ref}/{index}"))
}

/// The Dropbox folder path of a whole stream: `{root}/{blob_ref}`.
fn stream_path(root: &str, blob_ref: &str) -> Result<String, BlobError> {
    guard_blob_ref(blob_ref)?;
    Ok(format!("{root}/{blob_ref}"))
}

/// Dropbox's RPC/content error shape for a missing path is a `409` with a JSON
/// body whose `error_summary` contains `not_found` (e.g.
/// `"path/not_found/..."`). Any other status, or a `409` that does NOT parse as
/// this shape, is NOT treated as absence — it surfaces as a real error
/// (fail-closed: malformed response never silently reads as "not found").
fn is_path_not_found(status: u16, body: &[u8]) -> bool {
    if status != 409 {
        return false;
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(v) => v
            .get("error_summary")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.contains("not_found")),
        Err(_) => false,
    }
}

/// The production [`ColdTier`]: Dropbox API v2 behind the [`DropboxHttp`]
/// transport seam. `H` is [`HyperDropboxHttp`] in production and
/// `MockDropboxHttp` in unit tests. See the module doc for the zero-knowledge
/// egress contract and path mapping.
pub struct DropboxTier<H: DropboxHttp> {
    http: H,
    token: DropboxToken,
    /// Dropbox app folder root, e.g. `/maxsecu` (no trailing slash).
    root: String,
    api_host: String,
    content_host: String,
}

impl<H: DropboxHttp> fmt::Debug for DropboxTier<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DropboxTier")
            .field("root", &self.root)
            .field("api_host", &self.api_host)
            .field("content_host", &self.content_host)
            .field("token", &self.token) // DropboxToken's own Debug redacts it
            .finish()
    }
}

impl<H: DropboxHttp> DropboxTier<H> {
    /// Build a tier over an explicit transport `http` (mocks in tests, or a
    /// [`HyperDropboxHttp`] pointed at a non-default host for a loopback stub).
    /// `token` is the caller-sourced runtime credential (env/config — never
    /// hardcoded); `root` is the Dropbox app-folder root (e.g. `/maxsecu`).
    fn with_http_and_hosts(
        http: H,
        token: impl Into<String>,
        root: impl Into<String>,
        api_host: impl Into<String>,
        content_host: impl Into<String>,
    ) -> Self {
        let root = root.into();
        DropboxTier {
            http,
            token: DropboxToken::new(token),
            root: root.trim_end_matches('/').to_owned(),
            api_host: api_host.into(),
            content_host: content_host.into(),
        }
    }

    fn auth_header(&self) -> (String, String) {
        (
            "authorization".to_owned(),
            format!("Bearer {}", self.token.as_str()),
        )
    }

    fn json_headers(&self) -> Vec<(String, String)> {
        vec![
            self.auth_header(),
            ("content-type".to_owned(), "application/json".to_owned()),
        ]
    }

    async fn post_json(
        &self,
        host: &str,
        path: &str,
        body: serde_json::Value,
    ) -> Result<DropboxResponse, BlobError> {
        let req = DropboxRequest {
            method: DropboxMethod::Post,
            url: format!("{host}{path}"),
            headers: self.json_headers(),
            body: body.to_string().into_bytes(),
        };
        self.http.execute(req).await
    }

    /// `POST .../files/delete_v2 {"path"}` — idempotent, `path/not_found` is
    /// success (matches [`ColdTier::delete_chunk`]/`delete_stream` semantics).
    async fn delete_path(&self, path: String, op: &'static str) -> Result<(), BlobError> {
        let resp = self
            .post_json(
                &self.api_host,
                "/2/files/delete_v2",
                serde_json::json!({ "path": path }),
            )
            .await?;
        if resp.status == 200 || is_path_not_found(resp.status, &resp.body) {
            Ok(())
        } else {
            Err(BlobError::new(op, format!("dropbox http {}", resp.status)))
        }
    }
}

#[async_trait]
impl<H: DropboxHttp> ColdTier for DropboxTier<H> {
    /// `POST .../files/upload` — the ciphertext `bytes` go verbatim as the
    /// request body; NOTHING else about the plaintext/manifest is derived here.
    async fn put_chunk(&self, blob_ref: &str, index: u64, bytes: Vec<u8>) -> Result<(), BlobError> {
        let path = chunk_path(&self.root, blob_ref, index)?;
        let arg =
            serde_json::json!({ "path": path, "mode": "overwrite", "mute": true }).to_string();
        let req = DropboxRequest {
            method: DropboxMethod::Post,
            url: format!("{}/2/files/upload", self.content_host),
            headers: vec![
                self.auth_header(),
                ("dropbox-api-arg".to_owned(), arg),
                (
                    "content-type".to_owned(),
                    "application/octet-stream".to_owned(),
                ),
            ],
            body: bytes,
        };
        let resp = self.http.execute(req).await?;
        if resp.status / 100 == 2 {
            Ok(())
        } else {
            Err(BlobError::new(
                "dropbox_put_chunk",
                format!("dropbox http {}", resp.status),
            ))
        }
    }

    /// `POST .../files/download` — a present chunk returns its bytes verbatim;
    /// an absent chunk maps to `Ok(None)` (no oracle beyond presence, matching
    /// every other tier).
    async fn get_chunk(&self, blob_ref: &str, index: u64) -> Result<Option<Vec<u8>>, BlobError> {
        let path = chunk_path(&self.root, blob_ref, index)?;
        let arg = serde_json::json!({ "path": path }).to_string();
        let req = DropboxRequest {
            method: DropboxMethod::Post,
            url: format!("{}/2/files/download", self.content_host),
            headers: vec![self.auth_header(), ("dropbox-api-arg".to_owned(), arg)],
            body: Vec::new(),
        };
        let resp = self.http.execute(req).await?;
        if resp.status == 200 {
            Ok(Some(resp.body))
        } else if is_path_not_found(resp.status, &resp.body) {
            Ok(None)
        } else {
            Err(BlobError::new(
                "dropbox_get_chunk",
                format!("dropbox http {}", resp.status),
            ))
        }
    }

    /// `POST .../files/list_folder` (+ `/continue` for pagination) — counts
    /// entries under the stream's folder. A missing folder (never uploaded, or
    /// fully torn down) is `0`, not an error.
    async fn chunk_count(&self, blob_ref: &str) -> Result<u64, BlobError> {
        let path = stream_path(&self.root, blob_ref)?;
        let resp = self
            .post_json(
                &self.api_host,
                "/2/files/list_folder",
                serde_json::json!({ "path": path }),
            )
            .await?;
        if is_path_not_found(resp.status, &resp.body) {
            return Ok(0);
        }
        if resp.status != 200 {
            return Err(BlobError::new(
                "dropbox_chunk_count",
                format!("dropbox http {}", resp.status),
            ));
        }
        let mut v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| {
            BlobError::new("dropbox_chunk_count", format!("malformed response: {e}"))
        })?;
        let mut count = list_folder_entry_count(&v)?;
        let mut has_more = v.get("has_more").and_then(|b| b.as_bool()).unwrap_or(false);
        while has_more {
            let cursor = v
                .get("cursor")
                .and_then(|c| c.as_str())
                .ok_or_else(|| BlobError::new("dropbox_chunk_count", "has_more without cursor"))?
                .to_owned();
            let resp = self
                .post_json(
                    &self.api_host,
                    "/2/files/list_folder/continue",
                    serde_json::json!({ "cursor": cursor }),
                )
                .await?;
            if resp.status != 200 {
                return Err(BlobError::new(
                    "dropbox_chunk_count",
                    format!("dropbox http {}", resp.status),
                ));
            }
            v = serde_json::from_slice(&resp.body).map_err(|e| {
                BlobError::new("dropbox_chunk_count", format!("malformed response: {e}"))
            })?;
            count += list_folder_entry_count(&v)?;
            has_more = v.get("has_more").and_then(|b| b.as_bool()).unwrap_or(false);
        }
        Ok(count)
    }

    /// `POST .../files/delete_v2` on the stream folder — idempotent.
    async fn delete_stream(&self, blob_ref: &str) -> Result<(), BlobError> {
        let path = stream_path(&self.root, blob_ref)?;
        self.delete_path(path, "dropbox_delete_stream").await
    }

    /// `POST .../files/delete_v2` on one chunk file — idempotent.
    async fn delete_chunk(&self, blob_ref: &str, index: u64) -> Result<(), BlobError> {
        let path = chunk_path(&self.root, blob_ref, index)?;
        self.delete_path(path, "dropbox_delete_chunk").await
    }

    /// `POST .../files/get_metadata` — presence WITHOUT downloading bytes.
    async fn has_chunk(&self, blob_ref: &str, index: u64) -> Result<bool, BlobError> {
        let path = chunk_path(&self.root, blob_ref, index)?;
        let resp = self
            .post_json(
                &self.api_host,
                "/2/files/get_metadata",
                serde_json::json!({ "path": path }),
            )
            .await?;
        if resp.status == 200 {
            Ok(true)
        } else if is_path_not_found(resp.status, &resp.body) {
            Ok(false)
        } else {
            Err(BlobError::new(
                "dropbox_has_chunk",
                format!("dropbox http {}", resp.status),
            ))
        }
    }

    /// Confirms presence first (never brokers/oracles an absent chunk), then
    /// `POST .../files/get_temporary_link`. Dropbox temporary links are valid
    /// ~4 hours and Dropbox — not this adapter — controls the real expiry; the
    /// `ttl_secs` argument is carried through to [`DirectLink::expires_in_s`] as
    /// the caller's *advisory* request, not a guarantee. The returned URL is a
    /// freshly-minted, single-file Dropbox capability — the master OAuth token
    /// is NEVER embedded in it.
    async fn broker_direct_link(
        &self,
        blob_ref: &str,
        index: u64,
        ttl_secs: u64,
    ) -> Result<Option<DirectLink>, BlobError> {
        if !self.has_chunk(blob_ref, index).await? {
            return Ok(None);
        }
        let path = chunk_path(&self.root, blob_ref, index)?;
        let resp = self
            .post_json(
                &self.api_host,
                "/2/files/get_temporary_link",
                serde_json::json!({ "path": path }),
            )
            .await?;
        if is_path_not_found(resp.status, &resp.body) {
            return Ok(None);
        }
        if resp.status != 200 {
            return Err(BlobError::new(
                "dropbox_broker_direct_link",
                format!("dropbox http {}", resp.status),
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(|e| {
            BlobError::new(
                "dropbox_broker_direct_link",
                format!("malformed response: {e}"),
            )
        })?;
        let link = v
            .get("link")
            .and_then(|l| l.as_str())
            .ok_or_else(|| BlobError::new("dropbox_broker_direct_link", "missing link field"))?;
        Ok(Some(DirectLink {
            url: link.to_owned(),
            expires_in_s: ttl_secs,
        }))
    }
}

/// `entries` must be a JSON array on a well-formed `list_folder`/`continue`
/// response; anything else is a malformed response (fail-closed error, never a
/// silent `0`).
fn list_folder_entry_count(v: &serde_json::Value) -> Result<u64, BlobError> {
    v.get("entries")
        .and_then(|e| e.as_array())
        .map(|a| a.len() as u64)
        .ok_or_else(|| BlobError::new("dropbox_chunk_count", "missing/invalid entries"))
}

/// Split one of OUR generated `https://host/path...` URLs into `(host, path)`.
/// Not a general URL parser — the adapter only ever builds URLs of this exact
/// shape itself, so this is a closed, controlled input.
fn split_https_url(url: &str) -> Result<(&str, &str), BlobError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| BlobError::new("dropbox_url", "expected an https URL"))?;
    let idx = rest
        .find('/')
        .ok_or_else(|| BlobError::new("dropbox_url", "URL missing a path"))?;
    Ok((&rest[..idx], &rest[idx..]))
}

/// The real transport: hyper over tokio-rustls (`aws_lc_rs` provider), verifying
/// Dropbox's PUBLIC WebPKI identity via `webpki-roots` (mirrors
/// `crate::audit::HttpSinkPublisher::post_json`'s connect → TLS 1.3 → http1
/// handshake → send_request → drain dance, but against the public Dropbox hosts
/// rather than a pinned self-signed cert). Contains no other I/O.
pub struct HyperDropboxHttp {
    tls: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,
}

impl HyperDropboxHttp {
    pub fn new() -> Result<Self, BlobError> {
        let provider =
            std::sync::Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| BlobError::new("dropbox_tls_init", e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(HyperDropboxHttp {
            tls: std::sync::Arc::new(tls),
        })
    }
}

#[async_trait]
impl DropboxHttp for HyperDropboxHttp {
    async fn execute(&self, req: DropboxRequest) -> Result<DropboxResponse, BlobError> {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;
        use tokio_rustls::rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let (host, path) = split_https_url(&req.url)?;

        let tcp = tokio::net::TcpStream::connect((host, 443u16))
            .await
            .map_err(|e| BlobError::new("dropbox_connect", e.to_string()))?;
        let connector = TlsConnector::from(self.tls.clone());
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| BlobError::new("dropbox_tls", "invalid server name"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| BlobError::new("dropbox_tls", e.to_string()))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| BlobError::new("dropbox_handshake", e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let method = match req.method {
            DropboxMethod::Post => "POST",
        };
        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);
        for (k, v) in &req.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let http_req = builder
            .body(Full::<Bytes>::from(req.body))
            .map_err(|e| BlobError::new("dropbox_request", e.to_string()))?;

        let resp = sender
            .send_request(http_req)
            .await
            .map_err(|e| BlobError::new("dropbox_send", e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| BlobError::new("dropbox_body", e.to_string()))?
            .to_bytes()
            .to_vec();
        Ok(DropboxResponse { status, body })
    }
}

impl DropboxTier<HyperDropboxHttp> {
    /// Build the REAL production adapter. `token` is the caller-sourced runtime
    /// OAuth access token (env/config — NEVER hardcoded); `root` is the Dropbox
    /// app-folder root (e.g. `/maxsecu`). Talks to the real Dropbox hosts.
    pub fn new(token: impl Into<String>, root: impl Into<String>) -> Result<Self, BlobError> {
        Ok(DropboxTier::with_http_and_hosts(
            HyperDropboxHttp::new()?,
            token,
            root,
            DEFAULT_API_HOST,
            DEFAULT_CONTENT_HOST,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Records every request it received (in order) and returns canned
    /// responses from a queue, one per call — so a unit test asserts EXACTLY
    /// what would have egressed, with no network.
    struct MockDropboxHttp {
        requests: Mutex<Vec<DropboxRequest>>,
        responses: Mutex<VecDeque<DropboxResponse>>,
    }

    impl MockDropboxHttp {
        fn new(responses: Vec<DropboxResponse>) -> Self {
            MockDropboxHttp {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
        fn requests(&self) -> Vec<DropboxRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DropboxHttp for MockDropboxHttp {
        async fn execute(&self, req: DropboxRequest) -> Result<DropboxResponse, BlobError> {
            self.requests.lock().unwrap().push(req);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| BlobError::new("mock_dropbox", "no canned response queued"))
        }
    }

    fn resp(status: u16, body: impl Into<Vec<u8>>) -> DropboxResponse {
        DropboxResponse {
            status,
            body: body.into(),
        }
    }

    fn json_resp(status: u16, v: serde_json::Value) -> DropboxResponse {
        resp(status, v.to_string().into_bytes())
    }

    fn not_found_resp() -> DropboxResponse {
        json_resp(
            409,
            serde_json::json!({
                "error_summary": "path/not_found/...",
                "error": { ".tag": "path", "path": { ".tag": "not_found" } }
            }),
        )
    }

    const TOKEN: &str = "test-token-NOT-A-REAL-SECRET";

    fn tier(responses: Vec<DropboxResponse>) -> (DropboxTier<MockDropboxHttp>, ()) {
        let mock = MockDropboxHttp::new(responses);
        let t = DropboxTier::with_http_and_hosts(
            mock,
            TOKEN,
            "/maxsecu",
            "https://api.dropboxapi.com",
            "https://content.dropboxapi.com",
        );
        (t, ())
    }

    const REF: &str = "aabbccddeeff00112233445566778899/1/1";

    #[tokio::test]
    async fn put_chunk_sends_ciphertext_verbatim_with_correct_path_and_bearer() {
        let (t, _) = tier(vec![resp(200, Vec::new())]);
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        t.put_chunk(REF, 3, ciphertext.clone()).await.unwrap();

        let reqs = t.http.requests();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.url, "https://content.dropboxapi.com/2/files/upload");
        // The recorded body is the ciphertext VERBATIM — nothing added, nothing
        // stripped.
        assert_eq!(r.body, ciphertext);
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == &format!("Bearer {TOKEN}")));
        let arg = r
            .headers
            .iter()
            .find(|(k, _)| k == "dropbox-api-arg")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(arg.contains("/maxsecu/aabbccddeeff00112233445566778899/1/1/3"));
        assert!(arg.contains("\"mode\":\"overwrite\""));
        // No plaintext/manifest/title field of any kind leaked into the request.
        assert!(!arg.contains("title"));
    }

    #[tokio::test]
    async fn get_chunk_round_trips_present_and_absent() {
        let (t, _) = tier(vec![resp(200, vec![1, 2, 3]), not_found_resp()]);
        assert_eq!(t.get_chunk(REF, 0).await.unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(t.get_chunk(REF, 1).await.unwrap(), None);
    }

    #[tokio::test]
    async fn has_chunk_true_false_without_a_download_call() {
        let (t, _) = tier(vec![
            json_resp(200, serde_json::json!({ "name": "0" })),
            not_found_resp(),
        ]);
        assert!(t.has_chunk(REF, 0).await.unwrap());
        assert!(!t.has_chunk(REF, 1).await.unwrap());
        // Only get_metadata calls happened — never files/download.
        for r in t.http.requests() {
            assert!(!r.url.contains("/files/download"));
            assert!(r.url.contains("/files/get_metadata"));
        }
    }

    #[tokio::test]
    async fn chunk_count_parses_list_folder_with_pagination() {
        let (t, _) = tier(vec![
            json_resp(
                200,
                serde_json::json!({
                    "entries": [{"name": "0"}, {"name": "1"}],
                    "has_more": true,
                    "cursor": "cursor-abc"
                }),
            ),
            json_resp(
                200,
                serde_json::json!({
                    "entries": [{"name": "2"}],
                    "has_more": false
                }),
            ),
        ]);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 3);

        let reqs = t.http.requests();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].url.ends_with("/files/list_folder"));
        assert!(reqs[1].url.ends_with("/files/list_folder/continue"));
        assert!(String::from_utf8_lossy(&reqs[1].body).contains("cursor-abc"));
    }

    #[tokio::test]
    async fn chunk_count_missing_folder_is_zero() {
        let (t, _) = tier(vec![not_found_resp()]);
        assert_eq!(t.chunk_count(REF).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn delete_chunk_and_delete_stream_are_idempotent_on_not_found() {
        let (t, _) = tier(vec![
            json_resp(200, serde_json::json!({"metadata": {}})),
            not_found_resp(),
            json_resp(200, serde_json::json!({"metadata": {}})),
            not_found_resp(),
        ]);
        t.delete_chunk(REF, 0).await.unwrap();
        t.delete_chunk(REF, 0).await.unwrap(); // repeat: not-found → still Ok
        t.delete_stream(REF).await.unwrap();
        t.delete_stream(REF).await.unwrap(); // repeat: not-found → still Ok
    }

    #[tokio::test]
    async fn broker_direct_link_present_absent_and_no_token_leak() {
        let link_url = "https://dl.dropboxusercontent.com/apitl/1/abcXYZ";
        let (t, _) = tier(vec![
            // present: get_metadata 200, then get_temporary_link 200
            json_resp(200, serde_json::json!({ "name": "0" })),
            json_resp(200, serde_json::json!({ "link": link_url, "metadata": {} })),
            // absent: get_metadata not-found → broker never calls get_temporary_link
            not_found_resp(),
        ]);

        let link = t.broker_direct_link(REF, 0, 900).await.unwrap().unwrap();
        assert_eq!(link.url, link_url);
        assert_eq!(link.expires_in_s, 900);

        assert!(t.broker_direct_link(REF, 7, 900).await.unwrap().is_none());

        // The bearer token NEVER appears anywhere except the Authorization
        // header value of each recorded request (never in a URL, a JSON body,
        // or any other header).
        for r in t.http.requests() {
            assert!(!r.url.contains(TOKEN));
            assert!(!String::from_utf8_lossy(&r.body).contains(TOKEN));
            for (k, v) in &r.headers {
                if k == "authorization" {
                    assert_eq!(v, &format!("Bearer {TOKEN}"));
                } else {
                    assert!(!v.contains(TOKEN));
                }
            }
        }
    }

    #[tokio::test]
    async fn fail_closed_on_server_error_and_malformed_json() {
        let (t, _) = tier(vec![
            resp(500, b"internal error".to_vec()),
            resp(200, b"not json at all".to_vec()),
        ]);
        assert!(t.put_chunk(REF, 0, vec![1]).await.is_err());
        // chunk_count on a 200 with an unparseable body must error, not panic
        // and not silently report 0.
        assert!(t.chunk_count(REF).await.is_err());
    }

    #[tokio::test]
    async fn rejects_path_traversal_in_blob_ref() {
        let (t, _) = tier(vec![]);
        assert!(t.put_chunk("../escape", 0, vec![1]).await.is_err());
        assert!(t.get_chunk("../escape", 0).await.is_err());
        // No request was ever issued — the guard fires before any I/O.
        assert!(t.http.requests().is_empty());
    }

    #[tokio::test]
    async fn debug_never_prints_the_token() {
        let (t, _) = tier(vec![]);
        let debug = format!("{t:?}");
        assert!(!debug.contains(TOKEN));
        assert!(debug.contains("redacted"));
    }

    /// Live, real-network round trip against actual Dropbox. `#[ignore]`d so it
    /// never runs in CI; gated on `DROPBOX_TEST_TOKEN` so it never runs even
    /// with `--ignored` unless the operator supplies a real token. See the
    /// module doc for the exact command to run this manually.
    #[tokio::test]
    #[ignore = "live network test against real Dropbox; requires DROPBOX_TEST_TOKEN"]
    async fn dropbox_live_round_trip() {
        let token = match std::env::var("DROPBOX_TEST_TOKEN") {
            Ok(t) if !t.is_empty() => t,
            _ => {
                eprintln!("skipping dropbox_live_round_trip: DROPBOX_TEST_TOKEN is not set");
                return;
            }
        };
        let suffix = maxsecu_crypto::random_array::<8>();
        let mut hex = String::new();
        for b in suffix {
            hex.push_str(&format!("{b:02x}"));
        }
        let root = format!("/maxsecu-live-test-{hex}");
        let tier = DropboxTier::new(token, root).expect("real transport init");

        let blob_ref = "livetest/1/1";
        let payload = maxsecu_crypto::random_array::<64>().to_vec();

        tier.put_chunk(blob_ref, 0, payload.clone())
            .await
            .expect("put_chunk");
        let got = tier
            .get_chunk(blob_ref, 0)
            .await
            .expect("get_chunk")
            .expect("present");
        assert_eq!(got, payload);
        assert!(tier.has_chunk(blob_ref, 0).await.expect("has_chunk"));

        let link = tier
            .broker_direct_link(blob_ref, 0, 300)
            .await
            .expect("broker_direct_link")
            .expect("link present");
        assert!(link.url.starts_with("https://"));

        tier.delete_chunk(blob_ref, 0).await.expect("delete_chunk");
        assert!(tier
            .get_chunk(blob_ref, 0)
            .await
            .expect("get_chunk after delete")
            .is_none());

        // Best-effort cleanup of the test folder itself.
        let _ = tier.delete_stream(blob_ref).await;
    }
}
