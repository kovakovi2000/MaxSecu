//! T4 exit-gate end-to-end suite for **post-upload multi-recipient sharing**
//! (`reshare_file`), over REAL loopback TLS with NO mocked crypto — mirroring the
//! standard of `upload_e2e.rs`.
//!
//! Each scenario stands up the secret-free app server (MemoryStore + FsBlobStore)
//! under a pinned D5 directory root, PLUS a REAL out-of-band **sink** on its own
//! pinned TLS identity that anchors the control-log head (spec §0 D-OQ1). It then
//! drives the real reshare over the live connections:
//!   * `client_app::sink::fetch_anchored_head` (loaded from the on-disk pinned
//!     `SinkPins` via `config::load_sink_pins`) fetches + cryptographically
//!     validates the anchored revocation head from the sink;
//!   * `client_core::TombstoneSet` authenticates the served control records
//!     against that anchored head;
//!   * `client_app::directory::resolve_recipient` re-resolves + D5-verifies each
//!     recipient at share time;
//!   * `client_core::build_reshare` performs the real X25519 / ML-KEM-hybrid
//!     re-wrap + possession-entailing grant;
//!   * the wrap is POSTed to `/v1/files/{id}/wraps` and the recipient downloads +
//!     runs the full `verify_and_open` ladder to prove the DEK genuinely opens.
//!
//! ## Why the flow is reconstructed rather than calling `reshare_file`
//! `reshare_file` is a `#[tauri::command]` that takes `tauri::AppHandle` (bound to
//! the concrete `Wry` runtime — not constructible headless) and its orchestration
//! (`reshare_inner` / `run_reshare_batch`) plus the glue helpers `recover_own_dek`
//! / `build_tombstones` / `wrap_wire` are private / `pub(crate)`, so an external
//! test crate cannot reach them. Exactly as `upload_e2e.rs` reconstructs the
//! upload pipeline from public primitives, this suite reconstructs the per-batch
//! loop from the SAME public product code (`build_reshare`, `fetch_anchored_head`,
//! `resolve_recipient`, `TombstoneSet`, `load_sink_pins`) over real transport and
//! real crypto — only the trivial POST-body shaping mirrors `share.rs::wrap_req_body`
//! byte-for-byte. The private orchestration's per-recipient isolation is unit-tested
//! in `commands/share.rs`.

use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_admin_core::{CoSign, ControlChain, DirectorySigner, RevokeParams};
use maxsecu_client_app::config::{client_config_for_pinned_root, load_sink_pins};
use maxsecu_client_app::directory::resolve_recipient;
use maxsecu_client_app::download::parse_file_view;
use maxsecu_client_app::sink::fetch_anchored_head;
use maxsecu_client_app::upload::{prepare_image_streams, run_pipeline};
use maxsecu_client_core::{
    build_reshare, build_upload, verify_and_open, ControlRecordIn, DirectoryVerifier,
    DownloadBundle, Identity, IssuerInfo, MemoryTrustStore, ReshareError, ReshareParams,
    StreamChunks, TombstoneSet, UploadParams, VerifyContext, WrapOut, NO_ADMINS, NO_GRANTERS,
};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, sha256, unwrap_dek, unwrap_dek_hybrid, Dek, EncPublicKey,
    HybridEncSecretKey, SigningKey, WrappedDek,
};
use maxsecu_encoding::structs::{DirBinding, Grant, Manifest, WrapContext};
use maxsecu_encoding::types::{
    Bytes32, FileScope, FileType, Id, MlKemPub, RecipientType, Role, RoleSet, StreamType, Suite,
    Text, Timestamp,
};
use maxsecu_sink_server::{router as sink_router, serve as sink_serve, Anchorer, SinkState};

use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, GrantAction,
    MemoryAuditSink, MemoryStore,
};

const TS: u64 = 1_719_500_000_000;
const FAR_FUTURE_MS: u64 = 4_102_444_800_000;
/// Test-only loopback bearer authorizing appends to the in-process sink (§6.1).
const SINK_TOKEN: &str = "sink-admin-secret";

// ============================================================================
// TLS + HTTP harness (copied from upload_e2e.rs)
// ============================================================================

struct TestPki {
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
}

fn test_pki() -> TestPki {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TestPki {
        server_config: Arc::new(server_config),
        client_config: Arc::new(client_config),
    }
}

/// A self-signed `localhost` cert for the sink: its `ServerConfig` + the raw DER
/// the client pins as its ONLY sink root.
fn sink_pki() -> (Arc<ServerConfig>, Vec<u8>) {
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

struct Conn {
    sender: SendRequest<Full<Bytes>>,
    exporter: [u8; 32],
}

async fn connect(addr: std::net::SocketAddr, client_config: Arc<ClientConfig>) -> Conn {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let exporter = export_channel_binding(tls.get_ref().1).unwrap();
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Conn { sender, exporter }
}

async fn post(
    conn: &mut Conn,
    uri: &str,
    auth: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/json");
    if let Some(t) = auth {
        req = req.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let req = req.body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

async fn get_json(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, serde_json::Value) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

async fn get_raw(conn: &mut Conn, uri: &str, auth: &str) -> (StatusCode, Vec<u8>) {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = conn.sender.send_request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn stream_from_name(s: &str) -> StreamType {
    match s {
        "content" => StreamType::Content,
        "metadata" => StreamType::Metadata,
        "thumbnail" => StreamType::Thumbnail,
        "preview" => StreamType::Preview,
        _ => panic!("unknown stream {s}"),
    }
}

fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

/// Register + channel-bound-login an identity; return its `user_id` + token.
async fn register_and_login(
    c: &mut Conn,
    owner: &Identity,
    username: &str,
    reg_key: &str,
) -> ([u8; 16], String) {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "registration_key": reg_key,
        }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "registration over TLS ({username})"
    );
    let user_id = hex16(res["user_id"].as_str().unwrap());

    let (_st, ch) = post(
        c,
        "/v1/session/challenge",
        None,
        serde_json::json!({ "username": username }),
    )
    .await;
    let nonce: [u8; 32] = B64
        .decode(ch["nonce_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let server_id = ch["server_id"].as_str().unwrap().to_owned();
    let proof = {
        use maxsecu_encoding::labels;
        use maxsecu_encoding::structs::AuthProofContext;
        let ctx = AuthProofContext {
            server_id: Text::new(&server_id).unwrap(),
            tls_exporter: Bytes32(c.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(owner.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        c,
        "/v1/session/proof",
        None,
        serde_json::json!({ "username": username, "timestamp": TS, "proof_b64": proof }),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "login over the bound channel ({username})"
    );
    (user_id, res["session_token"].as_str().unwrap().to_owned())
}

/// Publish a D5-signed binding for `(username, user_id, identity)` under `roles`.
/// When `pq`, the binding carries the identity's ML-KEM-768 key (a PQ-enrolled
/// recipient); otherwise it is a classical (v1) binding.
async fn publish_binding(
    c: &mut Conn,
    signer: &DirectorySigner,
    username: &str,
    uid: [u8; 16],
    id: &Identity,
    roles: &[Role],
    pq: bool,
) {
    let binding = DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id(uid),
        enc_pub: Bytes32(id.enc_pub_bytes()),
        sig_pub: Bytes32(id.sig_pub_bytes()),
        key_version: 1,
        roles: RoleSet::new(roles.iter().copied()),
        not_before: Timestamp(0),
        not_after: Timestamp(FAR_FUTURE_MS),
        mlkem_pub: None,
    };
    let mlkem = if pq {
        id.mlkem_pub_bytes().map(MlKemPub)
    } else {
        None
    };
    let signed = signer.sign_binding(&binding, mlkem);
    let (st, _) = post(
        c,
        "/v1/directory",
        None,
        serde_json::json!({
            "binding_b64": B64.encode(maxsecu_encoding::encode(&signed.binding)),
            "directory_signature_b64": B64.encode(signed.signature),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish binding {username}");
}

/// Register + login + publish a binding for a fresh identity; returns it.
async fn enroll(
    c: &mut Conn,
    signer: &DirectorySigner,
    ctr: &mut usize,
    username: &str,
    roles: &[Role],
    pq: bool,
) -> (Identity, [u8; 16], String) {
    let voucher = format!("voucher-{ctr}");
    *ctr += 1;
    let id = Identity::generate();
    let (uid, token) = register_and_login(c, &id, username, &voucher).await;
    publish_binding(c, signer, username, uid, &id, roles, pq).await;
    (id, uid, token)
}

/// GET the file view + every chunk back and rebuild a `DownloadBundle` (mirrors
/// upload_e2e.rs). The `auth` token decides WHOSE `my_wrap` (self-wrap or a
/// reshared wrap) the view carries.
async fn download_bundle(c: &mut Conn, token: &str, fid_hex: &str) -> DownloadBundle {
    let (st, rec) = get_json(c, &format!("/v1/files/{fid_hex}?version=latest"), token).await;
    assert_eq!(st, StatusCode::OK, "file view for download");
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{fid_hex}/versions/1/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(c, &uri, token).await;
            assert_eq!(cs, StatusCode::OK);
            chunks.push(bytes);
        }
        dl_streams.push(StreamChunks {
            stream_type: stream_from_name(st_name),
            chunks,
        });
    }
    let dec = |v: &serde_json::Value| B64.decode(v.as_str().unwrap()).unwrap();
    let dec64 = |v: &serde_json::Value| -> [u8; 64] { dec(v).try_into().unwrap() };
    let mw = &rec["my_wrap"];
    let rg = &rec["recovery_grant"];
    DownloadBundle {
        manifest_bytes: dec(&rec["manifest_b64"]),
        manifest_sig: dec64(&rec["manifest_sig_b64"]),
        genesis_bytes: dec(&rec["genesis_b64"]),
        genesis_sig: dec64(&rec["genesis_sig_b64"]),
        wrapped_dek: wrap_from_bytes(&dec(&mw["wrapped_dek_b64"])),
        grant_bytes: dec(&mw["grant_b64"]),
        grant_sig: dec64(&mw["grant_sig_b64"]),
        ancestor_grants: vec![],
        recovery_grant_bytes: dec(&rg["grant_b64"]),
        recovery_grant_sig: dec64(&rg["grant_sig_b64"]),
        streams: dl_streams,
    }
}

fn gen_png() -> Vec<u8> {
    use image::{DynamicImage, ImageFormat, RgbImage};
    use std::io::Cursor;
    let mut img = RgbImage::new(96, 72);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = image::Rgb([(x % 256) as u8, (y % 256) as u8, 21]);
    }
    let mut buf = Vec::new();
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

// ============================================================================
// Reshare reconstruction over public product code (see module doc)
// ============================================================================

#[derive(Debug, Clone)]
struct Outcome {
    username: String,
    ok: bool,
    code: Option<String>,
}

/// Sanitized per-recipient failure code — mirrors `share.rs::reshare_error_code`.
fn reshare_error_code(e: &ReshareError) -> &'static str {
    match e {
        ReshareError::RecipientRevoked => "revoked",
        ReshareError::ResharePqKeyMissing => "pq_key_missing",
        ReshareError::DekCommitMismatch => "verify_failed",
        ReshareError::RecipientIsRecovery => "recovery_recipient",
        ReshareError::WrapFailed => "wrap_failed",
    }
}

/// The `POST /v1/files/{id}/wraps` body — byte-identical to `share.rs::wrap_req_body`.
fn wrap_body(w: &WrapOut) -> serde_json::Value {
    let mut wire = w.wrapped_dek.enc.to_vec();
    wire.extend_from_slice(&w.wrapped_dek.ct);
    serde_json::json!({
        "recipient_id": hex(&w.recipient_id.0),
        "recipient_type": "user",
        "wrapped_dek_b64": B64.encode(&wire),
        "wrap_alg": 1,
        "granted_by": hex(&w.granted_by.0),
        "grant_b64": B64.encode(maxsecu_encoding::encode::<Grant>(&w.grant)),
        "grant_sig_b64": B64.encode(w.grant_sig),
    })
}

/// The per-recipient reshare loop, reconstructed from public product code exactly
/// as `run_reshare_batch` does: (async resolve+verify under the pinned D5) →
/// (sync `build_reshare`, fail-closed on tombstone / PQ-missing / commitment) →
/// (async POST). One [`Outcome`] per entered username, in order; a per-recipient
/// failure never aborts the batch. `post_token` lets a scenario inject a transient
/// POST-auth failure (a real non-201) without touching the crypto.
#[allow(clippy::too_many_arguments)]
async fn reshare_batch(
    conn: &mut Conn,
    post_token: &str,
    file_id_hex: &str,
    file_id: [u8; 16],
    version: u64,
    dek_commit: [u8; 32],
    suite: Suite,
    granter: &Identity,
    granter_id: [u8; 16],
    dek: &Dek,
    tombstones: &TombstoneSet,
    pinned: [u8; 32],
    recipients: &[&str],
) -> Vec<Outcome> {
    let verifier = DirectoryVerifier::new(pinned);
    let mut outcomes = Vec::with_capacity(recipients.len());
    for uname in recipients {
        let mut trust = MemoryTrustStore::new();
        let author = match resolve_recipient(
            &mut conn.sender,
            "localhost",
            uname,
            &verifier,
            &mut trust,
            TS,
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                outcomes.push(Outcome {
                    username: (*uname).to_owned(),
                    ok: false,
                    code: Some(e.code),
                });
                continue;
            }
        };
        let params = ReshareParams {
            granter,
            granter_id: Id(granter_id),
            file_id: Id(file_id),
            version,
            dek_commit,
            recipient_id: Id(author.user_id),
            recipient_enc_pub: EncPublicKey::from_bytes(author.enc_pub),
            suite,
            recipient_mlkem_pub: author.mlkem_pub,
            created_at: Timestamp(TS),
        };
        match build_reshare(&params, dek, tombstones) {
            Ok(w) => {
                let (st, _) = post(
                    conn,
                    &format!("/v1/files/{file_id_hex}/wraps"),
                    Some(post_token),
                    wrap_body(&w),
                )
                .await;
                if st == StatusCode::CREATED {
                    outcomes.push(Outcome {
                        username: (*uname).to_owned(),
                        ok: true,
                        code: None,
                    });
                } else {
                    outcomes.push(Outcome {
                        username: (*uname).to_owned(),
                        ok: false,
                        code: Some("share_failed".to_owned()),
                    });
                }
            }
            Err(e) => outcomes.push(Outcome {
                username: (*uname).to_owned(),
                ok: false,
                code: Some(reshare_error_code(&e).to_owned()),
            }),
        }
    }
    outcomes
}

// ============================================================================
// Fixture: a running server + sink + pinned D5 + logged-in owner
// ============================================================================

struct Fixture {
    conn: Conn,
    app_dir: PathBuf,
    blob_dir: PathBuf,
    dir_signer: DirectorySigner,
    pinned: [u8; 32],
    owner: Identity,
    owner_id: [u8; 16],
    owner_token: String,
    ctr: usize,
    audit: Arc<MemoryAuditSink>,
    /// Sink dial info, so a scenario can advance the control log (scenario 4).
    sink_addr: std::net::SocketAddr,
    sink_cc: Arc<ClientConfig>,
}

impl Fixture {
    async fn boot() -> Fixture {
        let rnd = hex(&maxsecu_crypto::random_array::<8>());
        let app_dir = std::env::temp_dir().join(format!("mxreshare_{rnd}"));
        let blob_dir = app_dir.join("blobs");
        std::fs::create_dir_all(app_dir.join("config")).unwrap();

        // ---- D5 directory root (the pinned trust anchor for all bindings). The
        // server holds the private half (from the same seed) so registration-key
        // enrollment can sign bindings; the scripted ceremony signer publishes the
        // PQ/role bindings this test needs, which verify under the same pinned key. ----
        let d5_seed = maxsecu_crypto::random_array::<32>();
        let dir_signer = DirectorySigner::from_seed(&d5_seed);
        let pinned = dir_signer.public_key();

        // ---- App server (MemoryStore + FsBlobStore + a MemoryAuditSink) ----
        let store = MemoryStore::new();
        for i in 0..64usize {
            store.add_reg_key(sha256(format!("voucher-{i}").as_bytes()));
        }
        let audit = Arc::new(MemoryAuditSink::new());
        let state = AppState {
            auth: Arc::new(
                AuthService::new(store, AuthConfig::default().with_directory_pub(pinned))
                    .with_dir_signer(Arc::new(SigningKey::from_seed(&d5_seed))),
            ),
            blobs: Arc::new(FsBlobStore::new(&blob_dir)),
            audit: audit.clone(),
            direct_links_enabled: false,
            max_file_bytes: None,
        };
        let pki = test_pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            pki.server_config.clone(),
            maxsecu_server::router(state),
        ));

        // ---- Real out-of-band sink over its OWN pinned TLS identity ----
        let custodian = SigningKey::generate();
        let custodian_pub = custodian.verifying_key().to_bytes();
        let anchorer = Anchorer::new(custodian, SigningKey::generate());
        let sink_state = SinkState::new(anchorer, SINK_TOKEN);
        let (sink_server_cfg, sink_cert_der) = sink_pki();
        let sink_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_addr = sink_listener.local_addr().unwrap();
        tokio::spawn(sink_serve(
            sink_listener,
            sink_server_cfg,
            sink_router(sink_state),
        ));

        // ---- Write the on-disk SinkPins the loader (load_sink_pins) reads ----
        let cfg = app_dir.join("config");
        std::fs::write(
            cfg.join("sink.json"),
            serde_json::json!({
                "addr": sink_addr.to_string(),
                "server_name": "localhost",
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(cfg.join("sink_root.der"), &sink_cert_der).unwrap();
        std::fs::write(cfg.join("sink_custodians.der"), custodian_pub).unwrap();
        // (no sink_transparency.der — the v1 deployment ships only the custodian form.)
        let sink_cc = client_config_for_pinned_root(&sink_cert_der).unwrap();

        // ---- Owner: registered, logged in, published ----
        let mut conn = connect(addr, pki.client_config.clone()).await;
        let mut ctr = 0usize;
        let (owner, owner_id, owner_token) = enroll(
            &mut conn,
            &dir_signer,
            &mut ctr,
            "owner",
            &[Role::User],
            false,
        )
        .await;

        Fixture {
            conn,
            app_dir,
            blob_dir,
            dir_signer,
            pinned,
            owner,
            owner_id,
            owner_token,
            ctr,
            audit,
            sink_addr,
            sink_cc,
        }
    }

    /// Upload one image file authored by the owner. `pq` publishes a PQ recovery
    /// recipient so `build_upload` selects `Suite::V2` (self+recovery both PQ);
    /// otherwise a classical `Suite::V1` file. Returns `(file_id, canonical content)`.
    async fn upload_image(&mut self, pq: bool) -> ([u8; 16], Vec<u8>) {
        let rname = format!("recovery-{}", self.ctr);
        // Enroll the standing recovery recipient and take its keys directly (the
        // buddy directory-resolve was retired in T8). `pq` still drives the suite:
        // include the recovery ML-KEM key only when a PQ recovery is requested, so
        // `build_upload` selects Suite::V2 exactly as before (self+recovery both PQ).
        let (recovery_id, _uid, _tok) = enroll(
            &mut self.conn,
            &self.dir_signer,
            &mut self.ctr,
            &rname,
            &[Role::User],
            pq,
        )
        .await;
        let recovery_enc = recovery_id.enc_pub_bytes();
        let recovery_mlkem = if pq { recovery_id.mlkem_pub_bytes() } else { None };

        let src_png = gen_png();
        let (file_type, streams) =
            prepare_image_streams(&src_png, "Sunset", &["beach".to_owned()]).unwrap();
        assert_eq!(file_type, FileType::Image);
        let canonical = streams.content.clone();
        let file_id = Id(maxsecu_crypto::random_array::<16>());
        let bundle = build_upload(
            &UploadParams {
                owner: &self.owner,
                owner_id: Id(self.owner_id),
                owner_key_version: 1,
                file_id,
                file_type,
                chunk_size: 4096,
                recovery_pub: EncPublicKey::from_bytes(recovery_enc),
                recovery_mlkem_pub: recovery_mlkem,
                created_at: Timestamp(TS),
            },
            &streams,
        )
        .unwrap();
        run_pipeline(
            &mut self.conn.sender,
            "localhost",
            &self.owner_token,
            &bundle,
            |_d, _t| {},
        )
        .await
        .unwrap();
        (file_id.0, canonical)
    }

    /// Recover the owner's DEK from its OWN served self-wrap — real crypto,
    /// mirroring `download.rs::recover_own_dek` (both suites). This is the
    /// possession precondition every reshare needs.
    async fn recover_owner_dek(&mut self, file_id: [u8; 16]) -> Dek {
        let fid_hex = hex(&file_id);
        let (st, view_json) = get_json(
            &mut self.conn,
            &format!("/v1/files/{fid_hex}?version=latest"),
            &self.owner_token,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "owner file view");
        let view = parse_file_view(&view_json).unwrap();
        let manifest: Manifest = maxsecu_encoding::decode(&view.manifest_bytes).unwrap();
        let ctx = WrapContext {
            file_id: Id(file_id),
            version: manifest.version,
            recipient_id: Id(self.owner_id),
        };
        let dek = match manifest.alg {
            Suite::V1 => unwrap_dek(self.owner.enc_secret(), &view.wrapped_dek, &ctx).unwrap(),
            Suite::V2 => {
                let seed = self.owner.mlkem_seed().unwrap();
                let mut wire = Vec::with_capacity(32 + view.wrapped_dek.ct.len());
                wire.extend_from_slice(&view.wrapped_dek.enc);
                wire.extend_from_slice(&view.wrapped_dek.ct);
                let hybrid = deserialize_hybrid_wrap(&wire).unwrap();
                let hsk = HybridEncSecretKey::from_components(
                    self.owner.enc_secret().expose_bytes(),
                    seed,
                );
                unwrap_dek_hybrid(&hsk, &hybrid, &ctx).unwrap()
            }
        };
        assert_eq!(
            dek.commit(),
            manifest.dek_commit.0,
            "recovered DEK opens to commitment"
        );
        dek
    }

    /// The file's manifest suite (V1/V2), read from the owner's served view.
    async fn file_suite(&mut self, file_id: [u8; 16]) -> Suite {
        let fid_hex = hex(&file_id);
        let (st, view_json) = get_json(
            &mut self.conn,
            &format!("/v1/files/{fid_hex}?version=latest"),
            &self.owner_token,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let view = parse_file_view(&view_json).unwrap();
        let manifest: Manifest = maxsecu_encoding::decode(&view.manifest_bytes).unwrap();
        manifest.alg
    }

    /// The current recipient `user_id`s of a file, per the owner-only server view.
    async fn recipients_of(&mut self, file_id: [u8; 16]) -> Vec<[u8; 16]> {
        let fid_hex = hex(&file_id);
        let (st, json) = get_json(
            &mut self.conn,
            &format!("/v1/files/{fid_hex}/recipients"),
            &self.owner_token,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "owner lists recipients");
        json["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| hex16(r["recipient_id"].as_str().unwrap()))
            .collect()
    }

    /// Download the file AS `recipient` (its own reshared wrap) and prove the
    /// canonical content round-trips through the full `verify_and_open` ladder.
    async fn assert_recipient_opens(
        &mut self,
        file_id: [u8; 16],
        recipient_id: [u8; 16],
        recipient: &Identity,
        token: &str,
        expected_content: &[u8],
    ) {
        let fid_hex = hex(&file_id);
        let bundle = download_bundle(&mut self.conn, token, &fid_hex).await;
        let owner_sig_pub = self.owner.sig_pub_bytes();
        let ctx = VerifyContext {
            file_id: Id(file_id),
            author_sig_pub: owner_sig_pub,
            owner_sig_pub,
            recipient_id: Id(recipient_id),
            recipient_type: RecipientType::User,
            recipient_secret: recipient.enc_secret(),
            recipient_mlkem_seed: recipient.mlkem_seed(),
            seen_max_version: None,
            granter_sig_pub: &NO_GRANTERS,
            admin_sig_pub: &NO_ADMINS,
            tombstones: None,
            compromise: None,
        };
        let opened = verify_and_open(&ctx, &bundle).expect("recipient opens the reshared file");
        let content = &opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Content)
            .unwrap()
            .plaintext;
        assert_eq!(
            content, expected_content,
            "reshared content round-trips exactly"
        );
        let meta = &opened
            .streams
            .iter()
            .find(|s| s.stream_type == StreamType::Metadata)
            .unwrap()
            .plaintext;
        assert!(
            std::str::from_utf8(meta).unwrap().contains("Sunset"),
            "reshared metadata title decrypts"
        );
    }

    /// Fetch the sink-anchored control-log head over the pinned channel via the
    /// REAL `config::load_sink_pins` + `sink::fetch_anchored_head` — on a blocking
    /// thread (the sink client owns an internal runtime, so it must not nest).
    async fn anchored_head(&self) -> [u8; 32] {
        let dir = self.app_dir.clone();
        tokio::task::spawn_blocking(move || {
            let pins = load_sink_pins(&dir).expect("pinned SinkPins load");
            fetch_anchored_head(&pins).expect("anchored head verifies under the pinned custodian")
        })
        .await
        .unwrap()
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.app_dir);
        let _ = std::fs::remove_dir_all(&self.blob_dir);
    }
}

/// POST one control record to the sink over its pinned TLS channel; returns status.
async fn post_sink_record(
    addr: std::net::SocketAddr,
    cc: Arc<ClientConfig>,
    record_bytes: &[u8],
) -> StatusCode {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(cc);
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let body = serde_json::json!({ "record_b64": B64.encode(record_bytes) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/control-log/records")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {SINK_TOKEN}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    sender.send_request(req).await.unwrap().status()
}

fn empty_tombstones() -> TombstoneSet {
    TombstoneSet::verify(&[], maxsecu_encoding::GENESIS_HEAD.0).unwrap()
}

// ============================================================================
// Scenario 1 — share to a fresh recipient → their download verifies
// ============================================================================
#[tokio::test]
async fn scenario1_share_to_fresh_recipient_downloads_and_verifies() {
    let mut fx = Fixture::boot().await;
    let (file_id, content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;

    // The empty revocation state is attested by the REAL sink's genesis anchor.
    let head = fx.anchored_head().await;
    assert_eq!(
        head,
        maxsecu_encoding::GENESIS_HEAD.0,
        "an un-advanced sink anchors the genesis head"
    );
    let tombstones = TombstoneSet::verify(&[], head).unwrap();

    let (carol, carol_id, carol_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "carol",
        &[Role::User],
        false,
    )
    .await;

    let out = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["carol"],
    )
    .await;
    assert_eq!(out.len(), 1);
    assert!(
        out[0].ok && out[0].code.is_none(),
        "fresh recipient shares OK: {out:?}"
    );

    // GATE: carol is now a recipient and her download opens the exact plaintext.
    assert!(fx.recipients_of(file_id).await.contains(&carol_id));
    fx.assert_recipient_opens(file_id, carol_id, &carol, &carol_token, &content)
        .await;
    fx.cleanup();
}

// ============================================================================
// Scenario 2 — idempotent re-share → still exactly one recipient row
// ============================================================================
#[tokio::test]
async fn scenario2_idempotent_reshare_keeps_one_recipient_row() {
    let mut fx = Fixture::boot().await;
    let (file_id, _content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;
    let tombstones = TombstoneSet::verify(&[], fx.anchored_head().await).unwrap();
    let (_carol, carol_id, _carol_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "carol",
        &[Role::User],
        false,
    )
    .await;

    // Share to carol TWICE.
    for _ in 0..2 {
        let out = reshare_batch(
            &mut fx.conn,
            &fx.owner_token,
            &hex(&file_id),
            file_id,
            1,
            dek.commit(),
            Suite::V1,
            &fx.owner,
            fx.owner_id,
            &dek,
            &tombstones,
            fx.pinned,
            &["carol"],
        )
        .await;
        assert!(out[0].ok, "each idempotent re-share succeeds: {out:?}");
    }

    // GATE: exactly one recipient row for carol (Store::add_wrap replaced it).
    let recips = fx.recipients_of(file_id).await;
    assert_eq!(
        recips.iter().filter(|r| **r == carol_id).count(),
        1,
        "idempotent re-share yields exactly one recipient row: {recips:?}"
    );
    fx.cleanup();
}

// ============================================================================
// Scenario 3 — unpublished recipient → code:"untrusted", no wrap POST
// ============================================================================
#[tokio::test]
async fn scenario3_unpublished_recipient_untrusted_no_post() {
    let mut fx = Fixture::boot().await;
    let (file_id, _content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;
    let tombstones = TombstoneSet::verify(&[], fx.anchored_head().await).unwrap();

    // "ghost" is never registered/published → the D5 resolve fails closed.
    let out = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["ghost"],
    )
    .await;
    assert_eq!(out.len(), 1);
    assert!(!out[0].ok);
    assert_eq!(out[0].code.as_deref(), Some("untrusted"));

    // GATE: no wrap POST happened — no Reshare edge, and no recipients on the file.
    assert!(
        !fx.audit
            .edges()
            .iter()
            .any(|e| e.action == GrantAction::Reshare),
        "an untrusted resolve never POSTs a wrap"
    );
    // The only recipient row is the owner's own self-wrap; no third party was added.
    let recips = fx.recipients_of(file_id).await;
    assert!(
        recips.iter().all(|r| *r == fx.owner_id),
        "no third-party recipient row was created for an untrusted username: {recips:?}"
    );
    fx.cleanup();
}

// ============================================================================
// Scenario 4 — tombstoned recipient rejected while a co-batch valid one succeeds
// ============================================================================
#[tokio::test]
async fn scenario4_tombstoned_recipient_rejected_cobatch_valid_succeeds() {
    let mut fx = Fixture::boot().await;
    let (file_id, content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;

    // Two published recipients; `victim` will be account-wide revoked, `keep` not.
    let (_victim, victim_id, _vt) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "victim",
        &[Role::User],
        false,
    )
    .await;
    let (keep, keep_id, keep_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "keep",
        &[Role::User],
        false,
    )
    .await;

    // A REAL dual-controlled account-wide revocation of `victim`, appended to the
    // sink so the anchored head advances past genesis.
    let admin = SigningKey::generate();
    let co = SigningKey::generate();
    let admin_id = [0xA1u8; 16];
    let co_id = [0xC0u8; 16];
    let mut chain = ControlChain::new();
    let rec = chain
        .revoke(
            &admin,
            RevokeParams {
                scope: FileScope::AccountWide,
                revoked_user_id: Id(victim_id),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id(admin_id),
                created_at: Timestamp(TS),
            },
            Some(CoSign {
                admin_id: Id(co_id),
                key: &co,
            }),
        )
        .unwrap();
    assert_eq!(
        post_sink_record(fx.sink_addr, fx.sink_cc.clone(), &rec.bytes).await,
        StatusCode::OK,
        "the sink accepts the appended revocation"
    );

    // The sink-anchored head now commits to the revoke; the served record set is
    // authenticated against it (real chain + issuer-authority verify).
    let head = fx.anchored_head().await;
    assert_ne!(head, maxsecu_encoding::GENESIS_HEAD.0, "the head advanced");
    let records = vec![ControlRecordIn {
        bytes: rec.bytes.clone(),
        sig: rec.sig,
        co_sig: rec.co_sig,
    }];
    let admin_pub = admin.verifying_key().to_bytes();
    let co_pub = co.verifying_key().to_bytes();
    let issuer = |id: Id| -> Option<IssuerInfo> {
        if id == Id(admin_id) {
            Some(IssuerInfo {
                sig_pub: admin_pub,
                roles: vec![Role::Admin],
                key_version: 1,
            })
        } else if id == Id(co_id) {
            Some(IssuerInfo {
                sig_pub: co_pub,
                roles: vec![Role::Admin],
                key_version: 1,
            })
        } else {
            None
        }
    };
    let tombstones = TombstoneSet::verify_authenticated(&records, head, &issuer)
        .expect("authenticated chain verifies against the sink-anchored head");
    assert!(tombstones.is_account_revoked(&victim_id));

    // Same batch: `victim` is refused (revoked), `keep` still succeeds.
    let out = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["victim", "keep"],
    )
    .await;
    assert_eq!(out.len(), 2, "one row per entered username");
    assert_eq!(out[0].username, "victim");
    assert!(!out[0].ok);
    assert_eq!(out[0].code.as_deref(), Some("revoked"));
    assert_eq!(out[1].username, "keep");
    assert!(
        out[1].ok,
        "the non-revoked co-batch recipient still succeeds: {out:?}"
    );

    // GATE: only `keep` gained access; `victim` never did.
    let recips = fx.recipients_of(file_id).await;
    assert!(recips.contains(&keep_id));
    assert!(
        !recips.contains(&victim_id),
        "a revoked recipient is never re-admitted"
    );
    fx.assert_recipient_opens(file_id, keep_id, &keep, &keep_token, &content)
        .await;
    fx.cleanup();
}

// ============================================================================
// Scenario 5 — batch partial-failure + targeted retry
// ============================================================================
#[tokio::test]
async fn scenario5_batch_partial_failure_then_targeted_retry() {
    let mut fx = Fixture::boot().await;
    let (file_id, content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;
    let tombstones = TombstoneSet::verify(&[], fx.anchored_head().await).unwrap();

    let (carol, carol_id, carol_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "carol",
        &[Role::User],
        false,
    )
    .await;
    let (dave, dave_id, dave_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "dave",
        &[Role::User],
        false,
    )
    .await;

    // Batch [carol, dave] where dave's POST hits a REAL transient auth failure
    // (a bogus session token → 401 non-201 → "share_failed"), isolated from
    // carol's success. carol POSTs with the valid owner token; dave with a bad one.
    let out_carol = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["carol"],
    )
    .await;
    assert!(
        out_carol[0].ok,
        "carol succeeds in the batch: {out_carol:?}"
    );

    let out_dave_fail = reshare_batch(
        &mut fx.conn,
        "not-a-valid-session-token",
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["dave"],
    )
    .await;
    assert!(!out_dave_fail[0].ok);
    assert_eq!(
        out_dave_fail[0].code.as_deref(),
        Some("share_failed"),
        "a non-201 POST fails this recipient (real transient), not the batch"
    );
    // The failure created no dave row.
    assert!(!fx.recipients_of(file_id).await.contains(&dave_id));

    // Targeted retry of ONLY dave with the valid token → success (idempotent-safe).
    let out_dave_retry = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["dave"],
    )
    .await;
    assert!(
        out_dave_retry[0].ok,
        "the targeted retry succeeds: {out_dave_retry:?}"
    );

    // GATE: both recipients present; carol untouched (still exactly one row); both open.
    let recips = fx.recipients_of(file_id).await;
    assert_eq!(recips.iter().filter(|r| **r == carol_id).count(), 1);
    assert!(recips.contains(&dave_id));
    fx.assert_recipient_opens(file_id, carol_id, &carol, &carol_token, &content)
        .await;
    fx.assert_recipient_opens(file_id, dave_id, &dave, &dave_token, &content)
        .await;
    fx.cleanup();
}

// ============================================================================
// Scenario 6 — V2/hybrid round-trip incl. pq_key_missing fail-closed
// ============================================================================
#[tokio::test]
async fn scenario6_v2_hybrid_roundtrip_and_pq_key_missing() {
    let mut fx = Fixture::boot().await;
    // A PQ recovery recipient makes the upload Suite::V2 (self+recovery both PQ).
    let (file_id, content) = fx.upload_image(true).await;
    assert_eq!(
        fx.file_suite(file_id).await,
        Suite::V2,
        "the file is Suite::V2"
    );
    let dek = fx.recover_owner_dek(file_id).await;
    let tombstones = TombstoneSet::verify(&[], fx.anchored_head().await).unwrap();

    // A PQ-enrolled recipient (binding carries ML-KEM) and a classical one.
    let (pqr, pqr_id, pqr_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "pqr",
        &[Role::User],
        true,
    )
    .await;
    let (_classical, classical_id, _ct) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "classic",
        &[Role::User],
        false,
    )
    .await;

    let out = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V2,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["pqr", "classic"],
    )
    .await;
    assert_eq!(out.len(), 2);
    // The PQ recipient gets a hybrid re-wrap …
    assert_eq!(out[0].username, "pqr");
    assert!(out[0].ok, "V2 re-share to a PQ recipient succeeds: {out:?}");
    // … the classical recipient fails CLOSED (never a silent classical downgrade).
    assert_eq!(out[1].username, "classic");
    assert!(!out[1].ok);
    assert_eq!(out[1].code.as_deref(), Some("pq_key_missing"));

    // GATE: the PQ recipient opens the V2 hybrid wrap; the classical one has no row
    // (a `pq_key_missing` fail-close leaves NO wrap — never a silent downgrade side-effect).
    let recips = fx.recipients_of(file_id).await;
    assert!(recips.contains(&pqr_id));
    assert!(
        !recips.contains(&classical_id),
        "V2→classical pq_key_missing must leave no wrap row for the classical recipient"
    );
    fx.assert_recipient_opens(file_id, pqr_id, &pqr, &pqr_token, &content)
        .await;
    fx.cleanup();
}

// ============================================================================
// Scenario 7 — non-holder cannot reshare (DEK recovery fails before any POST)
// ============================================================================
#[tokio::test]
async fn scenario7_non_holder_cannot_reshare_before_any_post() {
    let mut fx = Fixture::boot().await;
    let (file_id, _content) = fx.upload_image(false).await;

    // `mallory` is a fully-registered user who holds NO wrap on the owner's file.
    let (mallory, mallory_id, mallory_token) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "mallory",
        &[Role::User],
        false,
    )
    .await;
    // A published (but never-shared-to) target, to prove no POST reaches the server.
    let (_erin, erin_id, _et) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "erin",
        &[Role::User],
        false,
    )
    .await;

    // The reshare precondition is possession: the non-holder's own file view is a
    // 404 (no wrap held), so the DEK is unrecoverable — the batch never reaches a POST.
    let fid_hex = hex(&file_id);
    let (st, _view) = get_json(
        &mut fx.conn,
        &format!("/v1/files/{fid_hex}?version=latest"),
        &mallory_token,
    )
    .await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "a non-holder cannot fetch the file view → cannot recover the DEK"
    );

    // Belt-and-suspenders: even a forged POST by the non-holder is refused by the
    // server (NoAccess → 404), so no wrap is ever created regardless.
    let bogus = Dek::generate();
    let verifier = DirectoryVerifier::new(fx.pinned);
    let mut trust = MemoryTrustStore::new();
    let erin = resolve_recipient(
        &mut fx.conn.sender,
        "localhost",
        "erin",
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    let params = ReshareParams {
        granter: &mallory,
        granter_id: Id(mallory_id),
        file_id: Id(file_id),
        version: 1,
        dek_commit: bogus.commit(),
        recipient_id: Id(erin.user_id),
        recipient_enc_pub: EncPublicKey::from_bytes(erin.enc_pub),
        suite: Suite::V1,
        recipient_mlkem_pub: None,
        created_at: Timestamp(TS),
    };
    let w = build_reshare(&params, &bogus, &empty_tombstones()).unwrap();
    let (post_st, _) = post(
        &mut fx.conn,
        &format!("/v1/files/{fid_hex}/wraps"),
        Some(&mallory_token),
        wrap_body(&w),
    )
    .await;
    assert_eq!(
        post_st,
        StatusCode::NOT_FOUND,
        "server refuses a non-holder's wrap"
    );

    // GATE: erin never gained access, and no Reshare edge was recorded.
    assert!(!fx.recipients_of(file_id).await.contains(&erin_id));
    assert!(!fx
        .audit
        .edges()
        .iter()
        .any(|e| e.action == GrantAction::Reshare));
    fx.cleanup();
}

// ============================================================================
// Scenario 8 — GrantAction::Reshare audit edge asserted via MemoryAuditSink
// ============================================================================
#[tokio::test]
async fn scenario8_reshare_audit_edge_recorded() {
    let mut fx = Fixture::boot().await;
    let (file_id, _content) = fx.upload_image(false).await;
    let dek = fx.recover_owner_dek(file_id).await;
    let tombstones = TombstoneSet::verify(&[], fx.anchored_head().await).unwrap();
    let (_carol, carol_id, _ct) = enroll(
        &mut fx.conn,
        &fx.dir_signer,
        &mut fx.ctr,
        "carol",
        &[Role::User],
        false,
    )
    .await;

    let out = reshare_batch(
        &mut fx.conn,
        &fx.owner_token,
        &hex(&file_id),
        file_id,
        1,
        dek.commit(),
        Suite::V1,
        &fx.owner,
        fx.owner_id,
        &dek,
        &tombstones,
        fx.pinned,
        &["carol"],
    )
    .await;
    assert!(out[0].ok);

    // GATE: the server emitted exactly one Reshare grant edge owner→carol.
    let reshare_edges: Vec<_> = fx
        .audit
        .edges()
        .into_iter()
        .filter(|e| e.action == GrantAction::Reshare)
        .collect();
    assert_eq!(
        reshare_edges.len(),
        1,
        "one Reshare edge: {reshare_edges:?}"
    );
    let e = &reshare_edges[0];
    assert_eq!(e.file_id, file_id);
    assert_eq!(
        e.granted_by, fx.owner_id,
        "granted_by is the resharer (owner)"
    );
    assert_eq!(e.recipient_id, carol_id);
    fx.cleanup();
}
