//! Native `stream://` range-protocol end-to-end test, over REAL loopback TLS.
//!
//! `range_streaming_reassembles_plaintext_over_real_tls` proves the shipping VIEW
//! path end-to-end: upload synthetic high-entropy content, register a `VideoJob`,
//! stream it back through `commands::video::serve_range` in bounded windows,
//! reassemble, and assert byte-exact equality with the original plaintext (plus
//! cache-hit and ciphertext-at-rest invariants). It drives the **real**
//! `client-app` modules — `upload::run_pipeline`, `download::{parse_file_view,
//! build_stream_header}`, `directory::{resolve_and_verify_author,
//! resolve_my_user_id}`, the `client-core` `verify_and_open_headers`/
//! `open_content_decryptor` header ladder, and `video::{parse_fragment_index,
//! chunks_for_fragment,feed_fragment}` — over a live connection to the secret-free
//! server (`MemoryStore` + `FsBlobStore`, no Postgres). No ffmpeg / worker binary
//! dependency; this test always runs.
//!
//! The retired confined-decode headline test (author transcode + upload + the OLD
//! decode-and-emit view/seek/back-seek path over `VideoSessionDecoder::run_session`)
//! was removed once native `<video>` (WebView2) became the shipping viewer — see
//! the Task-2 cleanup. The forged-author invariant that test also covered is still
//! exercised by the unit test `core_fails_closed_for_a_forged_author` in
//! `commands/video.rs`.

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

use maxsecu_ceremony_harness::Ceremony;
use maxsecu_client_app::directory::{
    resolve_and_verify_author, resolve_my_user_id, resolve_recovery_recipient,
};
use maxsecu_client_app::download::{build_stream_header, parse_file_view};
use maxsecu_client_app::fragment_cache::FragmentCache;
use maxsecu_client_app::upload::run_pipeline;
use maxsecu_client_app::video::parse_fragment_index;
use maxsecu_client_core::{
    build_upload, open_content_decryptor, verify_and_open_headers, DirectoryVerifier, Identity,
    MemoryTrustStore, PlaintextStreams, StreamHeader, UploadParams, VerifyContext, NO_ADMINS,
    NO_GRANTERS,
};
use maxsecu_crypto::{sha256, EncPublicKey};
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{FileType, Id, RecipientType, Role, StreamType, Timestamp};
use maxsecu_encoding::{decode, labels};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
};

const VOUCHER: &str = "in-person-code-001";
const VOUCHER2: &str = "in-person-code-002";
const TS: u64 = 1_719_500_000_000;
const CHUNK: usize = 4096; // synthetic range test's self-consistent chunk size

// ---- TLS harness (copied from upload_e2e.rs / video_upload_e2e.rs) ----------

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

async fn register_and_login(
    c: &mut Conn,
    owner: &Identity,
    username: &str,
    voucher: &str,
) -> ([u8; 16], String) {
    let (st, res) = post(
        c,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(owner.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(owner.sig_pub_bytes()),
            "enrollment_voucher": voucher,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "registration over TLS");
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
        use maxsecu_encoding::structs::AuthProofContext;
        use maxsecu_encoding::types::{Bytes32, Text};
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
    assert_eq!(st, StatusCode::OK, "login over the bound channel");
    (user_id, res["session_token"].as_str().unwrap().to_owned())
}

async fn publish_binding(
    c: &mut Conn,
    ceremony: &Ceremony,
    username: &str,
    uid: [u8; 16],
    id: &Identity,
) {
    let pb = ceremony.sign_binding(
        username,
        uid,
        id.enc_pub_bytes(),
        id.sig_pub_bytes(),
        &[Role::User],
        1,
    );
    let (st, _) = post(
        c,
        "/v1/directory",
        None,
        serde_json::json!({
            "binding_b64": B64.encode(&pb.binding_bytes),
            "directory_signature_b64": B64.encode(pb.signature),
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "publish binding {username}");
}

/// Task 6 headline: the `stream://` range protocol proves end-to-end over REAL TLS —
/// upload synthetic high-entropy content, register a `VideoJob`, stream it back in
/// 50 KiB windows via `serve_range`, reassemble, and assert (1) byte-exact equality
/// with the original plaintext, (2) the Content-Range denominator is the plaintext
/// length, (3) a cache re-read is byte-identical, (4) the on-disk ciphertext never
/// contains the plaintext. ALWAYS RUNS — no ffmpeg / worker binary dependency.
#[tokio::test]
async fn range_streaming_reassembles_plaintext_over_real_tls() {
    // ---- Synthetic high-entropy content spanning MANY chunks + SEVERAL fragments ----
    // 41 content chunks: 40 full (4096 B each) + 1 partial (1000 B). Non-chunk-aligned
    // tail ensures the range plan handles partial last-chunk correctly.
    let content_len = 40 * CHUNK + 1000;
    let mut content = Vec::with_capacity(content_len);
    while content.len() < content_len {
        let arr = maxsecu_crypto::random_array::<32>();
        content.extend_from_slice(&arr);
    }
    content.truncate(content_len);

    // Fragment index: 5 fragments covering [0,10), [10,20), [20,30), [30,40), [40,41).
    // Satisfies parse_fragment_index's contract: contiguous seq, non-decreasing pts_ms,
    // chunk_len >= 1, chunk_start contiguous from 0, covers all 41 chunks exactly once.
    let total_chunks = (content_len as u64).div_ceil(CHUNK as u64); // == 41
    let mut frags_json = Vec::new();
    let mut cs = 0u64;
    let mut seq = 0u32;
    while cs < total_chunks {
        let cl = 10u64.min(total_chunks - cs);
        frags_json.push(serde_json::json!({
            "seq": seq,
            "pts_ms": (seq as u64) * 1000,
            "chunk_start": cs,
            "chunk_len": cl
        }));
        cs += cl;
        seq += 1;
    }
    let frag_count = frags_json.len();
    let metadata_json = serde_json::json!({
        "title": "range clip",
        "tags": [],
        "fragments": frags_json
    });
    let streams = PlaintextStreams {
        content: content.clone(),
        metadata: Some(serde_json::to_vec(&metadata_json).unwrap()),
        thumbnail: None,
        preview: None,
    };

    // ---- Server boot (verbatim from phase7_video_author_to_view_over_real_tls) ----
    let ceremony = Ceremony::generate();
    let pinned = ceremony.directory_pub();
    let blob_dir = std::env::temp_dir().join(format!(
        "mxrangeblob_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let store = MemoryStore::new();
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    store.add_voucher(sha256(VOUCHER2.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(
            store,
            AuthConfig::default().with_directory_pub(pinned),
        )),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
        audit: Arc::new(maxsecu_server::NullAuditSink),
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
    let mut c = connect(addr, pki.client_config.clone()).await;

    // ---- Author + recovery: register, login, publish D5 bindings ----
    let owner = Identity::generate();
    let (user_id, token) = register_and_login(&mut c, &owner, "alice", VOUCHER).await;
    publish_binding(&mut c, &ceremony, "alice", user_id, &owner).await;
    let recovery = Identity::generate();
    let (recovery_uid, _rt) = register_and_login(&mut c, &recovery, "recovery-1", VOUCHER2).await;
    publish_binding(&mut c, &ceremony, "recovery-1", recovery_uid, &recovery).await;

    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let rr = resolve_recovery_recipient(
        &mut c.sender,
        "localhost",
        "recovery-1",
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();

    // ---- Upload the synthetic video ----
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let fid_hex = hex(&file_id.0);
    let bundle = build_upload(
        &UploadParams {
            owner: &owner,
            owner_id: Id(user_id),
            owner_key_version: 1,
            file_id,
            file_type: FileType::Video,
            chunk_size: 4096,
            recovery_pub: EncPublicKey::from_bytes(rr.enc_pub),
            recovery_mlkem_pub: rr.mlkem_pub,
            created_at: Timestamp(TS),
        },
        &streams,
    )
    .unwrap();
    run_pipeline(&mut c.sender, "localhost", &token, &bundle, |_d, _t| {})
        .await
        .expect("range test: video upload pipeline succeeds");

    // ---- Build the VideoJob (mirror GATE 3 a-d from the phase7 test) ----
    let (st, view_json) = get_json(
        &mut c,
        &format!("/v1/files/{fid_hex}?version=latest"),
        &token,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "range test: file view fetch");
    let view = parse_file_view(&view_json).unwrap();
    let manifest: Manifest = decode(&view.manifest_bytes).expect("manifest decodes");

    // (b) D5-verify the author BEFORE any decode.
    let author = resolve_and_verify_author(
        &mut c.sender,
        "localhost",
        &hex(&manifest.author_id.0),
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();
    let my_id = resolve_my_user_id(
        &mut c.sender,
        "localhost",
        "alice",
        &verifier,
        &mut trust,
        TS,
    )
    .await
    .unwrap();

    // (c) Header (small streams only — no content fetched here).
    let header: StreamHeader =
        build_stream_header(&mut c.sender, "localhost", &token, &fid_hex, &view)
            .await
            .unwrap();

    // (d) TCB header ladder: verify, parse authenticated fragment index, derive decryptor.
    let ctx = VerifyContext {
        file_id,
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: owner.enc_secret(),
        recipient_mlkem_seed: None,
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    };
    let opened = verify_and_open_headers(&ctx, &header).expect("range test: header ladder opens");
    let meta = opened
        .small_streams
        .iter()
        .find(|s| s.stream_type == StreamType::Metadata)
        .expect("metadata small stream present");
    let meta_json: serde_json::Value = serde_json::from_slice(&meta.plaintext).unwrap();
    let index = parse_fragment_index(&meta_json).expect("range test: fragment index parses");
    assert_eq!(
        index.len(),
        frag_count,
        "range test: fragment index has {} entries",
        frag_count
    );
    let decryptor = open_content_decryptor(&ctx, &header).expect("range test: content decryptor");
    let version = decryptor.version();

    // (e) On-disk ciphertext fragment cache.
    let cache_dir = std::env::temp_dir().join(format!(
        "mxrangecache_{}",
        hex(&maxsecu_crypto::random_array::<8>())
    ));
    let cache = FragmentCache::open(&cache_dir, 8 * 1024 * 1024).unwrap();

    // Register the VideoJob: decryptor, authenticated index, empty cache.
    // total_len = content_len: the last chunk has 1000 plaintext bytes (no padding),
    // so (41-1)*4096 + 1000 == content_len exactly.
    //
    // Build the persistent authed channel from the harness connection (c.sender is
    // not used after build_stream_header above). All serve_range calls serialize over
    // this one HTTP/1.1 connection instead of re-authing per range.
    let channel = std::sync::Arc::new(tokio::sync::Mutex::new(
        maxsecu_client_app::jobs::AuthedChannel {
            sender: c.sender,          // MOVE — c.sender not used after this point
            host: "localhost".to_string(),
            token: token.clone(),
        },
    ));
    let jobs = maxsecu_client_app::jobs::VideoJobs::new();
    jobs.0.lock().await.insert(
        fid_hex.clone(),
        maxsecu_client_app::jobs::VideoJob {
            decryptor,
            index,
            cache,
            file_id_hex: fid_hex.clone(),
            version,
            chunk_size: 4096u64,
            total_len: content_len as u64,
            channel: Some(channel),
        },
    );

    // ===================================================================
    // ASSERT 1 + 2: stream + reassemble — 50,000-byte windows crossing chunk
    // AND fragment boundaries. Each window is one serve_range call; the loop
    // walks the full content_len and assembles the slices in order.
    // ===================================================================
    let mut assembled: Vec<u8> = Vec::new();
    let mut off = 0u64;
    loop {
        let r = maxsecu_client_app::commands::video::serve_range(
            &jobs,
            &fid_hex,
            off,
            Some(off + 50_000 - 1),
        )
        .await
        .expect("serve_range: window served without error");
        assert_eq!(
            r.total_len,
            content_len as u64,
            "ASSERT 2: Content-Range denominator equals the plaintext length"
        );
        assembled.extend_from_slice(&r.body);
        off += r.len;
        if off >= r.total_len {
            break;
        }
    }
    assert_eq!(
        assembled, content,
        "ASSERT 1: reassembled ranges are byte-for-byte equal to the original content plaintext"
    );

    // ===================================================================
    // ASSERT 3: cache-hit re-read — same bytes, no server interaction needed
    // because all 41 chunks are already cached after the full forward pass.
    // ===================================================================
    let again = maxsecu_client_app::commands::video::serve_range(
        &jobs,
        &fid_hex,
        0,
        Some(9999),
    )
    .await
    .unwrap();
    assert_eq!(
        again.body,
        content[0..10000],
        "ASSERT 3: re-read of a cached range returns identical plaintext bytes"
    );

    // ===================================================================
    // ASSERT 4: ciphertext-only on disk — fragment 0's cached blob is opaque
    // ciphertext; the plaintext (content[0..10*CHUNK]) never appears in it.
    // ===================================================================
    let f0_bytes = 10 * CHUNK; // fragment 0 covers 10 chunks = 40960 B of plaintext
    let plaintext0 = &content[0..f0_bytes];
    let cached0 = {
        let mut g = jobs.0.lock().await;
        let job = g.get_mut(&fid_hex).unwrap();
        job.cache.get(&fid_hex, 0)
    }
    .expect("ASSERT 4: fragment 0 ciphertext is cached after the full forward pass");
    assert_ne!(
        cached0.as_slice(),
        plaintext0,
        "ASSERT 4: the cached blob is not the plaintext"
    );
    assert!(
        !cached0
            .windows(plaintext0.len().max(1))
            .any(|w| w == plaintext0),
        "ASSERT 4: the plaintext never appears as a subslice in the at-rest ciphertext blob"
    );

    let _ = std::fs::remove_dir_all(&blob_dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}
