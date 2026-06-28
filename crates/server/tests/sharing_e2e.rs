//! Phase-4 exit-gate end-to-end test (DESIGN §17 Phase 4, §12.4b/§12.5/§12.9).
//!
//! Drives the **real stack** over loopback TLS through the full multi-recipient
//! sharing lifecycle, proving the served-interface Phase-4 gates:
//!
//! - **online re-share** (§12.4b): the owner re-shares read to V; V downloads and
//!   decrypts (its grant chains directly to the author);
//! - **multi-hop ancestor chain** (§12.5): V re-shares to W; W downloads, the
//!   server serves W's leaf grant + the ancestor grant chain, and W verifies the
//!   chain to the author and decrypts;
//! - **carry-forward across rotation** (§12.9): the owner fetches the recipient
//!   set, rotates to a fresh DEK, carries V and W forward (re-rooted under the new
//!   author), and W decrypts the new version under DEK';
//! - **soft-revoke** (§12.8): the owner soft-revokes V; V's record then 404s;
//! - **forged ancestor chain** is rejected on download (fail closed).
//!
//! Each user holds its own channel-bound session (its own TLS connection).

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

use maxsecu_client_core::{
    build_next_version, build_reshare, build_upload, verify_and_open, CarryForwardCandidate,
    DownloadBundle, DownloadError, Identity, PlaintextStreams, ReshareParams, RotateParams,
    RotationBundle, StreamChunks, TombstoneSet, UploadBundle, UploadParams, VerifyContext,
    NO_GRANTERS,
};
use maxsecu_crypto::{generate_enc_keypair, sha256, unwrap_dek, Dek, EncPublicKey, WrappedDek};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::{FileType, Id, RecipientType, StreamType, Timestamp};
use maxsecu_encoding::{encode, GENESIS_HEAD};
use maxsecu_server::{
    export_channel_binding, serve, AppState, AuthConfig, AuthService, FsBlobStore, MemoryStore,
    NullAuditSink,
};

const TS: u64 = 1_719_500_000_000;
const CONTENT: &[u8] = b"PHASE4_SHARED_SECRET_payload_that_must_decrypt_for_every_reader";

// ---- TLS harness (mirrors file_e2e.rs) ----

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

async fn put_raw(conn: &mut Conn, uri: &str, auth: &str, body: Vec<u8>) -> StatusCode {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("host", "localhost")
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    conn.sender.send_request(req).await.unwrap().status()
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
    let bytes = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, bytes)
}

async fn delete(conn: &mut Conn, uri: &str, auth: &str) -> StatusCode {
    conn.sender.ready().await.unwrap();
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("MaxSecu-Session {auth}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    conn.sender.send_request(req).await.unwrap().status()
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

fn stream_name(st: StreamType) -> &'static str {
    match st {
        StreamType::Content => "content",
        StreamType::Metadata => "metadata",
        StreamType::Thumbnail => "thumbnail",
        StreamType::Preview => "preview",
    }
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

fn wrap_bytes(w: &WrappedDek) -> Vec<u8> {
    let mut v = w.enc.to_vec();
    v.extend_from_slice(&w.ct);
    v
}
fn wrap_from_bytes(b: &[u8]) -> WrappedDek {
    WrappedDek {
        enc: b[..32].try_into().unwrap(),
        ct: b[32..].to_vec(),
    }
}

// ---- enrollment + sharing helpers ----

async fn register(conn: &mut Conn, username: &str, voucher: &str, id: &Identity) -> [u8; 16] {
    let (st, res) = post(
        conn,
        "/v1/users",
        None,
        serde_json::json!({
            "username": username,
            "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
            "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
            "enrollment_voucher": voucher,
        }),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register {username}");
    hex16(res["user_id"].as_str().unwrap())
}

async fn login(conn: &mut Conn, username: &str, id: &Identity) -> String {
    let (_st, ch) = post(
        conn,
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
        use maxsecu_encoding::types::{Bytes32, Text};
        let ctx = AuthProofContext {
            server_id: Text::new(&server_id).unwrap(),
            tls_exporter: Bytes32(conn.exporter),
            nonce: Bytes32(nonce),
            timestamp: Timestamp(TS),
        };
        B64.encode(id.signing_key().sign_canonical(labels::AUTH, &ctx))
    };
    let (st, res) = post(
        conn,
        "/v1/session/proof",
        None,
        serde_json::json!({"username": username, "timestamp": TS, "proof_b64": proof}),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login {username}");
    res["session_token"].as_str().unwrap().to_owned()
}

fn wrap_json(w: &maxsecu_client_core::WrapOut) -> serde_json::Value {
    let rid = if w.recipient_type == RecipientType::Recovery {
        "recovery".to_owned()
    } else {
        hex(&w.recipient_id.0)
    };
    serde_json::json!({
        "recipient_id": rid,
        "recipient_type": if w.recipient_type == RecipientType::Recovery { "recovery" } else { "user" },
        "wrapped_dek_b64": B64.encode(wrap_bytes(&w.wrapped_dek)),
        "wrap_alg": 1,
        "granted_by": hex(&w.granted_by.0),
        "grant_b64": B64.encode(encode(&w.grant)),
        "grant_sig_b64": B64.encode(w.grant_sig),
    })
}

fn stream_specs(streams: &[maxsecu_client_core::SealedStreamOut]) -> Vec<serde_json::Value> {
    streams
        .iter()
        .map(|s| {
            serde_json::json!({
                "stream_type": stream_name(s.stream_type),
                "chunk_count": s.chunk_count,
                "chunk_size": s.chunk_size,
                "total_bytes": s.total_bytes,
            })
        })
        .collect()
}

/// PUT every ciphertext chunk for a version, then finalize.
async fn upload_chunks_and_finalize(
    conn: &mut Conn,
    token: &str,
    file_hex: &str,
    version: u64,
    streams: &[maxsecu_client_core::SealedStreamOut],
) {
    for s in streams {
        for (i, chunk) in s.chunks.iter().enumerate() {
            let uri = format!(
                "/v1/files/{file_hex}/versions/{version}/streams/{}/chunks/{i}",
                stream_name(s.stream_type)
            );
            assert_eq!(put_raw(conn, &uri, token, chunk.clone()).await, StatusCode::OK);
        }
    }
    let (st, _) = post(
        conn,
        &format!("/v1/files/{file_hex}/versions/{version}/finalize"),
        Some(token),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize v{version}");
}

/// Fetch a downloader's records + chunks and rebuild a [`DownloadBundle`].
async fn fetch_bundle(conn: &mut Conn, token: &str, file_hex: &str, version: u64) -> DownloadBundle {
    let (st, rec) =
        get_json(conn, &format!("/v1/files/{file_hex}?version={version}"), token).await;
    assert_eq!(st, StatusCode::OK, "GET file v{version}");
    let mut dl_streams = Vec::new();
    for s in rec["streams"].as_array().unwrap() {
        let st_name = s["stream_type"].as_str().unwrap();
        let count = s["chunk_count"].as_u64().unwrap();
        let mut chunks = Vec::new();
        for i in 0..count {
            let uri = format!("/v1/files/{file_hex}/versions/{version}/streams/{st_name}/chunks/{i}");
            let (cs, bytes) = get_raw(conn, &uri, token).await;
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
    let ancestor_grants = mw["ancestor_grants"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|g| (dec(&g["grant_b64"]), dec64(&g["grant_sig_b64"])))
                .collect()
        })
        .unwrap_or_default();
    DownloadBundle {
        manifest_bytes: dec(&rec["manifest_b64"]),
        manifest_sig: dec64(&rec["manifest_sig_b64"]),
        genesis_bytes: dec(&rec["genesis_b64"]),
        genesis_sig: dec64(&rec["genesis_sig_b64"]),
        wrapped_dek: wrap_from_bytes(&dec(&mw["wrapped_dek_b64"])),
        grant_bytes: dec(&mw["grant_b64"]),
        grant_sig: dec64(&mw["grant_sig_b64"]),
        ancestor_grants,
        recovery_grant_bytes: dec(&rg["grant_b64"]),
        recovery_grant_sig: dec64(&rg["grant_sig_b64"]),
        streams: dl_streams,
    }
}

fn small_streams() -> PlaintextStreams {
    PlaintextStreams {
        content: CONTENT.to_vec(),
        metadata: Some(b"title=shared".to_vec()),
        thumbnail: None,
        preview: None,
    }
}

fn empty_tombstones() -> TombstoneSet {
    TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap()
}

/// Recover a version's DEK from a recipient's own wrap.
fn unwrap_self(secret: &maxsecu_crypto::EncSecretKey, w: &WrappedDek, file: Id, version: u64, rid: Id) -> Dek {
    let ctx = WrapContext { file_id: file, version, recipient_id: rid };
    unwrap_dek(secret, w, &ctx).unwrap()
}

#[tokio::test]
async fn phase4_sharing_exit_gates_over_real_tls() {
    let blob_dir = std::env::temp_dir().join(format!("mxs4_{}", hex(&maxsecu_crypto::random_array::<8>())));
    let store = MemoryStore::new();
    for code in ["v-alice", "v-bob", "v-carol"] {
        store.add_voucher(sha256(code.as_bytes()));
    }
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(FsBlobStore::new(&blob_dir)),
        audit: Arc::new(NullAuditSink),
    };
    let pki = test_pki();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, pki.server_config.clone(), maxsecu_server::router(state)));

    // Three parties, each on its own channel-bound connection.
    let mut c_owner = connect(addr, pki.client_config.clone()).await;
    let mut c_v = connect(addr, pki.client_config.clone()).await;
    let mut c_w = connect(addr, pki.client_config.clone()).await;
    let owner = Identity::generate();
    let v = Identity::generate();
    let w = Identity::generate();
    let owner_id = register(&mut c_owner, "alice", "v-alice", &owner).await;
    let v_id = register(&mut c_owner, "bob", "v-bob", &v).await;
    let w_id = register(&mut c_owner, "carol", "v-carol", &w).await;
    let owner_tok = login(&mut c_owner, "alice", &owner).await;
    let v_tok = login(&mut c_v, "bob", &v).await;
    let w_tok = login(&mut c_w, "carol", &w).await;

    // ---- Owner uploads v1 ----
    let file_id = Id(maxsecu_crypto::random_array::<16>());
    let file_hex = hex(&file_id.0);
    let (_rsk, recovery_pub) = generate_enc_keypair();
    let params = UploadParams {
        owner: &owner,
        owner_id: Id(owner_id),
        owner_key_version: 1,
        file_id,
        file_type: FileType::Blog,
        chunk_size: 4096,
        recovery_pub,
        created_at: Timestamp(TS),
    };
    let bundle: UploadBundle = build_upload(&params, &small_streams()).unwrap();
    let body = serde_json::json!({
        "file_id": file_hex,
        "file_type": "blog",
        "genesis_b64": B64.encode(encode(&bundle.genesis)),
        "genesis_sig_b64": B64.encode(bundle.genesis_sig),
        "manifest_b64": B64.encode(encode(&bundle.manifest)),
        "manifest_sig_b64": B64.encode(bundle.manifest_sig),
        "streams": stream_specs(&bundle.streams),
        "wraps": bundle.wraps.iter().map(wrap_json).collect::<Vec<_>>(),
    });
    let (st, _) = post(&mut c_owner, "/v1/files", Some(&owner_tok), body).await;
    assert_eq!(st, StatusCode::CREATED, "stage v1");
    upload_chunks_and_finalize(&mut c_owner, &owner_tok, &file_hex, 1, &bundle.streams).await;

    let dek_commit = bundle.manifest.dek_commit.0;
    let owner_wrap = bundle.wraps.iter().find(|x| x.recipient_type == RecipientType::User).unwrap();
    let dek = unwrap_self(owner.enc_secret(), &owner_wrap.wrapped_dek, file_id, 1, Id(owner_id));

    // ---- GATE: online re-share owner → V; V downloads + decrypts ----
    let to_v = build_reshare(
        &ReshareParams {
            granter: &owner,
            granter_id: Id(owner_id),
            file_id,
            version: 1,
            dek_commit,
            recipient_id: Id(v_id),
            recipient_enc_pub: EncPublicKey::from_bytes(v.enc_pub_bytes()),
            created_at: Timestamp(TS),
        },
        &dek,
        &empty_tombstones(),
    )
    .unwrap();
    let (st, _) = post(
        &mut c_owner,
        &format!("/v1/files/{file_hex}/wraps"),
        Some(&owner_tok),
        wrap_json(&to_v),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "re-share to V");

    let v_bundle = fetch_bundle(&mut c_v, &v_tok, &file_hex, 1).await;
    let v_ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(v_id),
        recipient_type: RecipientType::User,
        recipient_secret: v.enc_secret(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS, // V's grant is author-rooted
    };
    let opened = verify_and_open(&v_ctx, &v_bundle).expect("V opens the re-shared file");
    assert_eq!(
        opened.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap().plaintext,
        CONTENT
    );

    // ---- GATE: V re-shares to W; W downloads, the ancestor chain verifies ----
    let dek_v = unwrap_self(v.enc_secret(), &v_bundle.wrapped_dek, file_id, 1, Id(v_id));
    let to_w = build_reshare(
        &ReshareParams {
            granter: &v,
            granter_id: Id(v_id),
            file_id,
            version: 1,
            dek_commit,
            recipient_id: Id(w_id),
            recipient_enc_pub: EncPublicKey::from_bytes(w.enc_pub_bytes()),
            created_at: Timestamp(TS),
        },
        &dek_v,
        &empty_tombstones(),
    )
    .unwrap();
    let (st, _) = post(
        &mut c_v,
        &format!("/v1/files/{file_hex}/wraps"),
        Some(&v_tok),
        wrap_json(&to_w),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "V re-shares to W");

    let w_bundle = fetch_bundle(&mut c_w, &w_tok, &file_hex, 1).await;
    assert_eq!(w_bundle.ancestor_grants.len(), 1, "server served V's ancestor grant");
    let v_pub = v.sig_pub_bytes();
    let resolver = move |id: Id| (id == Id(v_id)).then_some(v_pub);
    let w_ctx = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(w_id),
        recipient_type: RecipientType::User,
        recipient_secret: w.enc_secret(),
        seen_max_version: None,
        granter_sig_pub: &resolver,
    };
    let opened = verify_and_open(&w_ctx, &w_bundle).expect("W opens via the ancestor chain");
    assert_eq!(
        opened.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap().plaintext,
        CONTENT
    );

    // ---- GATE: a forged ancestor grant is rejected on download ----
    let mut tampered = clone_bundle(&w_bundle);
    tampered.ancestor_grants[0].1[0] ^= 0x01;
    assert_eq!(
        verify_and_open(&w_ctx, &tampered),
        Err(DownloadError::GrantSignature)
    );

    // ---- GATE: rotation carries V and W forward under a fresh DEK ----
    let (st, recips) = get_json(
        &mut c_owner,
        &format!("/v1/files/{file_hex}/recipients"),
        &owner_tok,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "owner reads recipients");
    let enc_for = |id: [u8; 16]| -> EncPublicKey {
        if id == v_id {
            EncPublicKey::from_bytes(v.enc_pub_bytes())
        } else if id == w_id {
            EncPublicKey::from_bytes(w.enc_pub_bytes())
        } else {
            EncPublicKey::from_bytes(owner.enc_pub_bytes())
        }
    };
    let dec = |s: &str| B64.decode(s).unwrap();
    let dec64 = |s: &str| -> [u8; 64] { dec(s).try_into().unwrap() };
    let candidates: Vec<CarryForwardCandidate> = recips["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| hex16(r["recipient_id"].as_str().unwrap()) != owner_id)
        .map(|r| {
            let rid = hex16(r["recipient_id"].as_str().unwrap());
            let ancestors = r["ancestor_grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| (dec(g["grant_b64"].as_str().unwrap()), dec64(g["grant_sig_b64"].as_str().unwrap())))
                .collect();
            CarryForwardCandidate {
                recipient_id: Id(rid),
                recipient_enc_pub: enc_for(rid),
                leaf_grant_bytes: dec(r["grant_b64"].as_str().unwrap()),
                leaf_grant_sig: dec64(r["grant_sig_b64"].as_str().unwrap()),
                ancestor_grants: ancestors,
            }
        })
        .collect();
    assert_eq!(candidates.len(), 2, "V and W are carry-forward candidates");

    let cf_resolver = move |id: Id| (id == Id(v_id)).then_some(v_pub);
    let (_rsk2, recovery_pub2) = generate_enc_keypair();
    let rot: RotationBundle = build_next_version(
        &RotateParams {
            owner: &owner,
            owner_id: Id(owner_id),
            file_id,
            file_type: FileType::Blog,
            new_version: 2,
            chunk_size: 4096,
            recovery_pub: recovery_pub2,
            created_at: Timestamp(TS + 1),
            prior_version: 1,
            prior_dek_commit: dek_commit,
            prior_author_id: Id(owner_id),
            prior_author_sig_pub: owner.sig_pub_bytes(),
        },
        &small_streams(),
        &dek,
        &candidates,
        &empty_tombstones(),
        &cf_resolver,
    )
    .unwrap();
    // owner + recovery + V + W.
    assert_eq!(rot.wraps.len(), 4);

    let rot_body = serde_json::json!({
        "file_type": "blog",
        "manifest_b64": B64.encode(encode(&rot.manifest)),
        "manifest_sig_b64": B64.encode(rot.manifest_sig),
        "streams": stream_specs(&rot.streams),
        "wraps": rot.wraps.iter().map(wrap_json).collect::<Vec<_>>(),
    });
    let (st, _) = post(
        &mut c_owner,
        &format!("/v1/files/{file_hex}/versions"),
        Some(&owner_tok),
        rot_body,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "stage v2");
    upload_chunks_and_finalize(&mut c_owner, &owner_tok, &file_hex, 2, &rot.streams).await;

    // W reads v2 under DEK' — its grant is now re-rooted under the owner.
    let w_v2 = fetch_bundle(&mut c_w, &w_tok, &file_hex, 2).await;
    assert!(w_v2.ancestor_grants.is_empty(), "carry-forward re-rooted W's grant");
    let w_ctx2 = VerifyContext {
        file_id,
        author_sig_pub: owner.sig_pub_bytes(),
        owner_sig_pub: owner.sig_pub_bytes(),
        recipient_id: Id(w_id),
        recipient_type: RecipientType::User,
        recipient_secret: w.enc_secret(),
        seen_max_version: Some(1),
        granter_sig_pub: &NO_GRANTERS,
    };
    let opened2 = verify_and_open(&w_ctx2, &w_v2).expect("W opens v2 under the rotated DEK");
    assert_eq!(opened2.version, 2);
    assert_eq!(
        opened2.streams.iter().find(|s| s.stream_type == StreamType::Content).unwrap().plaintext,
        CONTENT
    );

    // ---- GATE: soft-revoke V → V's record 404s ----
    let revoke_uri = format!("/v1/files/{file_hex}/wraps/{}", hex(&v_id));
    assert_eq!(delete(&mut c_owner, &revoke_uri, &owner_tok).await, StatusCode::NO_CONTENT);
    let (st, _) = get_json(&mut c_v, &format!("/v1/files/{file_hex}?version=2"), &v_tok).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "soft-revoked V can no longer fetch");
}

/// `DownloadBundle` is not `Clone`; rebuild for tampering.
fn clone_bundle(b: &DownloadBundle) -> DownloadBundle {
    DownloadBundle {
        manifest_bytes: b.manifest_bytes.clone(),
        manifest_sig: b.manifest_sig,
        genesis_bytes: b.genesis_bytes.clone(),
        genesis_sig: b.genesis_sig,
        wrapped_dek: b.wrapped_dek.clone(),
        grant_bytes: b.grant_bytes.clone(),
        grant_sig: b.grant_sig,
        ancestor_grants: b.ancestor_grants.clone(),
        recovery_grant_bytes: b.recovery_grant_bytes.clone(),
        recovery_grant_sig: b.recovery_grant_sig,
        streams: b
            .streams
            .iter()
            .map(|s| StreamChunks {
                stream_type: s.stream_type,
                chunks: s.chunks.clone(),
            })
            .collect(),
    }
}
