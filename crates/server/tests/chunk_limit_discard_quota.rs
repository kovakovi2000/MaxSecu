//! Body-limit, owner-discard, and file-size quota integration tests.
//!
//! Tests three server behaviors introduced in the same increment:
//!
//! 1. **8 MiB + 64 KiB `DefaultBodyLimit`** — unblocks streaming 6 MiB chunk
//!    PUTs that the old 2 MiB axum default rejected (Part 1).
//! 2. **`DELETE /v1/files/{file_id}`** — owner-only, append-only-safe discard
//!    of a never-finalized upload (Part 2).
//! 3. **Optional `max_file_bytes` quota** (default `None`) — operator-
//!    configured cap on the declared content stream size (Part 3).
//!
//! Uses the tower-oneshot approach (no TLS) with a fake `EXPORTER` constant,
//! mirroring the `sanitized_errors` test suite pattern.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use axum::Extension;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;
use tower::ServiceExt;

use maxsecu_crypto::{generate_enc_keypair, sha256, SigningKey};
use maxsecu_encoding::encode;
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, Genesis, Manifest, Stream};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileType, Id, StreamType, Suite, Text, Timestamp,
};
use maxsecu_server::{
    router, AppState, AuthConfig, AuthService, MemoryBlobStore, MemoryStore, NullAuditSink,
    TlsExporter,
};

/// Fake TLS-exporter value (all-0xE1). Must match the value used when signing
/// auth-proof challenges in this file.
const EXPORTER: [u8; 32] = [0xE1; 32];
/// Enrollment vouchers pre-seeded into every test router (one per registration).
const VOUCHER: &str = "clq-test-voucher-01";
const VOUCHER2: &str = "clq-test-voucher-02";
const VOUCHER3: &str = "clq-test-voucher-03";
/// Fixed timestamp (ms) used in all auth proofs.
const TS: u64 = 1_719_500_000_000;

// ── Hex helpers ──────────────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// ── Router factory ───────────────────────────────────────────────────────────

fn mk_router_with_quota(quota: Option<u64>) -> axum::Router {
    let store = MemoryStore::new();
    // Pre-seed multiple one-time vouchers (one per user that a test may register).
    store.add_voucher(sha256(VOUCHER.as_bytes()));
    store.add_voucher(sha256(VOUCHER2.as_bytes()));
    store.add_voucher(sha256(VOUCHER3.as_bytes()));
    let state = AppState {
        auth: Arc::new(AuthService::new(store, AuthConfig::default())),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: quota,
    };
    router(state).layer(Extension(TlsExporter(EXPORTER)))
}

fn mk_router() -> axum::Router {
    mk_router_with_quota(None)
}

// ── Request builders ─────────────────────────────────────────────────────────

fn req_json(
    method: &str,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header(AUTHORIZATION, format!("MaxSecu-Session {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn req_put_bytes(uri: &str, bytes: Vec<u8>, token: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
        .body(Body::from(bytes))
        .unwrap()
}

fn req_delete(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
        .body(Body::empty())
        .unwrap()
}

fn req_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(AUTHORIZATION, format!("MaxSecu-Session {token}"))
        .body(Body::empty())
        .unwrap()
}

// ── Send helpers ─────────────────────────────────────────────────────────────

async fn send(
    r: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, serde_json::Value) {
    let resp = r.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

async fn send_status(r: &axum::Router, req: Request<Body>) -> StatusCode {
    r.clone().oneshot(req).await.unwrap().status()
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

fn make_proof(sk: &SigningKey, server_id: &str, nonce: &[u8; 32]) -> String {
    let ctx = AuthProofContext {
        server_id: Text::new(server_id).unwrap(),
        tls_exporter: Bytes32(EXPORTER),
        nonce: Bytes32(*nonce),
        timestamp: Timestamp(TS),
    };
    B64.encode(sk.sign_canonical(labels::AUTH, &ctx))
}

/// Register a user via a one-time enrollment voucher, then log in.
/// `voucher` must be one of the constants pre-seeded in [`mk_router_with_quota`].
/// Returns `(user_id_bytes, session_token)`.
async fn register_and_login(
    r: &axum::Router,
    username: &str,
    sk: &SigningKey,
    voucher: &str,
) -> ([u8; 16], String) {
    let (_, enc_pub) = generate_enc_keypair();
    let (st, res) = send(
        r,
        req_json(
            "POST",
            "/v1/users",
            json!({
                "username": username,
                "enc_pub_b64":  B64.encode(enc_pub.to_bytes()),
                "sig_pub_b64":  B64.encode(sk.verifying_key().to_bytes()),
                "enrollment_voucher": voucher,
            }),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "register {username}");
    let user_id = hex16(res["user_id"].as_str().unwrap());

    let (_, ch) = send(
        r,
        req_json(
            "POST",
            "/v1/session/challenge",
            json!({"username": username}),
            None,
        ),
    )
    .await;
    let nonce: [u8; 32] = B64
        .decode(ch["nonce_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let server_id = ch["server_id"].as_str().unwrap();
    let proof = make_proof(sk, server_id, &nonce);

    let (st, res) = send(
        r,
        req_json(
            "POST",
            "/v1/session/proof",
            json!({"username": username, "timestamp": TS, "proof_b64": proof}),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "login {username}");
    let token = res["session_token"].as_str().unwrap().to_owned();
    (user_id, token)
}

// ── File fixtures ─────────────────────────────────────────────────────────────

/// Build a manifest with a configurable chunk_size and content chunk_count.
/// Metadata is always 1 chunk (same global chunk_size). Sigs are placeholders.
fn manifest_b64(
    file: [u8; 16],
    version: u64,
    owner: [u8; 16],
    chunk_size: u32,
    content_chunk_count: u64,
) -> String {
    let m = Manifest {
        file_id: Id(file),
        version,
        file_type: FileType::Blog,
        alg: Suite::V1,
        chunk_size,
        dek_commit: Bytes32([0xDC; 32]),
        streams: vec![
            Stream {
                stream_type: StreamType::Content,
                compression: Compression::None,
                chunk_count: content_chunk_count,
                digest: Bytes32([0xC0; 32]),
            },
            Stream {
                stream_type: StreamType::Metadata,
                compression: Compression::None,
                chunk_count: 1,
                digest: Bytes32([0x2E; 32]),
            },
        ],
        recovery_present: true,
        author_id: Id(owner),
        created_at: Timestamp(TS),
    };
    B64.encode(encode(&m))
}

fn genesis_b64(file: [u8; 16], owner: [u8; 16]) -> String {
    B64.encode(encode(&Genesis {
        file_id: Id(file),
        owner_id: Id(owner),
        owner_key_version: 1,
        created_at: Timestamp(TS),
    }))
}

fn wraps_json(owner: [u8; 16]) -> serde_json::Value {
    json!([
        {
            "recipient_id":    hex(&owner),
            "recipient_type":  "user",
            "wrapped_dek_b64": B64.encode([0xA1u8; 48]),
            "wrap_alg":        1,
            "granted_by":      hex(&owner),
            "grant_b64":       B64.encode([0xB1u8; 8]),
            "grant_sig_b64":   B64.encode([0xC1u8; 64]),
        },
        {
            "recipient_id":    "recovery",
            "recipient_type":  "recovery",
            "wrapped_dek_b64": B64.encode([0xA2u8; 48]),
            "wrap_alg":        1,
            "granted_by":      hex(&owner),
            "grant_b64":       B64.encode([0xB2u8; 8]),
            "grant_sig_b64":   B64.encode([0xC2u8; 64]),
        },
    ])
}

fn stage_body(
    file: [u8; 16],
    owner: [u8; 16],
    chunk_size: u32,
    content_chunk_count: u64,
    total_content_bytes: u64,
) -> serde_json::Value {
    json!({
        "file_id":          hex(&file),
        "file_type":        "blog",
        "genesis_b64":      genesis_b64(file, owner),
        "genesis_sig_b64":  B64.encode([0x9Au8; 64]),
        "manifest_b64":     manifest_b64(file, 1, owner, chunk_size, content_chunk_count),
        "manifest_sig_b64": B64.encode([0x9Bu8; 64]),
        "streams": [
            {"stream_type": "content",  "total_bytes": total_content_bytes},
            {"stream_type": "metadata", "total_bytes": 256u64},
        ],
        "wraps": wraps_json(owner),
    })
}

fn chunk_uri(file: [u8; 16], version: u64, stream: &str, idx: u64) -> String {
    format!(
        "/v1/files/{}/versions/{version}/streams/{stream}/chunks/{idx}",
        hex(&file)
    )
}

fn file_uri(file: [u8; 16]) -> String {
    format!("/v1/files/{}", hex(&file))
}

/// Stage + PUT every declared chunk + finalize version 1 of a file.
async fn stage_finalize(
    r: &axum::Router,
    file: [u8; 16],
    owner: [u8; 16],
    token: &str,
    chunk_size: u32,
    content_chunk_count: u64,
) {
    let (st, _) = send(
        r,
        req_json(
            "POST",
            "/v1/files",
            stage_body(file, owner, chunk_size, content_chunk_count, 1024),
            Some(token),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "stage");

    for idx in 0..content_chunk_count {
        let st = send_status(
            r,
            req_put_bytes(&chunk_uri(file, 1, "content", idx), vec![0x10u8; 32], token),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "PUT content/{idx}");
    }
    let st = send_status(
        r,
        req_put_bytes(&chunk_uri(file, 1, "metadata", 0), vec![0x10u8; 16], token),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT metadata/0");

    let (st, _) = send(
        r,
        req_json(
            "POST",
            &format!("/v1/files/{}/versions/1/finalize", hex(&file)),
            json!({}),
            Some(token),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "finalize");
}

// ─────────────────────────────────────────────────────────────────────────────
// Part 1 — DefaultBodyLimit: 6 MiB chunk PUT succeeds; >8 MiB+64 KiB → 413
// ─────────────────────────────────────────────────────────────────────────────

/// A 6 MiB chunk PUT succeeds; a body that exceeds the 8 MiB + 64 KiB limit
/// is rejected with 413 Payload Too Large.
#[tokio::test]
async fn chunk_body_limit() {
    const FILE: [u8; 16] = [0xB1; 16];
    // 6 MiB as the manifest chunk_size: within [4 KiB, 8 MiB] and the global
    // DefaultBodyLimit of 8 MiB + 64 KiB.
    const CHUNK_SZ: u32 = 6 * 1024 * 1024;

    let r = mk_router();
    let alice_sk = SigningKey::generate();
    let (alice_id, alice_tok) = register_and_login(&r, "alice_bl", &alice_sk, VOUCHER).await;

    // Stage a file: content = 1 chunk × 6 MiB
    let (st, _) = send(
        &r,
        req_json(
            "POST",
            "/v1/files",
            stage_body(FILE, alice_id, CHUNK_SZ, 1, CHUNK_SZ as u64),
            Some(&alice_tok),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "stage with 6 MiB chunk_size");

    // ── within limit: PUT 6 MiB → 200 OK ────────────────────────────────────
    // The put_chunk body-size check: body.len() <= chunk_size + AEAD_TAG_LEN.
    // DefaultBodyLimit: 6 MiB < 8 MiB + 64 KiB.  Both pass.
    let six_mib = vec![0x5Au8; 6 * 1024 * 1024];
    let st = send_status(
        &r,
        req_put_bytes(&chunk_uri(FILE, 1, "content", 0), six_mib, &alice_tok),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "6 MiB chunk PUT must succeed");

    // ── over limit: 8 MiB + 128 KiB body → 413 ─────────────────────────────
    // Sent to POST /v1/session/challenge (no auth required) so the
    // DefaultBodyLimit fires on the Json extractor before any handler logic.
    // 8 MiB + 128 KiB = 8_519_680 > limit 8 MiB + 64 KiB = 8_454_144.
    let over = vec![0x5Bu8; 8 * 1024 * 1024 + 128 * 1024];
    let st = send_status(
        &r,
        Request::builder()
            .method("POST")
            .uri("/v1/session/challenge")
            .header("content-type", "application/json")
            .body(Body::from(over))
            .unwrap(),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body exceeding 8 MiB + 64 KiB must be 413"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Part 2 — Owner-only discard of never-finalized uploads
// ─────────────────────────────────────────────────────────────────────────────

/// Owner can discard a staged-but-not-finalized upload (204); idempotent on
/// repeat; file is absent (404) after discard.
#[tokio::test]
async fn discard_staged_by_owner_is_204_and_idempotent() {
    const FILE: [u8; 16] = [0xD1; 16];

    let r = mk_router();
    let alice_sk = SigningKey::generate();
    let (alice_id, alice_tok) = register_and_login(&r, "alice_disc", &alice_sk, VOUCHER).await;

    // Stage (no finalize)
    let (st, _) = send(
        &r,
        req_json(
            "POST",
            "/v1/files",
            stage_body(FILE, alice_id, 1 << 20, 2, 2_000_000),
            Some(&alice_tok),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "stage v1");

    // PUT one chunk to exercise blob-reference cleanup on discard
    let st = send_status(
        &r,
        req_put_bytes(&chunk_uri(FILE, 1, "content", 0), vec![0x10u8; 32], &alice_tok),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "PUT content/0");

    // ── discard → 204 ────────────────────────────────────────────────────────
    let st = send_status(&r, req_delete(&file_uri(FILE), &alice_tok)).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "owner discard must be 204");

    // ── file absent: no finalized version → 404 ──────────────────────────────
    let (st, _) = send(&r, req_get(&file_uri(FILE), &alice_tok)).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "discarded file must be 404");

    // ── second discard (no staged version left) → still 204 ──────────────────
    let st = send_status(&r, req_delete(&file_uri(FILE), &alice_tok)).await;
    assert_eq!(
        st,
        StatusCode::NO_CONTENT,
        "repeated discard must be idempotent 204"
    );
}

/// Non-owner DELETE returns 404 (same status as missing — no oracle).
#[tokio::test]
async fn discard_by_non_owner_is_404() {
    const FILE: [u8; 16] = [0xD2; 16];

    let r = mk_router();
    let alice_sk = SigningKey::generate();
    let bob_sk = SigningKey::generate();
    let (alice_id, alice_tok) = register_and_login(&r, "alice_no", &alice_sk, VOUCHER).await;
    let (_bob_id, bob_tok) = register_and_login(&r, "bob_no", &bob_sk, VOUCHER2).await;

    // Alice stages a file
    let (st, _) = send(
        &r,
        req_json(
            "POST",
            "/v1/files",
            stage_body(FILE, alice_id, 1 << 20, 2, 2_000_000),
            Some(&alice_tok),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Bob tries to discard → 404 (no oracle: same as unknown file)
    let st = send_status(&r, req_delete(&file_uri(FILE), &bob_tok)).await;
    assert_eq!(
        st,
        StatusCode::NOT_FOUND,
        "non-owner discard must be 404 (no oracle)"
    );
}

/// DELETE of a finalized file → 409 CONFLICT; the file remains fully accessible.
#[tokio::test]
async fn discard_finalized_is_409_and_file_survives() {
    const FILE: [u8; 16] = [0xD3; 16];

    let r = mk_router();
    let alice_sk = SigningKey::generate();
    let (alice_id, alice_tok) = register_and_login(&r, "alice_fin", &alice_sk, VOUCHER).await;

    // Stage + finalize a complete v1
    stage_finalize(&r, FILE, alice_id, &alice_tok, 1 << 20, 2).await;

    // DELETE → 409 (finalized version blocks discard; append-only invariant)
    let st = send_status(&r, req_delete(&file_uri(FILE), &alice_tok)).await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "discard of finalized file must be 409"
    );

    // The file is still served after the failed discard attempt
    let (st, _) = send(
        &r,
        req_get(&format!("{}?version=latest", file_uri(FILE)), &alice_tok),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::OK,
        "finalized file must still be served after failed discard"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Part 3 — Optional file-size quota (max_file_bytes)
// ─────────────────────────────────────────────────────────────────────────────

/// `None` quota: any declared size stages fine.
/// `Some(cap)`: declared (chunk_count × chunk_size) > cap → 413.
/// `Some(cap)`: declared ≤ cap → 201.
#[tokio::test]
async fn file_size_quota() {
    // ── quota=None → 100 MiB declared stages fine ────────────────────────────
    let r_none = mk_router_with_quota(None);
    let sk = SigningKey::generate();
    let (owner_none, tok_none) = register_and_login(&r_none, "alice_q1", &sk, VOUCHER).await;
    let (st, _) = send(
        &r_none,
        req_json(
            "POST",
            "/v1/files",
            // 1 MiB × 100 chunks = 100 MiB declared content
            stage_body([0xE1; 16], owner_none, 1 << 20, 100, 100 * 1024 * 1024),
            Some(&tok_none),
        ),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "no quota: 100 MiB declared must stage fine"
    );

    // ── quota=Some(1 MiB): declared 2 MiB > cap → 413 ───────────────────────
    let r_small = mk_router_with_quota(Some(1 << 20)); // 1 MiB cap
    let sk2 = SigningKey::generate();
    let (owner_small, tok_small) = register_and_login(&r_small, "alice_q2", &sk2, VOUCHER).await;
    let (st, _) = send(
        &r_small,
        req_json(
            "POST",
            "/v1/files",
            // 1 MiB × 2 chunks = 2 MiB declared > 1 MiB cap
            stage_body([0xE2; 16], owner_small, 1 << 20, 2, 2_000_000),
            Some(&tok_small),
        ),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::PAYLOAD_TOO_LARGE,
        "quota=1 MiB: 2 MiB declared must be 413"
    );

    // ── quota=Some(4 MiB): declared 2 MiB ≤ cap → 201 ───────────────────────
    let r_ok = mk_router_with_quota(Some(4 << 20)); // 4 MiB cap
    let sk3 = SigningKey::generate();
    let (owner_ok, tok_ok) = register_and_login(&r_ok, "alice_q3", &sk3, VOUCHER).await;
    let (st, _) = send(
        &r_ok,
        req_json(
            "POST",
            "/v1/files",
            // 1 MiB × 2 chunks = 2 MiB declared ≤ 4 MiB cap
            stage_body([0xE3; 16], owner_ok, 1 << 20, 2, 2_000_000),
            Some(&tok_ok),
        ),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CREATED,
        "quota=4 MiB: 2 MiB declared must be 201"
    );
}
