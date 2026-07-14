//! **The `/v1` HTTP seam** — surface 10 of the backward-compatibility gate
//! (`docs/superpowers/specs/2026-07-14-backward-compat-gate-design.md` §5).
//!
//! THE RULE: *every upgrade must keep existing users' access intact. No change
//! may force a re-enroll, re-key, re-upload, re-share, or reset.*
//!
//! A client that shipped months ago talks to today's server. Nothing type-checks
//! that seam: every DTO in `crates/server/src/http.rs` is **private**, and the
//! client re-implements the wire by hand with `serde_json::json!`
//! (`client-app/src/{http_client,session,upload,directory}.rs`,
//! `commands/{register,share}.rs`). A field rename on either side compiles
//! cleanly and silently locks users out — that is exactly how the shipped
//! PQ-enrollment bug happened (`2a626d6`: the client never sent
//! `mlkem_pub_b64`, the server had no such field, and every V2 reshare failed
//! `pq_key_missing`).
//!
//! This file closes that hole with three assertions, all driving the **real**
//! `maxsecu_server::router()` in-process over `MemoryStore` (no network, no
//! Postgres, no wall-clock expiry):
//!
//! 1. [`compat_frozen_requests_are_still_accepted`] — every frozen request body
//!    is POSTed **verbatim** at its route and must still be accepted. A newly
//!    *required* field anywhere makes this fail (serde → 422).
//! 2. [`compat_frozen_response_fields_are_still_emitted`] — every live response
//!    must be a recursive **superset** of the frozen one's key structure (same
//!    key, same path, same JSON type). Additive keys are fine; that is the whole
//!    additive-evolution contract.
//! 3. [`compat_route_surface_is_a_superset`] — every `(method, path)` the shipped
//!    client depends on must still dispatch (no `404`/`405`).
//!
//! Plus [`compat_corpus_is_locked`]: the fixtures are ADD-ONLY (`corpus.lock`).
//!
//! ## Replaying one-shot requests
//!
//! `POST /v1/session/proof` carries a signature over a server-minted, single-use
//! nonce. The frozen BODY BYTES are still posted unmodified — the harness
//! reconstructs the minimal state instead, by inserting the frozen nonce
//! (`Store::insert_nonce`, far-future expiry) and the frozen user. Nothing about
//! the request is relaxed: the server verifies the real Ed25519 proof over
//! `canonical(auth_proof_context)` = `(server_id, tls_exporter, nonce, timestamp)`.
//!
//! **One exemption, stated plainly:** the proof is bound to the connection's TLS
//! exporter (RFC 5705), which a live TLS handshake derives per connection and
//! which therefore cannot be frozen. The router takes it from an
//! `Extension<TlsExporter>`, so the harness pins it to a fixed value — the same
//! thing the server's own tests do. Every OTHER field of the frozen proof body
//! (username, timestamp, the signature itself) is verified for real.
//!
//! ## Regenerating
//!
//! Never, for an existing fixture — that is a `corpus.lock` failure by design.
//! To ADD a new one:
//!   cargo test -p maxsecu-compat --test http_wire emit_http_fixtures -- --ignored
//! then review the diff and record it in `docs/compat/LEDGER.md`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

use maxsecu_admin_core::{CoSign, ControlChain, RevokeParams};
use maxsecu_crypto::{
    mlkem_public_from_seed, sha256, sign_delegation, wrap_dek, x25519_public_from_secret, Dek,
    EncPublicKey, SigningKey,
};
use maxsecu_encoding::structs::{
    AuthProofContext, DirBinding, Genesis, Grant, Manifest, Stream, WrapContext,
};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileScope, FileType, Id, MlKemPub, RecipientType, Role, RoleSet,
    StreamType, Suite, Text, Timestamp,
};
use maxsecu_encoding::{encode, labels, RECOVERY_ID};
use maxsecu_server::{
    router, AppState, AuthConfig, AuthService, DelegationCtx, MemoryBlobStore, MemoryStore,
    NullAuditSink, Store, TlsExporter, UserRecord,
};

use maxsecu_compat::CHECKLIST;

// ---------------------------------------------------------------------------
// Frozen constants — the harness's half of the corpus
// ---------------------------------------------------------------------------

const AREA: &str = "http";

/// The per-connection TLS exporter. NOT freezable (a live TLS handshake derives
/// it) — see the module docs' exemption note. Fixed here exactly as the server's
/// own tests fix it.
const EXPORTER: [u8; 32] = [0xE7; 32];

/// `AuthConfig::default().server_id` — the value the frozen login proof signs.
const SERVER_ID: &str = "maxsecu-dev-1";

/// 2100-01-01. Every signed artifact in this corpus is valid until then, so the
/// gate never starts failing because a fixture expired.
const FAR_FUTURE_MS: u64 = 4_102_444_800_000;
const FAR_FUTURE_SECS: u64 = 4_102_444_800;

/// The timestamp inside every frozen signed record (fixed ⇒ deterministic).
const TS_MS: u64 = 1_719_500_000_000;

const ALICE_ID: [u8; 16] = [0x11; 16]; // author / admin / logs in
const BOB_ID: [u8; 16] = [0x22; 16]; // reshare recipient / co-signing admin
const CAROL_ID: [u8; 16] = [0x33; 16]; // subject of the frozen POST /v1/directory
const FILE_ID: [u8; 16] = [0xF1; 16];
/// A SECOND file, staged by the pre-bundles `POST /v1/files` body (no `listed`,
/// no `bundle_id`). Never finalized, so it perturbs nothing else in the flow.
const FILE_ID_2: [u8; 16] = [0xF2; 16];

/// The nonce the frozen `session_proof.req.json` signs over. Re-inserted into
/// the store so the one-shot challenge state can be reconstructed.
const NONCE: [u8; 32] = [0x5A; 32];

/// Single-use registration keys the two frozen `POST /v1/users` bodies present.
const REG_KEY_PQ: &str = "compat-registration-key-pq-v1";
const REG_KEY_CLASSIC: &str = "compat-registration-key-classic-v1";

const CHUNK_SIZE: u32 = 4096;

fn alice_hex() -> String {
    hex::encode(ALICE_ID)
}
fn file_hex() -> String {
    hex::encode(FILE_ID)
}

// ---------------------------------------------------------------------------
// Frozen key material (compat/fixtures/http/keys.testkey.json)
// ---------------------------------------------------------------------------

/// Every key the corpus needs, derived from the frozen seeds. TEST-ONLY.
struct Keys {
    d5: SigningKey,
    d5_pub: [u8; 32],
    alice_sig: SigningKey,
    alice_sig_pub: [u8; 32],
    alice_enc_pub: [u8; 32],
    alice_mlkem_pub: [u8; 1184],
    bob_sig: SigningKey,
    bob_sig_pub: [u8; 32],
    bob_enc_pub: [u8; 32],
    bob_mlkem_pub: [u8; 1184],
    carol_sig_pub: [u8; 32],
    carol_enc_pub: [u8; 32],
    carol_mlkem_pub: [u8; 1184],
    /// The enrollee in `users_register.v2.req.json` (a PQ client).
    newuser_sig_pub: [u8; 32],
    newuser_enc_pub: [u8; 32],
    newuser_mlkem_pub: [u8; 1184],
    /// The enrollee in `users_register.v1_no_mlkem.req.json` (a pre-PQ client).
    olduser_sig_pub: [u8; 32],
    olduser_enc_pub: [u8; 32],
    recovery_sig_pub: [u8; 32],
    recovery_enc_pub: [u8; 32],
    recovery_mlkem_pub: [u8; 1184],
}

fn seed32(j: &Value, k: &str) -> [u8; 32] {
    let v = hex::decode(
        j[k].as_str()
            .unwrap_or_else(|| panic!("keys.testkey.json: missing {k}")),
    )
    .unwrap_or_else(|_| panic!("keys.testkey.json: {k} is not hex"));
    v.try_into()
        .unwrap_or_else(|_: Vec<u8>| panic!("keys.testkey.json: {k} is not 32 bytes"))
}

fn seed64(j: &Value, k: &str) -> [u8; 64] {
    let v = hex::decode(
        j[k].as_str()
            .unwrap_or_else(|| panic!("keys.testkey.json: missing {k}")),
    )
    .unwrap_or_else(|_| panic!("keys.testkey.json: {k} is not hex"));
    v.try_into()
        .unwrap_or_else(|_: Vec<u8>| panic!("keys.testkey.json: {k} is not 64 bytes"))
}

fn mlkem(j: &Value, k: &str) -> [u8; 1184] {
    mlkem_public_from_seed(&seed64(j, k)).expect("a 64-byte ML-KEM decapsulation seed")
}

impl Keys {
    fn load() -> Keys {
        let j: Value = serde_json::from_str(&maxsecu_compat::read_str(AREA, "keys.testkey.json"))
            .expect("keys.testkey.json is valid JSON");
        let d5 = SigningKey::from_seed(&seed32(&j, "d5_sig_seed"));
        let alice_sig = SigningKey::from_seed(&seed32(&j, "alice_sig_seed"));
        let bob_sig = SigningKey::from_seed(&seed32(&j, "bob_sig_seed"));
        Keys {
            d5_pub: d5.verifying_key().to_bytes(),
            d5,
            alice_sig_pub: alice_sig.verifying_key().to_bytes(),
            alice_sig,
            alice_enc_pub: x25519_public_from_secret(&seed32(&j, "alice_x25519_secret")),
            alice_mlkem_pub: mlkem(&j, "alice_mlkem_seed"),
            bob_sig_pub: bob_sig.verifying_key().to_bytes(),
            bob_sig,
            bob_enc_pub: x25519_public_from_secret(&seed32(&j, "bob_x25519_secret")),
            bob_mlkem_pub: mlkem(&j, "bob_mlkem_seed"),
            carol_sig_pub: SigningKey::from_seed(&seed32(&j, "carol_sig_seed"))
                .verifying_key()
                .to_bytes(),
            carol_enc_pub: x25519_public_from_secret(&seed32(&j, "carol_x25519_secret")),
            carol_mlkem_pub: mlkem(&j, "carol_mlkem_seed"),
            newuser_sig_pub: SigningKey::from_seed(&seed32(&j, "newuser_sig_seed"))
                .verifying_key()
                .to_bytes(),
            newuser_enc_pub: x25519_public_from_secret(&seed32(&j, "newuser_x25519_secret")),
            newuser_mlkem_pub: mlkem(&j, "newuser_mlkem_seed"),
            olduser_sig_pub: SigningKey::from_seed(&seed32(&j, "olduser_sig_seed"))
                .verifying_key()
                .to_bytes(),
            olduser_enc_pub: x25519_public_from_secret(&seed32(&j, "olduser_x25519_secret")),
            recovery_sig_pub: SigningKey::from_seed(&seed32(&j, "recovery_sig_seed"))
                .verifying_key()
                .to_bytes(),
            recovery_enc_pub: x25519_public_from_secret(&seed32(&j, "recovery_x25519_secret")),
            recovery_mlkem_pub: mlkem(&j, "recovery_mlkem_seed"),
        }
    }
}

// ---------------------------------------------------------------------------
// The harness — the REAL router over MemoryStore
// ---------------------------------------------------------------------------

/// Sign a directory binding with the frozen D5 key (what enrollment produces and
/// what `POST /v1/directory` re-verifies).
fn binding(
    k: &Keys,
    username: &str,
    user_id: [u8; 16],
    enc_pub: [u8; 32],
    sig_pub: [u8; 32],
    mlkem_pub: Option<[u8; 1184]>,
    admin: bool,
) -> (Vec<u8>, [u8; 64]) {
    let roles = if admin {
        RoleSet::new([Role::User, Role::Admin])
    } else {
        RoleSet::new([Role::User])
    };
    let b = DirBinding {
        username: Text::new(username).expect("a canonical username"),
        user_id: Id(user_id),
        enc_pub: Bytes32(enc_pub),
        sig_pub: Bytes32(sig_pub),
        key_version: 1,
        roles,
        not_before: Timestamp(0),
        not_after: Timestamp(FAR_FUTURE_MS), // never expires ⇒ no wall-clock flake
        mlkem_pub: mlkem_pub.map(MlKemPub),
    };
    let sig = k.d5.sign_canonical(labels::DIRBINDING, &b);
    (encode(&b), sig)
}

/// Build the router the gate drives: the real `maxsecu_server::router()` over a
/// `MemoryStore` seeded with exactly the state the frozen requests presuppose.
///
/// * alice — the author/admin who logs in with the frozen proof (admin binding
///   ⇒ `AdminSession`, so the frozen control-log POST is authorized);
/// * bob — the reshare recipient and the co-signing admin;
/// * the frozen login nonce, so the one-shot `session/proof` body replays;
/// * the two single-use registration keys the frozen `POST /v1/users` bodies
///   present;
/// * a **Dev** `DelegationCtx` (operational key == pinned D5) carrying a
///   self-issued delegation cert with a far-future window, so both
///   `/v1/bootstrap/*` GETs serve and enrollment is open.
///
/// The recovery account is deliberately NOT seeded: the frozen
/// `POST /v1/recovery/register` body creates it, first, as part of the flow.
async fn harness(k: &Keys) -> Router {
    let store = MemoryStore::new();

    store.add_user(
        "alice",
        UserRecord {
            user_id: ALICE_ID,
            enc_pub: k.alice_enc_pub,
            sig_pub: k.alice_sig_pub,
        },
    );
    store.add_user(
        "bob",
        UserRecord {
            user_id: BOB_ID,
            enc_pub: k.bob_enc_pub,
            sig_pub: k.bob_sig_pub,
        },
    );

    let (ab, asig) = binding(
        k,
        "alice",
        ALICE_ID,
        k.alice_enc_pub,
        k.alice_sig_pub,
        Some(k.alice_mlkem_pub),
        true,
    );
    store.put_binding(ALICE_ID, 1, ab, asig).await.unwrap();
    let (bb, bsig) = binding(
        k,
        "bob",
        BOB_ID,
        k.bob_enc_pub,
        k.bob_sig_pub,
        Some(k.bob_mlkem_pub),
        false,
    );
    store.put_binding(BOB_ID, 1, bb, bsig).await.unwrap();

    // Reconstructed one-shot state: the nonce the frozen proof signs over.
    store
        .insert_nonce(NONCE, "alice", FAR_FUTURE_MS)
        .await
        .unwrap();

    for key in [REG_KEY_PQ, REG_KEY_CLASSIC] {
        store
            .issue_registration_key(sha256(key.as_bytes()), FAR_FUTURE_MS)
            .await
            .unwrap();
    }

    // Dev delegation: operational key == pinned D5, self-issued cert, far-future
    // window (so `enrollment_open` and both bootstrap GETs never time out).
    let cert = sign_delegation(&k.d5, &k.d5_pub, 0, FAR_FUTURE_SECS);
    let auth = AuthService::new(store, AuthConfig::default().with_directory_pub(k.d5_pub))
        .with_dir_signer(Arc::new(SigningKey::from_seed(&k.d5.to_seed())))
        .with_delegation(Arc::new(DelegationCtx::dev(k.d5_pub, cert)));

    let state = AppState {
        auth: Arc::new(auth),
        blobs: Arc::new(MemoryBlobStore::new()),
        audit: Arc::new(NullAuditSink),
        direct_links_enabled: false,
        max_file_bytes: None,
    };
    router(state).layer(Extension(TlsExporter(EXPORTER)))
}

// ---------------------------------------------------------------------------
// Dispatch helpers
// ---------------------------------------------------------------------------

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    if let Some(t) = token {
        req = req.header("authorization", format!("MaxSecu-Session {t}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .expect("the router is infallible");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 << 20)
        .await
        .expect("a bounded response body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

/// POST/PUT a **frozen request fixture verbatim** — the bytes on disk, unedited.
async fn send_frozen(
    app: &Router,
    method: &str,
    uri: &str,
    fixture: &str,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let ct = if fixture.ends_with(".bin") {
        "application/octet-stream"
    } else {
        "application/json"
    };
    let body = maxsecu_compat::read(AREA, fixture);
    send(app, method, uri, Some(ct), body, token).await
}

async fn get(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    send(app, "GET", uri, None, Vec::new(), token).await
}

// ---------------------------------------------------------------------------
// The scripted flow — every frozen request, replayed verbatim, in order
// ---------------------------------------------------------------------------

/// One recorded step: the fixture stem and the live response body. (The status
/// is asserted in-flow by [`accepted`], so it is not carried here.)
struct Recorded {
    stem: &'static str,
    json: Value,
}

/// Why a break at this endpoint locks users out. Printed by every failure.
fn blast(stem: &str) -> &'static str {
    match stem {
        "users_register.v2" => {
            "PQ enrollment (`POST /v1/users` with `mlkem_pub_b64`). Drop or rename the field and \
             the directory binding goes back to classical — every Suite::V2 reshare to that user \
             fails `pq_key_missing`. This is the bug 2a626d6 already shipped once."
        }
        "users_register.v1_no_mlkem" => {
            "Classical enrollment (`POST /v1/users` WITHOUT `mlkem_pub_b64`). Clients in the field \
             predate that field. Making it required means an existing client can never enroll — \
             and `mlkem_pub_b64` MUST stay optional forever."
        }
        "recovery_register.v2" | "recovery_register.v1_no_mlkem" => {
            "`POST /v1/recovery/register` is what `maxsecu-setup` calls at install. Break it and no \
             new server can be stood up from an existing (already-shipped) setup tool."
        }
        "recovery_pubkey" => {
            "`GET /v1/recovery/pubkey` is the client's embedded-pin compare (T8) AND the PQ recovery \
             wrap target. Drop `mlkem_pub_b64` and every hybrid upload loses its recovery wrap."
        }
        "session_challenge" | "session_proof" => {
            "LOGIN. Every user in the field is locked out of their account — the single worst \
             possible break."
        }
        "directory_publish" | "directory_by_username" | "directory_by_id" => {
            "The signed key directory. Clients verify `binding_b64` against the pinned D5 root; \
             without it every share/resolve fails closed and no recipient can be targeted."
        }
        "bootstrap_operational_key" | "bootstrap_delegation" => {
            "The offline-D5 delegation hop (`pinned D5 → delegation → operational_pub → binding`). \
             A client that cannot complete it rejects the directory ⇒ TOTAL lockout."
        }
        "files_create.v1_no_bundle_fields" => {
            "A PRE-BUNDLES client's `POST /v1/files` — no `listed`, no `bundle_id` (both post-date \
             it). Making either required means every client shipped before the bundles feature can \
             no longer upload anything. They must stay `#[serde(default)]` forever."
        }
        "files_create" | "files_stage_version" | "files_finalize" | "files_chunk" => {
            "UPLOAD. A newly-required field here means an existing client can no longer post \
             anything (`stage_failed` / `finalize_failed` — the real-VPS bug class)."
        }
        "files_get" | "files_list" => {
            "READING ALREADY-UPLOADED DATA. `manifest_b64` / `my_wrap.wrapped_dek_b64` / \
             `genesis_b64` are how a client decrypts what it already owns. Drop one and existing \
             data becomes unreadable — permanently, since the server holds no keys."
        }
        "files_add_wrap" | "files_recipients" => {
            "RESHARE. `POST /v1/files/{id}/wraps` is the sharing seam; `recipients` drives rotation \
             carry-forward. Break either and existing users cannot share (or silently lose \
             recipients on the next rotation)."
        }
        "revocations_post" | "revocations_get" => {
            "The revocation control-log. Clients replay the chain to fail closed on revoked access; \
             a missing field means a tombstone is silently ignored — a SECURITY downgrade."
        }
        _ => "an access-critical `/v1` endpoint the shipped client depends on",
    }
}

/// Assert the frozen request was ACCEPTED (assertion (a)). The failure message
/// is deliberately loud: this fires when someone adds a required field.
fn accepted(stem: &'static str, got: StatusCode, want: StatusCode, body: &Value) {
    assert_eq!(
        got,
        want,
        "\n\nFROZEN REQUEST REJECTED: compat/fixtures/{AREA}/{stem}.req.json → {got} (want {want})\n\
         The exact bytes a shipped client sends are no longer accepted at this route.\n\
         A 422 almost always means a field was made REQUIRED (serde) that used to be optional or \
         absent; a 400 means validation got stricter.\n\
         BLAST RADIUS: {}\n\
         Do NOT edit the fixture — it is a snapshot of what a real client in the field already \
         sends. Keep the field optional (additive evolution only).\n\
         server said: {body}\n{CHECKLIST}\n",
        blast(stem)
    );
}

/// Drive the whole flow with the frozen bytes, asserting (a) as it goes, and
/// record every live response for (b).
///
/// The order is the real deployment order: stand up recovery → enroll → log in →
/// publish → upload → read → reshare → revoke → rotate. Nothing is faked; each
/// step's state is produced by the previous frozen request.
async fn run_flow(app: &Router) -> BTreeMap<&'static str, Recorded> {
    let mut out: BTreeMap<&'static str, Recorded> = BTreeMap::new();
    let mut rec = |stem: &'static str, json: Value| {
        out.insert(stem, Recorded { stem, json });
    };
    let fid = file_hex();

    // 1. The escrow recovery account (maxsecu-setup, once-only).
    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/recovery/register",
        "recovery_register.v2.req.json",
        None,
    )
    .await;
    accepted("recovery_register.v2", st, StatusCode::CREATED, &j);
    rec("recovery_register.v2", j);

    // 2. Enrollment — PQ (with mlkem_pub_b64) and pre-PQ (without). BOTH must work.
    let (st, j) = send_frozen(app, "POST", "/v1/users", "users_register.v2.req.json", None).await;
    accepted("users_register.v2", st, StatusCode::CREATED, &j);
    rec("users_register.v2", j);

    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/users",
        "users_register.v1_no_mlkem.req.json",
        None,
    )
    .await;
    accepted("users_register.v1_no_mlkem", st, StatusCode::CREATED, &j);
    rec("users_register.v1_no_mlkem", j);

    // 3. Login (channel-bound challenge/proof).
    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/session/challenge",
        "session_challenge.req.json",
        None,
    )
    .await;
    accepted("session_challenge", st, StatusCode::OK, &j);
    rec("session_challenge", j);

    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/session/proof",
        "session_proof.req.json",
        None,
    )
    .await;
    accepted("session_proof", st, StatusCode::OK, &j);
    let token = j["session_token"]
        .as_str()
        .expect("the frozen proof still mints a session")
        .to_owned();
    rec("session_proof", j);
    let tok = Some(token.as_str());

    // 4. Directory: publish a D5-signed binding, then read bindings back.
    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/directory",
        "directory_publish.req.json",
        None,
    )
    .await;
    accepted("directory_publish", st, StatusCode::CREATED, &j);
    rec("directory_publish", j);

    let (st, j) = get(app, "/v1/directory/alice", None).await;
    accepted("directory_by_username", st, StatusCode::OK, &j);
    rec("directory_by_username", j);

    let (st, j) = get(app, &format!("/v1/directory/by-id/{}", alice_hex()), None).await;
    accepted("directory_by_id", st, StatusCode::OK, &j);
    rec("directory_by_id", j);

    // 5. The recovery pubkey (embedded-pin compare + PQ recovery wrap target).
    let (st, j) = get(app, "/v1/recovery/pubkey", None).await;
    accepted("recovery_pubkey", st, StatusCode::OK, &j);
    rec("recovery_pubkey", j);

    // 6. The offline-D5 bootstrap hop.
    let (st, j) = get(app, "/v1/bootstrap/operational-key", None).await;
    accepted("bootstrap_operational_key", st, StatusCode::OK, &j);
    rec("bootstrap_operational_key", j);

    let (st, j) = get(app, "/v1/bootstrap/delegation", None).await;
    accepted("bootstrap_delegation", st, StatusCode::OK, &j);
    rec("bootstrap_delegation", j);

    // 7. Upload: stage v1 → PUT every chunk → finalize.
    let (st, j) = send_frozen(app, "POST", "/v1/files", "files_create.req.json", tok).await;
    accepted("files_create", st, StatusCode::CREATED, &j);
    rec("files_create", j);

    // A PRE-BUNDLES client omits `listed` and `bundle_id` entirely (they were added
    // by the bundles feature). Staging a second file with that older body must still
    // be accepted — making either field required would stop every shipped client from
    // posting anything. Left staged (never finalized), so it perturbs nothing below.
    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/files",
        "files_create.v1_no_bundle_fields.req.json",
        tok,
    )
    .await;
    accepted(
        "files_create.v1_no_bundle_fields",
        st,
        StatusCode::CREATED,
        &j,
    );
    rec("files_create.v1_no_bundle_fields", j);

    for (stream, index, fixture) in CHUNKS {
        let uri = format!("/v1/files/{fid}/versions/1/streams/{stream}/chunks/{index}");
        let (st, j) = send_frozen(app, "PUT", &uri, fixture, tok).await;
        accepted("files_chunk", st, StatusCode::OK, &j);
    }

    let (st, j) = send_frozen(
        app,
        "POST",
        &format!("/v1/files/{fid}/versions/1/finalize"),
        "files_finalize.req.json",
        tok,
    )
    .await;
    accepted("files_finalize", st, StatusCode::OK, &j);
    rec("files_finalize", j);

    // 8. Read back what was uploaded (the "already-uploaded data" surface).
    let (st, j) = get(app, &format!("/v1/files/{fid}?version=latest"), tok).await;
    accepted("files_get", st, StatusCode::OK, &j);
    rec("files_get", j);

    let (st, j) = get(app, "/v1/files?limit=50", tok).await;
    accepted("files_list", st, StatusCode::OK, &j);
    rec("files_list", j);

    // 9. Reshare to bob, then read the recipient list back.
    let (st, j) = send_frozen(
        app,
        "POST",
        &format!("/v1/files/{fid}/wraps"),
        "files_add_wrap.req.json",
        tok,
    )
    .await;
    accepted("files_add_wrap", st, StatusCode::CREATED, &j);
    rec("files_add_wrap", j);

    let (st, j) = get(app, &format!("/v1/files/{fid}/recipients"), tok).await;
    accepted("files_recipients", st, StatusCode::OK, &j);
    rec("files_recipients", j);

    // 10. The revocation control-log (admin-gated; alice's binding carries Admin).
    let (st, j) = send_frozen(
        app,
        "POST",
        "/v1/revocations",
        "revocations_post.req.json",
        tok,
    )
    .await;
    accepted("revocations_post", st, StatusCode::CREATED, &j);
    rec("revocations_post", j);

    let (st, j) = get(app, "/v1/revocations", None).await;
    accepted("revocations_get", st, StatusCode::OK, &j);
    rec("revocations_get", j);

    // 11. Rotation: stage v2 of the same file (no genesis; wraps carried forward).
    let (st, j) = send_frozen(
        app,
        "POST",
        &format!("/v1/files/{fid}/versions"),
        "files_stage_version.req.json",
        tok,
    )
    .await;
    accepted("files_stage_version", st, StatusCode::CREATED, &j);
    rec("files_stage_version", j);

    out
}

/// The three frozen ciphertext chunks of the frozen upload: `(stream, index, fixture)`.
const CHUNKS: [(&str, u64, &str); 3] = [
    ("content", 0, "files_chunk.content.0.bin"),
    ("content", 1, "files_chunk.content.1.bin"),
    ("metadata", 0, "files_chunk.metadata.0.bin"),
];

// ---------------------------------------------------------------------------
// (a) Old request bodies are still accepted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn compat_frozen_requests_are_still_accepted() {
    let k = Keys::load();
    let app = harness(&k).await;
    // Every `accepted(..)` assertion fires inside the flow.
    let recorded = run_flow(&app).await;
    assert!(
        recorded.len() >= 15,
        "the flow must exercise every frozen request"
    );

    // `POST /v1/recovery/register` is once-only, so the pre-PQ (classical) variant
    // of that body needs its own clean server — an existing `maxsecu-setup` build
    // that omits `mlkem_pub_b64` must still be able to stand a server up.
    let fresh = harness(&k).await;
    let (st, j) = send_frozen(
        &fresh,
        "POST",
        "/v1/recovery/register",
        "recovery_register.v1_no_mlkem.req.json",
        None,
    )
    .await;
    accepted("recovery_register.v1_no_mlkem", st, StatusCode::CREATED, &j);
}

// ---------------------------------------------------------------------------
// (b) Old response fields are still emitted
// ---------------------------------------------------------------------------

/// The JSON type name used in the "type changed" message.
fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `live` must be a recursive **superset** of `frozen`'s key structure: every key
/// an old client reads still exists, at the same JSON path, with the same JSON
/// type. Values are NOT compared (nonces, ids and tokens are fresh every run).
/// Additive keys are fine — that is the whole contract.
///
/// A frozen `null` (an `Option` field that was `None` when frozen) asserts only
/// that the KEY still exists; its type is left open.
fn assert_superset(frozen: &Value, live: &Value, path: &str, stem: &str) {
    match frozen {
        Value::Object(f) => {
            let Some(l) = live.as_object() else {
                panic!(
                    "\n\nRESPONSE SHAPE CHANGED at `{path}` ({stem}): was an object, now {}.\n\
                     BLAST RADIUS: {}\n{CHECKLIST}\n",
                    type_of(live),
                    blast(stem)
                );
            };
            for (key, fv) in f {
                let child = format!("{path}.{key}");
                let Some(lv) = l.get(key) else {
                    panic!(
                        "\n\nRESPONSE FIELD REMOVED: `{child}` ({stem})\n\
                         The shipped client reads `{child}`. Today's server no longer emits it — \
                         every client in the field breaks on this response.\n\
                         BLAST RADIUS: {}\n\
                         Fields may be ADDED, never removed or renamed. If this is a rename, keep \
                         emitting the old key as well and record it in docs/compat/LEDGER.md.\n\
                         live keys here: {:?}\n{CHECKLIST}\n",
                        blast(stem),
                        l.keys().collect::<Vec<_>>()
                    );
                };
                assert_superset(fv, lv, &child, stem);
            }
        }
        Value::Array(f) => {
            let Some(l) = live.as_array() else {
                panic!(
                    "\n\nRESPONSE SHAPE CHANGED at `{path}` ({stem}): was an array, now {}.\n\
                     BLAST RADIUS: {}\n{CHECKLIST}\n",
                    type_of(live),
                    blast(stem)
                );
            };
            for (i, fv) in f.iter().enumerate() {
                let child = format!("{path}[{i}]");
                let Some(lv) = l.get(i) else {
                    panic!(
                        "\n\nRESPONSE ROW DISAPPEARED: `{child}` ({stem}) — the frozen response \
                         carried {} rows here, today's server returns {}.\n\
                         BLAST RADIUS: {}\n{CHECKLIST}\n",
                        f.len(),
                        l.len(),
                        blast(stem)
                    );
                };
                assert_superset(fv, lv, &child, stem);
            }
        }
        // A frozen `null` only pins the KEY's existence (it was an absent Option).
        Value::Null => {}
        _ => {
            assert_eq!(
                type_of(frozen),
                type_of(live),
                "\n\nRESPONSE FIELD TYPE CHANGED: `{path}` ({stem}) was {} and is now {}.\n\
                 An old client parses this field with the old type and fails closed.\n\
                 BLAST RADIUS: {}\n{CHECKLIST}\n",
                type_of(frozen),
                type_of(live),
                blast(stem)
            );
        }
    }
}

#[tokio::test]
async fn compat_frozen_response_fields_are_still_emitted() {
    let k = Keys::load();
    let app = harness(&k).await;
    let live = run_flow(&app).await;

    let mut checked = 0usize;
    for (stem, r) in &live {
        let file = format!("{stem}.res.json");
        // Only the steps whose response carries a body are frozen (a 201/204 with
        // an empty body has no shape to lock).
        if !maxsecu_compat::area(AREA).join(&file).exists() {
            continue;
        }
        let frozen: Value = serde_json::from_slice(&maxsecu_compat::read(AREA, &file))
            .unwrap_or_else(|e| panic!("{file} is not valid JSON: {e}"));
        assert_superset(&frozen, &r.json, "$", r.stem);
        checked += 1;
    }
    assert!(
        checked >= 12,
        "expected every frozen response fixture to be exercised, checked only {checked} \
         — a fixture stopped being reached by the flow. {CHECKLIST}"
    );
}

// ---------------------------------------------------------------------------
// (c) The route surface is a superset
// ---------------------------------------------------------------------------

/// The routes are dispatched with NO session token: an authenticated endpoint
/// answers `401` (the extractor rejects), which still proves the route EXISTS.
/// A `404` means the endpoint vanished or moved; a `405` means its method
/// changed. Both lock out a shipped client, which has these paths compiled in.
///
/// Out of scope (they live on OTHER routers, not `maxsecu_server::router()`):
/// `GET /v1/bootstrap/pins` (portable-server) and `GET /v1/control-log/head`
/// (sink-server).
#[tokio::test]
async fn compat_route_surface_is_a_superset() {
    let k = Keys::load();
    let app = harness(&k).await;
    // Run the flow first so the state-dependent GETs (directory, recovery pubkey,
    // revocations) answer 200 rather than a legitimate 404 — that keeps "404" an
    // unambiguous signal for "this route no longer exists".
    run_flow(&app).await;

    let routes: Value = serde_json::from_slice(&maxsecu_compat::read(AREA, "routes.json"))
        .expect("routes.json is valid JSON");
    let routes = routes["routes"]
        .as_array()
        .expect("routes.json: `routes` []");
    assert!(!routes.is_empty(), "the frozen route surface is empty");

    for r in routes {
        let method = r["method"].as_str().expect("route.method");
        let path = r["path"].as_str().expect("route.path");
        let (status, _) = send(
            &app,
            method,
            path,
            Some("application/json"),
            b"{}".to_vec(),
            None,
        )
        .await;
        assert!(
            status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
            "\n\nROUTE GONE: `{method} {path}` → {status}\n\
             The shipped client has this path compiled in. A 404 means the endpoint was removed or \
             moved; a 405 means its HTTP method changed. Either way every client in the field that \
             calls it breaks — and there is no way to update a client that can no longer log in.\n\
             BLAST RADIUS: an access-critical route disappeared from `maxsecu_server::router()`.\n\
             Routes may be ADDED. An existing one may never be removed or moved.\n{CHECKLIST}\n"
        );
    }
}

// ---------------------------------------------------------------------------
// The corpus is add-only
// ---------------------------------------------------------------------------

#[test]
fn compat_corpus_is_locked() {
    maxsecu_compat::verify_corpus_lock(AREA);
}

// ---------------------------------------------------------------------------
// Fixture generation — run ONCE, then never again (see the module docs)
// ---------------------------------------------------------------------------

/// Deterministic filler standing in for a sealed ciphertext chunk. The HTTP seam
/// never opens these — the server stores chunk bytes verbatim (`blob.rs`) and
/// only bounds their length. Realistic lengths (`chunk_size` + the 16-byte GCM
/// tag, and a short final chunk) so the `413` bound is exercised for real.
fn filler(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn write_fixture(name: &str, bytes: &[u8]) {
    let path = maxsecu_compat::area(AREA).join(name);
    std::fs::create_dir_all(path.parent().unwrap()).expect("create the fixture area");
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn write_json(name: &str, v: &Value) {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    write_fixture(name, s.as_bytes());
}

/// The frozen seeds. TEST-ONLY, and deliberately obvious as such.
fn keys_file() -> Value {
    let h32 = |b: u8| hex::encode([b; 32]);
    let h64 = |b: u8| hex::encode([b; 64]);
    json!({
        "_comment": "TEST-ONLY key material for the HTTP compat corpus. These seeds are \
                     hard-coded, public, and worthless: they exist only so the frozen request \
                     bodies (signatures, bindings, grants) can be replayed offline. They are \
                     NEVER used by any shipped binary, and must never be named recovery_pin.bin \
                     or placed anywhere client-app/build.rs reads.",
        "d5_sig_seed": h32(0xD5),
        "alice_sig_seed": h32(0xA1),
        "alice_x25519_secret": h32(0xA2),
        "alice_mlkem_seed": h64(0xA3),
        "bob_sig_seed": h32(0xB1),
        "bob_x25519_secret": h32(0xB2),
        "bob_mlkem_seed": h64(0xB3),
        "carol_sig_seed": h32(0xC1),
        "carol_x25519_secret": h32(0xC2),
        "carol_mlkem_seed": h64(0xC3),
        "newuser_sig_seed": h32(0x71),
        "newuser_x25519_secret": h32(0x72),
        "newuser_mlkem_seed": h64(0x73),
        "olduser_sig_seed": h32(0x81),
        "olduser_x25519_secret": h32(0x82),
        "recovery_sig_seed": h32(0xE1),
        "recovery_x25519_secret": h32(0xE2),
        "recovery_mlkem_seed": h64(0xE3),
    })
}

/// The `(method, path)` surface the shipped client + `maxsecu-setup` compile in.
fn routes_file() -> Value {
    let fid = file_hex();
    let uid = alice_hex();
    let bid = hex::encode(BOB_ID);
    let rows: Vec<Value> = vec![
        ("POST", "/v1/users".to_owned()),
        ("POST", "/v1/registration-keys".to_owned()),
        ("GET", "/v1/bootstrap/operational-key".to_owned()),
        ("GET", "/v1/bootstrap/delegation".to_owned()),
        ("POST", "/v1/bootstrap/delegation".to_owned()),
        ("POST", "/v1/admin/delegation".to_owned()),
        ("POST", "/v1/recovery/register".to_owned()),
        ("GET", "/v1/recovery/pubkey".to_owned()),
        ("POST", "/v1/recovery/challenge".to_owned()),
        ("POST", "/v1/recovery/verify".to_owned()),
        ("POST", "/v1/session/challenge".to_owned()),
        ("POST", "/v1/session/proof".to_owned()),
        ("POST", "/v1/session/logout".to_owned()),
        ("POST", "/v1/directory".to_owned()),
        ("GET", "/v1/directory/alice".to_owned()),
        ("GET", format!("/v1/directory/by-id/{uid}")),
        ("GET", "/v1/revocations".to_owned()),
        ("POST", "/v1/revocations".to_owned()),
        ("POST", "/v1/reinstatements".to_owned()),
        ("POST", "/v1/key-compromise".to_owned()),
        ("GET", "/v1/files?limit=50".to_owned()),
        ("POST", "/v1/files".to_owned()),
        ("GET", format!("/v1/files/{fid}?version=latest")),
        ("DELETE", format!("/v1/files/{fid}")),
        ("GET", format!("/v1/files/{fid}/recipients")),
        ("POST", format!("/v1/files/{fid}/wraps")),
        ("DELETE", format!("/v1/files/{fid}/wraps/{bid}")),
        ("POST", format!("/v1/files/{fid}/versions")),
        ("POST", format!("/v1/files/{fid}/versions/1/finalize")),
        (
            "PUT",
            format!("/v1/files/{fid}/versions/1/streams/content/chunks/0"),
        ),
        (
            "GET",
            format!("/v1/files/{fid}/versions/1/streams/content/chunks/0"),
        ),
        (
            "GET",
            format!("/v1/files/{fid}/versions/1/streams/content/chunks/0/status"),
        ),
        (
            "POST",
            format!("/v1/files/{fid}/versions/1/streams/content/chunks/0/direct-link"),
        ),
    ]
    .into_iter()
    .map(|(m, p)| json!({ "method": m, "path": p }))
    .collect();
    json!({
        "_comment": "The (method, path) surface a SHIPPED client depends on. Routes may be added; \
                     an existing one may never be removed or moved. Dispatched with no session \
                     token — a 401 still proves the route exists; a 404/405 does not.",
        "routes": rows,
    })
}

// -- request-body builders (used ONLY by the emit test) ----------------------

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn manifest(file: [u8; 16], version: u64, dek_commit: [u8; 32]) -> Manifest {
    Manifest {
        file_id: Id(file),
        version,
        file_type: FileType::Blog,
        alg: Suite::V1,
        chunk_size: CHUNK_SIZE,
        dek_commit: Bytes32(dek_commit),
        streams: vec![
            Stream {
                stream_type: StreamType::Content,
                compression: Compression::None,
                chunk_count: 2,
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
        author_id: Id(ALICE_ID),
        created_at: Timestamp(TS_MS + version),
    }
}

/// One `wraps[]` entry exactly as `client-app::upload::stage_body` shapes it.
#[allow(clippy::too_many_arguments)] // mirrors the client's builder 1:1 on purpose
fn wrap_entry(
    file: [u8; 16],
    version: u64,
    recipient_id: [u8; 16],
    recipient_type: RecipientType,
    recipient_enc_pub: [u8; 32],
    granted_by: [u8; 16],
    granter: &SigningKey,
    dek: &Dek,
) -> Value {
    let ctx = WrapContext {
        file_id: Id(file),
        version,
        recipient_id: Id(recipient_id),
    };
    let wrapped = wrap_dek(&EncPublicKey::from_bytes(recipient_enc_pub), dek, &ctx)
        .expect("a valid X25519 recipient key");
    let mut wire = wrapped.enc.to_vec();
    wire.extend_from_slice(&wrapped.ct);

    let grant = Grant {
        file_id: Id(file),
        file_version: version,
        recipient_id: Id(recipient_id),
        recipient_type,
        dek_commit: Bytes32(dek.commit()),
        granted_by: Id(granted_by),
        created_at: Timestamp(TS_MS),
    };
    let grant_sig = granter.sign_canonical(labels::GRANT, &grant);
    json!({
        "recipient_id": if recipient_type == RecipientType::Recovery {
            "recovery".to_owned()
        } else {
            hex::encode(recipient_id)
        },
        "recipient_type": if recipient_type == RecipientType::Recovery { "recovery" } else { "user" },
        "wrapped_dek_b64": b64(&wire),
        "wrap_alg": 1,
        "granted_by": hex::encode(granted_by),
        "grant_b64": b64(&encode(&grant)),
        "grant_sig_b64": b64(&grant_sig),
    })
}

fn streams_field() -> Value {
    json!([
        { "stream_type": "content",  "chunk_count": 2, "chunk_size": CHUNK_SIZE, "total_bytes": 4640 },
        { "stream_type": "metadata", "chunk_count": 1, "chunk_size": CHUNK_SIZE, "total_bytes": 272 },
    ])
}

#[tokio::test]
#[ignore = "run with --ignored to generate the frozen HTTP corpus; the gate NEVER regenerates it"]
async fn emit_http_fixtures() {
    // 1. The key material must exist before anything can be derived from it.
    write_json("keys.testkey.json", &keys_file());
    let k = Keys::load();

    // 2. The chunk bodies (opaque to the server; realistic lengths).
    let chunk0 = filler(CHUNK_SIZE as usize + 16, 0x11);
    let chunk1 = filler(528, 0x22);
    let meta0 = filler(272, 0x33);
    write_fixture("files_chunk.content.0.bin", &chunk0);
    write_fixture("files_chunk.content.1.bin", &chunk1);
    write_fixture("files_chunk.metadata.0.bin", &meta0);

    // 3. The request bodies — byte-for-byte what a shipped client sends.
    write_json(
        "users_register.v2.req.json",
        &json!({
            "username": "newuser",
            "enc_pub_b64": b64(&k.newuser_enc_pub),
            "sig_pub_b64": b64(&k.newuser_sig_pub),
            "mlkem_pub_b64": b64(&k.newuser_mlkem_pub),
            "registration_key": REG_KEY_PQ,
        }),
    );
    // A pre-PQ client: no `mlkem_pub_b64` at all. It MUST still enroll.
    write_json(
        "users_register.v1_no_mlkem.req.json",
        &json!({
            "username": "olduser",
            "enc_pub_b64": b64(&k.olduser_enc_pub),
            "sig_pub_b64": b64(&k.olduser_sig_pub),
            "registration_key": REG_KEY_CLASSIC,
        }),
    );
    write_json(
        "recovery_register.v2.req.json",
        &json!({
            "enc_pub_b64": b64(&k.recovery_enc_pub),
            "sig_pub_b64": b64(&k.recovery_sig_pub),
            "mlkem_pub_b64": b64(&k.recovery_mlkem_pub),
        }),
    );
    write_json(
        "recovery_register.v1_no_mlkem.req.json",
        &json!({
            "enc_pub_b64": b64(&k.recovery_enc_pub),
            "sig_pub_b64": b64(&k.recovery_sig_pub),
        }),
    );
    write_json(
        "session_challenge.req.json",
        &json!({ "username": "alice" }),
    );
    // The login proof over the FROZEN nonce + the fixed exporter + server_id.
    let proof_ctx = AuthProofContext {
        server_id: Text::new(SERVER_ID).unwrap(),
        tls_exporter: Bytes32(EXPORTER),
        nonce: Bytes32(NONCE),
        timestamp: Timestamp(TS_MS),
    };
    write_json(
        "session_proof.req.json",
        &json!({
            "username": "alice",
            "timestamp": TS_MS,
            "proof_b64": b64(&k.alice_sig.sign_canonical(labels::AUTH, &proof_ctx)),
        }),
    );
    let (cb, csig) = binding(
        &k,
        "carol",
        CAROL_ID,
        k.carol_enc_pub,
        k.carol_sig_pub,
        Some(k.carol_mlkem_pub),
        false,
    );
    write_json(
        "directory_publish.req.json",
        &json!({
            "binding_b64": b64(&cb),
            "directory_signature_b64": b64(&csig),
        }),
    );

    // The upload: a real DEK, real HPKE wraps, real signed manifest/genesis/grants.
    let dek = Dek::from_bytes([0x7D; 32]);
    let m1 = manifest(FILE_ID, 1, dek.commit());
    let genesis = Genesis {
        file_id: Id(FILE_ID),
        owner_id: Id(ALICE_ID),
        owner_key_version: 1,
        created_at: Timestamp(TS_MS),
    };
    write_json(
        "files_create.req.json",
        &json!({
            "file_id": file_hex(),
            "file_type": "blog",
            "genesis_b64": b64(&encode(&genesis)),
            "genesis_sig_b64": b64(&k.alice_sig.sign_canonical(labels::GENESIS, &genesis)),
            "manifest_b64": b64(&encode(&m1)),
            "manifest_sig_b64": b64(&k.alice_sig.sign_canonical(labels::MANIFEST, &m1)),
            "streams": streams_field(),
            "wraps": [
                wrap_entry(FILE_ID, 1, ALICE_ID, RecipientType::User, k.alice_enc_pub, ALICE_ID, &k.alice_sig, &dek),
                wrap_entry(FILE_ID, 1, RECOVERY_ID.0, RecipientType::Recovery, k.recovery_enc_pub, ALICE_ID, &k.alice_sig, &dek),
            ],
            "listed": true,
        }),
    );
    // A PRE-BUNDLES client: no `listed`, no `bundle_id` (both post-date it). Same
    // shape otherwise, on a second file so it can be staged alongside the first.
    let dek_b = Dek::from_bytes([0x7F; 32]);
    let mb = manifest(FILE_ID_2, 1, dek_b.commit());
    let genesis_b = Genesis {
        file_id: Id(FILE_ID_2),
        owner_id: Id(ALICE_ID),
        owner_key_version: 1,
        created_at: Timestamp(TS_MS),
    };
    write_json(
        "files_create.v1_no_bundle_fields.req.json",
        &json!({
            "file_id": hex::encode(FILE_ID_2),
            "file_type": "blog",
            "genesis_b64": b64(&encode(&genesis_b)),
            "genesis_sig_b64": b64(&k.alice_sig.sign_canonical(labels::GENESIS, &genesis_b)),
            "manifest_b64": b64(&encode(&mb)),
            "manifest_sig_b64": b64(&k.alice_sig.sign_canonical(labels::MANIFEST, &mb)),
            "streams": streams_field(),
            "wraps": [
                wrap_entry(FILE_ID_2, 1, ALICE_ID, RecipientType::User, k.alice_enc_pub, ALICE_ID, &k.alice_sig, &dek_b),
                wrap_entry(FILE_ID_2, 1, RECOVERY_ID.0, RecipientType::Recovery, k.recovery_enc_pub, ALICE_ID, &k.alice_sig, &dek_b),
            ],
        }),
    );
    // The client posts a bare JSON `null` body to finalize (upload.rs).
    write_json("files_finalize.req.json", &Value::Null);
    // The reshare seam: one wrap row, granted_by == the caller.
    write_json(
        "files_add_wrap.req.json",
        &wrap_entry(
            FILE_ID,
            1,
            BOB_ID,
            RecipientType::User,
            k.bob_enc_pub,
            ALICE_ID,
            &k.alice_sig,
            &dek,
        ),
    );
    // A rotation (v2): no genesis; every wrap carried forward.
    let dek2 = Dek::from_bytes([0x7E; 32]);
    let m2 = manifest(FILE_ID, 2, dek2.commit());
    write_json(
        "files_stage_version.req.json",
        &json!({
            "file_type": "blog",
            "manifest_b64": b64(&encode(&m2)),
            "manifest_sig_b64": b64(&k.alice_sig.sign_canonical(labels::MANIFEST, &m2)),
            "streams": streams_field(),
            "wraps": [
                wrap_entry(FILE_ID, 2, ALICE_ID, RecipientType::User, k.alice_enc_pub, ALICE_ID, &k.alice_sig, &dek2),
                wrap_entry(FILE_ID, 2, RECOVERY_ID.0, RecipientType::Recovery, k.recovery_enc_pub, ALICE_ID, &k.alice_sig, &dek2),
                wrap_entry(FILE_ID, 2, BOB_ID, RecipientType::User, k.bob_enc_pub, ALICE_ID, &k.alice_sig, &dek2),
            ],
        }),
    );
    // An account-wide revocation tombstone (dual-controlled ⇒ `co_sig_b64` present).
    let mut chain = ControlChain::new();
    let signed = chain
        .revoke(
            &k.alice_sig,
            RevokeParams {
                scope: FileScope::AccountWide,
                revoked_user_id: Id(CAROL_ID),
                revoked_capability: None,
                from_version: 1,
                issued_by: Id(ALICE_ID),
                created_at: Timestamp(TS_MS),
            },
            Some(CoSign {
                admin_id: Id(BOB_ID),
                key: &k.bob_sig,
            }),
        )
        .expect("a co-signed account-wide revoke");
    write_json(
        "revocations_post.req.json",
        &json!({
            "record_b64": b64(&signed.bytes),
            "sig_b64": b64(&signed.sig),
            "co_sig_b64": b64(&signed.co_sig.expect("dual control")),
        }),
    );

    write_json("routes.json", &routes_file());

    // 4. Drive the REAL router with those exact bytes and freeze what it answers.
    let app = harness(&k).await;
    let recorded = run_flow(&app).await;
    for (stem, r) in &recorded {
        if r.json.is_null() {
            continue; // 201/204 with an empty body — no shape to freeze
        }
        write_json(&format!("{stem}.res.json"), &r.json);
    }

    // 5. The lock: `<filename>  <sha256-hex>`, sorted, LF.
    let dir = maxsecu_compat::area(AREA);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("the fixture area exists")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n != "corpus.lock")
        .collect();
    names.sort();
    let mut lock = String::from(
        "# compat/fixtures/http — the frozen /v1 HTTP wire corpus.\n\
         # ADD-ONLY: a fixture may never be edited or deleted (docs/compat/CHECKLIST.md).\n",
    );
    for n in &names {
        lock.push_str(&format!(
            "{n}  {}\n",
            maxsecu_compat::sha256_hex(&maxsecu_compat::read(AREA, n))
        ));
    }
    write_fixture("corpus.lock", lock.as_bytes());

    eprintln!("wrote {} fixtures to {}", names.len(), dir.display());
}
