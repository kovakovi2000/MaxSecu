//! The setup round-trip, factored as a library fn so the e2e can drive it against
//! an in-process server. `main.rs` builds [`SetupOpts`] + a pinned [`Transport`]
//! from flags/env and calls [`run`].
//!
//! The recovery-login round-trip (challenge → unwrap nonce → channel-bound proof →
//! verify) is implemented INLINE here, mirroring `server/tests/recovery_login_e2e.rs`
//! — the tool holds the recovery private key it just generated, so it can log in as
//! the recovery account without depending on any not-yet-merged client command.

use std::fmt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use zeroize::Zeroizing;

use maxsecu_client_app::recovery_pin::canonical_pin;
use maxsecu_client_app::transport::Transport;
use maxsecu_client_core::{keyblob, password, Identity, ARGON2_DESKTOP_TARGET};
use maxsecu_crypto::{deserialize_hybrid_wrap, unwrap_dek_hybrid, HybridEncSecretKey};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, Text, Timestamp};
use maxsecu_encoding::RECOVERY_ID;

/// Where each artifact landed + the recovery enc pubkey that was pinned/registered.
#[derive(Debug, Clone)]
pub struct SetupReport {
    /// The recovery account's X25519 enc pubkey (public; safe to print).
    pub recovery_enc_pub: [u8; 32],
    /// `true` if the recovery account carries an ML-KEM key (hybrid → uploads V2).
    pub hybrid: bool,
    /// Sealed recovery private-key `local_key_blob` path (`--out`).
    pub out: PathBuf,
    /// Canonical `recovery_pin.bin` path (`--pin-out`).
    pub pin_out: PathBuf,
    /// First registration key (plaintext) path (`--first-key-out`).
    pub first_key_out: PathBuf,
}

/// Inputs to [`run`]. Paths must NOT already exist (fail-closed: never clobber a
/// prior recovery blob / pin / key). `host` is the TLS SNI + HTTP `Host` header.
pub struct SetupOpts {
    pub host: String,
    pub out: PathBuf,
    pub pin_out: PathBuf,
    pub first_key_out: PathBuf,
    /// Passphrase that seals the recovery `local_key_blob`. Zeroized on drop.
    pub passphrase: Zeroizing<String>,
}

/// Everything that can stop the bootstrap. [`SetupError::AlreadyRegistered`] is the
/// only variant that maps to a distinct (non-1) exit code — it is the expected
/// "run me only once" outcome, not a fault.
#[derive(Debug)]
pub enum SetupError {
    /// `POST /v1/recovery/register` returned 409: the server already has a recovery
    /// account. NOTHING is written; the caller exits non-zero.
    AlreadyRegistered,
    /// A pre-flight guard failed (output path already exists, weak passphrase) —
    /// caught BEFORE any network or key generation.
    Precheck(String),
    /// A transport/HTTP failure (could not reach or talk to the server).
    Network(String),
    /// The server answered, but not as the recovery protocol requires.
    Protocol(String),
    /// Sealing or writing a cold artifact failed.
    Io(String),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetupError::AlreadyRegistered => write!(
                f,
                "the server already has a recovery account registered (409); nothing was written"
            ),
            SetupError::Precheck(m) => write!(f, "pre-flight check failed: {m}"),
            SetupError::Network(m) => write!(f, "network error: {m}"),
            SetupError::Protocol(m) => write!(f, "protocol error: {m}"),
            SetupError::Io(m) => write!(f, "write error: {m}"),
        }
    }
}

impl std::error::Error for SetupError {}

/// Bootstrap the system against `t` (a pinned-TLS transport to the fresh server).
///
/// Ordering matters for the "409 writes nothing" contract: all pre-flight guards run
/// FIRST (no network, no key material touched), then register/login/mint, and ONLY
/// on full success are the three cold artifacts written. A 409 (or any failure)
/// returns before the first write.
pub async fn run(t: &Transport, opts: &SetupOpts) -> Result<SetupReport, SetupError> {
    // (0) Pre-flight — before any network or key generation. Never clobber an
    // existing artifact, and reject a weak seal passphrase up front so we don't
    // register-then-fail-to-seal.
    preflight(opts)?;

    // (1) Generate the ONE system recovery identity: hybrid X25519 + ML-KEM enc key
    // (so every upload's recovery grant stays Suite::V2) + an Ed25519 sig key. The
    // private halves never leave this process except as the sealed --out file.
    let recovery = Identity::generate();
    let enc_pub = recovery.enc_pub_bytes();
    let mlkem_pub = recovery.mlkem_pub_bytes(); // always Some for a fresh identity

    // (2) One pinned-TLS connection for the whole flow: the recovery challenge/verify
    // are channel-bound to THIS connection's RFC-5705 exporter, so they must share it.
    let (mut conn, exporter) = open(t).await?;

    // (3) Register the recovery PUBLIC keys. 409 → already registered → write nothing.
    register(&mut conn, &opts.host, &recovery).await?;

    // (4) Log in AS the recovery account (channel-bound challenge/response) → an
    // admin session token.
    let token = recovery_login(&mut conn, &opts.host, &recovery, &exporter).await?;

    // (5) Mint the FIRST registration key with the recovery admin session. Whoever
    // enrolls with it first becomes admin via the server's atomic first-admin claim.
    let first_key = mint_first_key(&mut conn, &opts.host, &token).await?;

    // (6) Write the three cold artifacts — only now that register + mint succeeded.
    seal_recovery_key(&opts.out, opts.passphrase.as_str(), &recovery)?;
    write_new(
        &opts.pin_out,
        &canonical_pin(&enc_pub, mlkem_pub.as_ref().map(|m| &m[..])),
    )?;
    write_new(&opts.first_key_out, first_key.as_bytes())?;

    Ok(SetupReport {
        recovery_enc_pub: enc_pub,
        hybrid: mlkem_pub.is_some(),
        out: opts.out.clone(),
        pin_out: opts.pin_out.clone(),
        first_key_out: opts.first_key_out.clone(),
    })
}

// ---- pre-flight ----

fn preflight(opts: &SetupOpts) -> Result<(), SetupError> {
    password::check(opts.passphrase.as_str())
        .map_err(|_| SetupError::Precheck("recovery seal passphrase is too weak".into()))?;
    for p in [&opts.out, &opts.pin_out, &opts.first_key_out] {
        if p.exists() {
            return Err(SetupError::Precheck(format!(
                "output path already exists (refusing to overwrite): {}",
                p.display()
            )));
        }
    }
    Ok(())
}

// ---- HTTP over the pinned Transport (mirror demo-seed) ----

async fn open(t: &Transport) -> Result<(SendRequest<Full<Bytes>>, [u8; 32]), SetupError> {
    let (tls, exporter) = t
        .connect()
        .await
        .map_err(|e| SetupError::Network(e.message.clone()))?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| SetupError::Network(format!("http handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, exporter))
}

async fn post(
    s: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
    body: serde_json::Value,
    bearer: Option<&str>,
) -> Result<(StatusCode, serde_json::Value), SetupError> {
    s.ready()
        .await
        .map_err(|e| SetupError::Network(e.to_string()))?;
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", host)
        .header("content-type", "application/json");
    if let Some(tk) = bearer {
        b = b.header("authorization", format!("MaxSecu-Session {tk}"));
    }
    let req = b
        .body(Full::new(Bytes::from(body.to_string())))
        .map_err(|e| SetupError::Network(e.to_string()))?;
    let resp = s
        .send_request(req)
        .await
        .map_err(|e| SetupError::Network(e.to_string()))?;
    let st = resp.status();
    let by = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| SetupError::Network(e.to_string()))?
        .to_bytes();
    Ok((st, parse_json(&by)))
}

fn parse_json(by: &[u8]) -> serde_json::Value {
    if by.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(by).unwrap_or(serde_json::Value::Null)
    }
}

// ---- protocol steps ----

/// `POST /v1/recovery/register` with the recovery PUBLIC keys. Only public material
/// crosses the wire. 201 → registered; 409 → already registered (write nothing).
async fn register(
    conn: &mut SendRequest<Full<Bytes>>,
    host: &str,
    id: &Identity,
) -> Result<(), SetupError> {
    let mut body = serde_json::json!({
        "enc_pub_b64": B64.encode(id.enc_pub_bytes()),
        "sig_pub_b64": B64.encode(id.sig_pub_bytes()),
    });
    if let Some(mlkem) = id.mlkem_pub_bytes() {
        body["mlkem_pub_b64"] = serde_json::Value::String(B64.encode(mlkem));
    }
    let (st, _j) = post(conn, host, "/v1/recovery/register", body, None).await?;
    match st {
        StatusCode::CREATED => Ok(()),
        StatusCode::CONFLICT => Err(SetupError::AlreadyRegistered),
        other => Err(SetupError::Protocol(format!(
            "recovery register: unexpected status {other}"
        ))),
    }
}

/// Channel-bound one-time recovery login (spec §6): challenge → unwrap the nonce
/// with the recovery private key → sign a channel-bound proof → verify → session
/// token. Returns the admin session token (zeroized on drop).
async fn recovery_login(
    conn: &mut SendRequest<Full<Bytes>>,
    host: &str,
    id: &Identity,
    exporter: &[u8; 32],
) -> Result<Zeroizing<String>, SetupError> {
    let (st, ch) = post(conn, host, "/v1/recovery/challenge", serde_json::json!({}), None).await?;
    if st != StatusCode::OK {
        return Err(SetupError::Protocol(format!("recovery challenge: {st}")));
    }
    let suite = ch["suite"].as_str().unwrap_or_default();
    let server_id = ch["server_id"]
        .as_str()
        .ok_or_else(|| SetupError::Protocol("challenge missing server_id".into()))?
        .to_owned();
    let challenge_id_hex = ch["challenge_id"]
        .as_str()
        .ok_or_else(|| SetupError::Protocol("challenge missing challenge_id".into()))?;
    let challenge_id =
        hex16(challenge_id_hex).ok_or_else(|| SetupError::Protocol("bad challenge_id hex".into()))?;
    let blob = B64
        .decode(
            ch["wrapped_blob_b64"]
                .as_str()
                .ok_or_else(|| SetupError::Protocol("challenge missing wrapped_blob_b64".into()))?,
        )
        .map_err(|_| SetupError::Protocol("bad wrapped_blob_b64".into()))?;

    // Unwrap the nonce. A hybrid (PQ) recovery account → the server wraps with V2,
    // which we open with {enc_secret, mlkem_seed}. This tool always registers a
    // hybrid account, so a non-v2 challenge is a protocol mismatch.
    let ctx = challenge_ctx(&challenge_id);
    if suite != "v2" {
        return Err(SetupError::Protocol(format!(
            "unexpected challenge suite {suite:?} (expected v2 hybrid)"
        )));
    }
    let mlkem_seed = id
        .mlkem_seed()
        .ok_or_else(|| SetupError::Protocol("v2 challenge but recovery identity has no ML-KEM".into()))?;
    let sk = HybridEncSecretKey::from_components(id.enc_secret().expose_bytes(), mlkem_seed);
    let wrapped =
        deserialize_hybrid_wrap(&blob).map_err(|_| SetupError::Protocol("malformed hybrid wrap".into()))?;
    let dek = unwrap_dek_hybrid(&sk, &wrapped, &ctx)
        .map_err(|_| SetupError::Protocol("recovery nonce unwrap failed".into()))?;
    let nonce: Zeroizing<[u8; 32]> = Zeroizing::new(*dek.expose());

    // Channel-bound proof over (server_id, THIS connection's exporter, nonce, ts),
    // signed with the recovery SIGNING key.
    let ts = now_ms();
    let proof_ctx = AuthProofContext {
        server_id: Text::new(&server_id)
            .map_err(|_| SetupError::Protocol("server_id not canonical".into()))?,
        tls_exporter: Bytes32(*exporter),
        nonce: Bytes32(*nonce),
        timestamp: Timestamp(ts),
    };
    let proof = B64.encode(id.signing_key().sign_canonical(labels::AUTH, &proof_ctx));

    let (st, res) = post(
        conn,
        host,
        "/v1/recovery/verify",
        serde_json::json!({
            "challenge_id": challenge_id_hex,
            "proof_b64": proof,
            "timestamp": ts,
        }),
        None,
    )
    .await?;
    if st != StatusCode::OK {
        return Err(SetupError::Protocol(format!("recovery verify rejected: {st}")));
    }
    let token = res["session_token"]
        .as_str()
        .ok_or_else(|| SetupError::Protocol("verify missing session_token".into()))?
        .to_owned();
    Ok(Zeroizing::new(token))
}

/// `POST /v1/registration-keys` under the recovery admin session → the first
/// single-use registration key (plaintext, returned once; zeroized on drop).
async fn mint_first_key(
    conn: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
) -> Result<Zeroizing<String>, SetupError> {
    let (st, res) = post(
        conn,
        host,
        "/v1/registration-keys",
        serde_json::json!({}),
        Some(token),
    )
    .await?;
    if st != StatusCode::CREATED {
        return Err(SetupError::Protocol(format!("mint registration key: {st}")));
    }
    let key = res["registration_key"]
        .as_str()
        .ok_or_else(|| SetupError::Protocol("mint response missing registration_key".into()))?
        .to_owned();
    Ok(Zeroizing::new(key))
}

// ---- cold artifacts ----

/// Argon2id-seal the WHOLE recovery identity (never bare key bytes) with the same
/// `keyblob` the client keystore uses, then write it create-new. The blob is
/// byte-shaped exactly like a client `local_key_blob`, so the cold copy can later be
/// restored as an ordinary keystore.
fn seal_recovery_key(out: &Path, passphrase: &str, id: &Identity) -> Result<(), SetupError> {
    let blob = keyblob::seal(passphrase, id, ARGON2_DESKTOP_TARGET)
        .map_err(|_| SetupError::Io("could not seal recovery key".into()))?;
    write_new(out, &blob)
}

/// Write `bytes` to `path`, creating parent dirs, and FAILING if the file already
/// exists (`create_new`) — closing the tiny race between pre-flight and write.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SetupError::Io(format!("create dir {}: {e}", parent.display())))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| SetupError::Io(format!("write {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| SetupError::Io(format!("write {}: {e}", path.display())))?;
    Ok(())
}

// ---- small helpers ----

/// The WrapContext the server binds a recovery challenge wrap to (spec §6): the
/// challenge_id as `file_id`, version 0, `recipient_id = RECOVERY_ID`.
fn challenge_ctx(challenge_id: &[u8; 16]) -> WrapContext {
    WrapContext {
        file_id: Id(*challenge_id),
        version: 0,
        recipient_id: RECOVERY_ID,
    }
}

/// 32 lowercase-hex chars → 16 bytes; `None` on any non-hex / wrong length.
fn hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
