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
use maxsecu_client_core::{keyblob, password, seedblob, Identity, ARGON2_DESKTOP_TARGET};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, parse_delegation, pin_fingerprint, sign_delegation, unwrap_dek_hybrid,
    HybridEncSecretKey, SigningKey,
};
use maxsecu_encoding::labels;
use maxsecu_encoding::structs::{AuthProofContext, WrapContext};
use maxsecu_encoding::types::{Bytes32, Id, Text, Timestamp};
use maxsecu_encoding::RECOVERY_ID;

/// The offline-D5 delegation window: 90 days (spec §2/§7).
const DELEGATION_WINDOW_SECS: u64 = 90 * 86_400;

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
    /// The offline-D5 ceremony report, if the ceremony ran (a delegation token was
    /// supplied). `None` for a legacy/no-ceremony run.
    pub ceremony: Option<CeremonyReport>,
}

/// Outcome of the offline-D5 ceremony (spec §§6,7): the admin-minted user-facing
/// connection code plus where the D5 custody artifacts landed.
#[derive(Debug, Clone)]
pub struct CeremonyReport {
    /// The user-facing connection code `addr:port#pin_fingerprint(server_cert,
    /// d5_pub)` (the inversion — the admin PC mints it, spec §6).
    pub connection_code: String,
    /// The pinned D5 (directory) public key, written to `directory_pub.der`.
    pub d5_pub: [u8; 32],
    /// Where the sealed at-rest D5 landed (`d5_key.blob`).
    pub d5_out: PathBuf,
    /// Where the D5 recovery backup landed (`d5_recovery.blob`, same passphrase as
    /// `recovery_key.blob`).
    pub d5_recovery_out: PathBuf,
    /// Where the local `directory_pub.der` pin landed.
    pub dir_pub_out: PathBuf,
    /// The delegation window end (unix seconds).
    pub valid_until: u64,
}

/// Inputs to the offline-D5 ceremony (spec §7). Present in [`SetupOpts::ceremony`]
/// only for a Prod install; when absent, [`run`] does the legacy recovery-only
/// bootstrap unchanged.
pub struct CeremonyOpts {
    /// The one-time bootstrap delegation token (printed by `install-server.sh`;
    /// `SETUP_DELEGATION_TOKEN`). Burned by a successful `POST /bootstrap/delegation`.
    pub token: Zeroizing<String>,
    /// The pinned server cert DER bytes — hashed into the connection code and the
    /// TLS pin. (Same bytes the pinned [`Transport`] was built from.)
    pub server_cert: Vec<u8>,
    /// The `addr:port` the connection code advertises (what a user dials). Defaults
    /// to the dial target but may differ (e.g. a public address vs a local map).
    pub connect_addr: String,
    /// Sealed at-rest D5 output (`d5_key.blob`). Create-new; never clobbered.
    pub d5_out: PathBuf,
    /// D5 recovery backup output (`d5_recovery.blob`), sealed under the SAME setup
    /// passphrase as `recovery_key.blob`. Create-new.
    pub d5_recovery_out: PathBuf,
    /// Local `directory_pub.der` pin output (the client's pinned D5). Create-new.
    pub dir_pub_out: PathBuf,
}

/// Inputs to [`run`]. Paths must NOT already exist (fail-closed: never clobber a
/// prior recovery blob / pin / key). `host` is the TLS SNI + HTTP `Host` header.
pub struct SetupOpts {
    pub host: String,
    pub out: PathBuf,
    pub pin_out: PathBuf,
    pub first_key_out: PathBuf,
    /// Passphrase that seals the recovery `local_key_blob` AND (when the ceremony
    /// runs) the D5 seed blobs — the only passphrase available at ceremony time.
    /// Zeroized on drop.
    pub passphrase: Zeroizing<String>,
    /// The offline-D5 ceremony inputs (spec §7). `Some` for a Prod install (a
    /// delegation token was supplied); `None` for the legacy recovery-only path.
    pub ceremony: Option<CeremonyOpts>,
}

/// Everything that can stop the bootstrap. [`SetupError::AlreadyRegistered`] is the
/// only variant that maps to a distinct (non-1) exit code — it is the expected
/// "run me only once" outcome, not a fault.
#[derive(Debug)]
pub enum SetupError {
    /// `POST /v1/recovery/register` returned 409: the server already has a recovery
    /// account. NOTHING is written; the caller exits non-zero.
    AlreadyRegistered,
    /// `POST /v1/bootstrap/delegation` returned 409 (NotAwaiting): the server is
    /// ALREADY delegated. NOTHING is written — we refuse to generate a fresh
    /// (mismatched) D5 or print a wrong connection code. Mirrors the
    /// [`AlreadyRegistered`](Self::AlreadyRegistered) "already done" exit-3 posture.
    AlreadyDelegated,
    /// `POST /v1/bootstrap/delegation` returned 403: the one-time token was wrong.
    /// NOTHING is written; re-runnable with the correct token.
    DelegationBadToken,
    /// `POST /v1/bootstrap/delegation` returned 400: the server rejected the cert
    /// (bad signature / window / op-key). NOTHING is written.
    DelegationBadCert,
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
            SetupError::AlreadyDelegated => write!(
                f,
                "the server is already delegated (bootstrap 409 NotAwaiting); nothing was written"
            ),
            SetupError::DelegationBadToken => write!(
                f,
                "the one-time delegation token was rejected (403); nothing was written"
            ),
            SetupError::DelegationBadCert => write!(
                f,
                "the server rejected the delegation certificate (400); nothing was written"
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
/// Ordering matters for two contracts:
///   * "409 writes nothing" — all pre-flight guards run FIRST (no network, no key
///     material touched), and NOTHING is written to disk before `register` commits,
///     so a 409 (or any earlier failure) leaves the operator's paths untouched.
///   * "the once-only register never orphans the recovery key" — the pure-CPU
///     Argon2id seal is computed BEFORE `register`, so a seal/OOM/CPU failure surfaces
///     PRE-commit (still zero disk writes). Only AFTER register + mint succeed are the
///     three cold artifacts written; if a post-commit write then fails, an EMERGENCY
///     block (base64 sealed blob + first key) is dumped to stderr so the irreplaceable
///     material is never lost, and the call still returns an error.
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

    // (2) Compute the sealed recovery blob NOW (pure CPU: Argon2id + AEAD), BEFORE the
    // once-only register commits. A seal / OOM / CPU failure here fails the whole run
    // with nothing on disk and nothing committed server-side, so a re-run is clean. The
    // bytes are held (Zeroizing) until the post-register write. Also precompute the pin.
    let sealed = seal_recovery_blob(opts.passphrase.as_str(), &recovery)?;
    let pin = canonical_pin(&enc_pub, mlkem_pub.as_ref().map(|m| &m[..]));

    // (2b) Offline-D5 ceremony pre-compute (pure CPU): generate the D5 root, seal it
    // at rest AND into the recovery backup (both under the setup passphrase — the
    // only one available), and precompute the connection code. Nothing is uploaded
    // or written yet; the sealed blobs are held until the post-commit write. `None`
    // when no delegation token was supplied (legacy recovery-only path).
    let d5 = match &opts.ceremony {
        Some(c) => Some(precompute_d5(opts.passphrase.as_str(), c)?),
        None => None,
    };

    // (3) One pinned-TLS connection for the whole flow: the recovery challenge/verify
    // are channel-bound to THIS connection's RFC-5705 exporter, so they must share it.
    let (mut conn, exporter) = open(t).await?;

    // (3b) CEREMONY (spec §7: BEFORE the recovery-account setup). Fetch the server's
    // operational key, sign the 90-day delegation over it with D5, and upload it with
    // the one-time token. A successful POST burns the token (the point of no return
    // for the ceremony). 403/409/400 → a clear error with NOTHING written; in
    // particular a 409 (already delegated) stops us cold rather than minting a wrong
    // connection code for a mismatched, freshly-generated D5.
    let mut ceremony_valid_until = 0u64;
    if let Some(c) = &opts.ceremony {
        let d5 = d5.as_ref().expect("ceremony ⇒ d5 precomputed");
        ceremony_valid_until =
            upload_delegation(&mut conn, &opts.host, &c.token, &d5.d5, &d5.d5_pub).await?;
    }

    // (4) Register the recovery PUBLIC keys. 409 → already registered → write nothing.
    register(&mut conn, &opts.host, &recovery).await?;

    // (5) Log in AS the recovery account (channel-bound challenge/response) → an
    // admin session token.
    let token = recovery_login(&mut conn, &opts.host, &recovery, &exporter).await?;

    // (6) Mint the FIRST registration key with the recovery admin session. Whoever
    // enrolls with it first becomes admin via the server's atomic first-admin claim.
    let first_key = mint_first_key(&mut conn, &opts.host, &token).await?;

    // (7) Write the cold artifacts — only now that the delegation + register + mint
    // committed. These commits are IRREVERSIBLE (a re-run 409s), so a write failure
    // here would otherwise strand irreplaceable material. On ANY write error, dump an
    // emergency recovery block (incl. the sealed D5) to stderr before returning.
    if let Err(e) = write_all_artifacts(opts, &sealed, &pin, first_key.as_str(), d5.as_ref()) {
        emergency_dump(&sealed, first_key.as_str(), d5.as_ref());
        return Err(e);
    }
    // `sealed` (Zeroizing<Vec<u8>>) is dropped/zeroized here on the success path.

    Ok(SetupReport {
        recovery_enc_pub: enc_pub,
        hybrid: mlkem_pub.is_some(),
        out: opts.out.clone(),
        pin_out: opts.pin_out.clone(),
        first_key_out: opts.first_key_out.clone(),
        ceremony: d5.map(|d| {
            d.report(
                opts.ceremony.as_ref().expect("d5 ⇒ ceremony opts"),
                ceremony_valid_until,
            )
        }),
    })
}

// ---- pre-flight ----

fn preflight(opts: &SetupOpts) -> Result<(), SetupError> {
    password::check(opts.passphrase.as_str())
        .map_err(|_| SetupError::Precheck("recovery seal passphrase is too weak".into()))?;
    let mut paths: Vec<&Path> = vec![&opts.out, &opts.pin_out, &opts.first_key_out];
    if let Some(c) = &opts.ceremony {
        paths.push(&c.d5_out);
        paths.push(&c.d5_recovery_out);
        paths.push(&c.dir_pub_out);
    }
    for p in paths {
        if p.exists() {
            return Err(SetupError::Precheck(format!(
                "output path already exists (refusing to overwrite): {}",
                p.display()
            )));
        }
    }
    Ok(())
}

// ---- offline-D5 ceremony ----

/// The pre-computed, held-in-memory ceremony state: the D5 signing key (to sign the
/// delegation once we learn the op-key), its public half, the two sealed D5 blobs
/// (at-rest + backup, both under the setup passphrase), and the connection code.
struct PrecomputedD5 {
    d5: SigningKey,
    d5_pub: [u8; 32],
    /// Sealed at-rest D5 seed (`d5_key.blob`).
    sealed_at_rest: Zeroizing<Vec<u8>>,
    /// Sealed D5 seed backup (`d5_recovery.blob`), SAME passphrase as recovery.
    sealed_backup: Zeroizing<Vec<u8>>,
    /// `addr:port#pin_fingerprint(server_cert, d5_pub)`.
    connection_code: String,
}

impl PrecomputedD5 {
    fn report(&self, c: &CeremonyOpts, valid_until: u64) -> CeremonyReport {
        CeremonyReport {
            connection_code: self.connection_code.clone(),
            d5_pub: self.d5_pub,
            d5_out: c.d5_out.clone(),
            d5_recovery_out: c.d5_recovery_out.clone(),
            dir_pub_out: c.dir_pub_out.clone(),
            valid_until,
        }
    }
}

/// Pure-CPU ceremony pre-compute: generate D5, seal it at rest + as a backup (both
/// under `passphrase`), and derive the connection code from the pinned cert + D5
/// pub. No network, no disk. A seal failure surfaces here (nothing committed).
fn precompute_d5(passphrase: &str, c: &CeremonyOpts) -> Result<PrecomputedD5, SetupError> {
    let d5 = SigningKey::generate();
    let d5_pub = d5.verifying_key().to_bytes();
    let seed = Zeroizing::new(d5.to_seed());
    let sealed_at_rest = seedblob::seal_seed(passphrase, &seed, ARGON2_DESKTOP_TARGET)
        .map_err(|_| SetupError::Io("could not seal the D5 key".into()))?;
    // Fresh salt/nonce per seal → the backup differs byte-wise from the at-rest blob
    // but recovers the SAME seed under the same passphrase.
    let sealed_backup = seedblob::seal_seed(passphrase, &seed, ARGON2_DESKTOP_TARGET)
        .map_err(|_| SetupError::Io("could not seal the D5 backup".into()))?;
    let connection_code = format!(
        "{}#{}",
        c.connect_addr,
        pin_fingerprint(&c.server_cert, &d5_pub)
    );
    Ok(PrecomputedD5 {
        d5,
        d5_pub,
        sealed_at_rest: Zeroizing::new(sealed_at_rest),
        sealed_backup: Zeroizing::new(sealed_backup),
        connection_code,
    })
}

/// The ceremony network step (spec §7): GET the server's operational public key,
/// sign a fresh 90-day delegation over it with D5, and POST it with the one-time
/// token. Maps the server's status codes to the typed ceremony errors.
async fn upload_delegation(
    conn: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    d5: &SigningKey,
    d5_pub: &[u8; 32],
) -> Result<u64, SetupError> {
    // (a) operational key.
    let (st, res) = get(conn, host, "/v1/bootstrap/operational-key").await?;
    if st != StatusCode::OK {
        return Err(SetupError::Protocol(format!(
            "GET operational-key: unexpected status {st} \
             (is the server running the delegation model?)"
        )));
    }
    let op_pub: [u8; 32] = res["operational_pub_b64"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            SetupError::Protocol("operational-key: missing/bad operational_pub_b64".into())
        })?;

    // (b) sign the delegation over the op-key for [now, now+90d] (unix SECONDS).
    let now = now_secs();
    let valid_until = now + DELEGATION_WINDOW_SECS;
    let cert = sign_delegation(d5, &op_pub, now, valid_until);

    // (c) upload with the one-time token (TOFU-pins our D5 server-side).
    let (st, _res) = post(
        conn,
        host,
        "/v1/bootstrap/delegation",
        serde_json::json!({
            "token": token,
            "directory_pub_b64": B64.encode(d5_pub),
            "delegation_cert_b64": B64.encode(&cert),
        }),
        None,
    )
    .await?;
    match st {
        StatusCode::CREATED => Ok(valid_until),
        StatusCode::FORBIDDEN => Err(SetupError::DelegationBadToken),
        StatusCode::CONFLICT => Err(SetupError::AlreadyDelegated),
        StatusCode::BAD_REQUEST => Err(SetupError::DelegationBadCert),
        other => Err(SetupError::Protocol(format!(
            "bootstrap delegation: unexpected status {other}"
        ))),
    }
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

/// `GET uri` over the pinned connection, returning `(status, json)`.
async fn get(
    s: &mut SendRequest<Full<Bytes>>,
    host: &str,
    uri: &str,
) -> Result<(StatusCode, serde_json::Value), SetupError> {
    s.ready()
        .await
        .map_err(|e| SetupError::Network(e.to_string()))?;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", host)
        .body(Full::new(Bytes::new()))
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
    let (st, ch) = post(
        conn,
        host,
        "/v1/recovery/challenge",
        serde_json::json!({}),
        None,
    )
    .await?;
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
    let challenge_id = hex16(challenge_id_hex)
        .ok_or_else(|| SetupError::Protocol("bad challenge_id hex".into()))?;
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
    let mlkem_seed = id.mlkem_seed().ok_or_else(|| {
        SetupError::Protocol("v2 challenge but recovery identity has no ML-KEM".into())
    })?;
    let sk = HybridEncSecretKey::from_components(id.enc_secret().expose_bytes(), mlkem_seed);
    let wrapped = deserialize_hybrid_wrap(&blob)
        .map_err(|_| SetupError::Protocol("malformed hybrid wrap".into()))?;
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
        return Err(SetupError::Protocol(format!(
            "recovery verify rejected: {st}"
        )));
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
/// `keyblob` the client keystore uses, returning the sealed BYTES (held `Zeroizing`).
/// The blob is byte-shaped exactly like a client `local_key_blob`, so the cold copy
/// can later be restored as an ordinary keystore. Pure CPU (no I/O): computed BEFORE
/// the once-only register so a seal failure never orphans a committed recovery key.
fn seal_recovery_blob(passphrase: &str, id: &Identity) -> Result<Zeroizing<Vec<u8>>, SetupError> {
    let blob = keyblob::seal(passphrase, id, ARGON2_DESKTOP_TARGET)
        .map_err(|_| SetupError::Io("could not seal recovery key".into()))?;
    Ok(Zeroizing::new(blob))
}

/// Write the cold artifacts create-new. Called ONLY after the delegation + register
/// + mint have committed. When the ceremony ran, ALSO writes the three D5 custody
/// artifacts (sealed at-rest D5, sealed backup, and the local `directory_pub.der`
/// pin). On the first failure, returns the error (the caller then emergency-dumps).
fn write_all_artifacts(
    opts: &SetupOpts,
    sealed: &[u8],
    pin: &[u8],
    first_key: &str,
    d5: Option<&PrecomputedD5>,
) -> Result<(), SetupError> {
    write_new(&opts.out, sealed)?;
    write_new(&opts.pin_out, pin)?;
    write_new(&opts.first_key_out, first_key.as_bytes())?;
    if let (Some(c), Some(d5)) = (&opts.ceremony, d5) {
        // The pin the client trusts is the raw 32-byte D5 public key.
        write_new(&c.dir_pub_out, &d5.d5_pub)?;
        write_new(&c.d5_out, &d5.sealed_at_rest)?;
        write_new(&c.d5_recovery_out, &d5.sealed_backup)?;
    }
    Ok(())
}

/// Last-resort recovery of the two IRREPLACEABLE secrets when a post-commit write
/// fails. The sealed blob is passphrase-encrypted (safe-ish to print); the first key is
/// a bootstrap secret dumped only because register/mint already committed and a re-run
/// 409s. NEVER prints the passphrase or any bare private key. The pin is omitted (it is
/// recomputable from the sealed blob).
fn emergency_dump(sealed: &[u8], first_key: &str, d5: Option<&PrecomputedD5>) {
    let bar = "!".repeat(72);
    eprintln!();
    eprintln!("{bar}");
    eprintln!("!!!  EMERGENCY: SETUP COMMITTED SERVER-SIDE BUT COULD NOT WRITE FILES  !!!");
    eprintln!("{bar}");
    eprintln!();
    eprintln!("The recovery account is REGISTERED and the first registration key is MINTED,");
    eprintln!("but one or more artifact files could NOT be written to disk. These values are");
    eprintln!("IRREPLACEABLE and re-running this tool will 409. SAVE THEM NOW, BY HAND.");
    eprintln!();
    eprintln!("--- SEALED RECOVERY KEY BLOB (base64; passphrase-encrypted, == the --out file) ---");
    eprintln!("Recreate with e.g.:  echo '<line-below>' | base64 -d > recovery_key_blob");
    eprintln!("{}", B64.encode(sealed));
    eprintln!();
    eprintln!("--- FIRST REGISTRATION KEY (bootstrap secret; whoever enrolls FIRST is admin) ---");
    eprintln!("{first_key}");
    eprintln!();
    if let Some(d5) = d5 {
        // The delegation is already installed server-side; the D5 root is now the
        // directory authority. It is sealed under the setup passphrase, so it is
        // safe-ish to print — losing it means clients can never be re-pinned.
        eprintln!("--- SEALED D5 ROOT (base64; passphrase-encrypted, == the d5_key.blob file) ---");
        eprintln!("Recreate with e.g.:  echo '<line-below>' | base64 -d > d5_key.blob");
        eprintln!("{}", B64.encode(&d5.sealed_at_rest));
        eprintln!();
        eprintln!("--- CONNECTION CODE (public; hand this to users) ---");
        eprintln!("{}", d5.connection_code);
        eprintln!();
    }
    eprintln!("(The recovery_pin.bin + directory_pub.der are NOT dumped — recomputable from the");
    eprintln!(" sealed blobs above.)");
    eprintln!("{bar}");
    eprintln!();
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

/// Unix SECONDS (the delegation window's unit).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---- D5 restore (spec §7) ----

/// Inputs to [`restore`]: rebuild the D5 custody + connection code on a NEW admin
/// PC from the recovery backup. No network; no delegation upload (the server keeps
/// the delegation it already has — the SAME directory root, so no client re-pin).
pub struct RestoreOpts {
    /// The recovery passphrase (the same one that sealed `d5_recovery.blob`).
    pub passphrase: Zeroizing<String>,
    /// The `d5_recovery.blob` backup to restore from (input; must exist).
    pub d5_recovery_in: PathBuf,
    /// The pinned server cert DER bytes (for the connection code + TLS pin).
    pub server_cert: Vec<u8>,
    /// The `addr:port` the connection code advertises.
    pub connect_addr: String,
    /// Where to write the re-established at-rest seal (`d5_key.blob`). Create-new.
    pub d5_out: PathBuf,
    /// Where to write the local `directory_pub.der` pin. Create-new.
    pub dir_pub_out: PathBuf,
}

/// What [`restore`] produced.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub connection_code: String,
    pub d5_pub: [u8; 32],
    pub d5_out: PathBuf,
    pub dir_pub_out: PathBuf,
}

/// Restore the offline-D5 root from the recovery backup onto a new admin PC (spec
/// §7). Unseal the backup → re-derive `d5_pub` → write `directory_pub.der` +
/// re-seal the at-rest `d5_key.blob` → print the SAME connection code. Does NOT
/// re-run the delegation upload: the server already holds a valid delegation for
/// this exact D5, so nothing needs to change server-side and no client re-pins.
pub fn restore(opts: &RestoreOpts) -> Result<RestoreReport, SetupError> {
    // Never clobber existing outputs (same fail-closed posture as `preflight`).
    password::check(opts.passphrase.as_str())
        .map_err(|_| SetupError::Precheck("recovery passphrase is too weak".into()))?;
    for p in [&opts.d5_out, &opts.dir_pub_out] {
        if p.exists() {
            return Err(SetupError::Precheck(format!(
                "output path already exists (refusing to overwrite): {}",
                p.display()
            )));
        }
    }
    let backup = std::fs::read(&opts.d5_recovery_in).map_err(|e| {
        SetupError::Io(format!(
            "read D5 backup {}: {e}",
            opts.d5_recovery_in.display()
        ))
    })?;
    let seed = seedblob::unseal_seed(opts.passphrase.as_str(), &backup).map_err(|e| {
        SetupError::Precheck(format!(
            "could not unseal the D5 backup (wrong passphrase or corrupt file): {e}"
        ))
    })?;
    let d5 = SigningKey::from_seed(&seed);
    let d5_pub = d5.verifying_key().to_bytes();

    // Re-establish the at-rest seal (fresh salt/nonce), then write both create-new.
    let sealed_at_rest =
        seedblob::seal_seed(opts.passphrase.as_str(), &seed, ARGON2_DESKTOP_TARGET)
            .map_err(|_| SetupError::Io("could not re-seal the D5 key".into()))?;
    write_new(&opts.dir_pub_out, &d5_pub)?;
    write_new(&opts.d5_out, &sealed_at_rest)?;

    let connection_code = format!(
        "{}#{}",
        opts.connect_addr,
        pin_fingerprint(&opts.server_cert, &d5_pub)
    );
    Ok(RestoreReport {
        connection_code,
        d5_pub,
        d5_out: opts.d5_out.clone(),
        dir_pub_out: opts.dir_pub_out.clone(),
    })
}

// ---- offline-D5 delegation renewal (spec §7 "Manual fallback") ----

/// Inputs to [`renew`] — the robust, unattended `renew-delegation` path. All via
/// arg/env for the install scripts. Both the D5 root AND the recovery key are
/// sealed under the SAME `passphrase` (the recovery passphrase): the D5 SIGNS the
/// fresh delegation, and the recovery identity LOGS IN to obtain the admin session
/// that `POST /v1/admin/delegation` requires (the recovery principal is a
/// bindingless admin, spec §6).
pub struct RenewOpts {
    /// TLS SNI + HTTP `Host` header (mirrors [`SetupOpts::host`]).
    pub host: String,
    /// The recovery passphrase; unseals BOTH the D5 blob and the recovery key blob.
    /// Zeroized on drop.
    pub passphrase: Zeroizing<String>,
    /// The sealed at-rest D5 root (`d5_key.blob`) to sign the renewal with.
    pub d5_in: PathBuf,
    /// The sealed recovery key blob (`recovery_key.blob`) used to mint the admin
    /// session (recovery-login). Same passphrase as `d5_in`.
    pub recovery_in: PathBuf,
    /// Renew regardless of the 21-day threshold (`--force`).
    pub force: bool,
}

/// What [`renew`] did: a no-op (already outside the renew threshold) or a fresh
/// 90-day delegation installed. Either is a SUCCESS (exit 0); only faults error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewOutcome {
    /// Not within the 21-day threshold and `--force` not set — nothing changed.
    NotDue { valid_until: u64 },
    /// A fresh 90-day delegation was signed and installed. Carries the new
    /// `valid_until` (unix seconds).
    Renewed { valid_until: u64 },
}

/// Renew the directory delegation against `t` (a pinned-TLS transport). Unseal D5 +
/// recovery → recovery-login → read the current `valid_until` → apply the 21-day
/// threshold ([`is_due`]) → if due, sign a fresh 90-day delegation for the server's
/// current operational key and push it via the admin-gated `POST /v1/admin/delegation`.
///
/// Fail-closed and non-destructive: NOTHING on disk is touched. A failure exits
/// non-zero but corrupts nothing (the existing server-side delegation stands). A
/// not-due run is a clean no-op.
pub async fn renew(t: &Transport, opts: &RenewOpts) -> Result<RenewOutcome, SetupError> {
    use maxsecu_client_app::commands::renew::{is_due, sign_renewal};

    // (1) Unseal the D5 root (signer) and the recovery identity (admin login). Both
    //     under the recovery passphrase. A wrong passphrase / corrupt blob fails
    //     closed here, before any network — nothing is written, ever.
    let d5_blob = std::fs::read(&opts.d5_in)
        .map_err(|e| SetupError::Io(format!("read D5 blob {}: {e}", opts.d5_in.display())))?;
    let seed = seedblob::unseal_seed(opts.passphrase.as_str(), &d5_blob).map_err(|e| {
        SetupError::Precheck(format!(
            "could not unseal the D5 key (wrong passphrase or corrupt file): {e}"
        ))
    })?;
    let d5 = SigningKey::from_seed(&seed);

    let rec_blob = std::fs::read(&opts.recovery_in).map_err(|e| {
        SetupError::Io(format!(
            "read recovery key blob {}: {e}",
            opts.recovery_in.display()
        ))
    })?;
    let recovery = keyblob::unlock(opts.passphrase.as_str(), &rec_blob).map_err(|e| {
        SetupError::Precheck(format!(
            "could not unseal the recovery key (wrong passphrase or corrupt file): {e}"
        ))
    })?;

    // (2) One pinned-TLS connection: recovery-login is channel-bound, so the admin
    //     session and the renewal POST must share it.
    let (mut conn, exporter) = open(t).await?;
    let token = recovery_login(&mut conn, &opts.host, &recovery, &exporter).await?;

    // (3) Read the current delegation to learn valid_until (404 ⇒ nothing to renew).
    let (st, doc) = get(&mut conn, &opts.host, "/v1/bootstrap/delegation").await?;
    match st {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => {
            return Err(SetupError::Protocol(
                "the server holds no delegation to renew (awaiting bootstrap or legacy)".into(),
            ))
        }
        other => {
            return Err(SetupError::Protocol(format!(
                "GET delegation: unexpected status {other}"
            )))
        }
    }
    let cert = doc["delegation_cert_b64"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .ok_or_else(|| SetupError::Protocol("delegation doc missing/bad delegation_cert_b64".into()))?;
    let valid_until = parse_delegation(&cert)
        .map_err(|_| SetupError::Protocol("server sent a malformed delegation cert".into()))?
        .valid_until();

    // (4) Threshold. Not due (and not forced) ⇒ a clean no-op, exit 0.
    let now = now_secs();
    if !is_due(valid_until, now, opts.force) {
        return Ok(RenewOutcome::NotDue { valid_until });
    }

    // (5) The server's current operational key — the renewal MUST authorize it (the
    //     server rejects a delegation for any other op-key: op-rotation is out of scope).
    let (st, res) = get(&mut conn, &opts.host, "/v1/bootstrap/operational-key").await?;
    if st != StatusCode::OK {
        return Err(SetupError::Protocol(format!(
            "GET operational-key: unexpected status {st}"
        )));
    }
    let op_pub: [u8; 32] = res["operational_pub_b64"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            SetupError::Protocol("operational-key: missing/bad operational_pub_b64".into())
        })?;

    // (6) Sign a fresh 90-day delegation and push it admin-authenticated.
    let (renewal, new_valid_until) = sign_renewal(&d5, &op_pub, now);
    let (st, _res) = post(
        &mut conn,
        &opts.host,
        "/v1/admin/delegation",
        serde_json::json!({ "delegation_cert_b64": B64.encode(&renewal) }),
        Some(token.as_str()),
    )
    .await?;
    match st {
        StatusCode::OK => Ok(RenewOutcome::Renewed {
            valid_until: new_valid_until,
        }),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(SetupError::Protocol(
            "admin authorization rejected by the server (401/403)".into(),
        )),
        StatusCode::CONFLICT => Err(SetupError::Protocol(
            "the server is not delegated — nothing to renew (409)".into(),
        )),
        StatusCode::BAD_REQUEST => Err(SetupError::DelegationBadCert),
        other => Err(SetupError::Protocol(format!(
            "admin delegation renewal: unexpected status {other}"
        ))),
    }
}
