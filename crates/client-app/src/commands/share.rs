//! Post-upload multi-recipient sharing (T4). `reshare_file` extends READ access to
//! N additional directory-verified recipients for an already-uploaded file, from
//! the running app — no re-upload, no new version. It ties together the merged
//! helpers: the sink-anchored revocation head (`crate::sink`), the authenticated
//! `TombstoneSet` (`crate::revocations`), own-DEK recovery (`crate::download`),
//! third-party recipient resolution (`crate::directory`), and the crypto reshare
//! primitive (`client_core::reshare::build_reshare`).
//!
//! **One `reauth` for the whole batch.** The file view is fetched once, the DEK
//! recovered once, and the `TombstoneSet` built once — up front, as batch-wide
//! prerequisites (a failure of any is a whole-command `Err`, nothing was POSTed).
//! The same `sender`/`token` are then reused for every recipient's directory
//! resolve + wrap POST.
//!
//! **Per-recipient fail isolation (spec §5).** Every entered username yields
//! EXACTLY ONE [`ReshareOutcomeDto`] (never a dropped row); one recipient failing
//! (unresolvable → "untrusted", revoked → "revoked", missing PQ key →
//! "pq_key_missing", transient POST error) never aborts the batch or rolls back
//! the others. Re-sharing is idempotent server-side (`Store::add_wrap` replaces
//! the row), so retrying just the failed rows is always safe.
//!
//! **Identity-borrow discipline (spec §9).** The non-`Clone` `Identity` is borrowed
//! ONLY for the synchronous `recover_own_dek` and each synchronous `build_reshare`
//! (grant signing) — NEVER across an `.await`. The per-recipient loop is structured
//! (async resolve) → (sync borrow: `build_reshare` → `WrapOut`) → (async POST) so
//! the borrow structurally cannot span the resolve or POST awaits.
//!
//! **Seam safety.** Only DTOs cross the Tauri boundary — never a `Dek`, `WrapOut`,
//! `Identity`, or `TombstoneSet`. `SharePhase` event payloads carry only
//! `file_id`/`username`/`ok`/sanitized `code`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;
use tauri::{Emitter, State};

use maxsecu_client_core::{
    build_reshare, DirectoryVerifier, MemoryTrustStore, ReshareError, ReshareParams, TombstoneSet,
    TrustStore, WrapOut,
};
use maxsecu_crypto::{Dek, EncPublicKey};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::Manifest;
use maxsecu_encoding::types::{Id, Suite, Timestamp};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::connection::{open_conn, reauth, server_of};
use crate::commands::feed::{hex, hex16, now_ms};
use crate::config::{load_directory_pub, load_sink_pins};
use crate::directory::VerifiedAuthor;
use crate::download::{parse_file_view, recover_own_dek};
use crate::dto::{
    ReshareOutcomeDto, ReshareRequest, ResolveRecipientRequest, ResolvedRecipientDto,
};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};
use crate::recipients::list_recipients;
use crate::revocations::build_tombstones;
use crate::sink::fetch_anchored_head;
use crate::state::{SharePhase, EVT_RESHARE};
use crate::upload::wrap_wire;

// ---------------------------------------------------------------------------
// reshare_file — the integration crux (T4 Task 8)
// ---------------------------------------------------------------------------

/// `reshare_file` — re-share an already-uploaded file to N additional recipients.
/// One `reauth` for the whole batch; per-recipient fail-isolated; idempotent;
/// fail-closed on every verification step. Emits [`SharePhase`] over
/// [`EVT_RESHARE`]. Returns one [`ReshareOutcomeDto`] per entered username (in
/// request order) — never drops a row.
#[tauri::command]
pub async fn reshare_file(
    req: ReshareRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<ReshareOutcomeDto>, UiError> {
    let emit = |p: SharePhase| {
        let _ = app.emit(EVT_RESHARE, p);
    };
    let outcomes = reshare_inner(&req, &dir, &session, &connect_lock, &emit).await?;
    let shared = outcomes.iter().filter(|o| o.ok).count() as u32;
    let failed = outcomes.len() as u32 - shared;
    emit(SharePhase::Done {
        file_id: req.file_id.clone(),
        shared,
        failed,
    });
    Ok(outcomes)
}

/// The batch-wide prerequisites (spec §4 steps 1–4). A failure of ANY of these is
/// a whole-command `Err` (nothing was POSTed yet). Only the per-recipient steps
/// (delegated to [`run_reshare_batch`]) are fail-isolated.
async fn reshare_inner(
    req: &ReshareRequest,
    dir: &State<'_, AppDir>,
    session: &State<'_, Session>,
    connect_lock: &State<'_, ConnectLock>,
    emit: &impl Fn(SharePhase),
) -> Result<Vec<ReshareOutcomeDto>, UiError> {
    // Validate the REQUESTED id up front (also rejects a malformed id before it is
    // interpolated into a request URL). This is the id `recover_own_dek` binds the
    // self-wrap to (content-substitution defense) — NOT the served manifest id.
    let file_id = hex16(&req.file_id)?;

    // Pinned trust anchors: the D5 directory root and the out-of-band sink pins.
    // Both are batch-wide prerequisites — a missing/malformed pin fails closed.
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();
    let sink_pins = load_sink_pins(&dir.0)?;

    let username = { session.0.lock().await.username.clone() }
        .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    // Step 1: ONE reauth for the whole batch (one channel, one token).
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;

    // Step 2: fetch the file's own view once (same call the viewer makes).
    let (status, view_json) = get_json(
        &mut sender,
        &format!("/v1/files/{}?version=latest", req.file_id),
        Some(&token),
        &host,
    )
    .await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("fetch_failed", "That item is not available."));
    }
    let view = parse_file_view(&view_json)?;
    let manifest: Manifest =
        decode(&view.manifest_bytes).map_err(|_| UiError::new("untrusted", "Malformed record."))?;

    // Resolve MY OWN user id under the pinned D5 (the AUTHENTICATED caller's id) —
    // this is the `recipient_id` the served self-wrap is bound to, and the granter
    // id for the new grants. Never a client-supplied id.
    let my_id = crate::directory::resolve_my_user_id(
        &mut sender,
        &host,
        &username,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // Step 3: recover the DEK from the caller's OWN self-wrap, ONCE. Borrow the
    // identity ONLY for this synchronous call (no await while borrowed).
    let dek = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        recover_own_dek(&view, file_id, identity, my_id)?
    }; // guard drops here — identity no longer borrowed

    // Step 4: fetch the sink-anchored head out of band, then build the authenticated
    // TombstoneSet against it. Both fail CLOSED (a reshare cannot proceed on an
    // unverified revocation state — `build_reshare` takes a mandatory TombstoneSet).
    let anchored_head = fetch_anchored_head(&sink_pins)?;
    let tombstones = build_tombstones(
        &mut sender,
        &host,
        anchored_head,
        &verifier,
        &mut trust,
        now,
    )
    .await?;

    // Steps 5–8: per-recipient resolve → wrap → POST, fail-isolated.
    let outcomes = run_reshare_batch(
        &mut sender,
        &host,
        &token,
        &req.file_id,
        file_id,
        manifest.version,
        manifest.dek_commit.0,
        manifest.alg,
        my_id,
        &dek,
        &tombstones,
        session,
        &req.recipient_usernames,
        &verifier,
        &mut trust,
        now,
        emit,
    )
    .await;

    Ok(outcomes)
}

/// The per-recipient loop (spec §4 steps 5–8, §5 batch isolation). Takes plain,
/// testable arguments (no Tauri `State`) so the batch-isolation contract can be
/// unit-tested against an in-process HTTP stub. Every entered username produces
/// EXACTLY ONE outcome, in order; a per-recipient failure never aborts the batch.
///
/// **Borrow discipline.** `session` (not a raw `&Identity`) is threaded in so the
/// non-`Clone` identity can be RE-borrowed for each synchronous `build_reshare`
/// and released BEFORE the async POST — the loop is (async resolve) → (sync borrow:
/// build) → (async POST), so the borrow never spans an await.
#[allow(clippy::too_many_arguments)]
async fn run_reshare_batch(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    token: &str,
    file_id_hex: &str,
    file_id: [u8; 16],
    version: u64,
    dek_commit: [u8; 32],
    suite: Suite,
    granter_id: [u8; 16],
    dek: &Dek,
    tombstones: &TombstoneSet,
    session: &Session,
    recipients: &[String],
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
    emit: &impl Fn(SharePhase),
) -> Vec<ReshareOutcomeDto> {
    let mut outcomes = Vec::with_capacity(recipients.len());

    for uname in recipients {
        emit(SharePhase::Resolving {
            file_id: file_id_hex.to_owned(),
            username: uname.clone(),
        });

        // (async) Re-resolve + re-verify under the pinned D5 at SHARE-time (TOCTOU
        // closure — never trust the picker's earlier resolve). Fail-closed →
        // per-recipient outcome, never aborts the batch.
        let author =
            match crate::directory::resolve_recipient(sender, host, uname, verifier, trust, now_ms)
                .await
            {
                Ok(a) => a,
                Err(e) => {
                    push_outcome(&mut outcomes, emit, file_id_hex, uname, false, Some(e.code));
                    continue;
                }
            };

        emit(SharePhase::Verifying {
            file_id: file_id_hex.to_owned(),
            username: uname.clone(),
        });
        emit(SharePhase::Wrapping {
            file_id: file_id_hex.to_owned(),
            username: uname.clone(),
        });

        // (sync borrow) Build the wrap+grant. The identity is borrowed ONLY inside
        // this block — it never crosses the POST await below. `build_reshare` is
        // fail-closed (revoked / missing PQ key / recovery sentinel / commitment
        // mismatch), each mapped to a sanitized per-recipient code.
        let built: Result<WrapOut, String> = {
            let guard = session.0.lock().await;
            match guard.identity.as_ref() {
                Some(identity) => {
                    let params = ReshareParams {
                        granter: identity,
                        granter_id: Id(granter_id),
                        file_id: Id(file_id),
                        version,
                        dek_commit,
                        recipient_id: Id(author.user_id),
                        recipient_enc_pub: EncPublicKey::from_bytes(author.enc_pub),
                        suite,
                        recipient_mlkem_pub: author.mlkem_pub,
                        created_at: Timestamp(now_ms),
                    };
                    build_reshare(&params, dek, tombstones)
                        .map_err(|e| reshare_error_code(&e).to_owned())
                }
                None => Err("locked".to_owned()),
            }
        }; // guard drops here — identity no longer borrowed, safe to await

        let wrap = match built {
            Ok(w) => w,
            Err(code) => {
                push_outcome(&mut outcomes, emit, file_id_hex, uname, false, Some(code));
                continue;
            }
        };

        // (async) POST the wrap. A non-201 or transport error is a per-recipient
        // failure, not a batch abort (idempotent server-side → safe to retry).
        let body = wrap_req_body(&wrap);
        let uri = format!("/v1/files/{file_id_hex}/wraps");
        match post_json(sender, &uri, &body, Some(token), host).await {
            Ok((st, _)) if st == hyper::StatusCode::CREATED => {
                push_outcome(&mut outcomes, emit, file_id_hex, uname, true, None);
            }
            Ok(_) => {
                push_outcome(
                    &mut outcomes,
                    emit,
                    file_id_hex,
                    uname,
                    false,
                    Some("share_failed".to_owned()),
                );
            }
            Err(e) => {
                push_outcome(&mut outcomes, emit, file_id_hex, uname, false, Some(e.code));
            }
        }
    }

    outcomes
}

/// Record one recipient's terminal outcome (append to the result Vec AND emit the
/// `Recipient` phase). Centralized so every path produces exactly one row + event.
fn push_outcome(
    outcomes: &mut Vec<ReshareOutcomeDto>,
    emit: &impl Fn(SharePhase),
    file_id_hex: &str,
    username: &str,
    ok: bool,
    code: Option<String>,
) {
    emit(SharePhase::Recipient {
        file_id: file_id_hex.to_owned(),
        username: username.to_owned(),
        ok,
        code: code.clone(),
    });
    outcomes.push(ReshareOutcomeDto {
        username: username.to_owned(),
        ok,
        code,
    });
}

/// Map a [`ReshareError`] to a stable, sanitized per-recipient code (no oracle,
/// no internal detail). Mirrors the spec §4 step 6 mapping.
fn reshare_error_code(e: &ReshareError) -> &'static str {
    match e {
        ReshareError::RecipientRevoked => "revoked",
        ReshareError::ResharePqKeyMissing => "pq_key_missing",
        ReshareError::DekCommitMismatch => "verify_failed",
        ReshareError::RecipientIsRecovery => "recovery_recipient",
        ReshareError::WrapFailed => "wrap_failed",
    }
}

/// Shape one `WrapOut` into the `POST /v1/files/{id}/wraps` body (a single
/// `WrapReq`, api.md §10.1) — the same field shape `upload::stage_body` uses for a
/// `wraps[]` entry. A reshare always targets a USER (never recovery).
fn wrap_req_body(w: &WrapOut) -> serde_json::Value {
    serde_json::json!({
        "recipient_id": hex(&w.recipient_id.0),
        "recipient_type": "user",
        "wrapped_dek_b64": B64.encode(wrap_wire(w)),
        "wrap_alg": 1,
        "granted_by": hex(&w.granted_by.0),
        "grant_b64": B64.encode(maxsecu_encoding::encode(&w.grant)),
        "grant_sig_b64": B64.encode(w.grant_sig),
    })
}

// ---------------------------------------------------------------------------
// resolve_recipient — thin wrapper for the picker (dialog, later task)
// ---------------------------------------------------------------------------

/// `resolve_recipient` — resolve + D5-verify a single third-party username for the
/// share picker. The `GET /v1/directory/{username}` lookup is UNAUTHENTICATED, so
/// this opens a plain pinned channel (no `reauth`). A fail-closed resolve (404 /
/// bad signature / expiry / recovery-sentinel) propagates as `Err(UiError)` — the
/// dialog surfaces the rejection and never adds an unverified row.
///
/// `already_shared` is set to `false` here; the dialog computes it itself by
/// cross-checking the resolved `user_id` against `list_file_recipients`.
#[tauri::command]
pub async fn resolve_recipient(
    req: ResolveRecipientRequest,
    dir: State<'_, AppDir>,
) -> Result<ResolvedRecipientDto, UiError> {
    let pinned = load_directory_pub(&dir.0)?;
    let verifier = DirectoryVerifier::new(pinned);
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exporter) = open_conn(&dir.0, &server).await?;
    let author = crate::directory::resolve_recipient(
        &mut sender,
        &host,
        &req.username,
        &verifier,
        &mut trust,
        now,
    )
    .await?;
    Ok(resolved_recipient_dto(req.username, &author))
}

/// Map a D5-verified [`VerifiedAuthor`] into the picker DTO. `fingerprint` is the
/// first 8 bytes hex (matching the `author_fp` derivation used in the viewer);
/// `already_shared` is `false` (the dialog cross-checks it — see [`resolve_recipient`]).
fn resolved_recipient_dto(username: String, author: &VerifiedAuthor) -> ResolvedRecipientDto {
    ResolvedRecipientDto {
        username,
        user_id: hex(&author.user_id),
        fingerprint: hex(&author.fingerprint[..8]),
        already_shared: false,
    }
}

// ---------------------------------------------------------------------------
// list_file_recipients — thin wrapper for duplicate-awareness (dialog, later task)
// ---------------------------------------------------------------------------

/// `list_file_recipients` — the current recipient `user_id`s (hex) for a file, for
/// the picker's "already has access" note. Owner-only + bearer-authenticated, so
/// it `reauth`s. FAILS OPEN: the underlying `list_recipients` returns an empty set
/// (never an error) for a `404` (no oracle: missing file OR non-owner), any other
/// non-`200`, a transport error, or a malformed body — an empty result reads as
/// "unknown" and never blocks the dialog. A malformed id likewise degrades to
/// empty rather than blocking.
#[tauri::command]
pub async fn list_file_recipients(
    file_id: String,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<String>, UiError> {
    // Fail-open on a malformed id (do not block the dialog with an error).
    if hex16(&file_id).is_err() {
        return Ok(Vec::new());
    }
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, &session, &connect_lock).await?;
    let rows = list_recipients(&mut sender, &file_id, &token, &host).await;
    Ok(rows.iter().map(|r| hex(&r.user_id)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    use crate::commands::auth::SessionInner;
    use maxsecu_client_core::Identity;
    use maxsecu_crypto::{generate_enc_keypair, SigningKey};
    use maxsecu_encoding::structs::DirBinding;
    use maxsecu_encoding::types::{Bytes32, Role, RoleSet, Text};
    use maxsecu_encoding::{encode, labels, GENESIS_HEAD};

    use http_body_util::BodyExt;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    const NOW: u64 = 1_719_500_000_000;
    const GRANTER_ID: [u8; 16] = [0x11; 16];
    const FILE_ID: [u8; 16] = [0xF1; 16];

    fn b64(b: &[u8]) -> String {
        B64.encode(b)
    }

    /// A D5-signed directory binding JSON body (`GET /v1/directory/{username}`
    /// shape) binding `alice` to a real X25519 enc key (so `build_reshare`'s wrap
    /// succeeds against a genuine curve point).
    fn alice_binding(d5: &SigningKey, enc_pub: [u8; 32]) -> String {
        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32(enc_pub),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let sig = d5.sign_canonical(labels::DIRBINDING, &b);
        serde_json::json!({
            "binding_b64": b64(&encode(&b)),
            "directory_signature_b64": b64(&sig),
        })
        .to_string()
    }

    /// An in-process HTTP/1.1 stub answering each request from a fixed
    /// `path -> (status, body)` map (default `404`, empty body). Routes both the
    /// per-recipient `GET /v1/directory/{username}` and the `POST
    /// /v1/files/{id}/wraps` a batch fans out to (mirrors `revocations.rs`'s
    /// `spawn_router`).
    async fn spawn_router(routes: HashMap<String, (hyper::StatusCode, String)>) -> String {
        let routes = Arc::new(routes);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let routes = routes.clone();
                        async move {
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            let resp = match routes.get(&path) {
                                Some((status, body)) => Response::builder()
                                    .status(*status)
                                    .body(Full::<Bytes>::from(body.clone()))
                                    .unwrap(),
                                None => Response::builder()
                                    .status(hyper::StatusCode::NOT_FOUND)
                                    .body(Full::<Bytes>::new(Bytes::new()))
                                    .unwrap(),
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

    fn session_with_identity() -> Session {
        Session(Mutex::new(SessionInner {
            identity: Some(Identity::generate()),
            username: Some("me".to_owned()),
            ..Default::default()
        }))
    }

    fn empty_tombstones() -> TombstoneSet {
        TombstoneSet::verify(&[], GENESIS_HEAD.0).unwrap()
    }

    /// The batch-isolation contract (spec §5, testing plan step 5): a MIXED batch
    /// (one unresolvable username, one valid) returns EXACTLY one `ok:false` + one
    /// `ok:true`, in request order, never aborting the batch nor dropping a row.
    #[tokio::test]
    async fn mixed_batch_is_per_recipient_isolated_never_drops_a_row() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        // A real recipient enc key so the wrap targets a genuine curve point.
        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        let mut routes = HashMap::new();
        // "ghost" is intentionally NOT routed → default 404 → resolve fails closed.
        routes.insert(
            "/v1/directory/alice".to_owned(),
            (
                hyper::StatusCode::OK,
                alice_binding(&d5, alice_pk.to_bytes()),
            ),
        );
        // The wrap POST for this file → 201 (idempotent add_wrap success).
        routes.insert(
            format!("/v1/files/{file_id_hex}/wraps"),
            (hyper::StatusCode::CREATED, "{}".to_owned()),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;

        let recipients = vec!["ghost".to_owned(), "alice".to_owned()];
        let outcomes = run_reshare_batch(
            &mut sender,
            "localhost",
            "tok",
            &file_id_hex,
            FILE_ID,
            1,
            dek.commit(),
            Suite::V1,
            GRANTER_ID,
            &dek,
            &tombstones,
            &session,
            &recipients,
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        // Exactly one row per entered username, in order — never a dropped row.
        assert_eq!(outcomes.len(), 2, "one outcome per entered username");
        assert_eq!(outcomes[0].username, "ghost");
        assert!(
            !outcomes[0].ok,
            "unresolvable recipient fails, per-recipient"
        );
        assert_eq!(outcomes[0].code.as_deref(), Some("untrusted"));
        assert_eq!(outcomes[1].username, "alice");
        assert!(outcomes[1].ok, "the valid recipient still succeeds");
        assert!(outcomes[1].code.is_none(), "success carries no code");
    }

    #[test]
    fn resolved_recipient_dto_maps_fields() {
        let author = VerifiedAuthor {
            user_id: [0xAB; 16],
            sig_pub: [0x51; 32],
            enc_pub: [0xE1; 32],
            fingerprint: [0xFC; 32],
            key_version: 1,
            mlkem_pub: None,
        };
        let dto = resolved_recipient_dto("bob".to_owned(), &author);
        assert_eq!(dto.username, "bob");
        assert_eq!(dto.user_id, "ab".repeat(16));
        // fingerprint is the first 8 bytes hex (matches author_fp elsewhere).
        assert_eq!(dto.fingerprint, "fc".repeat(8));
        assert!(!dto.already_shared);
    }

    #[test]
    fn reshare_error_codes_are_sanitized_and_stable() {
        assert_eq!(
            reshare_error_code(&ReshareError::RecipientRevoked),
            "revoked"
        );
        assert_eq!(
            reshare_error_code(&ReshareError::ResharePqKeyMissing),
            "pq_key_missing"
        );
        assert_eq!(
            reshare_error_code(&ReshareError::DekCommitMismatch),
            "verify_failed"
        );
        assert_eq!(
            reshare_error_code(&ReshareError::RecipientIsRecovery),
            "recovery_recipient"
        );
        assert_eq!(reshare_error_code(&ReshareError::WrapFailed), "wrap_failed");
    }
}
