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
//! never aborts the batch or rolls back the others. The sanitized per-recipient
//! failure codes are: "untrusted" (unresolvable / bad binding), "revoked",
//! "pq_key_missing", "verify_failed" (DEK-commitment mismatch), "recovery_recipient",
//! "wrap_failed", "share_failed" (a non-201 POST), "key_changed" (the recipient's
//! TOFU-pinned key CHANGED and was NOT user-confirmed — trust-alarm B,
//! [`crate::tofu`]; the outcome carries the old + new short fingerprints), "locked"
//! (the identity was momentarily absent mid-batch — see [`run_reshare_batch`]), or a
//! transport error code. Re-sharing is idempotent server-side (`Store::add_wrap` replaces the row),
//! so retrying just the failed rows is always safe.
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
use maxsecu_encoding::structs::{BundleBody, Manifest};
use maxsecu_encoding::types::{Id, Suite, Timestamp};

use crate::commands::auth::{AppDir, ConnectLock, Session};
use crate::commands::bundle::open_bundle_members;
use crate::commands::connection::{open_conn, reauth, server_of};
use crate::commands::feed::{hex, hex16, now_ms};
use crate::config::{load_directory_pub, load_sink_pins_opt};
use crate::directory::VerifiedAuthor;
use crate::download::{parse_file_view, recover_own_dek};
use crate::dto::{
    ContactDto, ReshareOutcomeDto, ReshareRequest, ResolveRecipientRequest,
    ResolvedRecipientDto,
};
use crate::error::UiError;
use crate::http_client::{get_json, post_json};
use crate::recipients::list_recipients;
use crate::revocations::build_tombstones;
use crate::sink::fetch_anchored_head;
use crate::state::{SharePhase, EVT_RESHARE};
use crate::tofu::{TofuOutcome, TofuStore};
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
    // `reshare_inner` emits the terminal `Done` for `req.file_id` itself (right
    // where the batch that produced this file's tray progress finished), so the
    // row always finalizes. Nothing more to emit here.
    reshare_inner(&req, &dir, &session, &connect_lock, &emit).await
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

    // Pinned trust anchors: the D5 directory root (a batch-wide prerequisite — a
    // missing/malformed pin fails closed). The sink is OPT-IN and loaded lazily at
    // step 4 (see `load_sink_pins_opt` below).
    let pinned = load_directory_pub(&dir.0)?;
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();

    let username = { session.0.lock().await.username.clone() }
        .ok_or_else(|| UiError::new("locked", "Sign in first."))?;

    // Step 1: ONE reauth for the whole batch (one channel, one token).
    let server = server_of(&dir.0)?;
    let (mut sender, host, token) = reauth(&dir.0, &server, session, connect_lock).await?;
    // Offline-D5 hop (spec §3/§7): resolve the effective directory verifier over the
    // pinned connection; fail closed on a bad delegation before any binding is trusted.
    let verifier =
        crate::directory::build_delegated_verifier(&mut sender, &host, pinned, now).await?;

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
    // NOTE: we decode the manifest but do NOT independently re-verify `manifest_sig`
    // here. That is safe by construction: every manifest field this flow consumes is
    // cryptographically pinned downstream — `version`/`alg`/`dek_commit` are all bound
    // into the AEAD-`WrapContext` + `dek.commit()` self-check inside `recover_own_dek`
    // (a forged manifest cannot open the real self-wrap), and the new grants are signed
    // over the REQUESTED `file_id` (below), never the served `manifest.file_id`. A
    // malicious server can therefore only deny service, not redirect the DEK or forge a
    // grant that survives the recipient's own grant-chain verification on download.
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

    // Step 3: recover the DEK from the caller's OWN self-wrap, ONCE, and open the
    // identity-sealed TOFU pin store (alarm-B). Borrow the identity ONLY for these
    // synchronous calls (no await while borrowed) — the store keeps only its derived
    // sealing key, never the identity, so it can outlive the guard.
    let (dek, mut tofu, mut contacts) = {
        let guard = session.0.lock().await;
        let identity = guard
            .identity
            .as_ref()
            .ok_or_else(|| UiError::new("locked", "Unlock your keystore first."))?;
        let dek = recover_own_dek(&view, file_id, identity, my_id)?;
        let tofu = TofuStore::open(&dir.0, identity)?;
        // Best-effort: a corrupt/unreadable contacts roster (UX-only) must NEVER
        // block a share — degrade to no recording, unlike the fail-closed TOFU open.
        let contacts = crate::contacts::ContactStore::open(&dir.0, identity).ok();
        (dek, tofu, contacts)
    }; // guard drops here — identity no longer borrowed

    // Step 4: build the authenticated TombstoneSet. The sink is OPT-IN: when one is
    // pinned, fetch its anchored head out of band and verify the served set reaches
    // it; when none is pinned, pass `None` so the set is verified UNANCHORED. Both
    // fail CLOSED (a reshare cannot proceed on an unverified revocation state —
    // `build_reshare` takes a mandatory TombstoneSet).
    let anchored_head = match load_sink_pins_opt(&dir.0)? {
        Some(pins) => Some(fetch_anchored_head(&pins)?),
        None => None,
    };
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
        &mut tofu,
        contacts.as_mut(),
        &req.recipient_usernames,
        &req.accepted_key_changes,
        &verifier,
        &mut trust,
        now,
        emit,
    )
    .await;

    // Terminal `Done` for THIS file's tray row (spec §6/§11), emitted per file,
    // right where the batch that produced its progress finished. Because a
    // `Resolving` (which opens the row) is only ever emitted from inside the batch
    // above, every file that has a row reaches this point and finalizes it. A
    // bundle reshare relies on exactly this: it fans out over the bundle file AND
    // every member, calling `reshare_inner` per target, so each member emits its
    // OWN `Done` and no member row is left stuck on "Wrapping…". (A single
    // bundle-level `Done` used to finalize only the bundle row.)
    emit(done_phase(&req.file_id, &outcomes));
    Ok(outcomes)
}

// ---------------------------------------------------------------------------
// reshare_bundle — share a bundle AND all its members as a unit (WS8, Task 8.1)
// ---------------------------------------------------------------------------

/// The ordered set of file ids a bundle-reshare must fan out to: the bundle file
/// FIRST, then every member in the bundle's SIGNED order. Pure + testable. The
/// member ids come from the verified `BundleBody` (the decrypted signed content),
/// NEVER a server-served listing — content-substitution defense.
pub(crate) fn bundle_share_targets(bundle_id: [u8; 16], body: &BundleBody) -> Vec<[u8; 16]> {
    let mut targets = Vec::with_capacity(1 + body.members.len());
    targets.push(bundle_id);
    for m in &body.members {
        targets.push(m.file_id.0);
    }
    targets
}

/// Collapse the per-TARGET reshare results (one inner Vec per target file, each
/// with exactly one row per recipient in `recipients` order) into ONE aggregate
/// row per recipient: a recipient's bundle-share SUCCEEDS only if EVERY target
/// (the bundle file and all its members) shared to them. The first failing
/// target's sanitized code is surfaced. Pure + testable; per-recipient
/// fail-isolated (each recipient's aggregate is independent).
fn aggregate_bundle_outcomes(
    per_target: &[Vec<ReshareOutcomeDto>],
    recipients: &[String],
) -> Vec<ReshareOutcomeDto> {
    recipients
        .iter()
        .enumerate()
        .map(|(i, uname)| {
            // A recipient fails the bundle if ANY target failed (or dropped) its row.
            let mut code: Option<String> = None;
            for target in per_target {
                match target.get(i) {
                    Some(o) if o.ok => {}
                    Some(o) => {
                        code = o.code.clone().or_else(|| Some("share_failed".to_owned()));
                        break;
                    }
                    None => {
                        code = Some("share_failed".to_owned());
                        break;
                    }
                }
            }
            ReshareOutcomeDto {
                username: uname.clone(),
                ok: code.is_none(),
                code,
                old_fingerprint: None,
                new_fingerprint: None,
            }
        })
        .collect()
}

/// `reshare_bundle` — re-share a bundle AND all of its members to N recipients as
/// a UNIT. The verified member list is sourced from the SIGNED `BundleBody`
/// (`open_bundle_members`) — never a server listing — so the fan-out set is
/// tamper-proof. Each target file is reshared via the same per-recipient
/// machinery as [`reshare_file`] (`reshare_inner`), then the per-target results
/// are aggregated to ONE outcome per recipient: a recipient's share succeeds only
/// if the bundle file and EVERY member shared to them. Per-recipient
/// fail-isolated; emits [`SharePhase`] over [`EVT_RESHARE`] — per-target progress
/// AND a per-target `Done` (one for the bundle file and one per member, so every
/// tray row finalizes), never a single bundle-scoped `Done`.
#[tauri::command]
pub async fn reshare_bundle(
    req: ReshareRequest,
    app: tauri::AppHandle,
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
    connect_lock: State<'_, ConnectLock>,
) -> Result<Vec<ReshareOutcomeDto>, UiError> {
    let emit = |p: SharePhase| {
        let _ = app.emit(EVT_RESHARE, p);
    };

    // Validate the requested id + fetch the VERIFIED signed member list. A failure
    // here (can't verify the bundle) is a whole-command Err: without the authentic
    // membership we cannot safely fan out (content-substitution discipline).
    let bundle_id = hex16(&req.file_id)?;
    let (body, _version, _mine) =
        open_bundle_members(&req.file_id, &dir, &session, &connect_lock).await?;
    let targets = bundle_share_targets(bundle_id, &body);

    // Fan out to each target [bundle, members…] reusing the per-recipient reshare
    // machinery. A per-TARGET prerequisite failure (a member that can't be opened
    // / reshared at all) is absorbed into a per-recipient failure for THAT target
    // rather than aborting the whole bundle — the aggregate then marks every
    // recipient failed (they did not get the complete bundle).
    let mut per_target: Vec<Vec<ReshareOutcomeDto>> = Vec::with_capacity(targets.len());
    for target in &targets {
        let sub = ReshareRequest {
            file_id: hex(target),
            recipient_usernames: req.recipient_usernames.clone(),
            accepted_key_changes: req.accepted_key_changes.clone(),
        };
        let outcomes = match reshare_inner(&sub, &dir, &session, &connect_lock, &emit).await {
            Ok(o) => o,
            Err(e) => req
                .recipient_usernames
                .iter()
                .map(|u| ReshareOutcomeDto {
                    username: u.clone(),
                    ok: false,
                    code: Some(e.code.clone()),
                    old_fingerprint: None,
                    new_fingerprint: None,
                })
                .collect(),
        };
        per_target.push(outcomes);
    }

    // Each target's `reshare_inner` (in the loop above) already emitted its OWN
    // terminal `Done`, so every tray row — the bundle file AND each member —
    // finalizes individually. We deliberately do NOT emit a second bundle-level
    // `Done` here: it only ever carried `req.file_id`, so it finalized the bundle
    // row while leaving every member row stuck. The aggregate below is purely the
    // command's RETURN value for the dialog (a recipient succeeds only if EVERY
    // target shared to them) — it never crosses the event channel.
    let aggregate = aggregate_bundle_outcomes(&per_target, &req.recipient_usernames);
    Ok(aggregate)
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
///
/// `pub` (Tauri-free) so `crates/client-e2e/reshare_e2e.rs` drives the ACTUAL
/// orchestration — the real per-recipient resolve→TOFU→wrap→POST loop and per-file
/// outcome tally that ships, with `build_add_wrap_body` shaping the wire — over a
/// live server, instead of a hand-copied reconstruction that is green by design.
#[allow(clippy::too_many_arguments)]
pub async fn run_reshare_batch(
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
    tofu: &mut TofuStore,
    mut contacts: Option<&mut crate::contacts::ContactStore>,
    recipients: &[String],
    accepted_key_changes: &[String],
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
                    push_outcome(
                        &mut outcomes,
                        emit,
                        file_id_hex,
                        uname,
                        false,
                        Some(e.code),
                        None,
                        None,
                    );
                    continue;
                }
            };

        // (sync, no await) Trust-alarm layer B: TOFU-pin the resolved+verified key.
        // A first sighting pins WITHOUT blocking; the SAME key Matches; a CHANGED key
        // for a pinned username is handled here. If the user has EXPLICITLY confirmed
        // the change (`accepted_key_changes`), re-pin and PROCEED to the wrap/POST;
        // otherwise surface a per-recipient `key_changed` outcome carrying the old +
        // new short fingerprints (warn + confirm) — no wrap, no POST for this
        // recipient (per-recipient isolation; the pin is NOT overwritten). A
        // store-write error is fail-closed rather than silently unpinned.
        match tofu.check_or_pin(uname, &author.enc_pub, &author.sig_pub) {
            Ok(TofuOutcome::Pinned) | Ok(TofuOutcome::Match) => {}
            Ok(TofuOutcome::Changed) => {
                if accepted_key_changes.iter().any(|u| u == uname) {
                    // User explicitly confirmed this key change → re-pin and proceed.
                    if let Err(e) = tofu.repin(uname, &author.enc_pub, &author.sig_pub) {
                        push_outcome(
                            &mut outcomes,
                            emit,
                            file_id_hex,
                            uname,
                            false,
                            Some(e.code),
                            None,
                            None,
                        );
                        continue;
                    }
                    // fall through to the wrap/POST below (no `continue`).
                } else {
                    // Not confirmed → surface a warn+confirm outcome with both prints.
                    let old_fp = tofu
                        .pinned_fingerprint(uname)
                        .map(|fp| crate::tofu::short_fingerprint(&fp));
                    let new_fp = crate::tofu::short_fingerprint(&crate::tofu::key_fingerprint(
                        &author.enc_pub,
                        &author.sig_pub,
                    ));
                    push_outcome(
                        &mut outcomes,
                        emit,
                        file_id_hex,
                        uname,
                        false,
                        Some("key_changed".to_owned()),
                        old_fp,
                        Some(new_fp),
                    );
                    continue;
                }
            }
            Err(e) => {
                push_outcome(
                    &mut outcomes,
                    emit,
                    file_id_hex,
                    uname,
                    false,
                    Some(e.code),
                    None,
                    None,
                );
                continue;
            }
        }

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
                // The session mutex is released between recipients, so a concurrent
                // logout / lock mid-batch can make the identity momentarily absent
                // here. Fail closed for THIS recipient (no wrap produced, row still
                // recorded) rather than aborting the whole batch.
                None => Err("locked".to_owned()),
            }
        }; // guard drops here — identity no longer borrowed, safe to await

        let wrap = match built {
            Ok(w) => w,
            Err(code) => {
                push_outcome(
                    &mut outcomes,
                    emit,
                    file_id_hex,
                    uname,
                    false,
                    Some(code),
                    None,
                    None,
                );
                continue;
            }
        };

        // (async) POST the wrap. A non-201 or transport error is a per-recipient
        // failure, not a batch abort (idempotent server-side → safe to retry).
        let body = build_add_wrap_body(&wrap);
        let uri = format!("/v1/files/{file_id_hex}/wraps");
        match post_json(sender, &uri, &body, Some(token), host).await {
            Ok((st, _)) if st == hyper::StatusCode::CREATED => {
                // Best-effort: remember this recipient as a contact (roster for the
                // share checklist). A store-write failure must NEVER turn a
                // successful share into a failure — swallow it (mirrors the
                // best-effort index write in `feed.rs`).
                let fp = crate::tofu::key_fingerprint(&author.enc_pub, &author.sig_pub);
                if let Some(c) = contacts.as_deref_mut() {
                    let _ = c.upsert(uname, author.user_id, fp);
                }
                push_outcome(&mut outcomes, emit, file_id_hex, uname, true, None, None, None);
            }
            Ok(_) => {
                push_outcome(
                    &mut outcomes,
                    emit,
                    file_id_hex,
                    uname,
                    false,
                    Some("share_failed".to_owned()),
                    None,
                    None,
                );
            }
            Err(e) => {
                push_outcome(
                    &mut outcomes,
                    emit,
                    file_id_hex,
                    uname,
                    false,
                    Some(e.code),
                    None,
                    None,
                );
            }
        }
    }

    outcomes
}

/// Record one recipient's terminal outcome (append to the result Vec AND emit the
/// `Recipient` phase). Centralized so every path produces exactly one row + event.
#[allow(clippy::too_many_arguments)]
fn push_outcome(
    outcomes: &mut Vec<ReshareOutcomeDto>,
    emit: &impl Fn(SharePhase),
    file_id_hex: &str,
    username: &str,
    ok: bool,
    code: Option<String>,
    old_fingerprint: Option<String>,
    new_fingerprint: Option<String>,
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
        old_fingerprint,
        new_fingerprint,
    });
}

/// The terminal [`SharePhase::Done`] for ONE file's reshare batch: an
/// AUTHORITATIVE tally (`shared` = the `ok` rows, `failed` = the remainder) over
/// that file's own outcomes. Pure + testable. Every file that opened a
/// `<share-tray>` row (i.e. emitted a `Resolving`) MUST receive exactly one of
/// these so the row finalizes — a bundle reshare fans out over many `file_id`s,
/// so this is emitted PER FILE (see [`reshare_inner`]), never once per batch.
fn done_phase(file_id_hex: &str, outcomes: &[ReshareOutcomeDto]) -> SharePhase {
    let shared = outcomes.iter().filter(|o| o.ok).count() as u32;
    let failed = outcomes.len() as u32 - shared;
    SharePhase::Done {
        file_id: file_id_hex.to_owned(),
        shared,
        failed,
    }
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
///
/// PURE + `pub` so the wire shape is testable without a network
/// (`tests/compat.rs`). Every key here is read by the server's `add_wrap`
/// handler: dropping one silently breaks sharing for every existing user (a
/// recipient with no `wrapped_dek_b64`/`grant_b64` can never open the file).
pub fn build_add_wrap_body(w: &WrapOut) -> serde_json::Value {
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
    let mut trust = MemoryTrustStore::new();
    let now = now_ms();
    let server = server_of(&dir.0)?;
    let (mut sender, host, _exporter) = open_conn(&dir.0, &server).await?;
    // Offline-D5 hop (spec §3/§7): resolve the effective directory verifier over the
    // pinned connection; fail closed on a bad delegation before resolving the recipient.
    let verifier =
        crate::directory::build_delegated_verifier(&mut sender, &host, pinned, now).await?;
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

// ---------------------------------------------------------------------------
// list_contacts — the roster source for the share checklist
// ---------------------------------------------------------------------------

/// `list_contacts` — the local address book (people you've successfully shared
/// with), the roster for the share checklist. Reads the identity-sealed
/// [`crate::contacts::ContactStore`].
///
/// FAILS OPEN to an empty roster: a not-yet-signed-in identity, an absent store,
/// or any store-open error all degrade to `Ok(vec![])` so the dialog is NEVER
/// blocked (manual username input remains fully available). `fingerprint` is the
/// first 8 bytes hex (matching `resolved_recipient_dto`). `already_shared` is not
/// part of this DTO — the dialog computes access itself via `list_file_recipients`.
#[tauri::command]
pub async fn list_contacts(
    dir: State<'_, AppDir>,
    session: State<'_, Session>,
) -> Result<Vec<ContactDto>, UiError> {
    let guard = session.0.lock().await;
    let Some(identity) = guard.identity.as_ref() else {
        return Ok(Vec::new()); // not signed in → empty roster, fail-open
    };
    let store = match crate::contacts::ContactStore::open(&dir.0, identity) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()), // corrupt/unreadable → empty, never block
    };
    Ok(store
        .list()
        .into_iter()
        .map(|c| ContactDto {
            username: c.username,
            user_id: hex(&c.user_id),
            fingerprint: hex(&c.fingerprint[..8]),
        })
        .collect())
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

    /// A fresh, empty TOFU store in a unique temp dir (so every batch test starts
    /// with no pins — the first sighting pins WITHOUT blocking). The dir is left in
    /// the OS temp space; these are ephemeral test runs.
    fn empty_tofu() -> TofuStore {
        let dir = std::env::temp_dir().join(format!(
            "mxtofu_share_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        TofuStore::open(&dir, &Identity::generate()).unwrap()
    }

    /// A fresh, empty ContactStore in a unique temp dir (so a batch test starts
    /// with no contacts). Left in OS temp space; these are ephemeral test runs.
    fn empty_contacts() -> crate::contacts::ContactStore {
        let dir = std::env::temp_dir().join(format!(
            "mxcontacts_share_{}_{}",
            std::process::id(),
            maxsecu_crypto::random_array::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        crate::contacts::ContactStore::open(&dir, &Identity::generate()).unwrap()
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
            &mut empty_tofu(),
            Some(&mut empty_contacts()),
            &recipients,
            &[],
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

    /// An in-process HTTP/1.1 stub that serves a fixed `alice` binding for ANY
    /// `GET /v1/directory/*` and, for the `/wraps` POST, returns the FIRST status in
    /// `wrap_statuses` on the first hit, the second on the next, etc. (a
    /// per-`/wraps`-POST sequence). Lets one batch drive a POST failure for one
    /// recipient and a success for the next.
    async fn spawn_seq_wrap_stub(
        binding_body: String,
        wrap_statuses: Vec<hyper::StatusCode>,
    ) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let binding_body = Arc::new(binding_body);
        let statuses = Arc::new(wrap_statuses);
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let binding_body = binding_body.clone();
                let statuses = statuses.clone();
                let hits = hits.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let binding_body = binding_body.clone();
                        let statuses = statuses.clone();
                        let hits = hits.clone();
                        async move {
                            let path = req.uri().path().to_owned();
                            let _ = req.into_body().collect().await;
                            let resp = if path.ends_with("/wraps") {
                                let n = hits.fetch_add(1, Ordering::SeqCst);
                                let st = statuses
                                    .get(n)
                                    .copied()
                                    .unwrap_or(hyper::StatusCode::CREATED);
                                Response::builder()
                                    .status(st)
                                    .body(Full::<Bytes>::from("{}"))
                                    .unwrap()
                            } else if path.starts_with("/v1/directory/") {
                                Response::builder()
                                    .status(hyper::StatusCode::OK)
                                    .body(Full::<Bytes>::from((*binding_body).clone()))
                                    .unwrap()
                            } else {
                                Response::builder()
                                    .status(hyper::StatusCode::NOT_FOUND)
                                    .body(Full::<Bytes>::new(Bytes::new()))
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

    /// The POST-failure isolation branch (spec §5): in ONE batch, a recipient whose
    /// `/wraps` POST the server rejects (a non-201 — here `500`) fails closed with
    /// `code:"share_failed"`, and this does NOT abort the batch — a SUBSEQUENT
    /// recipient whose POST succeeds still gets `ok:true`. Every input username
    /// yields exactly one row, in order.
    #[tokio::test]
    async fn post_failure_is_isolated_from_a_succeeding_recipient_in_one_batch() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        // Both usernames resolve to a valid binding (the stub serves the same
        // `alice` binding for any /v1/directory/*); they differ only in the /wraps
        // POST outcome: the FIRST POST → 500, the SECOND → 201.
        let addr = spawn_seq_wrap_stub(
            alice_binding(&d5, alice_pk.to_bytes()),
            vec![
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                hyper::StatusCode::CREATED,
            ],
        )
        .await;
        let mut sender = connect(&addr).await;

        // "rfail" is resolved+wrapped first (its POST → 500), then "rok" (POST → 201)
        // in the SAME batch — proving the first failure did not abort the batch.
        let recipients = vec!["rfail".to_owned(), "rok".to_owned()];
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
            &mut empty_tofu(),
            Some(&mut empty_contacts()),
            &recipients,
            &[],
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        // Exactly one row per input username, in order — never a dropped row.
        assert_eq!(outcomes.len(), 2, "one outcome per entered username");
        assert_eq!(outcomes[0].username, "rfail");
        assert!(!outcomes[0].ok, "a non-201 POST fails this recipient");
        assert_eq!(outcomes[0].code.as_deref(), Some("share_failed"));
        assert_eq!(outcomes[1].username, "rok");
        assert!(
            outcomes[1].ok,
            "the batch was not aborted: the next recipient still succeeds"
        );
        assert!(outcomes[1].code.is_none());
    }

    /// Trust-alarm layer B (spec §0-B/§7): a username whose key was TOFU-pinned to a
    /// DIFFERENT key now resolves to a changed key ⇒ fail-closed `key_changed`,
    /// blocking the share for that recipient (no wrap POST), while an UNPINNED peer
    /// in the same batch is a normal first-sighting that still succeeds — the alarm
    /// is per-recipient and blocks a CHANGE only, never a first sighting.
    #[tokio::test]
    async fn changed_pinned_key_blocks_the_share_but_first_sighting_proceeds() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        // The server serves alice's REAL binding (enc = alice_pk, sig = [0x51;32]).
        let mut routes = HashMap::new();
        routes.insert(
            "/v1/directory/alice".to_owned(),
            (
                hyper::StatusCode::OK,
                alice_binding(&d5, alice_pk.to_bytes()),
            ),
        );
        routes.insert(
            "/v1/directory/carol".to_owned(),
            (
                hyper::StatusCode::OK,
                alice_binding(&d5, alice_pk.to_bytes()),
            ),
        );
        // A 201 wraps route: if the alarm did NOT block, "alice" would succeed here —
        // so a `key_changed` outcome proves the block happened BEFORE the POST.
        routes.insert(
            format!("/v1/files/{file_id_hex}/wraps"),
            (hyper::StatusCode::CREATED, "{}".to_owned()),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;

        // Pre-pin "alice" to a DIFFERENT key than the server will serve → Changed.
        // "carol" is left UNPINNED → a normal first sighting.
        let mut tofu = empty_tofu();
        assert_eq!(
            tofu.check_or_pin("alice", &[0x00; 32], &[0x51; 32]).unwrap(),
            TofuOutcome::Pinned
        );

        let recipients = vec!["alice".to_owned(), "carol".to_owned()];
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
            &mut tofu,
            Some(&mut empty_contacts()),
            &recipients,
            &[],
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        assert_eq!(outcomes.len(), 2, "one outcome per entered username");
        // alice: changed pinned key (not confirmed) → blocked with a `key_changed`
        // warn+confirm outcome carrying BOTH the old and new short fingerprints.
        assert_eq!(outcomes[0].username, "alice");
        assert!(!outcomes[0].ok, "a changed pinned key blocks the share");
        assert_eq!(outcomes[0].code.as_deref(), Some("key_changed"));
        assert!(
            outcomes[0].old_fingerprint.is_some(),
            "key_changed carries the previously-pinned fingerprint"
        );
        assert!(
            outcomes[0].new_fingerprint.is_some(),
            "key_changed carries the newly-served fingerprint"
        );
        // carol: first sighting → pinned WITHOUT blocking → the share still succeeds.
        assert_eq!(outcomes[1].username, "carol");
        assert!(outcomes[1].ok, "a first-sighting peer is not blocked");
        assert!(outcomes[1].code.is_none());
    }

    /// The user-confirmed key-change path (spec §Part 3): a username whose pinned
    /// key CHANGED but is listed in `accepted_key_changes` is RE-PINNED and shared
    /// to (ok:true, no code) — mirroring the changed-key test setup but passing the
    /// acceptance. A first-sighting peer (carol) still succeeds.
    #[tokio::test]
    async fn accepted_key_change_repins_and_shares() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        let mut routes = HashMap::new();
        routes.insert(
            "/v1/directory/alice".to_owned(),
            (
                hyper::StatusCode::OK,
                alice_binding(&d5, alice_pk.to_bytes()),
            ),
        );
        routes.insert(
            "/v1/directory/carol".to_owned(),
            (
                hyper::StatusCode::OK,
                alice_binding(&d5, alice_pk.to_bytes()),
            ),
        );
        routes.insert(
            format!("/v1/files/{file_id_hex}/wraps"),
            (hyper::StatusCode::CREATED, "{}".to_owned()),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;

        // Pre-pin "alice" to a DIFFERENT key than the server will serve → Changed;
        // "carol" left UNPINNED → a first sighting.
        let mut tofu = empty_tofu();
        assert_eq!(
            tofu.check_or_pin("alice", &[0x00; 32], &[0x51; 32]).unwrap(),
            TofuOutcome::Pinned
        );

        let recipients = vec!["alice".to_owned(), "carol".to_owned()];
        let accepted = vec!["alice".to_owned()];
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
            &mut tofu,
            Some(&mut empty_contacts()),
            &recipients,
            &accepted,
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        assert_eq!(outcomes.len(), 2, "one outcome per entered username");
        // alice: the confirmed key change re-pins and shares.
        assert_eq!(outcomes[0].username, "alice");
        assert!(outcomes[0].ok, "an accepted key change re-pins and shares");
        assert_eq!(outcomes[0].code, None);
        // The re-pin persisted: the new key now Matches, the old key would trip.
        assert_eq!(
            tofu.check_or_pin("alice", &alice_pk.to_bytes(), &[0x51; 32])
                .unwrap(),
            TofuOutcome::Match
        );
        // carol: first sighting → still succeeds.
        assert_eq!(outcomes[1].username, "carol");
        assert!(outcomes[1].ok, "a first-sighting peer is not blocked");
        assert!(outcomes[1].code.is_none());
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

    fn outcome(username: &str, ok: bool) -> ReshareOutcomeDto {
        ReshareOutcomeDto {
            username: username.to_owned(),
            ok,
            code: if ok {
                None
            } else {
                Some("share_failed".to_owned())
            },
            old_fingerprint: None,
            new_fingerprint: None,
        }
    }

    /// The terminal `Done` a file emits carries an authoritative `shared`/`failed`
    /// tally over THAT file's own outcomes — and, crucially, is scoped to the
    /// file_id passed in. Because `reshare_inner` calls this per file, a bundle
    /// reshare emits one `Done` per target (bundle + each member), so every tray
    /// row finalizes instead of members hanging on "Wrapping…".
    #[test]
    fn done_phase_tallies_per_file_and_keeps_the_file_id() {
        // Mixed batch → shared counts the ok rows; failed is the remainder.
        let mixed = done_phase(
            "ab".repeat(16).as_str(),
            &[outcome("a", true), outcome("b", false), outcome("c", true)],
        );
        assert_eq!(
            mixed,
            SharePhase::Done {
                file_id: "ab".repeat(16),
                shared: 2,
                failed: 1,
            }
        );

        // All-ok, single-failed, and empty edges — always for the given file_id.
        assert_eq!(
            done_phase("f1", &[outcome("a", true), outcome("b", true)]),
            SharePhase::Done {
                file_id: "f1".to_owned(),
                shared: 2,
                failed: 0,
            }
        );
        assert_eq!(
            done_phase("f2", &[outcome("a", false)]),
            SharePhase::Done {
                file_id: "f2".to_owned(),
                shared: 0,
                failed: 1,
            }
        );
        assert_eq!(
            done_phase("f3", &[]),
            SharePhase::Done {
                file_id: "f3".to_owned(),
                shared: 0,
                failed: 0,
            }
        );
    }

    /// A successful share RECORDS the recipient as a contact; an unresolvable /
    /// failed recipient records NOTHING. Uses the same `spawn_router` stub as the
    /// isolation test (alice → 201 wrap; ghost → default 404 resolve).
    #[tokio::test]
    async fn successful_share_records_a_contact_failed_does_not() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();

        let (_alice_sk, alice_pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();

        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        let mut routes = HashMap::new();
        routes.insert(
            "/v1/directory/alice".to_owned(),
            (hyper::StatusCode::OK, alice_binding(&d5, alice_pk.to_bytes())),
        );
        routes.insert(
            format!("/v1/files/{file_id_hex}/wraps"),
            (hyper::StatusCode::CREATED, "{}".to_owned()),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;

        let mut contacts = empty_contacts();
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
            &mut empty_tofu(),
            Some(&mut contacts),
            &recipients,
            &[],
            &verifier,
            &mut trust,
            NOW,
            &|_| {},
        )
        .await;

        assert_eq!(outcomes.len(), 2);
        assert!(!outcomes[0].ok, "ghost fails");
        assert!(outcomes[1].ok, "alice succeeds");

        // Only the successful recipient (alice) was recorded — ghost never resolved.
        let list = contacts.list();
        assert_eq!(list.len(), 1, "only the successful share is a contact");
        assert_eq!(list[0].username, "alice");
        // alice's binding uses user_id [0x0A; 16] (see `alice_binding`).
        assert_eq!(list[0].user_id, [0x0A; 16]);
    }

    #[test]
    fn bundle_share_targets_lists_bundle_then_members() {
        use maxsecu_encoding::structs::{BundleBody, BundleMember};
        use maxsecu_encoding::types::{FileType, Id};
        let bundle_id = [0xB1; 16];
        let body = BundleBody {
            members: vec![
                BundleMember {
                    file_id: Id([0x01; 16]),
                    file_type: FileType::Video,
                },
                BundleMember {
                    file_id: Id([0x02; 16]),
                    file_type: FileType::Image,
                },
            ],
        };
        let t = bundle_share_targets(bundle_id, &body);
        assert_eq!(t, vec![[0xB1; 16], [0x01; 16], [0x02; 16]]);
    }

    #[test]
    fn bundle_share_targets_is_just_the_bundle_when_empty() {
        use maxsecu_encoding::structs::BundleBody;
        let t = bundle_share_targets([0xB2; 16], &BundleBody { members: vec![] });
        assert_eq!(t, vec![[0xB2; 16]]);
    }

    /// Aggregation (Task 8.1): a recipient's bundle-share succeeds ONLY if every
    /// target (bundle + all members) shared to them; the first failing target's
    /// code is surfaced. Per-recipient independent.
    #[test]
    fn aggregate_bundle_outcomes_requires_every_target_per_recipient() {
        let recipients = vec!["a".to_owned(), "b".to_owned()];
        // Two targets. `a` shares in both. `b` shares in the bundle but the
        // member wrap fails.
        let per_target = vec![
            vec![
                ReshareOutcomeDto {
                    username: "a".into(),
                    ok: true,
                    code: None,
                    old_fingerprint: None,
                    new_fingerprint: None,
                },
                ReshareOutcomeDto {
                    username: "b".into(),
                    ok: true,
                    code: None,
                    old_fingerprint: None,
                    new_fingerprint: None,
                },
            ],
            vec![
                ReshareOutcomeDto {
                    username: "a".into(),
                    ok: true,
                    code: None,
                    old_fingerprint: None,
                    new_fingerprint: None,
                },
                ReshareOutcomeDto {
                    username: "b".into(),
                    ok: false,
                    code: Some("share_failed".into()),
                    old_fingerprint: None,
                    new_fingerprint: None,
                },
            ],
        ];
        let agg = aggregate_bundle_outcomes(&per_target, &recipients);
        assert_eq!(agg.len(), 2, "one aggregate row per recipient");
        assert_eq!(agg[0].username, "a");
        assert!(agg[0].ok, "a got every target → bundle-share succeeds");
        assert!(agg[0].code.is_none());
        assert_eq!(agg[1].username, "b");
        assert!(!agg[1].ok, "b missed a member → bundle-share fails");
        assert_eq!(agg[1].code.as_deref(), Some("share_failed"));
    }

    #[test]
    fn aggregate_bundle_outcomes_surfaces_first_failing_targets_code() {
        let recipients = vec!["a".to_owned()];
        // The bundle file itself failed to reshare (e.g. untrusted) → the whole
        // bundle-share fails for this recipient with that first code.
        let per_target = vec![
            vec![ReshareOutcomeDto {
                username: "a".into(),
                ok: false,
                code: Some("untrusted".into()),
                old_fingerprint: None,
                new_fingerprint: None,
            }],
            vec![ReshareOutcomeDto {
                username: "a".into(),
                ok: false,
                code: Some("share_failed".into()),
                old_fingerprint: None,
                new_fingerprint: None,
            }],
        ];
        let agg = aggregate_bundle_outcomes(&per_target, &recipients);
        assert_eq!(agg.len(), 1);
        assert!(!agg[0].ok);
        assert_eq!(
            agg[0].code.as_deref(),
            Some("untrusted"),
            "the FIRST failing target's code wins"
        );
    }

    /// A recipient who RESOLVES but whose wrap POST fails (non-201) records NO
    /// contact — proving recording is gated on the CREATED arm, not on resolve.
    #[tokio::test]
    async fn post_failure_records_no_contact() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (_sk, pk) = generate_enc_keypair();
        let dek = Dek::generate();
        let tombstones = empty_tombstones();
        let session = session_with_identity();
        let file_id_hex: String = FILE_ID.iter().map(|b| format!("{b:02x}")).collect();

        let addr = spawn_seq_wrap_stub(
            alice_binding(&d5, pk.to_bytes()),
            vec![hyper::StatusCode::INTERNAL_SERVER_ERROR],
        )
        .await;
        let mut sender = connect(&addr).await;

        let mut contacts = empty_contacts();
        let recipients = vec!["alice".to_owned()];
        let outcomes = run_reshare_batch(
            &mut sender, "localhost", "tok", &file_id_hex, FILE_ID, 1,
            dek.commit(), Suite::V1, GRANTER_ID, &dek, &tombstones, &session,
            &mut empty_tofu(), Some(&mut contacts), &recipients, &[],
            &verifier, &mut trust, NOW, &|_| {},
        )
        .await;

        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].ok, "the 500 POST fails the share");
        assert!(contacts.list().is_empty(), "a POST failure records no contact");
    }
}
