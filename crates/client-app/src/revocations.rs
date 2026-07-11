//! Build an **authenticated** [`TombstoneSet`] from the server-served control log,
//! made safe by the pinned-D5 issuer authority and, WHEN a sink is pinned, the
//! sink-anchored head (T4 / spec §9 TombstoneSet checklist).
//!
//! `GET /v1/revocations` is served by the UNTRUSTED app server: the record bytes,
//! their issuer signatures, and the advisory chain heads all come from an operator
//! who could roll back, fork, or withhold a fresh tombstone. Issuer authority makes
//! the served set usable; the sink-anchored head is an OPTIONAL second fact that,
//! when present, additionally pins the tip:
//!
//! * the **anchored head** — when a sink is pinned, it is fetched out of band from
//!   that sink in Task 4 ([`crate::sink::fetch_anchored_head`]) and passed in here,
//!   pinning the exact chain tip the served records must reach (a short/withheld set
//!   is a `Gap`). The sink is now OPT-IN: `anchored_head` is `None` when no sink is
//!   pinned, in which case the served set is verified UNANCHORED (issuer authority +
//!   internal chain integrity only, with no external tip to catch a withheld tail);
//! * **issuer authority** — every record's `issued_by` (and, for dual-controlled
//!   records, its co-signer) is re-resolved to a D5-verified directory binding
//!   under the pinned root, so the operator cannot forge admin authority.
//!
//! [`build_tombstones`] fetches the records, pre-resolves the distinct issuers
//! (the directory lookups are async, but [`TombstoneSet::verify_authenticated`]'s
//! `issuer` callback is synchronous — so they are resolved up front into a map the
//! closure reads), and runs the synchronous chain+authority verify. Every
//! [`TombstoneError`] collapses to ONE sanitized, fail-closed [`UiError`]: an
//! unverifiable revocation state is never silently treated as "nothing revoked".
//!
//! No identity or secret material is involved — this verifies PUBLIC records under
//! the pinned D5, plus the sink-anchored head when a sink is pinned. The returned
//! [`TombstoneSet`] never crosses the command seam; it feeds the reshare recipient
//! check (Task 8).

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use maxsecu_client_core::{
    ControlRecordIn, DirectoryVerifier, IssuerInfo, TombstoneError, TombstoneSet, TrustStore,
};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::{DirBinding, KeyCompromise, Reinstatement, Revocation};
use maxsecu_encoding::types::Id;

use crate::error::UiError;
use crate::http_client::get_json;

/// Fetch `GET /v1/revocations`, authenticate every record's issuer authority under
/// the pinned D5, and verify the served set. When `anchored_head` is `Some`, the set
/// must be a contiguous chain reaching that head (the head Task 4 attested out of
/// band via the sink); when it is `None` (no sink pinned — the opt-in sink path) the
/// set is verified UNANCHORED (issuer authority + internal chain integrity only).
/// Returns the authoritative [`TombstoneSet`] for §7.6 decisions, or a single
/// sanitized fail-closed [`UiError`] on any transport/parse/chain/authority failure.
///
/// `anchored_head` is a PARAMETER (not fetched here): the caller/Task 8 obtains it
/// from [`crate::sink::fetch_anchored_head`] only when a sink is pinned, passing
/// `None` otherwise. Decoupling the sink fetch from the record fetch keeps each
/// independently testable — a test can anchor a head directly without standing up a
/// sink — and lets Task 8 fetch the anchor once and reuse it. `verifier`/`trust`
/// resolve each issuer binding under the pinned root; `now_ms` is the validity-window
/// clock for those bindings.
pub(crate) async fn build_tombstones(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    anchored_head: Option<[u8; 32]>,
    verifier: &DirectoryVerifier,
    // `+ Send`: the trust object is held across the `get_json` awaits, so the
    // returned future must be `Send` (mirrors `directory::resolve_and_verify_author`).
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<TombstoneSet, UiError> {
    // 1. Fetch the untrusted served record set.
    let records = fetch_control_records(sender, host).await?;

    // 2. Collect the distinct issuer ids (each record's `issued_by` plus any
    //    co-signer). A record whose bytes don't decode contributes no ids — it will
    //    be rejected as `Malformed` by the verify step regardless.
    let mut ids: Vec<[u8; 16]> = Vec::new();
    for rec in &records {
        for id in record_issuers(&rec.bytes) {
            if !ids.contains(&id.0) {
                ids.push(id.0);
            }
        }
    }

    // 3. Pre-resolve each distinct issuer to its D5-verified `IssuerInfo` up front
    //    (the async directory lookups cannot happen inside the sync `issuer`
    //    closure). An id that will not D5-resolve is simply left out of the map, so
    //    a record it issued fails closed as `UnknownIssuer` in step 4 — never
    //    silently trusted.
    let mut resolved: HashMap<[u8; 16], IssuerInfo> = HashMap::new();
    for id in ids {
        if let Some(info) = resolve_issuer(sender, host, &id, verifier, trust, now_ms).await {
            resolved.insert(id, info);
        }
    }

    // 4. Synchronous chain + authority verify. With a pinned sink, verify against
    //    the anchored head; without one (opt-in sink), verify UNANCHORED. The closure
    //    only reads the pre-resolved map. Every failure is fail-closed.
    let issuer = |id: Id| resolved.get(&id.0).cloned();
    match anchored_head {
        Some(head) => TombstoneSet::verify_authenticated(&records, head, &issuer),
        None => TombstoneSet::verify_authenticated_unanchored(&records, &issuer),
    }
    .map_err(map_tombstone_err)
}

/// Fetch + parse the served `GET /v1/revocations` record set into
/// [`ControlRecordIn`]s (canonical bytes + issuer sig + optional co-sig). Unlike
/// [`crate::recipients::list_recipients`] (a UX nicety that fails OPEN), this is
/// authoritative revocation state: a missing endpoint, a non-`200`, or a malformed
/// body FAILS CLOSED — never a silently-empty (permissive) set.
async fn fetch_control_records(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
) -> Result<Vec<ControlRecordIn>, UiError> {
    let (status, json) = get_json(sender, "/v1/revocations", None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(unverified());
    }
    let entries = json
        .get("records")
        .and_then(|v| v.as_array())
        .ok_or_else(unverified)?;
    let mut out = Vec::with_capacity(entries.len());
    for r in entries {
        let bytes = b64_bytes(r.get("record_b64"))?;
        let sig = b64_array::<64>(r.get("sig_b64"))?;
        // `co_sig_b64` is omitted for single-control records; present ⇒ must parse.
        let co_sig = match r.get("co_sig_b64") {
            None => None,
            Some(v) if v.is_null() => None,
            Some(_) => Some(b64_array::<64>(r.get("co_sig_b64"))?),
        };
        out.push(ControlRecordIn { bytes, sig, co_sig });
    }
    Ok(out)
}

/// The `issued_by` (and any co-signer) ids named by one control record. `[]` if the
/// bytes are not a canonical revocation/reinstatement/key-compromise record — the
/// verify step will reject such bytes as `Malformed`, so no id is needed here.
fn record_issuers(bytes: &[u8]) -> Vec<Id> {
    let type_id = match bytes {
        [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
        _ => return Vec::new(),
    };
    match type_id {
        0x0006 => decode::<Revocation>(bytes)
            .map(|r| {
                let mut v = vec![r.issued_by];
                v.extend(r.co_signed_by);
                v
            })
            .unwrap_or_default(),
        0x0007 => decode::<Reinstatement>(bytes)
            .map(|r| vec![r.issued_by, r.co_signed_by])
            .unwrap_or_default(),
        0x0008 => decode::<KeyCompromise>(bytes)
            .map(|r| vec![r.issued_by, r.co_signed_by])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Resolve one issuer `user_id` to its [`IssuerInfo`] via the pinned-D5 by-id
/// directory lookup (`GET /v1/directory/by-id/{hex}`), returning the verified
/// `sig_pub`, offline-signed role **ceiling**, and `key_version`. `None` (not an
/// error) on any failure — a `404`, a forged/expired/rolled-back binding, or a
/// transport hiccup — so the issuing record fails closed as `UnknownIssuer`.
///
/// This intentionally goes straight to the client-core [`DirectoryVerifier`]
/// (rather than [`crate::directory::resolve_and_verify_author`]) because the
/// tombstone authority check needs the binding's **roles**, which the download-path
/// `VerifiedAuthor` does not carry.
async fn resolve_issuer(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    user_id: &[u8; 16],
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Option<IssuerInfo> {
    let uri = format!("/v1/directory/by-id/{}", hex32(user_id));
    let (status, json) = get_json(sender, &uri, None, host).await.ok()?;
    if status != hyper::StatusCode::OK {
        return None;
    }
    let (bytes, sig) = parse_binding(&json)?;
    let binding: DirBinding = decode(&bytes).ok()?;
    let v = verifier
        .verify_binding(&binding, &sig, now_ms, trust)
        .ok()?;
    Some(IssuerInfo {
        sig_pub: v.sig_pub,
        roles: v.roles,
        key_version: v.key_version,
    })
}

/// Decode a §6.1 `BindingRes` JSON body into `(binding_bytes, signature)`. `None`
/// on any malformation (mirrors `directory::parse_binding`, which is module-private
/// there; the tombstone path needs the binding roles so it resolves independently).
fn parse_binding(json: &serde_json::Value) -> Option<(Vec<u8>, [u8; 64])> {
    let bytes = B64.decode(json.get("binding_b64")?.as_str()?).ok()?;
    let sig_vec = B64
        .decode(json.get("directory_signature_b64")?.as_str()?)
        .ok()?;
    let sig: [u8; 64] = sig_vec.try_into().ok()?;
    Some((bytes, sig))
}

/// Every [`TombstoneError`] is fail-closed: the served revocation state is
/// untrustworthy (a gap/withheld tail, a broken chain, malformed bytes, an
/// unknown/forged/non-admin issuer, or missing dual control) and MUST NOT be used.
/// All collapse to one sanitized code — WHICH check failed is an internal detail
/// that never crosses the seam (mirrors `sink::map_sink_err`).
fn map_tombstone_err(e: TombstoneError) -> UiError {
    match e {
        TombstoneError::Gap
        | TombstoneError::BrokenChain
        | TombstoneError::Malformed
        | TombstoneError::UnknownIssuer
        | TombstoneError::BadAuthority
        | TombstoneError::NotAdmin
        | TombstoneError::DualControlMissing => unverified(),
    }
}

/// The single sanitized fail-closed error for an unverifiable revocation state.
fn unverified() -> UiError {
    UiError::new(
        "revocation_unverified",
        "The revocation state could not be verified.",
    )
}

/// Base64-decode a JSON string field into raw bytes; fail-closed `unverified` on a
/// missing field or bad base64.
fn b64_bytes(v: Option<&serde_json::Value>) -> Result<Vec<u8>, UiError> {
    B64.decode(v.and_then(|v| v.as_str()).ok_or_else(unverified)?)
        .map_err(|_| unverified())
}

/// Base64-decode a JSON string field into a fixed `[u8; N]`; fail-closed on a
/// missing field, bad base64, or the wrong length.
fn b64_array<const N: usize>(v: Option<&serde_json::Value>) -> Result<[u8; N], UiError> {
    b64_bytes(v)?.try_into().map_err(|_| unverified())
}

/// Lowercase-hex a 16-byte id for the by-id directory path.
fn hex32(id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    use maxsecu_client_core::MemoryTrustStore;
    use maxsecu_crypto::{sha256, SigningKey};
    use maxsecu_encoding::structs::Revocation;
    use maxsecu_encoding::types::{Bytes32, FileScope, Id, Role, RoleSet, Text, Timestamp};
    use maxsecu_encoding::{encode, labels, GENESIS_HEAD};

    const NOW: u64 = 1_719_500_000_000;
    const A1_ID: [u8; 16] = [1; 16];
    const A2_ID: [u8; 16] = [2; 16];
    const NONADMIN_ID: [u8; 16] = [3; 16];
    const VICTIM: [u8; 16] = [0x99; 16];

    fn b64(b: &[u8]) -> String {
        B64.encode(b)
    }

    /// A D5-signed directory binding JSON body (`GET /v1/directory/by-id/…` shape)
    /// binding `user_id` to `signer`'s `sig_pub` under the offline-signed `roles`
    /// ceiling.
    fn binding_body(
        d5: &SigningKey,
        user_id: [u8; 16],
        signer: &SigningKey,
        roles: Vec<Role>,
    ) -> String {
        let b = DirBinding {
            username: Text::new("issuer").unwrap(),
            user_id: Id(user_id),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32(signer.verifying_key().to_bytes()),
            key_version: 1,
            roles: RoleSet::new(roles),
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

    /// Sign a revocation into its served-record JSON value + return the new head.
    fn record_json(
        rev: &Revocation,
        signer: &SigningKey,
        co: Option<&SigningKey>,
    ) -> (serde_json::Value, [u8; 32]) {
        let bytes = encode(rev);
        let sig = signer.sign_canonical(labels::REVOCATION, rev);
        let co_sig = co.map(|k| k.sign_canonical(labels::REVOCATION, rev));
        let head = sha256(&bytes);
        let mut obj = serde_json::json!({
            "kind": "revocation",
            "record_b64": b64(&bytes),
            "sig_b64": b64(&sig),
            "chain_head_b64": b64(&head),
        });
        if let Some(cs) = co_sig {
            obj["co_sig_b64"] = serde_json::Value::String(b64(&cs));
        }
        (obj, head)
    }

    fn account_revoke(prev_head: [u8; 32]) -> Revocation {
        Revocation {
            scope: FileScope::AccountWide,
            revoked_user_id: Id(VICTIM),
            revoked_capability: None,
            from_version: 1,
            revocation_epoch: 1,
            prev_head: Bytes32(prev_head),
            issued_by: Id(A1_ID),
            co_signed_by: Some(Id(A2_ID)),
            created_at: Timestamp(NOW),
        }
    }

    fn per_file_revoke(prev_head: [u8; 32], victim: [u8; 16], issued_by: [u8; 16]) -> Revocation {
        Revocation {
            scope: FileScope::Specific(Id([0x0A; 16])),
            revoked_user_id: Id(victim),
            revoked_capability: None,
            from_version: 1,
            revocation_epoch: 1,
            prev_head: Bytes32(prev_head),
            issued_by: Id(issued_by),
            co_signed_by: None,
            created_at: Timestamp(NOW),
        }
    }

    /// An in-process HTTP/1.1 stub that answers each request from a fixed
    /// `path -> (status, body)` map (default `404`). Routes both
    /// `GET /v1/revocations` and the per-issuer `GET /v1/directory/by-id/{hex}` a
    /// single [`build_tombstones`] call fans out to (mirrors `recipients.rs`'s
    /// `spawn_stub`, extended to route by path like `sink.rs`).
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

    fn revocations_body(records: &[serde_json::Value]) -> String {
        serde_json::json!({ "records": records, "next_cursor": null }).to_string()
    }

    fn by_id_path(user_id: [u8; 16]) -> String {
        format!("/v1/directory/by-id/{}", super::hex32(&user_id))
    }

    /// (a) A contiguous, dual-controlled account-wide revoke reaching the anchored
    /// head, with both admins D5-resolvable, verifies — and the victim reports
    /// `is_account_revoked == true`. This is the first real chain-verified,
    /// admin-authenticated revocation state in the shipped app.
    #[tokio::test]
    async fn account_revoked_id_is_detected_against_the_anchor() {
        let d5 = SigningKey::generate();
        let a1 = SigningKey::generate();
        let a2 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());

        let (rec, head) = record_json(&account_revoke(GENESIS_HEAD.0), &a1, Some(&a2));
        let mut routes = HashMap::new();
        routes.insert(
            "/v1/revocations".to_owned(),
            (hyper::StatusCode::OK, revocations_body(&[rec])),
        );
        routes.insert(
            by_id_path(A1_ID),
            (
                hyper::StatusCode::OK,
                binding_body(&d5, A1_ID, &a1, vec![Role::User, Role::Admin]),
            ),
        );
        routes.insert(
            by_id_path(A2_ID),
            (
                hyper::StatusCode::OK,
                binding_body(&d5, A2_ID, &a2, vec![Role::User, Role::Admin]),
            ),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;
        let mut trust = MemoryTrustStore::new();

        let set = build_tombstones(&mut sender, "localhost", Some(head), &verifier, &mut trust, NOW)
            .await
            .expect("authenticated chain verifies against the anchored head");
        assert!(
            set.is_account_revoked(&VICTIM),
            "the account-wide-revoked id is detected"
        );
        assert!(
            !set.is_account_revoked(&[0x55; 16]),
            "an unrelated id is not"
        );
    }

    /// (b) The server withholds the trailing record but the anchor commits to it —
    /// a `Gap` — so `build_tombstones` fails closed rather than returning a stale,
    /// permissive set.
    #[tokio::test]
    async fn withheld_trailing_record_fails_closed_as_gap() {
        let d5 = SigningKey::generate();
        let a1 = SigningKey::generate();
        let a2 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());

        // Two-record chain; the anchor commits to head-after-r2…
        let (rec1, head1) = record_json(&account_revoke(GENESIS_HEAD.0), &a1, Some(&a2));
        let (_rec2, head2) = record_json(&per_file_revoke(head1, [0x77; 16], A1_ID), &a1, None);

        // …but the server serves ONLY r1.
        let mut routes = HashMap::new();
        routes.insert(
            "/v1/revocations".to_owned(),
            (hyper::StatusCode::OK, revocations_body(&[rec1])),
        );
        routes.insert(
            by_id_path(A1_ID),
            (
                hyper::StatusCode::OK,
                binding_body(&d5, A1_ID, &a1, vec![Role::User, Role::Admin]),
            ),
        );
        routes.insert(
            by_id_path(A2_ID),
            (
                hyper::StatusCode::OK,
                binding_body(&d5, A2_ID, &a2, vec![Role::User, Role::Admin]),
            ),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;
        let mut trust = MemoryTrustStore::new();

        let err = build_tombstones(&mut sender, "localhost", Some(head2), &verifier, &mut trust, NOW)
            .await
            .expect_err("a withheld tail must fail closed");
        assert_eq!(err.code, "revocation_unverified");
    }

    /// (c) A record whose issuer's D5 binding is NOT an admin fails closed: the
    /// issuer signature verifies, but authority does not (`NotAdmin`).
    #[tokio::test]
    async fn non_admin_issuer_fails_closed() {
        let d5 = SigningKey::generate();
        let u = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());

        // A single-file revoke (no dual control) signed by `u`, whose binding
        // carries only the User ceiling — no admin authority.
        let (rec, head) = record_json(
            &per_file_revoke(GENESIS_HEAD.0, [0x55; 16], NONADMIN_ID),
            &u,
            None,
        );
        let mut routes = HashMap::new();
        routes.insert(
            "/v1/revocations".to_owned(),
            (hyper::StatusCode::OK, revocations_body(&[rec])),
        );
        routes.insert(
            by_id_path(NONADMIN_ID),
            (
                hyper::StatusCode::OK,
                binding_body(&d5, NONADMIN_ID, &u, vec![Role::User]),
            ),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;
        let mut trust = MemoryTrustStore::new();

        let err = build_tombstones(&mut sender, "localhost", Some(head), &verifier, &mut trust, NOW)
            .await
            .expect_err("a non-admin issuer must fail closed");
        assert_eq!(err.code, "revocation_unverified");
    }

    /// (d) The opt-in sink path: with `anchored_head == None` (no sink pinned), an
    /// empty served set verifies UNANCHORED and yields a [`TombstoneSet`] that
    /// revokes nobody — no external tip is required to accept an empty, well-formed
    /// control log.
    #[tokio::test]
    async fn build_tombstones_unanchored_accepts_empty_served_set() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());

        let mut routes = HashMap::new();
        routes.insert(
            "/v1/revocations".to_owned(),
            (hyper::StatusCode::OK, revocations_body(&[])),
        );
        let addr = spawn_router(routes).await;
        let mut sender = connect(&addr).await;
        let mut trust = MemoryTrustStore::new();

        let set = build_tombstones(&mut sender, "localhost", None, &verifier, &mut trust, NOW)
            .await
            .expect("an empty served set verifies unanchored");
        assert!(
            !set.is_account_revoked(&VICTIM),
            "an empty unanchored set revokes nobody"
        );
    }
}
