//! Directory resolution for the download path: turn an author/owner `user_id`
//! into a D5-VERIFIED `sig_pub`/`enc_pub` (the keys the verify ladder trusts).
//! The server is only the transport — every served binding is re-verified here
//! against the pinned D5 root (§7.2). Only verified key bytes leave this module;
//! grant/manifest interiors never do.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::client::conn::http1::SendRequest;

use maxsecu_client_core::{DirectoryVerifier, TrustStore};
use maxsecu_encoding::decode;
use maxsecu_encoding::structs::DirBinding;
use maxsecu_encoding::RECOVERY_ID;

use crate::error::UiError;
use crate::http_client::get_json;

/// TTL (ms) for a cached, verified author binding. Bounds how long a reused D5
/// verification + transparency result stays valid within a burst of opens (e.g.
/// every video in one bundle), short enough that an author key rotation is picked
/// up promptly on the next open.
const AUTHOR_CACHE_TTL_MS: u64 = 60_000;

/// Session-scoped memoization of the directory verify chain so opening several
/// videos in quick succession (a bundle's members, or a re-open) does not re-run
/// the same directory GET + D5 verify + transparency check each time.
///
/// SECURITY: only SUCCESSFULLY verified results are ever stored. A cached
/// [`VerifiedAuthor`] was D5-verified AND transparency-checked at insert time, so
/// reusing it within the TTL is equivalent to re-deriving it — the content is still
/// AEAD-verified against these keys downstream. `my_id` is keyed by username so a
/// re-login as a different user misses. Uses a plain `std::sync::Mutex` held only
/// across trivial map ops (never across an `.await`).
#[derive(Default)]
pub struct DirectoryCache {
    inner: std::sync::Mutex<DirCacheInner>,
}

#[derive(Default)]
struct DirCacheInner {
    my_id: Option<(String, [u8; 16])>,
    authors: std::collections::HashMap<[u8; 16], (VerifiedAuthor, u64)>,
}

impl DirectoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// My resolved `user_id` for `username`, if cached this session.
    pub fn my_id(&self, username: &str) -> Option<[u8; 16]> {
        let g = self.inner.lock().unwrap();
        g.my_id
            .as_ref()
            .filter(|(u, _)| u == username)
            .map(|(_, id)| *id)
    }

    pub fn put_my_id(&self, username: &str, id: [u8; 16]) {
        self.inner.lock().unwrap().my_id = Some((username.to_owned(), id));
    }

    /// A cached, still-fresh (< [`AUTHOR_CACHE_TTL_MS`]) verified author for `author_id`.
    pub fn author(&self, author_id: &[u8; 16], now_ms: u64) -> Option<VerifiedAuthor> {
        let g = self.inner.lock().unwrap();
        g.authors
            .get(author_id)
            .filter(|(_, at)| now_ms.saturating_sub(*at) < AUTHOR_CACHE_TTL_MS)
            .map(|(a, _)| a.clone())
    }

    pub fn put_author(&self, author_id: [u8; 16], author: VerifiedAuthor, now_ms: u64) {
        self.inner
            .lock()
            .unwrap()
            .authors
            .insert(author_id, (author, now_ms));
    }
}

/// A directory-verified author/owner: exactly the key bytes the §12.5 ladder
/// needs. No signed-record interior is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthor {
    pub user_id: [u8; 16],
    pub sig_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub fingerprint: [u8; 32],
    /// The verified binding's `key_version` (non-secret). The upload sets the
    /// owner's `owner_key_version` from this so `genesis_sig` verifies against the
    /// right binding.
    pub key_version: u64,
    /// The author's published ML-KEM key, if enrolled for PQ (mirrors
    /// `RecoveryRecipient::mlkem_pub`). `None` for a classical (V1) binding.
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Build the recipient-open [`VerifyContext`] shared by EVERY §12.5 open path
/// (viewer content/video-header, feed card header, bundle content, video job).
/// This is the ONE home for the content-substitution guard: `file_id` MUST be
/// the REQUESTED id (the ladder binds the served record to it via
/// `manifest.file_id != ctx.file_id => FileIdMismatch`; sourcing it from the
/// served manifest would make that a tautology and let an untrusted server
/// substitute any other validly-signed record the user can decrypt), the author/
/// owner sig pubs are pinned to the D5-verified author, and — critically —
/// `recipient_mlkem_seed` is `identity.mlkem_seed()` (NOT `None`): PQ-hybrid (V2)
/// records wrap the DEK to the recipient's ML-KEM key too, so the seed is
/// REQUIRED to unwrap them; passing `None` fails every V2 open closed. Keeping a
/// single builder means a future security edit lands in all paths at once.
///
/// Pure. The `<'a>` ties the returned ctx to the `identity` borrow, so callers
/// must hold it across a SYNCHRONOUS verify only (no await spanning the borrow).
pub(crate) fn build_verify_ctx<'a>(
    file_id: [u8; 16],
    author: &VerifiedAuthor,
    my_id: [u8; 16],
    identity: &'a maxsecu_client_core::Identity,
) -> maxsecu_client_core::VerifyContext<'a> {
    use maxsecu_client_core::{VerifyContext, NO_ADMINS, NO_GRANTERS};
    use maxsecu_encoding::types::{Id, RecipientType};
    VerifyContext {
        file_id: Id(file_id),
        author_sig_pub: author.sig_pub,
        owner_sig_pub: author.sig_pub,
        recipient_id: Id(my_id),
        recipient_type: RecipientType::User,
        recipient_secret: identity.enc_secret(),
        recipient_mlkem_seed: identity.mlkem_seed(),
        seen_max_version: None,
        granter_sig_pub: &NO_GRANTERS,
        admin_sig_pub: &NO_ADMINS,
        tombstones: None,
        compromise: None,
    }
}

/// Verify an already-fetched `(binding_bytes, signature)` under the pinned D5 and
/// extract the trusted keys. Factored out of the network path so it is unit-
/// testable without TLS. Any failure ⇒ a sanitized `untrusted` error.
pub fn verify_author_binding(
    verifier: &DirectoryVerifier,
    trust: &mut dyn TrustStore,
    binding_bytes: &[u8],
    signature: &[u8; 64],
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    let binding: DirBinding = decode(binding_bytes)
        .map_err(|_| UiError::new("untrusted", "Malformed directory record."))?;
    let v = verifier
        .verify_binding(&binding, signature, now_ms, trust)
        .map_err(|_| UiError::new("untrusted", "The author's identity could not be verified."))?;
    Ok(VerifiedAuthor {
        user_id: v.user_id,
        sig_pub: v.sig_pub,
        enc_pub: v.enc_pub,
        fingerprint: v.fingerprint,
        key_version: v.key_version,
        mlkem_pub: v.mlkem_pub,
    })
}

/// The recovery wrap-target keys: an X25519 `enc_pub` plus an OPTIONAL ML-KEM-768
/// key (present ⇒ the recovery grant is a Suite::V2 hybrid wrap). Since the
/// trusted-server-recovery redesign these come from the compiled-in recovery PIN
/// (`crate::recovery_pin`), NOT a directory binding — the server-served pubkey is
/// only ever COMPARED against the pin, never trusted on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecipient {
    pub enc_pub: [u8; 32],
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Trust-alarm A (spec §3/§7). Fetch the server-served recovery pubkey
/// (`GET /v1/recovery/pubkey`), constant-time-compare it against the compiled-in
/// recovery pin, and — ONLY on an exact match — return the **embedded pin's**
/// wrap-target keys (never the served ones; the served bytes are compared, not
/// trusted). This is called BEFORE any DEK wrap; on a mismatch the upload MUST be
/// blocked entirely (no wrap / no stage / no bytes stored).
///
/// * server has no recovery account (`404`) ⇒ fail-closed `no_recovery_account`;
/// * served pubkey ≠ embedded pin ⇒ fail-closed `server_untrusted` (the alarm);
/// * match ⇒ decode the embedded pin into its `{enc_pub, mlkem_pub}` halves.
///
/// No D5/directory verification is involved: the pin — not the directory — is the
/// trust anchor for the recovery wrap target.
pub async fn resolve_recovery_pin(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
) -> Result<RecoveryRecipient, UiError> {
    let (status, json) = get_json(sender, "/v1/recovery/pubkey", None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new(
            "no_recovery_account",
            "This server has no recovery account configured.",
        ));
    }
    // Canonicalize the served halves and compare the WHOLE blob against the pin.
    let served = parse_served_recovery_pin(&json)?;
    crate::recovery_pin::compare_served(&served).map_err(|_| {
        UiError::new(
            "server_untrusted",
            "This server's recovery key does not match this app's pinned key.",
        )
    })?;
    // Match: wrap to the EMBEDDED pin (trusted, compiled-in) — not the served key.
    let parsed = crate::recovery_pin::parse_pin(crate::recovery_pin::embedded_pin())
        .ok_or_else(|| UiError::new("server_untrusted", "The embedded recovery pin is malformed."))?;
    Ok(RecoveryRecipient {
        enc_pub: parsed.enc_pub,
        mlkem_pub: parsed.mlkem_pub,
    })
}

/// Decode a `GET /v1/recovery/pubkey` body (`{enc_pub_b64, mlkem_pub_b64?}`) into
/// the canonical pin byte form so it can be compared against the embedded pin. A
/// missing `mlkem_pub_b64` ⇒ a classical (33-byte) canonical pin; present ⇒ a
/// 1217-byte hybrid pin. Any malformed field fails closed as `server_untrusted`.
fn parse_served_recovery_pin(json: &serde_json::Value) -> Result<Vec<u8>, UiError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let bad = || UiError::new("server_untrusted", "The server sent a malformed recovery key.");
    let enc_vec = B64
        .decode(json["enc_pub_b64"].as_str().ok_or_else(bad)?)
        .map_err(|_| bad())?;
    let enc: [u8; 32] = enc_vec.try_into().map_err(|_| bad())?;
    let mlkem: Option<[u8; 1184]> = match json.get("mlkem_pub_b64").and_then(|v| v.as_str()) {
        None => None,
        Some(s) => {
            let m = B64.decode(s).map_err(|_| bad())?;
            Some(m.try_into().map_err(|_| bad())?)
        }
    };
    Ok(crate::recovery_pin::canonical_pin(
        &enc,
        mlkem.as_ref().map(|m| m.as_slice()),
    ))
}

/// Decode a §6.1 `BindingRes` JSON body into `(binding_bytes, signature)`.
fn parse_binding(json: &serde_json::Value) -> Result<(Vec<u8>, [u8; 64]), UiError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let untrusted = || UiError::new("untrusted", "Malformed directory record.");
    let bytes = B64
        .decode(json["binding_b64"].as_str().ok_or_else(untrusted)?)
        .map_err(|_| untrusted())?;
    let sig_vec = B64
        .decode(
            json["directory_signature_b64"]
                .as_str()
                .ok_or_else(untrusted)?,
        )
        .map_err(|_| untrusted())?;
    let sig: [u8; 64] = sig_vec.try_into().map_err(|_| untrusted())?;
    Ok((bytes, sig))
}

/// Fetch + D5-verify the binding for `user_id_hex` (`GET /v1/directory/by-id/…`).
/// `404` ⇒ the author is unsigned/pending ⇒ not a recipient (sanitized error).
/// `host` is the connect host threaded into the Host header (see http_client).
pub async fn resolve_and_verify_author(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    user_id_hex: &str,
    verifier: &DirectoryVerifier,
    // `+ Send`: the trust object is held across the `get_json` await, so the
    // returned future (and any async command awaiting it) must be `Send` for
    // Tauri. `MemoryTrustStore` is `Send`, so `&mut trust` still coerces here.
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    Ok(resolve_and_verify_author_logged(sender, host, user_id_hex, verifier, trust, now_ms)
        .await?
        .0)
}

/// Like [`resolve_and_verify_author`] but ALSO returns the canonical served
/// `DirBinding` leaf bytes — the EXACT bytes the directory KT log records for this
/// author (`crates/server/src/http.rs` publishes them on enrollment). The
/// browse/open resolve boundary feeds these to the trust-alarm-C gate
/// ([`crate::transparency::verify_binding_transparency`]) so the client can prove
/// the served binding is provably included in the KT log under a pinned,
/// non-equivocating checkpoint — catching a server that serves a key it never
/// logged. The bytes are the SAME ones D5-verified here (never re-fetched), so the
/// KT-proven leaf and the D5-trusted keys cannot diverge.
pub async fn resolve_and_verify_author_logged(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    user_id_hex: &str,
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<(VerifiedAuthor, Vec<u8>), UiError> {
    let (status, json) = get_json(
        sender,
        &format!("/v1/directory/by-id/{user_id_hex}"),
        None,
        host,
    )
    .await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new(
            "untrusted",
            "The author's identity is not published.",
        ));
    }
    let (bytes, sig) = parse_binding(&json)?;
    let author = verify_author_binding(verifier, trust, &bytes, &sig, now_ms)?;
    Ok((author, bytes))
}

/// Resolve MY own `user_id` from my published binding (`GET /v1/directory/{username}`),
/// used to compute the "only my uploads" flag. Verified under the pinned D5 too.
pub async fn resolve_my_user_id(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    verifier: &DirectoryVerifier,
    // `+ Send` for the same reason as `resolve_and_verify_author` (held across an
    // await ⇒ the future must be `Send` for a Tauri command).
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<[u8; 16], UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("pending", "Your account is not yet approved."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    Ok(verify_author_binding(verifier, trust, &bytes, &sig, now_ms)?.user_id)
}

/// Resolve + D5-verify MY OWN binding by username (`GET /v1/directory/{username}`),
/// returning the full verified author (user_id + key_version + keys). Used by the
/// upload to set `owner_id`/`owner_key_version`. Fail-closed `pending` if unpublished.
pub async fn resolve_my_binding(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    verifier: &DirectoryVerifier,
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("pending", "Your account is not yet approved."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    verify_author_binding(verifier, trust, &bytes, &sig, now_ms)
}

/// Resolve + D5-verify an arbitrary THIRD-PARTY recipient by username
/// (`GET /v1/directory/{username}`), for a post-upload share (multi-recipient
/// sharing design §3). Mirrors `resolve_my_binding`'s fetch+parse+verify+
/// fail-closed shape, but is generic (not the recovery sentinel) and returns the
/// full `VerifiedAuthor` (incl. `mlkem_pub`, forwarded from Task 1) so the caller
/// has everything `ReshareParams` needs. **No partial trust**: a `404`, a bad
/// signature, an expired `not_before`/`not_after`, or malformed bytes all fail
/// closed to `untrusted` — never a placeholder.
///
/// Defensively rejects a resolved `user_id == RECOVERY_ID`: this is defense in
/// depth only (`build_reshare` already rejects `RECOVERY_ID` server-independently,
/// `crates/client-core/src/reshare.rs`), not the sole security boundary — it just
/// gives the picker a clearer error than a downstream crypto-layer rejection would.
pub async fn resolve_recipient(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    verifier: &DirectoryVerifier,
    // `+ Send` for the same reason as the sibling resolvers (the trust object is
    // held across the `get_json` await ⇒ the future must be `Send`).
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<VerifiedAuthor, UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new("untrusted", "This username is not published."));
    }
    let (bytes, sig) = parse_binding(&json)?;
    let author = verify_author_binding(verifier, trust, &bytes, &sig, now_ms)?;
    if author.user_id == RECOVERY_ID.0 {
        return Err(UiError::new(
            "untrusted",
            "This username cannot be used as a share recipient.",
        ));
    }
    Ok(author)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maxsecu_client_core::MemoryTrustStore;
    use maxsecu_crypto::SigningKey;
    use maxsecu_encoding::encode;
    use maxsecu_encoding::labels;
    use maxsecu_encoding::structs::DirBinding;
    use maxsecu_encoding::types::{Bytes32, Id, MlKemPub, Role, RoleSet, Text, Timestamp};

    const NOW: u64 = 1_719_500_000_000;

    fn sample_author(id: u8) -> VerifiedAuthor {
        VerifiedAuthor {
            user_id: [id; 16],
            sig_pub: [id; 32],
            enc_pub: [id; 32],
            fingerprint: [id; 32],
            key_version: 1,
            mlkem_pub: None,
        }
    }

    #[test]
    fn directory_cache_my_id_is_username_scoped() {
        let c = DirectoryCache::new();
        assert_eq!(c.my_id("alice"), None);
        c.put_my_id("alice", [7u8; 16]);
        assert_eq!(c.my_id("alice"), Some([7u8; 16]));
        // A different username never reads alice's id (fail-safe on re-login).
        assert_eq!(c.my_id("bob"), None);
    }

    #[test]
    fn directory_cache_author_hits_within_ttl_and_expires_after() {
        let c = DirectoryCache::new();
        let id = [9u8; 16];
        assert_eq!(c.author(&id, NOW), None); // cold miss
        c.put_author(id, sample_author(9), NOW);
        // Fresh hit.
        assert_eq!(c.author(&id, NOW), Some(sample_author(9)));
        assert_eq!(c.author(&id, NOW + AUTHOR_CACHE_TTL_MS - 1), Some(sample_author(9)));
        // At/after the TTL → miss (re-verify).
        assert_eq!(c.author(&id, NOW + AUTHOR_CACHE_TTL_MS), None);
        // A different author id misses.
        assert_eq!(c.author(&[1u8; 16], NOW), None);
    }

    fn signed_binding(d5: &SigningKey) -> (Vec<u8>, [u8; 64]) {
        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let sig = d5.sign_canonical(labels::DIRBINDING, &b);
        (encode(&b), sig)
    }

    /// Same as `signed_binding` but with a PQ (ML-KEM) key published on the
    /// binding — mirrors `verified_binding_exposes_mlkem` in client-core's
    /// `directory.rs` tests.
    fn signed_binding_with_mlkem(d5: &SigningKey, mlkem_pub: [u8; 1184]) -> (Vec<u8>, [u8; 64]) {
        let b = DirBinding {
            username: Text::new("alice").unwrap(),
            user_id: Id([0x0A; 16]),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: Some(MlKemPub(mlkem_pub)),
        };
        let sig = d5.sign_canonical(labels::DIRBINDING, &b);
        (encode(&b), sig)
    }

    #[test]
    fn verifies_a_genuine_binding_and_extracts_keys() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding(&d5);
        let a = verify_author_binding(&verifier, &mut trust, &bytes, &sig, NOW).unwrap();
        assert_eq!(a.user_id, [0x0A; 16]);
        assert_eq!(a.sig_pub, [0x51; 32]);
        assert_eq!(a.enc_pub, [0xE1; 32]);
        assert_eq!(a.key_version, 1);
    }

    #[test]
    fn verified_author_exposes_mlkem_pub_when_published() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding_with_mlkem(&d5, [0x9C; 1184]);
        let a = verify_author_binding(&verifier, &mut trust, &bytes, &sig, NOW).unwrap();
        assert_eq!(a.mlkem_pub, Some([0x9C; 1184]));
    }

    #[test]
    fn verified_author_mlkem_pub_is_none_for_classical_binding() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding(&d5); // no mlkem_pub on this binding
        let a = verify_author_binding(&verifier, &mut trust, &bytes, &sig, NOW).unwrap();
        assert_eq!(a.mlkem_pub, None);
    }

    #[test]
    fn rejects_a_binding_signed_by_the_wrong_key() {
        let d5 = SigningKey::generate();
        let attacker = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, _good) = signed_binding(&d5);
        let forged =
            attacker.sign_canonical(labels::DIRBINDING, &decode::<DirBinding>(&bytes).unwrap());
        assert_eq!(
            verify_author_binding(&verifier, &mut trust, &bytes, &forged, NOW)
                .unwrap_err()
                .code,
            "untrusted"
        );
    }

    #[test]
    fn verify_author_binding_rejects_malformed_binding_bytes() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        // Not a canonical DirBinding ⇒ decode fails ⇒ sanitized untrusted (no panic).
        let err = verify_author_binding(&verifier, &mut trust, &[0xFFu8; 8], &[0u8; 64], NOW)
            .unwrap_err();
        assert_eq!(err.code, "untrusted");
    }

    #[test]
    fn parse_binding_rejects_malformed_json() {
        // Bad base64 ⇒ untrusted (no panic).
        let bad_b64 = serde_json::json!({
            "binding_b64": "!!!not-base64!!!",
            "directory_signature_b64": "AAAA"
        });
        assert_eq!(
            super::parse_binding(&bad_b64).unwrap_err().code,
            "untrusted"
        );
        // Wrong signature length (valid base64, but not 64 bytes) ⇒ untrusted.
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let short_sig = serde_json::json!({
            "binding_b64": B64.encode([1u8; 8]),
            "directory_signature_b64": B64.encode([2u8; 10])
        });
        assert_eq!(
            super::parse_binding(&short_sig).unwrap_err().code,
            "untrusted"
        );
        // Missing field ⇒ untrusted.
        let missing = serde_json::json!({ "binding_b64": B64.encode([1u8; 8]) });
        assert_eq!(
            super::parse_binding(&missing).unwrap_err().code,
            "untrusted"
        );
    }

    // --- `resolve_recipient` (third-party username resolver, T4 step) ---

    use http_body_util::BodyExt;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    /// The §6.1 `BindingRes` JSON shape a real server would send for a
    /// `GET /v1/directory/{username}` `200`.
    fn binding_json(bytes: &[u8], sig: &[u8; 64]) -> serde_json::Value {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        serde_json::json!({
            "binding_b64": B64.encode(bytes),
            "directory_signature_b64": B64.encode(sig),
        })
    }

    /// A tiny in-process HTTP/1.1 stub returning a fixed `(status, json body)` to
    /// every request, standing in for the pinned server connection (mirrors
    /// `recipients.rs`'s/`direct_link.rs`'s `spawn_stub`/`connect` test harness).
    async fn spawn_stub(status: hyper::StatusCode, body: serde_json::Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let status = status;
                let body = body.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let body = body.clone();
                        async move {
                            let _ = req.into_body().collect().await;
                            let resp = Response::builder()
                                .status(status)
                                .body(Full::<Bytes>::from(body.to_string()))
                                .unwrap();
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

    #[tokio::test]
    async fn resolve_recipient_returns_fully_verified_author_incl_mlkem() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding_with_mlkem(&d5, [0x9C; 1184]);
        let addr = spawn_stub(hyper::StatusCode::OK, binding_json(&bytes, &sig)).await;
        let mut sender = connect(&addr).await;

        let author = resolve_recipient(
            &mut sender,
            "localhost",
            "alice",
            &verifier,
            &mut trust,
            NOW,
        )
        .await
        .unwrap();

        assert_eq!(author.user_id, [0x0A; 16]);
        assert_eq!(author.sig_pub, [0x51; 32]);
        assert_eq!(author.enc_pub, [0xE1; 32]);
        assert_eq!(author.mlkem_pub, Some([0x9C; 1184]));
    }

    #[tokio::test]
    async fn resolve_recipient_fails_closed_on_404_not_published() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let addr = spawn_stub(hyper::StatusCode::NOT_FOUND, serde_json::Value::Null).await;
        let mut sender = connect(&addr).await;

        let err = resolve_recipient(
            &mut sender,
            "localhost",
            "nobody",
            &verifier,
            &mut trust,
            NOW,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, "untrusted");
    }

    #[tokio::test]
    async fn resolve_recipient_fails_closed_on_forged_signature() {
        let d5 = SigningKey::generate();
        let attacker = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, _good_sig) = signed_binding(&d5);
        let forged =
            attacker.sign_canonical(labels::DIRBINDING, &decode::<DirBinding>(&bytes).unwrap());
        let addr = spawn_stub(hyper::StatusCode::OK, binding_json(&bytes, &forged)).await;
        let mut sender = connect(&addr).await;

        let err = resolve_recipient(
            &mut sender,
            "localhost",
            "alice",
            &verifier,
            &mut trust,
            NOW,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, "untrusted");
    }

    #[tokio::test]
    async fn resolve_recipient_rejects_the_recovery_sentinel_defensively() {
        // A genuinely, validly signed binding — but its user_id IS the recovery
        // sentinel. Even though signature verification succeeds, the resolver
        // must reject it (defense in depth; `build_reshare` also rejects
        // RECOVERY_ID server-independently — this is a nicer error, not the sole
        // boundary). No partial trust: this must never come back as a usable
        // `VerifiedAuthor`.
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let b = DirBinding {
            username: Text::new("recovery").unwrap(),
            user_id: Id(RECOVERY_ID.0),
            enc_pub: Bytes32([0xE1; 32]),
            sig_pub: Bytes32([0x51; 32]),
            key_version: 1,
            roles: RoleSet::new([Role::User]),
            not_before: Timestamp(0),
            not_after: Timestamp(4_102_444_800_000),
            mlkem_pub: None,
        };
        let sig = d5.sign_canonical(labels::DIRBINDING, &b);
        let bytes = encode(&b);
        let addr = spawn_stub(hyper::StatusCode::OK, binding_json(&bytes, &sig)).await;
        let mut sender = connect(&addr).await;

        let err = resolve_recipient(
            &mut sender,
            "localhost",
            "recovery",
            &verifier,
            &mut trust,
            NOW,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, "untrusted");
    }
}
