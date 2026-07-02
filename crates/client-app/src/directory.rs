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

/// A directory-verified recovery recipient: the wrap-target keys only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecipient {
    pub enc_pub: [u8; 32],
    pub mlkem_pub: Option<[u8; 1184]>,
}

/// Verify an already-fetched recovery-recipient `(binding_bytes, signature)` under
/// the pinned D5 and extract its wrap-target keys. Factored out so it is unit-
/// testable without TLS (mirrors `verify_author_binding`).
pub fn verify_recovery_binding(
    verifier: &DirectoryVerifier,
    trust: &mut dyn TrustStore,
    binding_bytes: &[u8],
    signature: &[u8; 64],
    now_ms: u64,
) -> Result<RecoveryRecipient, UiError> {
    let binding: DirBinding = decode(binding_bytes)
        .map_err(|_| UiError::new("untrusted", "Malformed directory record."))?;
    let v = verifier
        .verify_binding(&binding, signature, now_ms, trust)
        .map_err(|_| UiError::new("untrusted", "The recovery recipient could not be verified."))?;
    Ok(RecoveryRecipient {
        enc_pub: v.enc_pub,
        mlkem_pub: v.mlkem_pub,
    })
}

/// Resolve + D5-verify the configured recovery recipient by username
/// (`GET /v1/directory/{username}`). Fail-closed `untrusted` if unpublished/forged.
pub async fn resolve_recovery_recipient(
    sender: &mut SendRequest<Full<Bytes>>,
    host: &str,
    username: &str,
    verifier: &DirectoryVerifier,
    // `+ Send` for the same reason as `resolve_and_verify_author` (the trust
    // object is held across the `get_json` await ⇒ the future must be `Send`).
    trust: &mut (dyn TrustStore + Send),
    now_ms: u64,
) -> Result<RecoveryRecipient, UiError> {
    let (status, json) = get_json(sender, &format!("/v1/directory/{username}"), None, host).await?;
    if status != hyper::StatusCode::OK {
        return Err(UiError::new(
            "untrusted",
            "The recovery recipient is not published.",
        ));
    }
    let (bytes, sig) = parse_binding(&json)?;
    verify_recovery_binding(verifier, trust, &bytes, &sig, now_ms)
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
    verify_author_binding(verifier, trust, &bytes, &sig, now_ms)
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
/// sharing design §3). Mirrors `resolve_recovery_recipient`'s fetch+parse+verify+
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
    fn recovery_recipient_extracts_enc_pub() {
        let d5 = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, sig) = signed_binding(&d5); // enc_pub [0xE1;32], sig_pub [0x51;32]
        let rr = verify_recovery_binding(&verifier, &mut trust, &bytes, &sig, NOW).unwrap();
        assert_eq!(rr.enc_pub, [0xE1; 32]);
        assert_eq!(rr.mlkem_pub, None);
    }

    #[test]
    fn recovery_recipient_rejects_wrong_key() {
        let d5 = SigningKey::generate();
        let attacker = SigningKey::generate();
        let verifier = DirectoryVerifier::new(d5.verifying_key().to_bytes());
        let mut trust = MemoryTrustStore::new();
        let (bytes, _) = signed_binding(&d5);
        let forged =
            attacker.sign_canonical(labels::DIRBINDING, &decode::<DirBinding>(&bytes).unwrap());
        assert_eq!(
            verify_recovery_binding(&verifier, &mut trust, &bytes, &forged, NOW)
                .unwrap_err()
                .code,
            "untrusted"
        );
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
