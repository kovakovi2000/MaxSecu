//! Small crate-internal helpers shared across `client-core` verifiers.

use maxsecu_crypto::VerifyingKey;

/// Does **any** pinned Ed25519 key strictly verify `sig` over `msg`?
///
/// The single source of truth for the pinned-allowlist signature check used by
/// both the sink anchor-proof verifier ([`crate::sink`]) and the directory
/// key-transparency verifier ([`crate::transparency`]). Keeping them in lockstep
/// preserves the **fail-closed** invariant: an **empty** `pubs` allowlist ⇒ no key
/// can verify ⇒ `false`, so nothing validates when nothing is pinned.
pub(crate) fn any_key_verifies(pubs: &[[u8; 32]], msg: &[u8], sig: &[u8; 64]) -> bool {
    pubs.iter().any(|pk| {
        VerifyingKey::from_bytes(pk)
            .and_then(|vk| vk.verify_raw(msg, sig))
            .is_ok()
    })
}
