//! T6 recovery-custody command: split a sealed recovery secret into `n` MSHARE1
//! shares, any `k` of which later reconstruct it (spec §4/§8).
//!
//! **Synchronous, local-only — no network, no `State`, no disk write.** This
//! module deliberately imports NO `hyper`/`http_client`/networking (spec §3): the
//! entire operation is (1) read the sealed file the caller named, (2) unseal it
//! with the passphrase (`admin_core::recovery_seal::open_recovery_secret`, T1),
//! (3) Shamir-split the recovery scalar (`admin_core::recovery::split_recovery_key`),
//! (4) wire-encode each `Share` as MSHARE1 (`crate::recovery_share::encode`, T2).
//!
//! Secret hygiene: the unsealed [`EncSecretKey`] carries its own zero-on-drop, and
//! the transient `Vec<Share>` bodies are wiped before return. Nothing sensitive is
//! written to disk or logged; the passphrase arrives already `Debug`-redacted in
//! the DTO and is dropped with the request.

use crate::dto::{SplitRecoveryKeyRequest, SplitRecoveryKeyResponse};
use crate::error::UiError;
use maxsecu_admin_core::recovery_seal::{open_recovery_secret, RecoverySealError};
use maxsecu_admin_core::split_recovery_key as split_scalar;
use zeroize::Zeroize;

/// Map a fail-closed [`RecoverySealError`] to a sanitized [`UiError`]. No path,
/// crypto internal, or secret ever crosses into the message — only a stable code
/// + short operator-facing text (mirrors `error.rs` discipline).
fn map_seal_err(e: RecoverySealError) -> UiError {
    match e {
        RecoverySealError::WrongPassphrase => UiError::new(
            "wrong_passphrase",
            "Wrong passphrase, or the recovery-secret file is corrupt.",
        ),
        RecoverySealError::CorruptFile => UiError::new(
            "recovery_file_corrupt",
            "The recovery-secret file is corrupt or not a MaxSecu recovery secret.",
        ),
        RecoverySealError::UnsupportedVersion(_) => UiError::new(
            "recovery_file_unsupported",
            "The recovery-secret file was written by a newer version of MaxSecu.",
        ),
        RecoverySealError::BelowArgonFloor => UiError::new(
            "recovery_file_weak",
            "The recovery-secret file uses key-derivation parameters below the required floor.",
        ),
    }
}

/// `split_recovery_key` — split a sealed recovery secret `k`-of-`n` (spec §8).
///
/// Synchronous, no network, no disk write. Fails closed on a bad threshold
/// (`k == 0 || n == 0 || k > n`, checked client-side-equivalently here AND again
/// inside `split_scalar` — defense in depth, D-E), on a wrong passphrase / corrupt
/// file, and on an unreadable path. On success returns exactly `n` MSHARE1 strings.
#[tauri::command]
pub fn split_recovery_key(
    req: SplitRecoveryKeyRequest,
) -> Result<SplitRecoveryKeyResponse, UiError> {
    // (D-E) Hard threshold check BEFORE any file/crypto work. `split_scalar` also
    // rejects these (ThresholdSplitFailed(BadThreshold)), but we fail closed early
    // with a specific, non-oracle code the UI can render inline.
    if req.k == 0 || req.n == 0 || req.k > req.n {
        return Err(UiError::new(
            "bad_threshold",
            "Choose a threshold with 1 ≤ k ≤ n.",
        ));
    }

    // (1) Read the caller-named sealed file. The bytes are ciphertext-at-rest (the
    // bare scalar is never present in them), so a read error is a benign path/IO
    // failure — mapped to a generic code, no path echoed back.
    let sealed = std::fs::read(&req.recovery_secret_path).map_err(|_| {
        UiError::new(
            "recovery_file_unreadable",
            "Could not read the recovery-secret file.",
        )
    })?;

    // (2) Unseal → the 32-byte recovery scalar as an EncSecretKey (zero-on-drop).
    // A wrong passphrase / tamper fails closed here — never a partial share set.
    let secret = open_recovery_secret(&sealed, &req.passphrase).map_err(map_seal_err)?;

    // (3) Shamir-split the scalar. Defense-in-depth: this independently rejects a
    // bad threshold with ThresholdSplitFailed(BadThreshold) → same UI code.
    let mut shares = split_scalar(&secret, req.k, req.n)
        .map_err(|_| UiError::new("bad_threshold", "Choose a threshold with 1 ≤ k ≤ n."))?;

    // (4) Wire-encode each Share as an MSHARE1 string with the operator label. The
    // strings ARE the interchange unit that legitimately crosses the seam (§8 DTO
    // rule); the raw Share bodies do not — wipe them once encoded.
    let out: Vec<String> = shares
        .iter()
        .map(|s| crate::recovery_share::encode(s, &req.label, req.k, req.n))
        .collect();
    for s in shares.iter_mut() {
        s.body.zeroize();
    }
    // `secret` (EncSecretKey) and `shares` (now-wiped) drop here.

    Ok(SplitRecoveryKeyResponse {
        shares: out,
        label: req.label,
        k: req.k,
        n: req.n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_share::parse_and_verify;
    use maxsecu_admin_core::recovery_seal::seal_recovery_secret;
    use maxsecu_crypto::{EncSecretKey, ARGON2_FLOOR};

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    /// A unique throwaway directory (no external tempdir crate — mirrors the
    /// keystore/config test convention in this crate).
    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("maxsecu-rc-{}-{}", std::process::id(), nanos()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Seal a known recovery scalar under `passphrase` into a fresh temp file and
    /// return (its dir, its path). Floor Argon2 params keep the KDF real but fast.
    fn sealed_secret_file(passphrase: &str) -> (std::path::PathBuf, String) {
        let scalar = [0x42u8; 32];
        let secret = EncSecretKey::from_bytes(scalar);
        let sealed = seal_recovery_secret(&secret, passphrase, ARGON2_FLOOR).expect("seal");
        let dir = tempdir();
        let path = dir.join("recovery.sealed");
        std::fs::write(&path, &sealed).expect("write");
        let path_str = path.to_string_lossy().into_owned();
        (dir, path_str)
    }

    fn req(path: &str, passphrase: &str, k: u8, n: u8) -> SplitRecoveryKeyRequest {
        SplitRecoveryKeyRequest {
            recovery_secret_path: path.to_owned(),
            passphrase: passphrase.to_owned(),
            label: "MaxSecu recovery key, 2026-07".to_owned(),
            k,
            n,
        }
    }

    #[test]
    fn valid_split_returns_n_verifiable_mshare1_strings() {
        let pw = "correct horse battery staple recovery!";
        let (_guard, path) = sealed_secret_file(pw);

        let resp = split_recovery_key(req(&path, pw, 3, 5)).expect("split ok");
        assert_eq!(resp.k, 3);
        assert_eq!(resp.n, 5);
        assert_eq!(resp.label, "MaxSecu recovery key, 2026-07");
        assert_eq!(resp.shares.len(), 5, "exactly n shares");

        let mut indices = Vec::new();
        for text in &resp.shares {
            assert!(text.starts_with("MSHARE1:"));
            let parsed = parse_and_verify(text).expect("MSHARE1 parses + checksum ok");
            assert_eq!(parsed.k, 3);
            assert_eq!(parsed.n, 5);
            assert_eq!(parsed.label, "MaxSecu recovery key, 2026-07");
            indices.push(parsed.index);
        }
        // Distinct custodian indices 1..=n.
        indices.sort_unstable();
        assert_eq!(indices, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn wrong_passphrase_fails_closed_no_shares() {
        let (_guard, path) = sealed_secret_file("the-right-passphrase-123");
        let err = split_recovery_key(req(&path, "the-WRONG-passphrase-123", 3, 5))
            .expect_err("must fail closed");
        assert_eq!(err.code, "wrong_passphrase");
    }

    #[test]
    fn bad_threshold_is_rejected_before_touching_the_file() {
        // k == 0, n == 0, and k > n all reject with the same specific code — and
        // a non-existent path proves the threshold gate runs BEFORE any file read.
        for (k, n) in [(0u8, 5u8), (3, 0), (6, 5)] {
            let err = split_recovery_key(req("/no/such/file.sealed", "pw", k, n))
                .expect_err("bad threshold must fail");
            assert_eq!(err.code, "bad_threshold", "k={k} n={n}");
        }
    }

    #[test]
    fn unreadable_path_maps_to_a_generic_code() {
        // Valid threshold but a path that does not exist → file-read error, not a
        // panic and not a leak of the path in the message.
        let err = split_recovery_key(req("/no/such/recovery.sealed", "pw", 3, 5))
            .expect_err("missing file must fail");
        assert_eq!(err.code, "recovery_file_unreadable");
    }

    #[test]
    fn corrupt_file_fails_closed() {
        let dir = tempdir();
        let path = dir.join("garbage.sealed");
        std::fs::write(&path, b"not a MaxSecu recovery secret").expect("write garbage");
        let err = split_recovery_key(req(&path.to_string_lossy(), "pw", 3, 5))
            .expect_err("garbage must fail");
        // Bad magic / short file → CorruptFile.
        assert_eq!(err.code, "recovery_file_corrupt");
    }

    #[test]
    fn k_equals_n_is_allowed() {
        let pw = "n-of-n custody passphrase";
        let (_guard, path) = sealed_secret_file(pw);
        let resp = split_recovery_key(req(&path, pw, 5, 5)).expect("k==n ok");
        assert_eq!(resp.shares.len(), 5);
    }
}
