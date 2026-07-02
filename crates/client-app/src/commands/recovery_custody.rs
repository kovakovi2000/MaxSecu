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

use crate::ceremony::CeremonySession;
use crate::dto::{
    AddShareRequest, AddShareResponse, SplitRecoveryKeyRequest, SplitRecoveryKeyResponse,
};
use crate::error::UiError;
use crate::recovery_share::{parse_and_verify, ShareParseError};
use maxsecu_admin_core::recovery_seal::{open_recovery_secret, RecoverySealError};
use maxsecu_admin_core::split_recovery_key as split_scalar;
use maxsecu_crypto::Share;
use tauri::State;
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

/// The shared `bad_threshold` [`UiError`] — `split_recovery_key` builds this
/// same error at two points (the early client-side gate and `split_scalar`'s
/// own defense-in-depth rejection); factored out so the code/message pair
/// has exactly one place to change.
fn bad_threshold_err() -> UiError {
    UiError::new("bad_threshold", "Choose a threshold with 1 ≤ k ≤ n.")
}

/// Map a fail-closed [`ShareParseError`] to a sanitized [`UiError`]. The
/// checksum-mismatch case gets its OWN distinct code (`corrupt_share`),
/// separate from every other parse failure (`malformed_share`) — spec §6 step
/// 1 calls for two visibly different messages: "check for a copy/paste
/// error" (the text isn't even shaped like a share) vs. "may be corrupted or
/// mistyped" (it parsed structurally but its content doesn't self-verify).
fn map_parse_err(e: ShareParseError) -> UiError {
    match e {
        ShareParseError::ChecksumMismatch => UiError::new(
            "corrupt_share",
            "This share may be corrupted or mistyped — re-enter it.",
        ),
        _ => UiError::new(
            "malformed_share",
            "This doesn't look like a MaxSecu recovery share — check for a copy/paste error.",
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
        return Err(bad_threshold_err());
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
    let mut shares = split_scalar(&secret, req.k, req.n).map_err(|_| bad_threshold_err())?;

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

/// `add_recovery_share` — accept one pasted/scanned MSHARE1 share into the
/// running reconstruct ceremony (spec §6 step 1).
///
/// Synchronous, local-only: parses + checksum-verifies the text (T2), then
/// validates it against the in-progress [`CeremonySession`] (T3) BEFORE
/// adding it, failing closed with a DISTINCT code per corruption/misuse
/// class:
/// 1. malformed text (`malformed_share`) — wrong version tag / bad base64 /
///    wrong field count / bad integer.
/// 2. wrong checksum (`corrupt_share`) — a DISTINCT code from (1); the text
///    parsed structurally but its content doesn't self-verify.
/// 3. (defense) an out-of-range `index` (`invalid_share_index`) —
///    `parse_and_verify` does not range-check `index` against `n`, so that's
///    this command's job.
/// 4. a duplicate `index` already collected this session (`duplicate_share`).
/// 5. a label OR `k` mismatch against the session's first-accepted share
///    (`foreign_share`) — both signal a share from a different split; `n` is
///    not independently cross-checked here because `CeremonySessionInner`
///    only fixes/retains `label`/`need` (its own doc comment, `ceremony.rs`)
///    — a same-label/same-k-but-different-n foreign share is still caught by
///    (3) against its OWN declared `n`, and, failing that, by the §6 step-4
///    real-wrap proof downstream (never by this command alone).
///
/// On success, adds the share and returns only `{have, need, label}` — the
/// share bytes / `share_text` never appear in the response, a log, or a
/// `Debug` impl (never redisplayed, spec §6 step 1).
#[tauri::command]
pub fn add_recovery_share(
    req: AddShareRequest,
    state: State<'_, CeremonySession>,
) -> Result<AddShareResponse, UiError> {
    add_share_to_session(&req.share_text, &state)
}

/// The testable logic behind [`add_recovery_share`], decoupled from
/// `tauri::State` (which has no public constructor outside a running Tauri
/// app) so it can be exercised directly against a plain [`CeremonySession`]
/// in unit tests.
fn add_share_to_session(
    share_text: &str,
    session: &CeremonySession,
) -> Result<AddShareResponse, UiError> {
    let parsed = parse_and_verify(share_text).map_err(map_parse_err)?;

    // (3) Defense: parse_and_verify does not range-check index against n.
    if parsed.index == 0 || parsed.index > parsed.n {
        return Err(UiError::new(
            "invalid_share_index",
            "This share's custodian index is out of range — check for a copy/paste error.",
        ));
    }

    let mut inner = session.0.lock().unwrap();

    // (4) Duplicate index already collected this session.
    if inner.shares().iter().any(|s| s.index == parsed.index) {
        return Err(UiError::new(
            "duplicate_share",
            &format!("You've already added share {}.", parsed.index),
        ));
    }

    // (5) Label or k mismatch against the session's first-accepted share.
    if let Some(existing_label) = inner.label() {
        if existing_label != parsed.label || inner.need() != parsed.k {
            return Err(UiError::new(
                "foreign_share",
                "This share is from a different recovery key set.",
            ));
        }
    }

    let share = Share {
        index: parsed.index,
        body: parsed.body,
    };
    inner.add_share(share, parsed.label, parsed.k);

    Ok(AddShareResponse {
        have: inner.have(),
        need: inner.need(),
        label: inner.label().unwrap_or_default().to_owned(),
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
        let (_dir, path) = sealed_secret_file(pw);

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
        let (_dir, path) = sealed_secret_file("the-right-passphrase-123");
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
        let (_dir, path) = sealed_secret_file(pw);
        let resp = split_recovery_key(req(&path, pw, 5, 5)).expect("k==n ok");
        assert_eq!(resp.shares.len(), 5);
    }
}

#[cfg(test)]
mod add_share_tests {
    use super::*;
    use maxsecu_crypto::split;

    /// `n` real MSHARE1 strings for an arbitrary test secret, `k`-of-`n`,
    /// under `label`. The secret's actual value is irrelevant here — this
    /// task never reconstructs, only accepts/accumulates wire-encoded shares.
    fn shares_for(k: u8, n: u8, label: &str) -> Vec<String> {
        let secret = b"add-recovery-share-test-secret!".to_vec();
        let shares = split(&secret, k, n).expect("split");
        shares
            .iter()
            .map(|s| crate::recovery_share::encode(s, label, k, n))
            .collect()
    }

    /// Flip one hex digit inside `text`'s trailing checksum field, keeping it
    /// 8 valid hex chars (so it fails `ChecksumMismatch`, not `BadChecksum`).
    fn mutate_checksum(text: &str) -> String {
        let mut fields: Vec<String> = text.split(':').map(|s| s.to_owned()).collect();
        let cs = fields.last_mut().expect("7 fields");
        let mut chars: Vec<char> = cs.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        *cs = chars.into_iter().collect();
        fields.join(":")
    }

    #[test]
    fn malformed_text_is_rejected_with_its_own_code() {
        let session = CeremonySession::new();
        let err = add_share_to_session("not a maxsecu recovery share at all", &session)
            .expect_err("malformed text must fail");
        assert_eq!(err.code, "malformed_share");
    }

    #[test]
    fn wrong_checksum_is_rejected_with_a_code_distinct_from_malformed() {
        let texts = shares_for(3, 5, "label-a");
        let mutated = mutate_checksum(&texts[0]);

        let session = CeremonySession::new();
        let err = add_share_to_session(&mutated, &session).expect_err("bad checksum must fail");
        assert_eq!(err.code, "corrupt_share");
        assert_ne!(
            err.code, "malformed_share",
            "checksum mismatch must be a DISTINCT code from generic malformed text"
        );
    }

    #[test]
    fn duplicate_index_already_in_session_is_rejected() {
        let texts = shares_for(3, 5, "label-a");
        let session = CeremonySession::new();
        add_share_to_session(&texts[0], &session).expect("first add ok");

        let err = add_share_to_session(&texts[0], &session).expect_err("duplicate index must fail");
        assert_eq!(err.code, "duplicate_share");
    }

    #[test]
    fn label_mismatch_against_first_accepted_share_is_rejected() {
        let first = shares_for(3, 5, "label-a");
        let foreign = shares_for(3, 5, "label-b");
        let session = CeremonySession::new();
        add_share_to_session(&first[0], &session).expect("first add ok");

        let err = add_share_to_session(&foreign[1], &session).expect_err("foreign label must fail");
        assert_eq!(err.code, "foreign_share");
    }

    #[test]
    fn k_mismatch_against_the_fixed_threshold_is_also_foreign_share() {
        // Same label, different k — mixing splits by threshold, not just by
        // label; the module docs call this the same foreign-set class.
        let first = shares_for(3, 5, "same-label");
        let different_k = shares_for(4, 5, "same-label");
        let session = CeremonySession::new();
        add_share_to_session(&first[0], &session).expect("first add ok");

        let err =
            add_share_to_session(&different_k[1], &session).expect_err("k mismatch must fail");
        assert_eq!(err.code, "foreign_share");
    }

    #[test]
    fn out_of_range_index_is_rejected() {
        // parse_and_verify does not range-check index against n — craft a
        // share whose own declared index (9) exceeds its own declared n (5).
        let bogus = Share {
            index: 9,
            body: b"whatever-body-bytes".to_vec(),
        };
        let text = crate::recovery_share::encode(&bogus, "label", 3, 5);

        let session = CeremonySession::new();
        let err = add_share_to_session(&text, &session).expect_err("out-of-range index must fail");
        assert_eq!(err.code, "invalid_share_index");
    }

    #[test]
    fn zero_index_is_rejected() {
        let bogus = Share {
            index: 0,
            body: b"whatever-body-bytes".to_vec(),
        };
        let text = crate::recovery_share::encode(&bogus, "label", 3, 5);

        let session = CeremonySession::new();
        let err = add_share_to_session(&text, &session).expect_err("index 0 must fail");
        assert_eq!(err.code, "invalid_share_index");
    }

    #[test]
    fn valid_shares_accumulate_have_and_never_redisplay_bytes() {
        let texts = shares_for(3, 5, "recovery-2026-07");
        let session = CeremonySession::new();

        let resp1 = add_share_to_session(&texts[0], &session).expect("share 1 ok");
        assert_eq!(resp1.have, 1);
        assert_eq!(resp1.need, 3);
        assert_eq!(resp1.label, "recovery-2026-07");

        let resp2 = add_share_to_session(&texts[1], &session).expect("share 2 ok");
        assert_eq!(resp2.have, 2);
        assert_eq!(resp2.need, 3);

        let resp3 = add_share_to_session(&texts[2], &session).expect("share 3 ok");
        assert_eq!(resp3.have, 3);
        assert_eq!(resp3.need, 3);
        assert_eq!(resp3.label, "recovery-2026-07");

        // The response is structurally {have, need, label} only — but also
        // verify at runtime that no fragment of any accepted share text
        // (base64 body, MSHARE1 tag, checksum) leaked into the serialized
        // response.
        let s = serde_json::to_string(&resp3).unwrap();
        for text in &texts[..3] {
            assert!(!s.contains(text), "share text leaked into response: {s}");
        }
        assert!(
            !s.contains("MSHARE1"),
            "MSHARE1 tag leaked into response: {s}"
        );
    }

    #[test]
    fn duplicate_index_does_not_bump_have() {
        let texts = shares_for(3, 5, "label-a");
        let session = CeremonySession::new();
        add_share_to_session(&texts[0], &session).expect("first add ok");
        let _ = add_share_to_session(&texts[0], &session); // rejected duplicate

        // A fresh valid (non-duplicate) share still succeeds and `have` only
        // reflects genuinely accepted shares (1 + 1 = 2, not 3).
        let resp = add_share_to_session(&texts[1], &session).expect("second distinct share ok");
        assert_eq!(resp.have, 2);
    }
}
