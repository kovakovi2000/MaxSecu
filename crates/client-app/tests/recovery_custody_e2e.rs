//! T6 e2e-shaped command-layer integration test (spec §12).
//!
//! Drives the REAL recovery-custody command logic — the same `*_in_session`
//! inner helpers the `#[tauri::command]` wrappers delegate to (widened to
//! `pub` for exactly this, mirroring how T4's e2e drives pub inner functions
//! rather than the Tauri commands, which need a running-app `State`). Nothing
//! here re-implements the ceremony: it seals a real recovery secret, splits it
//! through the actual `split_recovery_key` command, feeds MSHARE1 strings into
//! a plain `CeremonySession`, reconstructs, and proves against a REAL recovery
//! wire-wrap — the same construction as `recovery.rs::recovery_wire_wrap` and
//! the T7 recovery test.
//!
//! Real crypto, no mocks. The five spec §12 scenarios:
//!   S1 split 3-of-5 → collect 3 valid → reconstruct → prove against a real
//!      wrap → PASS.
//!   S2 only 2 shares → reconstruct rejected (`insufficient_shares`), no
//!      handle, no secret/share exposure anywhere.
//!   S3 one flipped `body` char → rejected at add-time (`corrupt_share`);
//!      never reaches reconstruct.
//!   S4 foreign-label share → rejected at add-time (`foreign_share`); PLUS a
//!      belt-and-braces genuinely-wrong reconstruction (shares mixed from two
//!      secrets under a spoofed matching label) that still fails the real-wrap
//!      proof (`verified:false`) — mirrors
//!      `recovery.rs::reconstructed_key_opens_only_for_correct_shares`.
//!   S5 all `n` shares → reconstruct still succeeds (the DTO layer does not
//!      hardcode exactly-`k`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use maxsecu_admin_core::recovery_seal::seal_recovery_secret;
use maxsecu_admin_core::split_recovery_key as split_scalar;
use maxsecu_client_app::ceremony::CeremonySession;
use maxsecu_client_app::commands::recovery_custody::{
    add_share_to_session, prove_in_session, reconstruct_in_session, split_recovery_key,
};
use maxsecu_client_app::dto::{ProveRequest, SplitRecoveryKeyRequest, SplitRecoveryKeyResponse};
use maxsecu_client_app::recovery_share::encode as encode_share;
use maxsecu_crypto::{
    generate_enc_keypair, random_array, wrap_dek, Dek, EncPublicKey, EncSecretKey, ARGON2_FLOOR,
};
use maxsecu_encoding::structs::WrapContext;
use maxsecu_encoding::types::Id;
use maxsecu_encoding::RECOVERY_ID;

const LABEL: &str = "MaxSecu recovery key, 2026-07";
const FILE_ID: Id = Id([0xF1; 16]);
const VERSION: u64 = 7;

/// Lowercase-hex a byte slice (self-contained; no reach into crate internals).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seal `secret` under `passphrase` into a UNIQUE temp file (random suffix on
/// top of pid so parallel test runs never collide), returning the guard dir and
/// the file path string the `split_recovery_key` command reads.
fn seal_to_temp(secret: &EncSecretKey, passphrase: &str) -> (std::path::PathBuf, String) {
    let sealed = seal_recovery_secret(secret, passphrase, ARGON2_FLOOR).expect("seal");
    let rand = hex(&random_array::<8>());
    let dir = std::env::temp_dir().join(format!("maxsecu-rc-e2e-{}-{}", std::process::id(), rand));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("recovery.sealed");
    std::fs::write(&path, &sealed).expect("write sealed");
    let path_str = path.to_string_lossy().into_owned();
    (dir, path_str)
}

/// Split a sealed recovery secret via the ACTUAL `split_recovery_key` command
/// (unseal + Shamir-split + MSHARE1-encode), returning its `n` share strings.
fn split_via_command(path: &str, passphrase: &str, k: u8, n: u8) -> SplitRecoveryKeyResponse {
    split_recovery_key(SplitRecoveryKeyRequest {
        recovery_secret_path: path.to_owned(),
        passphrase: passphrase.to_owned(),
        label: LABEL.to_owned(),
        k,
        n,
    })
    .expect("split_recovery_key command succeeds")
}

/// Build the wire recovery wrap `enc(32) ‖ ct` EXACTLY as the upload path does:
/// `wrap_dek` to the recovery PUBLIC key under the RECOVERY_ID-bound context
/// (mirrors `recovery.rs::recovery_wire_wrap`).
fn recovery_wire_wrap(rpk: &EncPublicKey, dek: &Dek, file_id: Id, version: u64) -> Vec<u8> {
    let ctx = WrapContext {
        file_id,
        version,
        recipient_id: RECOVERY_ID,
    };
    let w = wrap_dek(rpk, dek, &ctx).expect("wrap");
    let mut wire = w.enc.to_vec();
    wire.extend_from_slice(&w.ct);
    wire
}

/// A `ProveRequest` naming `handle`, committing to `dek`, carrying `wire`.
fn prove_req(handle: String, dek: &Dek, wire: &[u8]) -> ProveRequest {
    ProveRequest {
        ceremony_handle: handle,
        file_id_hex: hex(&FILE_ID.0),
        version: VERSION,
        dek_commit_hex: hex(&dek.commit()),
        recovery_wrap_b64: B64.encode(wire),
    }
}

/// Flip one character inside the MSHARE1 `body` field (field index 5), keeping
/// it a legal base64url character so the corruption is caught at the CHECKSUM
/// (`ChecksumMismatch` → `corrupt_share`), not by an earlier structural parse
/// error. Mirrors `recovery_share.rs`'s own body-mutation test helper.
fn flip_body_char(text: &str) -> String {
    let mut fields: Vec<String> = text.split(':').map(|s| s.to_owned()).collect();
    let body = &mut fields[5];
    let mut chars: Vec<char> = body.chars().collect();
    assert!(!chars.is_empty(), "body field is non-empty");
    // 'A' and 'B' are both valid base64url; swapping keeps length + alphabet so
    // the string still decodes to (different) bytes and reaches the checksum.
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    *body = chars.into_iter().collect();
    fields.join(":")
}

/// S1: split 3-of-5 → collect 3 valid shares → reconstruct → the reconstructed
/// key opens a REAL recovery wrap → `verified: true`.
#[test]
fn s1_three_of_five_reconstructs_and_proves_verified() {
    let (rsk, rpk) = generate_enc_keypair();
    let pw = "correct horse battery staple recovery!";
    let (_dir, path) = seal_to_temp(&rsk, pw);

    let resp = split_via_command(&path, pw, 3, 5);
    assert_eq!(resp.shares.len(), 5, "exactly n=5 MSHARE1 shares");
    assert_eq!(resp.k, 3);
    assert_eq!(resp.n, 5);

    // Collect 3 valid shares (indices 1,3,5 → positions 0,2,4); `have` reaches 3.
    let session = CeremonySession::new();
    let mut have = 0;
    for &i in &[0usize, 2, 4] {
        let a = add_share_to_session(&resp.shares[i], &session).expect("valid share accepted");
        have = a.have;
    }
    assert_eq!(have, 3, "three valid shares accepted → have == k");

    let rec = reconstruct_in_session(&session).expect("reconstruct succeeds");
    assert_eq!(rec.label, LABEL);
    assert_eq!(
        rec.ceremony_handle.len(),
        32,
        "16 random bytes → 32 hex chars"
    );

    // Prove the reconstruction against a REAL recovery wire-wrap for a known DEK.
    let dek = Dek::generate();
    let wire = recovery_wire_wrap(&rpk, &dek, FILE_ID, VERSION);
    let presp =
        prove_in_session(prove_req(rec.ceremony_handle, &dek, &wire), &session).expect("prove ok");
    assert!(
        presp.verified,
        "the reconstructed key opens the real recovery wrap → verified"
    );
}

/// S2: only 2 shares → reconstruct is refused with `insufficient_shares`, no
/// handle is minted, and no secret/share material is exposed anywhere.
#[test]
fn s2_below_threshold_is_insufficient_shares_no_exposure() {
    let (rsk, _rpk) = generate_enc_keypair();
    let pw = "two-shares-is-not-enough-pass";
    let (_dir, path) = seal_to_temp(&rsk, pw);
    let resp = split_via_command(&path, pw, 3, 5);

    // Add only k-1 = 2 shares.
    let session = CeremonySession::new();
    add_share_to_session(&resp.shares[0], &session).expect("share 1 ok");
    add_share_to_session(&resp.shares[1], &session).expect("share 2 ok");

    let err = reconstruct_in_session(&session).expect_err("below-k must fail closed");
    assert_eq!(err.code, "insufficient_shares");

    // No partial exposure: neither a share string nor the raw recovery scalar
    // appears in the sanitized error, and nothing was stored under any handle
    // (nothing was minted — the session holds no reconstructed key at all).
    let dbg = format!("{err:?}");
    assert!(
        !dbg.contains("MSHARE1"),
        "share text leaked into error: {dbg}"
    );
    let secret_hex = hex(&rsk.expose_bytes());
    assert!(
        !dbg.contains(&secret_hex),
        "recovery scalar leaked into error: {dbg}"
    );
    for share in &resp.shares {
        assert!(!dbg.contains(share), "a share string leaked into error");
    }
}

/// S3: one flipped `body` character → rejected at ADD-time by the checksum
/// (`corrupt_share`); it never reaches reconstruct.
#[test]
fn s3_flipped_body_char_is_corrupt_share_at_add_time() {
    let (rsk, _rpk) = generate_enc_keypair();
    let pw = "one-flipped-body-char-pass";
    let (_dir, path) = seal_to_temp(&rsk, pw);
    let resp = split_via_command(&path, pw, 3, 5);

    let corrupted = flip_body_char(&resp.shares[0]);
    let session = CeremonySession::new();
    let err = add_share_to_session(&corrupted, &session).expect_err("flipped body must fail");
    assert_eq!(err.code, "corrupt_share");

    // The rejected share was never admitted, so a subsequent reconstruct has
    // nothing to work with and fails closed (never silently used a bad share).
    {
        let inner = session.0.lock().unwrap();
        assert_eq!(inner.have(), 0, "the corrupt share was not admitted");
    }
    let rerr = reconstruct_in_session(&session).expect_err("no shares → fail closed");
    assert_eq!(rerr.code, "insufficient_shares");
}

/// S4: a foreign-label share is rejected at ADD-time (`foreign_share`); AND,
/// belt-and-braces, a genuinely-wrong reconstruction assembled from shares of
/// two different secrets (under a SPOOFED matching label that bypasses the
/// add-time label check) still FAILS the real-wrap proof (`verified:false`).
#[test]
fn s4_foreign_share_rejected_and_wrong_reconstruction_fails_proof() {
    // Secret A: the "real" recovery key — split via the actual command.
    let (rsk_a, rpk_a) = generate_enc_keypair();
    let pw = "foreign-share-scenario-pass";
    let (_dir, path) = seal_to_temp(&rsk_a, pw);
    let resp_a = split_via_command(&path, pw, 3, 5);

    // Secret B: an UNRELATED recovery key, split the same 3-of-5 shape.
    let (rsk_b, _rpk_b) = generate_enc_keypair();
    let shares_b = split_scalar(&rsk_b, 3, 5).expect("split B");

    // --- Part A: add-time foreign-label rejection ---
    let session = CeremonySession::new();
    add_share_to_session(&resp_a.shares[0], &session).expect("A share 1 ok"); // fixes label=LABEL
    add_share_to_session(&resp_a.shares[1], &session).expect("A share 2 ok");
    // A B-share under a DIFFERENT label → rejected against the session's label.
    let foreign = encode_share(&shares_b[2], "a-different-recovery-set", 3, 5);
    let ferr = add_share_to_session(&foreign, &session).expect_err("foreign label must fail");
    assert_eq!(ferr.code, "foreign_share");

    // --- Part B: belt-and-braces — spoof the label to bypass the add-time
    // check, drive a genuinely-wrong reconstruction, and prove it does NOT open
    // the real wrap (mirrors recovery.rs::reconstructed_key_opens_only_for_...).
    let spoofed = encode_share(&shares_b[2], LABEL, 3, 5); // B's index-3 share, spoofed label
    let mixed = CeremonySession::new();
    add_share_to_session(&resp_a.shares[0], &mixed).expect("A idx1 ok"); // index 1, poly A
    add_share_to_session(&resp_a.shares[1], &mixed).expect("A idx2 ok"); // index 2, poly A
    add_share_to_session(&spoofed, &mixed).expect("spoofed B share accepted (label matches)"); // index 3, poly B

    // The DTO layer does not validate correctness — mixing distinct-index shares
    // still Lagrange-interpolates a 32-byte scalar, so reconstruct returns Ok…
    let rec = reconstruct_in_session(&mixed).expect("mixed shares still reconstruct a key (Ok)");

    // …but that WRONG key cannot open a REAL recovery wrap to secret A's pubkey.
    let dek = Dek::generate();
    let wire = recovery_wire_wrap(&rpk_a, &dek, FILE_ID, VERSION);
    let presp = prove_in_session(prove_req(rec.ceremony_handle, &dek, &wire), &mixed)
        .expect("the proof attempt itself is a successful Ok(verified:false)");
    assert!(
        !presp.verified,
        "a wrong reconstruction must not open the real wrap → verified:false"
    );
}

/// S5: reconstruct with ALL `n` shares still succeeds — the DTO/command layer
/// does not hardcode exactly-`k` — and the result is the genuine recovery key.
#[test]
fn s5_all_n_shares_still_reconstruct() {
    let (rsk, rpk) = generate_enc_keypair();
    let pw = "all-n-shares-pass";
    let (_dir, path) = seal_to_temp(&rsk, pw);
    let resp = split_via_command(&path, pw, 3, 5);

    let session = CeremonySession::new();
    for i in 0..5usize {
        add_share_to_session(&resp.shares[i], &session).expect("all shares accepted");
    }
    {
        let inner = session.0.lock().unwrap();
        assert_eq!(inner.have(), 5, "all n=5 shares present (more than k=3)");
    }

    let rec = reconstruct_in_session(&session).expect("all-n reconstructs (not hardcoded to k)");

    // Confirm it's the RIGHT key: it opens a real recovery wrap → verified.
    let dek = Dek::generate();
    let wire = recovery_wire_wrap(&rpk, &dek, FILE_ID, VERSION);
    let presp =
        prove_in_session(prove_req(rec.ceremony_handle, &dek, &wire), &session).expect("prove ok");
    assert!(presp.verified, "all-n reconstruction is the genuine key");
}
