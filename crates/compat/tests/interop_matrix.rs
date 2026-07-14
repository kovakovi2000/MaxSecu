//! **Interop matrix — every frozen suite × every frozen keyblob version.**
//!
//! For each cell, today's code must still: **unwrap** the DEK from the frozen
//! wrap, **verify** the frozen signed manifest, and perform a **re-share** to
//! another recipient.
//!
//! This is the test that would have caught the shipped PQ-enrollment break
//! (`2a626d6`) — not as a missing JSON field, but as its actual symptom: *an old
//! classical binding can no longer participate in a re-share.*
//!
//! | file suite | keyblob v1 (classical) | keyblob v2 (PQ) |
//! |---|---|---|
//! | V1 (HPKE)   | unwrap + verify + reshare | unwrap + verify + reshare |
//! | V2 (hybrid) | **fails closed** (`ResharePqKeyMissing`) — see below | unwrap + verify + reshare |
//!
//! The `V2 × classical-recipient` cell cannot work today and **must not**: a
//! hybrid wrap needs the recipient's ML-KEM key, and there is none. Refusing is
//! correct (the alternative would be silently downgrading a PQ file to a
//! classical wrap). It is asserted explicitly, with its exact error, so that the
//! behaviour is a *decision* rather than an accident — and so the day someone
//! makes it succeed by stripping the PQ leg, this test tells them.
//!
//! ---------------------------------------------------------------------------
//! **TEST-ONLY KEY MATERIAL** — see the header of `golden_open.rs`.
//! ---------------------------------------------------------------------------

use maxsecu_client_core::{build_reshare, Identity, ReshareError, ReshareParams, TombstoneSet};
use maxsecu_compat::{read, read_str, CHECKLIST};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, generate_enc_keypair, generate_mlkem_keypair, unwrap_dek,
    unwrap_dek_hybrid, Dek, EncPublicKey, EncSecretKey, HybridEncSecretKey, VerifyingKey,
    WrappedDek,
};
use maxsecu_encoding::structs::{DirBinding, Manifest, WrapContext};
use maxsecu_encoding::types::{Id, Suite, Timestamp};
use maxsecu_encoding::{decode, labels, GENESIS_HEAD};
use serde_json::Value;

const NOW: Timestamp = Timestamp(1_719_500_000_000);

// ---------------------------------------------------------------------------
// loading the frozen world
// ---------------------------------------------------------------------------

fn expect(area: &str, file: &str) -> Value {
    serde_json::from_slice(&read(area, file)).expect("fixture expectation is valid JSON")
}

fn hex16(v: &Value) -> [u8; 16] {
    let b = hex::decode(v.as_str().expect("hex string")).expect("valid hex");
    let mut o = [0u8; 16];
    o.copy_from_slice(&b);
    o
}

fn no_tombstones() -> TombstoneSet {
    // An empty, genesis-anchored set: nobody is revoked. (Only `verify` can build
    // one, so a re-share can never run against an unverified set.)
    TombstoneSet::verify(&[], GENESIS_HEAD.0).expect("empty control chain")
}

/// Unlock a frozen keyblob — the ONLY way a real user's keys ever come back.
fn identity(stem: &str) -> Identity {
    let blob = read("keyblob", &format!("{stem}.bin"));
    let pw = read_str("keyblob", &format!("{stem}.passphrase.txt"));
    maxsecu_client_core::keyblob::unlock(&pw, &blob)
        .unwrap_or_else(|e| panic!("frozen {stem} no longer unlocks: {e}. {CHECKLIST}"))
}

/// A frozen, D5-delegation-signed directory binding — how a recipient's keys are
/// actually discovered before a share.
fn binding(stem: &str) -> DirBinding {
    decode(&read("encoding", &format!("{stem}.bin")))
        .unwrap_or_else(|e| panic!("frozen {stem} no longer decodes: {e}. {CHECKLIST}"))
}

/// A frozen signed manifest, VERIFIED under the author's directory sig key —
/// exactly what a download does before it will touch a single chunk.
fn verified_manifest(stem: &str, author_sig_pub: &[u8; 32]) -> Manifest {
    let bytes = read("encoding", &format!("{stem}.bin"));
    let raw = read("encoding", &format!("{stem}.sig"));
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw);

    let m: Manifest = decode(&bytes)
        .unwrap_or_else(|e| panic!("frozen {stem} no longer decodes: {e}. {CHECKLIST}"));
    VerifyingKey::from_bytes(author_sig_pub)
        .expect("author sig key")
        .verify_canonical(labels::MANIFEST, &m, &sig)
        .unwrap_or_else(|e| {
            panic!(
                "\n\nFROZEN MANIFEST NO LONGER VERIFIES ({stem}) — {e:?}\n\
                 The download path fails closed on an unverified manifest, so this means \
                 NO existing file of this suite can be opened by anyone. {CHECKLIST}\n"
            )
        });
    m
}

/// Open a frozen classical (Suite::V1 / HPKE) wrap with a recipient's X25519 key.
fn unwrap_frozen_v1(stem: &str, secret: &EncSecretKey) -> Dek {
    let exp = expect("crypto", &format!("{stem}.expect.json"));
    let wire = read("crypto", &format!("{stem}.bin"));
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&wire[..32]);
    let wrapped = WrappedDek {
        enc,
        ct: wire[32..].to_vec(),
    };
    let c = exp["wrap_context"].clone();
    let ctx = WrapContext {
        file_id: Id(hex16(&c["file_id"])),
        version: c["version"].as_u64().unwrap(),
        recipient_id: Id(hex16(&c["recipient_id"])),
    };
    unwrap_dek(secret, &wrapped, &ctx)
        .unwrap_or_else(|e| panic!("frozen {stem} no longer unwraps: {e}. {CHECKLIST}"))
}

/// Open the frozen hybrid (Suite::V2) wrap with a PQ recipient's {X25519, ML-KEM}.
fn unwrap_frozen_v2(id: &Identity) -> Dek {
    let exp = expect("crypto", "wrap_v2.expect.json");
    let wire = read("crypto", "wrap_v2.bin");
    let hybrid = deserialize_hybrid_wrap(&wire).expect("frozen hybrid wrap parses");
    let c = exp["wrap_context"].clone();
    let ctx = WrapContext {
        file_id: Id(hex16(&c["file_id"])),
        version: c["version"].as_u64().unwrap(),
        recipient_id: Id(hex16(&c["recipient_id"])),
    };
    let secret = HybridEncSecretKey::from_components(
        id.enc_secret().expose_bytes(),
        id.mlkem_seed()
            .expect("the v2 keyblob carries an ML-KEM seed"),
    );
    unwrap_dek_hybrid(&secret, &hybrid, &ctx)
        .unwrap_or_else(|e| panic!("frozen wrap_v2 no longer unwraps: {e}. {CHECKLIST}"))
}

// ---------------------------------------------------------------------------
// corpus coherence — the fixtures describe ONE world, not N unrelated blobs
// ---------------------------------------------------------------------------

/// The frozen keyblobs, wraps and directory bindings must all belong to the same
/// two users. Without this, every matrix cell below could pass while silently
/// testing unrelated key material.
#[test]
fn compat_frozen_corpus_is_one_coherent_world() {
    let a = identity("keyblob_v1"); // classical user (pre-PQ enrollment)
    let b = identity("keyblob_v2"); // PQ-enrolled user

    assert_eq!(
        a.enc_secret().expose_bytes().to_vec(),
        read("crypto", "wrap_v1.testkey"),
        "the frozen v1 keyblob and the frozen V1 wrap belong to different users — \
         the corpus is incoherent"
    );
    assert_eq!(
        b.enc_secret().expose_bytes().to_vec(),
        read("crypto", "wrap_v1_to_pq.testkey")
    );
    assert_eq!(
        b.enc_secret().expose_bytes().to_vec(),
        read("crypto", "wrap_v2.testkey")[..32].to_vec()
    );

    let bind_a = binding("signed_dirbinding_classical");
    let bind_b = binding("signed_dirbinding_pq");
    assert_eq!(bind_a.enc_pub.0, a.enc_pub_bytes());
    assert_eq!(bind_a.sig_pub.0, a.sig_pub_bytes());
    assert_eq!(bind_b.enc_pub.0, b.enc_pub_bytes());
    assert_eq!(bind_b.sig_pub.0, b.sig_pub_bytes());
    assert_eq!(
        bind_b.mlkem_pub.expect("pq binding").0,
        b.mlkem_pub_bytes().unwrap()
    );

    // The point of the whole matrix: the classical binding is EXACTLY the shape a
    // user enrolled before the PQ-enrollment fix still has published today.
    assert!(
        bind_a.mlkem_pub.is_none(),
        "the classical fixture must keep `mlkem_pub: None` — it stands in for every \
         already-enrolled user whose binding was never republished"
    );
}

// ---------------------------------------------------------------------------
// the matrix
// ---------------------------------------------------------------------------

/// Cell (V1 file × v1 classical keyblob): the oldest possible user, on the oldest
/// possible file. Unwrap, verify, re-share.
#[test]
fn compat_interop_v1_file_with_v1_classical_keyblob() {
    let a = identity("keyblob_v1");
    let bind_a = binding("signed_dirbinding_classical");
    let m = verified_manifest("signed_manifest_v1", &bind_a.sig_pub.0);
    assert_eq!(m.alg, Suite::V1);

    let dek = unwrap_frozen_v1("wrap_v1", a.enc_secret());
    assert_eq!(
        dek.commit(),
        m.dek_commit.0,
        "\n\nThe DEK unwrapped from a frozen V1 wrap no longer matches the frozen \
         manifest's `dek_commit`. Download fails closed on exactly this check, so every \
         classical file ever uploaded is unopenable. {CHECKLIST}\n"
    );

    reshare_and_reopen(&a, bind_a.user_id, &m, &dek, Suite::V1);
}

/// Cell (V1 file × v2 PQ keyblob): a user who UPGRADED to PQ must not lose the
/// classical files already shared with them. Their X25519 half still opens the
/// old HPKE wrap, and they can still re-share it.
#[test]
fn compat_interop_v1_file_with_v2_pq_keyblob() {
    let b = identity("keyblob_v2");
    let bind_a = binding("signed_dirbinding_classical");
    let bind_b = binding("signed_dirbinding_pq");
    let m = verified_manifest("signed_manifest_v1", &bind_a.sig_pub.0);
    assert_eq!(m.alg, Suite::V1);

    let dek = unwrap_frozen_v1("wrap_v1_to_pq", b.enc_secret());
    assert_eq!(
        dek.commit(),
        m.dek_commit.0,
        "\n\nA PQ-enrolled user can no longer open a CLASSICAL file that was shared with \
         them. Upgrading a user's keyblob to v2 must never strand the files they already \
         had access to. {CHECKLIST}\n"
    );

    // The re-share of a V1 file stays classical — the wrap layout follows the
    // FILE's suite, never the granter's or the recipient's capabilities.
    reshare_and_reopen(&b, bind_b.user_id, &m, &dek, Suite::V1);
}

/// Cell (V2 file × v2 PQ keyblob): the hybrid path end to end.
#[test]
fn compat_interop_v2_file_with_v2_pq_keyblob() {
    let b = identity("keyblob_v2");
    let bind_b = binding("signed_dirbinding_pq");
    let m = verified_manifest("signed_manifest_v2", &bind_b.sig_pub.0);
    assert_eq!(m.alg, Suite::V2);

    let dek = unwrap_frozen_v2(&b);
    assert_eq!(
        dek.commit(),
        m.dek_commit.0,
        "\n\nThe DEK unwrapped from the frozen 1168-byte hybrid wrap no longer matches the \
         frozen manifest's `dek_commit` — every post-quantum file is unopenable. \
         {CHECKLIST}\n"
    );

    reshare_and_reopen(&b, bind_b.user_id, &m, &dek, Suite::V2);
}

/// Cell (V2 file × v1 classical keyblob) — **the PQ-enrollment break, pinned.**
///
/// A user holding a classical (v1) keyblob has no ML-KEM key, and their directory
/// binding therefore publishes none. Re-sharing a Suite::V2 file *to* them cannot
/// produce an openable wrap, so `build_reshare` refuses with
/// [`ReshareError::ResharePqKeyMissing`].
///
/// **That refusal is CORRECT, not a break.** The hybrid wrap has no classical-only
/// mode; the only ways to "make it work" would be to silently drop the PQ leg
/// (downgrading a post-quantum file to classical security without telling anyone)
/// or to emit a wrap the recipient can never open. Failing closed — loudly, with a
/// distinct error the UI turns into "ask them to re-enroll" — is the right answer.
///
/// What the shipped bug actually was: enrollment stopped publishing `mlkem_pub`
/// for *newly* enrolled users' bindings, so EVERY recipient looked like this cell
/// and every V2 re-share died here. A field-level JSON test would not have caught
/// it; this one does, because it exercises the real symptom.
#[test]
fn compat_interop_v2_file_to_classical_recipient_fails_closed() {
    let b = identity("keyblob_v2"); // the granter: holds the V2 file's DEK
    let bind_a = binding("signed_dirbinding_classical"); // the classical recipient
    let bind_b = binding("signed_dirbinding_pq");
    let m = verified_manifest("signed_manifest_v2", &bind_b.sig_pub.0);
    let dek = unwrap_frozen_v2(&b);

    assert!(
        bind_a.mlkem_pub.is_none(),
        "the classical recipient has no ML-KEM key"
    );

    let err = build_reshare(
        &ReshareParams {
            granter: &b,
            granter_id: bind_b.user_id,
            file_id: m.file_id,
            version: m.version,
            dek_commit: m.dek_commit.0,
            recipient_id: bind_a.user_id,
            recipient_enc_pub: EncPublicKey::from_bytes(bind_a.enc_pub.0),
            suite: Suite::V2,
            recipient_mlkem_pub: bind_a.mlkem_pub.map(|k| k.0),
            created_at: NOW,
        },
        &dek,
        &no_tombstones(),
    )
    // `WrapOut` is not `Debug` (it carries key material), so map the Ok side away
    // before asserting on the error.
    .map(|_| ())
    .expect_err("a V2 re-share to a non-PQ recipient must fail closed");

    assert_eq!(
        err,
        ReshareError::ResharePqKeyMissing,
        "\n\nA Suite::V2 re-share to a recipient with NO ML-KEM key must fail closed with \
         `ResharePqKeyMissing` (so the UI can prompt them to re-enroll).\n\
         If this now SUCCEEDS, the PQ leg has been silently dropped and post-quantum files \
         are being wrapped classically — a security downgrade users were never told about.\n\
         If it now fails with a DIFFERENT error, the UI can no longer tell \"they need to \
         re-enroll\" apart from a genuine failure, and sharing looks permanently broken to \
         the user. {CHECKLIST}\n"
    );

    // And the same file re-shares fine to a PQ recipient — proving the refusal is
    // about the recipient's key material, not a broken V2 path.
    reshare_and_reopen(&b, bind_b.user_id, &m, &dek, Suite::V2);
}

// ---------------------------------------------------------------------------
// the shared re-share leg
// ---------------------------------------------------------------------------

/// Re-share `dek` (already unwrapped from a FROZEN wrap, under a FROZEN manifest)
/// to a brand-new recipient, then open the resulting wrap as that recipient.
///
/// This closes the loop the golden fixtures alone cannot: it is not enough that
/// today's code can *read* yesterday's data — a user must still be able to *use*
/// it. A file you can open but can no longer share is still a broken upgrade.
fn reshare_and_reopen(granter: &Identity, granter_id: Id, m: &Manifest, dek: &Dek, suite: Suite) {
    let (recip_enc_sk, recip_enc_pk) = generate_enc_keypair();
    let (recip_mlkem_seed, recip_mlkem_pub) = generate_mlkem_keypair();
    let recipient_id = Id([0x7E; 16]);

    let out = build_reshare(
        &ReshareParams {
            granter,
            granter_id,
            file_id: m.file_id,
            version: m.version,
            dek_commit: m.dek_commit.0,
            recipient_id,
            recipient_enc_pub: recip_enc_pk,
            suite,
            recipient_mlkem_pub: match suite {
                Suite::V1 => None,
                Suite::V2 => Some(recip_mlkem_pub),
            },
            created_at: NOW,
        },
        dek,
        &no_tombstones(),
    )
    .unwrap_or_else(|e| {
        panic!(
            "\n\nRE-SHARE OF A FROZEN {suite:?} FILE FAILED — {e}\n\
             The DEK came out of a wrap a real recipient already has, under a manifest a \
             real server already stores. If it can no longer be re-shared, existing users \
             can open their data but can never pass it on — the share button is dead for \
             every file uploaded before this change. {CHECKLIST}\n"
        )
    });

    // The grant is possession-entailing and signed by the granter.
    assert_eq!(out.granted_by, granter_id);
    assert_eq!(out.grant.dek_commit.0, m.dek_commit.0);
    VerifyingKey::from_bytes(&granter.sig_pub_bytes())
        .expect("granter sig key")
        .verify_canonical(labels::GRANT, &out.grant, &out.grant_sig)
        .expect("the re-share grant must verify under the granter's directory key");

    // ...and the new recipient can actually open what they were given.
    let ctx = WrapContext {
        file_id: m.file_id,
        version: m.version,
        recipient_id,
    };
    let opened = match suite {
        Suite::V1 => unwrap_dek(&recip_enc_sk, &out.wrapped_dek, &ctx)
            .expect("the re-shared classical wrap must open for the recipient"),
        Suite::V2 => {
            // A V2 re-share packs the hybrid wire into `WrappedDek` as enc ‖ ct.
            let mut wire = out.wrapped_dek.enc.to_vec();
            wire.extend_from_slice(&out.wrapped_dek.ct);
            assert_eq!(
                wire.len(),
                1168,
                "a V2 re-share must emit the 1168-byte hybrid wire"
            );
            let hybrid = deserialize_hybrid_wrap(&wire).expect("hybrid wire");
            let sec =
                HybridEncSecretKey::from_components(recip_enc_sk.expose_bytes(), recip_mlkem_seed);
            unwrap_dek_hybrid(&sec, &hybrid, &ctx)
                .expect("the re-shared hybrid wrap must open for the recipient")
        }
    };
    assert_eq!(
        opened.commit(),
        m.dek_commit.0,
        "the re-shared wrap opened to a DEK that does not match the manifest — the \
         recipient would be handed a key that decrypts nothing"
    );
}
