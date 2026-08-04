//! **Golden corpus — "yesterday's bytes must still open today."**
//!
//! Every fixture under `compat/fixtures/` was produced ONCE and frozen. These
//! tests never re-seal anything: they take the committed bytes of an artifact a
//! real user already has on disk (a keyblob, a wrapped DEK, a sealed chunk, a
//! signed binding) and prove that TODAY's code still **opens** it.
//!
//! This is deliberately not a round-trip. A round-trip seals and opens with the
//! same code, so both halves drift together, the suite stays green, and the real
//! user's data rots. That hole is exactly what this file closes.
//!
//! ---------------------------------------------------------------------------
//! **TEST-ONLY KEY MATERIAL.** Every `*.testkey`, `*.passphrase.txt` and the
//! secrets embedded in the fixtures below are throwaway values generated for
//! this gate and used nowhere else. They are committed ON PURPOSE — a golden
//! artifact is worthless without the key that opens it. They are not, and must
//! never become, production key material, and nothing here may be named
//! `recovery_pin.bin` or land anywhere `crates/client-app/build.rs` reads (that
//! would defeat the ship-guard against embedding a test pin).
//! ---------------------------------------------------------------------------
//!
//! To (re)generate the corpus — a deliberate, reviewable act, NOT something the
//! gate ever does:
//!
//! ```text
//! cargo test -p maxsecu-compat --test golden_open compat_emit_fixtures -- --ignored
//! ```
//!
//! Regenerating an EXISTING fixture is a `corpus.lock` failure by design.

use std::collections::BTreeMap;

use maxsecu_compat::{area, fixtures_root, read, read_str, sha256_hex, verify_corpus_lock};
use maxsecu_crypto::{
    deserialize_hybrid_wrap, generate_enc_keypair, generate_mlkem_keypair, open_chunk, sha256,
    sign_delegation, unwrap_dek, unwrap_dek_hybrid, verify_delegation, wrap_dek, wrap_dek_hybrid,
    Argon2Params, Dek, EncSecretKey, HybridEncPublicKey, HybridEncSecretKey, SigningKey,
    VerifyingKey, WrappedDek, ARGON2_FLOOR,
};
use maxsecu_encoding::structs::{
    BundleBody, BundleMember, DirBinding, Manifest, Stream, WrapContext,
};
use maxsecu_encoding::types::{
    Bytes32, Compression, FileType, Id, MlKemPub, Role, RoleSet, StreamType, Suite, Text, Timestamp,
};
use maxsecu_encoding::{decode, encode, labels};
use serde_json::{json, Value};

/// The seven corpus areas this track owns. (`http/`, `pin/` and `client-state/`
/// belong to other tracks and are locked by their own tests.)
const AREAS: [&str; 7] = [
    "encoding",
    "crypto",
    "keyblob",
    "seedblob",
    "delegation",
    "blobref",
    "backup",
];

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn hex_of(b: &[u8]) -> String {
    hex::encode(b)
}

fn expect(area_name: &str, file: &str) -> Value {
    serde_json::from_slice(&read(area_name, file)).expect("fixture expectation is valid JSON")
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k)
        .unwrap_or_else(|| panic!("frozen expectation is missing the `{k}` field"))
}

fn hex_field(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(field(v, k).as_str().expect("hex field is a string")).expect("field is valid hex")
}

fn arr32(v: &Value, k: &str) -> [u8; 32] {
    let b = hex_field(v, k);
    let mut o = [0u8; 32];
    assert_eq!(b.len(), 32, "`{k}` must be 32 bytes");
    o.copy_from_slice(&b);
    o
}

fn arr16(v: &Value, k: &str) -> [u8; 16] {
    let b = hex_field(v, k);
    let mut o = [0u8; 16];
    assert_eq!(b.len(), 16, "`{k}` must be 16 bytes");
    o.copy_from_slice(&b);
    o
}

fn u64_field(v: &Value, k: &str) -> u64 {
    field(v, k).as_u64().expect("numeric field")
}

/// `WrapContext` rebuilt from a frozen expectation (the exact context the wrap
/// was bound to — a mismatch here is precisely what makes an old wrap unopenable).
fn wrap_ctx(v: &Value) -> WrapContext {
    let c = field(v, "wrap_context");
    WrapContext {
        file_id: Id(arr16(c, "file_id")),
        version: u64_field(c, "version"),
        recipient_id: Id(arr16(c, "recipient_id")),
    }
}

/// The `StreamType` codepoint as frozen in a fixture (1..=4). These codepoints
/// are part of the AEAD AAD of every chunk — see `value_locks.rs`.
fn stream_type_of(code: u64) -> StreamType {
    match code {
        1 => StreamType::Content,
        2 => StreamType::Metadata,
        3 => StreamType::Thumbnail,
        4 => StreamType::Preview,
        other => panic!("unknown StreamType codepoint {other} in a frozen fixture"),
    }
}

// ===========================================================================
// (D) corpus.lock — fixtures may be ADDED, never edited, never deleted
// ===========================================================================

#[test]
fn compat_corpus_is_locked() {
    for a in AREAS {
        verify_corpus_lock(a);
    }
}

// ===========================================================================
// (A1) Chunk AEAD + per-stream HKDF — every chunk ever uploaded
// ===========================================================================

/// A frozen sealed chunk of EVERY stream type still opens under today's
/// `open_chunk`, to the exact original plaintext.
///
/// If a per-stream HKDF label (`MaxSecu-content-v1`, …), the chunk AAD framing,
/// or the counter-nonce derivation ever changes, this is the test that says so —
/// because every one of those changes makes every chunk already uploaded by
/// every user permanently undecryptable.
#[test]
fn compat_frozen_chunks_still_open() {
    let exp = expect("crypto", "chunks.expect.json");
    let mut dek_bytes = [0u8; 32];
    dek_bytes.copy_from_slice(&read("crypto", "chunk_dek.testkey"));
    let dek = Dek::from_bytes(dek_bytes);

    // The DEK commitment is itself a frozen value: `HKDF(DEK, dek-commit label)`.
    assert_eq!(
        hex_of(&dek.commit()),
        field(&exp, "dek_commit").as_str().unwrap(),
        "\n\nThe dek-commit HKDF label changed. Every manifest ever signed commits to \
         HKDF(DEK, \"MaxSecu-dek-commit-v1\"); a different label means every download's \
         `dek.commit() == manifest.dek_commit` check fails and NO existing file opens. \
         This cannot ship. see docs/compat/CHECKLIST.md\n"
    );

    let chunks = field(&exp, "chunks").as_array().expect("chunks[] array");
    assert!(!chunks.is_empty(), "the chunk corpus is empty");

    for c in chunks {
        let file = field(c, "file").as_str().unwrap();
        let st = stream_type_of(u64_field(c, "stream_type"));
        let aad = maxsecu_encoding::structs::ChunkAad {
            file_id: Id(arr16(c, "file_id")),
            version: u64_field(c, "version"),
            stream_type: st,
            chunk_index: u64_field(c, "chunk_index"),
            is_last: field(c, "is_last").as_bool().expect("is_last bool"),
        };

        // The per-stream subkey is a frozen known answer, so a label change is
        // caught here even before the AEAD open fails.
        let ck = dek.stream_subkey(st);
        assert_eq!(
            hex_of(&ck[..]),
            field(c, "stream_subkey").as_str().unwrap(),
            "\n\nThe per-stream HKDF label for {st:?} changed: EVERY chunk of that stream \
             ever uploaded becomes undecryptable, permanently. There is no admin escape \
             hatch and no re-derivation path — the users' data is simply gone. \
             This cannot ship. see docs/compat/CHECKLIST.md\n"
        );

        let ct = read("crypto", file);
        let pt = open_chunk(&ck, &aad, &ct).unwrap_or_else(|e| {
            panic!(
                "\n\nFROZEN CHUNK NO LONGER OPENS: compat/fixtures/crypto/{file} ({st:?}) — {e}\n\
                 These are the exact ciphertext bytes a user already has stored on the \
                 server. Today's code cannot decrypt them. That means EVERY chunk ever \
                 uploaded is now undecryptable, permanently. This cannot ship. \
                 see docs/compat/CHECKLIST.md\n"
            )
        });
        assert_eq!(
            hex_of(&pt),
            field(c, "plaintext").as_str().unwrap(),
            "frozen chunk {file} decrypted to the WRONG plaintext — silent data corruption"
        );
    }
}

// ===========================================================================
// (A2) DEK wrap V1 (HPKE) and V2 (1168-byte hybrid) — every file's key
// ===========================================================================

fn open_frozen_v1_wrap(stem: &str) -> Dek {
    let exp = expect("crypto", &format!("{stem}.expect.json"));
    let wire = read("crypto", &format!("{stem}.bin"));
    assert_eq!(
        wire.len(),
        80,
        "the V1 wrap wire form is enc(32) ‖ ct(48) = 80 bytes"
    );
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&wire[..32]);
    let wrapped = WrappedDek {
        enc,
        ct: wire[32..].to_vec(),
    };

    let mut sk = [0u8; 32];
    sk.copy_from_slice(&read("crypto", &format!("{stem}.testkey")));
    let secret = EncSecretKey::from_bytes(sk);

    let dek = unwrap_dek(&secret, &wrapped, &wrap_ctx(&exp)).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN DEK WRAP (V1 / HPKE) NO LONGER UNWRAPS: \
             compat/fixtures/crypto/{stem}.bin — {e}\n\
             This is a real recipient's stored `file_key_wraps` row. If today's code \
             cannot unwrap it, that user has permanently lost access to every file \
             shared with them — the DEK exists nowhere else. This cannot ship. \
             see docs/compat/CHECKLIST.md\n"
        )
    });
    assert_eq!(
        hex_of(dek.expose()),
        field(&exp, "dek").as_str().unwrap(),
        "the frozen V1 wrap opened, but to the WRONG DEK"
    );
    assert_eq!(
        hex_of(&dek.commit()),
        field(&exp, "dek_commit").as_str().unwrap()
    );
    dek
}

#[test]
fn compat_frozen_wrap_v1_still_unwraps() {
    open_frozen_v1_wrap("wrap_v1");
}

/// The same classical (Suite::V1) file, wrapped to the PQ-enrolled recipient.
/// A PQ identity keeps its X25519 `enc` key, so a V1 wrap to it must still open
/// with the classical path — upgrading a user to PQ must never strand the
/// classical files already shared with them.
#[test]
fn compat_frozen_wrap_v1_to_pq_recipient_still_unwraps() {
    open_frozen_v1_wrap("wrap_v1_to_pq");
}

#[test]
fn compat_frozen_wrap_v2_hybrid_still_unwraps() {
    let exp = expect("crypto", "wrap_v2.expect.json");
    let wire = read("crypto", "wrap_v2.bin");
    assert_eq!(
        wire.len(),
        1168,
        "\n\nThe hybrid wrap wire length moved off 1168 \
         (eph_x_pub 32 ‖ ct_pq 1088 ‖ aead_ct 48). Every Suite::V2 wrap already stored \
         is exactly 1168 bytes; a different layout cannot parse them. \
         see docs/compat/CHECKLIST.md\n"
    );

    let hybrid = deserialize_hybrid_wrap(&wire).expect("frozen 1168-byte hybrid wrap must parse");
    assert_eq!(hybrid.eph_x_pub.len(), 32);
    assert_eq!(hybrid.ct_pq.len(), 1088);
    assert_eq!(hybrid.aead_ct.len(), 48);

    // testkey = x25519 secret (32) ‖ ML-KEM-768 decapsulation seed (64).
    let key = read("crypto", "wrap_v2.testkey");
    assert_eq!(
        key.len(),
        96,
        "hybrid secret = 32-byte X25519 ‖ 64-byte ML-KEM seed"
    );
    let mut x = [0u8; 32];
    x.copy_from_slice(&key[..32]);
    let mut pq = [0u8; 64];
    pq.copy_from_slice(&key[32..]);
    let secret = HybridEncSecretKey::from_components(x, pq);

    let dek = unwrap_dek_hybrid(&secret, &hybrid, &wrap_ctx(&exp)).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN DEK WRAP (V2 / X25519+ML-KEM-768 hybrid) NO LONGER UNWRAPS — {e}\n\
             Either the `MaxSecu-hybrid-wrap-v2` KEK label, the KEK `info` construction \
             (LABEL ‖ ctx ‖ eph_x_pub ‖ ct_pq), the zero-nonce AEAD, or the wire layout \
             changed. Every PQ-suite file already uploaded becomes unopenable for every \
             recipient. This cannot ship. see docs/compat/CHECKLIST.md\n"
        )
    });
    assert_eq!(
        hex_of(dek.expose()),
        field(&exp, "dek").as_str().unwrap(),
        "the frozen V2 hybrid wrap opened, but to the WRONG DEK"
    );
}

// ===========================================================================
// (A3) MXKB keyblob v1 AND v2 — the user's login / identity
// ===========================================================================

fn open_frozen_keyblob(stem: &str) -> maxsecu_client_core::Identity {
    let exp = expect("keyblob", &format!("{stem}.expect.json"));
    let blob = read("keyblob", &format!("{stem}.bin"));
    let pw = read_str("keyblob", &format!("{stem}.passphrase.txt"));

    assert_eq!(
        blob.len() as u64,
        u64_field(&exp, "blob_len"),
        "frozen {stem} changed length"
    );

    let id = maxsecu_client_core::keyblob::unlock(&pw, &blob).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN KEYBLOB NO LONGER UNLOCKS: compat/fixtures/keyblob/{stem}.bin — {e}\n\
             This is the `local_key_blob` a real user has on disk. It is the ONLY copy of \
             their private keys. If today's code cannot unlock it, that user cannot log \
             in, cannot decrypt anything they own, and cannot be recovered — their account \
             and all of their data are gone, permanently. This cannot ship. \
             see docs/compat/CHECKLIST.md\n"
        )
    });

    assert_eq!(
        hex_of(&id.enc_pub_bytes()),
        field(&exp, "enc_pub").as_str().unwrap(),
        "frozen {stem} unlocked to the WRONG enc key — silent identity corruption"
    );
    assert_eq!(
        hex_of(&id.sig_pub_bytes()),
        field(&exp, "sig_pub").as_str().unwrap(),
        "frozen {stem} unlocked to the WRONG sig key — every record they signed is orphaned"
    );
    assert_eq!(
        hex_of(&id.fingerprint()),
        field(&exp, "fingerprint").as_str().unwrap(),
        "frozen {stem}: the identity fingerprint changed — the value users verified in \
         person at enrollment no longer matches"
    );
    id
}

/// A legacy **v1** keyblob (157 B, no ML-KEM half) — written by every client that
/// shipped before PQ enrollment — must still unlock today.
#[test]
fn compat_frozen_keyblob_v1_still_unlocks() {
    let exp = expect("keyblob", "keyblob_v1.expect.json");
    let blob = read("keyblob", "keyblob_v1.bin");
    assert_eq!(&blob[0..4], b"MXKB");
    assert_eq!(blob[4], 1, "keyblob v1 version byte");
    assert_eq!(blob.len(), 157, "keyblob v1 is 45 header + 96 + 16 tag");

    let id = open_frozen_keyblob("keyblob_v1");
    assert!(
        id.mlkem_pub_bytes().is_none(),
        "a v1 blob predates PQ enrollment and must unlock to a non-PQ identity"
    );
    assert!(field(&exp, "mlkem_pub_sha256").is_null());
}

/// A **v2** keyblob (221 B, carries the 64-byte ML-KEM-768 decapsulation seed).
#[test]
fn compat_frozen_keyblob_v2_still_unlocks() {
    let exp = expect("keyblob", "keyblob_v2.expect.json");
    let blob = read("keyblob", "keyblob_v2.bin");
    assert_eq!(&blob[0..4], b"MXKB");
    assert_eq!(blob[4], 2, "keyblob v2 version byte");
    assert_eq!(blob.len(), 221, "keyblob v2 is 45 header + 160 + 16 tag");

    let id = open_frozen_keyblob("keyblob_v2");
    let mlkem = id
        .mlkem_pub_bytes()
        .expect("a v2 blob carries an ML-KEM key");
    assert_eq!(mlkem.len(), 1184);
    assert_eq!(
        hex_of(&sha256(&mlkem)),
        field(&exp, "mlkem_pub_sha256").as_str().unwrap(),
        "\n\nThe ML-KEM public key re-derived from the frozen keyblob's seed changed. \
         Every PQ recipient's directory binding publishes this key; if it no longer \
         re-derives, every hybrid wrap addressed to them is unopenable. \
         see docs/compat/CHECKLIST.md\n"
    );
}

// ===========================================================================
// (A4) MXD5 seedblob — the offline D5 directory root
// ===========================================================================

#[test]
fn compat_frozen_seedblob_still_unseals() {
    let exp = expect("seedblob", "seedblob_v1.expect.json");
    let blob = read("seedblob", "seedblob_v1.bin");
    let pw = read_str("seedblob", "seedblob_v1.passphrase.txt");

    assert_eq!(&blob[0..4], b"MXD5", "seedblob magic");
    assert_eq!(
        blob.len(),
        93,
        "MXD5 v1 blob is 45 header + 32 seed + 16 tag"
    );

    let seed = maxsecu_client_core::unseal_seed(&pw, &blob).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN D5 SEEDBLOB NO LONGER UNSEALS — {e}\n\
             This is the admin's offline directory ROOT, sealed under the recovery \
             passphrase and backed into the recovery blob. If it cannot be unsealed, the \
             directory trust root is unrecoverable: no delegation can ever be re-signed, \
             every pinned client eventually rejects the server, and the whole deployment \
             locks out. This cannot ship. see docs/compat/CHECKLIST.md\n"
        )
    });
    assert_eq!(hex_of(&seed[..]), field(&exp, "seed").as_str().unwrap());

    // The seed must still derive the same D5 public key the clients pin.
    let d5 = SigningKey::from_seed(&seed);
    assert_eq!(
        hex_of(&d5.verifying_key().to_bytes()),
        field(&exp, "d5_pub").as_str().unwrap(),
        "the D5 seed no longer derives the pinned directory public key — every shipped \
         client pins that key and would reject the directory outright"
    );
}

// ===========================================================================
// (A5) 113-byte delegation cert + the full pinned-D5 → binding trust chain
// ===========================================================================

/// The frozen delegation cert still parses and verifies against the pinned D5
/// key, and the operational key it authorizes still verifies the frozen
/// directory bindings. This is the entire client-side trust chain
/// (`pinned D5 → delegation → operational_pub → binding`) replayed over bytes a
/// deployed server is serving right now.
///
/// `verify()` takes an explicit `now`, so the frozen `verify_at` (inside the
/// window) keeps this test free of any system-clock dependence. The window is
/// also deliberately wide (10 years) so nothing here can expire.
#[test]
fn compat_frozen_delegation_still_verifies() {
    let exp = expect("delegation", "delegation_v1.expect.json");
    let wire = read("delegation", "delegation_v1.bin");
    assert_eq!(
        wire.len(),
        113,
        "\n\nThe delegation-cert wire length moved off 113 (49-byte body ‖ 64-byte sig). \
         Every deployed server serves a 113-byte cert; a shipped client that cannot parse \
         it rejects the directory and locks every user out. see docs/compat/CHECKLIST.md\n"
    );

    let cert = maxsecu_crypto::parse_delegation(&wire).expect("frozen delegation cert must parse");
    assert_eq!(cert.version(), 1);
    assert_eq!(
        hex_of(&cert.operational_pub()),
        field(&exp, "operational_pub").as_str().unwrap()
    );
    assert_eq!(cert.valid_from(), u64_field(&exp, "valid_from"));
    assert_eq!(cert.valid_until(), u64_field(&exp, "valid_until"));

    let d5_pub = arr32(&exp, "d5_pub");
    let now = u64_field(&exp, "verify_at");
    let op_pub = verify_delegation(&d5_pub, &wire, now).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN DELEGATION CERT NO LONGER VERIFIES — {e:?}\n\
             Clients PIN the D5 root and verify `D5 → delegation → operational_pub → \
             binding`, failing closed. If a delegation the admin already signed offline no \
             longer verifies, every shipped client rejects the directory: TOTAL LOCKOUT of \
             every user, with the only fix being a new offline ceremony + a client \
             re-install. This cannot ship. see docs/compat/CHECKLIST.md\n"
        )
    });
    assert_eq!(op_pub, cert.operational_pub());

    // ...and the authorized operational key still verifies the frozen bindings.
    let op = VerifyingKey::from_bytes(&op_pub).expect("operational_pub is a valid Ed25519 key");
    for stem in ["signed_dirbinding_classical", "signed_dirbinding_pq"] {
        let bytes = read("encoding", &format!("{stem}.bin"));
        let binding: DirBinding = decode(&bytes).expect("frozen binding decodes");
        let sig = sig64("encoding", &format!("{stem}.sig"));
        op.verify_canonical(labels::DIRBINDING, &binding, &sig)
            .unwrap_or_else(|e| {
                panic!(
                    "\n\nTHE PINNED-D5 TRUST CHAIN IS BROKEN at {stem} — {e:?}\n\
                     A directory binding the server already signed under the delegated \
                     operational key no longer verifies. Clients fail closed on this, so \
                     every enrolled user is locked out. see docs/compat/CHECKLIST.md\n"
                )
            });
    }
}

// ===========================================================================
// (A6) Signed canonical structs — every signature ever made
// ===========================================================================

fn sig64(area_name: &str, file: &str) -> [u8; 64] {
    let b = read(area_name, file);
    assert_eq!(b.len(), 64, "{file} is a raw 64-byte Ed25519 signature");
    let mut s = [0u8; 64];
    s.copy_from_slice(&b);
    s
}

/// A frozen **signed** `DirBinding` — both the legacy classical shape
/// (`mlkem_pub: None`, i.e. every binding published before the PQ-enrollment fix)
/// and the PQ shape — still decodes to the same fields and still verifies under
/// today's `signing_input()` and label.
#[test]
fn compat_frozen_signed_dirbindings_still_verify() {
    for stem in ["signed_dirbinding_classical", "signed_dirbinding_pq"] {
        let exp = expect("encoding", &format!("{stem}.expect.json"));
        let bytes = read("encoding", &format!("{stem}.bin"));
        let sig = sig64("encoding", &format!("{stem}.sig"));

        let b: DirBinding = decode(&bytes).unwrap_or_else(|e| {
            panic!(
                "\n\nFROZEN DIRECTORY BINDING NO LONGER DECODES: {stem} — {e}\n\
                 This is a signed binding the server is serving right now. If it cannot be \
                 decoded, the user it names cannot be verified and cannot be shared with. \
                 see docs/compat/CHECKLIST.md\n"
            )
        });

        assert_eq!(
            b.username.as_str(),
            field(&exp, "username").as_str().unwrap()
        );
        assert_eq!(b.user_id, Id(arr16(&exp, "user_id")));
        assert_eq!(b.enc_pub, Bytes32(arr32(&exp, "enc_pub")));
        assert_eq!(b.sig_pub, Bytes32(arr32(&exp, "sig_pub")));
        assert_eq!(b.key_version, u64_field(&exp, "key_version"));
        assert_eq!(b.not_before, Timestamp(u64_field(&exp, "not_before")));
        assert_eq!(b.not_after, Timestamp(u64_field(&exp, "not_after")));
        match field(&exp, "mlkem_pub_sha256").as_str() {
            None => assert!(
                b.mlkem_pub.is_none(),
                "{stem} must stay a CLASSICAL binding: it is the exact shape every user \
                 enrolled before the PQ-enrollment fix still has published"
            ),
            Some(want) => {
                let k = b.mlkem_pub.expect("PQ binding carries an ML-KEM key");
                assert_eq!(k.0.len(), 1184);
                assert_eq!(hex_of(&sha256(&k.0)), want);
            }
        }

        let signer = VerifyingKey::from_bytes(&arr32(&exp, "signer_pub")).unwrap();
        assert_eq!(field(&exp, "label").as_str().unwrap(), labels::DIRBINDING);
        signer
            .verify_canonical(labels::DIRBINDING, &b, &sig)
            .unwrap_or_else(|e| {
                panic!(
                    "\n\nFROZEN DIRECTORY-BINDING SIGNATURE NO LONGER VERIFIES: {stem} — {e:?}\n\
                     The `MaxSecu-dirbinding-v1` label, the `signing_input` framing, or the \
                     canonical encoding of `dirbinding` changed. EVERY signature ever made \
                     over a binding is now invalid, so no client can verify any user's keys: \
                     enrollment, sharing and login all fail closed for everyone. \
                     This cannot ship. see docs/compat/CHECKLIST.md\n"
                )
            });
    }
}

/// A frozen **signed** `Manifest` (one per suite) still decodes and verifies.
#[test]
fn compat_frozen_signed_manifests_still_verify() {
    for stem in ["signed_manifest_v1", "signed_manifest_v2"] {
        let exp = expect("encoding", &format!("{stem}.expect.json"));
        let bytes = read("encoding", &format!("{stem}.bin"));
        let sig = sig64("encoding", &format!("{stem}.sig"));

        let m: Manifest = decode(&bytes).unwrap_or_else(|e| {
            panic!(
                "\n\nFROZEN MANIFEST NO LONGER DECODES: {stem} — {e}\n\
                 A signed manifest is stored verbatim per file version; every download \
                 re-decodes it. If it cannot be decoded the file cannot be opened at all. \
                 see docs/compat/CHECKLIST.md\n"
            )
        });

        assert_eq!(m.file_id, Id(arr16(&exp, "file_id")));
        assert_eq!(m.version, u64_field(&exp, "version"));
        assert_eq!(m.file_type as u8 as u64, u64_field(&exp, "file_type"));
        assert_eq!(
            match m.alg {
                Suite::V1 => 1u64,
                Suite::V2 => 2u64,
            },
            u64_field(&exp, "alg")
        );
        assert_eq!(m.chunk_size as u64, u64_field(&exp, "chunk_size"));
        assert_eq!(m.dek_commit, Bytes32(arr32(&exp, "dek_commit")));
        assert_eq!(m.author_id, Id(arr16(&exp, "author_id")));
        assert_eq!(m.created_at, Timestamp(u64_field(&exp, "created_at")));
        assert!(m.recovery_present);
        assert_eq!(m.streams.len(), 4, "content/metadata/thumbnail/preview");

        let signer = VerifyingKey::from_bytes(&arr32(&exp, "signer_pub")).unwrap();
        assert_eq!(field(&exp, "label").as_str().unwrap(), labels::MANIFEST);
        signer
            .verify_canonical(labels::MANIFEST, &m, &sig)
            .unwrap_or_else(|e| {
                panic!(
                    "\n\nFROZEN MANIFEST SIGNATURE NO LONGER VERIFIES: {stem} — {e:?}\n\
                     The `MaxSecu-manifest-v1` label, the `signing_input` framing, or the \
                     canonical encoding of `manifest` changed. Every file ever uploaded \
                     carries a manifest signed under the old bytes; none of them verify \
                     any more, and the client fails closed on an unverified manifest — so \
                     NO existing file can be opened. This cannot ship. \
                     see docs/compat/CHECKLIST.md\n"
                )
            });
    }
}

/// `BundleBody` (`0x000E`) is the one registered struct absent from
/// `crates/encoding/tests/fixtures/canonical_vectors.tsv`, so the corpus carries
/// its own frozen `encode()` blob. It is the encrypted content stream of every
/// bundle post ever made.
#[test]
fn compat_frozen_bundle_body_still_decodes() {
    let exp = expect("encoding", "bundle_body.expect.json");
    let bytes = read("encoding", "bundle_body.bin");
    let body: BundleBody = decode(&bytes).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN BUNDLE BODY NO LONGER DECODES — {e}\n\
             The bundle body is the (encrypted, signed) content stream of a bundle post. \
             If it cannot be decoded, every bundle ever posted shows as empty/broken and \
             its member posts are unreachable. see docs/compat/CHECKLIST.md\n"
        )
    });

    let members = field(&exp, "members").as_array().unwrap();
    assert_eq!(body.members.len(), members.len());
    for (got, want) in body.members.iter().zip(members) {
        assert_eq!(got.file_id, Id(arr16(want, "file_id")));
        assert_eq!(got.file_type as u8 as u64, u64_field(want, "file_type"));
    }
}

// ===========================================================================
// (A7) MXBU sealed server-backup bundle — frozen surface #12
// ===========================================================================

/// A frozen multi-part `MXBU` server-backup bundle still unseals under today's
/// `MxbuOpener`, to the exact original plaintext of every part.
///
/// This is the sealed run-state bundle a `backup-server.sh` run leaves in the
/// operator's cold tier (Dropbox / fs). It is the ONE thing in the system that is
/// not client-encrypted before it egresses — it carries the TLS private key, the
/// operational signing seed, the Dropbox refresh token and a whole `pg_dump` — so
/// a reader that can no longer open it means the rollback fails at the exact
/// moment the operator reaches for it. The bytes were minted by
/// `compat_emit_backup_fixtures` from the DOCUMENTED byte layout (never
/// `MxbuSealer`), so this proves today's reader opens FOREIGN bytes, not a
/// round-trip of today's writer — the `2a626d6` failure mode.
#[test]
fn compat_frozen_backup_still_unseals() {
    use maxsecu_server::backup::format::MxbuOpener;

    let exp = expect("backup", "backup_v1.expect.json");
    let bundle = read("backup", "backup_v1.bin");
    let pw = read_str("backup", "backup_v1.passphrase.txt");

    let parts = field(&exp, "parts").as_array().expect("parts[] array");
    assert!(
        parts.len() >= 2,
        "the backup fixture must be MULTI-part (it exercises nonce_for(index=1), the \
         is_last AAD, and multi-part open — a one-part fixture is weaker)"
    );

    // `backup_v1.bin` is the bundle's parts concatenated; each part's stored length
    // is frozen in the expectation, so walk them in order. The key is derived ONCE
    // from the first part (every part repeats the 45-byte header) — exactly what a
    // restorer walking `BackupIndex::parts` does.
    let mut opener: Option<MxbuOpener> = None;
    let mut off = 0usize;
    for p in parts {
        let plen = u64_field(p, "part_len") as usize;
        assert!(
            off + plen <= bundle.len(),
            "a frozen part_len runs past the bundle — fixture corruption"
        );
        let part = &bundle[off..off + plen];
        off += plen;

        if opener.is_none() {
            opener = Some(MxbuOpener::from_part(&pw, part).unwrap_or_else(|e| {
                panic!(
                    "\n\nFROZEN SERVER-BACKUP BUNDLE HEADER NO LONGER PARSES: \
                     compat/fixtures/backup/backup_v1.bin — {e}\n\
                     This is a sealed MXBU bundle an operator has sitting in their cold tier. \
                     If today's code cannot even derive its key, no rollback or dead-box \
                     rebuild can read it — the recovery path fails exactly when it is needed. \
                     see docs/compat/CHECKLIST.md\n"
                )
            }));
        }
        let idx = u64_field(p, "index") as u32;
        let is_last = field(p, "is_last").as_bool().expect("is_last bool");
        let pt = opener
            .as_ref()
            .unwrap()
            .open_part(idx, is_last, part)
            .unwrap_or_else(|e| {
                panic!(
                    "\n\nFROZEN SERVER-BACKUP PART NO LONGER OPENS: part {idx} of \
                     compat/fixtures/backup/backup_v1.bin — {e}\n\
                     The MXBU seal changed — its Argon2id KDF, the 45-byte header-as-AAD, the \
                     `nonce_base ⊕ part_index` nonce construction, or the `part_index ‖ is_last` \
                     AAD framing. Every backup bundle already written is now unopenable, so \
                     rollback and dead-box rebuild both fail. This cannot ship. \
                     see docs/compat/CHECKLIST.md\n"
                )
            });
        assert_eq!(
            hex_of(&pt),
            field(p, "plaintext").as_str().unwrap(),
            "frozen backup part {idx} opened to the WRONG plaintext — silent bundle corruption"
        );
    }
    assert_eq!(
        off,
        bundle.len(),
        "the fixture bundle has trailing bytes past its last part"
    );
}

/// A frozen `BackupIndex` (`type_id 0x000F`) still decodes, field for field.
///
/// The index is what every bundle's part 0 carries: the git SHA a `--only code`
/// rollback checks out, the entry table a restore writes back to disk, and the
/// per-part ciphertext digests every payload part is checked against before it is
/// opened. `backup_v1.bin` above freezes the MXBU *seal* and nothing more — its
/// part plaintexts are prose — so without this the wire framing of the container
/// inside the seal is unpinned, and the one thing a round-trip cannot catch is
/// exactly what would break it: reordering `entries` against `parts`, narrowing a
/// `len`, or changing how `path` is length-prefixed all keep `encode`/`decode`
/// agreeing with each other while making every bundle already sitting in an
/// operator's cold tier unreadable.
///
/// The bytes were written by `build_backup_index` from the DOCUMENTED layout
/// (`docs/encoding-spec.md` §4 `backup_index`), never by `encode()`.
#[test]
fn compat_frozen_backup_index_still_decodes() {
    use maxsecu_encoding::structs::BackupIndex;

    let exp = expect("backup", "backup_index_v1.expect.json");
    let bytes = read("backup", "backup_index_v1.bin");

    assert_eq!(
        u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
        u64_field(&exp, "type_id"),
        "the frozen backup index does not start with type_id 0x000F"
    );

    let idx: BackupIndex = decode(&bytes).unwrap_or_else(|e| {
        panic!(
            "\n\nFROZEN BACKUP INDEX NO LONGER DECODES — {e}\n\
             The BackupIndex is the authenticated table of contents inside part 0 of EVERY \
             sealed MXBU bundle. `backup::read_index` decodes it before anything else can \
             happen, so if these bytes stop decoding, every bundle an operator already has \
             on their cold tier becomes unlistable and unrestorable — rollback and dead-box \
             rebuild both fail at the first step. This cannot ship. \
             see docs/compat/CHECKLIST.md\n"
        )
    });

    assert_eq!(
        idx.git_sha.as_str(),
        field(&exp, "git_sha").as_str().unwrap()
    );
    assert_eq!(idx.created_at.0, u64_field(&exp, "created_at"));

    let entries = field(&exp, "entries").as_array().unwrap();
    assert_eq!(idx.entries.len(), entries.len());
    for (got, want) in idx.entries.iter().zip(entries) {
        // Zipped in order on purpose: `entries` order IS the payload order an
        // entry's offset is the running sum of, so a codec that sorted or
        // de-duplicated would put a restored file's bytes at the wrong offset.
        assert_eq!(got.path.as_str(), field(want, "path").as_str().unwrap());
        assert_eq!(got.len, u64_field(want, "len"));
        assert_eq!(got.digest, Bytes32(arr32(want, "digest")));
    }

    let parts = field(&exp, "parts").as_array().unwrap();
    assert_eq!(idx.parts.len(), parts.len());
    for (got, want) in idx.parts.iter().zip(parts) {
        // A part's index is its POSITION here, and that index is bound into the
        // part's AEAD AAD and nonce — so this order is load-bearing too.
        assert_eq!(got.len, u64_field(want, "len"));
        assert_eq!(got.digest, Bytes32(arr32(want, "digest")));
    }
}

// ===========================================================================
// The generator. NOT part of the gate — run once, commit the bytes.
// ===========================================================================

const USER_A: Id = Id([0xA1; 16]); // classical (v1 keyblob) user
const USER_B: Id = Id([0xB2; 16]); // PQ (v2 keyblob) user
const FILE_V1: Id = Id([0xF1; 16]); // a Suite::V1 file
const FILE_V2: Id = Id([0xF2; 16]); // a Suite::V2 file
const FILE_BLOBREF: Id = Id([0xB9; 16]);
const CREATED_AT: u64 = 1_700_000_000_000;
/// A 10-year delegation window so the frozen cert can never expire.
const DELEG_FROM: u64 = 1_700_000_000;
const DELEG_UNTIL: u64 = 1_700_000_000 + 3650 * 86_400;
const DELEG_VERIFY_AT: u64 = DELEG_FROM + 42;

fn write(area_name: &str, file: &str, bytes: &[u8]) {
    let p = area(area_name).join(file);
    std::fs::write(&p, bytes).unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
}

fn write_json(area_name: &str, file: &str, v: &Value) {
    let mut s = serde_json::to_string_pretty(v).expect("serializable");
    s.push('\n');
    write(area_name, file, s.as_bytes());
}

/// Build an `MXKB` blob **from the documented byte layout**, not by calling
/// `keyblob::seal`. That is the point: the corpus must be produced by an
/// independent writer (standing in for the old client that actually wrote it),
/// so the gate proves today's `unlock` opens *those* bytes rather than merely
/// round-tripping today's `seal`. It is also the only way to mint a v1 (non-PQ)
/// blob at all — every `Identity::generate()` today is PQ, so `seal` can no
/// longer produce one.
fn build_keyblob(
    pw: &str,
    version: u8,
    enc_sk: [u8; 32],
    enc_pk: [u8; 32],
    sig_seed: [u8; 32],
    mlkem_seed: Option<[u8; 64]>,
) -> Vec<u8> {
    let params = ARGON2_FLOOR; // keeps the gate fast; the real desktop target is slower
    let salt: [u8; 16] = maxsecu_crypto::random_array();
    let nonce: [u8; 12] = maxsecu_crypto::random_array();

    let mut header = Vec::with_capacity(45);
    header.extend_from_slice(b"MXKB");
    header.push(version);
    header.extend_from_slice(&params.m_kib.to_be_bytes());
    header.extend_from_slice(&params.t.to_be_bytes());
    header.extend_from_slice(&params.p.to_be_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    assert_eq!(header.len(), 45);

    let mut pt = Vec::new();
    pt.extend_from_slice(&enc_sk);
    pt.extend_from_slice(&enc_pk);
    pt.extend_from_slice(&sig_seed);
    if let Some(seed) = mlkem_seed {
        pt.extend_from_slice(&seed);
    }

    let key = maxsecu_crypto::derive_key(pw.as_bytes(), &salt, params).expect("floor params");
    let ct = maxsecu_crypto::seal(&key, &nonce, &header, &pt);
    let mut out = header;
    out.extend_from_slice(&ct);
    out
}

/// Build one stored `MXBU` backup part **from the documented byte layout** (frozen
/// surface #12), NOT by calling `MxbuSealer`. It mirrors
/// `crates/server/src/backup/format.rs`'s `build_part` test helper and
/// `build_keyblob` above: an independent second writer, so the gate proves today's
/// reader opens FOREIGN bytes instead of round-tripping our own `seal` (which would
/// let both halves drift together). The construction is normative in the design
/// spec's "MXBU v1" section — if the layout drifts, the reader stops opening this:
///
/// ```text
/// header = "MXBU" ‖ version=1 ‖ m_kib u32 BE ‖ t u32 BE ‖ p u32 BE ‖ salt[16] ‖ nonce_base[12]   (45)
/// aad    = header ‖ part_index u32 BE ‖ is_last u8
/// nonce  = nonce_base with part_index.to_be_bytes() XORed into bytes 8..12   (TLS 1.3 record nonce)
/// part   = header ‖ AES-256-GCM(derive_key(pw, salt, params), nonce, aad, plaintext)
/// ```
fn build_backup_part(
    pw: &str,
    params: Argon2Params,
    salt: &[u8; 16],
    nonce_base: &[u8; 12],
    part_index: u32,
    is_last: bool,
    pt: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(45);
    header.extend_from_slice(b"MXBU");
    header.push(1);
    header.extend_from_slice(&params.m_kib.to_be_bytes());
    header.extend_from_slice(&params.t.to_be_bytes());
    header.extend_from_slice(&params.p.to_be_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce_base);
    assert_eq!(header.len(), 45);

    let mut aad = header.clone();
    aad.extend_from_slice(&part_index.to_be_bytes());
    aad.push(u8::from(is_last));

    let key = maxsecu_crypto::derive_key(pw.as_bytes(), salt, params).expect("floor params");
    let mut nonce = *nonce_base;
    for (b, x) in nonce[8..].iter_mut().zip(part_index.to_be_bytes()) {
        *b ^= x;
    }
    let ct = maxsecu_crypto::seal(&key, &nonce, &aad, pt);

    let mut out = header;
    out.extend_from_slice(&ct);
    out
}

/// Build the canonical bytes of a `BackupIndex` (`type_id 0x000F`) **from the
/// documented byte layout** — `docs/encoding-spec.md` §2 (primitives) and §4
/// (`backup_index`) — NOT by calling `encode()`. Same discipline as
/// `build_keyblob` and `build_backup_part`: an independent second writer, so the
/// gate proves today's strict `decode` still accepts FOREIGN bytes instead of
/// round-tripping our own encoder, which would let writer and reader drift
/// together and stay green while a real operator's bundle rotted.
///
/// ```text
/// 0x000F u16 BE
///   git_sha    : u32 BE len ‖ utf8
///   entries    : u32 BE count ‖ count × (path: u32 BE len ‖ utf8, len: u64 BE, digest[32])
///   parts      : u32 BE count ‖ count × (len: u64 BE, digest[32])
///   created_at : u64 BE
/// ```
fn build_backup_index(
    git_sha: &str,
    entries: &[(&str, u64, [u8; 32])],
    parts: &[(u64, [u8; 32])],
    created_at: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x000Fu16.to_be_bytes());

    out.extend_from_slice(&(git_sha.len() as u32).to_be_bytes());
    out.extend_from_slice(git_sha.as_bytes());

    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (path, len, digest) in entries {
        out.extend_from_slice(&(path.len() as u32).to_be_bytes());
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(digest);
    }

    out.extend_from_slice(&(parts.len() as u32).to_be_bytes());
    for (len, digest) in parts {
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(digest);
    }

    out.extend_from_slice(&created_at.to_be_bytes());
    out
}

fn stream(t: StreamType, chunk_count: u64, digest: u8) -> Stream {
    Stream {
        stream_type: t,
        compression: Compression::None,
        chunk_count,
        digest: Bytes32([digest; 32]),
    }
}

fn manifest_for(
    file_id: Id,
    version: u64,
    alg: Suite,
    author: Id,
    dek_commit: [u8; 32],
) -> Manifest {
    Manifest {
        file_id,
        version,
        file_type: FileType::Video,
        alg,
        chunk_size: 1 << 20,
        dek_commit: Bytes32(dek_commit),
        streams: vec![
            stream(StreamType::Content, 3, 0xC0),
            stream(StreamType::Metadata, 1, 0x4D),
            stream(StreamType::Thumbnail, 1, 0x70),
            stream(StreamType::Preview, 1, 0x80),
        ],
        recovery_present: true,
        author_id: author,
        created_at: Timestamp(CREATED_AT),
    }
}

fn manifest_json(m: &Manifest, signer_pub: [u8; 32]) -> Value {
    json!({
        "label": labels::MANIFEST,
        "signer_pub": hex_of(&signer_pub),
        "file_id": hex_of(&m.file_id.0),
        "version": m.version,
        "file_type": m.file_type as u8,
        "alg": match m.alg { Suite::V1 => 1, Suite::V2 => 2 },
        "chunk_size": m.chunk_size,
        "dek_commit": hex_of(&m.dek_commit.0),
        "author_id": hex_of(&m.author_id.0),
        "created_at": m.created_at.0,
        "recovery_present": m.recovery_present,
    })
}

fn binding_for(
    username: &str,
    user_id: Id,
    enc_pub: [u8; 32],
    sig_pub: [u8; 32],
    mlkem: Option<[u8; 1184]>,
) -> DirBinding {
    DirBinding {
        username: Text::new(username).expect("short username"),
        user_id,
        enc_pub: Bytes32(enc_pub),
        sig_pub: Bytes32(sig_pub),
        key_version: 1,
        roles: RoleSet::new([Role::User]),
        not_before: Timestamp(CREATED_AT),
        not_after: Timestamp(CREATED_AT + 10 * 365 * 86_400_000),
        mlkem_pub: mlkem.map(MlKemPub),
    }
}

fn binding_json(b: &DirBinding, signer_pub: [u8; 32]) -> Value {
    json!({
        "label": labels::DIRBINDING,
        "signer_pub": hex_of(&signer_pub),
        "username": b.username.as_str(),
        "user_id": hex_of(&b.user_id.0),
        "enc_pub": hex_of(&b.enc_pub.0),
        "sig_pub": hex_of(&b.sig_pub.0),
        "key_version": b.key_version,
        "not_before": b.not_before.0,
        "not_after": b.not_after.0,
        "mlkem_pub_sha256": b.mlkem_pub.map(|k| hex_of(&sha256(&k.0))),
    })
}

fn ctx_of(file_id: Id, version: u64, recipient: Id) -> WrapContext {
    WrapContext {
        file_id,
        version,
        recipient_id: recipient,
    }
}

fn ctx_json(c: &WrapContext) -> Value {
    json!({
        "file_id": hex_of(&c.file_id.0),
        "version": c.version,
        "recipient_id": hex_of(&c.recipient_id.0),
    })
}

#[test]
#[ignore = "run with --ignored to (re)generate the frozen corpus ONCE; the gate never regenerates \
            (regenerating an existing fixture is a corpus.lock failure by design)"]
fn compat_emit_fixtures() {
    for a in AREAS {
        std::fs::create_dir_all(area(a)).expect("create fixture area");
    }

    // ---- identities -------------------------------------------------------
    // A: classical (a user who enrolled before PQ) — v1 keyblob, classical binding.
    // B: PQ-enrolled — v2 keyblob, binding carries ML-KEM.
    let (a_enc_sk, a_enc_pk) = generate_enc_keypair();
    let a_sig = SigningKey::generate();
    let (b_enc_sk, b_enc_pk) = generate_enc_keypair();
    let b_sig = SigningKey::generate();
    let (b_mlkem_seed, b_mlkem_pub) = generate_mlkem_keypair();

    // ---- keyblobs ---------------------------------------------------------
    let pw_a = "compat-fixture-keyblob-v1-passphrase";
    let pw_b = "compat-fixture-keyblob-v2-passphrase";
    let kb1 = build_keyblob(
        pw_a,
        1,
        a_enc_sk.expose_bytes(),
        a_enc_pk.to_bytes(),
        a_sig.to_seed(),
        None,
    );
    let kb2 = build_keyblob(
        pw_b,
        2,
        b_enc_sk.expose_bytes(),
        b_enc_pk.to_bytes(),
        b_sig.to_seed(),
        Some(b_mlkem_seed),
    );
    assert_eq!(kb1.len(), 157);
    assert_eq!(kb2.len(), 221);
    write("keyblob", "keyblob_v1.bin", &kb1);
    write("keyblob", "keyblob_v1.passphrase.txt", pw_a.as_bytes());
    write_json(
        "keyblob",
        "keyblob_v1.expect.json",
        &json!({
            "version": 1,
            "blob_len": kb1.len(),
            "enc_pub": hex_of(&a_enc_pk.to_bytes()),
            "sig_pub": hex_of(&a_sig.verifying_key().to_bytes()),
            "fingerprint": hex_of(&maxsecu_crypto::fingerprint(
                &a_enc_pk.to_bytes(), &a_sig.verifying_key().to_bytes())),
            "mlkem_pub_sha256": Value::Null,
        }),
    );
    write("keyblob", "keyblob_v2.bin", &kb2);
    write("keyblob", "keyblob_v2.passphrase.txt", pw_b.as_bytes());
    write_json(
        "keyblob",
        "keyblob_v2.expect.json",
        &json!({
            "version": 2,
            "blob_len": kb2.len(),
            "enc_pub": hex_of(&b_enc_pk.to_bytes()),
            "sig_pub": hex_of(&b_sig.verifying_key().to_bytes()),
            "fingerprint": hex_of(&maxsecu_crypto::fingerprint(
                &b_enc_pk.to_bytes(), &b_sig.verifying_key().to_bytes())),
            "mlkem_pub_sha256": hex_of(&sha256(&b_mlkem_pub)),
        }),
    );

    // ---- seedblob (offline D5 root) ---------------------------------------
    let d5_seed = [0xD5u8; 32];
    let pw_d5 = "compat-fixture-d5-seedblob-passphrase";
    let sb = maxsecu_client_core::seal_seed(pw_d5, &d5_seed, ARGON2_FLOOR).expect("seal seed");
    assert_eq!(sb.len(), 93);
    write("seedblob", "seedblob_v1.bin", &sb);
    write("seedblob", "seedblob_v1.passphrase.txt", pw_d5.as_bytes());
    write_json(
        "seedblob",
        "seedblob_v1.expect.json",
        &json!({
            "blob_len": sb.len(),
            "seed": hex_of(&d5_seed),
            "d5_pub": hex_of(&SigningKey::from_seed(&d5_seed).verifying_key().to_bytes()),
        }),
    );

    // ---- delegation cert (pinned D5 authorizes the server's op key) --------
    let d5 = SigningKey::from_seed(&d5_seed);
    let op = SigningKey::from_seed(&[0x09u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let cert = sign_delegation(&d5, &op_pub, DELEG_FROM, DELEG_UNTIL);
    assert_eq!(cert.len(), 113);
    write("delegation", "delegation_v1.bin", &cert);
    write_json(
        "delegation",
        "delegation_v1.expect.json",
        &json!({
            "wire_len": cert.len(),
            "d5_pub": hex_of(&d5.verifying_key().to_bytes()),
            "operational_pub": hex_of(&op_pub),
            "valid_from": DELEG_FROM,
            "valid_until": DELEG_UNTIL,
            "verify_at": DELEG_VERIFY_AT,
        }),
    );

    // ---- signed directory bindings (signed by the DELEGATED op key) --------
    let bind_a = binding_for(
        "alice",
        USER_A,
        a_enc_pk.to_bytes(),
        a_sig.verifying_key().to_bytes(),
        None, // the pre-PQ-enrollment shape: no ML-KEM key published
    );
    let bind_b = binding_for(
        "bob",
        USER_B,
        b_enc_pk.to_bytes(),
        b_sig.verifying_key().to_bytes(),
        Some(b_mlkem_pub),
    );
    write(
        "encoding",
        "signed_dirbinding_classical.bin",
        &encode(&bind_a),
    );
    write(
        "encoding",
        "signed_dirbinding_classical.sig",
        &op.sign_canonical(labels::DIRBINDING, &bind_a),
    );
    write_json(
        "encoding",
        "signed_dirbinding_classical.expect.json",
        &binding_json(&bind_a, op_pub),
    );
    write("encoding", "signed_dirbinding_pq.bin", &encode(&bind_b));
    write(
        "encoding",
        "signed_dirbinding_pq.sig",
        &op.sign_canonical(labels::DIRBINDING, &bind_b),
    );
    write_json(
        "encoding",
        "signed_dirbinding_pq.expect.json",
        &binding_json(&bind_b, op_pub),
    );

    // ---- DEKs, signed manifests, wraps ------------------------------------
    let dek1 = Dek::generate(); // the Suite::V1 file's DEK
    let dek2 = Dek::generate(); // the Suite::V2 file's DEK

    let m1 = manifest_for(FILE_V1, 1, Suite::V1, USER_A, dek1.commit());
    let m2 = manifest_for(FILE_V2, 1, Suite::V2, USER_B, dek2.commit());
    write("encoding", "signed_manifest_v1.bin", &encode(&m1));
    write(
        "encoding",
        "signed_manifest_v1.sig",
        &a_sig.sign_canonical(labels::MANIFEST, &m1),
    );
    write_json(
        "encoding",
        "signed_manifest_v1.expect.json",
        &manifest_json(&m1, a_sig.verifying_key().to_bytes()),
    );
    write("encoding", "signed_manifest_v2.bin", &encode(&m2));
    write(
        "encoding",
        "signed_manifest_v2.sig",
        &b_sig.sign_canonical(labels::MANIFEST, &m2),
    );
    write_json(
        "encoding",
        "signed_manifest_v2.expect.json",
        &manifest_json(&m2, b_sig.verifying_key().to_bytes()),
    );

    // V1 (HPKE) wrap of the V1 file's DEK to the classical user A.
    let c_a = ctx_of(FILE_V1, 1, USER_A);
    let w = wrap_dek(&a_enc_pk, &dek1, &c_a).expect("wrap v1");
    let mut wire = w.enc.to_vec();
    wire.extend_from_slice(&w.ct);
    write("crypto", "wrap_v1.bin", &wire);
    write("crypto", "wrap_v1.testkey", &a_enc_sk.expose_bytes());
    write_json(
        "crypto",
        "wrap_v1.expect.json",
        &json!({
            "suite": 1,
            "wrap_context": ctx_json(&c_a),
            "dek": hex_of(dek1.expose()),
            "dek_commit": hex_of(&dek1.commit()),
            "recipient_x25519_pub": hex_of(&a_enc_pk.to_bytes()),
            "secret_key_file": "wrap_v1.testkey",
        }),
    );

    // The SAME V1 file, also shared to the PQ user B (classical wrap to their
    // X25519 half) — a PQ upgrade must not strand classical files.
    let c_b1 = ctx_of(FILE_V1, 1, USER_B);
    let w = wrap_dek(&b_enc_pk, &dek1, &c_b1).expect("wrap v1 to pq recipient");
    let mut wire = w.enc.to_vec();
    wire.extend_from_slice(&w.ct);
    write("crypto", "wrap_v1_to_pq.bin", &wire);
    write("crypto", "wrap_v1_to_pq.testkey", &b_enc_sk.expose_bytes());
    write_json(
        "crypto",
        "wrap_v1_to_pq.expect.json",
        &json!({
            "suite": 1,
            "wrap_context": ctx_json(&c_b1),
            "dek": hex_of(dek1.expose()),
            "dek_commit": hex_of(&dek1.commit()),
            "recipient_x25519_pub": hex_of(&b_enc_pk.to_bytes()),
            "secret_key_file": "wrap_v1_to_pq.testkey",
        }),
    );

    // V2 (X25519 + ML-KEM-768 hybrid) wrap of the V2 file's DEK to user B.
    let c_b2 = ctx_of(FILE_V2, 1, USER_B);
    let hybrid_pub = HybridEncPublicKey {
        x25519: b_enc_pk.to_bytes(),
        mlkem: b_mlkem_pub,
    };
    let h = wrap_dek_hybrid(&hybrid_pub, &dek2, &c_b2).expect("wrap v2");
    let hwire = maxsecu_crypto::serialize_hybrid_wrap(&h);
    assert_eq!(hwire.len(), 1168);
    write("crypto", "wrap_v2.bin", &hwire);
    let mut hkey = b_enc_sk.expose_bytes().to_vec();
    hkey.extend_from_slice(&b_mlkem_seed);
    write("crypto", "wrap_v2.testkey", &hkey);
    write_json(
        "crypto",
        "wrap_v2.expect.json",
        &json!({
            "suite": 2,
            "wrap_context": ctx_json(&c_b2),
            "dek": hex_of(dek2.expose()),
            "dek_commit": hex_of(&dek2.commit()),
            "recipient_x25519_pub": hex_of(&b_enc_pk.to_bytes()),
            "recipient_mlkem_pub_sha256": hex_of(&sha256(&b_mlkem_pub)),
            "secret_key_file": "wrap_v2.testkey (x25519_secret[32] ‖ mlkem_seed[64])",
            "wire_len": hwire.len(),
        }),
    );

    // ---- sealed chunks, one per stream type --------------------------------
    let chunk_dek = Dek::from_bytes([0x5C; 32]);
    write("crypto", "chunk_dek.testkey", chunk_dek.expose());
    let plan: [(&str, StreamType, u64, bool, &[u8]); 5] = [
        (
            "chunk_content_0.bin",
            StreamType::Content,
            0,
            false,
            b"first content frame - not the last one".as_slice(),
        ),
        (
            "chunk_content_1.bin",
            StreamType::Content,
            1,
            true,
            b"second and FINAL content frame".as_slice(),
        ),
        (
            "chunk_metadata.bin",
            StreamType::Metadata,
            0,
            true,
            b"{\"title\":\"a frozen post\"}".as_slice(),
        ),
        (
            "chunk_thumbnail.bin",
            StreamType::Thumbnail,
            0,
            true,
            b"thumbnail bytes".as_slice(),
        ),
        (
            "chunk_preview.bin",
            StreamType::Preview,
            0,
            true,
            b"preview bytes".as_slice(),
        ),
    ];
    let mut chunk_meta: Vec<Value> = Vec::new();
    for (file, st, index, is_last, pt) in plan {
        let aad = maxsecu_encoding::structs::ChunkAad {
            file_id: FILE_V1,
            version: 1,
            stream_type: st,
            chunk_index: index,
            is_last,
        };
        let ck = chunk_dek.stream_subkey(st);
        let ct = maxsecu_crypto::seal_chunk(&ck, &aad, pt);
        write("crypto", file, &ct);
        chunk_meta.push(json!({
            "file": file,
            "file_id": hex_of(&FILE_V1.0),
            "version": 1,
            "stream_type": st as u8,
            "chunk_index": index,
            "is_last": is_last,
            "plaintext": hex_of(pt),
            "stream_subkey": hex_of(&ck[..]),
        }));
    }
    write_json(
        "crypto",
        "chunks.expect.json",
        &json!({
            "dek_key_file": "chunk_dek.testkey",
            "dek_commit": hex_of(&chunk_dek.commit()),
            "chunks": chunk_meta,
        }),
    );

    // ---- blob_ref: a frozen manifest the SERVER re-parses ------------------
    // Version 3 so `parse_stage` takes the rotation path (no genesis needed).
    let bm = manifest_for(FILE_BLOBREF, 3, Suite::V1, USER_A, dek1.commit());
    write("blobref", "blobref_manifest.bin", &encode(&bm));
    let hex_file = hex_of(&FILE_BLOBREF.0);
    write_json(
        "blobref",
        "blobref_manifest.expect.json",
        &json!({
            "file_id": hex_file,
            "caller_id": hex_of(&USER_A.0),
            "version": 3,
            "scheme": "hex(file_id)/version/stream_type",
            "blob_refs": {
                "1": format!("{hex_file}/3/1"),
                "2": format!("{hex_file}/3/2"),
                "3": format!("{hex_file}/3/3"),
                "4": format!("{hex_file}/3/4"),
            },
        }),
    );

    // ---- bundle body (type_id 0x000E) --------------------------------------
    let bundle = BundleBody {
        members: vec![
            BundleMember {
                file_id: Id([0x01; 16]),
                file_type: FileType::Video,
            },
            BundleMember {
                file_id: Id([0x02; 16]),
                file_type: FileType::Image,
            },
            BundleMember {
                file_id: Id([0x03; 16]),
                file_type: FileType::Generic,
            },
        ],
    };
    write("encoding", "bundle_body.bin", &encode(&bundle));
    write_json(
        "encoding",
        "bundle_body.expect.json",
        &json!({
            "type_id": 14,
            "members": bundle.members.iter().map(|m| json!({
                "file_id": hex_of(&m.file_id.0),
                "file_type": m.file_type as u8,
            })).collect::<Vec<_>>(),
        }),
    );

    // ---- the per-area locks ------------------------------------------------
    for a in AREAS {
        emit_corpus_lock(a);
    }
    eprintln!(
        "wrote the frozen corpus under {}",
        fixtures_root().display()
    );
}

/// Mint the `backup` area — the frozen `MXBU` server-backup bundle (surface #12) —
/// and it alone.
///
/// SEPARATE from `compat_emit_fixtures` ON PURPOSE. That generator is
/// all-or-nothing and NON-deterministic: it regenerates every identity with fresh
/// `random_array()` key material, so running it to add this one area would rewrite
/// all the OTHER areas' bytes, move every sha256 in every `corpus.lock`, and trip
/// both the corpus lock and the pre-push hook. This emitter writes only
/// `compat/fixtures/backup/*` and re-locks just that area. Run it ONCE:
///
/// ```text
/// cargo test -p maxsecu-compat --test golden_open compat_emit_backup_fixtures -- --ignored
/// ```
///
/// (Once `backup` is in `AREAS`, a later `compat_emit_fixtures` run also
/// `create_dir_all`s + `emit_corpus_lock`s it — harmless, it re-hashes what is on
/// disk — but the two generators must never both AUTHOR these bytes.)
#[test]
#[ignore = "run with --ignored ONCE to mint the MXBU backup fixture; the gate never regenerates \
            (regenerating an existing fixture is a corpus.lock failure by design)"]
fn compat_emit_backup_fixtures() {
    std::fs::create_dir_all(area("backup")).expect("create the backup fixture area");

    let params = ARGON2_FLOOR; // keeps the gate fast; the desktop target is 256 MiB / ~1s
    let pw = "compat-fixture-backup-bundle-passphrase"; // >= 12 chars (MIN_PASSPHRASE_CHARS)
                                                        // Fixed salt + nonce_base: the fixture is minted once and frozen, so a
                                                        // deterministic bundle is preferable to a random one.
    let salt = [0xBAu8; 16];
    let nonce_base = [0xBCu8; 12];

    // A MULTI-part bundle. Part 0 (is_last = false) exercises nonce_for(0) and the
    // is_last = false AAD; part 1 (is_last = true) exercises nonce_for(1), the
    // is_last = true AAD, and the multi-part open. Distinct lengths, too.
    let payloads: [(&[u8], bool); 2] = [
        (
            b"MXBU compat fixture -- server-backup bundle frame 0 of 2 (not the last part)"
                .as_slice(),
            false,
        ),
        (
            b"MXBU compat fixture -- final frame 1 of 2 (is_last)".as_slice(),
            true,
        ),
    ];

    let mut bundle: Vec<u8> = Vec::new();
    let mut parts_json: Vec<Value> = Vec::new();
    for (index, &(pt, is_last)) in payloads.iter().enumerate() {
        let part = build_backup_part(pw, params, &salt, &nonce_base, index as u32, is_last, pt);
        parts_json.push(json!({
            "index": index,
            "is_last": is_last,
            "part_len": part.len(),
            "plaintext": hex_of(pt),
        }));
        bundle.extend_from_slice(&part);
    }

    write("backup", "backup_v1.bin", &bundle);
    write("backup", "backup_v1.passphrase.txt", pw.as_bytes());
    write_json(
        "backup",
        "backup_v1.expect.json",
        &json!({
            "format": "MXBU",
            "magic": "MXBU",
            "version": 1,
            "argon": { "m_kib": params.m_kib, "t": params.t, "p": params.p },
            "header_len": 45,
            "passphrase_file": "backup_v1.passphrase.txt",
            "parts": parts_json,
        }),
    );

    // The bundle's authenticated table of contents, frozen SEPARATELY from the
    // seal above. `backup_v1.bin` pins the MXBU envelope and nothing else — its
    // part plaintexts are prose, so no byte in it constrains how a `BackupIndex`
    // is framed. Two entries and two parts (with different values), so list ORDER
    // is observable: swapping `entries` and `parts`, narrowing a `len`, or
    // changing the `path` encoding would all still round-trip through today's
    // `encode`/`decode` pair while leaving every bundle already in an operator's
    // Dropbox with an undecodable part 0.
    let index_entries: [(&str, u64, [u8; 32]); 2] = [
        ("tls/key.der", 1191, [0x11; 32]),
        ("config/operational_secret.bin", 32, [0x22; 32]),
    ];
    let index_parts: [(u64, [u8; 32]); 2] = [(8_388_653, [0x33; 32]), (4_096, [0x44; 32])];
    let index_git_sha = "0123456789abcdef0123456789abcdef01234567";
    let index_bytes = build_backup_index(index_git_sha, &index_entries, &index_parts, CREATED_AT);
    write("backup", "backup_index_v1.bin", &index_bytes);
    write_json(
        "backup",
        "backup_index_v1.expect.json",
        &json!({
            "type_id": 15,
            "git_sha": index_git_sha,
            "entries": index_entries.iter().map(|(path, len, digest)| json!({
                "path": path,
                "len": len,
                "digest": hex_of(digest),
            })).collect::<Vec<_>>(),
            "parts": index_parts.iter().map(|(len, digest)| json!({
                "len": len,
                "digest": hex_of(digest),
            })).collect::<Vec<_>>(),
            "created_at": CREATED_AT,
        }),
    );

    emit_corpus_lock("backup");
    eprintln!("wrote the backup corpus under {}", area("backup").display());
}

/// `<filename>  <sha256-hex>`, sorted by filename, LF endings, no self-entry.
fn emit_corpus_lock(area_name: &str) {
    let dir = area(area_name);
    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    for e in std::fs::read_dir(&dir).expect("area exists") {
        let name = e
            .expect("dir entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name == "corpus.lock" {
            continue;
        }
        let digest = sha256_hex(&std::fs::read(dir.join(&name)).expect("read fixture"));
        entries.insert(name, digest);
    }
    let mut out = String::new();
    out.push_str("# MaxSecu backward-compatibility gate — frozen corpus lock.\n");
    out.push_str("# Fixtures may be ADDED. Never edited. Never deleted.\n");
    out.push_str("# <filename>  <sha256-hex>, sorted.  see docs/compat/CHECKLIST.md\n");
    for (name, digest) in entries {
        out.push_str(&format!("{name}  {digest}\n"));
    }
    let p = dir.join("corpus.lock");
    std::fs::write(&p, out.as_bytes()).unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
}

/// Guard: the committed corpus is actually present. Without it every other test
/// here would "pass" vacuously by never finding anything to open.
#[test]
fn compat_fixture_paths_resolve() {
    let root = fixtures_root();
    assert!(
        root.is_dir(),
        "the frozen corpus is missing at {} — it is committed to the repo and the gate \
         cannot run without it",
        root.display()
    );
    for a in AREAS {
        assert!(area(a).is_dir(), "missing corpus area `{a}`");
    }
}
