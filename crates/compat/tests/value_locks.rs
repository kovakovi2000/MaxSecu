//! **Value locks — "the constants that ARE the format cannot silently move."**
//!
//! Direct assertions on the type_ids, domain-separation labels, magic bytes,
//! fixed lengths and path schemes that define MaxSecu's wire and at-rest formats.
//! Where the golden corpus proves the bytes still open, these prove *why*: they
//! fail at the constant that caused the break, with a message naming the blast
//! radius, instead of surfacing as a confusing AEAD error three layers away.
//!
//! ---------------------------------------------------------------------------
//! **TEST-ONLY KEY MATERIAL.** The `*.testkey` / `*.passphrase.txt` files read
//! here are throwaway values committed alongside the frozen corpus so the gate
//! can open it. They are never production key material.
//! ---------------------------------------------------------------------------

use std::path::PathBuf;

use maxsecu_compat::{read, read_str, CHECKLIST};
use maxsecu_crypto::{derive_key, deserialize_hybrid_wrap, hkdf_sha256_32, Argon2Params, Dek};
use maxsecu_encoding::structs::{
    AuthProofContext, BundleBody, ChunkAad, DirBinding, FingerprintInput, Genesis, Grant,
    KeyCompromise, Manifest, Reinstatement, Revocation, Stream, WrapContext, MLKEM768_PUB_LEN,
};
use maxsecu_encoding::types::{Compression, FileType, RecipientType, Role, StreamType};
use maxsecu_encoding::{decode, labels, Canonical, DecodeError, SUITE_V1, SUITE_V2};

// ===========================================================================
// (B1) The 13 canonical type_ids — the struct registry (encoding-spec §5)
// ===========================================================================

/// Every registered `type_id`. A `type_id` is the first two bytes of EVERY
/// canonical blob ever signed, stored or transmitted; moving one makes every
/// stored record of that type undecodable.
#[test]
fn compat_type_ids_are_frozen() {
    macro_rules! lock {
        ($t:ty, $id:expr, $what:expr) => {
            assert_eq!(
                <$t as Canonical>::TYPE_ID,
                $id,
                "\n\ntype_id of `{}` moved to 0x{:04X} (was 0x{:04X}): every {} ever \
                 encoded — signed, stored on the server, and sitting in users' local \
                 state — starts with the OLD two bytes and now fails to decode. \
                 This cannot ship. {}\n",
                stringify!($t),
                <$t as Canonical>::TYPE_ID,
                $id,
                $what,
                CHECKLIST
            );
        };
    }

    lock!(
        DirBinding,
        0x0001,
        "directory binding (every user's published keys)"
    );
    lock!(Manifest, 0x0002, "file manifest (every uploaded file)");
    lock!(Grant, 0x0003, "read grant (every share)");
    // 0x0004 = the removed `write_grant` (D29) — deliberately never re-used.
    lock!(Genesis, 0x0005, "file genesis record");
    lock!(Revocation, 0x0006, "revocation tombstone");
    lock!(Reinstatement, 0x0007, "reinstatement record");
    lock!(KeyCompromise, 0x0008, "key-compromise record");
    lock!(AuthProofContext, 0x0009, "login proof (every session)");
    lock!(
        WrapContext,
        0x000A,
        "wrap context (bound into EVERY DEK wrap)"
    );
    lock!(
        ChunkAad,
        0x000B,
        "chunk AAD (bound into EVERY uploaded chunk)"
    );
    lock!(FingerprintInput, 0x000C, "identity fingerprint input");
    lock!(Stream, 0x000D, "manifest stream entry");
    lock!(BundleBody, 0x000E, "bundle body (every bundle post)");
}

/// `0x0004` was `write_grant`, removed by D29. It must stay **unregistered** and
/// fail closed — a decoder that ever accepted it would parse an attacker-chosen
/// struct as something else.
#[test]
fn compat_type_id_0x0004_stays_unregistered() {
    // An unregistered id is rejected as UNKNOWN...
    assert_eq!(
        decode::<Grant>(&[0x00, 0x04]),
        Err(DecodeError::UnknownTypeId(0x0004)),
        "\n\ntype_id 0x0004 (the removed `write_grant`, D29) has been re-registered. \
         Re-using a retired codepoint lets old bytes decode as a NEW type — a type \
         confusion across the whole signed-record surface. It must stay unregistered and \
         fail closed. {CHECKLIST}\n"
    );
    // ...and a registered-but-wrong id is a DIFFERENT, more specific error, which
    // is what proves the check above is really testing "unregistered".
    assert_eq!(
        decode::<Grant>(&[0x00, 0x01]),
        Err(DecodeError::WrongTypeId {
            expected: 0x0003,
            got: 0x0001
        })
    );
}

// ===========================================================================
// (B2) Domain-separation labels — every signature ever made
// ===========================================================================

/// Every `encoding::labels::*` string, byte-for-byte. A signature covers
/// `u32 len(label) ‖ label ‖ canonical(struct)`; change one character of one
/// label and EVERY signature ever produced in that role becomes invalid — for
/// every user, retroactively, with no way to re-sign records whose signer is
/// offline or gone.
#[test]
fn compat_signing_labels_are_frozen() {
    let locked: [(&str, &str, &str); 13] = [
        (labels::DIRBINDING, "MaxSecu-dirbinding-v1",
         "every directory binding — NO user's keys can be verified, so nobody can log in, enroll or be shared with"),
        (labels::MANIFEST, "MaxSecu-manifest-v1",
         "every file manifest — NO uploaded file can be opened (the client fails closed on an unverified manifest)"),
        (labels::GRANT, "MaxSecu-grant-v1",
         "every read grant — every share ever made stops verifying"),
        (labels::GENESIS, "MaxSecu-genesis-v1",
         "every file's genesis record — file ownership can no longer be proven"),
        (labels::REVOCATION, "MaxSecu-revocation-v1",
         "every revocation tombstone — revoked users silently become un-revoked (a SECURITY regression)"),
        (labels::REINSTATEMENT, "MaxSecu-reinstatement-v1",
         "every reinstatement record"),
        (labels::KEY_COMPROMISE, "MaxSecu-key-compromise-v1",
         "every key-compromise record"),
        (labels::AUTH, "MaxSecu-auth-v1",
         "every login proof — no existing client can authenticate to the server"),
        (labels::SINK_HEAD, "MaxSecu-sink-head-v1",
         "every anchored sink head — the revocation chain can no longer be anchored"),
        (labels::SINK_CHECKPOINT, "MaxSecu-sink-checkpoint-v1",
         "every sink checkpoint"),
        (labels::KT_CHECKPOINT, "MaxSecu-kt-checkpoint-v1",
         "every key-transparency checkpoint"),
        (labels::UPDATE_MANIFEST, "MaxSecu-update-v1",
         "every signed release — no shipped client will accept an update again"),
        (labels::DIRECTORY_DELEGATION, "maxsecu/directory-delegation/v1",
         "every delegation cert — every pinned client rejects the directory: TOTAL LOCKOUT"),
    ];

    for (got, want, blast) in locked {
        assert_eq!(
            got, want,
            "\n\nDOMAIN-SEPARATION LABEL CHANGED: expected {want:?}, found {got:?}.\n\
             The label is length-framed into the signed bytes, so changing it invalidates \
             {blast}. Signatures cannot be re-made for data whose signer is offline, gone, \
             or is the user themselves on a device they no longer have. \
             This cannot ship. {CHECKLIST}\n"
        );
    }

    // The labels must also stay mutually distinct (cross-role reinterpretation).
    let mut all: Vec<&str> = locked.iter().map(|(g, _, _)| *g).collect();
    all.sort_unstable();
    let n = all.len();
    all.dedup();
    assert_eq!(
        all.len(),
        n,
        "two signing labels collided — cross-role signature reuse"
    );
}

// ===========================================================================
// (B3) The per-stream HKDF labels — every chunk ever uploaded
// ===========================================================================

/// `ck_<stream> = HKDF-SHA256(DEK, "MaxSecu-<stream>-v1")` and
/// `dek_commit = HKDF-SHA256(DEK, "MaxSecu-dek-commit-v1")`.
///
/// The labels live in a private `match` inside `crypto/dek.rs`, so they are
/// locked here through the public KDF: today's `stream_subkey()` must equal the
/// HKDF taken over the literal frozen label bytes.
#[test]
fn compat_hkdf_stream_labels_are_frozen() {
    let dek = Dek::from_bytes([0x5C; 32]);

    let locked: [(StreamType, &[u8]); 4] = [
        (StreamType::Content, b"MaxSecu-content-v1"),
        (StreamType::Metadata, b"MaxSecu-metadata-v1"),
        (StreamType::Thumbnail, b"MaxSecu-thumbnail-v1"),
        (StreamType::Preview, b"MaxSecu-preview-v1"),
    ];
    for (t, label) in locked {
        let want = hkdf_sha256_32(dek.expose(), label);
        assert_eq!(
            *dek.stream_subkey(t),
            want,
            "\n\n{} HKDF label changed: EVERY chunk ever uploaded on that stream becomes \
             undecryptable, permanently. The chunk key is derived from the DEK under this \
             label alone — there is no fallback, no admin escape hatch, and no way to \
             re-derive the old key. The users' media is simply gone. \
             This cannot ship. {CHECKLIST}\n",
            String::from_utf8_lossy(label)
        );
    }

    let want = hkdf_sha256_32(dek.expose(), b"MaxSecu-dek-commit-v1");
    assert_eq!(
        dek.commit(),
        want,
        "\n\nMaxSecu-dek-commit-v1 HKDF label changed: every signed manifest commits to \
         HKDF(DEK, this label). Download re-checks `dek.commit() == manifest.dek_commit` \
         and FAILS CLOSED on a mismatch — so no existing file opens, and no re-share can \
         be built. This cannot ship. {CHECKLIST}\n"
    );

    // The four subkeys and the commitment must stay mutually distinct (a
    // collision would let a chunk be replayed across streams).
    let keys = [
        *dek.stream_subkey(StreamType::Content),
        *dek.stream_subkey(StreamType::Metadata),
        *dek.stream_subkey(StreamType::Thumbnail),
        *dek.stream_subkey(StreamType::Preview),
        dek.commit(),
    ];
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "per-stream HKDF labels collided");
        }
    }
}

// ===========================================================================
// (B4) The hybrid (Suite::V2) wrap — every PQ file's key
// ===========================================================================

fn crypto_src(file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("crypto")
        .join("src")
        .join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// `HYBRID_WRAP_LABEL`, `HYBRID_WRAP_LEN`, `MLKEM_PUB_LEN`, `MLKEM_CT_LEN`,
/// `AEAD_CT_LEN`, `X25519_LEN`.
///
/// The lengths are locked *behaviourally*, through the public wire codec and the
/// frozen 1168-byte wrap. `HYBRID_WRAP_LABEL` is a private const with no public
/// accessor, so it is locked against its declaration in the source — belt and
/// braces: the load-bearing proof that the label still opens real data is
/// `golden_open::compat_frozen_wrap_v2_hybrid_still_unwraps`, which cannot pass
/// if the label moves.
#[test]
fn compat_hybrid_wrap_constants_are_frozen() {
    assert!(
        crypto_src("hybrid.rs")
            .contains(r#"const HYBRID_WRAP_LABEL: &[u8] = b"MaxSecu-hybrid-wrap-v2";"#),
        "\n\nHYBRID_WRAP_LABEL is no longer `b\"MaxSecu-hybrid-wrap-v2\"` (crypto/src/hybrid.rs).\n\
         That label is folded into the KEK `info` of every Suite::V2 wrap. Change it and \
         EVERY post-quantum file's DEK becomes unrecoverable for every recipient — the \
         file's key exists nowhere else. This cannot ship. {CHECKLIST}\n"
    );

    // The wire layout, proven over the frozen artifact: 32 ‖ 1088 ‖ 48 = 1168.
    let wire = read("crypto", "wrap_v2.bin");
    assert_eq!(
        wire.len(),
        1168,
        "\n\nHYBRID_WRAP_LEN moved off 1168. Every stored Suite::V2 wrap is exactly 1168 \
         bytes (eph_x_pub 32 ‖ ct_pq 1088 ‖ aead_ct 48); a parser expecting anything else \
         rejects every one of them. {CHECKLIST}\n"
    );
    let w = deserialize_hybrid_wrap(&wire).expect("the frozen hybrid wrap must still parse");
    assert_eq!(w.eph_x_pub.len(), 32, "X25519_LEN must stay 32");
    assert_eq!(w.ct_pq.len(), 1088, "MLKEM_CT_LEN must stay 1088");
    assert_eq!(
        w.aead_ct.len(),
        48,
        "AEAD_CT_LEN must stay 48 (32-byte DEK + 16-byte GCM tag)"
    );
    assert_eq!(32 + 1088 + 48, 1168);

    // Off-by-one on either side must still fail closed (the length IS the frame).
    assert!(deserialize_hybrid_wrap(&wire[..1167]).is_err());
    let mut long = wire.clone();
    long.push(0);
    assert!(deserialize_hybrid_wrap(&long).is_err());

    assert_eq!(
        MLKEM768_PUB_LEN, 1184,
        "\n\nMLKEM_PUB_LEN moved off 1184. The ML-KEM-768 encapsulation key is a \
         fixed-width field of every PQ directory binding; every binding already published \
         carries exactly 1184 bytes and would stop decoding. {CHECKLIST}\n"
    );
}

// ===========================================================================
// (B5) The delegation cert — the client's pinned trust root
// ===========================================================================

#[test]
fn compat_delegation_constants_are_frozen() {
    assert_eq!(maxsecu_crypto::DELEGATION_VERSION, 1);
    assert_eq!(
        maxsecu_crypto::DELEGATION_BODY_LEN,
        49,
        "the signed delegation body is version(1) ‖ operational_pub(32) ‖ valid_from(8) \
         ‖ valid_until(8) = 49 bytes; changing it invalidates every cert the admin has \
         ever signed offline. {CHECKLIST}"
    );
    assert_eq!(
        maxsecu_crypto::DELEGATION_WIRE_LEN,
        113,
        "\n\nDELEGATION_WIRE_LEN moved off 113 (49-byte body ‖ 64-byte signature). Every \
         deployed server serves a 113-byte cert and every SHIPPED client parses exactly \
         113 bytes, failing closed otherwise — a change here locks every user out of the \
         directory and the only fix is a re-install. This cannot ship. {CHECKLIST}\n"
    );
    assert_eq!(
        maxsecu_crypto::DELEGATION_BODY_LEN + 64,
        maxsecu_crypto::DELEGATION_WIRE_LEN
    );
}

// ===========================================================================
// (B6) MXKB keyblob + MXD5 seedblob — login and the recovery root
// ===========================================================================

/// The keyblob is a 45-byte self-describing header (also the AEAD AAD) followed
/// by the sealed private material. This reconstructs that layout from first
/// principles over the frozen bytes — magic, version, Argon2 params, salt, nonce,
/// header-as-AAD, and the exact v1/v2 lengths.
fn lock_keyblob(stem: &str, version: u8, blob_len: usize, plaintext_len: usize) {
    let blob = read("keyblob", &format!("{stem}.bin"));
    let pw = read_str("keyblob", &format!("{stem}.passphrase.txt"));

    assert_eq!(
        &blob[0..4],
        b"MXKB",
        "\n\nThe keyblob magic is no longer `MXKB`. Every user's `local_key_blob` on disk \
         starts with these four bytes; a different magic means the client refuses to load \
         the only copy of their private keys — every user is locked out permanently. \
         {CHECKLIST}\n"
    );
    assert_eq!(blob[4], version, "{stem}: version byte");
    assert_eq!(
        blob.len(),
        blob_len,
        "\n\nThe keyblob v{version} length moved off {blob_len} (45-byte header + \
         {plaintext_len} plaintext + 16-byte GCM tag). `unlock` checks the length exactly \
         and fails closed, so every existing v{version} blob is refused. {CHECKLIST}\n"
    );

    // Header = bytes 0..45, and it is the AEAD AAD. Re-open the ciphertext with
    // raw AES-256-GCM to prove BOTH facts independently of `keyblob::unlock`.
    let params = Argon2Params {
        m_kib: u32::from_be_bytes(blob[5..9].try_into().unwrap()),
        t: u32::from_be_bytes(blob[9..13].try_into().unwrap()),
        p: u32::from_be_bytes(blob[13..17].try_into().unwrap()),
    };
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blob[17..33]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[33..45]);

    let key = derive_key(pw.as_bytes(), &salt, params).expect("frozen params meet the floor");
    let pt = maxsecu_crypto::open(&key, &nonce, &blob[0..45], &blob[45..]).unwrap_or_else(|e| {
        panic!(
            "\n\nThe keyblob HEADER LAYOUT changed ({stem}): the 45-byte header is the AEAD \
             AAD, and re-deriving the key from the stored (m,t,p,salt) no longer opens the \
             ciphertext — {e}. Every user's key blob is now unreadable. {CHECKLIST}\n"
        )
    });
    assert_eq!(
        pt.len(),
        plaintext_len,
        "{stem}: sealed plaintext is enc_sk(32) ‖ enc_pk(32) ‖ sig_seed(32)\
         {}",
        if plaintext_len > 96 {
            " ‖ mlkem_seed(64)"
        } else {
            ""
        }
    );
}

#[test]
fn compat_keyblob_format_is_frozen() {
    lock_keyblob("keyblob_v1", 1, 157, 96);
    lock_keyblob("keyblob_v2", 2, 221, 160);
}

#[test]
fn compat_seedblob_format_is_frozen() {
    assert_eq!(
        maxsecu_client_core::SEEDBLOB_V1_LEN,
        93,
        "SEEDBLOB_V1_LEN moved off 93 (45-byte header + 32-byte seed + 16-byte tag): the \
         admin's sealed D5 root — the directory trust root, also backed into the recovery \
         blob — can no longer be opened. {CHECKLIST}"
    );

    let blob = read("seedblob", "seedblob_v1.bin");
    assert_eq!(blob.len(), 93);
    assert_eq!(
        &blob[0..4],
        b"MXD5",
        "the D5 seedblob magic is no longer `MXD5`. {CHECKLIST}"
    );
    assert_eq!(blob[4], 1, "seedblob v1 version byte");
}

/// `MXKB` and `MXD5` must stay DISTINCT and mutually unopenable. The magic is
/// bound into the AEAD AAD precisely so a keyblob can never be unsealed as a
/// seedblob (which would hand out an "Ed25519 seed" that is really the user's
/// X25519 secret) and vice-versa.
#[test]
fn compat_keyblob_and_seedblob_magics_stay_distinct() {
    let kb = read("keyblob", "keyblob_v2.bin");
    let sb = read("seedblob", "seedblob_v1.bin");
    assert_ne!(&kb[0..4], &sb[0..4], "MXKB and MXD5 must never collide");

    let kb_pw = read_str("keyblob", "keyblob_v2.passphrase.txt");
    let sb_pw = read_str("seedblob", "seedblob_v1.passphrase.txt");

    assert!(
        maxsecu_client_core::unseal_seed(&kb_pw, &kb).is_err(),
        "\n\nDOMAIN SEPARATION BROKEN: a keyblob (MXKB) opened as a D5 seedblob (MXD5). \
         The two formats share a header shape and a KDF; only the magic keeps them apart. \
         A crossover would let the D5 path treat a user's X25519 secret as a signing seed. \
         {CHECKLIST}\n"
    );
    assert!(
        maxsecu_client_core::keyblob::unlock(&sb_pw, &sb).is_err(),
        "\n\nDOMAIN SEPARATION BROKEN: a D5 seedblob (MXD5) opened as a keyblob (MXKB). \
         {CHECKLIST}\n"
    );
}

// ===========================================================================
// (B7) Suite + enum codepoints — the bytes inside every signed record
// ===========================================================================

#[test]
fn compat_suite_and_enum_codepoints_are_frozen() {
    assert_eq!(SUITE_V1, 0x0001, "Suite::V1 codepoint. {CHECKLIST}");
    assert_eq!(SUITE_V2, 0x0002, "Suite::V2 codepoint. {CHECKLIST}");

    // `alg` sits at a fixed offset of every manifest: type_id(2) ‖ file_id(16)
    // ‖ version(8) ‖ file_type(1) ‖ alg(2). Prove the codepoints over the frozen
    // signed manifests, not just over today's enum.
    let m1 = read("encoding", "signed_manifest_v1.bin");
    assert_eq!(
        &m1[27..29],
        &[0x00, 0x01],
        "the frozen Suite::V1 manifest no longer carries alg=0x0001. {CHECKLIST}"
    );
    let m2 = read("encoding", "signed_manifest_v2.bin");
    assert_eq!(
        &m2[27..29],
        &[0x00, 0x02],
        "the frozen Suite::V2 manifest no longer carries alg=0x0002. {CHECKLIST}"
    );

    // StreamType — bound into the AAD of EVERY chunk.
    assert_eq!(StreamType::Content as u8, 1);
    assert_eq!(StreamType::Metadata as u8, 2);
    assert_eq!(StreamType::Thumbnail as u8, 3);
    assert_eq!(
        StreamType::Preview as u8,
        4,
        "\n\nA StreamType codepoint moved. The stream_type is inside `canonical(chunk_aad)`, \
         which is the AEAD AAD of every chunk — a different codepoint means every chunk of \
         every stream fails its authentication check and no file opens. It is ALSO the last \
         path segment of `blob_ref`, so the chunks would orphan on disk as well. \
         This cannot ship. {CHECKLIST}\n"
    );

    // FileType — server-visible AND authenticated in the signed manifest.
    assert_eq!(FileType::Video as u8, 1);
    assert_eq!(FileType::Image as u8, 2);
    assert_eq!(FileType::Blog as u8, 3);
    assert_eq!(FileType::Generic as u8, 4);
    assert_eq!(
        FileType::Bundle as u8,
        5,
        "a FileType codepoint moved: every stored manifest and bundle body decodes to the \
         WRONG type (or fails closed). {CHECKLIST}"
    );

    // The remaining wire enums.
    assert_eq!(RecipientType::User as u8, 1);
    assert_eq!(RecipientType::Recovery as u8, 2);
    assert_eq!(Role::User as u8, 1);
    assert_eq!(Role::Admin as u8, 2);
    assert_eq!(Compression::None as u8, 0);
    assert_eq!(Compression::Zstd as u8, 1);
}

// ===========================================================================
// (B8) blob_ref — every chunk already stored on every server
// ===========================================================================

/// `blob_ref = hex(file_id)/version/stream_type`, assigned by the server in
/// `files::parse_stage` and stored in `file_streams.blob_ref`. It is the key
/// under which every chunk lives on disk / in Dropbox.
///
/// Known-answer test driven through the REAL `parse_stage` over a frozen
/// manifest: if the scheme changes, every chunk already stored on every server
/// orphans — the rows point at paths that no longer exist and no file can be
/// downloaded.
#[test]
fn compat_blob_ref_scheme_is_frozen() {
    let exp: serde_json::Value =
        serde_json::from_slice(&read("blobref", "blobref_manifest.expect.json")).expect("json");
    let manifest_bytes = read("blobref", "blobref_manifest.bin");

    let file_id_hex = exp["file_id"].as_str().unwrap();
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&hex::decode(file_id_hex).unwrap());
    let mut caller_id = [0u8; 16];
    caller_id.copy_from_slice(&hex::decode(exp["caller_id"].as_str().unwrap()).unwrap());
    let version = exp["version"].as_u64().unwrap();

    let parsed = maxsecu_server::parse_stage(maxsecu_server::StageInput {
        file_id,
        caller_id,
        file_type_advisory: 1,
        genesis: None, // a rotation (vN) — no genesis, so this stays a pure decode
        manifest_bytes,
        manifest_sig: [0u8; 64],
        wraps: vec![maxsecu_server::WrapInput {
            recipient_id: [0u8; 16],
            recipient_type: 2, // the recovery wrap parse_stage requires
            wrapped_dek: vec![0u8; 80],
            wrap_alg: 1,
            granted_by: caller_id,
            grant_bytes: Vec::new(),
            grant_sig: [0u8; 64],
        }],
        stream_totals: Vec::new(),
        proposed_version: version,
        listed: true,
        bundle_id: None,
    })
    .expect("a manifest a real server already staged must still parse");

    let want = &exp["blob_refs"];
    assert_eq!(parsed.streams.len(), 4);
    for s in &parsed.streams {
        let expected = want[s.stream_type.to_string()]
            .as_str()
            .expect("a frozen blob_ref for each stream type");
        assert_eq!(
            s.blob_ref, expected,
            "\n\nBLOB_REF SCHEME CHANGED (was `hex(file_id)/version/stream_type`, got \
             {:?}). Every chunk already stored on every deployed server — local disk and \
             Dropbox cold tier alike — lives under the OLD key. Change the scheme and all \
             of them orphan: the `file_streams` rows point at paths that no longer exist, \
             and no already-uploaded file can be downloaded again. Re-uploading is the \
             only fix, and the plaintext is on the users' machines, not ours. \
             This cannot ship. {CHECKLIST}\n",
            s.blob_ref
        );
    }
}

// ===========================================================================
// (B9) The pre-existing canonical golden vectors still decode
// ===========================================================================

/// `crates/encoding/tests/fixtures/canonical_vectors.tsv` is the repo's ONE
/// pre-existing frozen wire fixture (12 of the 13 registered structs; the 13th,
/// `BundleBody`, is frozen in `compat/fixtures/encoding/bundle_body.bin`).
///
/// The encoding crate's own test asserts today's `encode()` still *produces*
/// those bytes. This asserts the other, load-bearing direction: today's strict
/// `decode()` — re-encode guard and all — still *accepts* them. Those are the
/// bytes inside every signature ever made.
#[test]
fn compat_canonical_vectors_tsv_still_decodes() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join("encoding")
        .join("tests")
        .join("fixtures")
        .join("canonical_vectors.tsv");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    let mut seen = 0usize;
    for line in raw
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    {
        let (name, hexs) = line.split_once('\t').expect("name<TAB>hex");
        let bytes = hex::decode(hexs).expect("fixture hex");
        let type_id = u16::from_be_bytes([bytes[0], bytes[1]]);

        // `decode::<T>` runs the strict decoder AND the master re-encode guard, so
        // an Ok here means these exact bytes are still the one canonical form.
        let ok = match name {
            "dirbinding" => decode::<DirBinding>(&bytes).is_ok() && type_id == 0x0001,
            "manifest" => decode::<Manifest>(&bytes).is_ok() && type_id == 0x0002,
            "stream" => decode::<Stream>(&bytes).is_ok() && type_id == 0x000D,
            "grant_user" | "grant_recovery" => decode::<Grant>(&bytes).is_ok() && type_id == 0x0003,
            "genesis" => decode::<Genesis>(&bytes).is_ok() && type_id == 0x0005,
            "revocation_accountwide" | "revocation_specific_rolenarrow" => {
                decode::<Revocation>(&bytes).is_ok() && type_id == 0x0006
            }
            "reinstatement" => decode::<Reinstatement>(&bytes).is_ok() && type_id == 0x0007,
            "key_compromise" => decode::<KeyCompromise>(&bytes).is_ok() && type_id == 0x0008,
            "auth_proof_context" => decode::<AuthProofContext>(&bytes).is_ok() && type_id == 0x0009,
            "wrap_context" => decode::<WrapContext>(&bytes).is_ok() && type_id == 0x000A,
            "chunk_aad" => decode::<ChunkAad>(&bytes).is_ok() && type_id == 0x000B,
            "fingerprint_input" => decode::<FingerprintInput>(&bytes).is_ok() && type_id == 0x000C,
            other => panic!(
                "unknown vector `{other}` in canonical_vectors.tsv — a new struct was added \
                 without extending the compat gate. {CHECKLIST}"
            ),
        };
        assert!(
            ok,
            "\n\nFROZEN CANONICAL VECTOR NO LONGER DECODES: `{name}`.\n\
             These bytes are the wire form of a structure that is signed, stored and \
             transmitted. If today's strict decoder rejects them, every stored record of \
             that type is unreadable and every signature over it is unverifiable. \
             This cannot ship. {CHECKLIST}\n"
        );
        seen += 1;
    }
    assert!(
        seen >= 14,
        "the canonical vector file lost entries (saw {seen})"
    );
}
