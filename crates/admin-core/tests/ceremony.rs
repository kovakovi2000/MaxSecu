//! P2.1 — offline ceremony / signing core (DESIGN §7.1 directory bindings,
//! §12.1 fingerprint-confirmed enrollment, §11.5/§7.6 sink-anchored, hash-chained
//! control log). Pure: no I/O. Proves sign→verify, fingerprint gating, hash-chain
//! linkage, per-scope monotonic epochs, and dual-control enforcement.

use maxsecu_admin_core::{
    CeremonyError, ControlChain, ControlRecord, CoSign, DirectorySigner, KeyCompromiseParams,
    ReinstateParams, RevokeParams,
};
use maxsecu_crypto::{fingerprint, sha256, SigningKey};
use maxsecu_encoding::types::{FileScope, Id, Role, RoleSet, Text, Timestamp};
use maxsecu_encoding::{decode, encode, structs::DirBinding, GENESIS_HEAD};

const TS: Timestamp = Timestamp(1_719_500_000_000);

fn binding(username: &str, uid: u8, enc: u8, sig: u8, key_version: u64) -> DirBinding {
    DirBinding {
        username: Text::new(username).unwrap(),
        user_id: Id([uid; 16]),
        enc_pub: maxsecu_encoding::types::Bytes32([enc; 32]),
        sig_pub: maxsecu_encoding::types::Bytes32([sig; 32]),
        key_version,
        roles: RoleSet::new([Role::User]),
        not_before: TS,
        not_after: Timestamp(TS.0 + 31_536_000_000),
        mlkem_pub: None,
    }
}

// ---- directory binding signing (D5, §7.1) ----

#[test]
fn signed_binding_verifies_under_the_pinned_root_only() {
    let d5 = DirectorySigner::generate();
    let other = DirectorySigner::generate();
    let signed = d5.sign_binding(&binding("alice", 1, 0xE1, 0x51, 1), None);

    // Verifies under the directory-signing public key clients pin (§7.2 step 2).
    assert!(signed.verify(&d5.public_key()).is_ok());
    // …and under no other key — the server cannot forge a binding (§7).
    assert!(signed.verify(&other.public_key()).is_err());
}

#[test]
fn tampered_binding_fails_verification() {
    let d5 = DirectorySigner::generate();
    let mut signed = d5.sign_binding(&binding("alice", 1, 0xE1, 0x51, 1), None);
    // Flip the bound key — the offline signature no longer covers it.
    signed.binding.key_version = 2;
    assert!(signed.verify(&d5.public_key()).is_err());
}

#[test]
fn fingerprint_is_sha256_of_the_canonical_key_pair() {
    let d5 = DirectorySigner::generate();
    let b = binding("alice", 1, 0xE1, 0x51, 1);
    let signed = d5.sign_binding(&b, None);
    assert_eq!(signed.fingerprint(), fingerprint(&[0xE1; 32], &[0x51; 32]));
}

#[test]
fn sign_binding_includes_mlkem() {
    // A PQ binding: sign with an ML-KEM-768 key. The resulting binding verifies
    // under the pinned root (the D5 signature covers the trailing PQ field) and
    // carries the exact key — the fingerprint is unchanged (enc_pub ‖ sig_pub).
    let d5 = DirectorySigner::generate();
    let mlkem = maxsecu_encoding::types::MlKemPub([0x7A; 1184]);
    let b = binding("alice", 1, 0xE1, 0x51, 1);
    let signed = d5.sign_binding(&b, Some(mlkem));

    assert!(signed.verify(&d5.public_key()).is_ok());
    assert_eq!(signed.binding.mlkem_pub, Some(mlkem));
    assert_eq!(signed.fingerprint(), fingerprint(&[0xE1; 32], &[0x51; 32]));

    // Tampering with the PQ key breaks the signature (it is authenticated).
    let mut tampered = signed.clone();
    tampered.binding.mlkem_pub = Some(maxsecu_encoding::types::MlKemPub([0x00; 1184]));
    assert!(tampered.verify(&d5.public_key()).is_err());
}

// ---- fingerprint-confirmed enrollment ceremony (§12.1 / D9) ----

#[test]
fn enrollment_signs_only_when_the_confirmed_fingerprint_matches() {
    let d5 = DirectorySigner::generate();
    let b = binding("alice", 1, 0xE1, 0x51, 1);
    let confirmed = fingerprint(&[0xE1; 32], &[0x51; 32]);

    // Admin confirmed the correct fingerprint in person → signs.
    let signed = d5.sign_enrollment(&b, &confirmed).expect("matching fingerprint signs");
    assert!(signed.verify(&d5.public_key()).is_ok());
}

#[test]
fn enrollment_refuses_a_mismatched_fingerprint() {
    let d5 = DirectorySigner::generate();
    let b = binding("alice", 1, 0xE1, 0x51, 1);
    // A binding whose fingerprint doesn't match what the admin confirmed is
    // NEVER signed (the §12.1 exit gate / MITM defense).
    let wrong = fingerprint(&[0xAA; 32], &[0xBB; 32]);
    assert_eq!(
        d5.sign_enrollment(&b, &wrong).unwrap_err(),
        CeremonyError::FingerprintMismatch
    );
}

// ---- control-log hash chain (§7.6 / §11.5) ----

fn revoke_params(scope: FileScope, victim: u8, issuer: u8) -> RevokeParams {
    RevokeParams {
        scope,
        revoked_user_id: Id([victim; 16]),
        revoked_capability: None,
        from_version: 1,
        issued_by: Id([issuer; 16]),
        created_at: TS,
    }
}

#[test]
fn first_record_chains_to_genesis_head_then_each_links_to_the_prior() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let file = FileScope::Specific(Id([0x10; 16]));

    let r1 = chain
        .revoke(&admin, revoke_params(file, 0x99, 0x01), None)
        .unwrap();
    assert_eq!(r1.prev_head(), GENESIS_HEAD.0, "first record seeds from GENESIS_HEAD");
    assert_eq!(r1.head, sha256(&encode_record(&r1.record)), "head = SHA-256(canonical(record))");
    assert_eq!(chain.head(), r1.head);

    let r2 = chain
        .revoke(&admin, revoke_params(file, 0x98, 0x01), None)
        .unwrap();
    assert_eq!(r2.prev_head(), r1.head, "each record's prev_head is the prior head (contiguity)");
    assert_eq!(chain.head(), r2.head);
}

#[test]
fn revocation_epoch_is_monotonic_per_scope_and_independent_across_scopes() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let file_a = FileScope::Specific(Id([0x0A; 16]));
    let file_b = FileScope::Specific(Id([0x0B; 16]));

    let a1 = chain.revoke(&admin, revoke_params(file_a, 0x91, 1), None).unwrap();
    let a2 = chain.revoke(&admin, revoke_params(file_a, 0x92, 1), None).unwrap();
    let b1 = chain.revoke(&admin, revoke_params(file_b, 0x93, 1), None).unwrap();

    assert_eq!(a1.epoch(), Some(1));
    assert_eq!(a2.epoch(), Some(2), "same scope ⇒ next epoch");
    assert_eq!(b1.epoch(), Some(1), "a different scope has its own counter");
}

#[test]
fn issuer_signature_and_canonical_bytes_round_trip() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let admin_pub = admin.verifying_key().to_bytes();
    let rec = chain
        .revoke(&admin, revoke_params(FileScope::AccountWide, 0x99, 1),
            Some(CoSign { admin_id: Id([2; 16]), key: &SigningKey::generate() }))
        .unwrap();

    // The signature verifies under the issuer's key, over the published bytes…
    assert!(rec.verify(&admin_pub).is_ok());
    // …and the bytes are the one canonical form (decode round-trips).
    let ControlRecord::Revocation(ref rv) = rec.record else { panic!("expected revocation") };
    assert_eq!(decode::<maxsecu_encoding::structs::Revocation>(&rec.bytes).unwrap(), *rv);
}

// ---- dual control (§10.1 / §11.5a) ----

#[test]
fn account_wide_revoke_requires_a_co_signer() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    // Mass/`*` revoke without a second admin is rejected (dual control).
    assert_eq!(
        chain
            .revoke(&admin, revoke_params(FileScope::AccountWide, 0x99, 1), None)
            .unwrap_err(),
        CeremonyError::DualControlRequired
    );
}

#[test]
fn single_file_revoke_needs_no_co_signer_but_account_wide_co_sig_verifies() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let co = SigningKey::generate();
    let co_pub = co.verifying_key().to_bytes();

    // single-file: no co-signer needed.
    let single = chain
        .revoke(&admin, revoke_params(FileScope::Specific(Id([7; 16])), 0x99, 1), None)
        .unwrap();
    assert!(single.co_sig.is_none());

    // account-wide: co-signed, and the second signature verifies.
    let mass = chain
        .revoke(&admin, revoke_params(FileScope::AccountWide, 0x98, 1),
            Some(CoSign { admin_id: Id([2; 16]), key: &co }))
        .unwrap();
    assert!(mass.verify_co_sign(&co_pub).is_ok());
}

#[test]
fn reinstatement_is_always_dual_controlled_and_links_into_the_chain() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let admin_pub = admin.verifying_key().to_bytes();
    let co = SigningKey::generate();
    let co_pub = co.verifying_key().to_bytes();
    let file = FileScope::Specific(Id([0x10; 16]));

    let rev = chain.revoke(&admin, revoke_params(file, 0x99, 1), None).unwrap();
    let rein = chain.reinstate(
        &admin,
        ReinstateParams {
            scope: file,
            reinstated_user_id: Id([0x99; 16]),
            supersedes_epoch: rev.epoch().unwrap(),
            issued_by: Id([1; 16]),
            created_at: TS,
        },
        CoSign { admin_id: Id([2; 16]), key: &co },
    );
    assert_eq!(rein.prev_head(), rev.head, "reinstatement extends the same chain");
    assert!(rein.verify(&admin_pub).is_ok());
    assert!(rein.verify_co_sign(&co_pub).is_ok());
}

#[test]
fn key_compromise_record_is_dual_controlled_and_chains() {
    let mut chain = ControlChain::new();
    let admin = SigningKey::generate();
    let admin_pub = admin.verifying_key().to_bytes();
    let co = SigningKey::generate();
    let co_pub = co.verifying_key().to_bytes();

    let kc = chain.key_compromise(
        &admin,
        KeyCompromiseParams {
            user_id: Id([0x44; 16]),
            key_version: 3,
            effective_from: TS,
            issued_by: Id([1; 16]),
            created_at: TS,
        },
        CoSign { admin_id: Id([2; 16]), key: &co },
    );
    assert_eq!(kc.prev_head(), GENESIS_HEAD.0);
    assert!(kc.verify(&admin_pub).is_ok());
    assert!(kc.verify_co_sign(&co_pub).is_ok());
    assert!(matches!(kc.record, ControlRecord::KeyCompromise(_)));
    assert_eq!(kc.epoch(), None, "key_compromise carries no per-scope epoch");
}

// Helper mirroring the core's head derivation, so the test pins the formula.
fn encode_record(r: &ControlRecord) -> Vec<u8> {
    match r {
        ControlRecord::Revocation(x) => encode(x),
        ControlRecord::Reinstatement(x) => encode(x),
        ControlRecord::KeyCompromise(x) => encode(x),
    }
}
