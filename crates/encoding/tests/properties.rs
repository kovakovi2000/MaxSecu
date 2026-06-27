//! Property tests for the Phase-0 exit gate (encoding-spec §9):
//!
//! * `decode∘encode` identity — for every value `v`, `decode(encode(v)) == v`.
//! * `encode∘decode` identity on accepted inputs — for every accepted byte
//!   string `b` (here `b = encode(v)`), `encode(decode(b)) == b` (the canonical
//!   guard, §7 rule 5).
//!
//! Strategies generate only canonical values (sorted/unique sets & streams,
//! recovery-id binding upheld) so a round-trip is meaningful; the adversarial
//! rejection of *non*-canonical bytes is covered in `vectors.rs`.

use maxsecu_encoding::structs::*;
use maxsecu_encoding::types::*;
use maxsecu_encoding::{decode, encode, Canonical, RECOVERY_ID};
use proptest::prelude::*;

// ---------- leaf strategies ----------

fn id() -> impl Strategy<Value = Id> {
    any::<[u8; 16]>().prop_map(Id)
}
fn b32() -> impl Strategy<Value = Bytes32> {
    any::<[u8; 32]>().prop_map(Bytes32)
}
fn timestamp() -> impl Strategy<Value = Timestamp> {
    any::<u64>().prop_map(Timestamp)
}
fn text() -> impl Strategy<Value = Text> {
    // Printable ASCII is always valid UTF-8 and NFC-stable.
    proptest::string::string_regex("[ -~]{0,64}")
        .unwrap()
        .prop_map(|s| Text::new(&s).expect("printable ASCII within MAX_TEXT"))
}
fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::User), Just(Role::Admin)]
}
fn role_set() -> impl Strategy<Value = RoleSet> {
    proptest::collection::vec(role(), 0..3).prop_map(RoleSet::new)
}
fn stream_type() -> impl Strategy<Value = StreamType> {
    prop_oneof![
        Just(StreamType::Content),
        Just(StreamType::Metadata),
        Just(StreamType::Thumbnail),
        Just(StreamType::Preview),
    ]
}
fn compression() -> impl Strategy<Value = Compression> {
    prop_oneof![Just(Compression::None), Just(Compression::Zstd)]
}
fn file_type() -> impl Strategy<Value = FileType> {
    prop_oneof![
        Just(FileType::Video),
        Just(FileType::Image),
        Just(FileType::Blog),
    ]
}
fn recipient_type() -> impl Strategy<Value = RecipientType> {
    prop_oneof![Just(RecipientType::User), Just(RecipientType::Recovery)]
}
fn file_scope() -> impl Strategy<Value = FileScope> {
    prop_oneof![
        Just(FileScope::AccountWide),
        id().prop_map(FileScope::Specific),
    ]
}

// ---------- struct strategies (canonical values only) ----------

prop_compose! {
    fn stream()(
        stream_type in stream_type(),
        compression in compression(),
        chunk_count in any::<u64>(),
        digest in b32(),
    ) -> Stream {
        Stream { stream_type, compression, chunk_count, digest }
    }
}

fn streams() -> impl Strategy<Value = Vec<Stream>> {
    // Ascending & unique by stream_type — the canonical form (§4 / V-13).
    proptest::collection::vec(stream(), 0..5).prop_map(|mut v| {
        v.sort_by_key(|s| s.stream_type as u8);
        v.dedup_by_key(|s| s.stream_type as u8);
        v
    })
}

prop_compose! {
    fn dirbinding()(
        username in text(), user_id in id(), enc_pub in b32(), sig_pub in b32(),
        key_version in any::<u64>(), roles in role_set(),
        not_before in timestamp(), not_after in timestamp(),
    ) -> DirBinding {
        DirBinding { username, user_id, enc_pub, sig_pub, key_version, roles, not_before, not_after }
    }
}

prop_compose! {
    fn manifest()(
        file_id in id(), version in any::<u64>(), file_type in file_type(),
        chunk_size in any::<u32>(), dek_commit in b32(), streams in streams(),
        recovery_present in any::<bool>(), author_id in id(), created_at in timestamp(),
    ) -> Manifest {
        Manifest {
            file_id, version, file_type, alg: Suite::V1, chunk_size, dek_commit,
            streams, recovery_present, author_id, created_at,
        }
    }
}

prop_compose! {
    // Generate a *valid* grant: the recovery recipient_type is paired with
    // RECOVERY_ID (the §7-rule-4 binding) so the value is canonical/decodable.
    fn grant()(
        file_id in id(), file_version in any::<u64>(), recipient in id(),
        recipient_type in recipient_type(), dek_commit in b32(), granted_by in id(),
        created_at in timestamp(),
    ) -> Grant {
        let recipient_id = match recipient_type {
            RecipientType::Recovery => RECOVERY_ID,
            RecipientType::User => recipient,
        };
        Grant { file_id, file_version, recipient_id, recipient_type, dek_commit, granted_by, created_at }
    }
}

prop_compose! {
    fn genesis()(
        file_id in id(), owner_id in id(), owner_key_version in any::<u64>(),
        created_at in timestamp(),
    ) -> Genesis {
        Genesis { file_id, owner_id, owner_key_version, created_at }
    }
}

prop_compose! {
    fn revocation()(
        scope in file_scope(), revoked_user_id in id(),
        revoked_capability in proptest::option::of(role()),
        from_version in any::<u64>(), revocation_epoch in any::<u64>(),
        prev_head in b32(), issued_by in id(),
        co_signed_by in proptest::option::of(id()), created_at in timestamp(),
    ) -> Revocation {
        Revocation {
            scope, revoked_user_id, revoked_capability, from_version,
            revocation_epoch, prev_head, issued_by, co_signed_by, created_at,
        }
    }
}

prop_compose! {
    fn reinstatement()(
        scope in file_scope(), reinstated_user_id in id(),
        supersedes_epoch in any::<u64>(), reinstatement_epoch in any::<u64>(),
        prev_head in b32(), issued_by in id(), co_signed_by in id(),
        created_at in timestamp(),
    ) -> Reinstatement {
        Reinstatement {
            scope, reinstated_user_id, supersedes_epoch, reinstatement_epoch,
            prev_head, issued_by, co_signed_by, created_at,
        }
    }
}

prop_compose! {
    fn key_compromise()(
        user_id in id(), key_version in any::<u64>(), effective_from in timestamp(),
        prev_head in b32(), issued_by in id(), co_signed_by in id(),
        created_at in timestamp(),
    ) -> KeyCompromise {
        KeyCompromise { user_id, key_version, effective_from, prev_head, issued_by, co_signed_by, created_at }
    }
}

prop_compose! {
    fn auth_proof_context()(
        server_id in text(), tls_exporter in b32(), nonce in b32(), timestamp in timestamp(),
    ) -> AuthProofContext {
        AuthProofContext { server_id, tls_exporter, nonce, timestamp }
    }
}

prop_compose! {
    fn wrap_context()(
        file_id in id(), version in any::<u64>(), recipient_id in id(),
    ) -> WrapContext {
        WrapContext { file_id, version, recipient_id }
    }
}

prop_compose! {
    fn chunk_aad()(
        file_id in id(), version in any::<u64>(), stream_type in stream_type(),
        chunk_index in any::<u64>(), is_last in any::<bool>(),
    ) -> ChunkAad {
        ChunkAad { file_id, version, stream_type, chunk_index, is_last }
    }
}

prop_compose! {
    fn fingerprint_input()(enc_pub in b32(), sig_pub in b32()) -> FingerprintInput {
        FingerprintInput { enc_pub, sig_pub }
    }
}

/// Assert both identities for one value.
fn round_trips<T: Canonical + PartialEq + std::fmt::Debug>(v: &T) -> Result<(), TestCaseError> {
    let b = encode(v);
    let back = decode::<T>(&b).expect("canonical bytes must decode");
    prop_assert_eq!(&back, v, "decode∘encode identity");
    prop_assert_eq!(encode(&back), b, "encode∘decode identity (canonical guard)");
    Ok(())
}

proptest! {
    #[test] fn pr_dirbinding(v in dirbinding()) { round_trips(&v)?; }
    #[test] fn pr_manifest(v in manifest()) { round_trips(&v)?; }
    #[test] fn pr_stream(v in stream()) { round_trips(&v)?; }
    #[test] fn pr_grant(v in grant()) { round_trips(&v)?; }
    #[test] fn pr_genesis(v in genesis()) { round_trips(&v)?; }
    #[test] fn pr_revocation(v in revocation()) { round_trips(&v)?; }
    #[test] fn pr_reinstatement(v in reinstatement()) { round_trips(&v)?; }
    #[test] fn pr_key_compromise(v in key_compromise()) { round_trips(&v)?; }
    #[test] fn pr_auth_proof_context(v in auth_proof_context()) { round_trips(&v)?; }
    #[test] fn pr_wrap_context(v in wrap_context()) { round_trips(&v)?; }
    #[test] fn pr_chunk_aad(v in chunk_aad()) { round_trips(&v)?; }
    #[test] fn pr_fingerprint_input(v in fingerprint_input()) { round_trips(&v)?; }
}
