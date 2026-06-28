//! Re-share + soft-revoke over the in-memory [`Store`] (api.md §10, Phase 4 P4.3).
//!
//! Drives the sharing surface exactly as the HTTP handlers will: stage+finalize
//! a v1, re-share read to another user (`POST .../wraps`), serve the re-shared
//! recipient their wrap **plus the ancestor grant chain** to the author (§8.5),
//! and soft-revoke (`DELETE .../wraps/{recipient}`) with the owner-or-granter
//! coarse gate. The server stores inert bytes and never verifies grants — the
//! client re-verifies the chain (P4.1).

use maxsecu_encoding::structs::{Genesis, Manifest, Stream};
use maxsecu_encoding::types::{Bytes32, Compression, FileType, Id, StreamType, Suite, Timestamp};
use maxsecu_encoding::{encode, RECOVERY_ID};
use maxsecu_server::{
    parse_stage, AddWrapError, DeleteWrapError, GenesisInput, MemoryStore, StageInput, Store,
    VersionSelector, WrapInput,
};

const W: [u8; 16] = [0x55; 16];

const OWNER: [u8; 16] = [0x11; 16];
const R: [u8; 16] = [0x22; 16];
const V: [u8; 16] = [0x33; 16];
const STRANGER: [u8; 16] = [0x77; 16];
const FILE: [u8; 16] = [0xF1; 16];

fn manifest_bytes(version: u64) -> Vec<u8> {
    encode(&Manifest {
        file_id: Id(FILE),
        version,
        file_type: FileType::Blog,
        alg: Suite::V1,
        chunk_size: 1 << 20,
        dek_commit: Bytes32([0xDC; 32]),
        streams: vec![Stream {
            stream_type: StreamType::Content,
            compression: Compression::None,
            chunk_count: 1,
            digest: Bytes32([0xC0; 32]),
        }],
        recovery_present: true,
        author_id: Id(OWNER),
        created_at: Timestamp(1_719_500_000_000 + version),
    })
}

fn genesis_input() -> GenesisInput {
    GenesisInput {
        genesis_bytes: encode(&Genesis {
            file_id: Id(FILE),
            owner_id: Id(OWNER),
            owner_key_version: 1,
            created_at: Timestamp(1_719_500_000_000),
        }),
        genesis_sig: [0x9A; 64],
    }
}

/// A wrap row carrying a distinct grant marker so tests can assert *which* grant
/// the server returns (the server treats grant bytes as opaque).
fn wrap(recipient: [u8; 16], rtype: i16, granted_by: [u8; 16], tag: u8) -> WrapInput {
    WrapInput {
        recipient_id: recipient,
        recipient_type: rtype,
        wrapped_dek: vec![tag; 48],
        wrap_alg: 1,
        granted_by,
        grant_bytes: vec![tag; 8],
        grant_sig: [tag; 64],
    }
}

/// Stage v1 with `wraps` and finalize it.
async fn finalized_v1(store: &MemoryStore, wraps: Vec<WrapInput>) {
    let input = StageInput {
        file_id: FILE,
        caller_id: OWNER,
        file_type_advisory: FileType::Blog as u8 as i16,
        genesis: Some(genesis_input()),
        manifest_bytes: manifest_bytes(1),
        manifest_sig: [0x9B; 64],
        wraps,
        stream_totals: vec![(1, 1_000)],
        proposed_version: 1,
    };
    let parsed = parse_stage(input).unwrap();
    store.stage_version(parsed, 1000).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 1001).await.unwrap();
}

#[tokio::test]
async fn get_file_returns_the_ancestor_grant_chain_to_the_author() {
    let store = MemoryStore::new();
    // owner (author-rooted) + recovery + R (author-rooted) + V (re-shared by R).
    finalized_v1(
        &store,
        vec![
            wrap(OWNER, 1, OWNER, 0xA0),
            wrap(RECOVERY_ID.0, 2, OWNER, 0x5E),
            wrap(R, 1, OWNER, 0xB0),
            wrap(V, 1, R, 0xC0),
        ],
    )
    .await;

    // V's chain: V's leaf grant + R's ancestor grant (R is author-rooted).
    let v_view = store
        .get_file(FILE, VersionSelector::Latest, V)
        .await
        .unwrap()
        .expect("V holds a wrap");
    assert_eq!(v_view.my_wrap.grant_bytes, vec![0xC0; 8]);
    assert_eq!(
        v_view.my_wrap.ancestor_grants,
        vec![(vec![0xB0; 8], [0xB0; 64])],
        "exactly R's grant, chaining V to the author"
    );

    // R is author-rooted → no ancestors.
    let r_view = store
        .get_file(FILE, VersionSelector::Latest, R)
        .await
        .unwrap()
        .unwrap();
    assert!(r_view.my_wrap.ancestor_grants.is_empty());
}

#[tokio::test]
async fn reshare_adds_a_wrap_visible_to_the_new_recipient() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;

    // Before: V has no wrap (404/None, no oracle).
    assert!(store
        .get_file(FILE, VersionSelector::Latest, V)
        .await
        .unwrap()
        .is_none());

    // Owner re-shares read to V (granted_by = owner, the current wrap holder).
    store
        .add_wrap(FILE, wrap(V, 1, OWNER, 0xC0), OWNER, 2000)
        .await
        .expect("re-share succeeds");

    let v_view = store
        .get_file(FILE, VersionSelector::Latest, V)
        .await
        .unwrap()
        .expect("V now holds a wrap");
    assert_eq!(v_view.my_wrap.wrapped_dek, vec![0xC0; 48]);
}

#[tokio::test]
async fn reshare_by_a_non_holder_is_refused_without_an_oracle() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;

    // STRANGER holds no wrap → cannot re-share; indistinguishable from missing.
    assert_eq!(
        store
            .add_wrap(FILE, wrap(V, 1, STRANGER, 0xC0), STRANGER, 2000)
            .await,
        Err(AddWrapError::NoAccess)
    );
}

#[tokio::test]
async fn reshare_with_granted_by_not_the_caller_is_rejected() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;
    // Caller is owner but the grant claims someone else granted it — inconsistent.
    assert_eq!(
        store
            .add_wrap(FILE, wrap(V, 1, R, 0xC0), OWNER, 2000)
            .await,
        Err(AddWrapError::BadRequest)
    );
}

#[tokio::test]
async fn reshare_to_the_recovery_recipient_is_rejected() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;
    assert_eq!(
        store
            .add_wrap(FILE, wrap(RECOVERY_ID.0, 2, OWNER, 0xC0), OWNER, 2000)
            .await,
        Err(AddWrapError::BadRequest)
    );
}

#[tokio::test]
async fn soft_revoke_by_owner_denies_the_recipient() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;
    store
        .add_wrap(FILE, wrap(V, 1, OWNER, 0xC0), OWNER, 2000)
        .await
        .unwrap();

    // Owner soft-revokes V.
    store.delete_wrap(FILE, V, OWNER).await.expect("owner may revoke");
    assert!(store
        .get_file(FILE, VersionSelector::Latest, V)
        .await
        .unwrap()
        .is_none(), "V's wrap is gone");
}

#[tokio::test]
async fn soft_revoke_by_the_granter_denies_their_grantee() {
    let store = MemoryStore::new();
    // R is author-rooted; R re-shares to V; R (the granter) may revoke V.
    finalized_v1(
        &store,
        vec![
            wrap(OWNER, 1, OWNER, 0xA0),
            wrap(RECOVERY_ID.0, 2, OWNER, 0x5E),
            wrap(R, 1, OWNER, 0xB0),
        ],
    )
    .await;
    store
        .add_wrap(FILE, wrap(V, 1, R, 0xC0), R, 2000)
        .await
        .unwrap();

    store.delete_wrap(FILE, V, R).await.expect("granter may revoke grantee");
    assert!(store
        .get_file(FILE, VersionSelector::Latest, V)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn soft_revoke_by_an_unrelated_user_is_refused() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;
    store
        .add_wrap(FILE, wrap(V, 1, OWNER, 0xC0), OWNER, 2000)
        .await
        .unwrap();

    // R is neither the owner nor V's granter → cannot soft-revoke V.
    assert_eq!(
        store.delete_wrap(FILE, V, R).await,
        Err(DeleteWrapError::NotAuthorized)
    );
}

#[tokio::test]
async fn owner_lists_recipients_with_chains_for_rotation() {
    let store = MemoryStore::new();
    // owner + recovery + R (author-rooted) + W (re-shared by R).
    finalized_v1(
        &store,
        vec![
            wrap(OWNER, 1, OWNER, 0xA0),
            wrap(RECOVERY_ID.0, 2, OWNER, 0x5E),
            wrap(R, 1, OWNER, 0xB0),
            wrap(W, 1, R, 0xD0),
        ],
    )
    .await;

    let recips = store
        .list_recipients(FILE, OWNER)
        .await
        .unwrap()
        .expect("owner may list recipients");
    // Three user recipients (owner, R, W); recovery is excluded.
    assert_eq!(recips.len(), 3);
    assert!(recips.iter().all(|r| r.recipient_id != RECOVERY_ID.0));

    // W's entry carries the ancestor chain [R's grant]; R's is author-rooted.
    let w = recips.iter().find(|r| r.recipient_id == W).unwrap();
    assert_eq!(w.grant_bytes, vec![0xD0; 8]);
    assert_eq!(w.ancestor_grants, vec![(vec![0xB0; 8], [0xB0; 64])]);
    let r = recips.iter().find(|x| x.recipient_id == R).unwrap();
    assert!(r.ancestor_grants.is_empty());
}

#[tokio::test]
async fn non_owner_listing_recipients_is_indistinguishable_404() {
    let store = MemoryStore::new();
    finalized_v1(
        &store,
        vec![wrap(OWNER, 1, OWNER, 0xA0), wrap(RECOVERY_ID.0, 2, OWNER, 0x5E)],
    )
    .await;
    // A non-owner (even a recipient) cannot enumerate recipients — None (404).
    store
        .add_wrap(FILE, wrap(V, 1, OWNER, 0xC0), OWNER, 2000)
        .await
        .unwrap();
    assert!(store.list_recipients(FILE, V).await.unwrap().is_none());
    assert!(store.list_recipients(FILE, STRANGER).await.unwrap().is_none());
}
