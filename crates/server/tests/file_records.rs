//! File-records lifecycle over the in-memory [`Store`] (api.md §8, Phase 3 P3.6).
//!
//! Drives the public store API exactly as the HTTP handlers will: stage → (not
//! visible) → finalize (strict +1) → get (caller's wrap only) → rotate → list.
//! Proves the two-phase visibility, the serialize-on-`(file_id, version)` +1
//! gate, prior-version wrap teardown, the coarse owner check, and the no-oracle
//! 404 for a non-recipient — all without TLS/DB.

use maxsecu_encoding::structs::{Genesis, Manifest, Stream};
use maxsecu_encoding::types::{Bytes32, Compression, FileType, Id, StreamType, Suite, Timestamp};
use maxsecu_encoding::{encode, RECOVERY_ID};
use maxsecu_server::{
    parse_stage, FinalizeError, GenesisInput, ListFilter, MemoryStore, StageError, StageInput,
    Store, VersionSelector, WrapInput,
};

const OWNER: [u8; 16] = [0x11; 16];
const STRANGER: [u8; 16] = [0x77; 16];
const FILE: [u8; 16] = [0xF1; 16];

fn manifest_bytes(file: [u8; 16], version: u64, author: [u8; 16], ftype: FileType) -> Vec<u8> {
    let m = Manifest {
        file_id: Id(file),
        version,
        file_type: ftype,
        alg: Suite::V1,
        chunk_size: 1 << 20,
        dek_commit: Bytes32([0xDC; 32]),
        streams: vec![
            Stream {
                stream_type: StreamType::Content,
                compression: Compression::None,
                chunk_count: 2,
                digest: Bytes32([0xC0; 32]),
            },
            Stream {
                stream_type: StreamType::Metadata,
                compression: Compression::None,
                chunk_count: 1,
                digest: Bytes32([0x2E; 32]),
            },
        ],
        recovery_present: true,
        author_id: Id(author),
        created_at: Timestamp(1_719_500_000_000 + version),
    };
    encode(&m)
}

fn genesis_input(file: [u8; 16], owner: [u8; 16]) -> GenesisInput {
    GenesisInput {
        genesis_bytes: encode(&Genesis {
            file_id: Id(file),
            owner_id: Id(owner),
            owner_key_version: 1,
            created_at: Timestamp(1_719_500_000_000),
        }),
        genesis_sig: [0x9A; 64],
    }
}

fn wraps(owner: [u8; 16]) -> Vec<WrapInput> {
    vec![
        WrapInput {
            recipient_id: owner,
            recipient_type: 1,
            wrapped_dek: vec![0xA1; 48],
            wrap_alg: 1,
            granted_by: owner,
            grant_bytes: vec![0xB1; 8],
            grant_sig: [0xC1; 64],
        },
        WrapInput {
            recipient_id: RECOVERY_ID.0,
            recipient_type: 2,
            wrapped_dek: vec![0xA2; 48],
            wrap_alg: 1,
            granted_by: owner,
            grant_bytes: vec![0xB2; 8],
            grant_sig: [0xC2; 64],
        },
    ]
}

fn stage_input(
    file: [u8; 16],
    version: u64,
    owner: [u8; 16],
    genesis: Option<GenesisInput>,
    ftype: FileType,
) -> StageInput {
    StageInput {
        file_id: file,
        caller_id: owner,
        file_type_advisory: ftype as u8 as i16,
        genesis,
        manifest_bytes: manifest_bytes(file, version, owner, ftype),
        manifest_sig: [0x9B; 64],
        wraps: wraps(owner),
        stream_totals: vec![(1, 2_000_000), (2, 256)],
        proposed_version: version,
        listed: true,
        bundle_id: None,
    }
}

#[tokio::test]
async fn two_phase_upload_then_rotate_lifecycle() {
    let store = MemoryStore::new();

    // Stage v1 — not visible until finalize.
    let parsed = parse_stage(stage_input(
        FILE,
        1,
        OWNER,
        Some(genesis_input(FILE, OWNER)),
        FileType::Blog,
    ))
    .unwrap();
    assert_eq!(store.stage_version(parsed, 1000).await.unwrap(), 1);
    assert!(store
        .get_file(FILE, VersionSelector::Latest, OWNER)
        .await
        .unwrap()
        .is_none(), "staged version must not be visible");

    // Finalize v1 → now visible to the owner with its wrap + genesis + streams.
    store.finalize_version(FILE, 1, OWNER, 1001).await.unwrap();
    let view = store
        .get_file(FILE, VersionSelector::Latest, OWNER)
        .await
        .unwrap()
        .expect("finalized v1 is visible");
    assert_eq!(view.version, 1);
    assert_eq!(view.manifest_bytes, manifest_bytes(FILE, 1, OWNER, FileType::Blog));
    assert_eq!(view.my_wrap.wrapped_dek, vec![0xA1; 48]);
    assert!(view.recovery_grant.is_some(), "recovery grant served for presence check");
    assert_eq!(view.streams.len(), 2);

    // Stage + finalize v2 (rotation, no genesis) — strict +1.
    let parsed2 = parse_stage(stage_input(FILE, 2, OWNER, None, FileType::Blog)).unwrap();
    assert_eq!(store.stage_version(parsed2, 2000).await.unwrap(), 2);
    // v1 is still the visible version until v2 finalizes.
    assert_eq!(
        store.get_file(FILE, VersionSelector::Latest, OWNER).await.unwrap().unwrap().version,
        1
    );
    store.finalize_version(FILE, 2, OWNER, 2001).await.unwrap();
    assert_eq!(
        store.get_file(FILE, VersionSelector::Latest, OWNER).await.unwrap().unwrap().version,
        2
    );
    // The prior version's wraps were torn down (api.md §8.4): v1 no longer serves.
    assert!(store
        .get_file(FILE, VersionSelector::Specific(1), OWNER)
        .await
        .unwrap()
        .is_none(), "prior version's wraps deleted on finalize");
}

#[tokio::test]
async fn finalize_enforces_strict_plus_one() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(FILE, 1, OWNER, Some(genesis_input(FILE, OWNER)), FileType::Blog)).unwrap();
    store.stage_version(p1, 1).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 2).await.unwrap();

    // Stage v3 (skipping v2) then try to finalize it: current is 1, expected 2.
    let p3 = parse_stage(stage_input(FILE, 3, OWNER, None, FileType::Blog)).unwrap();
    store.stage_version(p3, 3).await.unwrap();
    assert_eq!(
        store.finalize_version(FILE, 3, OWNER, 4).await,
        Err(FinalizeError::VersionConflict { expected: 2, got: 3 })
    );
}

#[tokio::test]
async fn rotation_by_non_owner_is_rejected() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(FILE, 1, OWNER, Some(genesis_input(FILE, OWNER)), FileType::Blog)).unwrap();
    store.stage_version(p1, 1).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 2).await.unwrap();

    // A stranger authors v2 of someone else's file (author == caller passes the
    // pure parse, but the store's caller==owner check rejects it, D29).
    let attacker = parse_stage(stage_input(FILE, 2, STRANGER, None, FileType::Blog)).unwrap();
    assert_eq!(store.stage_version(attacker, 3).await, Err(StageError::NotOwner));
}

#[tokio::test]
async fn non_recipient_get_is_indistinguishable_404() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(FILE, 1, OWNER, Some(genesis_input(FILE, OWNER)), FileType::Blog)).unwrap();
    store.stage_version(p1, 1).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 2).await.unwrap();

    // A user with no wrap row gets None — same as a missing file (no oracle).
    assert!(store
        .get_file(FILE, VersionSelector::Latest, STRANGER)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn listing_filters_by_type_newest_first() {
    let store = MemoryStore::new();
    // A blog and a video, finalized at increasing times.
    let blog = [0xB1; 16];
    let video = [0x71; 16];
    let pb = parse_stage(stage_input(blog, 1, OWNER, Some(genesis_input(blog, OWNER)), FileType::Blog)).unwrap();
    store.stage_version(pb, 10).await.unwrap();
    store.finalize_version(blog, 1, OWNER, 100).await.unwrap();
    let pv = parse_stage(stage_input(video, 1, OWNER, Some(genesis_input(video, OWNER)), FileType::Video)).unwrap();
    store.stage_version(pv, 20).await.unwrap();
    store.finalize_version(video, 1, OWNER, 200).await.unwrap();

    // All files, newest (video) first.
    let all = store.list_files(ListFilter { file_type: None, limit: 10 }).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].file_id, video);
    // Small streams exclude content (stream_type 1); metadata (2) is listed.
    assert!(all[0].small_streams.iter().all(|(t, _)| *t != 1));
    assert!(all[0].small_streams.iter().any(|(t, _)| *t == 2));

    // Filter to blogs only.
    let blogs = store.list_files(ListFilter { file_type: Some(FileType::Blog as u8 as i16), limit: 10 }).await.unwrap();
    assert_eq!(blogs.len(), 1);
    assert_eq!(blogs[0].file_id, blog);
}
