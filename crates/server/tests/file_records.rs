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
    parse_stage, FinalizeError, GenesisInput, ListFilter, ListSort, MemoryStore, StageError,
    StageInput, Store, VersionSelector, WrapInput,
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
    assert!(
        store
            .get_file(FILE, VersionSelector::Latest, OWNER)
            .await
            .unwrap()
            .is_none(),
        "staged version must not be visible"
    );

    // Finalize v1 → now visible to the owner with its wrap + genesis + streams.
    store.finalize_version(FILE, 1, OWNER, 1001).await.unwrap();
    let view = store
        .get_file(FILE, VersionSelector::Latest, OWNER)
        .await
        .unwrap()
        .expect("finalized v1 is visible");
    assert_eq!(view.version, 1);
    assert_eq!(
        view.manifest_bytes,
        manifest_bytes(FILE, 1, OWNER, FileType::Blog)
    );
    assert_eq!(view.my_wrap.wrapped_dek, vec![0xA1; 48]);
    assert!(
        view.recovery_grant.is_some(),
        "recovery grant served for presence check"
    );
    assert_eq!(view.streams.len(), 2);

    // Stage + finalize v2 (rotation, no genesis) — strict +1.
    let parsed2 = parse_stage(stage_input(FILE, 2, OWNER, None, FileType::Blog)).unwrap();
    assert_eq!(store.stage_version(parsed2, 2000).await.unwrap(), 2);
    // v1 is still the visible version until v2 finalizes.
    assert_eq!(
        store
            .get_file(FILE, VersionSelector::Latest, OWNER)
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    store.finalize_version(FILE, 2, OWNER, 2001).await.unwrap();
    assert_eq!(
        store
            .get_file(FILE, VersionSelector::Latest, OWNER)
            .await
            .unwrap()
            .unwrap()
            .version,
        2
    );
    // The prior version's wraps were torn down (api.md §8.4): v1 no longer serves.
    assert!(
        store
            .get_file(FILE, VersionSelector::Specific(1), OWNER)
            .await
            .unwrap()
            .is_none(),
        "prior version's wraps deleted on finalize"
    );
}

#[tokio::test]
async fn finalize_enforces_strict_plus_one() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(
        FILE,
        1,
        OWNER,
        Some(genesis_input(FILE, OWNER)),
        FileType::Blog,
    ))
    .unwrap();
    store.stage_version(p1, 1).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 2).await.unwrap();

    // Stage v3 (skipping v2) then try to finalize it: current is 1, expected 2.
    let p3 = parse_stage(stage_input(FILE, 3, OWNER, None, FileType::Blog)).unwrap();
    store.stage_version(p3, 3).await.unwrap();
    assert_eq!(
        store.finalize_version(FILE, 3, OWNER, 4).await,
        Err(FinalizeError::VersionConflict {
            expected: 2,
            got: 3
        })
    );
}

#[tokio::test]
async fn rotation_by_non_owner_is_rejected() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(
        FILE,
        1,
        OWNER,
        Some(genesis_input(FILE, OWNER)),
        FileType::Blog,
    ))
    .unwrap();
    store.stage_version(p1, 1).await.unwrap();
    store.finalize_version(FILE, 1, OWNER, 2).await.unwrap();

    // A stranger authors v2 of someone else's file (author == caller passes the
    // pure parse, but the store's caller==owner check rejects it, D29).
    let attacker = parse_stage(stage_input(FILE, 2, STRANGER, None, FileType::Blog)).unwrap();
    assert_eq!(
        store.stage_version(attacker, 3).await,
        Err(StageError::NotOwner)
    );
}

#[tokio::test]
async fn non_recipient_get_is_indistinguishable_404() {
    let store = MemoryStore::new();
    let p1 = parse_stage(stage_input(
        FILE,
        1,
        OWNER,
        Some(genesis_input(FILE, OWNER)),
        FileType::Blog,
    ))
    .unwrap();
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
    let pb = parse_stage(stage_input(
        blog,
        1,
        OWNER,
        Some(genesis_input(blog, OWNER)),
        FileType::Blog,
    ))
    .unwrap();
    store.stage_version(pb, 10).await.unwrap();
    store.finalize_version(blog, 1, OWNER, 100).await.unwrap();
    let pv = parse_stage(stage_input(
        video,
        1,
        OWNER,
        Some(genesis_input(video, OWNER)),
        FileType::Video,
    ))
    .unwrap();
    store.stage_version(pv, 20).await.unwrap();
    store.finalize_version(video, 1, OWNER, 200).await.unwrap();

    // All files, newest (video) first.
    let all = store
        .list_files(ListFilter {
            limit: 10,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(all.entries.len(), 2);
    assert_eq!(all.entries[0].file_id, video);
    assert_eq!(all.total, 2, "`total` ignores limit/offset");
    // Small streams exclude content (stream_type 1); metadata (2) is listed.
    assert!(all.entries[0].small_streams.iter().all(|(t, _)| *t != 1));
    assert!(all.entries[0].small_streams.iter().any(|(t, _)| *t == 2));

    // Filter to blogs only.
    let blogs = store
        .list_files(ListFilter {
            file_type: Some(FileType::Blog as u8 as i16),
            limit: 10,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(blogs.entries.len(), 1);
    assert_eq!(blogs.entries[0].file_id, blog);
    assert_eq!(blogs.total, 1, "`total` is filtered by type too");
}

// ---- F3a: the MemoryStore half of the listing contract ----
//
// MemoryStore is not a toy here: it backs the ephemeral demo server and the
// whole client e2e suite, so a divergence from PgStore is a real behaviour
// change between two shipped configurations. These mirror the Postgres tests in
// `pg_store.rs` one-for-one.

/// Stage v1 of `file` owned by `owner` and finalize it at `at_ms`, so the
/// listing's sort key (`updated_at_ms`) is exactly `at_ms`.
async fn seed_listed(
    store: &MemoryStore,
    file: [u8; 16],
    owner: [u8; 16],
    ftype: FileType,
    at_ms: u64,
) {
    let p = parse_stage(stage_input(
        file,
        1,
        owner,
        Some(genesis_input(file, owner)),
        ftype,
    ))
    .unwrap();
    store.stage_version(p, at_ms).await.unwrap();
    store.finalize_version(file, 1, owner, at_ms).await.unwrap();
}

/// A user-type wrap for `recipient` granted by `granter` (the coarse `add_wrap`
/// gate requires `granted_by == caller_id`).
fn user_wrap(recipient: [u8; 16], granter: [u8; 16]) -> WrapInput {
    WrapInput {
        recipient_id: recipient,
        recipient_type: 1,
        wrapped_dek: vec![0xA3; 48],
        wrap_alg: 1,
        granted_by: granter,
        grant_bytes: vec![0xB3; 8],
        grant_sig: [0xC3; 64],
    }
}

/// Paging, `sort` and `owner_only` over `MemoryStore` — the same assertions the
/// Postgres suite makes, so the two backends cannot drift.
#[tokio::test]
async fn listing_pages_sorts_and_filters_by_owner_in_memory() {
    let store = MemoryStore::new();
    let other = [0x22u8; 16];

    // Five own files at strictly increasing times, plus one owned by someone
    // else and re-shared to OWNER.
    let mine: Vec<[u8; 16]> = (0..5u8).map(|i| [0xA0 + i; 16]).collect();
    for (i, id) in mine.iter().enumerate() {
        seed_listed(&store, *id, OWNER, FileType::Blog, 100 + (i as u64) * 10).await;
    }
    let foreign = [0xEEu8; 16];
    seed_listed(&store, foreign, other, FileType::Blog, 50).await;
    store
        .add_wrap(foreign, user_wrap(OWNER, other), other, 60)
        .await
        .unwrap();

    let newest_all: Vec<[u8; 16]> = vec![mine[4], mine[3], mine[2], mine[1], mine[0], foreign];

    // Three pages of 2 PARTITION the set — no duplicate, no gap — and `total` is
    // the whole set regardless of the window.
    let mut walked: Vec<[u8; 16]> = Vec::new();
    for off in [0u64, 2, 4] {
        let p = store
            .list_files(ListFilter {
                limit: 2,
                offset: off,
                ..ListFilter::for_caller(OWNER)
            })
            .await
            .unwrap();
        assert_eq!(p.total, 6, "`total` ignores limit/offset");
        walked.extend(p.entries.iter().map(|e| e.file_id));
    }
    assert_eq!(walked, newest_all);

    // An offset past the end is an empty page, not an error.
    let past = store
        .list_files(ListFilter {
            limit: 2,
            offset: 999,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert!(past.entries.is_empty());
    assert_eq!(past.total, 6);

    // `oldest` is the exact reverse of `newest`.
    let oldest = store
        .list_files(ListFilter {
            limit: 50,
            sort: ListSort::Oldest,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    let mut reversed = newest_all.clone();
    reversed.reverse();
    assert_eq!(
        oldest.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        reversed
    );
    assert_eq!(oldest.total, 6, "`total` is sort-independent");

    // `owner_only` = "My Content": the file shared TO me is not a file I own,
    // and `total` shrinks with the page.
    let owned = store
        .list_files(ListFilter {
            limit: 50,
            owner_only: true,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(owned.total, 5);
    assert_eq!(owned.entries.len(), 5);
    assert!(owned.entries.iter().all(|e| e.file_id != foreign));
}

/// The `file_id` tiebreak is what makes the order TOTAL. Without it, two files
/// finalized in the same millisecond order arbitrarily, and an OFFSET walk over
/// an arbitrary order can repeat one row and silently drop another — the entry
/// the user never sees is the failure mode that matters.
#[tokio::test]
async fn listing_order_is_total_when_timestamps_tie_in_memory() {
    let store = MemoryStore::new();
    let a = [0xA1u8; 16];
    let b = [0xB2u8; 16];
    let c = [0xC3u8; 16];
    for id in [c, a, b] {
        seed_listed(&store, id, OWNER, FileType::Blog, 500).await; // SAME ms
    }

    // Newest-first with an all-equal sort key ⇒ file_id ASC.
    let all = store
        .list_files(ListFilter {
            limit: 50,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(
        all.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        vec![a, b, c]
    );

    // …and paging over the tie still partitions.
    let mut walked: Vec<[u8; 16]> = Vec::new();
    for off in [0u64, 2] {
        let p = store
            .list_files(ListFilter {
                limit: 2,
                offset: off,
                ..ListFilter::for_caller(OWNER)
            })
            .await
            .unwrap();
        walked.extend(p.entries.iter().map(|e| e.file_id));
    }
    assert_eq!(
        walked,
        vec![a, b, c],
        "no duplicate and no gap across a tie"
    );

    // `file_id` is the ASC tiebreak in BOTH directions, so under a full tie
    // `oldest` is NOT the reverse of `newest` — it is identical. Asserted rather
    // than claimed, because the docs say "reverse … only up to ties".
    let oldest = store
        .list_files(ListFilter {
            limit: 50,
            sort: ListSort::Oldest,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(
        oldest.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        vec![a, b, c]
    );
}

/// The MemoryStore mirror of the Postgres re-share-mid-walk test: `updated_at`
/// is MUTABLE (`add_wrap` bumps it), so an OFFSET walk is not skip-free. Asserts
/// what actually happens rather than a stability the implementation does not have.
#[tokio::test]
async fn a_reshare_mid_walk_can_repeat_and_skip_a_page_entry_in_memory() {
    let store = MemoryStore::new();
    let bob = [0x22u8; 16];
    let f: Vec<[u8; 16]> = (1..=4u8).map(|i| [0xC0 + i; 16]).collect();
    for (i, id) in f.iter().enumerate() {
        seed_listed(&store, *id, OWNER, FileType::Blog, 100 + (i as u64) * 10).await;
    }

    let page1 = store
        .list_files(ListFilter {
            limit: 2,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    assert_eq!(
        page1.entries.iter().map(|e| e.file_id).collect::<Vec<_>>(),
        vec![f[3], f[2]]
    );

    // A re-share of the OLDEST file lands while the reader is on page 1.
    store
        .add_wrap(f[0], user_wrap(bob, OWNER), OWNER, 500)
        .await
        .unwrap();

    let page2 = store
        .list_files(ListFilter {
            limit: 2,
            offset: 2,
            ..ListFilter::for_caller(OWNER)
        })
        .await
        .unwrap();
    let seen: Vec<[u8; 16]> = page1
        .entries
        .iter()
        .chain(page2.entries.iter())
        .map(|e| e.file_id)
        .collect();
    assert_eq!(
        seen.iter().filter(|id| **id == f[2]).count(),
        2,
        "the re-share slid f3 from page 1 into page 2 — the reader sees it TWICE"
    );
    assert!(
        !seen.contains(&f[0]),
        "f1 jumped above the reader — it is MISSED. Accepted: sorting by the \
         immutable created_at instead would hide a re-shared file from the \
         recipient's feed entirely."
    );
}
