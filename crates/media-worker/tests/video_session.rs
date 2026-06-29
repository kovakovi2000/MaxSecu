//! Integration test for the **in-process persistent video decode session**
//! (MaxSecu Media App Phase 7, Task 3.2).
//!
//! Drives a [`VideoSession`] over the `client-core` `ClientMsg`/`WorkerMsg` seam
//! with the canonical-clip fixtures from Task 3.1 (each fragment is one
//! independently-decodable closed-GOP MP4 carrying one AV1 keyframe). Asserts the
//! session demuxes + decodes each fragment to a validated I420 frame and resumes
//! cleanly after a `Seek`.
//!
//! CF-2: rav1d's single-threaded decode overflows Windows' default 1 MiB
//! main-thread stack, so the WHOLE session is driven on a 64 MiB-stack worker
//! thread (the Task-3.3 worker `main` does the same).

#[path = "support/mod.rs"]
mod support;

use maxsecu_client_core::video::{validate_i420, ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::VideoSession;

use support::make_canonical_clip;

/// Run `f` on a 64 MiB-stack thread (CF-2). The session's deep rav1d call frames
/// would overflow the default thread stack on Windows otherwise.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(f)
        .expect("spawn 64 MiB decode thread")
        .join()
        .expect("decode thread panicked")
}

#[test]
fn decodes_three_fragments_to_validated_i420() {
    let (videos, eofs) = on_big_stack(|| {
        let clip = make_canonical_clip(64, 48, 3, false);
        let bounds = VideoBounds::default();
        let mut session = VideoSession::new();

        assert_eq!(
            session.feed(ClientMsg::Open { bounds }),
            vec![WorkerMsg::Ready],
            "Open must yield exactly Ready"
        );

        let mut videos = 0usize;
        let mut eofs: Vec<u32> = Vec::new();
        for (i, frag) in clip.fragments.iter().enumerate() {
            let msgs = session.feed(ClientMsg::Fragment {
                seq: i as u32,
                bytes: frag.clone(),
            });
            for m in msgs {
                match m {
                    WorkerMsg::Video(f) => {
                        assert_eq!((f.width, f.height), (64, 48), "decoded dims");
                        // The session validates before emitting; this must also hold
                        // independently here (no unvalidated frame ever escapes).
                        validate_i420(&f, &bounds).expect("emitted frame must validate");
                        videos += 1;
                    }
                    WorkerMsg::EndOfFragment { seq } => eofs.push(seq),
                    other => panic!("unexpected message: {other:?}"),
                }
            }
        }
        assert!(
            session.feed(ClientMsg::Close).is_empty(),
            "Close emits nothing"
        );
        (videos, eofs)
    });

    assert_eq!(videos, 3, "exactly 3 validated video frames");
    assert_eq!(
        eofs,
        vec![0, 1, 2],
        "one EndOfFragment per fragment, in order"
    );
}

#[test]
fn seek_then_refeed_reemits_frame() {
    let msgs = on_big_stack(|| {
        let clip = make_canonical_clip(64, 48, 3, false);
        let bounds = VideoBounds::default();
        let mut session = VideoSession::new();

        session.feed(ClientMsg::Open { bounds });
        for (i, frag) in clip.fragments.iter().enumerate() {
            session.feed(ClientMsg::Fragment {
                seq: i as u32,
                bytes: frag.clone(),
            });
        }

        // Seek back to fragment 1 (flushes the decoder), then re-feed it.
        let seek = session.feed(ClientMsg::Seek { fragment_seq: 1 });
        assert!(seek.is_empty(), "Seek itself emits no frames");

        let msgs = session.feed(ClientMsg::Fragment {
            seq: 1,
            bytes: clip.fragments[1].clone(),
        });
        session.feed(ClientMsg::Close);
        msgs
    });

    let videos: Vec<&WorkerMsg> = msgs
        .iter()
        .filter(|m| matches!(m, WorkerMsg::Video(_)))
        .collect();
    assert_eq!(
        videos.len(),
        1,
        "re-feeding the sought fragment re-emits exactly its frame"
    );
    assert!(
        matches!(msgs.last(), Some(WorkerMsg::EndOfFragment { seq: 1 })),
        "re-fed fragment still closes with its EndOfFragment"
    );
}
