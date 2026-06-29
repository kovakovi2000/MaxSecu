//! Cross-platform end-to-end test for the persistent video-decode **session**
//! over the real worker binary (`--video-session`, MaxSecu Media App Phase 7,
//! Task 3.3).
//!
//! Spawns the `media-worker` binary, ships `Open` + N framed `Fragment`s +
//! `Close` over its stdin, and reads the framed `WorkerMsg` stream back from its
//! stdout — asserting the SAME result as the in-process [`VideoSession`]
//! (`video_session.rs`), but across a real process boundary (separate address
//! space). The rav1d decode (CF-2: needs a 64 MiB stack) runs inside the worker,
//! so this parent thread only encodes the fixtures (rav1e, default stack — see
//! `fixture_smoke.rs`).
//!
//! Deadlock-free by construction: [`VideoSubprocessSession::run`] writes all
//! framed `ClientMsg`s on a writer thread while this thread reads framed
//! `WorkerMsg`s concurrently, so neither pipe direction can fill and stall.

#[path = "support/mod.rs"]
mod support;

use maxsecu_client_core::video::{validate_i420, ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::VideoSubprocessSession;

use support::make_canonical_clip;

/// Absolute path to the built worker binary (cargo provides this for the bin
/// target named `media-worker`).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

#[test]
fn subprocess_session_decodes_three_fragments() {
    let clip = make_canonical_clip(64, 48, 3, false);
    let bounds = VideoBounds::default();

    // The full session script: Open, three fragments, Close.
    let mut script = vec![ClientMsg::Open { bounds }];
    for (i, frag) in clip.fragments.iter().enumerate() {
        script.push(ClientMsg::Fragment {
            seq: i as u32,
            bytes: frag.clone(),
        });
    }
    script.push(ClientMsg::Close);

    let out = VideoSubprocessSession::new(WORKER)
        .run(script)
        .expect("framed worker session exchange");

    assert_eq!(
        out.first(),
        Some(&WorkerMsg::Ready),
        "the session must open with exactly one Ready"
    );

    let mut videos = 0usize;
    let mut eofs: Vec<u32> = Vec::new();
    for m in &out {
        match m {
            WorkerMsg::Ready => {}
            WorkerMsg::Video(f) => {
                assert_eq!(
                    (f.width, f.height),
                    (64, 48),
                    "decoded dims across the process boundary"
                );
                // The worker validates before emitting; this must hold independently
                // here too (no unvalidated frame ever escapes the worker).
                validate_i420(f, &bounds).expect("emitted frame must validate");
                videos += 1;
            }
            WorkerMsg::EndOfFragment { seq } => eofs.push(*seq),
            other => panic!("unexpected worker message: {other:?}"),
        }
    }

    // Same result as the in-process session, across a real process boundary.
    assert_eq!(
        videos, 3,
        "exactly 3 validated video frames via the subprocess session"
    );
    assert_eq!(
        eofs,
        vec![0, 1, 2],
        "one EndOfFragment per fragment, in order"
    );
}
