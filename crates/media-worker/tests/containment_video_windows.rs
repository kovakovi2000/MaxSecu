//! Windows AppContainer + Job Object **video-session** containment tests
//! (DESIGN §8.1/D30, media-sandbox §6 exit gate; MaxSecu Media App Phase 7,
//! Task 3.4). The persistent **duplex** session is the largest decode surface,
//! so it gets its own containment differential on top of the single-image
//! `containment_windows.rs`.
//!
//! Two properties are proven, mirroring the single-image suite:
//! * **Functional under confinement** — the AppContainer worker, driven over the
//!   duplex framed pipe, decodes a full `Open + 3 Fragments + Close` script to the
//!   SAME result as the in-process / cross-platform session (Ready + 3 validated
//!   64×48 frames + `EndOfFragment{0,1,2}`).
//! * **Confinement bites, mid-session** — a worker run with a late-lifetime probe
//!   (`--selftest-net-late` / `--selftest-spawn-late`, which first decode a real
//!   fragment so the worker is genuinely mid-session) or a key-blob read probe
//!   (`--selftest-read`) is DENIED inside the AppContainer + Job Object (verdict
//!   `0`), while the SAME worker + args run unconfined is ALLOWED (verdict `1`) —
//!   so the AppContainer is what blocks it, not a general inability.
#![cfg(windows)]

#[path = "support/mod.rs"]
mod support;

use maxsecu_client_core::video::{validate_i420, ClientMsg, VideoBounds, WorkerMsg};
use maxsecu_media_worker::{AppContainerVideoSession, SubprocessDecoder, VideoSessionDecoder};

use std::net::TcpListener;
use std::thread;

use support::make_canonical_clip;

/// Absolute path to the built worker binary (cargo provides this for the bin
/// target named `media-worker`).
const WORKER: &str = env!("CARGO_BIN_EXE_media-worker");

/// One independently-decodable closed-GOP fragment, to make the late-lifetime
/// probe worker genuinely decode something before it probes net / spawn.
fn one_fragment() -> Vec<u8> {
    make_canonical_clip(64, 48, 1, false)
        .fragments
        .into_iter()
        .next()
        .expect("a 1-frame clip has exactly one fragment")
}

#[test]
fn appcontainer_session_decodes_three_fragments() {
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

    // The duplex driver streams the script while reading WorkerMsgs concurrently,
    // all under the AppContainer + Job Object confinement.
    let out = AppContainerVideoSession::new(WORKER)
        .run_session(&script)
        .expect("confined framed worker session exchange");

    assert_eq!(
        out.first(),
        Some(&WorkerMsg::Ready),
        "the confined session must open with exactly one Ready"
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
                    "decoded dims across the confined process boundary"
                );
                // The worker validates before emitting; assert independently here
                // too (no unvalidated frame ever escapes the confined worker).
                validate_i420(f, &bounds).expect("emitted frame must validate");
                videos += 1;
            }
            WorkerMsg::EndOfFragment { seq } => eofs.push(*seq),
            other => panic!("unexpected worker message: {other:?}"),
        }
    }

    // Same result as the in-process / cross-platform session, under confinement.
    assert_eq!(
        videos, 3,
        "exactly 3 validated video frames via the confined session"
    );
    assert_eq!(
        eofs,
        vec![0, 1, 2],
        "one EndOfFragment per fragment, in order"
    );
}

#[test]
fn appcontainer_session_blocks_network_late_while_unconfined_allows() {
    // A loopback listener the worker will try to reach (offline, deterministic).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        if listener.accept().is_err() {
            break;
        }
    });
    let ports = port.to_string();
    let args = ["--selftest-net-late", ports.as_str()];

    // Sanity: the same worker unconfined decodes its fragment then DOES reach
    // loopback (a late-lifetime probe still succeeds without confinement).
    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    assert!(
        unconfined,
        "unconfined worker should reach loopback mid-session (test sanity)"
    );

    // The containment gate: the AppContainer worker, fed one framed fragment and
    // genuinely mid-session, still cannot reach the network.
    let frag = one_fragment();
    let confined = AppContainerVideoSession::new(WORKER)
        .selftest_with_fragment(&args, &frag)
        .expect("spawn confined session worker");
    assert!(
        !confined,
        "AppContainer worker reached the network mid-session — confinement FAILED"
    );
}

#[test]
fn appcontainer_duplex_session_blocks_network_late_while_unconfined_allows() {
    // Same denial as the test above, but driven through the NEW duplex
    // `spawn_confined_session` launcher (a writer thread streams one framed
    // fragment while the parent reads the verdict) — proving confinement over the
    // duplex path directly, not just via the shared `setup_confined_child`.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        if listener.accept().is_err() {
            break;
        }
    });
    let ports = port.to_string();
    let args = ["--selftest-net-late", ports.as_str()];

    // Sanity: the same worker + args unconfined reaches loopback mid-session.
    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    assert!(
        unconfined,
        "unconfined worker should reach loopback mid-session (test sanity)"
    );

    // The duplex launcher confines exactly as the serial one does.
    let frag = one_fragment();
    let confined = AppContainerVideoSession::new(WORKER)
        .selftest_duplex(&args, &frag)
        .expect("spawn confined duplex session worker");
    assert!(
        !confined,
        "duplex AppContainer launcher reached the network mid-session — confinement FAILED"
    );
}

#[test]
fn appcontainer_session_blocks_child_spawn_late_while_unconfined_allows() {
    let args = ["--selftest-spawn-late"];

    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    assert!(
        unconfined,
        "unconfined worker can spawn a child mid-session (test sanity)"
    );

    let frag = one_fragment();
    let confined = AppContainerVideoSession::new(WORKER)
        .selftest_with_fragment(&args, &frag)
        .expect("spawn confined session worker");
    assert!(
        !confined,
        "Job Object (active-process=1) must block child spawn mid-session"
    );
}

#[test]
fn appcontainer_session_blocks_reading_the_key_blob_while_unconfined_allows() {
    // A stand-in for the user's `local_key_blob`: a file in the user profile that
    // does not grant access to app packages.
    let mut path = std::env::temp_dir();
    path.push(format!("maxsecu_secret_session_{}.bin", std::process::id()));
    std::fs::write(&path, b"PRETEND-KEY-MATERIAL").unwrap();
    let p = path.to_string_lossy().to_string();
    let args = ["--selftest-read", p.as_str()];

    let unconfined = SubprocessDecoder::new(WORKER).selftest(&args).unwrap();
    let frag = one_fragment();
    let confined = AppContainerVideoSession::new(WORKER)
        .selftest_with_fragment(&args, &frag)
        .expect("spawn confined session worker");
    let _ = std::fs::remove_file(&path);

    assert!(
        unconfined,
        "unconfined worker can read the user file (test sanity)"
    );
    assert!(
        !confined,
        "AppContainer worker read the user's key blob — confinement FAILED"
    );
}
