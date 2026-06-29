//! Gate-3.1 smoke test for the canonical-clip fixture generator.
//!
//! Proves the test-support [`support::make_canonical_clip`] helper emits at least
//! one **independently-decodable** closed-GOP CMAF fragment: each fragment is a
//! self-contained tiny MP4 that `symphonia` (isomp4) demuxes and `rav1d` decodes
//! back to the source geometry. This is the known-good input the session-decode
//! tasks (3.2+) build on.

mod support;

/// `make_canonical_clip` must produce ≥1 fragment, each of which round-trips:
/// symphonia demuxes the `av01` sample, rav1d decodes it to the requested dims.
#[test]
fn canonical_clip_fragment_demuxes_and_decodes() {
    let clip = support::make_canonical_clip(64, 48, 1, false);

    assert_eq!(clip.width, 64);
    assert_eq!(clip.height, 48);
    assert!(
        !clip.has_audio,
        "with_audio=false must yield a video-only clip"
    );
    assert!(
        !clip.fragments.is_empty(),
        "must emit at least one independently-decodable fragment"
    );

    // Take the FIRST fragment and round-trip it on its own (independent decode).
    let fragment = &clip.fragments[0];

    // 1) symphonia (isomp4) demuxes the self-contained MP4 → raw AV1 sample + dims.
    let (sample, demux_w, demux_h) = support::demux_first_video_sample(fragment.clone());
    assert_eq!(
        (demux_w, demux_h),
        (64, 48),
        "symphonia must read the av01 visual-sample-entry geometry"
    );

    // 2) rav1d decodes that sample (on an enlarged-stack worker thread, CF-2) and
    //    the decoded picture geometry must match the source.
    let (dec_w, dec_h) =
        support::decode_av1_dims(&sample).expect("rav1d must decode the demuxed AV1 sample");
    assert_eq!(
        (dec_w, dec_h),
        (64, 48),
        "rav1d-decoded dimensions must equal the source dimensions"
    );
}

/// A multi-frame clip yields one independently-decodable fragment per frame, and
/// EACH fragment round-trips on its own (the "resume from fragment K" model).
#[test]
fn each_fragment_is_independently_decodable() {
    let frames = 3u32;
    let clip = support::make_canonical_clip(48, 32, frames, false);
    assert_eq!(clip.fragments.len(), frames as usize);

    for (k, fragment) in clip.fragments.iter().enumerate() {
        let (sample, w, h) = support::demux_first_video_sample(fragment.clone());
        assert_eq!((w, h), (48, 32), "fragment {k}: demux geometry");
        let (dw, dh) =
            support::decode_av1_dims(&sample).unwrap_or_else(|| panic!("fragment {k}: decode"));
        assert_eq!((dw, dh), (48, 32), "fragment {k}: decoded geometry");
    }
}
