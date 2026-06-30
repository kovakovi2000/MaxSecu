//! In-process **persistent video decode session** (MaxSecu Media App Phase 7,
//! Task 3.2 / media-sandbox §3, spec §7).
//!
//! A [`VideoSession`] consumes the `client-core` `ClientMsg` stream (Open →
//! Fragment* (with optional Seek) → Close) and emits validated `WorkerMsg`s,
//! holding the rav1d decoder context **across** calls so a paused/seeked playback
//! resumes without re-spawning. Each fragment is a self-contained CMAF MP4 with one
//! AV1 keyframe (one closed GOP — independently decodable), so the session can
//! flush + resume from any fragment boundary.
//!
//! Trust boundary: the bytes fed here are **attacker-authored** (the AV1-decode
//! surface is the system's top RCE risk). Defenses, in order:
//! * the per-fragment **byte cap** (`VideoBounds::max_fragment_bytes`) is enforced
//!   BEFORE any demux/decode/alloc (media-sandbox §3);
//! * the decoder is memory-safe Rust (`rav1d`, the dav1d port) with `asm` OFF;
//! * every decoded picture is de-strided into tightly-packed I420 planes and run
//!   through `validate_i420` BEFORE it is emitted — **no unvalidated frame ever
//!   escapes** to the renderer (spec §7);
//! * Task 3.3 wraps this same session in the OS-confined worker process.
//!
//! ## CF-2 (caller contract): enlarged stack
//! rav1d's single-threaded decode (`n_threads = 1`) overflows Windows' default
//! 1 MiB main-thread stack. **The caller MUST drive this session on a thread with a
//! 64 MiB stack** (`std::thread::Builder::new().stack_size(64 << 20)`). The Task-3.3
//! worker `main` and the integration test both do so. The session does not spawn its
//! own thread — it stays a synchronous, single-threaded state machine so the
//! confined worker fully controls (and the Job Object caps) the one decode thread.
//!
//! ## `unsafe`
//! The crate denies `unsafe_code` everywhere except the audited Win32 launcher. The
//! rav1d C ABI is `pub unsafe extern "C"`, so the FFI here is inherently unsafe; it
//! is confined to the five `#[allow(unsafe_code)]` helpers below ([`VideoSession::open_ctx`],
//! [`VideoSession::close_ctx`], [`VideoSession::decode_sample`], [`extract_i420`], and
//! [`copy_plane`]), each with per-call `// SAFETY:` notes. No other `unsafe` in this module.

use std::io::Cursor;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use maxsecu_client_core::sandbox::{DecodeError, OutputReject};
use maxsecu_client_core::video::{
    validate_i420, validate_pcm, ClientMsg, I420Frame, PcmChunk, VideoBounds, WorkerMsg,
};

use symphonia::core::codecs::audio::{AudioDecoder, AudioDecoderOptions};
use symphonia::core::codecs::CodecParameters;
use symphonia::core::formats::{FormatOptions, FormatReader, TrackType};
use symphonia::core::io::{MediaSourceStream, MediaSourceStreamOptions};
use symphonia::default::codecs::AacDecoder;
use symphonia::default::formats::IsoMp4Reader;

use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::headers::DAV1D_PIXEL_LAYOUT_I420;
use rav1d::include::dav1d::picture::Dav1dPicture;
use rav1d::src::lib::{
    dav1d_close, dav1d_data_create, dav1d_data_unref, dav1d_default_settings, dav1d_get_picture,
    dav1d_open, dav1d_picture_unref, dav1d_send_data,
};

/// dav1d returns the *negated* errno; `-EAGAIN` ("drain a picture, then retry") is
/// the only non-fatal feed/drain result. `EAGAIN == 11` on every target this crate
/// builds for (Windows MSVC and Linux x86_64), matching `Rav1dError::EAGAIN`.
const DAV1D_ERR_AGAIN: i32 = -11;

/// Hard upper bound on send/drain iterations per fragment — a genuinely hostile or
/// stuck stream terminates instead of spinning forever. A canonical fragment is one
/// keyframe still, so a handful of iterations suffice; the bound is generous.
const MAX_DRAIN_ITERS: usize = 4096;

/// Decode-expansion ceiling (decode-bomb defense) for the per-fragment AUDIO path:
/// the maximum number of seconds of PCM a single fragment may decode to. The total
/// emitted i16 sample budget per fragment is then
/// `max_sample_rate * max_audio_channels * MAX_FRAGMENT_AUDIO_SECONDS` — at the
/// default bounds (48 kHz × 2ch) that is 11.52 M samples (~23 MiB) per fragment,
/// far above any real closed-GOP fragment (seconds of audio) yet a hard ceiling so
/// a small hostile fragment within `max_fragment_bytes` cannot expand into
/// unbounded PCM. `validate_pcm` deliberately does NOT magnitude-cap `samples`, so
/// this session-layer bound is the magnitude defense. Over it ⇒ fail-closed.
const MAX_FRAGMENT_AUDIO_SECONDS: u64 = 120;

/// A persistent video-decode session over the launcher↔worker seam. Holds the live
/// rav1d context + active bounds across many `feed` calls. Drive on a 64 MiB-stack
/// thread (CF-2). Holds **no keys and opens no sockets**.
pub struct VideoSession {
    /// Active pre-decode bounds (set on `Open`).
    bounds: VideoBounds,
    /// The live rav1d context (`None` before `Open` / after `Close`). `Dav1dContext`
    /// is a `Copy` opaque handle (an internally ref-counted pointer).
    ctx: Option<Dav1dContext>,
    /// Monotonic presentation timestamp (ms) stamped on emitted frames; reset on
    /// `Open`. Canonical fixtures carry one frame per fragment.
    next_pts_ms: u64,
}

impl Default for VideoSession {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoSession {
    /// A fresh session with no open decoder. `feed(Open{..})` initializes it.
    pub fn new() -> Self {
        VideoSession {
            bounds: VideoBounds::default(),
            ctx: None,
            next_pts_ms: 0,
        }
    }

    /// Feed one launcher → worker message; returns the (possibly empty) sequence of
    /// worker → launcher messages it produces. The state machine:
    /// * `Open{bounds}` — store bounds, (re)initialize the rav1d context → `[Ready]`.
    /// * `Fragment{seq,bytes}` — byte-cap check, then decode each video sample to a
    ///   validated I420 frame (`[Video..]`), then AAC-decode the audio track to
    ///   validated PCM (`[Audio..]`), then `[EndOfFragment{seq}]` LAST.
    /// * `Seek{..}` — flush (tear down + recreate the context) → `[]`.
    /// * `Close` — tear down the context → `[]`.
    pub fn feed(&mut self, msg: ClientMsg) -> Vec<WorkerMsg> {
        match msg {
            ClientMsg::Open { bounds } => {
                self.bounds = bounds;
                self.next_pts_ms = 0;
                self.open_ctx();
                vec![WorkerMsg::Ready]
            }
            ClientMsg::Fragment { seq, bytes } => self.on_fragment(seq, bytes),
            ClientMsg::Seek { .. } => {
                // Flush: tear down + recreate so NO inter-fragment decoder state
                // leaks across the seek. Each fragment is independently decodable, so
                // the next Fragment decodes cleanly from the fresh context. Restamp
                // pts from the seek target (same as Open) so post-seek frames are
                // timestamped consistently rather than continuing to climb.
                self.next_pts_ms = 0;
                self.open_ctx();
                Vec::new()
            }
            ClientMsg::Close => {
                self.close_ctx();
                Vec::new()
            }
        }
    }

    /// Handle a `Fragment`: enforce the per-fragment byte cap BEFORE any
    /// decode/alloc, then demux + decode, always closing with `EndOfFragment`.
    fn on_fragment(&mut self, seq: u32, bytes: Vec<u8>) -> Vec<WorkerMsg> {
        // (1) Bounds BEFORE decode/alloc (media-sandbox §3): an oversized fragment is
        // rejected without ever touching the demuxer. `TooLarge{0,0}` carries no
        // picture dims (none decoded yet) — it signals a fragment-byte overrun.
        if bytes.len() as u64 > self.bounds.max_fragment_bytes {
            return vec![WorkerMsg::Error(DecodeError::TooLarge {
                width: 0,
                height: 0,
            })];
        }
        if self.ctx.is_none() {
            // Fragment before Open (no decoder) — fail closed.
            return vec![
                WorkerMsg::Error(DecodeError::DecodeFailed),
                WorkerMsg::EndOfFragment { seq },
            ];
        }

        let mut out = Vec::new();
        match demux_video_samples(&bytes) {
            Some(samples) if !samples.is_empty() => {
                for sample in samples {
                    let mut msgs = self.decode_sample(&sample);
                    let had_err = msgs.iter().any(|m| matches!(m, WorkerMsg::Error(_)));
                    out.append(&mut msgs);
                    if had_err {
                        break; // stop the fragment on the first decode/validation error.
                    }
                }
            }
            // No reader / no video packet → a malformed/empty fragment.
            _ => out.push(WorkerMsg::Error(DecodeError::DecodeFailed)),
        }
        // (2b) AUDIO (R1): demux + AAC-decode the audio track to validated PCM,
        // emitted AFTER all of this fragment's video frames (the audio track is
        // independent of the video outcome above — a video-only fragment, or a
        // fragment whose video failed, simply contributes whatever audio decodes).
        // The player buffers + A/V-syncs by pts, so emit order (all-video then
        // all-audio) is fine. A fragment with no audio track contributes nothing.
        out.extend(self.decode_audio_samples(&bytes));
        // (3) Fragment boundary marker LAST, regardless of per-sample outcome.
        out.push(WorkerMsg::EndOfFragment { seq });
        out
    }

    /// Demux + AAC-LC-decode the fragment's AUDIO track (if any) to validated,
    /// interleaved-i16 [`PcmChunk`]s, in packet order. Mirrors the video path's
    /// fail-closed posture: any decode/validation failure — or a per-fragment
    /// PCM-expansion overrun — yields a single `WorkerMsg::Error` and stops; a
    /// fragment with NO audio track yields an empty `Vec` (video-only is fine).
    ///
    /// Trust boundary: these are attacker-authored audio bytes (a NEW decode
    /// surface). symphonia's `aac` decoder is pure-Rust (no `unsafe` added here);
    /// the per-fragment **byte cap** is already enforced upstream in
    /// [`Self::on_fragment`], and the **decode-expansion ceiling**
    /// ([`MAX_FRAGMENT_AUDIO_SECONDS`]) bounds total emitted PCM so a small hostile
    /// fragment cannot expand into unbounded RAM. Never panics / OOBs on hostile
    /// input — symphonia errors map to a fail-closed `WorkerMsg::Error`.
    ///
    /// A fresh `AacDecoder` is built per fragment: each canonical fragment is
    /// self-contained with its own `esds`/AudioSpecificConfig, so no cross-fragment
    /// decoder state leaks (matching the video ctx flush on `Seek`). The decoder is
    /// a plain owned value dropped at end of scope — nothing to unref.
    fn decode_audio_samples(&self, mp4: &[u8]) -> Vec<WorkerMsg> {
        // Open the demuxer. A malformed container yields no audio (the video path
        // already reported the malformed fragment). Never panics on hostile bytes.
        let mss = MediaSourceStream::new(
            Box::new(Cursor::new(mp4.to_vec())),
            MediaSourceStreamOptions::default(),
        );
        let mut reader = match IsoMp4Reader::try_new(mss, FormatOptions::default()) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        // No audio track ⇒ video-only fragment; emit nothing.
        let Some(track) = reader.first_track(TrackType::Audio) else {
            return Vec::new();
        };
        let track_id = track.id;
        let time_base = track.time_base;
        let params = match track.codec_params.as_ref() {
            Some(CodecParameters::Audio(a)) => a.clone(),
            // An audio track present but not interpretable as audio params is a
            // malformed/hostile trak → fail closed.
            _ => return vec![WorkerMsg::Error(DecodeError::DecodeFailed)],
        };
        // Fresh per-fragment decoder; construction failure ⇒ fail closed.
        let mut decoder = match AacDecoder::try_new(&params, &AudioDecoderOptions::default()) {
            Ok(d) => d,
            Err(_) => return vec![WorkerMsg::Error(DecodeError::DecodeFailed)],
        };

        // Per-fragment PCM-expansion ceiling (decode-bomb defense). Saturating so a
        // pathological bounds set can never wrap.
        let ceiling: u64 = (self.bounds.max_sample_rate as u64)
            .saturating_mul(self.bounds.max_audio_channels as u64)
            .saturating_mul(MAX_FRAGMENT_AUDIO_SECONDS);

        let mut out: Vec<WorkerMsg> = Vec::new();
        let mut total_samples: u64 = 0;
        // Fallback running pts (per-channel frames) when the track has no time_base.
        let mut running_frames: u64 = 0;

        loop {
            let pkt = match reader.next_packet() {
                Ok(Some(p)) => p,
                Ok(None) => break,  // clean end of stream.
                Err(_) => break,    // truncated/EOF → stop with what we have.
            };
            if pkt.track_id != track_id {
                continue; // a non-audio packet — skip.
            }
            // Decode one AAC packet. A hostile/malformed packet → fail closed.
            let buf = match decoder.decode(&pkt) {
                Ok(b) => b,
                Err(_) => {
                    out.push(WorkerMsg::Error(DecodeError::DecodeFailed));
                    break;
                }
            };
            let rate = buf.spec().rate();
            let ch_count = buf.spec().channels().count();
            let frames = buf.frames() as u64;

            // Real-time-ish pts: prefer the packet pts via the track time_base
            // (≈ 1/sample_rate for audio), else a per-fragment running pts derived
            // from cumulative decoded frames. Negative pts (encoder delay) → 0.
            let pts_ms = time_base
                .and_then(|tb| tb.calc_time(pkt.pts))
                .map(|t| (t.as_secs_f64() * 1000.0).max(0.0) as u64)
                .unwrap_or_else(|| {
                    if rate > 0 {
                        running_frames.saturating_mul(1000) / rate as u64
                    } else {
                        0
                    }
                });
            running_frames = running_frames.saturating_add(frames);

            // Convert to interleaved i16 (one AAC frame is bounded: ≤1024 frames ×
            // channels, so this single allocation is small regardless of input).
            let mut samples: Vec<i16> = Vec::new();
            buf.copy_to_vec_interleaved(&mut samples);
            if samples.is_empty() {
                continue; // a frame that produced no audio (e.g. priming) — skip.
            }

            // Decode-expansion bound BEFORE accepting this chunk into the stream.
            total_samples = total_samples.saturating_add(samples.len() as u64);
            if total_samples > ceiling {
                out.push(WorkerMsg::Error(DecodeError::OutputRejected {
                    reason: OutputReject::OverCap,
                }));
                break;
            }

            // An absurd channel count truncates to 0 → validate_pcm rejects it.
            let channels = u8::try_from(ch_count).unwrap_or(0);
            let chunk = PcmChunk {
                channels,
                sample_rate: rate,
                pts_ms,
                samples,
            };
            match validate_pcm(&chunk, &self.bounds) {
                Ok(()) => out.push(WorkerMsg::Audio(chunk)),
                Err(e) => {
                    out.push(WorkerMsg::Error(e));
                    break;
                }
            }
        }
        out
    }

    /// (Re)initialize the rav1d context. Tears down any existing one first so a
    /// re-Open / Seek never leaks the previous handle. On failure leaves `ctx = None`
    /// (subsequent Fragments fail closed).
    #[allow(unsafe_code)]
    fn open_ctx(&mut self) {
        self.close_ctx();
        // SAFETY: the whole sequence is the dav1d-documented open lifecycle with
        // valid, correctly-typed, non-aliasing pointers to live stack storage;
        // results are checked before the handle is stored.
        unsafe {
            // SAFETY: `settings` is uninitialized stack storage of the right type;
            // `dav1d_default_settings` fully initializes it through the non-null ptr.
            let mut settings = MaybeUninit::<Dav1dSettings>::uninit();
            dav1d_default_settings(NonNull::new(settings.as_mut_ptr()).unwrap());
            let mut settings = settings.assume_init();
            settings.n_threads = 1; // single-threaded; caller supplies the 64 MiB stack (CF-2).
            settings.max_frame_delay = 1; // a lone keyframe still returns immediately.

            // SAFETY: `&mut ctx` (a live `Option<Dav1dContext>`) receives the opened
            // handle; `&mut settings` is fully initialized. On success dav1d sets
            // `ctx` to `Some(handle)`.
            let mut ctx: Option<Dav1dContext> = None;
            let res = dav1d_open(
                Some(NonNull::from(&mut ctx)),
                Some(NonNull::from(&mut settings)),
            );
            self.ctx = if res.0 == 0 { ctx } else { None };
        }
    }

    /// Tear down the rav1d context if one is open. Idempotent.
    #[allow(unsafe_code)]
    fn close_ctx(&mut self) {
        if self.ctx.is_some() {
            // SAFETY: `&mut self.ctx` holds a live handle; `dav1d_close` releases the
            // context's internal ref exactly once and sets the inner Option to `None`.
            unsafe {
                dav1d_close(Some(NonNull::from(&mut self.ctx)));
            }
            self.ctx = None;
        }
    }

    /// Decode one demuxed AV1 sample through the live context, emitting one
    /// `WorkerMsg::Video` per produced picture (validated first) or one
    /// `WorkerMsg::Error` on failure. Carries the Task-3.1 FFI hardening:
    /// unconditional `dav1d_data_unref` before any early return (stuck-stream leak
    /// fix) and `-EAGAIN`(retry)-vs-fatal(fail-fast) branching on `dav1d_send_data`.
    #[allow(unsafe_code)]
    fn decode_sample(&mut self, sample: &[u8]) -> Vec<WorkerMsg> {
        let handle = match self.ctx {
            Some(h) => h,
            None => return vec![WorkerMsg::Error(DecodeError::DecodeFailed)],
        };
        let bounds = self.bounds;
        let mut out: Vec<WorkerMsg> = Vec::new();

        // SAFETY: every dav1d FFI call below is given valid, correctly-typed,
        // non-aliasing pointers to live stack storage; the input bytes are copied
        // into a dav1d-owned buffer; the data ref is released UNCONDITIONALLY before
        // return; and each produced picture is unref'd exactly once after copy.
        unsafe {
            // SAFETY: `data` is uninitialized `Dav1dData`; `dav1d_data_create`
            // initializes it and returns a writable dav1d-owned buffer of exactly
            // `sample.len()` bytes, into which we copy the (non-overlapping) sample.
            let mut data = MaybeUninit::<Dav1dData>::uninit();
            let buf =
                dav1d_data_create(Some(NonNull::new(data.as_mut_ptr()).unwrap()), sample.len());
            if buf.is_null() {
                return vec![WorkerMsg::Error(DecodeError::DecodeFailed)];
            }
            std::ptr::copy_nonoverlapping(sample.as_ptr(), buf, sample.len());
            let mut data = data.assume_init();

            let mut fatal = false;
            for _ in 0..MAX_DRAIN_ITERS {
                if data.sz > 0 {
                    // SAFETY: `handle` is the live context; `&mut data` is the live,
                    // initialized data struct. On success dav1d takes the bytes
                    // (`data.sz` → 0); on `-EAGAIN` it keeps our ref for a retry. Any
                    // OTHER negative result is a hard feed error → fail fast.
                    let sr = dav1d_send_data(Some(handle), Some(NonNull::from(&mut data)));
                    if sr.0 != 0 && sr.0 != DAV1D_ERR_AGAIN {
                        fatal = true;
                        break;
                    }
                }
                // SAFETY: `pic` is uninitialized `Dav1dPicture`; on a `0` result dav1d
                // has fully initialized it and we own a ref to release.
                let mut pic = MaybeUninit::<Dav1dPicture>::uninit();
                let r =
                    dav1d_get_picture(Some(handle), Some(NonNull::new(pic.as_mut_ptr()).unwrap()));
                if r.0 == 0 {
                    let mut pic = pic.assume_init();
                    let extracted = extract_i420(&pic, &bounds, self.next_pts_ms);
                    // SAFETY: `pic` is a live, dav1d-initialized picture we own;
                    // release our reference exactly once now that the planes (if any)
                    // are copied into owned Vecs.
                    dav1d_picture_unref(Some(NonNull::from(&mut pic)));
                    match extracted {
                        Ok(frame) => match validate_i420(&frame, &bounds) {
                            Ok(()) => {
                                self.next_pts_ms += 1;
                                out.push(WorkerMsg::Video(frame));
                            }
                            Err(e) => {
                                out.push(WorkerMsg::Error(e));
                                fatal = true;
                                break;
                            }
                        },
                        Err(e) => {
                            out.push(WorkerMsg::Error(e));
                            fatal = true;
                            break;
                        }
                    }
                } else if r.0 == DAV1D_ERR_AGAIN {
                    if data.sz == 0 {
                        break; // all bytes consumed, nothing more to drain — done.
                    }
                    // else: dav1d wants the buffer drained before more input — loop.
                } else {
                    fatal = true;
                    break;
                }
            }

            // SAFETY: `data` is a valid, initialized local `Dav1dData`. Release our
            // ref UNCONDITIONALLY: `dav1d_send_data` only empties it on success, so a
            // stuck/early-exit stream can leave bytes (and the ref-counted input
            // buffer) un-taken, which `dav1d_close` does NOT free. `dav1d_data_unref`
            // is idempotent (`mem::take` inside) — safe even after full consumption.
            dav1d_data_unref(Some(NonNull::from(&mut data)));

            if fatal && !out.iter().any(|m| matches!(m, WorkerMsg::Error(_))) {
                out.push(WorkerMsg::Error(DecodeError::DecodeFailed));
            }
        }
        out
    }
}

impl Drop for VideoSession {
    fn drop(&mut self) {
        // Defense in depth: never leak the context if the caller forgets `Close`.
        self.close_ctx();
    }
}

/// De-stride a decoded `Dav1dPicture` into tightly-packed 8-bit I420 planes.
///
/// Rejects anything but 8-bit I420 (`DAV1D_PIXEL_LAYOUT_I420`, `bpc == 8`) — the
/// canonical clip format. Copies row-by-row out of the strided dav1d planes so the
/// result satisfies `validate_i420` exactly: `y.len() == w*h`,
/// `u.len() == v.len() == ceil(w/2)*ceil(h/2)`. A pre-copy dimension cap check
/// avoids ever allocating an over-cap copy (`validate_i420` re-checks downstream).
#[allow(unsafe_code)]
fn extract_i420(
    pic: &Dav1dPicture,
    bounds: &VideoBounds,
    pts_ms: u64,
) -> Result<I420Frame, DecodeError> {
    // 8-bit I420 only — the canonical decode format. Anything else is rejected
    // rather than mis-interpreted (a 10-bit or 4:2:2 picture would mis-size planes).
    if pic.p.layout != DAV1D_PIXEL_LAYOUT_I420 || pic.p.bpc != 8 {
        return Err(DecodeError::DecodeFailed);
    }
    if pic.p.w <= 0 || pic.p.h <= 0 {
        return Err(DecodeError::OutputRejected {
            reason: OutputReject::EmptyDims,
        });
    }
    let (w, h) = (pic.p.w as u32, pic.p.h as u32);

    // Pre-copy cap check: refuse to allocate an over-cap plane copy. validate_i420
    // re-applies the identical bound on the emitted frame (belt and suspenders).
    let (wu, hu) = (w as u64, h as u64);
    if w > bounds.max_width || h > bounds.max_height || wu * hu > bounds.max_pixels {
        return Err(DecodeError::OutputRejected {
            reason: OutputReject::OverCap,
        });
    }

    let (wz, hz) = (w as usize, h as usize);
    let cw = wz.div_ceil(2);
    let ch = hz.div_ceil(2);

    // Plane base pointers + row strides. stride[0] = Y, stride[1] = U & V.
    let y_base = pic.data[0].ok_or(DecodeError::DecodeFailed)?.as_ptr() as *const u8;
    let u_base = pic.data[1].ok_or(DecodeError::DecodeFailed)?.as_ptr() as *const u8;
    let v_base = pic.data[2].ok_or(DecodeError::DecodeFailed)?.as_ptr() as *const u8;
    // `stride` is `ptrdiff_t` (== `isize`), exactly what `copy_plane` wants.
    let y_stride = pic.stride[0];
    let uv_stride = pic.stride[1];

    let mut y = vec![0u8; wz * hz];
    let mut u = vec![0u8; cw * ch];
    let mut v = vec![0u8; cw * ch];

    // SAFETY: each (base, stride) pair addresses a dav1d-owned plane with at least
    // `rows` lines `stride` bytes apart and at least `row_width` valid bytes per line
    // (`row_width <= |stride|` for a `row_width`-wide plane); the destination Vecs are
    // sized exactly `rows * row_width`, so every copy is in-bounds on both ends. We
    // hold a live ref to `pic` for the duration, so the source stays mapped.
    unsafe {
        copy_plane(y_base, y_stride, wz, hz, &mut y);
        copy_plane(u_base, uv_stride, cw, ch, &mut u);
        copy_plane(v_base, uv_stride, cw, ch, &mut v);
    }

    Ok(I420Frame {
        width: w,
        height: h,
        pts_ms,
        y,
        u,
        v,
    })
}

/// Copy `rows` lines of `row_width` bytes from a strided source plane into the
/// tightly-packed `dst` (`dst.len() == rows * row_width`).
///
/// # Safety
/// `base` must point to at least `rows` readable lines spaced `stride` bytes apart,
/// each with `row_width` valid bytes; `dst.len()` must equal `rows * row_width`.
#[allow(unsafe_code)]
unsafe fn copy_plane(
    base: *const u8,
    stride: isize,
    row_width: usize,
    rows: usize,
    dst: &mut [u8],
) {
    // Defense in depth (debug-only, zero release-build cost): the soundness of the
    // strided reads below rests on rav1d's default-allocator invariant
    // `|stride| >= row_width` and `alloc >= rows*|stride|`. We never set
    // `settings.allocator`, so that invariant is in force; these asserts would trip
    // loudly if a future allocator swap or rav1d change ever broke it.
    debug_assert!(
        (row_width as isize) <= stride.abs(),
        "row_width must fit within stride"
    );
    debug_assert_eq!(dst.len(), rows * row_width, "dst must be tightly packed");
    for row in 0..rows {
        // SAFETY: `row < rows`, so `row*stride` stays within the source allocation and
        // the `row_width`-byte read is in-bounds (caller contract); the matching dst
        // slice `[row*row_width .. (row+1)*row_width]` is in-bounds since
        // `dst.len() == rows*row_width`.
        let src = base.offset(row as isize * stride);
        let src_row = std::slice::from_raw_parts(src, row_width);
        dst[row * row_width..(row + 1) * row_width].copy_from_slice(src_row);
    }
}

/// Demux every video sample out of a self-contained fragment MP4 with symphonia's
/// isomp4 reader. Returns `None` on a malformed reader / missing video track (the
/// session maps that to `DecodeError::DecodeFailed`) — never panics on hostile input.
fn demux_video_samples(mp4: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mss = MediaSourceStream::new(
        Box::new(Cursor::new(mp4.to_vec())),
        MediaSourceStreamOptions::default(),
    );
    let mut reader = IsoMp4Reader::try_new(mss, FormatOptions::default()).ok()?;
    let track_id = reader.first_track(TrackType::Video)?.id;

    let mut samples = Vec::new();
    loop {
        match reader.next_packet() {
            Ok(Some(pkt)) if pkt.track_id == track_id => samples.push(pkt.data.into_vec()),
            Ok(Some(_)) => continue, // a non-video packet — skip.
            Ok(None) => break,       // clean end of stream.
            Err(_) => break,         // truncated/EOF — stop; return what we have.
        }
    }
    Some(samples)
}
