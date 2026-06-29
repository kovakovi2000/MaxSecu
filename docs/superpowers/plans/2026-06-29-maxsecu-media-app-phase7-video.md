# MaxSecu Media App — Phase 7: Sandboxed Video — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Light up the media app's video path — author-side transcode to a canonical AV1/AAC/CMAF format and viewer-side decode of attacker-authored bytes — with the decode hot path in pure Rust and all C confined to a single AppContainer-isolated leaf worker.

**Architecture:** Two confined workers. (1) A **pure-Rust persistent-session decode worker** (`rav1d` AV1 + `symphonia` CMAF/AAC-LC) fed CMAF fragments over a new **duplex streaming proto**, emitting I420 frames + PCM that the WebView renders via a WebGL YUV→RGB shader + WebAudio. (2) A **C transcode/ingest worker** (`ffmpeg` decode → `rav1e` AV1 encode → AAC/CMAF mux) that runs once per upload. No C ever enters `client-core`/`client-app`/the main process; `FfmpegVideo` becomes a thin launcher mirroring the existing decode-worker seam. Seek + bounded decrypt-while-play are backed by closed-GOP fragments and an on-disk **ciphertext** fragment cache (plaintext never persisted).

**Tech Stack:** Rust 1.96 MSVC (Windows), `rav1d`/`rav1e`/`symphonia` + an ffmpeg `-sys` binding (codecs), `windows-sys` (AppContainer/Job Object FFI), Tauri 2 + vanilla-TS Web Components + WebGL/WebAudio (UI), `cargo-fuzz` (corpus).

**Spec:** `docs/superpowers/specs/2026-06-29-maxsecu-media-app-phase7-video.md` (read it first; decisions P7-1..P7-5).

---

## Conventions for every task (read once)

- **cargo not on PATH.** Prefix shell commands: bash `export PATH="$HOME/.cargo/bin:$PATH";` / PowerShell `$env:Path="$env:USERPROFILE\.cargo\bin;$env:Path";`.
- **Gates (all green before the single per-task commit):**
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo deny check`
  - `cargo audit`
  - `MAXSECU_PG_OPTIONAL=1 cargo test --workspace` — and run the worker crate **isolated, single-threaded**: `cargo test -p maxsecu-media-worker -- --test-threads=1` (known parallel-only AppContainer-profile flake, not yours).
  - UI tasks also: in `crates/client-app/ui` → `npm run typecheck && npm test && npm run test:a11y && npm run build`.
- **fmt:** keep `media-worker`, the new `media-transcode-worker`, `client-app`, and `ui` fmt-clean. `client-core` + `server` carry pre-existing Phase 0–7 drift — **never `cargo fmt --all`**; match in-file style for new `client-core` lines.
- **Confinement invariants (never violate):** workers hold NO keys and open NO sockets; the launcher hands a worker only already-decrypted canonical bytes for one file; the main process re-validates every worker output before render; only decoded frames/PCM + typed state cross the Tauri seam.
- **Commit discipline:** exactly ONE commit per task, conventional-commit subject, ending with the two trailers:
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01BJyhZPtdHPDcbDHVTJYRmw
  ```
  Do NOT push; do NOT merge to main.
- **Review between tasks:** spec-compliance review, then code-quality review; a **dedicated security review** for every TCB/codec/sandbox/launcher task (Tasks in gates 1–3 and 6, plus the cache). Combined review is allowed only for pure-UI tasks (gate 5 UI-only steps).
- **Verify-then-implement for codec calls:** where a step integrates `rav1d`/`symphonia`/`rav1e`/ffmpeg, FIRST open the crate's docs (`cargo doc -p <crate> --open` is unavailable headless — use `cargo doc -p <crate>` then read `target/doc`, or read docs.rs offline notes captured in Task 1.4) and confirm the real API, THEN write the implementation against it. Never invent codec signatures. Our own wire/types/validation code below is complete and authoritative.

---

## File structure (created/modified)

```
crates/
  client-core/src/
    video.rs              NEW  VideoBounds, I420Frame, PcmChunk, validate_i420/validate_pcm,
                               duplex decode-session proto types (our wire contract), DecodeError additions.
    media.rs              MOD  reshape FfmpegVideo -> launcher contract (no in-proc codec);
                               TranscodeRequest/TranscodeResult/FragmentEntry types.
    lib.rs                MOD  export `video` module.
  media-worker/src/
    session.rs            NEW  persistent decode-session state machine over client-core::video proto.
    lib.rs                MOD  VideoSessionDecoder seam + AppContainer session launcher.
    win32.rs              MOD  duplex streaming spawn (concurrent write/read across many messages).
    main.rs               MOD  worker session loop + new `--selftest-*` lifetime probes.
  media-worker/tests/
    video_session.rs      NEW  cross-platform session decode over SubprocessDecoder.
    containment_video_windows.rs  NEW  session-lifetime containment (net/spawn/key) for video.
    bombs_video.rs        NEW  oversize/duration/garbage/truncated-fragment rejection.
  media-transcode-worker/  NEW CRATE (lib+bin) — the ONLY crate that links ffmpeg C.
    Cargo.toml, src/lib.rs, src/main.rs, src/transcode.rs, tests/transcode.rs,
    tests/containment_transcode_windows.rs
  client-app/src/
    fragment_cache.rs     NEW  on-disk ciphertext LRU keyed by (file_id, fragment_seq).
    video.rs              NEW  orchestration: fragment index, seek mapping, decrypt-while-play feeder.
    commands/video.rs     NEW  open_video / video_seek / video_set_volume / cancel_video commands.
    state.rs              MOD  PlayerPhase + EVT_PLAYER.
    lib.rs / main.rs      MOD  module + command registration.
  client-app/tests/
    video_e2e.rs          NEW  author transcode -> upload -> browse -> sandboxed decode -> play, real TLS.
  client-app/ui/src/
    components/video-player.ts   MOD/NEW  WebGL YUV->RGB canvas + WebAudio + states + scrubber + volume.
    core/webgl-yuv.ts            NEW  shader + texture-upload helper.
    core/player.ts               NEW  frame/PCM event binding + A/V sync + pacing.
  fuzz/ (or crates/media-worker/fuzz/)  NEW  cargo-fuzz target over the decode proto + AV1/CMAF corpus.
docs/
  security-review-phase7-mediaapp.md  NEW (gate 7).
  media-sandbox.md / parameters.md     MOD (gate 1: ratified §4 + numeric caps).
```

---

# GATE 1 — Codec ratification + adoption (security-reviewed BEFORE adoption)

> Output: a verified, pinned codec crate set + a written decision doc + minimal smoke tests proving each crate decodes/encodes our canonical format. This gate unlocks concrete codec calls in later gates.

### Task 1.1: Spike crate to verify the decode crates exist and decode AV1/CMAF/AAC

**Files:**
- Create: `crates/_spike-codecs/Cargo.toml` (temporary; deleted at end of gate)
- Create: `crates/_spike-codecs/src/main.rs`

- [ ] **Step 1: Add the spike crate (NOT in workspace default-members yet).** Pin candidate versions of `rav1d`, `symphonia` (features `isomp4`, `aac`), `rav1e`. Use `cargo add --dry-run` first to read the latest compatible versions; record them.

```toml
[package]
name = "spike-codecs"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
# Versions are CANDIDATES — confirm with `cargo add --dry-run` / docs.rs before pinning.
rav1d = "*"          # AV1 decoder (memory-safe dav1d port) — confirm crate name + version
symphonia = { version = "*", default-features = false, features = ["isomp4", "aac"] }
rav1e = "*"
```

- [ ] **Step 2: Write a `main` that proves the round-trip in-process** (spike only — not production): generate a tiny raw frame, `rav1e`-encode to AV1, wrap minimal CMAF, `symphonia`-demux + `rav1d`-decode, assert dimensions match. Read each crate's real API from `target/doc` while writing this.

Run: `cargo run -p spike-codecs`
Expected: prints the decoded `WxH` equal to the source; exit 0.

- [ ] **Step 3: Record the REAL APIs you used** (exact types/functions for: rav1e encode config + packet loop; symphonia format-reader + AAC decoder; rav1d decoder send/recv + plane access) into a scratch note for Task 1.4. These become the authoritative signatures later tasks call.

- [ ] **Step 4: Commit the spike** (kept only through gate 1).

```bash
git add crates/_spike-codecs
git commit -m "chore(phase7): codec spike — verify rav1d/symphonia/rav1e round-trip"
```

### Task 1.2: Verify an ffmpeg `-sys` ingest binding builds on Windows MSVC

**Files:**
- Modify: `crates/_spike-codecs/Cargo.toml`, `crates/_spike-codecs/src/main.rs`

- [ ] **Step 1:** Add the chosen ffmpeg binding (candidate `ffmpeg-next` + `ffmpeg-sys-next`, or a narrower `ac-ffmpeg`). Confirm how its C library is sourced on Windows MSVC (vcpkg / prebuilt / `build`-feature). Record the exact provisioning steps.
- [ ] **Step 2:** Decode a tiny known H.264 (or MJPEG) test clip to a raw frame; print dims. If the C lib cannot be provisioned headlessly, record that as a **deferred-op** (ingest worker built behind a `cfg`/feature, gate 6 wires the real lib) — do NOT fabricate a working build.

Run: `cargo run -p spike-codecs --features ingest`
Expected: prints decoded source dims, or a recorded, documented provisioning blocker.

- [ ] **Step 3: Commit.**

```bash
git add crates/_spike-codecs
git commit -m "chore(phase7): codec spike — verify ffmpeg ingest binding on win-msvc"
```

### Task 1.3: deny.toml + audit posture for the new codec deps

**Files:**
- Modify: `deny.toml`

- [ ] **Step 1:** Run `cargo deny check` against the spike graph; capture every new advisory/license. For each, add a justified entry (license `allow` additions only if truly needed; advisory `ignore` only with a written rationale, mirroring the existing GTK/unic entries). Confirm `ring`/`openssl` are still absent (`cargo tree -i ring`, `cargo tree -i openssl` → empty).
- [ ] **Step 2:** Run `cargo audit`; record results.
- [ ] **Step 3:** Verify the ffmpeg `-sys` crate is the ONLY new C link and is reachable only from the spike (later: only from `media-transcode-worker`): `cargo tree -i <ffmpeg-sys-crate> -e normal`.
- [ ] **Step 4: Commit.**

```bash
git add deny.toml
git commit -m "chore(phase7): deny/audit posture for codec deps (ring/openssl still absent)"
```

### Task 1.4: Ratification decision doc + canonical caps; remove the spike

**Files:**
- Modify: `docs/media-sandbox.md` (ratify §4: AV1/AAC-LC/CMAF, closed-GOP), `docs/parameters.md` (numeric caps)
- Create: `docs/security-review-phase7-codec-ratification.md`
- Delete: `crates/_spike-codecs/`

- [ ] **Step 1:** Write `docs/security-review-phase7-codec-ratification.md`: the pinned crate set + versions, the verified APIs (from 1.1/1.2 notes), the attack-surface justification (why AppContainer + secret-less worker contains a codec 0-day), deny/audit outcomes, and the residuals. This is the **security-reviewed-before-adoption** artifact.
- [ ] **Step 2:** Ratify `media-sandbox.md` §4 to AV1 / AAC-LC / CMAF closed-GOP fragments, and set the numeric caps in `parameters.md`: `MAX_DURATION_MS`, `MAX_FRAMERATE`, `MAX_FRAGMENT_BYTES`, `MAX_TOTAL_BYTES`, `MAX_FRAGMENTS`, `MAX_AUDIO_CHANNELS`, `MAX_SAMPLE_RATE` (propose concrete values, e.g. 30 min, 120 fps, 16 MiB, 4 GiB, 4096, 2, 48 kHz).
- [ ] **Step 3:** `rm -rf crates/_spike-codecs` and remove it from the workspace.
- [ ] **Step 4:** Gates green; **dedicated security review of this doc + posture**; then commit.

```bash
git add docs/ deny.toml Cargo.toml Cargo.lock
git rm -r crates/_spike-codecs
git commit -m "docs(phase7): ratify canonical AV1/AAC-LC/CMAF + caps; security-reviewed codec adoption"
```

---

# GATE 2 — client-core video seam contracts (TCB; pure types, no codec)

> Output: the authoritative types + wire format + output-validation in `client-core`, fully unit-tested, with NO codec dependency. These are OUR code — fully specified below.

### Task 2.1: `VideoBounds`, `I420Frame`, `PcmChunk` + output-validation

**Files:**
- Create: `crates/client-core/src/video.rs`
- Modify: `crates/client-core/src/lib.rs` (add `pub mod video;`)
- Test: inline `#[cfg(test)]` in `video.rs`

- [ ] **Step 1: Write failing tests** for validation behavior.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32) -> I420Frame {
        let (cw, ch) = ((w as usize + 1) / 2, (h as usize + 1) / 2);
        I420Frame {
            width: w, height: h, pts_ms: 0,
            y: vec![0u8; w as usize * h as usize],
            u: vec![0u8; cw * ch],
            v: vec![0u8; cw * ch],
        }
    }

    #[test]
    fn accepts_consistent_i420() {
        assert!(validate_i420(&frame(4, 4), &VideoBounds::default()).is_ok());
    }

    #[test]
    fn rejects_plane_length_mismatch() {
        let mut f = frame(4, 4);
        f.y.truncate(3); // hostile/buggy worker under-reads
        assert_eq!(
            validate_i420(&f, &VideoBounds::default()),
            Err(DecodeError::OutputRejected { reason: OutputReject::BufferLenMismatch })
        );
    }

    #[test]
    fn rejects_dims_over_cap() {
        let b = VideoBounds { max_width: 2, ..VideoBounds::default() };
        assert_eq!(
            validate_i420(&frame(4, 4), &b),
            Err(DecodeError::OutputRejected { reason: OutputReject::OverCap })
        );
    }

    #[test]
    fn validates_pcm_shape() {
        let good = PcmChunk { channels: 2, sample_rate: 48_000, pts_ms: 0, samples: vec![0i16; 8] };
        assert!(validate_pcm(&good, &VideoBounds::default()).is_ok());
        let bad = PcmChunk { channels: 3, ..good.clone() }; // odd count vs channels
        assert_eq!(
            validate_pcm(&bad, &VideoBounds::default()),
            Err(DecodeError::OutputRejected { reason: OutputReject::BufferLenMismatch })
        );
    }
}
```

- [ ] **Step 2: Run, verify they fail.** `cargo test -p maxsecu-client-core video::tests -- --nocapture` → FAIL (types undefined).

- [ ] **Step 3: Implement the types + validation** (reuse `DecodeError`/`OutputReject` from `sandbox.rs`; add an `OverCap`/`BufferLenMismatch` path for I420/PCM). Note chroma is `ceil(w/2)*ceil(h/2)` per plane.

```rust
//! Video decode contracts (DESIGN §8.1/D30, Phase 7). Pure types + untrusted-output
//! validation; NO codec dependency (codecs live in the spawned, confined worker).

use crate::sandbox::{DecodeError, OutputReject};

/// Pre-decode bounds for video (media-sandbox §3 + spec §2.1). Hard ceilings,
/// checked before any allocation, in the main process AND each worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoBounds {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
    pub max_duration_ms: u64,
    pub max_framerate: u32,
    pub max_fragment_bytes: u64,
    pub max_total_bytes: u64,
    pub max_fragments: u32,
    pub max_audio_channels: u8,
    pub max_sample_rate: u32,
}

impl Default for VideoBounds {
    fn default() -> Self {
        // Values mirror docs/parameters.md (set in Task 1.4).
        VideoBounds {
            max_width: 7680,
            max_height: 4320,
            max_pixels: 33_177_600, // 8K
            max_duration_ms: 30 * 60 * 1000,
            max_framerate: 120,
            max_fragment_bytes: 16 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_fragments: 4096,
            max_audio_channels: 2,
            max_sample_rate: 48_000,
        }
    }
}

/// One decoded I420 (planar YUV 4:2:0) frame from the untrusted worker. RAM-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I420Frame {
    pub width: u32,
    pub height: u32,
    pub pts_ms: u64,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

/// One decoded interleaved-i16 PCM chunk from the untrusted worker. RAM-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcmChunk {
    pub channels: u8,
    pub sample_rate: u32,
    pub pts_ms: u64,
    pub samples: Vec<i16>,
}

#[inline]
fn chroma_dims(w: u32, h: u32) -> (u64, u64) {
    ((w as u64 + 1) / 2, (h as u64 + 1) / 2)
}

/// Validate an untrusted decoded frame BEFORE the renderer (spec §7).
pub fn validate_i420(f: &I420Frame, b: &VideoBounds) -> Result<(), DecodeError> {
    let reject = |reason| Err(DecodeError::OutputRejected { reason });
    if f.width == 0 || f.height == 0 {
        return reject(OutputReject::EmptyDims);
    }
    let (w, h) = (f.width as u64, f.height as u64);
    if f.width > b.max_width || f.height > b.max_height || w * h > b.max_pixels {
        return reject(OutputReject::OverCap);
    }
    let (cw, ch) = chroma_dims(f.width, f.height);
    if f.y.len() as u64 != w * h || f.u.len() as u64 != cw * ch || f.v.len() as u64 != cw * ch {
        return reject(OutputReject::BufferLenMismatch);
    }
    Ok(())
}

/// Validate an untrusted decoded PCM chunk BEFORE WebAudio (spec §7).
pub fn validate_pcm(p: &PcmChunk, b: &VideoBounds) -> Result<(), DecodeError> {
    let reject = |reason| Err(DecodeError::OutputRejected { reason });
    if p.channels == 0 || p.channels > b.max_audio_channels {
        return reject(OutputReject::BadChannels);
    }
    if p.sample_rate == 0 || p.sample_rate > b.max_sample_rate {
        return reject(OutputReject::OverCap);
    }
    if p.samples.len() % p.channels as usize != 0 {
        return reject(OutputReject::BufferLenMismatch);
    }
    Ok(())
}
```

- [ ] **Step 4: Run, verify pass.** `cargo test -p maxsecu-client-core video::tests`
- [ ] **Step 5: Commit.** `feat(client-core): video bounds, I420/PCM types, untrusted-output validation`

### Task 2.2: Duplex decode-session proto (our wire contract)

**Files:**
- Modify: `crates/client-core/src/video.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing round-trip tests** for each message (launcher↔worker), including truncated/trailing rejection (mirror the existing `media-worker::proto` discipline).

```rust
#[test]
fn open_and_fragment_roundtrip() {
    let open = ClientMsg::Open { bounds: VideoBounds::default() };
    assert_eq!(decode_client_msg(&encode_client_msg(&open)).unwrap(), open);
    let frag = ClientMsg::Fragment { seq: 7, bytes: vec![1, 2, 3] };
    assert_eq!(decode_client_msg(&encode_client_msg(&frag)).unwrap(), frag);
    let seek = ClientMsg::Seek { fragment_seq: 4 };
    assert_eq!(decode_client_msg(&encode_client_msg(&seek)).unwrap(), seek);
}

#[test]
fn worker_video_audio_roundtrip() {
    let v = WorkerMsg::Video(/* small I420Frame */);
    assert_eq!(decode_worker_msg(&encode_worker_msg(&v)).unwrap(), v);
    let a = WorkerMsg::Audio(/* small PcmChunk */);
    assert_eq!(decode_worker_msg(&encode_worker_msg(&a)).unwrap(), a);
}

#[test]
fn rejects_trailing_and_truncated() {
    let mut b = encode_client_msg(&ClientMsg::Seek { fragment_seq: 1 });
    b.push(0xFF);
    assert!(decode_client_msg(&b).is_err());
    assert!(decode_client_msg(&b[..1]).is_err());
}
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** length-prefixed, little-endian, **self-describing single-message** codecs (each message is framed by the caller with a u32 length prefix — see Task 3.x launcher). Define:

```rust
/// Launcher -> worker (one message per call; the session feeds many).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMsg {
    Open { bounds: VideoBounds },
    Fragment { seq: u32, bytes: Vec<u8> },
    Seek { fragment_seq: u32 },
    Close,
}

/// Worker -> launcher (streamed; many per fragment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerMsg {
    Ready,
    Video(I420Frame),
    Audio(PcmChunk),
    EndOfFragment { seq: u32 },
    Error(DecodeError),
}
```

Implement `encode_client_msg`/`decode_client_msg`/`encode_worker_msg`/`decode_worker_msg` with explicit tag bytes, `put_u32/put_u64` helpers (copy the proven helpers from `media-worker::proto`), injective framing (reject trailing bytes). Fill in the two `/* ... */` test bodies with small concrete frames.

- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit.** `feat(client-core): duplex video decode-session proto (framed, injective)`

---

# GATE 3 — Persistent-session decode worker + duplex launcher + containment

> The single largest review surface (the `unsafe` launcher grows duplex streaming). Pure Rust; driven by pre-canonicalized fixtures. Each task: dedicated security review.

### Task 3.1: Fixture generator (pre-canonical AV1/AAC/CMAF) behind a test helper

**Files:**
- Create: `crates/media-worker/tests/support/mod.rs` (or a `#[cfg(test)]` helper)

- [ ] **Step 1:** Using the gate-1-verified `rav1e`/muxer API, write a test-only helper `make_canonical_clip(w, h, frames, with_audio) -> CanonicalClip { fragments: Vec<Vec<u8>>, ... }` producing closed-GOP CMAF fragments. (This reuses the spike code, now in a real test helper.)
- [ ] **Step 2:** Assert it produces ≥1 independently-decodable fragment via `symphonia`+`rav1d`. Run; verify pass.
- [ ] **Step 3: Commit.** `test(media-worker): canonical AV1/AAC/CMAF fixture generator`

### Task 3.2: In-process session decode (no subprocess yet)

**Files:**
- Create: `crates/media-worker/src/session.rs`
- Modify: `crates/media-worker/src/lib.rs`
- Test: `crates/media-worker/tests/video_session.rs`

- [ ] **Step 1: Write a failing test:** feed `Open` + N `Fragment` messages to an in-process `decode_session(...)` and assert it yields validated `WorkerMsg::Video` frames (count, dims) + `EndOfFragment` per fragment, and that a `Seek` re-emits from the target fragment.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `session.rs`:** a `VideoSession` holding the `rav1d` decoder + `symphonia` reader, with `fn feed(&mut self, ClientMsg) -> Vec<WorkerMsg>`. Enforce `VideoBounds` per fragment BEFORE decode (size/dims/duration); on `Seek`, flush decoder state and resume. Use the gate-1-verified codec APIs. Every emitted frame passes `validate_i420`; every PCM `validate_pcm`.
- [ ] **Step 4: Run, verify pass** (cross-platform, no subprocess).
- [ ] **Step 5: Commit.** `feat(media-worker): in-process persistent video decode session`

### Task 3.3: Worker binary session loop + lifetime selftests

**Files:**
- Modify: `crates/media-worker/src/main.rs`

- [ ] **Step 1:** Add a `--video-session` mode: read length-prefixed `ClientMsg`s from stdin in a loop, drive `VideoSession`, write length-prefixed `WorkerMsg`s to stdout, until `Close`/EOF. Keep the existing single-image mode untouched.
- [ ] **Step 2:** Add lifetime selftests `--selftest-net-late` / `--selftest-spawn-late` (attempt the action AFTER processing one fragment) to prove containment holds across the *whole session*, not just at start.
- [ ] **Step 3:** Add a cross-platform `SubprocessDecoder`-style `VideoSubprocessSession` test that spawns the worker and exchanges a full Open→Fragments→Close exchange. Run; verify pass.
- [ ] **Step 4: Commit.** `feat(media-worker): worker session loop + late-lifetime containment probes`

### Task 3.4: Duplex streaming in the AppContainer launcher (`win32.rs`)

**Files:**
- Modify: `crates/media-worker/src/win32.rs`, `crates/media-worker/src/lib.rs`

- [ ] **Step 1: Write a failing Windows test** (`containment_video_windows.rs`): `AppContainerVideoSession::new(WORKER)` runs a full Open→Fragments→Close and returns validated frames matching the fixture; confined session is **denied** `--selftest-net-late`/`--selftest-spawn-late`/`--selftest-read` while the unconfined `SubprocessDecoder` differential is allowed.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `spawn_confined_session`: same AppContainer + Job Object setup as `spawn_confined`, but keep both pipes open and do **concurrent** I/O — a writer thread streaming `ClientMsg`s and the parent reading framed `WorkerMsg`s until the worker closes (mirror the existing writer-thread pattern in `SubprocessDecoder::decode_image`, extended to many messages). Preserve every existing SAFETY comment + handle-close discipline; the Job Object still kills the session on close. Add `AppContainerVideoSession` implementing a `VideoSessionDecoder` trait.
- [ ] **Step 4: Run, verify pass** (`cargo test -p maxsecu-media-worker -- --test-threads=1`).
- [ ] **Step 5: Commit.** `feat(media-worker): duplex streaming AppContainer session launcher + video containment`

### Task 3.5: Decompression-bomb / oversize / garbage suite

**Files:**
- Create: `crates/media-worker/tests/bombs_video.rs`

- [ ] **Step 1: Write tests:** oversize-dimension fragment, over-duration clip, over-`max_fragment_bytes`, truncated fragment, trailing-data frame, pure-garbage bytes → each rejected (the session emits `WorkerMsg::Error(DecodeError::...)` or the launcher returns `Worker`), worker killed not hung (bounded by a wall-clock assertion).
- [ ] **Step 2: Run, verify pass.**
- [ ] **Step 3: Commit.** `test(media-worker): video decompression-bomb/oversize/garbage rejection`

### Task 3.6: cargo-fuzz target + committed corpus

**Files:**
- Create: `crates/media-worker/fuzz/` (fuzz_targets/decode_session.rs + a small committed corpus)

- [ ] **Step 1:** Add a `cargo-fuzz` target that feeds arbitrary bytes as a single fragment to `VideoSession::feed` (must never panic/UB; only return `Error`). Commit a seed corpus (valid fixture fragments + a few mutated).
- [ ] **Step 2:** Run a short fuzz session locally (`cargo fuzz run decode_session -- -max_total_time=60`); record clean.
- [ ] **Step 3: Commit.** `test(media-worker): cargo-fuzz decode-session target + seed corpus`

---

# GATE 4 — Ciphertext fragment cache + fragment index (client-app orchestration)

### Task 4.1: On-disk ciphertext fragment LRU

**Files:**
- Create: `crates/client-app/src/fragment_cache.rs`
- Modify: `crates/client-app/src/lib.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing tests:** `put(file_id, seq, ciphertext)` then `get(file_id, seq)` returns the bytes; exceeding the byte cap evicts LRU; the on-disk files are the **ciphertext** (assert they are NOT the plaintext fixture bytes); cache dir is created under `<dir>/cache/frag/`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** a bounded LRU keyed by `(file_id_hex, seq)` storing ciphertext blobs as files (set `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` on Windows), with an in-memory index + a configurable byte cap (reuse the Phase-5 RAM/cache cap setting). **Never** store decoded/plaintext frames.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit.** `feat(client-app): bounded on-disk ciphertext fragment cache (no plaintext at rest)`

### Task 4.2: Fragment index + seek→chunk mapping + decrypt-while-play feeder

**Files:**
- Create: `crates/client-app/src/video.rs`
- Modify: `crates/client-app/src/lib.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write failing tests:** parse a `FragmentEntry` list from metadata; `fragment_for_time(pts_ms)` returns the right `seq`; `chunks_for_fragment(seq)` returns the contiguous chunk range; the feeder pulls from `FragmentCache` on a hit and only fetches on a miss.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `FragmentEntry { seq, pts_ms, chunk_start, chunk_len }`, the index parse, `fragment_for_time`, `chunks_for_fragment`, and a `feed_fragment(seq)` that: cache-hit → ciphertext from cache; miss → fetch chunks (reuse Phase-3 `fetch_stream_chunks`) → store ciphertext in cache → decrypt (TCB) → hand the canonical fragment to the session decoder. Plaintext discarded after the frame is emitted.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit.** `feat(client-app): fragment index + seek mapping + decrypt-while-play feeder`

### Task 4.3: Player commands + state machine

**Files:**
- Create: `crates/client-app/src/commands/video.rs`
- Modify: `crates/client-app/src/state.rs` (add `PlayerPhase` + `EVT_PLAYER`), `crates/client-app/src/main.rs` (register commands)

- [ ] **Step 1: Write failing test** (orchestration-level, using the in-process session + a fake transport): `open_video(file_id)` resolves the author binding under the pinned D5, opens a session, and emits `PlayerPhase::Buffering → Playing` with frames; `video_seek(pts)` re-feeds from the mapped fragment; `cancel_video` kills the session.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** commands `open_video`, `video_seek`, `video_set_volume` (stores a gain pref; no decode effect), `cancel_video`; `PlayerPhase { Buffering, Playing, Stalled, Error{code}, CodecUnavailable }` + `EVT_PLAYER`. Frames/PCM cross the seam as typed DTOs only (base64/byte arrays of I420 planes + PCM) — never keys/whole-plaintext. Use `serial()`-compatible reauth (Phase-3 pattern).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit.** `feat(client-app): video player commands + PlayerPhase state machine`

---

# GATE 5 — Player chrome light-up (UI; combined review OK for pure-UI steps)

### Task 5.1: WebGL YUV→RGB render core

**Files:**
- Create: `crates/client-app/ui/src/core/webgl-yuv.ts`
- Test: `crates/client-app/ui/src/webgl-yuv.test.ts` (logic-level; jsdom can't run real GL — test the planar-size math + shader-source assembly, not GPU output)

- [ ] **Step 1: Write failing tests** for `planeSizes(w,h)` (luma `w*h`, chroma `ceil(w/2)*ceil(h/2)`) and that `buildProgramSources()` returns a vertex+fragment shader pair referencing 3 samplers (`yTex`,`uTex`,`vTex`) with a BT.709 matrix.
- [ ] **Step 2: Run, verify fail.** `npm test`
- [ ] **Step 3: Implement** `webgl-yuv.ts`: shader sources (BT.709 limited-range YUV→RGB), `createYuvRenderer(canvas)` returning `{ draw(frame), resize(w,h), dispose() }` that uploads Y/U/V as `LUMINANCE`/`R8` textures and draws a fullscreen triangle. Guard for missing WebGL → throws a typed error the player maps to `Error`.
- [ ] **Step 4: Run, verify pass + `npm run build`.**
- [ ] **Step 5: Commit.** `feat(ui): WebGL YUV->RGB render core for the video player`

### Task 5.2: Player binding (frames/PCM events, A/V sync, pacing, volume)

**Files:**
- Create: `crates/client-app/ui/src/core/player.ts`
- Test: `crates/client-app/ui/src/player.test.ts`

- [ ] **Step 1: Write failing tests** for the A/V scheduler: frames buffered and released by `pts` against an audio clock; volume `GainNode` value set by `setVolume`; reduced-motion → no autoplay (a flag gate).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `player.ts`: subscribe to `EVT_PLAYER` + frame/PCM streams, decode base64 → typed arrays, push PCM into a WebAudio `GainNode`→destination graph, schedule frame draws by `pts`, expose `play/pause/seek/setVolume/setRate`, and a bounded in-RAM decoded-frame ring for instant local scrub.
- [ ] **Step 4: Run, verify pass + build.**
- [ ] **Step 5: Commit.** `feat(ui): player A/V sync, pacing, volume, decoded-frame ring`

### Task 5.3: `<video-player>` component + states + scrubber + a11y

**Files:**
- Modify/Create: `crates/client-app/ui/src/components/video-player.ts`
- Modify: feed/viewer wiring; `a11y.test.ts` (extend structural lint)

- [ ] **Step 1: Write failing a11y/structural tests:** the component has a focusable region, keyboard-operable controls (play/pause/seek/volume/mute) with labels + ARIA, non-color-only state (icon+text) for buffering/playing/stalled/error/codec-unavailable + "decode worker pending", and a played-vs-loaded scrubber with `aria-valuenow`.
- [ ] **Step 2: Run, verify fail.** `npm run test:a11y`
- [ ] **Step 3: Implement** `<video-player>`: mounts the canvas + `createYuvRenderer` + `player.ts`, renders the chrome + states, the played-vs-loaded scrubber (loaded = cache/fetch coverage), volume slider + mute, optional 0.5×–2× rate menu, and the default-OFF HW-decode waiver toggle (a setting stub that, when on, surfaces a security warning — wiring an actual HW path is out of scope). Reduced-motion respected. Remove the "codec gated" placeholder only where the worker genuinely backs it.
- [ ] **Step 4: Run, verify pass:** `npm run typecheck && npm test && npm run test:a11y && npm run build`.
- [ ] **Step 5: Commit.** `feat(ui): video-player chrome — states, scrubber, volume, a11y`

---

# GATE 6 — Author-side ffmpeg ingest worker (the C carve-out) + e2e

### Task 6.1: New `media-transcode-worker` crate skeleton + proto

**Files:**
- Create: `crates/media-transcode-worker/{Cargo.toml,src/lib.rs,src/main.rs}`
- Modify: root `Cargo.toml` workspace members
- Modify: `crates/client-core/src/media.rs` (TranscodeRequest/TranscodeResult/FragmentEntry types; reshape `FfmpegVideo`)

- [ ] **Step 1: Write failing tests** in `client-core` for the launcher contract: `TranscodeRequest { source, bounds }` encode/decode round-trip; `TranscodeResult { cmaf, thumbnail, preview, fragments: Vec<FragmentEntry>, loudness_gain_db: Option<f32> }` round-trip; `FfmpegVideo::new(worker_path)` builds (no in-proc codec).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the proto + types in `client-core` (no C), and the crate skeleton. `FfmpegVideo` becomes a launcher (`Transcoder` impl spawns the confined transcode worker, like the decode seam) — moving the actual transcode OUT of `client-core`. The ffmpeg `-sys` dep lives ONLY in `media-transcode-worker/Cargo.toml`.
- [ ] **Step 4: Run, verify pass; `cargo tree -i <ffmpeg-sys> -e normal` shows ONLY `media-transcode-worker`.**
- [ ] **Step 5: Commit.** `feat(transcode-worker): crate skeleton + C-free client-core launcher contract`

### Task 6.2: Real transcode (ffmpeg decode → rav1e AV1 → AAC/CMAF mux + loudnorm)

**Files:**
- Create: `crates/media-transcode-worker/src/transcode.rs`, `tests/transcode.rs`

- [ ] **Step 1: Write a failing test:** transcode a small source clip (from the gate-1 fixtures / a tiny committed sample) → assert the output CMAF demuxes+decodes via `symphonia`+`rav1d` to the expected dims/duration, has ≥1 closed-GOP fragment, a populated fragment index, and a thumbnail+preview.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the pipeline using the gate-1-verified APIs: ffmpeg decode source→raw frames/PCM (bounds-checked first), `rav1e` encode AV1, AAC encode + CMAF mux with chunk-aligned closed-GOP fragments, derive thumbnail+preview (reuse `RustImageCodec` on a keyframe), measure `loudnorm`. Enforce `VideoBounds` before any allocation.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit.** `feat(transcode-worker): ffmpeg->rav1e/AAC/CMAF canonical transcode + loudnorm`

### Task 6.3: Confine the transcode worker + containment tests

**Files:**
- Modify: `crates/media-transcode-worker/src/main.rs`
- Create: `crates/media-transcode-worker/tests/containment_transcode_windows.rs`

- [ ] **Step 1: Write failing Windows containment tests:** the confined transcode worker still produces a correct canonical clip, but is **denied** network / child-spawn / key-blob read (selftest probes), differential vs unconfined.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the worker stdin/stdout one-shot loop + `--selftest-*` probes, and reuse `media-worker::win32::spawn_confined` (or a shared confinement helper) to spawn it confined. (Factor the AppContainer spawn into a shared module if cleaner — separately reviewed.)
- [ ] **Step 4: Run, verify pass** (`-- --test-threads=1`).
- [ ] **Step 5: Commit.** `feat(transcode-worker): AppContainer confinement + containment proofs`

### Task 6.4: Upload-side wiring + preview-before-upload

**Files:**
- Modify: `crates/client-app/src/upload.rs`, `crates/client-app/src/commands/upload.rs`, UI `<upload-screen>`/`<video-player>`

- [ ] **Step 1: Write failing test:** `stage_upload` with `kind=video` runs the confined transcode (no network), returns an `UploadPreview` whose canonical content decodes in the player; `confirm_upload` runs the existing Phase-4 pipeline on the canonical streams.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the video branch in `prepare_*_streams` (calls `FfmpegVideo` launcher), preview-before-upload (render the canonical output in `<video-player>` before confirm), and thread the fragment index into metadata. No new server endpoints/crypto.
- [ ] **Step 4: Run, verify pass + UI gates.**
- [ ] **Step 5: Commit.** `feat(client-app): video upload via confined transcode + preview-before-upload`

### Task 6.5: Full author→view e2e over real TLS

**Files:**
- Create: `crates/client-app/tests/video_e2e.rs`

- [ ] **Step 1: Write the e2e** (mirror `upload_e2e.rs`/`browse_view_e2e.rs`, MemoryStore+FsBlobStore, real loopback TLS): transcode a small source → upload → list_feed shows the video card → open_video decodes ≥N frames through the **confined** session (Windows) / subprocess session (cross-platform) → seek re-feeds from the mapped fragment → a back-seek hits the ciphertext cache (assert no re-fetch). 5 gates, like prior phases.
- [ ] **Step 2: Run, verify pass** (`-- --test-threads=1` for the worker portions).
- [ ] **Step 3: Commit.** `test(client-app): video author->view e2e over real TLS (decode/seek/cache)`

---

# GATE 7 — Holistic security review + sign-off

### Task 7.1: Security review doc

**Files:**
- Create: `docs/security-review-phase7-mediaapp.md`

- [ ] **Step 1:** Holistic review against the spec's §7 exit gates: confinement (both workers, session lifetime), zero-C TCB (`cargo tree` evidence), output-validation coverage, bounds/bomb tests, no-plaintext-at-rest (cache is ciphertext), fuzz corpus, render path (no OS decoder on attacker bytes). Record PASS + residuals.
- [ ] **Step 2:** Confirm all gates green workspace-wide; `ring`/`openssl` still absent.
- [ ] **Step 3: Commit.** `docs(phase7): media-app video security-review sign-off (PASS)`

### Task 7.2: Update memory + plan status

**Files:**
- Modify: `C:\Users\gecim\.claude\projects\D--scrs-programs-MaxSecu\memory\media-app-plan.md`, `MEMORY.md`

- [ ] **Step 1:** Mark Phase 7 COMPLETE with the commit range + crate set + residuals; note media-app is now fully feature-complete (P1–P7) and the `finishing-a-development-branch` merge/PR decision is the natural next step.
- [ ] **Step 2: Commit.** `docs(memory): mark media-app Phase 7 (video) complete`

---

## Self-review (done while writing)

- **Spec coverage:** P7-1 codec scope → Gate 1 + 3 + 6; P7-2 render → Gate 5; P7-3 session/duplex → Gate 2.2 + 3.4; P7-4 AAC-LC → Gate 1.4 + 3.2; P7-5 sequencing → gate order. Amendments: HW render/decode split → 5.3; seek → 2.2/3.2/4.2; decrypt-while-play → 4.2; ciphertext cache → 4.1; volume/loudness → 4.3/5.2/6.2. Exit gates §7 → 3.5/3.6/6.3/7.1. All covered.
- **Placeholder scan:** codec-internal steps are explicitly verify-then-implement against gate-1 APIs (not fabricated); all OUR-code steps carry complete code. The deliberately-unpinned crate facts are produced by Gate 1 — that is the design, not a placeholder.
- **Type consistency:** `VideoBounds`, `I420Frame`, `PcmChunk`, `ClientMsg`/`WorkerMsg`, `FragmentEntry`, `TranscodeRequest`/`TranscodeResult`, `PlayerPhase`, `FfmpegVideo` (launcher) are used consistently across gates.
